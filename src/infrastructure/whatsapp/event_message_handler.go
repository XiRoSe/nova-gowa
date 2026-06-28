package whatsapp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/sirupsen/logrus"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

func handleMessage(ctx context.Context, evt *events.Message, chatStorageRepo domainChatStorage.IChatStorageRepository, client *whatsmeow.Client) {
	// Log message metadata
	metaParts := buildMessageMetaParts(evt)
	log.Infof("Received message %s from %s (%s): %+v",
		evt.Info.ID,
		evt.Info.SourceString(),
		strings.Join(metaParts, ", "),
		evt.Message,
	)

	// Materialize SecretEncryptedMessage{MESSAGE_EDIT} envelope (sent by recent
	// LID-migrated WhatsApp clients) into the legacy ProtocolMessage{MESSAGE_EDIT}
	// form, so chat storage, webhook, and auto-reply all use the existing
	// edit-handling paths unchanged. No-op when the envelope is absent or when
	// decryption fails.
	evt = materializeSecretEditMessage(ctx, evt, client)

	if isReactionMessage(evt) {
		if err := chatStorageRepo.CreateReaction(ctx, evt); err != nil {
			log.Errorf("Failed to store incoming reaction %s: %v", evt.Info.ID, err)
		}

		handleWebhookForward(ctx, evt, client)
		return
	}

	if err := chatStorageRepo.CreateMessage(ctx, evt); err != nil {
		// Log storage errors to avoid silent failures that could lead to data loss
		log.Errorf("Failed to store incoming message %s: %v", evt.Info.ID, err)
	}

	// Handle image message if present
	handleImageMessage(ctx, evt, client)

	// Auto-mark message as read if configured
	handleAutoMarkRead(ctx, evt, client)

	// Handle auto-reply if configured. Sealed fork: gated behind
	// NOVA_ALLOW_PLAINTEXT_EXITS (default OFF) so this legacy path cannot act on
	// or echo plaintext message content.
	if config.NovaAllowPlaintextExits {
		handleAutoReply(ctx, evt, chatStorageRepo, client)
	}

	// Forward to webhook if configured
	handleWebhookForward(ctx, evt, client)
}

func buildMessageMetaParts(evt *events.Message) []string {
	metaParts := []string{
		fmt.Sprintf("pushname: %s", evt.Info.PushName),
		fmt.Sprintf("timestamp: %s", evt.Info.Timestamp),
	}
	if evt.Info.Type != "" {
		metaParts = append(metaParts, fmt.Sprintf("type: %s", evt.Info.Type))
	}
	if evt.Info.Category != "" {
		metaParts = append(metaParts, fmt.Sprintf("category: %s", evt.Info.Category))
	}
	if evt.IsViewOnce {
		metaParts = append(metaParts, "view once")
	}
	return metaParts
}

func handleImageMessage(_ context.Context, _ *events.Message, _ *whatsmeow.Client) {
	// Sealed fork: this path used to download inbound images to config.PathStorages
	// ("storages/") and only log the file path — there is no consumer of that copy.
	// The webhook media that Nova actually fetches is written separately to
	// config.PathMedia ("statics/media") by event_message.go, which is untouched.
	// Suppress this redundant plaintext-media-at-rest writer entirely.
	log.Debugf("[PRIVACY] redundant storages image download suppressed")
}

func handleAutoMarkRead(ctx context.Context, evt *events.Message, client *whatsmeow.Client) {
	// Only mark read if auto-mark read is enabled and message is incoming
	if !config.WhatsappAutoMarkRead || evt.Info.IsFromMe {
		return
	}

	if client == nil {
		return
	}

	// Mark the message as read
	messageIDs := []types.MessageID{evt.Info.ID}
	timestamp := time.Now()
	chat := evt.Info.Chat
	sender := evt.Info.Sender

	if err := client.MarkRead(ctx, messageIDs, timestamp, chat, sender); err != nil {
		log.Warnf("Failed to mark message %s as read: %v", evt.Info.ID, err)
	} else {
		log.Debugf("Marked message %s as read", evt.Info.ID)
	}
}

// materializeSecretEditMessage decrypts a SecretEncryptedMessage{MESSAGE_EDIT}
// envelope into its inner ProtocolMessage{MESSAGE_EDIT} form so downstream
// consumers (chat storage, webhook payload builder, auto-reply) can rely on
// the legacy edit-handling code paths unchanged. Returns the original event
// when no envelope is present, when the client is nil, or when decryption
// fails — preserving existing behavior in every other case.
func materializeSecretEditMessage(ctx context.Context, evt *events.Message, client *whatsmeow.Client) *events.Message {
	if evt == nil || evt.Message == nil || client == nil {
		return evt
	}
	msg := utils.UnwrapMessage(evt.Message)
	sem := msg.GetSecretEncryptedMessage()
	if sem == nil || sem.GetSecretEncType() != waE2E.SecretEncryptedMessage_MESSAGE_EDIT {
		return evt
	}
	decrypted, err := client.DecryptSecretEncryptedMessage(ctx, evt)
	if err != nil {
		targetID := ""
		if k := sem.GetTargetMessageKey(); k != nil {
			targetID = k.GetID()
		}
		log.Warnf("Failed to decrypt SecretEncryptedMessage(MESSAGE_EDIT) for %s (target=%s): %v", evt.Info.ID, targetID, err)
		return evt
	}
	if decrypted == nil {
		return evt
	}
	cloned := *evt
	cloned.Message = decrypted
	return &cloned
}

func handleWebhookForward(ctx context.Context, evt *events.Message, client *whatsmeow.Client) {
	// Skip webhook for protocol messages that are internal sync messages
	if protocolMessage := evt.Message.GetProtocolMessage(); protocolMessage != nil {
		protocolType := protocolMessage.GetType().String()
		// Only allow REVOKE and MESSAGE_EDIT through - skip all other protocol messages
		// (HISTORY_SYNC_NOTIFICATION, APP_STATE_SYNC_KEY_SHARE, EPHEMERAL_SYNC_RESPONSE, etc.)
		switch protocolType {
		case "REVOKE", "MESSAGE_EDIT":
			// These are meaningful user actions, allow webhook
		default:
			log.Debugf("Skipping webhook for protocol message type: %s", protocolType)
			return
		}
	}

	if (len(config.WhatsappWebhook) > 0 || config.ChatwootEnabled) &&
		!strings.Contains(evt.Info.SourceString(), "broadcast") {
		go func(e *events.Message, c *whatsmeow.Client) {
			webhookCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := forwardMessageToWebhook(webhookCtx, c, e); err != nil {
				logrus.Error("Failed forward to webhook: ", err)
			}
		}(evt, client)
	}
}
