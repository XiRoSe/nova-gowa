// Package seal encrypts outgoing webhook message bodies to Nova's rotating
// epoch public key using a NaCl anonymous sealed box (X25519 +
// XSalsa20-Poly1305). The wire format produced by golang.org/x/crypto/nacl/box
// SealAnonymous — ephemeral_pub(32) ‖ box(...) — is byte-compatible with
// PyNaCl's SealedBox, so Nova opens the base64 blob unchanged.
//
// This package is FAIL-CLOSED: if the public key cannot be fetched or parsed,
// Seal returns an error and callers MUST drop the field instead of emitting
// plaintext. Plaintext message content must never reach the webhook payload.
package seal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	"golang.org/x/crypto/nacl/box"
)

// cacheTTL is how long a fetched public key is served before a refresh is
// attempted. staleGrace bounds how long a previously-fetched key may keep
// being served while refreshes are failing, so a brief outage of Nova's
// pubkey endpoint never forces us to drop message bodies.
const (
	cacheTTL   = 60 * time.Second
	staleGrace = 10 * time.Minute
)

// ErrNoPubkey indicates the sealing public key is unavailable. Callers that
// receive this (directly or wrapped) MUST fail closed: drop the field, never
// fall back to clear text.
var ErrNoPubkey = errors.New("seal: public key unavailable")

var (
	mu          sync.Mutex
	cachedKey   [32]byte
	cachedEpoch int
	cachedAt    time.Time
	hasKey      bool

	httpClient = &http.Client{Timeout: 10 * time.Second}
)

// pubkeyResponse is the JSON contract of Nova's GET /internal/seal-pubkey:
// {"epoch_id": <int>, "public_key": "<base64 32-byte X25519>"}.
type pubkeyResponse struct {
	EpochID   int    `json:"epoch_id"`
	PublicKey string `json:"public_key"`
}

// Seal encrypts plaintext to the cached epoch public key and returns the epoch
// id Nova needs to open it plus the base64-encoded sealed ciphertext. On any
// failure it returns an error and an empty string; callers MUST NOT emit
// plaintext in that case.
func Seal(plaintext []byte) (epochID int, ciphertextB64 string, err error) {
	key, epoch, err := getKey()
	if err != nil {
		return 0, "", err
	}
	sealed, err := box.SealAnonymous(nil, plaintext, &key, rand.Reader)
	if err != nil {
		return 0, "", fmt.Errorf("seal: SealAnonymous: %w", err)
	}
	return epoch, base64.StdEncoding.EncodeToString(sealed), nil
}

// getKey returns a fresh-enough public key, refreshing from Nova when the TTL
// has elapsed. A previously-fetched key is served as a fallback while refreshes
// fail, but only within staleGrace; beyond that, or with no key ever fetched,
// it returns an error so callers fail closed.
func getKey() (key [32]byte, epoch int, err error) {
	mu.Lock()
	defer mu.Unlock()

	if hasKey && time.Since(cachedAt) < cacheTTL {
		return cachedKey, cachedEpoch, nil
	}

	fetchedKey, fetchedEpoch, fetchErr := fetch()
	if fetchErr != nil {
		if hasKey && time.Since(cachedAt) < staleGrace {
			// Ride out a transient outage with the last good key rather than
			// dropping message bodies. Still sealed, never plaintext.
			return cachedKey, cachedEpoch, nil
		}
		return [32]byte{}, 0, fetchErr
	}

	cachedKey = fetchedKey
	cachedEpoch = fetchedEpoch
	cachedAt = time.Now()
	hasKey = true
	return cachedKey, cachedEpoch, nil
}

// fetch performs the authenticated GET against Nova's pubkey endpoint and
// parses the response into a 32-byte X25519 key.
func fetch() (key [32]byte, epoch int, err error) {
	var zero [32]byte

	url := config.SealPubkeyURL
	if url == "" {
		return zero, 0, fmt.Errorf("%w: SEAL_PUBKEY_URL not configured", ErrNoPubkey)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return zero, 0, fmt.Errorf("%w: build request: %v", ErrNoPubkey, err)
	}
	if config.SealPubkeyToken != "" {
		req.Header.Set("X-Internal-Token", config.SealPubkeyToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return zero, 0, fmt.Errorf("%w: request: %v", ErrNoPubkey, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return zero, 0, fmt.Errorf("%w: status %d: %s", ErrNoPubkey, resp.StatusCode, string(body))
	}

	var pr pubkeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return zero, 0, fmt.Errorf("%w: decode body: %v", ErrNoPubkey, err)
	}

	raw, err := base64.StdEncoding.DecodeString(pr.PublicKey)
	if err != nil {
		return zero, 0, fmt.Errorf("%w: base64 public_key: %v", ErrNoPubkey, err)
	}
	if len(raw) != 32 {
		return zero, 0, fmt.Errorf("%w: public_key is %d bytes, want 32", ErrNoPubkey, len(raw))
	}

	copy(zero[:], raw)
	return zero, pr.EpochID, nil
}
