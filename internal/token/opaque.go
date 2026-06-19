package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Token lifetime constants. These are the defaults; the service layer
// accepts overrides via config so they can be tuned without recompilation.
const (
	// DefaultAccessTTL is the lifetime of an opaque access token.
	// Short window limits the blast radius of a stolen token to 15 minutes.
	DefaultAccessTTL = 15 * time.Minute

	// DefaultRefreshTTL is the absolute lifetime of a refresh token family.
	// After this the user must re-authenticate from scratch (MFA re-challenge
	// if configured). 30 days balances UX with security.
	DefaultRefreshTTL = 30 * 24 * time.Hour

	// MaxSessionLifetime is the hard ceiling on any session regardless of
	// refresh activity. Forces periodic full re-authentication.
	MaxSessionLifetime = 90 * 24 * time.Hour
)

// Prefix constants make token type immediately identifiable in logs
// without decoding, and prevent accidental cross-submission between endpoints.
const (
	prefixAccess  = "atk_"
	prefixRefresh = "rtk_"
	prefixJTI     = "jti_"
)

// OpaqueToken holds both the raw value (returned once to the client,
// never persisted) and the hash (stored in Dgraph for O(1) lookup).
type OpaqueToken struct {
	Raw  string // returned to client; never stored
	Hash string // SHA-256 hex; stored in Dgraph
}

// GenerateAccessToken mints a new opaque access token.
// Format: atk_<32 bytes of crypto/rand as hex> — 68 chars total.
func GenerateAccessToken() (OpaqueToken, error) {
	return generate(prefixAccess)
}

// GenerateRefreshToken mints a new opaque refresh token.
// Format: rtk_<32 bytes of crypto/rand as hex>.
func GenerateRefreshToken() (OpaqueToken, error) {
	return generate(prefixRefresh)
}

// GenerateJTI mints a unique identifier for a refresh token generation.
// Used for replay detection: if a rotated-away JTI is presented, the
// entire session family is immediately revoked.
func GenerateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating JTI entropy: %w", err)
	}
	return prefixJTI + hex.EncodeToString(b), nil
}

// Hash returns the SHA-256 hex digest of a raw token string.
// This is the canonical lookup key stored in Dgraph. Calling Hash on a
// token received from the client lets us find the session record without
// ever persisting the plaintext credential.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// AccessExpiry returns the expiry time for a newly issued access token
// relative to now, using the provided TTL (or the default if zero).
func AccessExpiry(ttl time.Duration) time.Time {
	if ttl == 0 {
		ttl = DefaultAccessTTL
	}
	return time.Now().Add(ttl)
}

// RefreshExpiry returns the expiry time for a newly issued refresh token.
func RefreshExpiry(ttl time.Duration) time.Time {
	if ttl == 0 {
		ttl = DefaultRefreshTTL
	}
	return time.Now().Add(ttl)
}

// generate is the shared implementation for access and refresh token minting.
// It reads 32 bytes from crypto/rand, encodes them as hex, and prepends
// the type prefix. The raw value is returned alongside its SHA-256 hash.
func generate(prefix string) (OpaqueToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return OpaqueToken{}, fmt.Errorf("generating token entropy: %w", err)
	}
	raw := prefix + hex.EncodeToString(b)
	return OpaqueToken{
		Raw:  raw,
		Hash: Hash(raw),
	}, nil
}
