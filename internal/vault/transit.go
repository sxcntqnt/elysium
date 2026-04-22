package vault

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer is the interface the token manager depends on.
// Two implementations live in this file:
//   - TransitSigner — signs via Vault Transit (key material never leaves Vault)
//   - HMACSigner    — signs with a raw key from Vault KV v2 (dev / non-Transit)
//
// The composition root selects one; swapping to a Keygraph signer only requires
// satisfying this interface — no other layer changes.
type Signer interface {
	Sign(ctx context.Context, claims jwt.Claims) (string, error)
	Verify(ctx context.Context, tokenStr string) (*jwt.Token, error)
}

// ─── Transit Signer ───────────────────────────────────────────────────────────

// TransitSigner signs and verifies JWTs using the Vault Transit secrets engine.
// The HMAC key never leaves Vault; the service only ever sees the signature.
//
// Required Vault policy:
//
//	path "transit/hmac/<key-name>"   { capabilities = ["update"] }
//	path "transit/verify/<key-name>" { capabilities = ["update"] }
type TransitSigner struct {
	client     *Client
	mount      string
	keyName    string
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewTransitSigner creates a TransitSigner. The Transit key must already exist:
//
//	vault write -f transit/keys/<keyName> type=hmac
func NewTransitSigner(
	client *Client,
	mount, keyName, issuer string,
	accessTTL, refreshTTL time.Duration,
) *TransitSigner {
	return &TransitSigner{
		client:     client,
		mount:      mount,
		keyName:    keyName,
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// Sign builds a JWT, encodes header + payload, delegates the HMAC operation
// to Vault Transit, and returns the assembled token string.
//
// We construct the JWT manually rather than using golang-jwt's SignedString
// because there is no way to register a custom signing method that requires a
// live context — Vault Transit calls are network operations.
func (ts *TransitSigner) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("transit sign: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := header + "." + payload
	sig, err := ts.vaultHMAC(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify validates a JWT using Vault Transit's HMAC verify endpoint, then
// validates standard claims using jwt.NewValidator (jwt/v5 API).
// The cryptographic check happens in Vault — the service never sees the key.
func (ts *TransitSigner) Verify(ctx context.Context, tokenStr string) (*jwt.Token, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("transit verify: malformed token")
	}

	// 1. Verify the signature via Vault (cryptographic gate first).
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("transit verify: decode signature: %w", err)
	}
	if err := ts.vaultVerify(ctx, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}

	// 2. Decode the payload — signature is already proven valid.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("transit verify: decode payload: %w", err)
	}

	var claims jwt.MapClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("transit verify: unmarshal claims: %w", err)
	}

	// 3. Validate standard registered claims using the jwt/v5 Validator.
	//    MapClaims.Valid() was removed in v5 — use jwt.NewValidator instead.
	//    WithIssuedAt() opts-in to iat validation (disabled by default in v5).
	validator := jwt.NewValidator(
		jwt.WithIssuedAt(),
		jwt.WithIssuer(ts.issuer),
	)
	if err := validator.Validate(claims); err != nil {
		return nil, fmt.Errorf("transit verify: claims invalid: %w", err)
	}

	return &jwt.Token{Raw: tokenStr, Claims: claims, Valid: true}, nil
}

// vaultHMAC calls the Vault Transit HMAC endpoint and returns the raw signature bytes.
func (ts *TransitSigner) vaultHMAC(ctx context.Context, data []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/hmac/%s", ts.mount, ts.keyName)
	resp, err := ts.client.Raw().Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(data),
		"algorithm": "sha2-256",
	})
	if err != nil {
		return nil, fmt.Errorf("vault transit hmac: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("vault transit hmac: empty response")
	}

	// Vault returns "vault:v1:<base64mac>" — strip the version prefix.
	raw, ok := resp.Data["hmac"].(string)
	if !ok {
		return nil, fmt.Errorf("vault transit hmac: unexpected response shape")
	}
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault transit hmac: unexpected format %q", raw)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault transit hmac: base64 decode: %w", err)
	}
	return sig, nil
}

// vaultVerify calls the Vault Transit verify endpoint to check an HMAC.
func (ts *TransitSigner) vaultVerify(ctx context.Context, data, sig []byte) error {
	path := fmt.Sprintf("%s/verify/%s", ts.mount, ts.keyName)
	resp, err := ts.client.Raw().Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(data),
		"hmac":      "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
		"algorithm": "sha2-256",
	})
	if err != nil {
		return fmt.Errorf("vault transit verify: %w", err)
	}
	if resp == nil || resp.Data == nil {
		return fmt.Errorf("vault transit verify: empty response")
	}
	valid, _ := resp.Data["valid"].(bool)
	if !valid {
		return fmt.Errorf("vault transit verify: signature invalid")
	}
	return nil
}

// ─── HMAC Signer (KV v2 key, dev / non-Transit mode) ─────────────────────────

// HMACSigner signs JWTs with an HMAC-SHA256 key loaded from Vault KV v2.
// Use this when the Transit engine is unavailable (e.g. local dev Vault).
//
// The key is loaded once at construction time. For zero-downtime key rotation
// use TransitSigner with Vault's built-in key versioning instead.
type HMACSigner struct {
	key        []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewHMACSigner creates an HMACSigner from raw key material.
// The key should be loaded from Vault KV v2 via SecretManager.ReadAuthSecrets.
func NewHMACSigner(key []byte, issuer string, accessTTL, refreshTTL time.Duration) (*HMACSigner, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("hmac signer: key must be at least 32 bytes, got %d", len(key))
	}
	return &HMACSigner{
		key:        key,
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func (h *HMACSigner) Sign(_ context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(h.key)
	if err != nil {
		return "", fmt.Errorf("hmac signer: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a JWT using the jwt/v5 API.
// jwt.Parse in v5 calls the Validator internally with the options provided,
// so WithIssuer and WithIssuedAt are applied automatically.
func (h *HMACSigner) Verify(_ context.Context, tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("hmac signer: unexpected signing method %T", t.Method)
			}
			return h.key, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuedAt(),      // opt-in to iat validation (disabled by default in v5)
		jwt.WithIssuer(h.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("hmac signer: verify: %w", err)
	}

	// Constant-time issuer comparison as an extra defence against timing oracles.
	// WithIssuer above already rejects mismatches; this adds defence-in-depth.
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("hmac signer: unexpected claims type")
	}
	iss, _ := mapClaims["iss"].(string)
	if !hmac.Equal([]byte(h.issuer), []byte(iss)) {
		return nil, fmt.Errorf("hmac signer: issuer mismatch")
	}

	return token, nil
}
