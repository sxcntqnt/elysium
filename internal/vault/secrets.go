package vault

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// SecretManager reads static secrets from Vault KV v2.
// All reads are strongly typed — callers never receive raw map[string]interface{}.
type SecretManager struct {
	client  *Client
	kvMount string // e.g. "secret"
	prefix  string // e.g. "auth-service" — prepended to every secret path
}

// NewSecretManager creates a SecretManager reading from <kvMount>/data/<prefix>/...
//
// Expected KV layout:
//
//	secret/auth-service/database  → dgraph_target, tls_enabled
//	secret/auth-service/jwt       → signing_key, access_ttl, refresh_ttl
//	secret/auth-service/bcrypt    → cost
func NewSecretManager(client *Client, kvMount, prefix string) *SecretManager {
	return &SecretManager{client: client, kvMount: kvMount, prefix: prefix}
}

// AuthSecrets carries the JWT and bcrypt parameters sourced from Vault KV v2.
// These are fetched once at startup; layers that need them receive copies of
// the relevant fields — not a reference to this struct.
type AuthSecrets struct {
	// JWTSigningKey is the HMAC-SHA256 key used in local-HMAC mode.
	// Unused when UseTransit is true — the Transit engine holds the key material.
	JWTSigningKey []byte

	// AccessTokenTTL is how long access tokens live before expiry.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is how long refresh tokens are valid.
	RefreshTokenTTL time.Duration

	// BcryptCost is the work factor passed to bcrypt when hashing passwords.
	// The auth service enforces a floor of 12; Vault controls the ceiling.
	BcryptCost int
}

// DatabaseSecrets carries Dgraph (or future Keygraph) connection parameters.
type DatabaseSecrets struct {
	// DgraphTarget is the gRPC target string, e.g. "localhost:9080".
	DgraphTarget string

	// TLSEnabled controls whether the Dgraph gRPC connection uses TLS.
	TLSEnabled bool
}

// ReadAuthSecrets fetches the jwt and bcrypt secrets from KV v2.
// Call once at startup; re-read on a SIGHUP if live rotation is needed.
func (sm *SecretManager) ReadAuthSecrets(ctx context.Context) (AuthSecrets, error) {
	jwtData, err := sm.readKV(ctx, "jwt")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: read jwt config: %w", err)
	}

	bcryptData, err := sm.readKV(ctx, "bcrypt")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: read bcrypt config: %w", err)
	}

	signingKey, err := requireString(jwtData, "signing_key")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: jwt.signing_key: %w", err)
	}

	accessTTLStr, err := requireString(jwtData, "access_ttl")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: jwt.access_ttl: %w", err)
	}
	accessTTL, err := time.ParseDuration(accessTTLStr)
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: jwt.access_ttl parse: %w", err)
	}

	refreshTTLStr, err := requireString(jwtData, "refresh_ttl")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: jwt.refresh_ttl: %w", err)
	}
	refreshTTL, err := time.ParseDuration(refreshTTLStr)
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: jwt.refresh_ttl parse: %w", err)
	}

	costStr, err := requireString(bcryptData, "cost")
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: bcrypt.cost: %w", err)
	}
	cost, err := strconv.Atoi(costStr)
	if err != nil {
		return AuthSecrets{}, fmt.Errorf("vault secrets: bcrypt.cost parse: %w", err)
	}
	if cost < 12 {
		return AuthSecrets{}, fmt.Errorf("vault secrets: bcrypt cost %d is below the minimum of 12", cost)
	}

	return AuthSecrets{
		JWTSigningKey:   []byte(signingKey),
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
		BcryptCost:      cost,
	}, nil
}

// ReadDatabaseSecrets fetches the database secret from KV v2.
func (sm *SecretManager) ReadDatabaseSecrets(ctx context.Context) (DatabaseSecrets, error) {
	data, err := sm.readKV(ctx, "database")
	if err != nil {
		return DatabaseSecrets{}, fmt.Errorf("vault secrets: read database config: %w", err)
	}

	target, err := requireString(data, "dgraph_target")
	if err != nil {
		return DatabaseSecrets{}, fmt.Errorf("vault secrets: database.dgraph_target: %w", err)
	}

	tlsStr, _ := data["tls_enabled"].(string) // optional; defaults to false
	return DatabaseSecrets{
		DgraphTarget: target,
		TLSEnabled:   tlsStr == "true",
	}, nil
}

// readKV reads a single KV v2 secret at <mount>/data/<prefix>/<name>.
func (sm *SecretManager) readKV(ctx context.Context, name string) (map[string]interface{}, error) {
	path := fmt.Sprintf("%s/data/%s/%s", sm.kvMount, sm.prefix, name)

	secret, err := sm.client.Raw().Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("kv read %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("kv read %q: secret not found", path)
	}

	// KV v2 nests the actual payload under the "data" key.
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("kv read %q: unexpected data shape", path)
	}
	return data, nil
}

// requireString extracts a non-empty string from a Vault KV data map.
func requireString(data map[string]interface{}, key string) (string, error) {
	v, ok := data[key]
	if !ok {
		return "", fmt.Errorf("missing key %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("key %q must be a non-empty string", key)
	}
	return s, nil
}
