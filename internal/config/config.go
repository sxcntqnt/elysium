// Package config holds the fully-resolved runtime configuration for the
// auth service. All sensitive values (keys, DSN, bcrypt cost) originate
// from Vault KV v2. Non-sensitive values (ports, log level, signer mode)
// come from environment variables.
//
// Call Load once at startup. The returned Config is immutable — safe to
// share across goroutines without locking.
package config

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"sxcntqnt/auth-service/internal/vault"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Server   ServerConfig
	Auth     AuthConfig
	Database DatabaseConfig
	Vault    VaultConfig
}

// ServerConfig holds network and observability settings sourced from env vars.
type ServerConfig struct {
	HTTPAddr        string
	GRPCAddr        string
	ShutdownTimeout time.Duration
	LogLevel        string // "debug" | "info" | "warn" | "error"
	Env             string // "development" | "production"

	// Rate limiting parameters for the HTTP middleware.
	RateLimitRPS   float64
	RateLimitBurst int
}

// AuthConfig holds JWT and bcrypt parameters sourced from Vault KV v2.
type AuthConfig struct {
	Issuer          string
	BcryptCost      int           // from Vault; floor enforced in service.New
	AccessTokenTTL  time.Duration // from Vault
	RefreshTokenTTL time.Duration // from Vault

	// SigningKey is the raw HMAC key, populated only when UseTransit is false.
	SigningKey []byte

	// UseTransit selects which Signer the composition root wires.
	//   true  → vault.TransitSigner (key material never leaves Vault)
	//   false → vault.HMACSigner    (key from KV v2; simpler, dev-friendly)
	UseTransit bool

	// TransitKeyName and TransitMount are used only when UseTransit is true.
	TransitKeyName string // e.g. "auth-service-jwt"
	TransitMount   string // e.g. "transit"
}

// DatabaseConfig holds Dgraph connection parameters sourced from Vault KV v2.
type DatabaseConfig struct {
	DgraphTarget     string
	TLSEnabled       bool
	DgraphApplySchema bool // non-sensitive; from env var
}

// VaultConfig holds Vault bootstrap parameters read from the environment.
// These are the only values that CANNOT come from Vault — they are the
// bootstrap credentials used to reach Vault in the first place.
type VaultConfig struct {
	Address   string
	RoleID    string
	SecretID  string
	Namespace string
	KVMount   string
	KVPrefix  string
}

// VaultConfigFromEnv reads the Vault bootstrap parameters from the environment.
// Call this before instantiating the Vault client.
//
// Required environment variables:
//
//	VAULT_ADDR       default "http://127.0.0.1:8200"
//	VAULT_ROLE_ID    required
//	VAULT_SECRET_ID  required
//	VAULT_NAMESPACE  optional (root namespace if empty)
//	VAULT_KV_MOUNT   default "secret"
//	VAULT_KV_PREFIX  default "auth-service"
func VaultConfigFromEnv() VaultConfig {
	return VaultConfig{
		Address:   envStr("VAULT_ADDR", "http://127.0.0.1:8200"),
		RoleID:    os.Getenv("VAULT_ROLE_ID"),
		SecretID:  os.Getenv("VAULT_SECRET_ID"),
		Namespace: os.Getenv("VAULT_NAMESPACE"),
		KVMount:   envStr("VAULT_KV_MOUNT", "secret"),
		KVPrefix:  envStr("VAULT_KV_PREFIX", "auth-service"),
	}
}

// Load fetches all sensitive configuration from Vault KV v2 using the
// provided SecretManager, then merges non-sensitive env var values.
//
// Non-sensitive environment variables:
//
//	AUTH_HTTP_ADDR        default ":8080"
//	AUTH_GRPC_ADDR        default ":9090"
//	AUTH_SHUTDOWN_TIMEOUT default "30s"
//	AUTH_LOG_LEVEL        default "info"
//	AUTH_ENV              default "production"
//	AUTH_RATE_LIMIT_RPS   default "10"
//	AUTH_RATE_LIMIT_BURST default "30"
//	AUTH_ISSUER           default "auth-service"
//	AUTH_USE_TRANSIT      default "true"
//	AUTH_TRANSIT_KEY      default "auth-service-jwt"
//	AUTH_TRANSIT_MOUNT    default "transit"
//	DGRAPH_APPLY_SCHEMA   default "true"
func Load(ctx context.Context, sm *vault.SecretManager) (*Config, error) {
	authSecrets, err := sm.ReadAuthSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: load auth secrets: %w", err)
	}

	dbSecrets, err := sm.ReadDatabaseSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: load database secrets: %w", err)
	}

	rps, err := strconv.ParseFloat(envStr("AUTH_RATE_LIMIT_RPS", "10"), 64)
	if err != nil {
		return nil, fmt.Errorf("config: AUTH_RATE_LIMIT_RPS: %w", err)
	}
	burst, err := strconv.Atoi(envStr("AUTH_RATE_LIMIT_BURST", "30"))
	if err != nil {
		return nil, fmt.Errorf("config: AUTH_RATE_LIMIT_BURST: %w", err)
	}
	shutdownTimeout, err := time.ParseDuration(envStr("AUTH_SHUTDOWN_TIMEOUT", "30s"))
	if err != nil {
		return nil, fmt.Errorf("config: AUTH_SHUTDOWN_TIMEOUT: %w", err)
	}

	return &Config{
		Server: ServerConfig{
			HTTPAddr:        envStr("AUTH_HTTP_ADDR", ":8080"),
			GRPCAddr:        envStr("AUTH_GRPC_ADDR", ":9090"),
			ShutdownTimeout: shutdownTimeout,
			LogLevel:        envStr("AUTH_LOG_LEVEL", "info"),
			Env:             envStr("AUTH_ENV", "production"),
			RateLimitRPS:    rps,
			RateLimitBurst:  burst,
		},
		Auth: AuthConfig{
			Issuer:          envStr("AUTH_ISSUER", "auth-service"),
			BcryptCost:      authSecrets.BcryptCost,
			AccessTokenTTL:  authSecrets.AccessTokenTTL,
			RefreshTokenTTL: authSecrets.RefreshTokenTTL,
			SigningKey:       authSecrets.JWTSigningKey,
			UseTransit:      envBool("AUTH_USE_TRANSIT", true),
			TransitKeyName:  envStr("AUTH_TRANSIT_KEY", "auth-service-jwt"),
			TransitMount:    envStr("AUTH_TRANSIT_MOUNT", "transit"),
		},
		Database: DatabaseConfig{
			DgraphTarget:     dbSecrets.DgraphTarget,
			TLSEnabled:       dbSecrets.TLSEnabled,
			DgraphApplySchema: envBool("DGRAPH_APPLY_SCHEMA", true),
		},
	}, nil
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
