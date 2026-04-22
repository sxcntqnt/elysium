// Package vault wraps the HashiCorp Vault API into three focused concerns:
//   - Client  — AppRole authentication, token renewal, graceful shutdown
//   - Secrets — KV v2 static-secret reads (DSN, config values)
//   - Transit — signing and verification of JWTs via the Transit engine
//
// Nothing below this package knows about Vault. The composition root wires it
// at startup and the token manager receives a Signer — the same boundary that
// will accept a Keygraph signer in the future.
package vault

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client is a Vault-authenticated client that keeps its token renewed.
// Construct via New; release via Shutdown when the process exits.
type Client struct {
	raw    *vaultapi.Client
	secret *vaultapi.Secret // current AppRole login secret (carries TTL)
	logger *slog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Config holds the parameters needed to authenticate to Vault via AppRole.
// Pull all values from environment variables at the composition root —
// never hard-code credentials in source.
type Config struct {
	// Address is the Vault server URL, e.g. "https://vault.example.com:8200".
	Address string

	// RoleID and SecretID are the AppRole credentials.
	// In production use response-wrapping for zero-touch SecretID delivery.
	RoleID   string
	SecretID string

	// Namespace is optional; empty means the root namespace.
	Namespace string

	// TLSConfig controls mTLS verification. Always set CACert or rely on the
	// system pool in production — never set Insecure: true outside local dev.
	TLSConfig *vaultapi.TLSConfig
}

// New creates a Vault client, performs AppRole login, and starts the
// background token-renewal goroutine. Call Shutdown when the process exits.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = cfg.Address

	if cfg.TLSConfig != nil {
		if err := vcfg.ConfigureTLS(cfg.TLSConfig); err != nil {
			return nil, fmt.Errorf("vault: configure TLS: %w", err)
		}
	}

	raw, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	if cfg.Namespace != "" {
		raw.SetNamespace(cfg.Namespace)
	}

	// AppRole login — exchange RoleID + SecretID for a Vault token.
	loginSecret, err := raw.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
		"role_id":   cfg.RoleID,
		"secret_id": cfg.SecretID,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: approle login: %w", err)
	}
	if loginSecret == nil || loginSecret.Auth == nil {
		return nil, fmt.Errorf("vault: approle login returned empty auth")
	}

	raw.SetToken(loginSecret.Auth.ClientToken)

	c := &Client{
		raw:    raw,
		secret: loginSecret,
		logger: logger,
		stopCh: make(chan struct{}),
	}

	c.wg.Add(1)
	go c.renewToken()

	logger.Info("vault: authenticated via AppRole",
		slog.Bool("renewable", loginSecret.Auth.Renewable),
		slog.Int("lease_duration_s", loginSecret.Auth.LeaseDuration),
	)
	return c, nil
}

// Raw returns the underlying Vault API client used by Secrets and Transit.
// Do not call SetToken on the returned client — Client owns the token lifecycle.
func (c *Client) Raw() *vaultapi.Client { return c.raw }

// Shutdown signals the renewal goroutine to stop and waits for it to exit.
// Call this last in the graceful shutdown sequence — after all Vault API
// calls (Transit sign/verify, KV reads) have completed.
func (c *Client) Shutdown() {
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("vault: token renewal stopped")
}

// renewToken runs in the background and renews the Vault token before it
// expires. It uses time.NewTimer (not time.After) to avoid goroutine leaks.
//
// Strategy: sleep for 2/3 of the remaining TTL, then renew.
// If renewal fails, retry every 5 seconds until success or shutdown.
func (c *Client) renewToken() {
	defer c.wg.Done()

	for {
		ttl, err := c.secret.TokenTTL()
		if err != nil || ttl <= 0 {
			c.logger.Warn("vault: token is not renewable or TTL unavailable",
				slog.String("err", fmt.Sprintf("%v", err)))
			return
		}

		// Sleep for 2/3 of TTL, minimum 5 seconds.
		sleepFor := (ttl * 2) / 3
		if sleepFor < 5*time.Second {
			sleepFor = 5 * time.Second
		}

		timer := time.NewTimer(sleepFor)
		select {
		case <-c.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		renewed, err := c.raw.Auth().Token().RenewSelf(0)
		if err != nil {
			c.logger.Error("vault: token renewal failed — retrying in 5s",
				slog.String("err", err.Error()))

			retryTimer := time.NewTimer(5 * time.Second)
			select {
			case <-c.stopCh:
				retryTimer.Stop()
				return
			case <-retryTimer.C:
				continue
			}
		}

		c.secret = renewed
		c.logger.Info("vault: token renewed",
			slog.Int("lease_duration_s", renewed.Auth.LeaseDuration))
	}
}
