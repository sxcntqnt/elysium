// Package token handles JWT access and refresh token lifecycle.
//
// Three token varieties are supported:
//
//  1. Basic user token (Issue) — userID, nickname, email. No actor context.
//     Use for endpoints that need authentication but not authorisation.
//
//  2. Context-scoped user token (IssueContextToken) — all of the above plus
//     actor_id, actor_type, and flattened permission/policy-group arrays.
//     The caller sources these from Dgraph's getActiveContext query.
//     Use for endpoints that need role-based authorisation without a DB round-trip.
//
//  3. Service token (IssueServiceToken) — client_id, name, actor_type.
//     Issued on service account login.
//
// All three share the same Signer (Transit or HMAC) and the same Verify path.
// Verify returns a *domain.Principal whose fields are populated according to the
// token variety — callers use Principal.HasContext() to distinguish basic from
// context-scoped tokens.
package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"sxcntqnt/auth-service/internal/domain"
)

const refreshTokenBytes = 32 // 256 bits of entropy

// Signer is the interface the Manager depends on for cryptographic operations.
// Defined here (consumption site) — vault package implements it without
// importing this package, keeping the dependency direction clean.
type Signer interface {
	Sign(ctx context.Context, claims jwt.Claims) (string, error)
	Verify(ctx context.Context, tokenStr string) (*jwt.Token, error)
}

// Manager issues and validates JWTs for users and service accounts.
// Cryptographic operations are fully delegated to the injected Signer.
type Manager struct {
	signer         Signer
	issuer         string
	accessDuration time.Duration
}

// New constructs a Manager. Panics if signer is nil or issuer is empty.
func New(signer Signer, issuer string, accessDuration time.Duration) *Manager {
	if signer == nil {
		panic("token: signer must not be nil")
	}
	if issuer == "" {
		panic("token: issuer must not be empty")
	}
	return &Manager{signer: signer, issuer: issuer, accessDuration: accessDuration}
}

// jwtClaims is the internal JWT payload for all three token varieties.
// Unused fields are omitted from the serialised JSON via omitempty.
//
// Short claim keys (perms, dperms, pgroups) keep the token compact —
// permission arrays can be long for highly-permissioned actors.
type jwtClaims struct {
	jwt.RegisteredClaims

	// ── Shared ───────────────────────────────────────────────────────────────
	Kind      string `json:"kind"`                 // "user" | "service"
	ActorType string `json:"actor_type,omitempty"` // one of the 24 Dgraph ActorType values

	// ── User fields ───────────────────────────────────────────────────────────
	UserID   string `json:"user_id,omitempty"`
	ActorID  string `json:"actor_id,omitempty"` // Dgraph Actor node ID; empty on basic tokens
	Nickname string `json:"nickname,omitempty"`
	Email    string `json:"email,omitempty"`

	// Flattened allow-only action strings from the active actor context.
	// Short names keep the token small — "perms" not "permissions".
	Permissions          []string `json:"perms,omitempty"`
	DelegatedPermissions []string `json:"dperms,omitempty"`
	PolicyGroups         []string `json:"pgroups,omitempty"` // policy group IDs

	// ── Service fields ────────────────────────────────────────────────────────
	ClientID    string `json:"client_id,omitempty"`
	ServiceName string `json:"svc_name,omitempty"`
}

// ── Issue (basic user token) ──────────────────────────────────────────────────

// Issue mints a basic access + refresh token pair for a human user.
// The token carries userID, nickname, email, and kind:"user" only.
// No actor context is embedded — use IssueContextToken after Dgraph resolves
// the active context.
func (m *Manager) Issue(ctx context.Context, userID, nickname, email string) (*domain.TokenPair, error) {
	now := time.Now()
	return m.signPair(ctx, jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessDuration)),
			Issuer:    m.issuer,
			Subject:   userID,
		},
		Kind:     string(domain.PrincipalKindUser),
		UserID:   userID,
		Nickname: nickname,
		Email:    email,
	})
}

// ── IssueContextToken (context-scoped user token) ─────────────────────────────

// IssueContextToken mints a context-scoped access + refresh token pair.
// It embeds the full ActiveContext fields — actor_id, actor_type, and
// flattened permission arrays — so downstream services can make fast
// authorisation decisions without querying Dgraph.
//
// The caller must obtain the ContextActivationInput from Dgraph's
// getActiveContext query BEFORE calling this method. The auth service does not
// query Dgraph — it signs whatever context Dgraph's resolver has already produced.
//
// Returns ErrInvalidInput if the actor_type is not one of the 24 valid values,
// or if actor_id is empty.
func (m *Manager) IssueContextToken(ctx context.Context, input domain.ContextActivationInput) (*domain.TokenPair, error) {
	if !input.ActorType.IsValid() {
		return nil, fmt.Errorf("%w: actor_type %q is not a valid ActorType", domain.ErrInvalidInput, input.ActorType)
	}
	if input.ActorID == "" {
		return nil, fmt.Errorf("%w: actor_id must not be empty", domain.ErrInvalidInput)
	}

	now := time.Now()
	return m.signPair(ctx, jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessDuration)),
			Issuer:    m.issuer,
			Subject:   input.UserID,
		},
		Kind:                 string(domain.PrincipalKindUser),
		ActorType:            string(input.ActorType),
		UserID:               input.UserID,
		ActorID:              input.ActorID,
		Nickname:             input.Nickname,
		Email:                input.Email,
		Permissions:          input.Permissions,
		DelegatedPermissions: input.DelegatedPermissions,
		PolicyGroups:         input.PolicyGroups,
	})
}

// ── IssueServiceToken (service account token) ─────────────────────────────────

// IssueServiceToken mints a service account access + refresh token pair.
// The token carries client_id, name, kind:"service", and actor_type.
func (m *Manager) IssueServiceToken(ctx context.Context, clientID, name string, actorType domain.ActorType) (*domain.TokenPair, error) {
	now := time.Now()
	return m.signPair(ctx, jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessDuration)),
			Issuer:    m.issuer,
			Subject:   clientID,
		},
		Kind:        string(domain.PrincipalKindService),
		ActorType:   string(actorType),
		ClientID:    clientID,
		ServiceName: name,
	})
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

// signPair signs the claims and generates a random refresh token.
func (m *Manager) signPair(ctx context.Context, claims jwtClaims) (*domain.TokenPair, error) {
	signed, err := m.signer.Sign(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("token: sign: %w", err)
	}
	refresh, err := secureRandomString(refreshTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("token: generate refresh token: %w", err)
	}
	return &domain.TokenPair{
		AccessToken:  signed,
		RefreshToken: refresh,
		ExpiresIn:    int64(m.accessDuration.Seconds()),
	}, nil
}

// ── Verify ────────────────────────────────────────────────────────────────────

// Verify validates an access token and returns the embedded Principal.
// Works for all three token varieties — the caller uses Principal.HasContext()
// and Principal.Kind to determine which fields are populated.
func (m *Manager) Verify(ctx context.Context, tokenString string) (*domain.Principal, error) {
	tok, err := m.signer.Verify(ctx, tokenString)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrTokenInvalid
	}

	mapClaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, domain.ErrTokenInvalid
	}

	kind := domain.PrincipalKind(strClaim(mapClaims, "kind"))

	switch kind {
	case domain.PrincipalKindUser:
		userID := strClaim(mapClaims, "user_id")
		if userID == "" {
			return nil, domain.ErrTokenInvalid
		}
		return &domain.Principal{
			Kind:                 domain.PrincipalKindUser,
			ActorType:            domain.ActorType(strClaim(mapClaims, "actor_type")),
			UserID:               userID,
			ActorID:              strClaim(mapClaims, "actor_id"),
			Nickname:             strClaim(mapClaims, "nickname"),
			Email:                strClaim(mapClaims, "email"),
			Permissions:          stringSliceClaim(mapClaims, "perms"),
			DelegatedPermissions: stringSliceClaim(mapClaims, "dperms"),
			PolicyGroups:         stringSliceClaim(mapClaims, "pgroups"),
		}, nil

	case domain.PrincipalKindService:
		clientID := strClaim(mapClaims, "client_id")
		if clientID == "" {
			return nil, domain.ErrTokenInvalid
		}
		return &domain.Principal{
			Kind:      domain.PrincipalKindService,
			ActorType: domain.ActorType(strClaim(mapClaims, "actor_type")),
			ClientID:  clientID,
			Name:      strClaim(mapClaims, "svc_name"),
		}, nil

	default:
		// Tokens without a kind claim are rejected — legacy or forged.
		return nil, domain.ErrTokenInvalid
	}
}

// ── Claim extraction helpers ──────────────────────────────────────────────────

// strClaim safely extracts a string from a MapClaims map.
func strClaim(m jwt.MapClaims, key string) string {
	v, _ := m[key].(string)
	return v
}

// stringSliceClaim extracts a []string from a MapClaims map.
// JWT libraries unmarshal JSON arrays as []interface{}, so we handle that case.
func stringSliceClaim(m jwt.MapClaims, key string) []string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// secureRandomString returns n random bytes encoded as URL-safe base64.
// Uses crypto/rand — never math/rand for secrets.
func secureRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
