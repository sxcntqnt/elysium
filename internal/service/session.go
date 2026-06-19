package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/repository"
	dgraph "sxcntqnt/auth-service/internal/repository/dgraph"
	"sxcntqnt/auth-service/internal/token"
)

// SessionConfig holds tuneable lifetime values so they can be driven from
// config without touching service logic.
type SessionConfig struct {
	AccessTTL  time.Duration // default: 15m
	RefreshTTL time.Duration // default: 30d
}

func (c SessionConfig) accessTTL() time.Duration {
	if c.AccessTTL == 0 {
		return token.DefaultAccessTTL
	}
	return c.AccessTTL
}

func (c SessionConfig) refreshTTL() time.Duration {
	if c.RefreshTTL == 0 {
		return token.DefaultRefreshTTL
	}
	return c.RefreshTTL
}

// SessionService manages the full lifecycle of opaque-token sessions:
// creation, validation (used by /auth/verify), refresh token rotation,
// and revocation (logout, compromise response).
type SessionService struct {
	sessions repository.SessionRepository
	cfg      SessionConfig
	log      *slog.Logger
}

// NewSessionService constructs a SessionService. Follows the existing
// pattern in this codebase of constructor injection at the composition root.
func NewSessionService(
	sessions repository.SessionRepository,
	cfg SessionConfig,
	log *slog.Logger,
) *SessionService {
	return &SessionService{sessions: sessions, cfg: cfg, log: log}
}

// --- CreateSession ---

// CreateInput carries the identity and authorization data needed to open
// a new session after a successful login or service-account authentication.
type CreateSessionInput struct {
	Kind      domain.PrincipalKind
	UserID    string
	ClientID  string
	ActorID   string
	ActorType domain.ActorType

	Permissions          []string
	DelegatedPermissions []string
	PolicyGroups         []string
	PermissionVersion    uint64

	UserAgent string
	IPAddress string
}

// CreateSessionOutput holds the raw token strings returned to the caller.
// These are the only moment the raw values are accessible; after this they
// are gone from the service layer forever.
type CreateSessionOutput struct {
	Session      *domain.Session
	AccessToken  string // raw, returned to client once
	RefreshToken string // raw, returned to client once
}

// Create opens a new session after a successful credential check. It mints
// a fresh access/refresh token pair, hashes both, and persists the session
// record. The raw tokens are returned in CreateSessionOutput for the handler
// to deliver to the client.
func (s *SessionService) Create(ctx context.Context, in CreateSessionInput) (*CreateSessionOutput, error) {
	atk, err := token.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}
	rtk, err := token.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}
	jti, err := token.GenerateJTI()
	if err != nil {
		return nil, fmt.Errorf("generating refresh JTI: %w", err)
	}

	now := time.Now()
	sess, err := s.sessions.Create(ctx, domain.SessionCreateInput{
		Kind:      in.Kind,
		UserID:    in.UserID,
		ClientID:  in.ClientID,
		ActorID:   in.ActorID,
		ActorType: in.ActorType,

		AccessTokenHash:  atk.Hash,
		RefreshTokenHash: rtk.Hash,
		RefreshJTI:       jti,

		Permissions:          in.Permissions,
		DelegatedPermissions: in.DelegatedPermissions,
		PolicyGroups:         in.PolicyGroups,
		PermissionVersion:    in.PermissionVersion,

		ExpiresAt:        now.Add(s.cfg.accessTTL()),
		RefreshExpiresAt: now.Add(s.cfg.refreshTTL()),

		UserAgent: in.UserAgent,
		IPAddress: in.IPAddress,
	})
	if err != nil {
		return nil, fmt.Errorf("persisting session: %w", err)
	}

	return &CreateSessionOutput{
		Session:      sess,
		AccessToken:  atk.Raw,
		RefreshToken: rtk.Raw,
	}, nil
}

// AccessTTL exposes the configured access token lifetime so handlers can
// report expires_in without duplicating the default-fallback logic.
func (s *SessionService) AccessTTL() time.Duration {
	return s.cfg.accessTTL()
}

// VerifyToken looks up the session for a raw access token, checks that it
// is still active, and returns the Principal for header injection.
//
// Named VerifyToken (not Validate) so *SessionService satisfies
// middleware.TokenVerifier directly — middleware.Authenticate takes a
// TokenVerifier and was originally wired against *service.AuthService's
// VerifyToken (JWT-backed). Now that token minting and verification both
// live in SessionService, this is the one place that needs to match that
// existing interface shape; nothing in middleware/middleware.go changes.
//
// Error translation at this boundary: lookupAndCheck returns this package's
// own sentinels (ErrSessionNotFound, ErrSessionRevoked, ErrSessionExpired),
// which is correct for every other caller of lookupAndCheck/ValidateSession
// (refresh, RevokeSession, etc. legitimately want the precise service.*
// sentinel). But middleware.Authenticate's error handling is written against
// domain.ErrTokenExpired via errors.Is, and middleware/middleware.go
// deliberately has no dependency on the service package — its TokenVerifier
// contract is meant to be backend-agnostic. So VerifyToken translates this
// package's sentinels into the domain-level ones at this single boundary,
// keeping middleware decoupled while still surfacing the right HTTP status
// (401 "token expired" vs the generic "invalid token") to the caller.
// If middleware ever needs to distinguish revoked-vs-expired itself, that's
// the point to extend domain's sentinel set rather than reach into service.
func (s *SessionService) VerifyToken(ctx context.Context, rawAccessToken string) (*domain.Principal, error) {
	sess, err := s.lookupAndCheck(ctx, rawAccessToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionExpired):
			return nil, domain.ErrTokenExpired
		case errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrSessionNotFound):
			return nil, domain.ErrTokenInvalid
		default:
			return nil, err
		}
	}
	return sessionToPrincipal(sess), nil
}

// ValidateSession is identical to VerifyToken but returns the full Session
// record rather than the minimal Principal projection, and does NOT
// translate errors to domain sentinels — callers needing the session ID
// itself (logout, list-sessions, revoke-session) get this package's precise
// sentinels (ErrSessionNotFound, ErrSessionRevoked, ErrSessionExpired)
// rather than the collapsed domain.ErrTokenInvalid/ErrTokenExpired pair.
func (s *SessionService) ValidateSession(ctx context.Context, rawAccessToken string) (*domain.Session, error) {
	return s.lookupAndCheck(ctx, rawAccessToken)
}

// lookupAndCheck is the shared implementation behind Validate and
// ValidateSession: resolve the access token hash, confirm the session is
// active, and kick off an async LastSeenAt touch.
func (s *SessionService) lookupAndCheck(ctx context.Context, rawAccessToken string) (*domain.Session, error) {
	hash := token.Hash(rawAccessToken)

	sess, err := s.sessions.GetByAccessHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("looking up session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionNotFound
	}
	if !sess.IsValid() {
		if sess.Revoked {
			return nil, ErrSessionRevoked
		}
		return nil, ErrSessionExpired
	}

	// Touch asynchronously — we don't want LastSeenAt writes on the
	// critical verify path, but we do want eventual consistency on the
	// audit trail.
	//
	// This is a deliberate fire-and-forget goroutine, which is normally a
	// red flag (see golang-concurrency: every goroutine needs a clear
	// exit). It's justified here because: (1) it's bounded by its own
	// 3s timeout so it cannot leak indefinitely, (2) failure is non-fatal
	// and only degrades LastSeenAt freshness, never correctness of the
	// auth decision already made above. Under very high /auth/verify QPS
	// this does mean one extra goroutine per request; if that ever shows
	// up in profiling, replace with a bounded worker pool fed by a channel
	// (see errgroup.SetLimit pattern) rather than spawning unconditionally.
	go func() {
		touchCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.sessions.Touch(touchCtx, sess.ID); err != nil {
			s.log.Warn("session touch failed", slog.String("session_id", sess.ID), slog.Any("err", err))
		}
	}()

	return sess, nil
}

// --- Refresh ---

// RefreshInput carries the raw refresh token from the client cookie.
type RefreshInput struct {
	RawRefreshToken string
	UserAgent       string
	IPAddress       string
}

// RefreshOutput holds the new token pair after a successful rotation.
type RefreshOutput struct {
	Session      *domain.Session
	AccessToken  string
	RefreshToken string
}

// Refresh validates the provided refresh token, rotates it (revokes old,
// issues new), and returns the new token pair.
//
// If the refresh token belongs to an already-revoked session, this is a
// replay attack indicator. We revoke all sessions for the associated user
// and return ErrRefreshReplayed so the caller can log the security event
// and force a full re-authentication.
func (s *SessionService) Refresh(ctx context.Context, in RefreshInput) (*RefreshOutput, error) {
	hash := token.Hash(in.RawRefreshToken)

	sess, err := s.sessions.GetByRefreshHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("looking up refresh session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionNotFound
	}

	// Detect replay: token is present but session is already revoked.
	if sess.Revoked {
		s.log.Warn("refresh token replay detected — revoking all user sessions",
			slog.String("session_id", sess.ID),
			slog.String("user_id", sess.UserID),
			slog.String("ip", in.IPAddress),
		)
		// Best-effort revocation — don't block the error response.
		revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.sessions.RevokeAllForUser(revokeCtx, sess.UserID)
		return nil, ErrRefreshReplayed
	}

	if sess.IsRefreshExpired() {
		return nil, ErrRefreshExpired
	}

	// Mint new token pair.
	atk, err := token.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}
	rtk, err := token.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}
	jti, err := token.GenerateJTI()
	if err != nil {
		return nil, fmt.Errorf("generating refresh JTI: %w", err)
	}

	now := time.Now()
	newSess, err := s.sessions.RotateTokens(ctx, domain.SessionRefreshInput{
		OldSessionID:        sess.ID,
		NewAccessTokenHash:  atk.Hash,
		NewRefreshTokenHash: rtk.Hash,
		NewRefreshJTI:       jti,
		// Permission fields are empty here; RotateTokens carries them
		// forward from the old session. Pass non-zero values only when
		// calling after a permission version advance.
		NewExpiresAt:        now.Add(s.cfg.accessTTL()),
		NewRefreshExpiresAt: sess.RefreshExpiresAt, // honour the original family expiry
		UserAgent:           in.UserAgent,
		IPAddress:           in.IPAddress,
	})
	if err != nil {
		if errors.Is(err, dgraph.ErrRefreshTokenReplayed) {
			// Lost a race with a concurrent rotation — treat as replay.
			_ = s.sessions.RevokeAllForUser(ctx, sess.UserID)
			return nil, ErrRefreshReplayed
		}
		return nil, fmt.Errorf("rotating session tokens: %w", err)
	}

	return &RefreshOutput{
		Session:      newSess,
		AccessToken:  atk.Raw,
		RefreshToken: rtk.Raw,
	}, nil
}

// --- Logout ---

// Logout revokes the session associated with a raw access token. Used by
// POST /auth/logout when the client presents their current access token.
func (s *SessionService) Logout(ctx context.Context, rawAccessToken string) error {
	hash := token.Hash(rawAccessToken)
	sess, err := s.sessions.GetByAccessHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("looking up session for logout: %w", err)
	}
	if sess == nil {
		return nil // already gone — idempotent
	}
	return s.sessions.Revoke(ctx, sess.ID)
}

// LogoutAll revokes every active session for a user. Used by
// POST /auth/logout-all ("sign out from all devices").
func (s *SessionService) LogoutAll(ctx context.Context, userID string) error {
	return s.sessions.RevokeAllForUser(ctx, userID)
}

// RevokeSession revokes a specific session by ID. Used by
// DELETE /auth/sessions/{id} (remote logout of a specific device).
func (s *SessionService) RevokeSession(ctx context.Context, sessionID, requestingUserID string) error {
	sess, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("looking up session: %w", err)
	}
	if sess == nil {
		return ErrSessionNotFound
	}
	// Authorization check: users may only revoke their own sessions.
	if sess.UserID != requestingUserID {
		return ErrSessionNotOwned
	}
	return s.sessions.Revoke(ctx, sessionID)
}

// ListSessions returns the active sessions for a user, used by
// GET /auth/sessions for the "active devices" view.
func (s *SessionService) ListSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.sessions.ListForUser(ctx, userID)
}

// --- Context activation ---

// ActivateContext switches the actor context on an active session by
// revoking the current session and issuing a new one with the updated
// actor identity. This preserves the security invariant that each context
// change produces a fresh token pair, while maintaining a clean audit trail.
func (s *SessionService) ActivateContext(
	ctx context.Context,
	rawAccessToken string,
	actorID string,
	actorType domain.ActorType,
	perms []string,
	delegPerms []string,
	pgroups []string,
	permVersion uint64,
) (*CreateSessionOutput, error) {
	hash := token.Hash(rawAccessToken)
	sess, err := s.sessions.GetByAccessHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("looking up session for context activation: %w", err)
	}
	if sess == nil || !sess.IsValid() {
		return nil, ErrSessionNotFound
	}

	// Revoke the current session before minting the new one.
	if err := s.sessions.Revoke(ctx, sess.ID); err != nil {
		return nil, fmt.Errorf("revoking old session during context activation: %w", err)
	}

	return s.Create(ctx, CreateSessionInput{
		Kind:                 sess.Kind,
		UserID:               sess.UserID,
		ClientID:             sess.ClientID,
		ActorID:              actorID,
		ActorType:            actorType,
		Permissions:          perms,
		DelegatedPermissions: delegPerms,
		PolicyGroups:         pgroups,
		PermissionVersion:    permVersion,
	})
}

// --- Helpers ---

func sessionToPrincipal(s *domain.Session) *domain.Principal {
	return &domain.Principal{
		Kind:                 s.Kind,
		UserID:               s.UserID,
		ActorID:              s.ActorID,
		ActorType:            s.ActorType,
		ClientID:             s.ClientID,
		Permissions:          s.Permissions,
		DelegatedPermissions: s.DelegatedPermissions,
		PolicyGroups:         s.PolicyGroups,
	}
}

// --- Sentinel errors ---

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session has been revoked")
	ErrSessionExpired  = errors.New("session access window has expired")
	ErrRefreshReplayed = errors.New("refresh token has already been used — potential compromise detected")
	ErrRefreshExpired  = errors.New("refresh token family has expired; re-authentication required")
	ErrSessionNotOwned = errors.New("session does not belong to the requesting user")
)
