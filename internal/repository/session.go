package repository

import (
	"context"

	"sxcntqnt/auth-service/internal/domain"
)

// SessionRepository defines all persistence operations for the session
// subsystem. The concrete implementation lives in repository/dgraph/session.go.
//
// All lookups operate on hashed token values — raw tokens never enter
// the repository layer.
type SessionRepository interface {
	// Create persists a new session record. The caller is responsible for
	// hashing all token values before populating SessionCreateInput.
	Create(ctx context.Context, in domain.SessionCreateInput) (*domain.Session, error)

	// GetByAccessHash retrieves the session whose AccessTokenHash matches
	// the provided SHA-256 hex digest. Used by /auth/verify on every request.
	// Returns nil, nil when no matching session exists.
	GetByAccessHash(ctx context.Context, hash string) (*domain.Session, error)

	// GetByRefreshHash retrieves the session whose RefreshTokenHash matches
	// the provided hash. Used by /auth/refresh.
	// Returns nil, nil when no matching session exists.
	GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)

	// GetByID retrieves a session by its Dgraph UID. Used for session
	// management endpoints (/auth/sessions/{id}).
	GetByID(ctx context.Context, id string) (*domain.Session, error)

	// ListForUser returns all non-revoked sessions for a given user profile ID,
	// ordered by LastSeenAt descending. Used by /auth/sessions.
	ListForUser(ctx context.Context, userID string) ([]*domain.Session, error)

	// RotateTokens atomically revokes the old session and creates the new one.
	// This is the critical operation for refresh token rotation — it must be
	// executed in a single Dgraph transaction to prevent race conditions where
	// two simultaneous refresh requests both succeed.
	//
	// If the old session is already revoked when this is called (i.e., a
	// concurrent rotation beat us), the operation must fail so the caller
	// can trigger compromise detection.
	RotateTokens(ctx context.Context, in domain.SessionRefreshInput) (*domain.Session, error)

	// Revoke marks a single session as revoked. Idempotent — revoking an
	// already-revoked session is a no-op.
	Revoke(ctx context.Context, sessionID string) error

	// RevokeAllForUser marks every session for a user as revoked. Used for
	// "log out all devices" and compromise response.
	RevokeAllForUser(ctx context.Context, userID string) error

	// Touch updates LastSeenAt on an active session. Called on successful
	// /auth/verify to maintain an activity trail without a full write.
	Touch(ctx context.Context, sessionID string) error

	// DeleteExpired removes sessions whose RefreshExpiresAt is in the past.
	// Intended to be called by a background cleanup goroutine, not on the
	// hot path.
	DeleteExpired(ctx context.Context) (int64, error)
}
