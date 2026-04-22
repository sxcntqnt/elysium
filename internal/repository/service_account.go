package repository

import (
	"context"

	"sxcntqnt/auth-service/internal/domain"
)

// ServiceAccountRepository is the storage contract for machine identities.
// Defined at the consumption site (service layer).
//
// Zookie semantics mirror UserRepository: writes return a Zookie, reads
// accept a *domain.Zookie (nil = BestEffort, non-nil = strong read).
//
// Error rules:
//   - Return domain.ErrUserNotFound when a client_id lookup yields no result.
//   - Return domain.ErrUserAlreadyExists on duplicate client_id.
//   - Never log and return.
type ServiceAccountRepository interface {
	// CreateServiceAccount persists a new service account. SecretHash must be set.
	// Returns ErrUserAlreadyExists if client_id is already taken.
	CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) (domain.Zookie, error)

	// GetByClientID fetches the service account with the given client_id.
	// Pass a non-nil zookie to force a strong (non-BestEffort) read.
	// Returns ErrUserNotFound if no such account exists.
	GetByClientID(ctx context.Context, clientID string, zookie *domain.Zookie) (*domain.ServiceAccount, error)

	// Deactivate marks the service account as inactive without deleting it.
	// Returns the Zookie of the write.
	Deactivate(ctx context.Context, clientID string) (domain.Zookie, error)
}
