// Package repository defines the storage abstraction for the auth service.
// All implementations satisfy UserRepository — swap the concrete type at the
// composition root and nothing else in the codebase changes.
package repository

import (
	"context"

	"sxcntqnt/auth-service/internal/domain"
)

// UserRepository is the single storage contract for the auth service.
// Defined at the consumption site (service layer), not at the implementation.
//
// Zookie consistency contract:
//
//	Write methods (Create, Update, Delete) return a domain.Zookie encoding the
//	Dgraph commit timestamp of the completed transaction.
//
//	Read methods (GetByID, GetByEmail, List) accept a *domain.Zookie:
//	  nil         → BestEffort read (fast, potentially stale)
//	  non-nil     → Strong read (linearizable — guaranteed to see all commits
//	                             up to and including the provided write)
//
//	Use domain.StrongRead as the zookie argument for security-sensitive reads
//	that must be consistent but do not have a specific prior write to anchor to.
//
// Error rules:
//   - Every method must respect ctx cancellation and deadline.
//   - Return domain.ErrUserNotFound when a lookup yields no result.
//   - Return domain.ErrUserAlreadyExists on unique-constraint violations.
//   - Never log and return — return only; the transport layer logs.
type UserRepository interface {
	// Create persists a new user. PasswordHash must already be set.
	// Returns ErrUserAlreadyExists if email or nickname is taken.
	// Returns the Zookie of the completed write for read-your-writes consistency.
	Create(ctx context.Context, user *domain.User) (domain.Zookie, error)

	// GetByID fetches the user with the given ID.
	// Pass a non-nil zookie to force a strong (non-stale) read.
	// Returns ErrUserNotFound if the user does not exist.
	GetByID(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error)

	// GetByEmail fetches the user with the given email (case-insensitive).
	// Pass a non-nil zookie to force a strong read.
	// Returns ErrUserNotFound if the user does not exist.
	GetByEmail(ctx context.Context, email string, zookie *domain.Zookie) (*domain.User, error)

	// Update applies a partial update. Only non-nil fields in input are written.
	// Returns the updated User and the Zookie of the completed write.
	// Returns ErrUserNotFound if the user does not exist.
	Update(ctx context.Context, id string, input *domain.UpdateUserInput) (*domain.User, domain.Zookie, error)

	// Delete removes the user with the given ID.
	// Returns the Zookie of the completed write.
	// Returns ErrUserNotFound if the user does not exist.
	Delete(ctx context.Context, id string) (domain.Zookie, error)

	// List returns a paginated, optionally filtered slice of users.
	// Pass a non-nil zookie to force a strong read.
	List(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error)

	// Ping verifies the store is reachable — used by the health check.
	Ping(ctx context.Context) error
}
