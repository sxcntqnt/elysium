// Package service contains the business logic layer.
// It depends on repository and token interfaces — never on Vault or Dgraph directly.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/repository"
)

// bcryptFloor is the minimum acceptable cost factor.
// The actual cost comes from Vault KV v2 at startup — this constant prevents
// a misconfigured Vault secret from weakening password hashing.
const bcryptFloor = 12

// AuthService handles registration, credential verification, and profile
// management.
//
// Token minting moved to SessionService as part of the migration to opaque
// session tokens (see service/session.go). AuthService now returns resolved
// domain entities (*domain.User, context activation data) rather than
// *domain.TokenPair — the handler layer is responsible for taking that
// output and calling SessionService.Create / SessionService.ActivateContext
// to mint the actual client-facing tokens. This keeps credential validation
// and session lifecycle as two separately testable concerns, matching the
// existing project value of clean layering with interfaces defined at
// consumption sites.
type AuthService struct {
	repo       repository.UserRepository
	bcryptCost int
	logger     *slog.Logger
}

// New constructs an AuthService.
// Panics if bcryptCost is below bcryptFloor — a low cost is a security
// regression, not a configuration warning.
func New(repo repository.UserRepository, bcryptCost int, logger *slog.Logger) *AuthService {
	if bcryptCost < bcryptFloor {
		panic(fmt.Sprintf("service: bcryptCost %d is below the minimum of %d", bcryptCost, bcryptFloor))
	}
	return &AuthService{repo: repo, bcryptCost: bcryptCost, logger: logger}
}

// Register creates a new user account. Returns the created User and the
// Zookie of the write — the caller should pass it on the next read to avoid
// seeing stale data.
func (s *AuthService) Register(ctx context.Context, input domain.CreateUserInput) (*domain.User, domain.Zookie, error) {
	if err := input.Validate(); err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("register: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), s.bcryptCost)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("register: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New().String(),
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		Nickname:     input.Nickname,
		PasswordHash: string(hash),
		Email:        input.Email,
		Country:      input.Country,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	zookie, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("register: %w", err)
	}

	s.logger.InfoContext(ctx, "user registered",
		slog.String("user_id", user.ID),
		slog.String("email", user.Email),
	)
	return user, zookie, nil
}

// Login authenticates a user and returns the resolved User on success.
// It no longer mints tokens — the handler passes the returned User into
// SessionService.Create to open an opaque-token session.
//
// Timing-safe: bcrypt.CompareHashAndPassword always runs even on the
// user-not-found path — without it, a fast early return leaks whether
// an email exists in the system via response-time differences.
//
// Consistency: Login always performs a strong read (domain.StrongRead)
// because a recently changed password must be visible immediately —
// a stale read here is a security defect, not just an UX issue.
func (s *AuthService) Login(ctx context.Context, input domain.LoginInput) (*domain.User, error) {
	if err := input.Validate(); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	// Strong read — login must see the current password hash, never a stale one.
	user, err := s.repo.GetByEmail(ctx, input.Email, domain.StrongRead)
	if err != nil {
		//nolint:errcheck — always run bcrypt to prevent timing enumeration
		bcrypt.CompareHashAndPassword([]byte("$2a$12$dummyhashfortimingprotection"), []byte(input.Password))
		return nil, domain.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if !user.Active {
		return nil, domain.ErrUnauthorized
	}

	s.logger.InfoContext(ctx, "user authenticated", slog.String("user_id", user.ID))
	return user, nil
}

// GetUser returns an active user by ID.
// Pass a non-nil zookie to guarantee the caller sees their own recent writes.
func (s *AuthService) GetUser(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error) {
	user, err := s.repo.GetByID(ctx, id, zookie)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if !user.Active {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

// UpdateUser applies a partial update. callerID enforces ownership.
// Returns the updated User and the Zookie of the write.
func (s *AuthService) UpdateUser(ctx context.Context, callerID, targetID string, input domain.UpdateUserInput) (*domain.User, domain.Zookie, error) {
	if callerID != targetID {
		return nil, domain.Zookie{}, domain.ErrUnauthorized
	}

	user, zookie, err := s.repo.Update(ctx, targetID, &input)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("update user: %w", err)
	}

	s.logger.InfoContext(ctx, "user updated", slog.String("user_id", targetID))
	return user, zookie, nil
}

// DeleteUser removes a user. callerID enforces ownership.
// Returns the Zookie of the write.
func (s *AuthService) DeleteUser(ctx context.Context, callerID, targetID string) (domain.Zookie, error) {
	if callerID != targetID {
		return domain.Zookie{}, domain.ErrUnauthorized
	}

	zookie, err := s.repo.Delete(ctx, targetID)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("delete user: %w", err)
	}

	s.logger.InfoContext(ctx, "user deleted", slog.String("user_id", targetID))
	return zookie, nil
}

// ListUsers returns a paginated, optionally filtered list of users.
// Pass a non-nil zookie to guarantee the caller sees their own recent writes.
func (s *AuthService) ListUsers(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error) {
	filter.Normalise()
	result, err := s.repo.List(ctx, filter, zookie)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return result, nil
}

// ActivateContext validates a requested actor-context switch and returns the
// resolved domain.ContextActivationInput. It no longer mints a token — the
// handler passes the returned value into SessionService.ActivateContext to
// revoke the caller's current session and open a new one under the
// activated context.
//
// The caller must have already resolved input from Dgraph's getActiveContext
// query (actor_id, actor_type, permissions, etc.) before calling this method.
// AuthService does not query Dgraph for context data — it only enforces the
// ownership and validity invariants below.
func (s *AuthService) ActivateContext(ctx context.Context, callerID string, input domain.ContextActivationInput) (*domain.ContextActivationInput, error) {
	// Ensure the input is for the authenticated caller — prevent privilege
	// escalation by a user who substitutes another user's actor_id.
	if input.UserID != callerID {
		return nil, domain.ErrUnauthorized
	}
	if !input.ActorType.IsValid() {
		return nil, fmt.Errorf("activate context: %w", domain.ErrInvalidInput)
	}
	if input.ActorID == "" {
		return nil, fmt.Errorf("activate context: actor_id must not be empty: %w", domain.ErrInvalidInput)
	}

	s.logger.InfoContext(ctx, "context activation validated",
		slog.String("user_id", callerID),
		slog.String("actor_id", input.ActorID),
		slog.String("actor_type", string(input.ActorType)),
	)
	return &input, nil
}
