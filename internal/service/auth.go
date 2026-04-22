// Package service contains the business logic layer.
// It depends on repository and token interfaces — never on Vault or Dgraph directly.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/repository"
	"sxcntqnt/auth-service/internal/token"
	"golang.org/x/crypto/bcrypt"
)

// bcryptFloor is the minimum acceptable cost factor.
// The actual cost comes from Vault KV v2 at startup — this constant prevents
// a misconfigured Vault secret from weakening password hashing.
const bcryptFloor = 12

// TokenManager is the subset of token.Manager the service needs.
type TokenManager interface {
	Issue(ctx context.Context, userID, nickname, email string) (*domain.TokenPair, error)
	IssueContextToken(ctx context.Context, input domain.ContextActivationInput) (*domain.TokenPair, error)
	Verify(ctx context.Context, tokenString string) (*domain.Principal, error)
}

// AuthService handles registration, authentication, and profile management.
type AuthService struct {
	repo       repository.UserRepository
	tokens     TokenManager
	bcryptCost int
	logger     *slog.Logger
}

// New constructs an AuthService.
// Panics if bcryptCost is below bcryptFloor — a low cost is a security
// regression, not a configuration warning.
func New(repo repository.UserRepository, tokens TokenManager, bcryptCost int, logger *slog.Logger) *AuthService {
	if bcryptCost < bcryptFloor {
		panic(fmt.Sprintf("service: bcryptCost %d is below the minimum of %d", bcryptCost, bcryptFloor))
	}
	return &AuthService{repo: repo, tokens: tokens, bcryptCost: bcryptCost, logger: logger}
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

// Login authenticates a user and returns a token pair.
//
// Timing-safe: bcrypt.CompareHashAndPassword always runs even on the
// user-not-found path — without it, a fast early return leaks whether
// an email exists in the system via response-time differences.
//
// Consistency: Login always performs a strong read (domain.StrongRead)
// because a recently changed password must be visible immediately —
// a stale read here is a security defect, not just an UX issue.
func (s *AuthService) Login(ctx context.Context, input domain.LoginInput) (*domain.TokenPair, error) {
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

	pair, err := s.tokens.Issue(ctx, user.ID, user.Nickname, user.Email)
	if err != nil {
		return nil, fmt.Errorf("login: issue tokens: %w", err)
	}

	s.logger.InfoContext(ctx, "user logged in", slog.String("user_id", user.ID))
	return pair, nil
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

// ActivateContext exchanges a basic token's identity for a context-scoped token
// that embeds actor_id, actor_type, and flattened permission arrays.
//
// The caller must have already called Dgraph's getActiveContext query to
// obtain the context data and passes it here in ContextActivationInput.
// The auth service does not query Dgraph — it signs whatever context Dgraph's
// authoritative resolver has produced.
//
// The returned TokenPair replaces the caller's basic token. The new access
// token carries enough information for downstream services to make fast
// in-process authorisation decisions using Principal.HasPermission().
func (s *AuthService) ActivateContext(ctx context.Context, callerID string, input domain.ContextActivationInput) (*domain.TokenPair, error) {
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

	pair, err := s.tokens.IssueContextToken(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("activate context: %w", err)
	}

	s.logger.InfoContext(ctx, "context token issued",
		slog.String("user_id", callerID),
		slog.String("actor_id", input.ActorID),
		slog.String("actor_type", string(input.ActorType)),
	)
	return pair, nil
}

// VerifyToken validates an access token and returns the caller's Principal.
func (s *AuthService) VerifyToken(ctx context.Context, tokenString string) (*domain.Principal, error) {
	return s.tokens.Verify(ctx, tokenString)
}

// compile-time assertion: *token.Manager satisfies TokenManager.
var _ TokenManager = (*token.Manager)(nil)
