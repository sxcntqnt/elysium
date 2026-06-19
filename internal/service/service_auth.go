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

// serviceSecretMinLen is the minimum length for service client secrets.
// 32 characters gives ~160 bits of entropy when randomly generated.
const serviceSecretMinLen = 32

// ServiceAuthService handles service account lifecycle and credential
// verification. It sits alongside AuthService — both are wired in the
// composition root and both have had token minting removed in favour of
// SessionService (see service/session.go).
//
// Login no longer returns a *domain.TokenPair. It returns the resolved
// *domain.ServiceAccount on success; the handler passes ClientID into
// SessionService.Create to open an opaque-token session, exactly mirroring
// how AuthService.Login now hands its resolved *domain.User to the same
// SessionService.Create call. This keeps a single token-minting code path
// for both principal kinds rather than two parallel JWT issuers.
type ServiceAuthService struct {
	repo       repository.ServiceAccountRepository
	bcryptCost int
	logger     *slog.Logger
}

// NewServiceAuth constructs a ServiceAuthService.
// bcryptCost is sourced from Vault KV v2 (same value as AuthService).
func NewServiceAuth(
	repo repository.ServiceAccountRepository,
	bcryptCost int,
	logger *slog.Logger,
) *ServiceAuthService {
	if bcryptCost < bcryptFloor {
		panic(fmt.Sprintf("service: service auth bcryptCost %d is below the minimum of %d", bcryptCost, bcryptFloor))
	}
	return &ServiceAuthService{
		repo:       repo,
		bcryptCost: bcryptCost,
		logger:     logger,
	}
}

// CreateServiceAccount provisions a new machine identity.
// Returns the created ServiceAccount and the Zookie of the write.
// The plaintext secret is hashed before persistence — it is never stored.
func (s *ServiceAuthService) CreateServiceAccount(ctx context.Context, input domain.CreateServiceAccountInput) (*domain.ServiceAccount, domain.Zookie, error) {
	if err := input.Validate(); err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("create service account: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.ClientSecret), s.bcryptCost)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("create service account: hash secret: %w", err)
	}

	now := time.Now().UTC()
	sa := &domain.ServiceAccount{
		ID:          uuid.New().String(),
		ClientID:    input.ClientID,
		Name:        input.Name,
		SecretHash:  string(hash),
		ActorType:   input.ActorType,
		Permissions: input.Permissions,
		Active:      true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	zookie, err := s.repo.CreateServiceAccount(ctx, sa)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("create service account: %w", err)
	}

	s.logger.InfoContext(ctx, "service account created",
		slog.String("client_id", sa.ClientID),
		slog.String("name", sa.Name),
	)
	return sa, zookie, nil
}

// Login authenticates a service account and returns the resolved
// ServiceAccount on success. It no longer mints tokens — the handler
// passes the returned account's ClientID into SessionService.Create to
// open an opaque-token session.
//
// Timing-safe: bcrypt.CompareHashAndPassword always runs even on the
// client_id-not-found path — identical to the human Login defence.
//
// Consistency: always performs a strong read (domain.StrongRead) so a
// recently rotated secret is immediately effective.
func (s *ServiceAuthService) Login(ctx context.Context, input domain.ServiceLoginInput) (*domain.ServiceAccount, error) {
	if err := input.Validate(); err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}

	// Strong read — must see the current secret hash, never a stale replica.
	sa, err := s.repo.GetByClientID(ctx, input.ClientID, domain.StrongRead)
	if err != nil {
		//nolint:errcheck — always run bcrypt to prevent timing enumeration
		bcrypt.CompareHashAndPassword([]byte("$2a$12$dummyhashfortimingprotection"), []byte(input.ClientSecret))
		return nil, domain.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(sa.SecretHash), []byte(input.ClientSecret)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if !sa.Active {
		return nil, domain.ErrUnauthorized
	}

	s.logger.InfoContext(ctx, "service account authenticated",
		slog.String("client_id", sa.ClientID),
	)
	return sa, nil
}

// DeactivateServiceAccount marks the service account as inactive.
// Returns the Zookie of the write.
func (s *ServiceAuthService) DeactivateServiceAccount(ctx context.Context, clientID string) (domain.Zookie, error) {
	zookie, err := s.repo.Deactivate(ctx, clientID)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("deactivate service account: %w", err)
	}

	s.logger.InfoContext(ctx, "service account deactivated",
		slog.String("client_id", clientID),
	)
	return zookie, nil
}
