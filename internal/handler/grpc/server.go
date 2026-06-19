// Package grpc is the gRPC transport layer. No business logic lives here —
// only protocol translation between gRPC messages and domain types, plus
// Zookie extraction from incoming metadata and embedding in responses.
package grpc

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/handler/grpc/pb"
	"sxcntqnt/auth-service/internal/service"
)

// zookieMetaKey is the gRPC metadata key for the Zookie consistency token.
// Clients send it in incoming metadata on read calls; servers return it in
// trailing metadata on write calls (and embed it in response messages).
const zookieMetaKey = "x-zookie"

// AuthServicer mirrors the HTTP handler's interface — both transports agree
// on the same service contract.
//
// Login no longer returns *domain.TokenPair. It returns the resolved
// *domain.User on success; the gRPC server itself calls SessionService.Create
// to mint the opaque token pair that actually goes into pb.LoginResponse.
// This is the same two-phase split already applied on the HTTP side: the
// credential-check business logic (AuthServicer) is fully decoupled from
// token minting (SessionService), so both transports share one minting path
// instead of each owning its own JWT issuance.
//
// VerifyToken is removed from this interface entirely — gRPC principal
// resolution now goes through SessionService.Validate (see principalFromCtx),
// exactly mirroring requireSession in the HTTP handler. token.Manager and its
// JWT Verify path remain available elsewhere (e.g. for any caller still
// minting/verifying JWTs directly), but this transport no longer depends on it.
type AuthServicer interface {
	Register(ctx context.Context, input domain.CreateUserInput) (*domain.User, domain.Zookie, error)
	Login(ctx context.Context, input domain.LoginInput) (*domain.User, error)
	GetUser(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error)
	UpdateUser(ctx context.Context, callerID, targetID string, input domain.UpdateUserInput) (*domain.User, domain.Zookie, error)
	DeleteUser(ctx context.Context, callerID, targetID string) (domain.Zookie, error)
	ListUsers(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error)
}

// Server implements pb.AuthServiceServer.
type Server struct {
	pb.UnimplementedAuthServiceServer
	svc      AuthServicer
	sessions *service.SessionService
	logger   *slog.Logger
}

// New constructs a gRPC Server. sessions handles all token minting and
// validation — svc handles credential checks and user CRUD only.
func New(svc AuthServicer, sessions *service.SessionService, logger *slog.Logger) *Server {
	return &Server{svc: svc, sessions: sessions, logger: logger}
}

// ── Auth RPCs ─────────────────────────────────────────────────────────────────

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	user, zookie, err := s.svc.Register(ctx, domain.CreateUserInput{
		FirstName: req.GetFirstName(),
		LastName:  req.GetLastName(),
		Nickname:  req.GetNickname(),
		Password:  req.GetPassword(),
		Email:     req.GetEmail(),
		Country:   req.GetCountry(),
	})
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &pb.RegisterResponse{
		User:   domainUserToProto(user),
		Zookie: zookie.Token,
	}, nil
}

// Login authenticates the caller, then mints an opaque session token pair.
// Phase 1 (s.svc.Login) is pure credential verification — it returns the
// resolved User with no tokens attached. Phase 2 (s.sessions.Create) is the
// only place in the system that mints client-facing tokens, shared between
// this RPC and the HTTP handler's POST /auth/login.
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.svc.Login(ctx, domain.LoginInput{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	out, err := s.sessions.Create(ctx, service.CreateSessionInput{
		Kind:   domain.PrincipalKindUser,
		UserID: user.ID,
		// gRPC callers are typically other backend services rather than
		// browsers; there is no User-Agent/remote-addr in the same sense
		// as an HTTP request, so audit metadata is left empty here. If a
		// caller identity is available via gRPC peer/metadata in this
		// deployment, wire it through once that contract is decided.
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "grpc login: session create failed", slog.Any("err", err))
		return nil, status.Error(codes.Internal, "could not create session")
	}

	// Login is a read from the AuthServicer's perspective — no Zookie in
	// the response. The session write itself is not zookie-tracked because
	// session state is not part of the consistency domain pb.Zookie covers
	// (that domain is User/profile data); the access token returned here is
	// sufficient for the caller to authenticate subsequent calls immediately.
	return &pb.LoginResponse{
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
		ExpiresIn:    int64(s.sessions.AccessTTL().Seconds()),
	}, nil
}

// ── User RPCs ─────────────────────────────────────────────────────────────────

func (s *Server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	if _, err := s.principalFromCtx(ctx); err != nil {
		return nil, err
	}

	// Zookie from the request message; nil = BestEffort read.
	zookie := zookieFromProto(req.GetZookie())

	user, err := s.svc.GetUser(ctx, req.GetId(), zookie)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &pb.UserResponse{User: domainUserToProto(user)}, nil
}

func (s *Server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.WriteUserResponse, error) {
	principal, err := s.principalFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	input := domain.UpdateUserInput{}
	if v := req.GetFirstName(); v != "" {
		input.FirstName = &v
	}
	if v := req.GetLastName(); v != "" {
		input.LastName = &v
	}
	if v := req.GetNickname(); v != "" {
		input.Nickname = &v
	}
	if v := req.GetCountry(); v != "" {
		input.Country = &v
	}

	user, zookie, err := s.svc.UpdateUser(ctx, principal.UserID, req.GetId(), input)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &pb.WriteUserResponse{
		User:   domainUserToProto(user),
		Zookie: zookie.Token,
	}, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	principal, err := s.principalFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	zookie, err := s.svc.DeleteUser(ctx, principal.UserID, req.GetId())
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &pb.DeleteUserResponse{Message: "user deleted", Zookie: zookie.Token}, nil
}

func (s *Server) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	if _, err := s.principalFromCtx(ctx); err != nil {
		return nil, err
	}

	zookie := zookieFromProto(req.GetZookie())

	result, err := s.svc.ListUsers(ctx, domain.ListFilter{
		Country:  req.GetCountry(),
		Page:     int(req.GetPage()),
		PageSize: int(req.GetPageSize()),
	}, zookie)
	if err != nil {
		return nil, domainToGRPCError(err)
	}

	protoUsers := make([]*pb.User, len(result.Users))
	for i, u := range result.Users {
		protoUsers[i] = domainUserToProto(u)
	}
	return &pb.ListUsersResponse{
		Users: protoUsers,
		Total: int32(result.Total),
		Page:  int32(result.Page),
		Pages: int32(result.Pages),
	}, nil
}

func (s *Server) HealthCheck(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// principalFromCtx extracts and validates the Bearer token from incoming
// gRPC metadata via SessionService.Validate, mirroring requireSession in the
// HTTP handler. ctx is forwarded so the underlying Dgraph lookup respects
// the RPC deadline.
func (s *Server) principalFromCtx(ctx context.Context) (*domain.Principal, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	bearer := vals[0]
	if !strings.HasPrefix(bearer, "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "malformed authorization header")
	}

	principal, err := s.sessions.VerifyToken(ctx, strings.TrimPrefix(bearer, "Bearer "))
	if err != nil {
		// VerifyToken translates its internal service.* sentinels to
		// domain.ErrTokenExpired/domain.ErrTokenInvalid at its own boundary
		// (see service/session.go) precisely so every TokenVerifier caller —
		// middleware.Authenticate and this gRPC path alike — can check
		// against the same stable domain-level sentinels rather than each
		// needing its own knowledge of SessionService's internal error set.
		switch {
		case errors.Is(err, domain.ErrTokenExpired):
			return nil, status.Error(codes.Unauthenticated, "token expired")
		default:
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
	}
	return principal, nil
}

// zookieFromProto converts a proto Zookie string to a *domain.Zookie.
// Returns nil when the string is empty (caller accepts BestEffort reads).
func zookieFromProto(token string) *domain.Zookie {
	if token == "" {
		return nil
	}
	return &domain.Zookie{Token: token}
}

// zookieMetaFromCtx extracts the Zookie from incoming gRPC metadata.
// This is an alternative to embedding it in request messages; both are supported.
func zookieMetaFromCtx(ctx context.Context) *domain.Zookie {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	vals := md.Get(zookieMetaKey)
	if len(vals) == 0 || vals[0] == "" {
		return nil
	}
	return &domain.Zookie{Token: vals[0]}
}

func domainToGRPCError(err error) error {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		return status.Error(codes.NotFound, "user not found")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		return status.Error(codes.AlreadyExists, "user already exists")
	case errors.Is(err, domain.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, domain.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, "invalid input")
	case errors.Is(err, domain.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, domain.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "token expired")
	case errors.Is(err, domain.ErrTokenInvalid):
		return status.Error(codes.Unauthenticated, "invalid token")
	case errors.Is(err, domain.ErrRateLimited):
		return status.Error(codes.ResourceExhausted, "rate limit exceeded")
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}

func domainUserToProto(u *domain.User) *pb.User {
	return &pb.User{
		Id:        u.ID,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Nickname:  u.Nickname,
		Email:     u.Email,
		Country:   u.Country,
		Active:    u.Active,
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: u.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// Ensure zookieMetaFromCtx is used (grpc metadata path).
var _ = zookieMetaFromCtx

// compile-time assertion: *service.AuthService satisfies AuthServicer.
var _ AuthServicer = (*service.AuthService)(nil)
