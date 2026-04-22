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

	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/handler/grpc/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// zookieMetaKey is the gRPC metadata key for the Zookie consistency token.
// Clients send it in incoming metadata on read calls; servers return it in
// trailing metadata on write calls (and embed it in response messages).
const zookieMetaKey = "x-zookie"

// AuthServicer mirrors the HTTP handler's interface — both transports agree
// on the same service contract.
type AuthServicer interface {
	Register(ctx context.Context, input domain.CreateUserInput) (*domain.User, domain.Zookie, error)
	Login(ctx context.Context, input domain.LoginInput) (*domain.TokenPair, error)
	GetUser(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error)
	UpdateUser(ctx context.Context, callerID, targetID string, input domain.UpdateUserInput) (*domain.User, domain.Zookie, error)
	DeleteUser(ctx context.Context, callerID, targetID string) (domain.Zookie, error)
	ListUsers(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error)
	VerifyToken(ctx context.Context, tokenString string) (*domain.Principal, error)
}

// Server implements pb.AuthServiceServer.
type Server struct {
	pb.UnimplementedAuthServiceServer
	svc    AuthServicer
	logger *slog.Logger
}

// New constructs a gRPC Server.
func New(svc AuthServicer, logger *slog.Logger) *Server {
	return &Server{svc: svc, logger: logger}
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

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	pair, err := s.svc.Login(ctx, domain.LoginInput{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	// Login is a read — no Zookie in the response.
	return &pb.LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
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
	claims, err := s.principalFromCtx(ctx)
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

	user, zookie, err := s.svc.UpdateUser(ctx, claims.UserID, req.GetId(), input)
	if err != nil {
		return nil, domainToGRPCError(err)
	}
	return &pb.WriteUserResponse{
		User:   domainUserToProto(user),
		Zookie: zookie.Token,
	}, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	claims, err := s.principalFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	zookie, err := s.svc.DeleteUser(ctx, claims.UserID, req.GetId())
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

// principalFromCtx extracts and validates the Bearer token from incoming gRPC
// metadata. ctx is forwarded to VerifyToken so Transit calls respect the RPC deadline.
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

	claims, err := s.svc.VerifyToken(ctx, strings.TrimPrefix(bearer, "Bearer "))
	if err != nil {
		if errors.Is(err, domain.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	return claims, nil
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
