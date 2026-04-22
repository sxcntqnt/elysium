// Package http is the HTTP transport layer. No business logic lives here —
// only request decoding, service dispatch, response encoding, and Zookie
// header plumbing.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sxcntqnt/auth-service/internal/domain"
	"sxcntqnt/auth-service/internal/middleware"
)

// zookieHeader is the HTTP header used to convey Zookie consistency tokens.
// Clients receive this header on write responses and send it on read requests.
const zookieHeader = "X-Zookie"

// AuthServicer is the subset of service.AuthService the HTTP handler needs.
// VerifyToken carries ctx because Transit implementations call Vault per request.
type AuthServicer interface {
	Register(ctx context.Context, input domain.CreateUserInput) (*domain.User, domain.Zookie, error)
	Login(ctx context.Context, input domain.LoginInput) (*domain.TokenPair, error)
	ActivateContext(ctx context.Context, callerID string, input domain.ContextActivationInput) (*domain.TokenPair, error)
	GetUser(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error)
	UpdateUser(ctx context.Context, callerID, targetID string, input domain.UpdateUserInput) (*domain.User, domain.Zookie, error)
	DeleteUser(ctx context.Context, callerID, targetID string) (domain.Zookie, error)
	ListUsers(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error)
	VerifyToken(ctx context.Context, tokenString string) (*domain.Principal, error)
}

// RepoHealther is satisfied by any store with a Ping method.
type RepoHealther interface {
	Ping(ctx context.Context) error
}

// ServiceAuthServicer is the subset of service.ServiceAuthService the HTTP handler needs.
type ServiceAuthServicer interface {
	CreateServiceAccount(ctx context.Context, input domain.CreateServiceAccountInput) (*domain.ServiceAccount, domain.Zookie, error)
	Login(ctx context.Context, input domain.ServiceLoginInput) (*domain.TokenPair, error)
	DeactivateServiceAccount(ctx context.Context, clientID string) (domain.Zookie, error)
}

// Handler holds HTTP handler dependencies.
type Handler struct {
	svc     AuthServicer
	svcAuth ServiceAuthServicer
	store   RepoHealther
	logger  *slog.Logger
}

// New constructs a Handler. All dependencies injected — no globals.
func New(svc AuthServicer, svcAuth ServiceAuthServicer, store RepoHealther, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, svcAuth: svcAuth, store: store, logger: logger}
}

// RegisterRoutes attaches all routes to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMW func(http.Handler) http.Handler) {
	// Public — human auth.
	mux.HandleFunc("POST /auth/register", h.register)
	mux.HandleFunc("POST /auth/login", h.login)
	// Public — service auth.
	mux.HandleFunc("POST /auth/service/token", h.serviceLogin)

	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /ready", h.ready)

	protected := func(fn http.HandlerFunc) http.Handler { return authMW(http.HandlerFunc(fn)) }

	// Context activation — requires a valid basic or context token.
	// The client calls Dgraph's getActiveContext first, then exchanges the result here.
	mux.Handle("POST /auth/context/activate", protected(h.activateContext))

	mux.Handle("GET /users", protected(h.listUsers))
	mux.Handle("GET /users/{id}", protected(h.getUser))
	mux.Handle("PUT /users/{id}", protected(h.updateUser))
	mux.Handle("DELETE /users/{id}", protected(h.deleteUser))

	// Service account management — requires an authenticated principal.
	mux.Handle("POST /service-accounts", protected(h.createServiceAccount))
	mux.Handle("DELETE /service-accounts/{client_id}", protected(h.deactivateServiceAccount))
}

// ── Auth endpoints ────────────────────────────────────────────────────────────

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateUserInput
	if !h.decode(w, r, &input) {
		return
	}

	user, zookie, err := h.svc.Register(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	// Return the Zookie so the client can anchor subsequent reads to this write.
	h.setZookieHeader(w, zookie)
	h.respond(w, http.StatusCreated, map[string]interface{}{
		"user":   user,
		"zookie": zookie.Token,
	})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var input domain.LoginInput
	if !h.decode(w, r, &input) {
		return
	}

	pair, err := h.svc.Login(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	// Login is a read — no zookie in the response.
	h.respond(w, http.StatusOK, pair)
}

// ── User endpoints ────────────────────────────────────────────────────────────

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := h.svc.GetUser(r.Context(), r.PathValue("id"), h.readZookie(r))
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	h.respond(w, http.StatusOK, user)
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.PrincipalFromContext(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input domain.UpdateUserInput
	if !h.decode(w, r, &input) {
		return
	}

	user, zookie, err := h.svc.UpdateUser(r.Context(), claims.UserID, r.PathValue("id"), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.setZookieHeader(w, zookie)
	h.respond(w, http.StatusOK, map[string]interface{}{
		"user":   user,
		"zookie": zookie.Token,
	})
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.PrincipalFromContext(r.Context())
	if claims == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	zookie, err := h.svc.DeleteUser(r.Context(), claims.UserID, r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.setZookieHeader(w, zookie)
	h.respond(w, http.StatusOK, map[string]interface{}{
		"message": "user deleted",
		"zookie":  zookie.Token,
	})
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	result, err := h.svc.ListUsers(r.Context(), domain.ListFilter{
		Country:  strings.TrimSpace(q.Get("country")),
		Page:     page,
		PageSize: pageSize,
	}, h.readZookie(r))
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	h.respond(w, http.StatusOK, result)
}

// ── Context activation ────────────────────────────────────────────────────────

// activateContext exchanges a basic user token for a context-scoped token.
//
// Endpoint:  POST /auth/context/activate   (protected — requires valid token)
// Request body:
//
//	{
//	  "user_id":   "uuid",
//	  "actor_id":  "dgraph-actor-uid",
//	  "actor_type": "DRIVER",
//	  "permissions":           ["trip.start", "booking.view"],
//	  "delegated_permissions": [],
//	  "policy_groups":         ["drivers-group"]
//	}
//
// Flow:
//  1. Client calls POST /auth/login → gets basic token.
//  2. Client calls Dgraph getActiveContext(userId, contextType) → gets context.
//  3. Client calls this endpoint with the Dgraph response → gets context token.
//
// The resulting access token embeds the full ActiveContext fields, enabling
// downstream services to authorise requests without a Dgraph round-trip.
func (h *Handler) activateContext(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromContext(r.Context())
	if principal == nil || principal.Kind != domain.PrincipalKindUser {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input domain.ContextActivationInput
	if !h.decode(w, r, &input) {
		return
	}

	pair, err := h.svc.ActivateContext(r.Context(), principal.UserID, input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	h.respond(w, http.StatusOK, pair)
}

// ── Service auth endpoints ────────────────────────────────────────────────────

// serviceLogin authenticates a service account and returns a token pair.
// Endpoint: POST /auth/service/token
// Request:  {"client_id": "my-service", "client_secret": "..."}
// Response: {"access_token": "...", "refresh_token": "...", "expires_in": 900}
func (h *Handler) serviceLogin(w http.ResponseWriter, r *http.Request) {
	var input domain.ServiceLoginInput
	if !h.decode(w, r, &input) {
		return
	}
	pair, err := h.svcAuth.Login(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	h.respond(w, http.StatusOK, pair)
}

// createServiceAccount provisions a new machine identity.
// Endpoint: POST /service-accounts (protected)
// Request:  {"client_id": "...", "name": "...", "client_secret": "...", "permissions": [...]}
func (h *Handler) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateServiceAccountInput
	if !h.decode(w, r, &input) {
		return
	}
	sa, zookie, err := h.svcAuth.CreateServiceAccount(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	// Omit SecretHash from the response — never return hashed secrets.
	sa.SecretHash = ""
	h.setZookieHeader(w, zookie)
	h.respond(w, http.StatusCreated, map[string]interface{}{
		"service_account": sa,
		"zookie":          zookie.Token,
	})
}

// deactivateServiceAccount marks a service account as inactive.
// Endpoint: DELETE /service-accounts/{client_id} (protected)
func (h *Handler) deactivateServiceAccount(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	zookie, err := h.svcAuth.DeactivateServiceAccount(r.Context(), clientID)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}
	h.setZookieHeader(w, zookie)
	h.respond(w, http.StatusOK, map[string]interface{}{
		"message": "service account deactivated",
		"zookie":  zookie.Token,
	})
}

// ── Health endpoints ──────────────────────────────────────────────────────────

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	h.respond(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.store.Ping(ctx); err != nil {
		h.logger.ErrorContext(r.Context(), "readiness check failed",
			slog.String("error", err.Error()))
		h.respond(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		return
	}
	h.respond(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ── Zookie helpers ────────────────────────────────────────────────────────────

// readZookie parses the X-Zookie request header into a *domain.Zookie.
// Returns nil if the header is absent (caller accepts BestEffort reads).
// Returns a non-nil Zookie when the header is present — even if the token
// string is empty — so the repository will perform a strong read.
func (h *Handler) readZookie(r *http.Request) *domain.Zookie {
	v := r.Header.Get(zookieHeader)
	if v == "" {
		return nil
	}
	return &domain.Zookie{Token: v}
}

// setZookieHeader writes the Zookie token into the response header so clients
// can cache it without parsing the response body.
func (h *Handler) setZookieHeader(w http.ResponseWriter, z domain.Zookie) {
	if z.HasToken() {
		w.Header().Set(zookieHeader, z.Token)
	}
}

// ── Generic helpers ───────────────────────────────────────────────────────────

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		h.writeError(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func (h *Handler) respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("encode response", slog.String("error", err.Error()))
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	h.respond(w, status, map[string]string{"error": msg})
}

// handleServiceError maps domain sentinel errors to HTTP status codes.
// Technical details are logged server-side; only generic messages reach clients.
func (h *Handler) handleServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		h.writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		h.writeError(w, http.StatusConflict, "user already exists")
	case errors.Is(err, domain.ErrInvalidCredentials):
		h.writeError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, domain.ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "invalid input")
	case errors.Is(err, domain.ErrUnauthorized):
		h.writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, domain.ErrTokenExpired):
		h.writeError(w, http.StatusUnauthorized, "token expired")
	case errors.Is(err, domain.ErrTokenInvalid):
		h.writeError(w, http.StatusUnauthorized, "invalid token")
	case errors.Is(err, domain.ErrRateLimited):
		h.writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
	default:
		h.logger.ErrorContext(r.Context(), "unhandled service error",
			slog.String("error", err.Error()),
			slog.String("path", r.URL.Path),
		)
		h.writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
