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
	"sxcntqnt/auth-service/internal/service"
)

// zookieHeader is the HTTP header used to convey Zookie consistency tokens.
// Clients receive this header on write responses and send it on read requests.
const zookieHeader = "X-Zookie"

// AuthServicer is the subset of service.AuthService the HTTP handler needs.
//
// Login and ActivateContext no longer return *domain.TokenPair. Token
// minting moved to SessionService — AuthServicer now only validates
// credentials/ownership and returns resolved domain entities. The handler
// is responsible for taking that output and calling SessionService.Create /
// SessionService.ActivateContext to mint the opaque tokens actually sent
// to the client.
//
// VerifyToken is removed from this interface. The middleware.Authenticate
// wrapper that used to depend on AuthServicer.VerifyToken now depends on
// *service.SessionService.VerifyToken instead (SessionService satisfies
// middleware.TokenVerifier directly — see service/session.go) — wired at
// the composition root, no change needed in middleware/middleware.go.
type AuthServicer interface {
	Register(ctx context.Context, input domain.CreateUserInput) (*domain.User, domain.Zookie, error)
	Login(ctx context.Context, input domain.LoginInput) (*domain.User, error)
	ActivateContext(ctx context.Context, callerID string, input domain.ContextActivationInput) (*domain.ContextActivationInput, error)
	GetUser(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error)
	UpdateUser(ctx context.Context, callerID, targetID string, input domain.UpdateUserInput) (*domain.User, domain.Zookie, error)
	DeleteUser(ctx context.Context, callerID, targetID string) (domain.Zookie, error)
	ListUsers(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error)
}

// RepoHealther is satisfied by any store with a Ping method.
type RepoHealther interface {
	Ping(ctx context.Context) error
}

// ServiceAuthServicer is the subset of service.ServiceAuthService the HTTP
// handler needs. Login no longer returns *domain.TokenPair — same rationale
// as AuthServicer above.
type ServiceAuthServicer interface {
	CreateServiceAccount(ctx context.Context, input domain.CreateServiceAccountInput) (*domain.ServiceAccount, domain.Zookie, error)
	Login(ctx context.Context, input domain.ServiceLoginInput) (*domain.ServiceAccount, error)
	DeactivateServiceAccount(ctx context.Context, clientID string) (domain.Zookie, error)
}

// Handler holds HTTP handler dependencies.
type Handler struct {
	svc      AuthServicer
	svcAuth  ServiceAuthServicer
	sessions *service.SessionService
	store    RepoHealther
	logger   *slog.Logger
}

// New constructs a Handler. All dependencies injected — no globals.
// sessions is the new dependency: every endpoint that used to receive a
// *domain.TokenPair from svc/svcAuth now calls sessions.Create or
// sessions.ActivateContext as a second step to mint the client-facing
// opaque token pair.
func New(svc AuthServicer, svcAuth ServiceAuthServicer, sessions *service.SessionService, store RepoHealther, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, svcAuth: svcAuth, sessions: sessions, store: store, logger: logger}
}

// RegisterRoutes attaches all routes to mux. Unchanged from the JWT-based
// version — the route surface, protected() wrapper, and authMW contract are
// identical. Only what authMW is built from changes (see composition root):
// it now wraps middleware.Authenticate(sessionService) instead of
// middleware.Authenticate(authService).
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

	// New session-lifecycle endpoints. Added rather than replacing anything
	// above — POST /auth/login still exists and still returns tokens, it
	// just mints them via SessionService now instead of token.Manager.
	mux.HandleFunc("POST /auth/refresh", h.refresh)
	mux.Handle("POST /auth/logout", protected(h.logout))
	mux.Handle("POST /auth/logout-all", protected(h.logoutAll))
	mux.Handle("GET /auth/sessions", protected(h.listSessions))
	mux.Handle("DELETE /auth/sessions/{id}", protected(h.revokeSession))

	// GET /auth/verify — the NGINX forward-auth endpoint. Deliberately not
	// wrapped in protected(): it IS the auth check NGINX calls before
	// proxying to any upstream, so it can't depend on authMW having already
	// run. It does its own bearer-token validation and returns identity
	// headers (200) or 401, with no body either way.
	mux.HandleFunc("GET /auth/verify", h.verify)

	// GET /auth/me — current identity, listed in the document's endpoint
	// table as "useful" alongside /auth/verify.
	mux.Handle("GET /auth/me", protected(h.me))
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

// login authenticates the caller, then mints an opaque session token pair.
// Phase 1 (h.svc.Login) is pure credential verification — it returns the
// resolved User with no tokens attached. Phase 2 (h.sessions.Create) mints
// the access/refresh pair. The refresh token goes ONLY into the HttpOnly
// cookie (see setRefreshCookie) — it is deliberately never echoed in the
// JSON body. Putting it in the body as well as the cookie would defeat the
// entire point of HttpOnly: any XSS that can read the response body can
// then read the refresh token just as easily as if it had been stored in
// localStorage. The response shape is otherwise the same as the old
// domain.TokenPair minus refresh_token: { access_token, expires_in }.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var input domain.LoginInput
	if !h.decode(w, r, &input) {
		return
	}

	user, err := h.svc.Login(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	out, err := h.sessions.Create(r.Context(), service.CreateSessionInput{
		Kind:      domain.PrincipalKindUser,
		UserID:    user.ID,
		UserAgent: r.UserAgent(),
		IPAddress: clientIP(r),
	})
	if err != nil {
		h.logger.ErrorContext(r.Context(), "session create failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	h.setRefreshCookie(w, out.RefreshToken, out.Session.RefreshExpiresAt)

	// Login is a read — no zookie in the response.
	h.respond(w, http.StatusOK, map[string]any{
		"access_token": out.AccessToken,
		"expires_in":   int64(h.sessions.AccessTTL().Seconds()),
	})
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

// activateContext exchanges the caller's current session for one scoped to
// the requested actor context.
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
//  1. Client calls POST /auth/login → gets a basic session (no actor context).
//  2. Client calls Dgraph getActiveContext(userId, contextType) → gets context.
//  3. Client calls this endpoint with the Dgraph response → gets a new
//     session scoped to that actor context; the old session is revoked.
//
// The resulting access token's session carries the full ActiveContext
// fields, enabling downstream services (via /auth/verify -> NGINX headers)
// to authorise requests without a Dgraph round-trip.
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

	// Phase 1: AuthService enforces ownership (input.UserID == principal.UserID)
	// and ActorType/ActorID validity. It does not query Dgraph — by this point
	// the caller has already resolved input from Dgraph's getActiveContext.
	validated, err := h.svc.ActivateContext(r.Context(), principal.UserID, input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	// Phase 2: SessionService revokes the caller's current session (read from
	// the Authorization header that authMW already validated) and mints a
	// new opaque token pair scoped to the activated context.
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	out, err := h.sessions.ActivateContext(
		r.Context(),
		bearer,
		validated.ActorID,
		validated.ActorType,
		validated.Permissions,
		validated.DelegatedPermissions,
		validated.PolicyGroups,
		0, // PermissionVersion: not yet surfaced by ContextActivationInput
	)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "context activation session mint failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "context activation failed")
		return
	}

	h.setRefreshCookie(w, out.RefreshToken, out.Session.RefreshExpiresAt)

	h.respond(w, http.StatusOK, map[string]any{
		"access_token": out.AccessToken,
		"expires_in":   int64(h.sessions.AccessTTL().Seconds()),
		"actor_type":   string(out.Session.ActorType),
	})
}

// ── Service auth endpoints ────────────────────────────────────────────────────

// serviceLogin authenticates a service account and returns an opaque
// session access token. The refresh token, as with login, goes only into
// the HttpOnly cookie — not the JSON body.
// Endpoint: POST /auth/service/token
// Request:  {"client_id": "my-service", "client_secret": "..."}
// Response: {"access_token": "...", "expires_in": 900}
func (h *Handler) serviceLogin(w http.ResponseWriter, r *http.Request) {
	var input domain.ServiceLoginInput
	if !h.decode(w, r, &input) {
		return
	}

	acct, err := h.svcAuth.Login(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	out, err := h.sessions.Create(r.Context(), service.CreateSessionInput{
		Kind:        domain.PrincipalKindService,
		ClientID:    acct.ClientID,
		ActorType:   acct.ActorType,
		Permissions: acct.Permissions,
		UserAgent:   r.UserAgent(),
		IPAddress:   clientIP(r),
	})
	if err != nil {
		h.logger.ErrorContext(r.Context(), "service session create failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	h.setRefreshCookie(w, out.RefreshToken, out.Session.RefreshExpiresAt)

	h.respond(w, http.StatusOK, map[string]any{
		"access_token": out.AccessToken,
		"expires_in":   int64(h.sessions.AccessTTL().Seconds()),
	})
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

// ── Session lifecycle endpoints (new) ─────────────────────────────────────────

// refresh rotates the caller's refresh token and returns a new access token.
// Endpoint: POST /auth/refresh
// Reads the refresh token from the HttpOnly cookie set by login/serviceLogin/
// activateContext — not from the request body, so the token never needs to
// be readable by client-side script.
func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "no refresh token")
		return
	}

	out, err := h.sessions.Refresh(r.Context(), service.RefreshInput{
		RawRefreshToken: cookie.Value,
		UserAgent:       r.UserAgent(),
		IPAddress:       clientIP(r),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRefreshReplayed):
			h.logger.WarnContext(r.Context(), "refresh token replay detected — all sessions revoked",
				slog.String("ip", clientIP(r)))
			h.clearRefreshCookie(w)
			h.writeError(w, http.StatusUnauthorized, "session compromised; please log in again")
		case errors.Is(err, service.ErrRefreshExpired):
			h.clearRefreshCookie(w)
			h.writeError(w, http.StatusUnauthorized, "session expired; please log in again")
		default:
			h.writeError(w, http.StatusUnauthorized, "invalid refresh token")
		}
		return
	}

	h.setRefreshCookie(w, out.RefreshToken, out.Session.RefreshExpiresAt)
	h.respond(w, http.StatusOK, map[string]any{
		"access_token": out.AccessToken,
		"expires_in":   int64(h.sessions.AccessTTL().Seconds()),
	})
}

// logout revokes the session tied to the caller's current access token.
// Endpoint: POST /auth/logout (protected)
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := h.sessions.Logout(r.Context(), bearer); err != nil {
		h.logger.ErrorContext(r.Context(), "logout failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	h.clearRefreshCookie(w)
	h.respond(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// logoutAll revokes every session for the caller's user account.
// Endpoint: POST /auth/logout-all (protected)
func (h *Handler) logoutAll(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromContext(r.Context())
	if principal == nil || principal.Kind != domain.PrincipalKindUser {
		h.writeError(w, http.StatusForbidden, "not available for service accounts")
		return
	}
	if err := h.sessions.LogoutAll(r.Context(), principal.UserID); err != nil {
		h.logger.ErrorContext(r.Context(), "logout-all failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	h.clearRefreshCookie(w)
	h.respond(w, http.StatusOK, map[string]string{"status": "all sessions revoked"})
}

// listSessions returns the caller's active sessions ("active devices" view).
// Endpoint: GET /auth/sessions (protected)
func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromContext(r.Context())
	if principal == nil || principal.Kind != domain.PrincipalKindUser {
		h.writeError(w, http.StatusForbidden, "not available for service accounts")
		return
	}

	sessions, err := h.sessions.ListSessions(r.Context(), principal.UserID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "list sessions failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}

	type sessionView struct {
		ID         string    `json:"id"`
		ActorType  string    `json:"actor_type,omitempty"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		UserAgent  string    `json:"user_agent,omitempty"`
	}
	views := make([]sessionView, len(sessions))
	for i, s := range sessions {
		views[i] = sessionView{
			ID:         s.ID,
			ActorType:  string(s.ActorType),
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			ExpiresAt:  s.ExpiresAt,
			UserAgent:  s.UserAgent,
		}
	}
	h.respond(w, http.StatusOK, map[string]any{"sessions": views})
}

// revokeSession revokes one specific session, identified by path id.
// Endpoint: DELETE /auth/sessions/{id} (protected)
func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromContext(r.Context())
	if principal == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	targetID := r.PathValue("id")
	if targetID == "" {
		h.writeError(w, http.StatusBadRequest, "session id required")
		return
	}
	if err := h.sessions.RevokeSession(r.Context(), targetID, principal.UserID); err != nil {
		switch {
		case errors.Is(err, service.ErrSessionNotFound):
			h.writeError(w, http.StatusNotFound, "session not found")
		case errors.Is(err, service.ErrSessionNotOwned):
			h.writeError(w, http.StatusForbidden, "not your session")
		default:
			h.writeError(w, http.StatusInternalServerError, "could not revoke session")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Gateway / identity endpoints (new) ────────────────────────────────────────

// verify is the NGINX forward-auth endpoint from the document's architecture
// section. NGINX calls this via auth_request before allowing any upstream
// request through. It validates the bearer token via SessionService and
// returns identity headers for NGINX to inject into the proxied request.
//
//	200 OK   -> upstream allowed; X-* headers populated.
//	401      -> upstream denied; no body (NGINX returns its own error page).
//
// Deliberately bypasses authMW/protected(): this endpoint is itself the
// auth check, not a consumer of one.
func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	principal, err := h.sessions.VerifyToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Principal-Kind", string(principal.Kind))
	switch principal.Kind {
	case domain.PrincipalKindUser:
		w.Header().Set("X-User-Id", principal.UserID)
		w.Header().Set("X-Actor-Id", principal.ActorID)
		w.Header().Set("X-Actor-Type", string(principal.ActorType))
	case domain.PrincipalKindService:
		w.Header().Set("X-Client-Id", principal.ClientID)
		w.Header().Set("X-Service-Name", principal.Name)
	}
	if len(principal.Permissions) > 0 {
		w.Header().Set("X-Permissions", strings.Join(principal.Permissions, ","))
	}
	if len(principal.DelegatedPermissions) > 0 {
		w.Header().Set("X-Delegated-Permissions", strings.Join(principal.DelegatedPermissions, ","))
	}
	if len(principal.PolicyGroups) > 0 {
		w.Header().Set("X-Policy-Groups", strings.Join(principal.PolicyGroups, ","))
	}

	w.WriteHeader(http.StatusOK)
}

// me returns the caller's current identity as JSON.
// Endpoint: GET /auth/me (protected)
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromContext(r.Context())
	if principal == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	resp := map[string]any{"kind": string(principal.Kind)}
	switch principal.Kind {
	case domain.PrincipalKindUser:
		resp["user_id"] = principal.UserID
		resp["actor_id"] = principal.ActorID
		resp["actor_type"] = string(principal.ActorType)
		// Nickname/Email are not currently populated here: domain.Session
		// (and SessionCreateInput) don't carry these fields yet, so
		// sessionToPrincipal leaves them empty. The old JWT-based Principal
		// had them because the JWT claims embedded nickname/email directly
		// at issue time. If /auth/me needs these, either add the fields to
		// Session/SessionCreateInput and pass them through Create, or have
		// this handler do a GetUser lookup as a second call.
		resp["nickname"] = principal.Nickname
		resp["email"] = principal.Email
		resp["permissions"] = principal.Permissions
		resp["delegated_permissions"] = principal.DelegatedPermissions
		resp["policy_groups"] = principal.PolicyGroups
	case domain.PrincipalKindService:
		resp["client_id"] = principal.ClientID
		resp["service_name"] = principal.Name // same caveat: not yet populated by sessionToPrincipal
		resp["actor_type"] = string(principal.ActorType)
	}
	h.respond(w, http.StatusOK, resp)
}

// ── Refresh cookie helpers (new) ──────────────────────────────────────────────

// refreshCookieName/refreshCookiePath mirror the narrow-scope cookie pattern:
// HttpOnly, scoped only to the refresh endpoint, never readable by script.
const (
	refreshCookieName = "rtk"
	refreshCookiePath = "/auth/refresh"
)

func (h *Handler) setRefreshCookie(w http.ResponseWriter, rawToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    rawToken,
		Path:     refreshCookiePath,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   true, // production is HTTPS-only; adjust via config if a non-TLS dev path is needed
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clientIP mirrors middleware.clientIP (unexported there, so duplicated here
// rather than depending on an internal helper across packages). Honours
// X-Forwarded-For from the trusted NGINX hop, falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	return r.RemoteAddr
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
