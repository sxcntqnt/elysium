// Package middleware provides HTTP middleware for the auth service.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"sxcntqnt/auth-service/internal/domain"
)

type contextKey int

const principalKey contextKey = iota

// TokenVerifier is the subset of the auth service the middleware needs.
// ctx is required because Transit implementations call Vault on every verify.
//
// This interface is satisfied by *service.SessionService.VerifyToken as of
// the opaque-token migration (see service/session.go), not by
// *service.AuthService anymore — AuthService no longer has a VerifyToken
// method at all. No change is needed in this file beyond what's below:
// the composition root now constructs Authenticate(sessionService) instead
// of Authenticate(authService).
type TokenVerifier interface {
	VerifyToken(ctx context.Context, tokenString string) (*domain.Principal, error)
}

// Authenticate extracts and validates the Bearer token from the Authorization
// header. On success it stores the claims in the request context.
func Authenticate(verifier TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or malformed authorization header")
				return
			}

			// Pass r.Context() so the Vault Transit call can be cancelled if
			// the client disconnects before the token is verified.
			claims, err := verifier.VerifyToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
			if err != nil {
				// errors.Is, not switch err { case ... }: a plain equality
				// switch only matches if VerifyToken returns the sentinel
				// completely unwrapped. SessionService.VerifyToken's
				// underlying lookupAndCheck wraps lookup failures with
				// fmt.Errorf("...: %w", err) in some paths, and any future
				// caller (or a different TokenVerifier implementation) may
				// wrap further. errors.Is unwraps the chain correctly either
				// way; == silently degrades every wrapped sentinel to the
				// generic "invalid token" branch below, which would hide
				// genuine expiries and revocations behind the wrong message
				// and status semantics stay correct only by accident.
				switch {
				case errors.Is(err, domain.ErrTokenExpired):
					writeError(w, http.StatusUnauthorized, "token expired")
				default:
					writeError(w, http.StatusUnauthorized, "invalid token")
				}
				return
			}

			ctx := context.WithValue(r.Context(), principalKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PrincipalFromContext retrieves the Principal stored by Authenticate.
// Returns nil for unauthenticated requests.
func PrincipalFromContext(ctx context.Context) *domain.Principal {
	c, _ := ctx.Value(principalKey).(*domain.Principal)
	return c
}

// RateLimiter returns a per-IP rate limiting middleware.
// ip limiters are cleaned up after 5 minutes of inactivity to prevent
// the map from growing without bound (unbounded maps are a DoS vector).
func RateLimiter(rps float64, burst int) func(http.Handler) http.Handler {
	type entry struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      = newShardedMu(32) // 32-shard mutex — reduces lock contention
		clients = make(map[string]*entry)
	)

	// Background cleanup goroutine. Uses time.NewTimer — NOT time.After —
	// to avoid the goroutine-leak that time.After causes in loops.
	go func() {
		t := time.NewTimer(time.Minute)
		defer t.Stop()
		for {
			<-t.C
			mu.lockAll()
			for ip, e := range clients {
				if time.Since(e.lastSeen) > 5*time.Minute {
					delete(clients, ip)
				}
			}
			mu.unlockAll()
			t.Reset(time.Minute)
		}
	}()

	getLimiter := func(ip string) *rate.Limiter {
		mu.lock(ip)
		defer mu.unlock(ip)
		e, ok := clients[ip]
		if !ok {
			e = &entry{limiter: rate.NewLimiter(rate.Limit(rps), burst)}
			clients[ip] = e
		}
		e.lastSeen = time.Now()
		return e.limiter
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !getLimiter(clientIP(r)).Allow() {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogger logs each request with method, path, status, and duration.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.InfoContext(r.Context(), "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("ip", clientIP(r)),
			)
		})
	}
}

// SecurityHeaders sets conservative security headers on every response.
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Content-Security-Policy", "default-src 'none'")
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes middleware right-to-left: Chain(a, b, c)(h) → a(b(c(h))).
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// ─── internal helpers ─────────────────────────────────────────────────────────

type responseWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.status = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	//nolint:errcheck
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// shardedMu reduces contention on the rate limiter map by splitting the
// keyspace across 32 independent channels used as mutex tokens.
type shardedMu struct {
	shards []chan struct{}
	n      int
}

func newShardedMu(n int) *shardedMu {
	s := &shardedMu{shards: make([]chan struct{}, n), n: n}
	for i := range s.shards {
		s.shards[i] = make(chan struct{}, 1)
		s.shards[i] <- struct{}{}
	}
	return s
}

func (s *shardedMu) shard(key string) int {
	h := 0
	for _, c := range key {
		h = h*31 + int(c)
	}
	idx := h % s.n
	if idx < 0 {
		idx = -idx
	}
	return idx
}

func (s *shardedMu) lock(key string)   { <-s.shards[s.shard(key)] }
func (s *shardedMu) unlock(key string) { s.shards[s.shard(key)] <- struct{}{} }

func (s *shardedMu) lockAll() {
	for _, sh := range s.shards {
		<-sh
	}
}
func (s *shardedMu) unlockAll() {
	for _, sh := range s.shards {
		sh <- struct{}{}
	}
}
