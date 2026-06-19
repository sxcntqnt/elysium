# auth-service

Internal identity and authorization platform for the Matatu Pulse system. Issues, verifies, and revokes session credentials for both human users and machine (service-account) callers, and is the system of record for actor context (role) activation.

This service is the migration target described in the session-architecture build guide: it moved from self-contained JWTs to **opaque, server-resolved session tokens**, so that revocation, replay detection, and "log out everywhere" are first-class operations instead of being impossible until a JWT's `exp` naturally elapses.

## Architecture at a glance

```
Client
  │ Authorization: Bearer atk_xxxx  (access token)
  │ Cookie: rtk=rtk_xxxx             (refresh token, HttpOnly, /auth/refresh only)
  ▼
HTTP handler  ──┐                    gRPC handler ──┐
  (transport)   │                    (transport)    │
                ▼                                    ▼
        AuthService / ServiceAuthService     (credential checks,
                                               user/service-account CRUD —
                                               NEVER mints tokens)
                │
                ▼
          SessionService   (the only place that mints or verifies
                             client-facing tokens)
                │
                ▼
      repository.SessionRepository  →  Dgraph (Session nodes,
      (impl: dgraph.SessionRepo)        hashed tokens only)
```

Two services own two different concerns and neither leaks into the other:

- **`AuthService` / `ServiceAuthService`** (`internal/service/auth.go`, `service_auth.go`) verify credentials (bcrypt, timing-safe comparisons, strong reads) and own user / service-account CRUD. They return resolved domain entities (`*domain.User`, `*domain.ServiceAccount`) — they have no concept of tokens.
- **`SessionService`** (`internal/service/session.go`) is the only component that mints, rotates, validates, and revokes the opaque tokens clients actually hold. Both the HTTP and gRPC transports call it as a second step after credential validation succeeds.

This split means a credential check and a token-minting decision are independently testable, and a future identity store swap (Keygraph) only touches the repository layer, not session semantics.

`domain.Session.Kind` reuses the existing `domain.PrincipalKind` type (`PrincipalKindUser` / `PrincipalKindService`) that already backed JWT-based `Principal` — there is no separate `TokenKind` type. An earlier draft of this migration introduced a parallel `TokenKind` type plus a second `Principal` struct directly in `domain/session.go`; both were duplicate declarations against the existing `domain/user.go` types and were caught only once `go run` actually compiled the package (`Principal redeclared in this block`). They were removed before this version; see "Known gaps and deliberate deferrals" for the broader lesson this surfaced.

On the repository side, `repository.SessionRepository` is implemented by `dgraph.SessionRepo` (`internal/repository/dgraph/session.go`) — a thin wrapper holding a `*Repository` reference, not a set of new methods bolted directly onto `*Repository` itself. This mirrors `dgraph.ServiceAccountRepo` exactly, and for the same reason: `*Repository` already declares `Create`, `GetByID`, and `queryOne` for the `User` type, so a session-specific `Create`/`GetByID` on the same receiver type would be a duplicate method declaration, not an overload — Go has no method overloading. `dgraph.NewSessionRepo(repo)` shares the same underlying Dgraph connection as the `*Repository` it wraps; nothing about the connection pool changes, only the method set each wrapper exposes.

## Why opaque tokens instead of JWTs

A self-contained JWT is unrevocable by construction — once issued, it is valid until it expires, no matter what happens server-side. That is a structural risk for stolen-token and compromised-integration scenarios; this is the exact failure mode that motivated the opaque-token design (see "Replay detection" below for the specific defense against reused refresh tokens). Moving to opaque, server-resolved tokens trades a small amount of latency (one Dgraph lookup per request) for:

- **Real revocation** — logout, logout-all-devices, and admin-initiated revocation take effect immediately, not at natural token expiry.
- **Replay detection** — reusing a rotated-away refresh token is detectable and triggers automatic revocation of the entire session family (see `SessionService.Refresh`).
- **No client-side claim inspection** — clients never see permissions, actor type, or policy groups; only the resolved identity headers NGINX injects downstream ever carry that data.
- **One verification path for two transports** — HTTP and gRPC both call `SessionService.VerifyToken`; there is exactly one place that decides whether a token is valid.

The previous JWT-based `token.Manager` (`internal/token/jwt.go`) is left in the codebase but is no longer called by either transport. It can be removed in a follow-up cleanup once it's confirmed nothing else in this deployment needs raw JWT issuance.

## Token model

| | Access token | Refresh token |
|---|---|---|
| Format | `atk_<64 hex chars>` | `rtk_<64 hex chars>` |
| Entropy source | `crypto/rand`, 32 bytes | `crypto/rand`, 32 bytes |
| Stored as | SHA-256 hash only | SHA-256 hash only |
| Lifetime | 15 minutes (default, configurable) | 30 days (default, configurable) |
| Transport (HTTP) | JSON response body, `Authorization: Bearer` on subsequent calls | **HttpOnly cookie only**, scoped to `/auth/refresh`. Never echoed in any JSON response body. |
| Transport (gRPC) | Response message field | Response message field (no cookie concept in gRPC; caller is responsible for secure storage) |
| Rotation | N/A | Rotated on every `/auth/refresh` call. Reuse of an already-rotated token revokes the entire session family. |

Raw token values are generated in `internal/token/opaque.go` and exist in memory only long enough to be hashed and handed to the client once. The database (`repository/dgraph/session.go`) never stores anything except the SHA-256 hash, the refresh-token JTI, and the audit/lifecycle metadata in `domain.Session`.

### Why the refresh token is cookie-only on HTTP

Putting the refresh token in a JSON response body in addition to the `HttpOnly` cookie would defeat the purpose of `HttpOnly`: any XSS that can read a response body can read a body field just as easily as it could read `localStorage`. Every HTTP endpoint that mints or rotates tokens (`login`, `serviceLogin`, `activateContext`, `refresh`) returns only `{ access_token, expires_in }` and sets the refresh token exclusively via `Set-Cookie` with `HttpOnly`, `Secure`, and `SameSite=Strict`.

## Session lifecycle

```
POST /auth/login  ──────────────► Session created, no actor context
        │
        ▼
POST /auth/context/activate  ──► Old session revoked, new session
        │                         created scoped to the activated
        │                         actor (DRIVER, DISPATCHER, etc.)
        ▼
GET /auth/verify  (NGINX forward-auth, called on every proxied request)
        │
        ▼
POST /auth/refresh  ─────────────► Old refresh token revoked, new
        │                          access+refresh pair issued
        ▼
POST /auth/logout | /auth/logout-all  ──► Session(s) revoked immediately
```

Service accounts follow the same `Session` model under `domain.PrincipalKindService` — there is one session store and one verification path for both principal kinds, not two parallel systems.

### Replay detection

`SessionService.Refresh` checks whether the presented refresh token belongs to a session that is already revoked. If so, this is treated as a compromise signal (either a genuine stolen-token replay, or two concurrent refresh calls racing each other) and **every session belonging to that user is revoked**, not just the one being refreshed. The client is told to re-authenticate from scratch.

## Routes

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/register` | none | |
| POST | `/auth/login` | none | Mints a basic session, no actor context |
| POST | `/auth/service/token` | none | Service-account login |
| POST | `/auth/refresh` | refresh cookie | Rotates the refresh token |
| POST | `/auth/logout` | bearer | Revokes the current session |
| POST | `/auth/logout-all` | bearer | Revokes every session for the user |
| GET | `/auth/sessions` | bearer | "Active devices" view |
| DELETE | `/auth/sessions/{id}` | bearer | Revoke one specific session (ownership-checked) |
| POST | `/auth/context/activate` | bearer | Exchanges current session for one scoped to an actor context |
| GET | `/auth/verify` | bearer | **NGINX forward-auth endpoint.** Not wrapped in the usual auth middleware — it *is* the auth check. Returns `X-User-Id` / `X-Actor-Type` / `X-Permissions` etc. headers on 200, empty body on 401. |
| GET | `/auth/me` | bearer | Current identity as JSON |
| GET / PUT / DELETE | `/users`, `/users/{id}` | bearer | Existing user CRUD, unchanged by this migration |
| POST / DELETE | `/service-accounts`, `/service-accounts/{client_id}` | bearer | Existing service-account management, unchanged |
| GET | `/health`, `/ready` | none | Liveness / readiness probes |

The `GET /auth/verify` endpoint is the integration point for an NGINX (or Traefik/Caddy) `auth_request` forward-auth setup: NGINX calls it before proxying to any upstream service, and injects the returned `X-*` headers into the proxied request so downstream microservices never need to parse a token themselves.

## Known gaps and deliberate deferrals

These are tracked rather than silently fixed, since some require a decision this README doesn't make on your behalf. A few entries below are resolved-but-worth-remembering: real `go run` compile failures hit during this migration, kept here so the same mistake isn't reintroduced by a future edit.

**Open:**

- **`ContextResolver.ResolveActiveContext`** has no concrete implementation yet. It's the seam where the handler is meant to consume Dgraph's `getActiveContext` lambda query (defined in `scripts/schema/04-queries.graphql`) before calling `AuthService.ActivateContext`. Currently interface-only.
- **`domain.Session` does not carry `Nickname`/`Email`/service `Name`.** `GET /auth/me` therefore returns empty strings for those fields on the user path. The old JWT-based `Principal` had them because the JWT claims embedded them at issue time; the session record does not yet. Fix requires extending `Session`/`SessionCreateInput` and threading the values through `SessionService.Create`.
- **`internal/token/jwt.go` (`token.Manager`) is unused dead code** as of this migration, along with the Vault `Signer` wiring in `cmd/server/main.go`'s step 4. Neither has been deleted, in case something outside this file set still depends on raw JWT issuance.
- **gRPC does not expose `ActivateContext` or service-account login as RPCs.** Only `Register`, `Login`, `GetUser`, `UpdateUser`, `DeleteUser`, `ListUsers`, and `HealthCheck` exist in the current `.proto`/generated `pb` package. Adding the others requires a proto schema change, not just a Go-side wire-up.
- **Pre-existing `ServiceAccount` nodes in Dgraph predate the `sa.actor_type` predicate fix** (`repository/dgraph/service_account.go`) and will read back with an empty `ActorType` until re-created or backfilled directly in Dgraph.
- **gRPC's `principalFromCtx` and HTTP's `Authenticate` middleware both collapse session errors into two buckets** (`domain.ErrTokenExpired` / `domain.ErrTokenInvalid`) rather than surfacing "revoked" as a distinct case. `SessionService.VerifyToken` translates its internal `ErrSessionExpired` / `ErrSessionRevoked` / `ErrSessionNotFound` sentinels down to that two-value `domain` vocabulary at its own boundary, specifically so `middleware` package stays decoupled from `service`. Callers that need the finer-grained distinction (logout, session management) should call `SessionService.ValidateSession` instead, which does not perform this translation.

**Resolved during this migration, kept as history:**

- **`Principal redeclared in this block`** — an earlier draft of `domain/session.go` declared its own `TokenKind` type and a second `Principal` struct, duplicating `domain/user.go`'s existing `PrincipalKind` and `Principal`. `go build`/`go run` rejected the package outright. Fixed by deleting both from `session.go` and having `Session.Kind` / `SessionCreateInput.Kind` use `domain.PrincipalKind` directly. If you're extending the session type with new identity-shaped fields, check `user.go` first — `Principal` already carries `UserID`, `ActorID`, `ActorType`, `Nickname`, `Email`, `ClientID`, `Name`, `Permissions`, `DelegatedPermissions`, `PolicyGroups`; there is rarely a reason to add a parallel field set rather than reuse what's there.
- **`method Repository.Create already declared`** (and the same for `GetByID`, `queryOne`) — the first draft of `repository/dgraph/session.go` declared `Create`/`GetByID`/`queryOne` directly on `*Repository`, colliding with the existing methods of the same name that operate on `*domain.User`. Go has no method overloading, so this is a hard compile error, not a runtime ambiguity. Fixed by introducing `dgraph.SessionRepo`, a wrapper struct holding `r *Repository` — the exact same pattern `dgraph.ServiceAccountRepo` already used for service accounts. Any future Dgraph-backed type that needs its own `Create`/`GetByID`-style methods should follow this wrapper pattern from the start rather than adding methods straight onto `*Repository`.
- **`assert.go` / `main.go` follow-on errors** — both of the bugs above cascaded into `repository/dgraph/assert.go` (asserting the wrong concrete type against `repository.SessionRepository`) and `cmd/server/main.go` (passing `repo` directly into `service.NewSessionService` instead of a constructed `dgraph.NewSessionRepo(repo)`). Both are fixed now that `SessionRepo` exists as its own type — `assert.go` checks `(*SessionRepo)(nil)`, and `main.go` constructs `sessionRepo := dgraph.NewSessionRepo(repo)` before passing it to `service.NewSessionService`, mirroring how `saRepo := dgraph.NewServiceAccountRepo(repo)` is already built two lines above it.

## NGINX forward-auth (deferred integration detail)

The original design discussion for this service covered wiring NGINX's `auth_request` directive against `GET /auth/verify`, with the auth service as the central identity provider for a broader microservice mesh. That NGINX-side configuration (the `location = /_auth { proxy_pass http://auth-service/auth/verify; }` block and surrounding `auth_request_set` directives) is infrastructure configuration that lives outside this Go repository and has not yet been written as part of this migration — `/auth/verify` is ready to be called, but the reverse-proxy configuration itself is a separate piece of work.

## Local development

```sh
make build      # builds bin/auth-service
docker compose up   # starts Dgraph + dependencies for local dev
```

Vault AppRole credentials (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`) must be present in the environment before the service can start — see `cmd/server/main.go`'s boot sequence comment for the full startup order. All other configuration (TTLs, bcrypt cost, Dgraph target, rate limits) is sourced from Vault KV v2 at startup, not from local environment variables or flags.
