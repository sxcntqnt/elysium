package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors — compared with errors.Is, allocated once.
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidInput       = errors.New("invalid input")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrRateLimited        = errors.New("rate limit exceeded")
)

// Compiled once at package level — regexp compilation is O(n) and allocates.
var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	nicknameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]{3,32}$`)
)

// User is the core domain entity. No framework or DB dependencies live here.
type User struct {
	ID           string    `json:"id"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Nickname     string    `json:"nickname"`
	PasswordHash string    `json:"-"` // never serialised to JSON
	Email        string    `json:"email"`
	Country      string    `json:"country"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CreateUserInput carries validated, sanitised input for user creation.
type CreateUserInput struct {
	FirstName string
	LastName  string
	Nickname  string
	Password  string // plaintext — hashed before persistence
	Email     string
	Country   string
}

// Validate enforces business rules at the boundary before any persistence.
func (i *CreateUserInput) Validate() error {
	i.Email = strings.ToLower(strings.TrimSpace(i.Email))
	i.Nickname = strings.TrimSpace(i.Nickname)
	i.FirstName = strings.TrimSpace(i.FirstName)
	i.LastName = strings.TrimSpace(i.LastName)
	i.Country = strings.TrimSpace(i.Country)

	if i.FirstName == "" || i.LastName == "" {
		return ErrInvalidInput
	}
	if !emailRegex.MatchString(i.Email) {
		return ErrInvalidInput
	}
	if !nicknameRegex.MatchString(i.Nickname) {
		return ErrInvalidInput
	}
	if len(i.Password) < 8 {
		return ErrInvalidInput
	}
	if i.Country == "" {
		return ErrInvalidInput
	}
	return nil
}

// UpdateUserInput carries validated fields for a partial user update.
// Pointer fields allow distinguishing "not provided" from zero value.
type UpdateUserInput struct {
	FirstName *string
	LastName  *string
	Nickname  *string
	Country   *string
}

// LoginInput carries credentials for authentication.
type LoginInput struct {
	Email    string
	Password string
}

// Validate sanitises and checks credentials before any DB call.
func (i *LoginInput) Validate() error {
	i.Email = strings.ToLower(strings.TrimSpace(i.Email))
	if !emailRegex.MatchString(i.Email) {
		return ErrInvalidInput
	}
	if i.Password == "" {
		return ErrInvalidInput
	}
	return nil
}

// ListFilter defines optional filters and pagination for user listing.
type ListFilter struct {
	Country  string
	Page     int
	PageSize int
}

// Normalise applies safe defaults so callers don't have to.
func (f *ListFilter) Normalise() {
	if f.Page < 1 {
		f.Page = 1
	}
	switch {
	case f.PageSize < 1:
		f.PageSize = 20
	case f.PageSize > 100:
		f.PageSize = 100
	}
}

// ListResult is the paginated response from the repository.
type ListResult struct {
	Users []*User
	Total int
	Page  int
	Pages int
}

// TokenPair holds access and refresh tokens issued at login.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
}

// PrincipalKind distinguishes human users from service accounts in the token.
type PrincipalKind string

const (
	PrincipalKindUser    PrincipalKind = "user"
	PrincipalKindService PrincipalKind = "service"
)

// Principal is the unified identity returned by token verification.
// It represents either a human user (with an optional active actor context)
// or an authenticated service account.
//
// Two token varieties exist for human users:
//
//	Basic token (from POST /auth/login):
//	  Kind=user, UserID, Nickname, Email set.
//	  ActorID, ActorType, Permissions, DelegatedPermissions, PolicyGroups are empty.
//	  Use this for endpoints that only require authentication, not authorisation.
//
//	Context-scoped token (from POST /auth/context/activate):
//	  All fields set. ActorType matches one of the 24 Dgraph ActorType values.
//	  Permissions/DelegatedPermissions are flattened allow-only action strings,
//	  mirroring ActiveContext.permissions in the Dgraph schema.
//	  Use this for endpoints that require role-based authorisation.
type Principal struct {
	Kind PrincipalKind

	// ActorType is the specific role this principal is currently operating as.
	//   - Users:    one of the 24 ActorType values; empty on basic login tokens.
	//   - Services: the ActorType assigned to the service account at creation.
	ActorType ActorType

	// ── User fields — populated when Kind == PrincipalKindUser ───────────────
	UserID   string
	ActorID  string // the specific actor record ID (actors table / Dgraph Actor node)
	Nickname string
	Email    string

	// Permissions from the active actor context — flattened allow-only action
	// strings. Mirrors ActiveContext.permissions in the Dgraph schema.
	// Empty for basic (non-context-scoped) user tokens.
	Permissions          []string
	DelegatedPermissions []string
	PolicyGroups         []string // policyGroupIds on the Dgraph Actor node

	// ── Service fields — populated when Kind == PrincipalKindService ─────────
	ClientID string // unique service identifier
	Name     string // human-readable service name
}

// HasPermission reports whether the principal's embedded permissions include
// the given allow action string. Fast in-memory check — no Dgraph round-trip.
//
// For authoritative scope-sensitive checks (deny-aware, org-scoped), query
// Dgraph's EffectivePermission type directly.
func (p *Principal) HasPermission(action string) bool {
	for _, perm := range p.Permissions {
		if perm == action {
			return true
		}
	}
	for _, perm := range p.DelegatedPermissions {
		if perm == action {
			return true
		}
	}
	return false
}

// IsActorType reports whether this principal is operating as the given actor type.
func (p *Principal) IsActorType(t ActorType) bool { return p.ActorType == t }

// IsOrgStaff reports whether this principal is operating as any org staff role.
// Mirrors the ORG_STAFF_TYPES.includes() check in context.template.ts.
func (p *Principal) IsOrgStaff() bool { return IsOrgStaff(p.ActorType) }

// HasContext reports whether this is a context-scoped token (actor type activated).
// Basic login tokens return false; context tokens from /auth/context/activate return true.
func (p *Principal) HasContext() bool { return p.ActorID != "" && p.ActorType.IsValid() }
