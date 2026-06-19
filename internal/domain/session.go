package domain

import "time"

// Session is the central persistence unit for all authentication state.
// Clients receive opaque access and refresh tokens that map back to this
// record. The raw token strings are never persisted — only their SHA-256
// hashes are stored, so a database breach cannot be used to replay sessions.
//
// Both user sessions and service-account sessions are stored in this same
// type, differentiated by Kind. This gives us a single validation pipeline
// through /auth/verify regardless of caller identity.
//
// Session.Kind reuses domain.PrincipalKind ("user" / "service") from user.go
// rather than declaring a parallel type — they represent the same concept and
// mapping between them was a source of compile errors.
type Session struct {
	// ID is the canonical Dgraph UID for this session node.
	ID string `json:"id"`

	// Kind is "user" or "service". Reuses PrincipalKind so the session
	// and principal identity types are directly comparable without conversion.
	Kind PrincipalKind `json:"kind"`

	// --- Identity fields (mutually populated based on Kind) ---

	// UserID is the canonical domain profile UUID. Populated for Kind == PrincipalKindUser.
	UserID string `json:"user_id,omitempty"`

	// ClientID is the service-account identifier. Populated for Kind == PrincipalKindService.
	ClientID string `json:"client_id,omitempty"`

	// --- Actor context (populated after context activation) ---

	// ActorID is the active actor node UID within the user's profile graph.
	ActorID string `json:"actor_id,omitempty"`

	// ActorType is the role the actor is operating as (e.g., DRIVER, PASSENGER).
	ActorType ActorType `json:"actor_type,omitempty"`

	// --- Token hashes (raw tokens are never persisted) ---

	// AccessTokenHash is SHA-256(raw access token). Used for O(1) session
	// lookup on every /auth/verify call.
	AccessTokenHash string `json:"-"`

	// RefreshTokenHash is SHA-256(raw refresh token).
	RefreshTokenHash string `json:"-"`

	// RefreshJTI is a unique identifier for the current refresh token generation.
	// On rotation, a new JTI is issued and the old record is marked with
	// ReplacedByJTI. Reuse of a revoked JTI triggers full session revocation
	// (compromise detection).
	RefreshJTI string `json:"-"`

	// ReplacedByJTI is the JTI of the token that superseded this refresh token.
	// Non-empty means this refresh token has been rotated and must be rejected.
	ReplacedByJTI string `json:"-"`

	// --- Authorization snapshot ---

	Permissions          []string `json:"permissions,omitempty"`
	DelegatedPermissions []string `json:"delegated_permissions,omitempty"`
	PolicyGroups         []string `json:"policy_groups,omitempty"`

	// PermissionVersion is a monotonically increasing counter. /auth/verify
	// compares this against the current version in Dgraph; a mismatch triggers
	// a permission reload without requiring a full re-login.
	PermissionVersion uint64 `json:"permission_version"`

	// --- Lifecycle ---

	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RefreshExpiresAt time.Time  `json:"refresh_expires_at"`

	// Revoked is true when the session has been explicitly terminated
	// (logout, admin action, compromise detection).
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// --- Audit metadata ---

	UserAgent string `json:"user_agent,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

// IsExpired returns true if the access window has closed.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsRefreshExpired returns true if the refresh token has exceeded its
// absolute lifetime. After this point the user must re-authenticate.
func (s *Session) IsRefreshExpired() bool {
	return time.Now().After(s.RefreshExpiresAt)
}

// IsValid returns true if the session can be used for access token validation.
func (s *Session) IsValid() bool {
	return !s.Revoked && !s.IsExpired()
}

// SessionCreateInput carries everything needed to mint a new session.
type SessionCreateInput struct {
	Kind      PrincipalKind
	UserID    string
	ClientID  string
	ActorID   string
	ActorType ActorType

	AccessTokenHash  string
	RefreshTokenHash string
	RefreshJTI       string

	Permissions          []string
	DelegatedPermissions []string
	PolicyGroups         []string
	PermissionVersion    uint64

	ExpiresAt        time.Time
	RefreshExpiresAt time.Time

	UserAgent string
	IPAddress string
}

// SessionRefreshInput carries the data needed to rotate a refresh token.
// The old session is revoked and a new one is created atomically.
type SessionRefreshInput struct {
	OldSessionID string

	NewAccessTokenHash  string
	NewRefreshTokenHash string
	NewRefreshJTI       string

	Permissions          []string
	DelegatedPermissions []string
	PolicyGroups         []string
	PermissionVersion    uint64

	NewExpiresAt        time.Time
	NewRefreshExpiresAt time.Time

	UserAgent string
	IPAddress string
}
