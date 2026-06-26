package dgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/dgraph-io/dgo/v230/protos/api"
	"sxcntqnt/auth-service/internal/domain"
)

// sessionSchema declares Dgraph predicates and indexes for the Session type.
// Applied via ApplySessionSchema — same Alter-based mechanism as userSchema
// and serviceAccountSchema; no separate .dql file is used.
const sessionSchema = `
type Session {
    session.kind
    session.user_id
    session.client_id
    session.actor_id
    session.actor_type
    session.access_token_hash
    session.refresh_token_hash
    session.refresh_jti
    session.replaced_by_jti
    session.permissions
    session.delegated_permissions
    session.policy_groups
    session.permission_version
    session.created_at
    session.updated_at
    session.last_seen_at
    session.expires_at
    session.refresh_expires_at
    session.revoked
    session.revoked_at
    session.user_agent
    session.ip_address
}

session.kind:                string   @index(exact)          .
session.user_id:             string   @index(exact)          .
session.client_id:           string   @index(exact)          .
session.actor_id:            string   @index(exact)          .
session.actor_type:          string   @index(exact)          .
session.access_token_hash:   string   @index(exact) @upsert  .
session.refresh_token_hash:  string   @index(exact) @upsert  .
session.refresh_jti:         string   @index(exact)          .
session.replaced_by_jti:     string                          .
session.permissions:         [string]                        .
session.delegated_permissions: [string]                      .
session.policy_groups:       [string]                        .
session.permission_version:  int                             .
session.created_at:          datetime @index(hour)           .
session.updated_at:          datetime                        .
session.last_seen_at:        datetime @index(hour)           .
session.expires_at:          datetime @index(hour)           .
session.refresh_expires_at:  datetime @index(hour)           .
session.revoked:             bool     @index(bool)           .
session.revoked_at:          datetime                        .
session.user_agent:          string                          .
session.ip_address:          string   @index(exact)          .
`

// ApplySessionSchema installs the Session schema. Idempotent — safe to call
// on every process restart, matching ApplySchema and ApplyServiceAccountSchema.
func (r *Repository) ApplySessionSchema(ctx context.Context) error {
	if err := r.client.Alter(ctx, &api.Operation{Schema: sessionSchema}); err != nil {
		return fmt.Errorf("dgraph: apply session schema: %w", err)
	}
	return nil
}

// SessionRepo implements repository.SessionRepository.
// It wraps the same underlying Dgraph client as Repository, keeping
// the connection pool shared while avoiding method-name collisions with
// Repository's existing Create/GetByID/queryOne methods (which operate on
// *domain.User). This mirrors the exact pattern used by ServiceAccountRepo.
// Construct via NewSessionRepo — do not use the zero value.
type SessionRepo struct {
	r *Repository
}

// NewSessionRepo creates a SessionRepo sharing the same Dgraph connection
// as the provided Repository.
func NewSessionRepo(r *Repository) *SessionRepo {
	return &SessionRepo{r: r}
}

// sessionNode is the wire format for Dgraph reads.
type sessionNode struct {
	UID              string   `json:"uid"`
	Kind             string   `json:"session.kind"`
	UserID           string   `json:"session.user_id"`
	ClientID         string   `json:"session.client_id"`
	ActorID          string   `json:"session.actor_id"`
	ActorType        string   `json:"session.actor_type"`
	AccessTokenHash  string   `json:"session.access_token_hash"`
	RefreshTokenHash string   `json:"session.refresh_token_hash"`
	RefreshJTI       string   `json:"session.refresh_jti"`
	ReplacedByJTI    string   `json:"session.replaced_by_jti"`
	Permissions      []string `json:"session.permissions"`
	DelegPerms       []string `json:"session.delegated_permissions"`
	PolicyGroups     []string `json:"session.policy_groups"`
	PermVersion      uint64   `json:"session.permission_version"`
	CreatedAt        string   `json:"session.created_at,omitempty"`
	UpdatedAt        string   `json:"session.updated_at,omitempty"`
	LastSeenAt       string   `json:"session.last_seen_at,omitempty"`
	ExpiresAt        string   `json:"session.expires_at,omitempty"`
	RefreshExpiresAt string   `json:"session.refresh_expires_at,omitempty"`
	Revoked          bool     `json:"session.revoked"`
	RevokedAt        string   `json:"session.revoked_at,omitempty"`
	UserAgent        string   `json:"session.user_agent"`
	IPAddress        string   `json:"session.ip_address"`
}

// nodeToSession converts the Dgraph wire type to a domain.Session, parsing
// RFC3339 timestamp strings explicitly — the same convention used by
// dgraphUser.toDomain() and dgraphServiceAccount.toDomain() in this package.
func nodeToSession(n sessionNode) *domain.Session {
	createdAt, _ := time.Parse(time.RFC3339, n.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, n.UpdatedAt)
	lastSeenAt, _ := time.Parse(time.RFC3339, n.LastSeenAt)
	expiresAt, _ := time.Parse(time.RFC3339, n.ExpiresAt)
	refreshExpiresAt, _ := time.Parse(time.RFC3339, n.RefreshExpiresAt)

	var revokedAt *time.Time
	if n.RevokedAt != "" {
		if t, err := time.Parse(time.RFC3339, n.RevokedAt); err == nil {
			revokedAt = &t
		}
	}

	return &domain.Session{
		ID:                   n.UID,
		Kind:                 domain.PrincipalKind(n.Kind),
		UserID:               n.UserID,
		ClientID:             n.ClientID,
		ActorID:              n.ActorID,
		ActorType:            domain.ActorType(n.ActorType),
		AccessTokenHash:      n.AccessTokenHash,
		RefreshTokenHash:     n.RefreshTokenHash,
		RefreshJTI:           n.RefreshJTI,
		ReplacedByJTI:        n.ReplacedByJTI,
		Permissions:          n.Permissions,
		DelegatedPermissions: n.DelegPerms,
		PolicyGroups:         n.PolicyGroups,
		PermissionVersion:    n.PermVersion,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		LastSeenAt:           lastSeenAt,
		ExpiresAt:            expiresAt,
		RefreshExpiresAt:     refreshExpiresAt,
		Revoked:              n.Revoked,
		RevokedAt:            revokedAt,
		UserAgent:            n.UserAgent,
		IPAddress:            n.IPAddress,
	}
}

const sessionFields = `
	uid
	session.kind
	session.user_id
	session.client_id
	session.actor_id
	session.actor_type
	session.access_token_hash
	session.refresh_token_hash
	session.refresh_jti
	session.replaced_by_jti
	session.permissions
	session.delegated_permissions
	session.policy_groups
	session.permission_version
	session.created_at
	session.updated_at
	session.last_seen_at
	session.expires_at
	session.refresh_expires_at
	session.revoked
	session.revoked_at
	session.user_agent
	session.ip_address`

// Create persists a new session node.
func (s *SessionRepo) Create(ctx context.Context, in domain.SessionCreateInput) (*domain.Session, error) {
	now := time.Now().UTC()

	nquads := fmt.Sprintf(`
		_:session <dgraph.type> "Session" .
		_:session <session.kind> %q .
		_:session <session.user_id> %q .
		_:session <session.client_id> %q .
		_:session <session.actor_id> %q .
		_:session <session.actor_type> %q .
		_:session <session.access_token_hash> %q .
		_:session <session.refresh_token_hash> %q .
		_:session <session.refresh_jti> %q .
		_:session <session.permission_version> "%d"^^<xs:int> .
		_:session <session.expires_at> %q .
		_:session <session.refresh_expires_at> %q .
		_:session <session.revoked> "false"^^<xs:boolean> .
		_:session <session.created_at> %q .
		_:session <session.updated_at> %q .
		_:session <session.last_seen_at> %q .
		_:session <session.user_agent> %q .
		_:session <session.ip_address> %q .
	`,
		string(in.Kind), in.UserID, in.ClientID, in.ActorID, string(in.ActorType),
		in.AccessTokenHash, in.RefreshTokenHash, in.RefreshJTI,
		in.PermissionVersion,
		in.ExpiresAt.UTC().Format(time.RFC3339),
		in.RefreshExpiresAt.UTC().Format(time.RFC3339),
		now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339),
		in.UserAgent, in.IPAddress,
	)
	for _, p := range in.Permissions {
		nquads += fmt.Sprintf("_:session <session.permissions> %q .\n", p)
	}
	for _, p := range in.DelegatedPermissions {
		nquads += fmt.Sprintf("_:session <session.delegated_permissions> %q .\n", p)
	}
	for _, g := range in.PolicyGroups {
		nquads += fmt.Sprintf("_:session <session.policy_groups> %q .\n", g)
	}

	mu := &api.Mutation{SetNquads: []byte(nquads), CommitNow: true}
	resp, err := s.r.client.NewTxn().Mutate(ctx, mu)
	if err != nil {
		return nil, fmt.Errorf("dgraph: create session: %w", err)
	}
	uid := resp.Uids["session"]
	if uid == "" {
		return nil, fmt.Errorf("dgraph: create session: no uid returned")
	}
	return s.GetByID(ctx, uid)
}

// GetByAccessHash retrieves a session by its access token hash.
func (s *SessionRepo) GetByAccessHash(ctx context.Context, hash string) (*domain.Session, error) {
	return s.queryOne(ctx, "session.access_token_hash", hash)
}

// GetByRefreshHash retrieves a session by its refresh token hash.
func (s *SessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	return s.queryOne(ctx, "session.refresh_token_hash", hash)
}

// validDgraphUID matches Dgraph's own hex uid format: "0x" followed by one
// or more hex digits. GetByID's id parameter is NOT always internally
// generated — it is also reachable from the HTTP layer via
// DELETE /auth/sessions/{id} (RevokeSession), where it comes straight off
// the URL path with no upstream validation. Since GetByID builds its query
// via literal string interpolation (see the uid-vs-string-variable
// rationale on GetByID itself), every call site must be guarded against a
// malformed or malicious id breaking out of the intended query — this is
// the one and only place that guard needs to live.
var validDgraphUID = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)

// GetByID retrieves a session by its Dgraph UID.
//
// Uses literal uid interpolation rather than a $-parameterized query
// variable: Dgraph's func: uid(...) root function expects either a literal
// uid or a uid-typed query variable bound via "X AS var(...)" earlier in
// the same query — it does not accept an externally-supplied string
// parameter the way eq(predicate, $var) does. Declaring $uid: string and
// writing func: uid($uid) produces "Type of variable uid not specified" at
// query time (confirmed against Dgraph's own DQL error set). This mirrors
// how repository.go's Delete already builds fmt.Sprintf(`{"uid": %q}`, ...)
// rather than parameterizing a uid.
//
// Because id can originate from user-supplied HTTP path input (see
// validDgraphUID doc comment), it is validated against Dgraph's hex uid
// format before being interpolated — rejecting anything else outright
// rather than ever passing it through to query construction.
func (s *SessionRepo) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	if !validDgraphUID.MatchString(id) {
		return nil, fmt.Errorf("dgraph: get session by id: invalid uid format %q", id)
	}

	q := fmt.Sprintf(`
		{
			session(func: uid(%s)) @filter(type(Session)) {%s
			}
		}`, id, sessionFields)

	resp, err := s.r.client.NewReadOnlyTxn().Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dgraph: get session by id: %w", err)
	}
	var result struct {
		Session []sessionNode `json:"session"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: unmarshal session: %w", err)
	}
	if len(result.Session) == 0 {
		return nil, nil
	}
	return nodeToSession(result.Session[0]), nil
}

// ListForUser returns all non-revoked sessions for a user, newest first.
func (s *SessionRepo) ListForUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	q := fmt.Sprintf(`
		query Sessions($uid: string) {
			sessions(func: eq(session.user_id, $uid), orderasc: session.last_seen_at)
				@filter(NOT eq(session.revoked, true)) {%s
			}
		}`, sessionFields)

	resp, err := s.r.client.NewReadOnlyTxn().QueryWithVars(ctx, q, map[string]string{"$uid": userID})
	if err != nil {
		return nil, fmt.Errorf("dgraph: list sessions for user: %w", err)
	}
	var result struct {
		Sessions []sessionNode `json:"sessions"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: unmarshal session list: %w", err)
	}
	sessions := make([]*domain.Session, len(result.Sessions))
	for i, n := range result.Sessions {
		sessions[i] = nodeToSession(n)
	}
	return sessions, nil
}

// RotateTokens atomically revokes the old session and creates a new one in a
// single Dgraph transaction. If the old session is already revoked when we
// read it inside the transaction, we return ErrRefreshTokenReplayed so the
// caller can trigger full-family revocation.
func (s *SessionRepo) RotateTokens(ctx context.Context, in domain.SessionRefreshInput) (*domain.Session, error) {
	if !validDgraphUID.MatchString(in.OldSessionID) {
		return nil, fmt.Errorf("dgraph: rotate tokens: invalid uid format %q", in.OldSessionID)
	}

	txn := s.r.client.NewTxn()
	defer txn.Discard(ctx) //nolint:errcheck

	// Literal interpolation, not a $-parameterized query variable — same
	// rationale as GetByID above: func: uid(...) does not accept a
	// string-typed external parameter.
	q := fmt.Sprintf(`
		{
			old(func: uid(%s)) @filter(type(Session)) {
				uid
				session.revoked
				session.kind
				session.user_id
				session.client_id
				session.actor_id
				session.actor_type
				session.permissions
				session.delegated_permissions
				session.policy_groups
				session.permission_version
				session.user_agent
				session.ip_address
			}
		}`, in.OldSessionID)
	qresp, err := txn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dgraph: rotate tokens read: %w", err)
	}
	var qresult struct {
		Old []sessionNode `json:"old"`
	}
	if err := json.Unmarshal(qresp.Json, &qresult); err != nil {
		return nil, fmt.Errorf("dgraph: rotate tokens unmarshal: %w", err)
	}
	if len(qresult.Old) == 0 {
		return nil, fmt.Errorf("dgraph: session %s not found during rotation", in.OldSessionID)
	}
	old := qresult.Old[0]
	if old.Revoked {
		return nil, ErrRefreshTokenReplayed
	}

	now := time.Now().UTC()

	perms := in.Permissions
	delegPerms := in.DelegatedPermissions
	pgroups := in.PolicyGroups
	permVersion := in.PermissionVersion
	if len(perms) == 0 {
		perms = old.Permissions
		delegPerms = old.DelegPerms
		pgroups = old.PolicyGroups
		permVersion = old.PermVersion
	}

	revokeNquads := fmt.Sprintf(`
		<%s> <session.revoked> "true"^^<xs:boolean> .
		<%s> <session.revoked_at> %q .
		<%s> <session.replaced_by_jti> %q .
		<%s> <session.updated_at> %q .
	`, old.UID, old.UID, now.Format(time.RFC3339),
		old.UID, in.NewRefreshJTI,
		old.UID, now.Format(time.RFC3339))

	createNquads := fmt.Sprintf(`
		_:new <dgraph.type> "Session" .
		_:new <session.kind> %q .
		_:new <session.user_id> %q .
		_:new <session.client_id> %q .
		_:new <session.actor_id> %q .
		_:new <session.actor_type> %q .
		_:new <session.access_token_hash> %q .
		_:new <session.refresh_token_hash> %q .
		_:new <session.refresh_jti> %q .
		_:new <session.permission_version> "%d"^^<xs:int> .
		_:new <session.expires_at> %q .
		_:new <session.refresh_expires_at> %q .
		_:new <session.revoked> "false"^^<xs:boolean> .
		_:new <session.created_at> %q .
		_:new <session.updated_at> %q .
		_:new <session.last_seen_at> %q .
		_:new <session.user_agent> %q .
		_:new <session.ip_address> %q .
	`,
		old.Kind, old.UserID, old.ClientID, old.ActorID, old.ActorType,
		in.NewAccessTokenHash, in.NewRefreshTokenHash, in.NewRefreshJTI,
		permVersion,
		in.NewExpiresAt.UTC().Format(time.RFC3339),
		in.NewRefreshExpiresAt.UTC().Format(time.RFC3339),
		now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339),
		in.UserAgent, in.IPAddress,
	)
	for _, p := range perms {
		createNquads += fmt.Sprintf("_:new <session.permissions> %q .\n", p)
	}
	for _, p := range delegPerms {
		createNquads += fmt.Sprintf("_:new <session.delegated_permissions> %q .\n", p)
	}
	for _, g := range pgroups {
		createNquads += fmt.Sprintf("_:new <session.policy_groups> %q .\n", g)
	}

	mresp, err := txn.Mutate(ctx, &api.Mutation{
		SetNquads: []byte(revokeNquads + "\n" + createNquads),
	})
	if err != nil {
		return nil, fmt.Errorf("dgraph: rotate tokens mutate: %w", err)
	}
	if err := txn.Commit(ctx); err != nil {
		return nil, fmt.Errorf("dgraph: rotate tokens commit: %w", err)
	}
	uid := mresp.Uids["new"]
	if uid == "" {
		return nil, fmt.Errorf("dgraph: rotate tokens: no uid returned for new session")
	}
	return s.GetByID(ctx, uid)
}

// Revoke marks a single session as revoked. Idempotent.
func (s *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	now := time.Now().UTC()
	nquads := fmt.Sprintf(`
		<%s> <session.revoked> "true"^^<xs:boolean> .
		<%s> <session.revoked_at> %q .
		<%s> <session.updated_at> %q .
	`, sessionID, sessionID, now.Format(time.RFC3339), sessionID, now.Format(time.RFC3339))

	mu := &api.Mutation{SetNquads: []byte(nquads), CommitNow: true}
	if _, err := s.r.client.NewTxn().Mutate(ctx, mu); err != nil {
		return fmt.Errorf("dgraph: revoke session %s: %w", sessionID, err)
	}
	return nil
}

// RevokeAllForUser marks every session for a user as revoked.
func (s *SessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	q := `
		query Sessions($uid: string) {
			sessions(func: eq(session.user_id, $uid))
				@filter(NOT eq(session.revoked, true)) {
				uid
			}
		}`
	resp, err := s.r.client.NewReadOnlyTxn().QueryWithVars(ctx, q, map[string]string{"$uid": userID})
	if err != nil {
		return fmt.Errorf("dgraph: list sessions for bulk revoke: %w", err)
	}
	var result struct {
		Sessions []struct{ UID string `json:"uid"` } `json:"sessions"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return fmt.Errorf("dgraph: unmarshal sessions for bulk revoke: %w", err)
	}
	if len(result.Sessions) == 0 {
		return nil
	}

	now := time.Now().UTC()
	var nquads string
	for _, ss := range result.Sessions {
		nquads += fmt.Sprintf(`
			<%s> <session.revoked> "true"^^<xs:boolean> .
			<%s> <session.revoked_at> %q .
			<%s> <session.updated_at> %q .
		`, ss.UID, ss.UID, now.Format(time.RFC3339), ss.UID, now.Format(time.RFC3339))
	}
	mu := &api.Mutation{SetNquads: []byte(nquads), CommitNow: true}
	if _, err := s.r.client.NewTxn().Mutate(ctx, mu); err != nil {
		return fmt.Errorf("dgraph: bulk revoke sessions for user %s: %w", userID, err)
	}
	return nil
}

// Touch updates LastSeenAt on an active session.
func (s *SessionRepo) Touch(ctx context.Context, sessionID string) error {
	nquads := fmt.Sprintf("<%s> <session.last_seen_at> %q .\n",
		sessionID, time.Now().UTC().Format(time.RFC3339))
	mu := &api.Mutation{SetNquads: []byte(nquads), CommitNow: true}
	if _, err := s.r.client.NewTxn().Mutate(ctx, mu); err != nil {
		return fmt.Errorf("dgraph: touch session %s: %w", sessionID, err)
	}
	return nil
}

// DeleteExpired removes sessions whose RefreshExpiresAt is in the past.
func (s *SessionRepo) DeleteExpired(ctx context.Context) (int64, error) {
	threshold := time.Now().UTC().Format(time.RFC3339)
	q := fmt.Sprintf(`{
		expired(func: type(Session)) @filter(le(session.refresh_expires_at, %q)) {
			uid
		}
	}`, threshold)

	resp, err := s.r.client.NewReadOnlyTxn().Query(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("dgraph: query expired sessions: %w", err)
	}
	var result struct {
		Expired []struct{ UID string `json:"uid"` } `json:"expired"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return 0, fmt.Errorf("dgraph: unmarshal expired sessions: %w", err)
	}
	if len(result.Expired) == 0 {
		return 0, nil
	}

	type deleteRef struct {
		UID string `json:"uid"`
	}
	refs := make([]deleteRef, len(result.Expired))
	for i, e := range result.Expired {
		refs[i] = deleteRef{UID: e.UID}
	}
	delJSON, err := json.Marshal(refs)
	if err != nil {
		return 0, fmt.Errorf("dgraph: marshal expired session uids: %w", err)
	}
	mu := &api.Mutation{DeleteJson: delJSON, CommitNow: true}
	if _, err := s.r.client.NewTxn().Mutate(ctx, mu); err != nil {
		return 0, fmt.Errorf("dgraph: delete expired sessions: %w", err)
	}
	return int64(len(result.Expired)), nil
}

// queryOne is the shared implementation for hash-based lookups.
func (s *SessionRepo) queryOne(ctx context.Context, predicate, value string) (*domain.Session, error) {
	q := fmt.Sprintf(`
		query Session($val: string) {
			session(func: eq(%s, $val)) @filter(type(Session)) {%s
			}
		}`, predicate, sessionFields)

	resp, err := s.r.client.NewReadOnlyTxn().QueryWithVars(ctx, q, map[string]string{"$val": value})
	if err != nil {
		return nil, fmt.Errorf("dgraph: query session by %s: %w", predicate, err)
	}
	var result struct {
		Session []sessionNode `json:"session"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: unmarshal session: %w", err)
	}
	if len(result.Session) == 0 {
		return nil, nil
	}
	return nodeToSession(result.Session[0]), nil
}

// ErrRefreshTokenReplayed is returned by RotateTokens when the old session
// is already revoked — a potential compromise signal.
var ErrRefreshTokenReplayed = fmt.Errorf("refresh token has already been rotated or revoked")
