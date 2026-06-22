// Package dgraph implements repository.UserRepository using Dgraph as the
// backing store. All queries are parameterised — no string concatenation of
// user-supplied values into DQL.
//
// Zookie routing:
//
//	Read methods call newReadTxn(zookie). When zookie is nil the transaction
//	uses BestEffort(), which Dgraph may serve from a stale replica. When
//	zookie is non-nil the transaction does NOT call BestEffort(), so Dgraph
//	routes the read through the leader (or a fully caught-up replica),
//	guaranteeing the caller sees all commits up to and including the zookie's
//	CommitTs. Write methods capture CommitTs from the Dgraph response and
//	encode it as a Zookie for the caller.
package dgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	dgo "github.com/dgraph-io/dgo/v230"
	"github.com/dgraph-io/dgo/v230/protos/api"
	"sxcntqnt/auth-service/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Repository is the Dgraph implementation of repository.UserRepository.
// Construct via New; the zero value is not usable.
type Repository struct {
	client *dgo.Dgraph
}

// New opens a gRPC connection to Dgraph and returns a ready Repository.
// Call Close on the returned *grpc.ClientConn during graceful shutdown.
func New(target string) (*Repository, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dgraph: dialing %s: %w", target, err)
	}
	return &Repository{client: dgo.NewDgraphClient(api.NewDgraphClient(conn))}, conn, nil
}

// ApplySchema installs the schema without dropping data — idempotent, safe
// to call on every process restart.
func (r *Repository) ApplySchema(ctx context.Context) error {
	if err := r.client.Alter(ctx, &api.Operation{Schema: userSchema}); err != nil {
		return fmt.Errorf("dgraph: apply schema: %w", err)
	}
	return nil
}

// userSchema declares Dgraph predicates and indexes for the User type.
const userSchema = `
type User {
    user.id
    user.first_name
    user.last_name
    user.nickname
    user.password_hash
    user.email
    user.country
    user.active
    user.created_at
    user.updated_at
}

user.id:            string   @index(exact)          @upsert .
user.email:         string   @index(exact)          @upsert .
user.nickname:      string   @index(exact)          @upsert .
user.first_name:    string   @index(trigram, term)           .
user.last_name:     string   @index(trigram, term)           .
user.country:       string   @index(exact, term)             .
user.password_hash: string                                   .
user.active:        bool     @index(bool)                    .
user.created_at:    datetime @index(hour)                    .
user.updated_at:    datetime                                 .
`

// ─── Wire type ────────────────────────────────────────────────────────────────

type dgraphUser struct {
	UID          string   `json:"uid,omitempty"`
	DType        []string `json:"dgraph.type,omitempty"`
	ID           string   `json:"user.id,omitempty"`
	FirstName    string   `json:"user.first_name,omitempty"`
	LastName     string   `json:"user.last_name,omitempty"`
	Nickname     string   `json:"user.nickname,omitempty"`
	PasswordHash string   `json:"user.password_hash,omitempty"`
	Email        string   `json:"user.email,omitempty"`
	Country      string   `json:"user.country,omitempty"`
	Active       bool     `json:"user.active"`
	CreatedAt    string   `json:"user.created_at,omitempty"`
	UpdatedAt    string   `json:"user.updated_at,omitempty"`
}

func (d *dgraphUser) toDomain() *domain.User {
	created, _ := time.Parse(time.RFC3339, d.CreatedAt)
	updated, _ := time.Parse(time.RFC3339, d.UpdatedAt)
	return &domain.User{
		ID:           d.ID,
		FirstName:    d.FirstName,
		LastName:     d.LastName,
		Nickname:     d.Nickname,
		PasswordHash: d.PasswordHash,
		Email:        d.Email,
		Country:      d.Country,
		Active:       d.Active,
		CreatedAt:    created,
		UpdatedAt:    updated,
	}
}

// ─── Zookie routing ───────────────────────────────────────────────────────────

// newReadTxn selects the correct read transaction mode based on the zookie.
//
//	nil zookie   → BestEffort (may serve from a stale replica; fastest)
//	non-nil      → strong read (no BestEffort; Dgraph routes to a consistent node)
func (r *Repository) newReadTxn(zookie *domain.Zookie) *dgo.Txn {
	txn := r.client.NewReadOnlyTxn()
	if zookie == nil {
		return txn.BestEffort()
	}
	// A non-nil zookie (even with an empty token) forces a strong read.
	// Dgraph linearizable reads guarantee the caller sees all commits up to
	// and including the zookie's CommitTs.
	return txn
}

// zookieFromTxn extracts the CommitTs from a Dgraph response and encodes it
// as a Zookie. Returns a zero Zookie if the response carries no context.
func zookieFromTxn(txnCtx *api.TxnContext) domain.Zookie {
	if txnCtx == nil || txnCtx.CommitTs == 0 {
		return domain.Zookie{}
	}
	return domain.NewZookie(txnCtx.CommitTs)
}

// ─── Write methods ────────────────────────────────────────────────────────────

// Create persists a new user using an upsert mutation to prevent duplicates
// even under concurrent registration. Returns the Zookie of the write.
func (r *Repository) Create(ctx context.Context, u *domain.User) (domain.Zookie, error) {
	du := dgraphUser{
		UID:          "_:user",
		DType:        []string{"User"},
		ID:           u.ID,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		Nickname:     u.Nickname,
		PasswordHash: u.PasswordHash,
		Email:        u.Email,
		Country:      u.Country,
		Active:       u.Active,
		CreatedAt:    u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:    u.UpdatedAt.UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(du)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: marshal user: %w", err)
	}

	// Only create if neither email nor nickname already exists.
	req := &api.Request{
		Query: `
			query q($email: string, $nickname: string) {
				email as var(func: eq(user.email, $email))
				nickname as var(func: eq(user.nickname, $nickname))
			}`,
		Mutations: []*api.Mutation{
			{
				SetJson: data,
				Cond:    `@if(eq(len(email), 0) AND eq(len(nickname), 0))`,
			},
		},
		Vars: map[string]string{
			"$email":    strings.ToLower(u.Email),
			"$nickname": u.Nickname,
		},
		CommitNow: true,
	}

	resp, err := r.client.NewTxn().Do(ctx, req)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: create user: %w", err)
	}

	// Condition failed => duplicate email or nickname.
	if len(resp.Uids) == 0 {
		return domain.Zookie{}, domain.ErrUserAlreadyExists
	}

	return zookieFromTxn(resp.Txn), nil
}
// Update applies a partial update inside a read-modify-write transaction.
// Uses CommitNow on the mutation to capture CommitTs for the returned Zookie.
func (r *Repository) Update(ctx context.Context, id string, input *domain.UpdateUserInput) (*domain.User, domain.Zookie, error) {
	txn := r.client.NewTxn()
	defer txn.Discard(ctx) //nolint:errcheck

	// 1. Read current state (strong read — we are about to write).
	resp, err := txn.QueryWithVars(ctx, `
		query q($id: string) {
			users(func: eq(user.id, $id)) {
				uid
				user.id
				user.first_name
				user.last_name
				user.nickname
				user.email
				user.country
				user.active
				user.created_at
				user.updated_at
			}
		}`, map[string]string{"id": id})
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("dgraph: update read: %w", err)
	}

	var result struct {
		Users []dgraphUser `json:"users"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("dgraph: update unmarshal: %w", err)
	}
	if len(result.Users) == 0 {
		return nil, domain.Zookie{}, domain.ErrUserNotFound
	}

	du := result.Users[0]

	// 2. Apply only the fields the caller provided.
	if input.FirstName != nil {
		du.FirstName = *input.FirstName
	}
	if input.LastName != nil {
		du.LastName = *input.LastName
	}
	if input.Nickname != nil {
		du.Nickname = *input.Nickname
	}
	if input.Country != nil {
		du.Country = *input.Country
	}
	du.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.Marshal(du)
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("dgraph: update marshal: %w", err)
	}

	// 3. Commit inline with CommitNow so we get the CommitTs in the response.
	mutResp, err := txn.Mutate(ctx, &api.Mutation{SetJson: data, CommitNow: true})
	if err != nil {
		return nil, domain.Zookie{}, fmt.Errorf("dgraph: update mutate: %w", err)
	}
	// CommitNow: true means the txn is already committed — do not call Commit.
	return du.toDomain(), zookieFromTxn(mutResp.Txn), nil
}

// Delete removes the user node and all its predicates.
// Returns the Zookie of the completed write.
func (r *Repository) Delete(ctx context.Context, id string) (domain.Zookie, error) {
	// Resolve the Dgraph uid for the delete mutation.
	resp, err := r.client.NewReadOnlyTxn().QueryWithVars(ctx, `
		query q($id: string) {
			users(func: eq(user.id, $id)) { uid }
		}`, map[string]string{"id": id})
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: delete lookup: %w", err)
	}

	var result struct {
		Users []struct {
			UID string `json:"uid"`
		} `json:"users"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: delete unmarshal: %w", err)
	}
	if len(result.Users) == 0 {
		return domain.Zookie{}, domain.ErrUserNotFound
	}

	mutResp, err := r.client.NewTxn().Mutate(ctx, &api.Mutation{
		DeleteJson: []byte(fmt.Sprintf(`{"uid": %q}`, result.Users[0].UID)),
		CommitNow:  true,
	})
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: delete mutate: %w", err)
	}
	return zookieFromTxn(mutResp.Txn), nil
}

// ─── Read methods ─────────────────────────────────────────────────────────────

// GetByID fetches a user by the application-level UUID.
// Pass a non-nil zookie to ensure the read is not served from a stale replica.
func (r *Repository) GetByID(ctx context.Context, id string, zookie *domain.Zookie) (*domain.User, error) {
	return r.queryOne(ctx, `
		query q($id: string) {
			users(func: eq(user.id, $id)) {
				uid
				user.id
				user.first_name
				user.last_name
				user.nickname
				user.password_hash
				user.email
				user.country
				user.active
				user.created_at
				user.updated_at
			}
		}`, map[string]string{"id": id}, zookie)
}

// GetByEmail fetches a user by email address.
// Pass a non-nil zookie to ensure a consistent read.
func (r *Repository) GetByEmail(ctx context.Context, email string, zookie *domain.Zookie) (*domain.User, error) {
	return r.queryOne(ctx, `
		query q($email: string) {
			users(func: eq(user.email, $email)) {
				uid
				user.id
				user.first_name
				user.last_name
				user.nickname
				user.password_hash
				user.email
				user.country
				user.active
				user.created_at
				user.updated_at
			}
		}`, map[string]string{"email": strings.ToLower(email)}, zookie)
}

// queryOne is the shared single-user lookup implementation.
func (r *Repository) queryOne(ctx context.Context, q string, vars map[string]string, zookie *domain.Zookie) (*domain.User, error) {
	resp, err := r.newReadTxn(zookie).QueryWithVars(ctx, q, vars)
	if err != nil {
		return nil, fmt.Errorf("dgraph: query: %w", err)
	}

	var result struct {
		Users []dgraphUser `json:"users"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: unmarshal: %w", err)
	}
	if len(result.Users) == 0 {
		return nil, domain.ErrUserNotFound
	}
	return result.Users[0].toDomain(), nil
}

// List returns paginated users, optionally filtered by country.
// Pass a non-nil zookie to force a consistent read.
func (r *Repository) List(ctx context.Context, filter domain.ListFilter, zookie *domain.Zookie) (*domain.ListResult, error) {
	filter.Normalise()
	offset := (filter.Page - 1) * filter.PageSize

	vars := map[string]string{
		"offset":   fmt.Sprintf("%d", offset),
		"pageSize": fmt.Sprintf("%d", filter.PageSize),
	}

	var q string
	if filter.Country != "" {
		q = `
		query q($country: string, $offset: int, $pageSize: int) {
			users(func: eq(user.country, $country), offset: $offset, first: $pageSize) @filter(eq(user.active, true)) {
				uid
				user.id user.first_name user.last_name user.nickname
				user.email user.country user.active user.created_at user.updated_at
			}
			total(func: eq(user.country, $country)) @filter(eq(user.active, true)) {
				count(uid)
			}
		}`
		vars["country"] = filter.Country
	} else {
		q = `
		query q($offset: int, $pageSize: int) {
			users(func: type(User), offset: $offset, first: $pageSize) @filter(eq(user.active, true)) {
				uid
				user.id user.first_name user.last_name user.nickname
				user.email user.country user.active user.created_at user.updated_at
			}
			total(func: type(User)) @filter(eq(user.active, true)) {
				count(uid)
			}
		}`
	}

	resp, err := r.newReadTxn(zookie).QueryWithVars(ctx, q, vars)
	if err != nil {
		return nil, fmt.Errorf("dgraph: list: %w", err)
	}

	var result struct {
		Users []dgraphUser `json:"users"`
		Total []struct {
			Count int `json:"count"`
		} `json:"total"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: list unmarshal: %w", err)
	}

	users := make([]*domain.User, len(result.Users))
	for i, du := range result.Users {
		users[i] = du.toDomain()
	}

	total := 0
	if len(result.Total) > 0 {
		total = result.Total[0].Count
	}
	pages := int(math.Ceil(float64(total) / float64(filter.PageSize)))
	if pages < 1 {
		pages = 1
	}

	return &domain.ListResult{
		Users: users,
		Total: total,
		Page:  filter.Page,
		Pages: pages,
	}, nil
}

// Ping verifies the Dgraph connection — used by the readiness endpoint.
func (r *Repository) Ping(ctx context.Context) error {
	if _, err := r.client.NewReadOnlyTxn().QueryWithVars(ctx, `{ q(func: uid(0x1)) { uid } }`, nil); err != nil {
		return fmt.Errorf("dgraph: ping: %w", err)
	}
	return nil
}
