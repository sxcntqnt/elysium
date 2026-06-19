package dgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/dgo/v230/protos/api"
	"sxcntqnt/auth-service/internal/domain"
)

// serviceAccountSchema declares the Dgraph predicates for ServiceAccount nodes.
//
// sa.actor_type added: domain.ServiceAccount has carried an ActorType field
// since service accounts were introduced, but this predicate, the wire type
// below, and toDomain() never included it — so GetByClientID silently
// returned a zero-value ActorType regardless of what CreateServiceAccount
// persisted. Indexed @index(exact) to match the convention used for
// sa.client_id and sa.id, since ActorType is a low-cardinality exact-match
// field (one of the 24 domain.ActorType values), not a free-text field.
const serviceAccountSchema = `
type ServiceAccount {
    sa.id
    sa.client_id
    sa.name
    sa.secret_hash
    sa.actor_type
    sa.permissions
    sa.active
    sa.created_at
    sa.updated_at
}

sa.id:          string   @index(exact)          @upsert .
sa.client_id:   string   @index(exact)          @upsert .
sa.name:        string   @index(term)                   .
sa.secret_hash: string                                  .
sa.actor_type:  string   @index(exact)                  .
sa.permissions: [string]                               .
sa.active:      bool     @index(bool)                  .
sa.created_at:  datetime @index(hour)                  .
sa.updated_at:  datetime                               .
`

// ApplyServiceAccountSchema extends the Dgraph schema to include
// ServiceAccount predicates. Call once at startup after ApplySchema.
//
// This is additive-only via Alter (no drop), so existing ServiceAccount
// nodes created before this fix simply have an absent sa.actor_type
// predicate — toDomain() will produce ActorType: "" for those until they
// are re-saved (e.g. via a future UpdateServiceAccount, if one is added)
// or backfilled directly in Dgraph. New accounts created after this fix
// are correct from creation.
func (r *Repository) ApplyServiceAccountSchema(ctx context.Context) error {
	if err := r.client.Alter(ctx, &api.Operation{Schema: serviceAccountSchema}); err != nil {
		return fmt.Errorf("dgraph: apply service account schema: %w", err)
	}
	return nil
}

// ServiceAccountRepo implements repository.ServiceAccountRepository.
// It wraps the same underlying Dgraph client as Repository, keeping
// the connection pool shared while giving each interface a clean method set.
// Construct via NewServiceAccountRepo — do not use the zero value.
type ServiceAccountRepo struct {
	r *Repository // borrows the client and helpers (newReadTxn, zookieFromTxn)
}

// NewServiceAccountRepo creates a ServiceAccountRepo sharing the same
// Dgraph connection as the provided Repository.
func NewServiceAccountRepo(r *Repository) *ServiceAccountRepo {
	return &ServiceAccountRepo{r: r}
}

// dgraphServiceAccount is the Dgraph wire type.
type dgraphServiceAccount struct {
	UID         string   `json:"uid,omitempty"`
	DType       []string `json:"dgraph.type,omitempty"`
	ID          string   `json:"sa.id,omitempty"`
	ClientID    string   `json:"sa.client_id,omitempty"`
	Name        string   `json:"sa.name,omitempty"`
	SecretHash  string   `json:"sa.secret_hash,omitempty"`
	ActorType   string   `json:"sa.actor_type,omitempty"`
	Permissions []string `json:"sa.permissions,omitempty"`
	Active      bool     `json:"sa.active"`
	CreatedAt   string   `json:"sa.created_at,omitempty"`
	UpdatedAt   string   `json:"sa.updated_at,omitempty"`
}

func (d *dgraphServiceAccount) toDomain() *domain.ServiceAccount {
	created, _ := time.Parse(time.RFC3339, d.CreatedAt)
	updated, _ := time.Parse(time.RFC3339, d.UpdatedAt)
	perms := d.Permissions
	if perms == nil {
		perms = []string{}
	}
	return &domain.ServiceAccount{
		ID:          d.ID,
		ClientID:    d.ClientID,
		Name:        d.Name,
		SecretHash:  d.SecretHash,
		ActorType:   domain.ActorType(d.ActorType),
		Permissions: perms,
		Active:      d.Active,
		CreatedAt:   created,
		UpdatedAt:   updated,
	}
}

// CreateServiceAccount persists a new ServiceAccount using an upsert condition
// so concurrent registrations with the same client_id produce only one record.
// Returns the Zookie of the completed write.
func (s *ServiceAccountRepo) CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) (domain.Zookie, error) {
	dsa := dgraphServiceAccount{
		UID:         "_:sa",
		DType:       []string{"ServiceAccount"},
		ID:          sa.ID,
		ClientID:    sa.ClientID,
		Name:        sa.Name,
		SecretHash:  sa.SecretHash,
		ActorType:   string(sa.ActorType),
		Permissions: sa.Permissions,
		Active:      sa.Active,
		CreatedAt:   sa.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   sa.UpdatedAt.UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(dsa)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: marshal service account: %w", err)
	}

	req := &api.Request{
		Query: `
			query {
				existing as var(func: eq(sa.client_id, $clientID))
			}`,
		Mutations: []*api.Mutation{{
			SetJson:   data,
			Cond:      `@if(eq(len(existing), 0))`,
			CommitNow: true,
		}},
		Vars:      map[string]string{"$clientID": sa.ClientID},
		CommitNow: true,
	}

	resp, err := s.r.client.NewTxn().Do(ctx, req)
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: create service account: %w", err)
	}
	if len(resp.Uids) == 0 {
		return domain.Zookie{}, domain.ErrUserAlreadyExists
	}
	return zookieFromTxn(resp.Txn), nil
}

// GetByClientID fetches a service account by its client_id.
// Pass a non-nil zookie to force a strong (non-BestEffort) read.
func (s *ServiceAccountRepo) GetByClientID(ctx context.Context, clientID string, zookie *domain.Zookie) (*domain.ServiceAccount, error) {
	resp, err := s.r.newReadTxn(zookie).QueryWithVars(ctx, `
		query q($clientID: string) {
			accounts(func: eq(sa.client_id, $clientID)) {
				uid
				sa.id
				sa.client_id
				sa.name
				sa.secret_hash
				sa.actor_type
				sa.permissions
				sa.active
				sa.created_at
				sa.updated_at
			}
		}`, map[string]string{"$clientID": clientID})
	if err != nil {
		return nil, fmt.Errorf("dgraph: get service account: %w", err)
	}

	var result struct {
		Accounts []dgraphServiceAccount `json:"accounts"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return nil, fmt.Errorf("dgraph: unmarshal service account: %w", err)
	}
	if len(result.Accounts) == 0 {
		return nil, domain.ErrUserNotFound
	}
	return result.Accounts[0].toDomain(), nil
}

// Deactivate sets sa.active=false for the given client_id.
// The record is retained for audit purposes — hard delete is intentionally absent.
// Returns the Zookie of the write.
func (s *ServiceAccountRepo) Deactivate(ctx context.Context, clientID string) (domain.Zookie, error) {
	// Resolve uid first — Dgraph deletes/patches by uid.
	resp, err := s.r.client.NewReadOnlyTxn().QueryWithVars(ctx, `
		query q($clientID: string) {
			accounts(func: eq(sa.client_id, $clientID)) { uid }
		}`, map[string]string{"$clientID": clientID})
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: deactivate lookup: %w", err)
	}

	var result struct {
		Accounts []struct {
			UID string `json:"uid"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(resp.Json, &result); err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: deactivate unmarshal: %w", err)
	}
	if len(result.Accounts) == 0 {
		return domain.Zookie{}, domain.ErrUserNotFound
	}

	patch, err := json.Marshal(map[string]interface{}{
		"uid":           result.Accounts[0].UID,
		"sa.active":     false,
		"sa.updated_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: deactivate marshal: %w", err)
	}

	mutResp, err := s.r.client.NewTxn().Mutate(ctx, &api.Mutation{
		SetJson:   patch,
		CommitNow: true,
	})
	if err != nil {
		return domain.Zookie{}, fmt.Errorf("dgraph: deactivate mutate: %w", err)
	}
	return zookieFromTxn(mutResp.Txn), nil
}
