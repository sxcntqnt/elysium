package domain

import "time"

// ServiceAccount represents a machine identity — a backend service, a CLI
// tool, or any non-human caller that needs authenticated API access.
//
// Authentication flow:
//
//	POST /auth/service/token  {"client_id": "...", "client_secret": "..."}
//	→ same TokenPair as human login, JWT carries kind:"service" and actor_type.
//
// Service tokens flow through the same middleware and Signer as user tokens —
// the difference is the claims shape, the issuing endpoint, and the ActorType.
type ServiceAccount struct {
	ID           string
	ClientID     string    // unique; used as the login identifier
	Name         string    // human-readable label, e.g. "inventory-service"
	SecretHash   string    // bcrypt hash of the client secret; never serialised
	ActorType    ActorType // the role this service operates as (e.g. ADMIN, DISPATCHER)
	Permissions  []string
	Active       bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateServiceAccountInput carries validated input for service account creation.
type CreateServiceAccountInput struct {
	ClientID     string
	Name         string
	ClientSecret string    // plaintext — hashed before persistence
	ActorType    ActorType // must satisfy ActorType.IsValid()
	Permissions  []string
}

// Validate enforces the minimum constraints on service account creation.
func (i *CreateServiceAccountInput) Validate() error {
	if i.ClientID == "" || len(i.ClientID) > 64 {
		return ErrInvalidInput
	}
	if i.Name == "" {
		return ErrInvalidInput
	}
	if len(i.ClientSecret) < 32 {
		// Service secrets must be strong — 32+ chars enforced here.
		return ErrInvalidInput
	}
	if !i.ActorType.IsValid() {
		return ErrInvalidInput
	}
	return nil
}

// ServiceLoginInput carries credentials for service authentication.
type ServiceLoginInput struct {
	ClientID     string
	ClientSecret string
}

// Validate sanitises service login input.
func (i *ServiceLoginInput) Validate() error {
	if i.ClientID == "" {
		return ErrInvalidInput
	}
	if i.ClientSecret == "" {
		return ErrInvalidInput
	}
	return nil
}
