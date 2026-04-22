package dgraph

import "sxcntqnt/auth-service/internal/repository"

// Compile-time assertions — the compiler rejects any method signature drift
// between the concrete Dgraph types and the repository interfaces they satisfy.
//
// These are the only lines in the dgraph package that import repository,
// keeping the dependency direction: dgraph → repository → domain.
var (
	_ repository.UserRepository           = (*Repository)(nil)
	_ repository.ServiceAccountRepository = (*ServiceAccountRepo)(nil)
)
