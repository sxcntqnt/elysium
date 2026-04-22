package domain

import (
	"encoding/base64"
	"encoding/binary"
)

// Zookie is an opaque consistency token modelled after the Zanzibar zookie
// pattern described in Google's Zanzibar paper.
//
// Problem it solves:
//
//	Dgraph read-only transactions with BestEffort may return data from a
//	slightly stale replica. After a write (register, update, delete) a client
//	that immediately reads back the same record risks seeing pre-write state.
//
// How it works:
//
//	Every write returns a Zookie encoding the Dgraph CommitTs of that
//	transaction. Clients that need read-your-writes consistency attach the
//	Zookie to subsequent read requests (X-Zookie header / grpc metadata).
//	The repository routes Zookie-carrying reads through a regular (non-
//	BestEffort) transaction which Dgraph guarantees to be linearizable with
//	all commits up to and including that timestamp.
//
// Staleness contract:
//
//	nil *Zookie  → BestEffort read  (fast, potentially stale)
//	non-nil      → Strong read      (linearizable, includes caller's last write)
//
// The zero value (Token == "") is a valid non-nil Zookie that requests a
// strong read without pinning to a specific commit — used internally by
// security-sensitive paths like Login.
type Zookie struct {
	Token string `json:"zookie,omitempty"`
}

// NewZookie encodes a Dgraph CommitTs as an opaque, URL-safe token.
// The encoding is an 8-byte little-endian representation of the uint64,
// base64url-encoded without padding so it is safe in HTTP headers.
func NewZookie(commitTs uint64) Zookie {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, commitTs)
	return Zookie{Token: base64.RawURLEncoding.EncodeToString(b)}
}

// HasToken reports whether the Zookie carries a specific commit timestamp
// (as opposed to being a "strong read without specific ts" sentinel).
func (z Zookie) HasToken() bool { return z.Token != "" }

// StrongRead is a sentinel non-nil Zookie pointer that forces a strong read
// without requiring a specific commit timestamp. Use it for security-sensitive
// reads (e.g. Login) that must never operate on stale data.
var StrongRead = &Zookie{}
