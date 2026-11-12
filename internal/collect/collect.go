// Package collect holds what every collector shares: the snapshot a
// successful collection returns, and the classified error a failed one
// returns. It talks to no external service.
package collect

import "time"

// Class says why a collection attempt failed. It is recorded on the run and
// never becomes a check result.
type Class string

// The error classes a collection attempt can end in.
const (
	Auth        Class = "auth"               // credential missing, invalid or expired
	Permission  Class = "permission"         // credential valid but not allowed to read this
	RateLimited Class = "rate_limited"       // the source asked the caller to slow down
	NotFound    Class = "not_found"          // the resource does not exist, or is hidden
	Network     Class = "network"            // no usable response, or the attempt timed out
	Server      Class = "server"             // the source reported a fault of its own
	Malformed   Class = "malformed_response" // the response was not in the expected form
	Unexpected  Class = "unexpected_status"  // any other refusal
	Storage     Class = "storage"            // evidence was read but could not be saved
	Interrupted Class = "interrupted"        // the worker stopped before the run finished
)

// Classes lists every class, in the order documents show them.
var Classes = []Class{Auth, Permission, RateLimited, NotFound, Network, Server, Malformed, Unexpected, Storage, Interrupted}

// Error is a classified collection failure.
type Error struct {
	Class  Class
	Detail string
	// RetryAfter is how long the source asked the caller to wait, when it said.
	RetryAfter time.Duration
}

func (e *Error) Error() string { return string(e.Class) + ": " + e.Detail }

// Snapshot is the evidence one successful collection produced.
type Snapshot struct {
	// Kind names the observation, such as "github.branch_rules".
	Kind string
	// Normalizer versions the shape of Payload.
	Normalizer string
	// Payload is the canonical evidence: the same source state always
	// yields the same bytes.
	Payload []byte
	// Complete is false when a listing was not read to its end.
	Complete bool
	// SourceTimestamp is when the source says the data was produced, when
	// that differs from the time of collection.
	SourceTimestamp *time.Time
}
