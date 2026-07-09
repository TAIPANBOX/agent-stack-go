// Package chain implements the delegation-chain helpers defined by the
// agent-passport SPEC (§5) and its v0.2 normative rule: a chain is an
// ordered, root-first list of agent:// or user:// URIs. The last entry is
// the immediate principal; the first is the root (usually a human). A
// service receiving a chain appends exactly one entry, its own principal,
// and MUST reject a chain that already contains that principal (a cycle) or
// that would exceed the maximum depth.
package chain

import (
	"errors"
	"fmt"
	"regexp"
)

// MaxDepth is the maximum number of entries a delegation chain may hold,
// per the v0.2 delegation-chain rule: a chain MUST be acyclic and MUST NOT
// exceed 32 entries.
const MaxDepth = 32

// entryPattern matches a well-formed chain entry scheme: agent:// or
// user://. Compiled once and reused by Validate.
var entryPattern = regexp.MustCompile(`^(agent|user)://`)

// Sentinel errors returned by Append and Validate. Wrapped with additional
// context, so callers can still branch on failure kind with errors.Is.
var (
	// ErrCycle means the chain already contains the principal being
	// appended (Append), or contains a duplicate entry (Validate).
	ErrCycle = errors.New("chain: cycle detected")
	// ErrTooDeep means the chain would exceed, or already exceeds,
	// MaxDepth entries.
	ErrTooDeep = errors.New("chain: exceeds max depth")
	// ErrInvalidEntry means an entry is not an agent:// or user:// URI.
	ErrInvalidEntry = errors.New("chain: invalid entry")
)

// Append returns a new chain with principal appended to chain. chain itself
// is never mutated: Append always allocates its own backing array, so two
// chains derived from the same parent by different calls never alias each
// other's memory.
//
// It returns ErrCycle if principal already appears in chain: a service MUST
// reject a chain that already contains its own principal. It returns
// ErrTooDeep if the result would exceed MaxDepth entries.
func Append(chain []string, principal string) ([]string, error) {
	for _, p := range chain {
		if p == principal {
			return nil, fmt.Errorf("%w: %q already present in chain", ErrCycle, principal)
		}
	}
	if len(chain) >= MaxDepth {
		return nil, fmt.Errorf("%w: chain already has %d entries, max %d", ErrTooDeep, len(chain), MaxDepth)
	}

	out := make([]string, len(chain), len(chain)+1)
	copy(out, chain)
	out = append(out, principal)
	return out, nil
}

// Validate checks that chain is acyclic (no entry repeated), within
// MaxDepth, and that every entry is an agent:// or user:// URI. A nil or
// empty chain is valid: per the spec, it means the agent acts autonomously.
func Validate(chain []string) error {
	if len(chain) > MaxDepth {
		return fmt.Errorf("%w: %d entries, max %d", ErrTooDeep, len(chain), MaxDepth)
	}
	seen := make(map[string]bool, len(chain))
	for _, p := range chain {
		if seen[p] {
			return fmt.Errorf("%w: %q appears more than once", ErrCycle, p)
		}
		seen[p] = true
		if !entryPattern.MatchString(p) {
			return fmt.Errorf("%w: %q", ErrInvalidEntry, p)
		}
	}
	return nil
}
