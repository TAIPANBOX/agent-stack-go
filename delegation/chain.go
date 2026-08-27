// Package exchange holds the RFC 8693 token-exchange logic, as pure functions
// over already-verified claims.
//
// Pure on purpose: the exchange is where a delegation chain is built, and a
// chain built the wrong way round validates cleanly while saying the opposite
// of what happened. That has to be testable without a key, a clock or a socket.
package delegation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxDepth is the longest chain this service will build or accept, counted in
// `on_behalf_of` ENTRIES.
//
// The unit is the whole of it. agent-passport SPEC section 5.1 says "Maximum
// chain depth is 32 entries", and section 5 calls the members of
// `on_behalf_of` entries; the subject is the first of them. So this bounds the
// assembled chain and not the RFC 8693 actor list, and the two differ by one
// whenever a token names a subject.
//
// The record and this must agree: a token carrying a chain the record cannot
// hold is a delegation nothing could audit. It is also what stops a caller
// walking a self-referential `act` for ever.
const MaxDepth = 32

// MaxActorsWithSubject is MaxDepth expressed in RFC 8693 actors, for a token
// that names a subject.
//
// Derived rather than re-typed, because the two numbers are one decision.
// Measured 2026-08-27: `Chain` bounded the ACTOR list at MaxDepth and then
// prepended the subject, so a 32-actor token verified at the door and produced
// a 33-entry chain that every validating consumer in the estate quarantined
// ("maxItems: got 33, want 32"). A second literal is how the two halves of one
// rule drift apart while both look right.
const MaxActorsWithSubject = MaxDepth - 1

var (
	ErrNoSubject = errors.New("delegation: the subject token names no subject")
	ErrTooDeep   = fmt.Errorf("delegation: the delegation chain is longer than %d", MaxDepth)
	ErrSelf      = errors.New("delegation: an actor may not delegate to itself")
	// ErrCycle means the assembled chain names one principal twice.
	//
	// SPEC 5.1: the `on_behalf_of` chain MUST be acyclic. `chain.Validate`
	// has enforced that at the RECORD since it was written; the door did
	// not, so this package could hand out a chain the record refuses. That
	// is the same defect as the depth off-by-one one commit earlier, and it
	// has the same structural cause: `scripts/deps-layering.sh` requires
	// this package to depend on the standard library alone, so it cannot
	// call `chain.Validate` and the rule exists twice on purpose.
	//
	// Two rules that must agree with nothing comparing them is the shape
	// this estate has spent two days finding, so a gate compares them:
	// `scripts/door-and-record-agree.sh`.
	ErrCycle = errors.New("delegation: the delegation chain names a principal twice")
	// ErrInvalidEntry means a principal is not an `agent://` or `user://` URI.
	//
	// SPEC section 5: entries are `agent://` or `user://` URIs. The record has
	// refused anything else since `chain.Validate` was written; the door
	// refused only an EMPTY principal, so a token naming `mailto:alice`
	// verified and its trail could not be written.
	//
	// Found in this change's own NOT PROVEN section, which had recorded that
	// `door-and-record-agree.sh` mapped the record's rule onto the door's
	// weaker one through an alias. A gate reporting agreement where the check
	// is weaker is worse than no gate: it says the question was asked.
	ErrInvalidEntry = errors.New("delegation: a chain entry is not an agent:// or user:// URI")
)

// Act is the RFC 8693 section 4.1 actor claim, nested.
type Act struct {
	Sub string `json:"sub"`
	Act *Act   `json:"act,omitempty"`
}

// BuildAct turns an agent-passport delegation chain into an `act` claim.
//
// # The direction, which is the whole of this function
//
// RFC 8693 section 4.1: "The outermost 'act' claim represents the current actor
// while nested 'act' claims represent prior actors." So the OUTERMOST is the
// immediate actor, and nesting goes back in time.
//
// agent-passport SPEC section 5 orders `on_behalf_of` as "an ordered list, root
// first", so the immediate actor is at the END.
//
// The mapping is therefore a REVERSAL, and this is the one place in the estate
// where getting a direction wrong produces something that verifies perfectly
// and asserts the opposite of what happened: that the root delegated to nobody
// and the immediate actor authorised the whole chain. A signature over a lie is
// still a valid signature.
//
//	chain (root first):  [user://alice, agent://triage, agent://runbook]
//	act (current first): {runbook, act:{triage, act:{alice}}}
func BuildAct(chain []string) (*Act, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	if len(chain) > MaxDepth {
		return nil, ErrTooDeep
	}
	// Walk the chain from the ROOT, wrapping each new actor around what came
	// before, so the last one processed ends up outermost.
	var act *Act
	for _, sub := range chain {
		if sub == "" {
			return nil, ErrNoSubject
		}
		act = &Act{Sub: sub, Act: act}
	}
	return act, nil
}

// ReadAct turns an `act` claim back into an agent-passport chain, root first.
//
// The inverse of [BuildAct], and it is a separate function rather than a
// reversal at the call site because the two are used by different processes:
// this service builds, and every enforcement point reads. A test holds them
// against each other in both directions, because an inverse that is not one is
// how a chain silently reverses on its way through the estate.
func ReadAct(act *Act) ([]string, error) {
	var reversed []string
	for a := act; a != nil; a = a.Act {
		if len(reversed) >= MaxDepth {
			return nil, ErrTooDeep
		}
		if a.Sub == "" {
			return nil, ErrNoSubject
		}
		reversed = append(reversed, a.Sub)
	}
	// Collected current-first; the estate wants root-first.
	chain := make([]string, len(reversed))
	for i, sub := range reversed {
		chain[len(reversed)-1-i] = sub
	}
	return chain, nil
}

// Extend adds one actor to a chain, refusing the shapes that are not
// delegations at all.
//
// A chain that already names the actor is refused rather than deduplicated: an
// agent appearing twice in its own delegation chain is either a loop or a
// confused caller, and quietly collapsing it would hide both while producing a
// token that looks ordinary.
func Extend(chain []string, actor string) ([]string, error) {
	if actor == "" {
		return nil, ErrNoSubject
	}
	if len(chain)+1 > MaxDepth {
		return nil, ErrTooDeep
	}
	for _, s := range chain {
		if s == actor {
			return nil, ErrSelf
		}
	}
	out := make([]string, 0, len(chain)+1)
	out = append(out, chain...)
	return append(out, actor), nil
}

// Chain is the agent-passport `on_behalf_of` for a token: the subject, then
// the actors, root first.
//
// # The join nobody sees until they look
//
// RFC 8693 keeps them apart. `sub` is who the token is FOR, and `act` is the
// chain of who is acting; the subject is deliberately not in `act`, because it
// is not an actor. agent-passport SPEC section 5 does the opposite: its
// `on_behalf_of` is one ordered list, root first, and the root is the person.
//
// So the two are not the same list with a different order. They are a list and
// a list-plus-its-head, and a service that handed `ReadAct` straight to the
// record would write a delegation chain with the human missing from it. Every
// token would still verify; the trail would say a fleet of agents acted on
// nobody's behalf.
//
// Found by the end-to-end test rather than by reading either specification,
// which is the only way this kind of mismatch is ever found.
func Chain(sub string, act *Act) ([]string, error) {
	actors, err := ReadAct(act)
	if err != nil {
		return nil, err
	}
	out := actors
	if sub != "" {
		// The subject is about to become the chain's first ENTRY, and SPEC 5.1
		// counts entries. Bounding the actors alone would hand out a chain one
		// longer than anything downstream will accept.
		if len(actors) > MaxActorsWithSubject {
			return nil, ErrTooDeep
		}
		out = make([]string, 0, len(actors)+1)
		out = append(out, sub)
		out = append(out, actors...)
	}
	// Acyclic, because SPEC 5.1 requires it and `chain.Validate` refuses a
	// chain that is not. Checked HERE rather than assumed from upstream: this
	// is what an enforcement point calls, and a door that hands out a chain the
	// record will refuse has verified a token whose trail cannot be written.
	// That is the quarantine the depth cap produced one commit ago, one rule
	// over.
	//
	// It catches the trap `BuildAct` invites: its doc example passes a whole
	// root-first chain, root included, so the root lands inside `act` while
	// also being the token's `sub`, and the assembled chain names it twice.
	// vouchryx does not do that, measured on a live token on 2026-08-27, which
	// is why this was a trap rather than an outage.
	seen := make(map[string]bool, len(out))
	for _, p := range out {
		if seen[p] {
			return nil, ErrCycle
		}
		seen[p] = true
		// The SCHEME only, deliberately, which is exactly what the record
		// checks. A stricter pattern here would refuse chains the record
		// accepts, which is this rule failing in the other direction.
		if !strings.HasPrefix(p, "agent://") && !strings.HasPrefix(p, "user://") {
			return nil, ErrInvalidEntry
		}
	}
	return out, nil
}

// decodeAct reads an `act` claim out of the loosely typed claim map.
func decodeAct(raw any, into *Act) error {
	if raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
