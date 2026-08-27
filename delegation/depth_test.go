package delegation_test

// The seam between the two halves of the delegation cap.
//
// One half builds a chain out of an RFC 8693 token; the other half is the
// record that has to hold it. They live in two packages, they were written
// months apart, and no test inside either one can see the other's bound. That
// is the shape a cross-package test exists for.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/chain"
	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

func actors(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("agent://acme.example/a%03d", i)
	}
	return out
}

// TestEveryChainThisPackageHandsOutIsOneTheRecordWillHold sweeps the boundary
// instead of picking a value at it. agent-passport SPEC 5.1 bounds the chain
// at 32 ENTRIES, `chain.Validate` enforces exactly that, and this package
// assembles `[sub] + actors`. So the actor list and the chain are off by one
// whenever a subject is present, and picking a single depth is how an
// off-by-one survives a test suite.
func TestEveryChainThisPackageHandsOutIsOneTheRecordWillHold(t *testing.T) {
	for n := 0; n <= chain.MaxDepth+4; n++ {
		for _, sub := range []string{"", "user://acme.example/alice"} {
			act, err := delegation.BuildAct(actors(n))
			if err != nil {
				continue // this package refused to build it; nothing was handed out
			}
			got, err := delegation.Chain(sub, act)
			if err != nil {
				continue // refused, which is the honest answer at the boundary
			}
			if err := chain.Validate(got); err != nil {
				t.Fatalf("Chain(sub=%q, %d actors) handed out a %d-entry chain the record refuses: %v",
					sub, n, len(got), err)
			}
		}
	}
}

// TestTheSubjectCountsTowardsTheCapBecauseTheSpecCountsEntries pins which of
// the two readings of SPEC 5.1 this estate holds. "Maximum chain depth is 32
// entries" is a bound on `on_behalf_of`, and section 5 calls its members
// entries; the subject is the first of them.
func TestTheSubjectCountsTowardsTheCapBecauseTheSpecCountsEntries(t *testing.T) {
	full, err := delegation.BuildAct(actors(chain.MaxDepth - 1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := delegation.Chain("user://acme.example/alice", full)
	if err != nil {
		t.Fatalf("a subject plus %d actors is exactly %d entries and must be built: %v",
			chain.MaxDepth-1, chain.MaxDepth, err)
	}
	if len(got) != chain.MaxDepth {
		t.Fatalf("chain length = %d, want %d", len(got), chain.MaxDepth)
	}

	overFull, err := delegation.BuildAct(actors(chain.MaxDepth))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := delegation.Chain("user://acme.example/alice", overFull); !errors.Is(err, delegation.ErrTooDeep) {
		t.Fatalf("a subject plus %d actors is %d entries and must be refused, got %v",
			chain.MaxDepth, chain.MaxDepth+1, err)
	}
}

// TestAChainWithNoSubjectStillGetsTheWholeCap guards the direction the fix
// must not overshoot in. A machine-to-machine exchange has no human at the
// root, its chain is the actors alone, and 32 of them is 32 entries. Capping
// the actor list at 31 unconditionally would refuse a chain the SPEC allows.
func TestAChainWithNoSubjectStillGetsTheWholeCap(t *testing.T) {
	act, err := delegation.BuildAct(actors(chain.MaxDepth))
	if err != nil {
		t.Fatal(err)
	}
	got, err := delegation.Chain("", act)
	if err != nil {
		t.Fatalf("%d actors with no subject is %d entries and must be built: %v",
			chain.MaxDepth, chain.MaxDepth, err)
	}
	if len(got) != chain.MaxDepth {
		t.Fatalf("chain length = %d, want %d", len(got), chain.MaxDepth)
	}
	if err := chain.Validate(got); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
