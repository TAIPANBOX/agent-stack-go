package delegation

import (
	"errors"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/chain"
)

// The record refuses a cyclic chain: SPEC 5.1 says `on_behalf_of` MUST be
// acyclic, and `chain.Validate` enforces it. The door did not.
//
// So `Chain` handed out a chain the record would refuse, which is the same
// shape as the depth off-by-one one commit earlier, and the reason the two
// drifted is structural: `deps-layering.sh` requires `delegation` to depend on
// the standard library alone, so it cannot call `chain.Validate` and the rule
// has to exist twice.
//
// This test is in `delegation` and imports `chain` because a TEST may: the
// layering rule is about the library's dependencies, not its test binary's, and
// comparing the two answers is the only honest way to assert they agree.
func TestEveryChainThisPackageHandsOutIsAcyclicBecauseTheRecordRequiresIt(t *testing.T) {
	// The exact shape `BuildAct` invites: its doc example passes a whole
	// root-first chain, root included, so the root ends up inside `act` while
	// also being the token's `sub`.
	root := "user://acme.example/alice"
	act, err := BuildAct([]string{root, "agent://acme.example/triage"})
	if err != nil {
		t.Fatalf("BuildAct: %v", err)
	}

	got, err := Chain(root, act)
	if err == nil {
		if verr := chain.Validate(got); verr != nil {
			t.Fatalf(
				"Chain handed out %v, which the record refuses: %v",
				got, verr,
			)
		}
		t.Fatalf("Chain accepted a chain naming %q twice: %v", root, got)
	}
	if !errors.Is(err, ErrCycle) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// The mirror, and the one that stops the fix overshooting: two DIFFERENT
// principals are not a cycle, and the common chain must keep working.
func TestADistinctSubjectAndActorAreNotACycle(t *testing.T) {
	act, err := BuildAct([]string{"agent://acme.example/triage"})
	if err != nil {
		t.Fatalf("BuildAct: %v", err)
	}
	got, err := Chain("user://acme.example/alice", act)
	if err != nil {
		t.Fatalf("an ordinary chain was refused: %v", err)
	}
	want := []string{"user://acme.example/alice", "agent://acme.example/triage"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if verr := chain.Validate(got); verr != nil {
		t.Fatalf("the record refuses what the door built: %v", verr)
	}
}

// A repeat among the ACTORS alone, with no subject involved, so the check is
// about the whole assembled chain rather than only about the subject.
func TestARepeatedActorIsACycleToo(t *testing.T) {
	act, err := BuildAct([]string{
		"agent://acme.example/triage",
		"agent://acme.example/runbook",
		"agent://acme.example/triage",
	})
	if err != nil {
		t.Fatalf("BuildAct: %v", err)
	}
	if _, err := Chain("user://acme.example/alice", act); !errors.Is(err, ErrCycle) {
		t.Fatalf("a chain naming one actor twice was accepted: %v", err)
	}
}

// The record refuses an entry that is not an `agent://` or `user://` URI. The
// door refused only an EMPTY one, so a token naming a principal like
// `mailto:alice` verified and its trail could not be written.
//
// Found in this change's own NOT PROVEN section: the gate that compares the two
// carried a recorded alias mapping the record's `ErrInvalidEntry` onto the
// door's `ErrNoSubject`, and they are not the same rule. A gate reporting
// agreement where the check is weaker is worse than no gate, because it says
// the question was asked.
func TestEveryEntryThisPackageHandsOutIsOneTheRecordAccepts(t *testing.T) {
	for _, bad := range []string{
		"mailto:alice@acme.example",
		"acme.example/alice",
		"https://acme.example/alice",
		"agent:/acme.example/triage",
	} {
		act, err := BuildAct([]string{bad})
		if err != nil {
			t.Fatalf("BuildAct(%q): %v", bad, err)
		}
		got, err := Chain("user://acme.example/alice", act)
		if err == nil {
			if verr := chain.Validate(got); verr != nil {
				t.Fatalf("Chain handed out %v, which the record refuses: %v", got, verr)
			}
			t.Fatalf("Chain accepted %q as a principal: %v", bad, got)
		}
		if !errors.Is(err, ErrInvalidEntry) {
			t.Fatalf("%q refused for the wrong reason: %v", bad, err)
		}
	}
}

// The mirror: both schemes the SPEC names must keep working, at either end of
// the chain, or this check would refuse every real token.
func TestBothSchemesTheSpecNamesAreAccepted(t *testing.T) {
	act, err := BuildAct([]string{"user://acme.example/carol", "agent://acme.example/triage"})
	if err != nil {
		t.Fatalf("BuildAct: %v", err)
	}
	got, err := Chain("user://acme.example/alice", act)
	if err != nil {
		t.Fatalf("a chain of the two schemes the spec names was refused: %v", err)
	}
	if verr := chain.Validate(got); verr != nil {
		t.Fatalf("the record refuses what the door built: %v", verr)
	}
}
