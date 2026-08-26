package delegation

import (
	"encoding/json"
	"strings"
	"testing"
)

// THE TEST THIS PACKAGE EXISTS FOR. RFC 8693 nests `act` current-first;
// agent-passport SPEC section 5 orders `on_behalf_of` root-first. Getting the
// direction wrong produces a token that verifies perfectly and asserts the
// opposite of what happened: that the root delegated to nobody and the
// immediate actor authorised the whole chain. A signature over a lie is still a
// valid signature, so nothing downstream would catch it.
func TestTheOutermostActorIsTheImmediateOneAndNotTheRoot(t *testing.T) {
	chain := []string{"user://acme/alice", "agent://acme/triage", "agent://acme/runbook"}
	act, err := BuildAct(chain)
	if err != nil {
		t.Fatal(err)
	}
	if act.Sub != "agent://acme/runbook" {
		t.Fatalf("the outermost act must be the CURRENT actor, got %q", act.Sub)
	}
	if act.Act.Sub != "agent://acme/triage" {
		t.Fatalf("one in should be the previous actor, got %q", act.Act.Sub)
	}
	if act.Act.Act.Sub != "user://acme/alice" {
		t.Fatalf("innermost should be the root, got %q", act.Act.Act.Sub)
	}
	if act.Act.Act.Act != nil {
		t.Fatal("the chain kept going past its root")
	}
}

func TestReadingAnActGivesBackTheChainRootFirst(t *testing.T) {
	chain := []string{"user://acme/alice", "agent://acme/triage", "agent://acme/runbook"}
	act, _ := BuildAct(chain)
	got, err := ReadAct(act)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(chain, ",") {
		t.Fatalf("round trip changed the chain: %v -> %v", chain, got)
	}
}

func TestAOneHopChainIsNotSecretlyReversed(t *testing.T) {
	// A single element round-trips under BOTH directions, so it can never
	// catch an inversion. Named here so nobody mistakes it for coverage of the
	// property above.
	act, _ := BuildAct([]string{"user://acme/alice"})
	if act.Sub != "user://acme/alice" || act.Act != nil {
		t.Fatalf("a one-hop chain is one act: %+v", act)
	}
}

func TestTheWireShapeIsTheRfcs(t *testing.T) {
	// Held against the JSON rather than the struct, because the struct is ours
	// and the wire is the RFC's. An `act` that serialised its nesting under any
	// other member would verify here and be unreadable to every other
	// implementation.
	act, _ := BuildAct([]string{"a", "b"})
	raw, err := json.Marshal(act)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"sub":"b","act":{"sub":"a"}}`
	if string(raw) != want {
		t.Fatalf("wire shape drifted:\n got %s\nwant %s", raw, want)
	}
}

func TestAnEmptyChainIsNoActRatherThanAnEmptyOne(t *testing.T) {
	// `"act": {"sub": ""}` would assert that somebody with no name is acting,
	// which is a stronger and falser claim than saying nothing.
	act, err := BuildAct(nil)
	if err != nil || act != nil {
		t.Fatalf("an empty chain must produce no act: %+v %v", act, err)
	}
}

func TestAChainLongerThanTheSpecsCapIsRefused(t *testing.T) {
	// SPEC 5.1 caps the recorded chain at 32. A token carrying more would be a
	// delegation nothing in this estate could audit.
	long := make([]string, MaxDepth+1)
	for i := range long {
		long[i] = "agent://acme/a" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	if _, err := BuildAct(long); err != ErrTooDeep {
		t.Fatalf("a chain of %d was not refused: %v", len(long), err)
	}
}

func TestAnActThatPointsAtItselfDoesNotSpin(t *testing.T) {
	// The claim comes off the wire, so its shape is the caller's to choose. A
	// reader that walked a cycle would hang inside the request path.
	loop := &Act{Sub: "a"}
	loop.Act = loop
	if _, err := ReadAct(loop); err != ErrTooDeep {
		t.Fatalf("a self-referential act was walked: %v", err)
	}
}

func TestAnActorAlreadyInTheChainIsRefusedRatherThanDeduplicated(t *testing.T) {
	// An agent appearing twice in its own delegation chain is a loop or a
	// confused caller. Collapsing it quietly would hide both and produce a
	// token that looks ordinary.
	chain := []string{"user://acme/alice", "agent://acme/triage"}
	if _, err := Extend(chain, "agent://acme/triage"); err != ErrSelf {
		t.Fatalf("a repeated actor was accepted: %v", err)
	}
	got, err := Extend(chain, "agent://acme/runbook")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "agent://acme/runbook" {
		t.Fatalf("an honest extension goes on the END, root-first: %v", got)
	}
}

func TestExtendDoesNotWriteIntoItsCallersSlice(t *testing.T) {
	// `append` on a slice with spare capacity writes through. A chain shared
	// between two exchanges would then acquire the other's actor, which is a
	// delegation nobody granted.
	backing := make([]string, 2, 8)
	backing[0], backing[1] = "user://acme/alice", "agent://acme/triage"
	if _, err := Extend(backing, "agent://acme/one"); err != nil {
		t.Fatal(err)
	}
	second, err := Extend(backing, "agent://acme/two")
	if err != nil {
		t.Fatal(err)
	}
	if second[2] != "agent://acme/two" {
		t.Fatalf("the second extension saw the first: %v", second)
	}
}

// RFC 8693 keeps the subject out of `act`; agent-passport puts the root INTO
// `on_behalf_of`. A service that handed `ReadAct` straight to the record would
// write a delegation chain with the human missing, and every token would still
// verify.
func TestTheEstateChainCarriesTheSubjectAndTheRfcsActDoesNot(t *testing.T) {
	act, _ := BuildAct([]string{"agent://acme/triage", "agent://acme/runbook"})

	actors, err := ReadAct(act)
	if err != nil {
		t.Fatal(err)
	}
	if len(actors) != 2 {
		t.Fatalf("`act` holds actors only: %v", actors)
	}

	chain, err := Chain("user://acme/alice", act)
	if err != nil {
		t.Fatal(err)
	}
	want := "user://acme/alice,agent://acme/triage,agent://acme/runbook"
	if strings.Join(chain, ",") != want {
		t.Fatalf("the estate chain is the subject then the actors:\n got %v\nwant %s", chain, want)
	}
}

func TestAChainWithNoSubjectIsTheActorsAlone(t *testing.T) {
	// A machine-to-machine exchange with no human at the root is legitimate.
	// Prepending an empty string would put a nameless principal at the head of
	// a delegation chain, which is a stronger and falser claim than saying
	// nothing.
	act, _ := BuildAct([]string{"agent://acme/one"})
	chain, err := Chain("", act)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0] != "agent://acme/one" {
		t.Fatalf("%v", chain)
	}
}
