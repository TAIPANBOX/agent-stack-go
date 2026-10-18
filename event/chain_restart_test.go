package event

import (
	"reflect"
	"strings"
	"testing"
)

// Scenario: features/checkpoints.feature, "a restart names the last good line
// before it". A restart is not a break (invariant 7); the verifier says where
// each one starts so that a resume checkpoint can explain it.

func TestVerifyChainReportsTheLastWellFormedLineBeforeEachRestart(t *testing.T) {
	seg := chainOf(t, vecEvent1(), vecEvent2())
	fresh := chainOf(t, vecEvent3(), vecEvent1())
	lines := []string{
		seg[0],
		seg[1],
		"not an event at all",
		fresh[0],                   // line 4: a head, after a malformed line
		fresh[1],                   // line 5: chained to line 4
		chainOf(t, vecEvent2())[0], // line 6: a head again, straight after a good line
	}
	r, restarts, err := VerifyChainRestarts(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.HeadLines, []int{1, 4, 6}) {
		t.Fatalf("head lines: %v", r.HeadLines)
	}
	if want := []Restart{{Line: 4, After: 2}, {Line: 6, After: 5}}; !reflect.DeepEqual(restarts, want) {
		t.Fatalf("each restart names the last well-formed line before it: want %v, got %v", want, restarts)
	}
	if !r.Ok() {
		t.Fatalf("restarts are not breaks: %+v", r.Breaks)
	}
}
