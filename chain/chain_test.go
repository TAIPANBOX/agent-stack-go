package chain

import (
	"errors"
	"fmt"
	"testing"
)

func TestAppend(t *testing.T) {
	got, err := Append(nil, "user://acme.example/j.doe")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	want := []string{"user://acme.example/j.doe"}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("Append(nil, ...) = %v, want %v", got, want)
	}

	got, err = Append(got, "agent://acme.example/orchestrator")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	want = []string{"user://acme.example/j.doe", "agent://acme.example/orchestrator"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Append chain = %v, want %v", got, want)
	}
}

func TestAppendCycle(t *testing.T) {
	c := []string{"user://acme.example/j.doe", "agent://acme.example/orchestrator"}
	_, err := Append(c, "agent://acme.example/orchestrator")
	if !errors.Is(err, ErrCycle) {
		t.Errorf("Append error = %v, want wrapping ErrCycle", err)
	}
}

func TestAppendDoesNotMutateInput(t *testing.T) {
	base := []string{"user://acme.example/j.doe"}
	if _, err := Append(base, "agent://acme.example/orchestrator"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(base) != 1 || base[0] != "user://acme.example/j.doe" {
		t.Errorf("input chain was mutated: %v", base)
	}
}

// TestAppendNoAliasingBetweenSiblingChains guards the specific Go slice
// pitfall Append must avoid: appending to a slice that has spare capacity
// can silently write into memory a sibling slice still holds a reference
// to. Two agents that both received the same upstream chain and each
// append their own principal must get fully independent results.
func TestAppendNoAliasingBetweenSiblingChains(t *testing.T) {
	base := make([]string, 2, 8) // len 2, cap 8: room for an in-place append
	base[0] = "user://acme.example/j.doe"
	base[1] = "agent://acme.example/orchestrator"

	a, err := Append(base, "agent://acme.example/worker-a")
	if err != nil {
		t.Fatalf("Append a: %v", err)
	}
	b, err := Append(base, "agent://acme.example/worker-b")
	if err != nil {
		t.Fatalf("Append b: %v", err)
	}
	if got := a[len(a)-1]; got != "agent://acme.example/worker-a" {
		t.Errorf("a's last entry = %q, want worker-a (b's Append must not overwrite it)", got)
	}
	if got := b[len(b)-1]; got != "agent://acme.example/worker-b" {
		t.Errorf("b's last entry = %q, want worker-b", got)
	}
	if len(base) != 2 {
		t.Errorf("base was mutated: len = %d, want 2", len(base))
	}
}

func TestAppendMaxDepthBoundary(t *testing.T) {
	// A chain of MaxDepth-1 entries may still grow to exactly MaxDepth.
	almostFull := make([]string, MaxDepth-1)
	for i := range almostFull {
		almostFull[i] = fmt.Sprintf("agent://acme.example/a%d", i)
	}
	full, err := Append(almostFull, "agent://acme.example/last")
	if err != nil {
		t.Fatalf("Append at depth %d: %v", len(almostFull), err)
	}
	if len(full) != MaxDepth {
		t.Fatalf("len(full) = %d, want %d", len(full), MaxDepth)
	}
	if err := Validate(full); err != nil {
		t.Errorf("Validate(full %d-entry chain) = %v, want nil", MaxDepth, err)
	}

	// A chain already at MaxDepth must reject any further append.
	if _, err := Append(full, "agent://acme.example/one-too-many"); !errors.Is(err, ErrTooDeep) {
		t.Errorf("Append beyond MaxDepth error = %v, want wrapping ErrTooDeep", err)
	}
}

func TestValidate(t *testing.T) {
	valid := [][]string{
		nil,
		{},
		{"agent://acme.example/bot"},
		{"user://acme.example/j.doe", "agent://acme.example/orchestrator", "agent://acme.example/worker"},
	}
	for _, c := range valid {
		if err := Validate(c); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", c, err)
		}
	}

	cases := []struct {
		name    string
		chain   []string
		wantErr error
	}{
		{
			name:    "duplicate entry",
			chain:   []string{"agent://acme.example/orchestrator", "agent://acme.example/orchestrator"},
			wantErr: ErrCycle,
		},
		{
			name:    "invalid scheme",
			chain:   []string{"https://acme.example/bot"},
			wantErr: ErrInvalidEntry,
		},
		{
			name:    "no scheme at all",
			chain:   []string{"acme.example/bot"},
			wantErr: ErrInvalidEntry,
		},
		{
			name:    "cycle checked before a later invalid entry",
			chain:   []string{"agent://acme.example/orchestrator", "agent://acme.example/orchestrator", "not-a-uri"},
			wantErr: ErrCycle,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.chain)
			if !errors.Is(err, c.wantErr) {
				t.Errorf("Validate(%v) error = %v, want wrapping %v", c.chain, err, c.wantErr)
			}
		})
	}
}

func TestValidateTooDeep(t *testing.T) {
	tooDeep := make([]string, MaxDepth+1)
	for i := range tooDeep {
		tooDeep[i] = fmt.Sprintf("agent://acme.example/a%d", i)
	}
	if err := Validate(tooDeep); !errors.Is(err, ErrTooDeep) {
		t.Errorf("Validate(%d entries) error = %v, want wrapping ErrTooDeep", len(tooDeep), err)
	}
}
