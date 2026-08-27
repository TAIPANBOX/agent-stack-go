package delegation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/chain"
)

// vector is one case from the cross-language table.
type vector struct {
	Name         string   `json:"name"`
	Why          string   `json:"why"`
	Sub          string   `json:"sub"`
	Act          []string `json:"act"`
	ActGenerated *struct {
		Template string `json:"template"`
		Count    int    `json:"count"`
	} `json:"act_generated"`
	Verdict string   `json:"verdict"`
	Chain   []string `json:"chain"`
}

// actors is the `act` list, outermost first, with a generated case expanded.
func (v vector) actors() []string {
	if v.ActGenerated == nil {
		return v.Act
	}
	out := make([]string, 0, v.ActGenerated.Count)
	for i := 1; i <= v.ActGenerated.Count; i++ {
		out = append(out, fmt.Sprintf(v.ActGenerated.Template, i))
	}
	return out
}

// asAct nests the actors the way RFC 8693 does, outermost first.
func (v vector) asAct() *Act {
	var act *Act
	for i := len(v.actors()) - 1; i >= 0; i-- {
		act = &Act{Sub: v.actors()[i], Act: act}
	}
	return act
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "chain", "testdata", "chain-verdict-vectors.json"))
	if err != nil {
		t.Fatalf("the cross-language verdict table is unreadable: %v", err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the verdict table is not JSON this test can read: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("the verdict table is empty, so this test would prove nothing")
	}
	return doc.Vectors
}

// TestTheDoorAnswersTheCrossLanguageTable is the whole point of the table.
//
// The record's rules live in `chain` and this door cannot call them:
// `scripts/deps-layering.sh` requires `delegation` to depend on the standard
// library alone. So the rules exist twice by construction, in Go, and a third
// time in Rust at tokenfuse's own door, with no seam between any of them.
//
// Three of the estate's rules were found disagreeing across those copies on
// 2026-08-27, all in one afternoon. Prose could not hold them and a gate reading
// source text could not either: a regex over two languages tells you a rule is
// MENTIONED, never that it ANSWERS. A table each door runs is the only form of
// this check that cannot be satisfied by a comment.
func TestTheDoorAnswersTheCrossLanguageTable(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Chain(v.Sub, v.asAct())
			switch v.Verdict {
			case "accept":
				if err != nil {
					t.Fatalf("refused a chain the table accepts: %v\nwhy this case exists: %s", err, v.Why)
				}
				if v.Chain != nil && !equal(got, v.Chain) {
					t.Fatalf("assembled %v, the table says %v\nwhy: %s", got, v.Chain, v.Why)
				}
				// Whatever the door builds, the record must hold. The table
				// pins the shape; this pins that the two agree about it.
				if verr := chain.Validate(got); verr != nil {
					t.Fatalf("the door built %v and the record refuses it: %v", got, verr)
				}
			case "cycle":
				if !errors.Is(err, ErrCycle) {
					t.Fatalf("got (%v, %v), the table says cycle\nwhy: %s", got, err, v.Why)
				}
			case "too_deep":
				if !errors.Is(err, ErrTooDeep) {
					t.Fatalf("got (%v, %v), the table says too_deep\nwhy: %s", got, err, v.Why)
				}
			case "invalid_entry":
				if !errors.Is(err, ErrInvalidEntry) && !errors.Is(err, ErrNoSubject) {
					t.Fatalf("got (%v, %v), the table says invalid_entry\nwhy: %s", got, err, v.Why)
				}
			default:
				t.Fatalf("the table names a verdict this test does not know: %q", v.Verdict)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
