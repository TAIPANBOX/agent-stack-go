package passport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// idOfPassport is the id-extractor LoadDir's real consumers (Wardryx,
// Idryx) each pass; both dedupe Passport batches by ID.
func idOfPassport(p Passport) string { return p.ID }

func TestLoadDirDirectory(t *testing.T) {
	out, rep, err := LoadDir("testdata", Parse, idOfPassport)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// 4 files on disk: 2 valid, 2 malformed (not json, missing owner).
	if rep.Files != 4 {
		t.Errorf("Files = %d, want 4", rep.Files)
	}
	if rep.Malformed != 2 {
		t.Errorf("Malformed = %d, want 2", rep.Malformed)
	}
	if len(out) != 2 {
		t.Fatalf("passports = %d, want 2: %+v", len(out), out)
	}
	byID := map[string]bool{}
	for _, p := range out {
		byID[p.ID] = true
	}
	if !byID["agent://acme.example/finance/bot-a"] || !byID["agent://acme.example/support/bot-b"] {
		t.Errorf("loaded ids = %+v, missing an expected valid passport", byID)
	}
}

func TestLoadDirGlob(t *testing.T) {
	out, rep, err := LoadDir("testdata/valid_*.json", Parse, idOfPassport)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if rep.Files != 2 || rep.Malformed != 0 {
		t.Errorf("Files/Malformed = %d/%d, want 2/0", rep.Files, rep.Malformed)
	}
	if len(out) != 2 {
		t.Errorf("passports = %d, want 2", len(out))
	}
}

func TestLoadDirSingleFile(t *testing.T) {
	out, rep, err := LoadDir("testdata/valid_a.json", Parse, idOfPassport)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if rep.Files != 1 || rep.Malformed != 0 || len(out) != 1 {
		t.Errorf("Files/Malformed/passports = %d/%d/%d, want 1/0/1", rep.Files, rep.Malformed, len(out))
	}
}

func TestLoadDirMissingFile(t *testing.T) {
	if _, _, err := LoadDir("testdata/does-not-exist.json", Parse, idOfPassport); err == nil {
		t.Fatal("LoadDir(missing file): expected an error, got nil")
	}
}

// TestLoadDirDuplicateIDFirstWins covers LoadDir's documented dedup: two
// files whose parsed values share an id key keep only the first occurrence
// in sorted-path order, so a directory with a duplicate is still
// deterministic.
func TestLoadDirDuplicateIDFirstWins(t *testing.T) {
	dir := t.TempDir()
	first := `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://x/dup","owner":"a@x.com","runtime":"first"}`
	second := `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://x/dup","owner":"a@x.com","runtime":"second"}`
	if err := os.WriteFile(filepath.Join(dir, "a-first.json"), []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b-second.json"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}

	out, rep, err := LoadDir(dir, Parse, idOfPassport)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if rep.Files != 2 || rep.Malformed != 0 {
		t.Errorf("Files/Malformed = %d/%d, want 2/0", rep.Files, rep.Malformed)
	}
	if len(out) != 1 {
		t.Fatalf("passports = %d, want 1 (dedup by id)", len(out))
	}
	if out[0].Runtime != "first" {
		t.Errorf("Runtime = %q, want %q (first file in sorted-path order wins)", out[0].Runtime, "first")
	}
}

// TestLoadDirGenericOverAnyType proves LoadDir is genuinely reusable beyond
// Passport: any parse func([]byte) (T, error) plus an id extractor works,
// which is the entire point of extracting it out of Wardryx/Idryx's
// Passport-specific duplicates.
func TestLoadDirGenericOverAnyType(t *testing.T) {
	type widget struct {
		Name  string
		Count int
	}
	parseWidget := func(data []byte) (widget, error) {
		s := string(data)
		if s == "bad" {
			return widget{}, errors.New("bad widget")
		}
		return widget{Name: s, Count: len(s)}, nil
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, rep, err := LoadDir(dir, parseWidget, func(w widget) string { return w.Name })
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if rep.Files != 2 || rep.Malformed != 1 {
		t.Errorf("Files/Malformed = %d/%d, want 2/1", rep.Files, rep.Malformed)
	}
	if len(out) != 1 || out[0].Name != "alpha" || out[0].Count != 5 {
		t.Errorf("widgets = %+v, want one {alpha 5}", out)
	}
}
