package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestMarshalGoldenShape(t *testing.T) {
	e := Event{
		Schema:   SchemaV02,
		TS:       "2026-07-09T03:12:44.100Z",
		Source:   "wardryx",
		Type:     "policy_deny",
		AgentID:  "agent://acme-bank.example/support/tier1-bot",
		Severity: SeverityHigh,
		RunID:    "run-8842",
		Data:     map[string]any{"reason": "budget_exceeded"},
	}
	data, err := Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme-bank.example/support/tier1-bot","severity":"high","run_id":"run-8842","data":{"reason":"budget_exceeded"}}`
	if string(data) != want {
		t.Errorf("Marshal =\n%s\nwant\n%s", data, want)
	}
}

func TestMarshalOmitsEmptyOptionals(t *testing.T) {
	e := Event{
		Schema:  SchemaV02,
		TS:      "2026-07-09T00:00:00Z",
		Source:  "wardryx",
		Type:    "policy_allow",
		AgentID: "agent://acme.example/bot",
	}
	data, err := Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	for _, key := range []string{"severity", "run_id", "on_behalf_of", "data", "prev_hash"} {
		if _, ok := raw[key]; ok {
			t.Errorf("key %q present, want omitted: %s", key, data)
		}
	}
}

func TestUnmarshalRoundTrip(t *testing.T) {
	want := Event{
		Schema:     SchemaV02,
		TS:         "2026-07-09T00:00:00Z",
		Source:     "wardryx",
		Type:       "policy_deny",
		AgentID:    "agent://acme.example/bot",
		Severity:   SeverityHigh,
		RunID:      "run-1",
		OnBehalfOf: []string{"user://acme.example/j.doe"},
		Data:       map[string]any{"tool": "shell.exec"},
		PrevHash:   "sha256:" + strings.Repeat("a", 64),
	}
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantErr error
	}{
		{"not json", `not json`, ErrInvalidJSON},
		{"missing schema", `{"ts":"t","source":"s","type":"t","agent_id":"a"}`, ErrMissingSchema},
		{"missing ts", `{"schema":"` + SchemaV02 + `","source":"s","type":"t","agent_id":"a"}`, ErrMissingTS},
		{"missing source", `{"schema":"` + SchemaV02 + `","ts":"t","type":"t","agent_id":"a"}`, ErrMissingSource},
		{"missing type", `{"schema":"` + SchemaV02 + `","ts":"t","source":"s","agent_id":"a"}`, ErrMissingType},
		{"missing agent_id", `{"schema":"` + SchemaV02 + `","ts":"t","source":"s","type":"t"}`, ErrMissingAgentID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(c.data))
			if !errors.Is(err, c.wantErr) {
				t.Errorf("Unmarshal error = %v, want wrapping %v", err, c.wantErr)
			}
		})
	}
}

// TestUnmarshalAcceptsV01Schema pins the v0.1/v0.2 compatibility rule:
// consumers MUST accept either schema string, so Unmarshal only checks that
// schema is non-empty, never that it equals SchemaV02 specifically.
func TestUnmarshalAcceptsV01Schema(t *testing.T) {
	data := []byte(`{"schema":"` + SchemaV01 + `","ts":"t","source":"tokenfuse","type":"budget_exhausted","agent_id":"agent://acme.example/bot"}`)
	e, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Schema != SchemaV01 {
		t.Errorf("Schema = %q, want %q", e.Schema, SchemaV01)
	}
}

func TestWriterWritesNDJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i := range 3 {
		e := Event{
			Schema:  SchemaV02,
			TS:      "2026-07-09T00:00:00Z",
			Source:  "wardryx",
			Type:    "policy_allow",
			AgentID: "agent://acme.example/bot",
			RunID:   fmt.Sprintf("run-%d", i),
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3: %q", len(lines), lines)
	}
	for i, line := range lines {
		e, err := Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("Unmarshal(line %d): %v", i, err)
		}
		if e.RunID != fmt.Sprintf("run-%d", i) {
			t.Errorf("line %d: RunID = %q, want %q", i, e.RunID, fmt.Sprintf("run-%d", i))
		}
	}
}

// TestWriterConcurrentWrites exercises the mutex guard under -race: many
// goroutines write through the same Writer, and the file must end up with
// exactly one well-formed line per write, never a torn/interleaved line.
func TestWriterConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			e := Event{
				Schema:  SchemaV02,
				TS:      "2026-07-09T00:00:00Z",
				Source:  "wardryx",
				Type:    "policy_allow",
				AgentID: "agent://acme.example/bot",
				RunID:   fmt.Sprintf("run-%d", i),
			}
			if err := w.Write(e); err != nil {
				t.Errorf("Write(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("lines = %d, want %d (a torn write would change this count)", len(lines), n)
	}
	seen := make(map[string]bool, n)
	for _, line := range lines {
		e, err := Unmarshal([]byte(line))
		if err != nil {
			t.Fatalf("Unmarshal(%q): %v", line, err)
		}
		if seen[e.RunID] {
			t.Errorf("duplicate run_id %q (interleaved/corrupted write?)", e.RunID)
		}
		seen[e.RunID] = true
	}
	if len(seen) != n {
		t.Errorf("distinct run_ids = %d, want %d", len(seen), n)
	}
}

func TestNewWriterBadPath(t *testing.T) {
	_, err := NewWriter(filepath.Join(t.TempDir(), "nonexistent-dir", "events.ndjson"))
	if err == nil {
		t.Fatal("NewWriter: expected an error for a missing parent directory")
	}
}

func TestScanSkipsMalformedLines(t *testing.T) {
	input := strings.Join([]string{
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:00Z","source":"wardryx","type":"policy_allow","agent_id":"agent://acme.example/bot"}`,
		``, // blank line: skipped silently, not counted in Lines
		`not json`,
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:01Z","source":"wardryx","type":"policy_deny"}`, // missing agent_id
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:02Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot"}`,
	}, "\n")

	var got []Event
	res, err := Scan(strings.NewReader(input), func(e Event) error {
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Lines != 4 {
		t.Errorf("Lines = %d, want 4 (blank line not counted)", res.Lines)
	}
	if res.Malformed != 2 {
		t.Errorf("Malformed = %d, want 2", res.Malformed)
	}
	if len(got) != 2 {
		t.Fatalf("decoded events = %d, want 2", len(got))
	}
	if got[0].TS != "2026-07-09T00:00:00Z" || got[1].TS != "2026-07-09T00:00:02Z" {
		t.Errorf("unexpected events: %+v", got)
	}
}

func TestScanCallbackErrorStopsScan(t *testing.T) {
	input := strings.Join([]string{
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:00Z","source":"wardryx","type":"policy_allow","agent_id":"agent://acme.example/bot"}`,
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:01Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot"}`,
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:02Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot"}`,
	}, "\n")

	sentinel := errors.New("stop here")
	var got []Event
	_, err := Scan(strings.NewReader(input), func(e Event) error {
		got = append(got, e)
		if len(got) == 2 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Scan error = %v, want wrapping %v", err, sentinel)
	}
	if len(got) != 2 {
		t.Errorf("callback invocations = %d, want 2 (scan should stop after the error)", len(got))
	}
}

func TestReadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	content := strings.Join([]string{
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:00Z","source":"wardryx","type":"policy_allow","agent_id":"agent://acme.example/bot"}`,
		`not json`,
		`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T00:00:01Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	events, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
}

func TestReadFileMissing(t *testing.T) {
	if _, err := ReadFile(filepath.Join(t.TempDir(), "does-not-exist.ndjson")); err == nil {
		t.Fatal("ReadFile: expected an error for a missing file")
	}
}
