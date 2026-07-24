package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

func mustLoadSchemas(t *testing.T) *compiledSchemas {
	t.Helper()
	s, err := loadSchemas()
	if err != nil {
		t.Fatalf("loadSchemas: %v", err)
	}
	return s
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func realSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ------------------------------------------------------------------
// loadSchemas: the embedded schemas must actually compile, exercising the
// embed directive, AddResource, and Compile for real, not against a mock.
// ------------------------------------------------------------------

func TestLoadSchemasCompiles(t *testing.T) {
	s := mustLoadSchemas(t)
	if s.passport == nil || s.eventV01 == nil || s.eventV02 == nil {
		t.Fatalf("loadSchemas returned a nil schema: %+v", s)
	}
}

// ------------------------------------------------------------------
// passportSchemaName: the passport-vs-event classification
// ------------------------------------------------------------------

func TestPassportSchemaName(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"v0.1 passport", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://x.example/a"}`, "taipanbox.dev/agent-passport/v0.1", true},
		{"event v0.1, not a passport", `{"schema":"taipanbox.dev/agent-event/v0.1"}`, "", false},
		{"event v0.2, not a passport", `{"schema":"taipanbox.dev/agent-event/v0.2"}`, "", false},
		{"no schema field", `{"id":"agent://x.example/a"}`, "", false},
		{"not json", `not json`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := passportSchemaName([]byte(tc.raw))
			if ok != tc.ok || got != tc.want {
				t.Errorf("passportSchemaName(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// ------------------------------------------------------------------
// checkFile: passport documents
// ------------------------------------------------------------------

func TestCheckFileValidPassport(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/support/bot","owner":"team-x"}`)
	if !checkFile(s, path, false) {
		t.Error("expected a valid Passport document to conform")
	}
}

func TestCheckFileInvalidPassportBadAgentID(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"not-a-valid-uri","owner":"team-x"}`)
	if checkFile(s, path, false) {
		t.Error("expected a Passport document with a malformed id to fail conformance")
	}
}

func TestCheckFileInvalidPassportMissingRequiredField(t *testing.T) {
	s := mustLoadSchemas(t)
	// owner is required per agent-passport.schema.json §4.
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot"}`)
	if checkFile(s, path, false) {
		t.Error("expected a Passport document missing owner to fail conformance")
	}
}

// ------------------------------------------------------------------
// checkFile: event streams
// ------------------------------------------------------------------

func validEventLine(schema string) string {
	return `{"schema":"` + schema + `","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","severity":"high"}`
}

func TestCheckFileValidEventStreamV01(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", validEventLine("taipanbox.dev/agent-event/v0.1")+"\n")
	if !checkFile(s, path, false) {
		t.Error("expected a valid v0.1 event line to conform")
	}
}

func TestCheckFileValidEventStreamV02(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", validEventLine("taipanbox.dev/agent-event/v0.2")+"\n")
	if !checkFile(s, path, false) {
		t.Error("expected a valid v0.2 event line to conform")
	}
}

func TestCheckFileValidEventWithRealPrevHash(t *testing.T) {
	s := mustLoadSchemas(t)
	line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","prev_hash":"` + realSHA256("prev-event") + `"}`
	path := writeFile(t, "e.ndjson", line+"\n")
	if !checkFile(s, path, false) {
		t.Error("expected an event with a well-formed 64-hex-char prev_hash to conform")
	}
}

func TestCheckFileEventWithMalformedPrevHash(t *testing.T) {
	s := mustLoadSchemas(t)
	// 63 hex chars, one short of the required 64 -- the exact defect a
	// live run against real fixtures elsewhere in the stack surfaced.
	line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","prev_hash":"sha256:2e81d20e76391693864bc8b7c0963b6aa87ef867c36bc80a0678166dcfb316"}`
	path := writeFile(t, "e.ndjson", line+"\n")
	if checkFile(s, path, false) {
		t.Error("expected a 63-hex-char prev_hash to fail the exact-64 pattern")
	}
}

func TestCheckFileEventMultipleLinesAllValid(t *testing.T) {
	s := mustLoadSchemas(t)
	content := validEventLine("taipanbox.dev/agent-event/v0.1") + "\n" + validEventLine("taipanbox.dev/agent-event/v0.2") + "\n"
	path := writeFile(t, "e.ndjson", content)
	if !checkFile(s, path, false) {
		t.Error("expected two valid lines (v0.1 and v0.2) to both conform")
	}
}

func TestCheckFileEventOneBadLineFailsWholeFile(t *testing.T) {
	s := mustLoadSchemas(t)
	content := validEventLine("taipanbox.dev/agent-event/v0.1") + "\n" + `{"schema":"taipanbox.dev/agent-event/v0.1"}` + "\n" // missing required fields
	path := writeFile(t, "e.ndjson", content)
	if checkFile(s, path, false) {
		t.Error("expected one malformed line among otherwise-valid lines to fail the file")
	}
}

func TestCheckFileEventUnrecognizedSchema(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", `{"schema":"something-else/v9"}`+"\n")
	if checkFile(s, path, false) {
		t.Error("expected an unrecognized schema value to fail")
	}
}

func TestCheckFileBlankLinesSkippedNotCountedAsContent(t *testing.T) {
	s := mustLoadSchemas(t)
	content := "\n\n" + validEventLine("taipanbox.dev/agent-event/v0.1") + "\n\n"
	path := writeFile(t, "e.ndjson", content)
	if !checkFile(s, path, false) {
		t.Error("expected blank lines around one valid line to still conform")
	}
}

// ------------------------------------------------------------------
// checkFile: files that are neither a Passport document nor an event
// stream, or missing/empty
// ------------------------------------------------------------------

func TestCheckFileGarbageNotJSON(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "g.txt", "this is not json at all\n")
	if checkFile(s, path, false) {
		t.Error("expected a non-JSON file to fail")
	}
}

func TestCheckFileEmpty(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "empty.json", "")
	if checkFile(s, path, false) {
		t.Error("expected an empty file to fail")
	}
}

func TestCheckFileMissing(t *testing.T) {
	s := mustLoadSchemas(t)
	if checkFile(s, filepath.Join(t.TempDir(), "does-not-exist.json"), false) {
		t.Error("expected a missing file to fail")
	}
}

func TestCheckFileValidJSONButNeitherPassportNorEvent(t *testing.T) {
	s := mustLoadSchemas(t)
	// Valid JSON, no recognizable "schema" field at all.
	path := writeFile(t, "x.json", `{"hello":"world"}`+"\n")
	if checkFile(s, path, false) {
		t.Error("expected a JSON file with no recognized schema to fail")
	}
}

// ------------------------------------------------------------------
// -chain: the SPEC §6.5 prev_hash verification over event streams
// ------------------------------------------------------------------

func chainEvent(ts, typ string, data map[string]any) event.Event {
	return event.Event{
		Schema: event.SchemaV02, TS: ts, Source: "wardryx", Type: typ,
		AgentID: "agent://acme.example/support/tier1-bot", Severity: "info",
		Data: data,
	}
}

// chainLines marshals events as one NDJSON stream, threading prev_hash the
// way a ChainedWriter would.
func chainLines(t *testing.T, events ...event.Event) string {
	t.Helper()
	var b strings.Builder
	prev := ""
	for _, e := range events {
		e.PrevHash = prev
		data, err := event.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		b.Write(data)
		b.WriteByte('\n')
		h, err := event.ChainHash(e)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		prev = h
	}
	return b.String()
}

func TestChainPassesACleanStream(t *testing.T) {
	s := mustLoadSchemas(t)
	stream := chainLines(t,
		chainEvent("2026-07-24T12:00:00Z", "policy_allow", map[string]any{"policy": "p1"}),
		chainEvent("2026-07-24T12:00:01Z", "policy_deny", map[string]any{"policy": "p1"}),
		chainEvent("2026-07-24T12:00:02Z", "approval_requested", nil),
	)
	path := writeFile(t, "chained.ndjson", stream)
	if !checkFile(s, path, true) {
		t.Fatalf("a clean chained stream must pass -chain")
	}
}

func TestChainFailsOnATamperedLine(t *testing.T) {
	s := mustLoadSchemas(t)
	stream := chainLines(t,
		chainEvent("2026-07-24T12:00:00Z", "policy_allow", map[string]any{"policy": "p1"}),
		chainEvent("2026-07-24T12:00:01Z", "policy_deny", map[string]any{"policy": "p1"}),
	)
	// Tamper with line 1's payload after the chain was computed: line 2's
	// stored prev_hash no longer matches. Schema-wise the stream stays
	// valid, so only -chain catches this.
	tampered := strings.Replace(stream, `"policy":"p1"`, `"policy":"p2"`, 1)
	path := writeFile(t, "tampered.ndjson", tampered)
	if checkFile(s, path, true) {
		t.Fatalf("a tampered chained stream must fail -chain")
	}
	if !checkFile(s, path, false) {
		t.Fatalf("without -chain the same stream is schema-valid (the whole point)")
	}
}

func TestChainRestartIsNotAFailure(t *testing.T) {
	s := mustLoadSchemas(t)
	first := chainLines(t,
		chainEvent("2026-07-24T12:00:00Z", "policy_allow", nil),
		chainEvent("2026-07-24T12:00:01Z", "policy_deny", nil),
	)
	second := chainLines(t,
		chainEvent("2026-07-24T12:00:02Z", "approval_requested", nil),
	)
	path := writeFile(t, "restart.ndjson", first+second)
	if !checkFile(s, path, true) {
		t.Fatalf("a chain restart is legal per spec and must not fail -chain")
	}
}

func TestChainFlagLeavesPassportsAlone(t *testing.T) {
	s := mustLoadSchemas(t)
	passport := `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/support/tier1-bot","owner":"team-x@acme.example","attestation":{"method":"none"},"created_at":"2026-07-24T12:00:00Z"}`
	path := writeFile(t, "passport.json", passport)
	if checkFile(s, path, true) != checkFile(s, path, false) {
		t.Fatalf("-chain must not change a passport document's verdict")
	}
}
