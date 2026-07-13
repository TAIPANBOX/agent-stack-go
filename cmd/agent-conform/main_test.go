package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
	if !checkFile(s, path) {
		t.Error("expected a valid Passport document to conform")
	}
}

func TestCheckFileInvalidPassportBadAgentID(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"not-a-valid-uri","owner":"team-x"}`)
	if checkFile(s, path) {
		t.Error("expected a Passport document with a malformed id to fail conformance")
	}
}

func TestCheckFileInvalidPassportMissingRequiredField(t *testing.T) {
	s := mustLoadSchemas(t)
	// owner is required per agent-passport.schema.json §4.
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot"}`)
	if checkFile(s, path) {
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
	if !checkFile(s, path) {
		t.Error("expected a valid v0.1 event line to conform")
	}
}

func TestCheckFileValidEventStreamV02(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", validEventLine("taipanbox.dev/agent-event/v0.2")+"\n")
	if !checkFile(s, path) {
		t.Error("expected a valid v0.2 event line to conform")
	}
}

func TestCheckFileValidEventWithRealPrevHash(t *testing.T) {
	s := mustLoadSchemas(t)
	line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","prev_hash":"` + realSHA256("prev-event") + `"}`
	path := writeFile(t, "e.ndjson", line+"\n")
	if !checkFile(s, path) {
		t.Error("expected an event with a well-formed 64-hex-char prev_hash to conform")
	}
}

func TestCheckFileEventWithMalformedPrevHash(t *testing.T) {
	s := mustLoadSchemas(t)
	// 63 hex chars, one short of the required 64 -- the exact defect a
	// live run against real fixtures elsewhere in the stack surfaced.
	line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","prev_hash":"sha256:2e81d20e76391693864bc8b7c0963b6aa87ef867c36bc80a0678166dcfb316"}`
	path := writeFile(t, "e.ndjson", line+"\n")
	if checkFile(s, path) {
		t.Error("expected a 63-hex-char prev_hash to fail the exact-64 pattern")
	}
}

func TestCheckFileEventMultipleLinesAllValid(t *testing.T) {
	s := mustLoadSchemas(t)
	content := validEventLine("taipanbox.dev/agent-event/v0.1") + "\n" + validEventLine("taipanbox.dev/agent-event/v0.2") + "\n"
	path := writeFile(t, "e.ndjson", content)
	if !checkFile(s, path) {
		t.Error("expected two valid lines (v0.1 and v0.2) to both conform")
	}
}

func TestCheckFileEventOneBadLineFailsWholeFile(t *testing.T) {
	s := mustLoadSchemas(t)
	content := validEventLine("taipanbox.dev/agent-event/v0.1") + "\n" + `{"schema":"taipanbox.dev/agent-event/v0.1"}` + "\n" // missing required fields
	path := writeFile(t, "e.ndjson", content)
	if checkFile(s, path) {
		t.Error("expected one malformed line among otherwise-valid lines to fail the file")
	}
}

func TestCheckFileEventUnrecognizedSchema(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", `{"schema":"something-else/v9"}`+"\n")
	if checkFile(s, path) {
		t.Error("expected an unrecognized schema value to fail")
	}
}

func TestCheckFileBlankLinesSkippedNotCountedAsContent(t *testing.T) {
	s := mustLoadSchemas(t)
	content := "\n\n" + validEventLine("taipanbox.dev/agent-event/v0.1") + "\n\n"
	path := writeFile(t, "e.ndjson", content)
	if !checkFile(s, path) {
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
	if checkFile(s, path) {
		t.Error("expected a non-JSON file to fail")
	}
}

func TestCheckFileEmpty(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "empty.json", "")
	if checkFile(s, path) {
		t.Error("expected an empty file to fail")
	}
}

func TestCheckFileMissing(t *testing.T) {
	s := mustLoadSchemas(t)
	if checkFile(s, filepath.Join(t.TempDir(), "does-not-exist.json")) {
		t.Error("expected a missing file to fail")
	}
}

func TestCheckFileValidJSONButNeitherPassportNorEvent(t *testing.T) {
	s := mustLoadSchemas(t)
	// Valid JSON, no recognizable "schema" field at all.
	path := writeFile(t, "x.json", `{"hello":"world"}`+"\n")
	if checkFile(s, path) {
		t.Error("expected a JSON file with no recognized schema to fail")
	}
}
