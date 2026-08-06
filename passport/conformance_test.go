package passport

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The same single-source-of-truth guard event/conformance_test.go has carried
// since wave 2, for the other half of the contract. The canonical wire format
// lives in the JSON Schema (testdata/schema/agent-passport.schema.json, a copy of
// TAIPANBOX/agent-passport's schemas/agent-passport.schema.json, held to it by
// scripts/schemas-in-sync.sh), and this package's Passport struct is a Go
// binding of it. Without this file the README's claim that both packages are
// "checked by a schema conformance test" was true of one of them.
//
// github.com/santhosh-tekuri/jsonschema/v6 is a test-only dependency here:
// nothing in passport.go or load.go imports it, which scripts/deps-layering.sh
// enforces by reading non-test imports only (CLAUDE.md invariant 1).
//
// The copy sits one level down, in testdata/schema/, and not beside event's
// because passport/testdata/ is not a loose bag of fixtures: LoadDir globs
// testdata/*.json and load_test.go asserts the exact count it finds, 4 files of
// which 2 are malformed. Dropping a schema in there turns a passing test into
// "Malformed = 3, want 2", which is a true statement about a set that stopped
// meaning what it meant. Measured, not guessed: that is what it printed.

// loadPassportSchema compiles the local copy of the canonical Passport schema.
// Compiling reads only that file: it has no $ref, so its $id (an https:// URL)
// is never dereferenced over the network, and the 2020-12 meta-schema ships
// inside the jsonschema module.
func loadPassportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("testdata/schema/agent-passport.schema.json")
	if err != nil {
		t.Fatalf("compile testdata/schema/agent-passport.schema.json: %v", err)
	}
	return sch
}

// goldenPassport populates EVERY field the struct has. A conformance test on a
// minimal document only proves the required fields work, and the fields that
// drift are the optional ones nobody looks at.
func goldenPassport() Passport {
	return Passport{
		Schema:      RequiredSchema,
		ID:          "agent://acme-bank.example/support/tier1-bot",
		Owner:       "user://acme-bank.example/support-team",
		DisplayName: "Tier-1 support bot",
		Runtime:     "langgraph",
		Parent:      "agent://acme-bank.example/support/orchestrator",
		Attestation: &Attestation{
			Method: "spiffe-svid",
			Detail: "spiffe://acme-bank.example/agent/support/tier1-bot",
		},
		Filesystem: []FsScope{
			{Path: "/data/reports", Mode: "read"},
			{Path: "/data/out", Mode: "write"},
		},
		Models: []Model{
			{Provider: "anthropic", Model: "claude-sonnet-4-5", Endpoint: "api.anthropic.com"},
			{Provider: "openai"},
		},
		Labels:    map[string]string{"env": "prod", "cost_center": "cs-eu", "version": "2.4.1"},
		CreatedAt: "2026-08-05T00:00:00Z",
	}
}

func validate(t *testing.T, data []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	return loadPassportSchema(t).Validate(inst)
}

// TestPassportConformance marshals what this package's own struct produces and
// validates it against the canonical schema, so a Go-side change that the
// schema forbids fails here rather than in a consumer.
func TestPassportConformance(t *testing.T) {
	data, err := json.Marshal(goldenPassport())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := validate(t, data); err != nil {
		t.Errorf("the golden passport does not conform to the canonical schema: %v\npassport json: %s", err, data)
	}
}

// TestPassportConformanceRoundTrip closes the loop the other way: a document
// this package PARSED, re-marshaled, still conforms. Parse drops nothing it
// cannot represent, so anything it silently discarded would show up here as a
// document that no longer matches what went in.
func TestPassportConformanceRoundTrip(t *testing.T) {
	in, err := json.Marshal(goldenPassport())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	p, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal after Parse: %v", err)
	}
	if err := validate(t, out); err != nil {
		t.Errorf("a parsed and re-marshaled passport stopped conforming: %v\n%s", err, out)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("Parse lost or reordered a field:\n in: %s\nout: %s", in, out)
	}
}

// TestPassportStructAndSchemaDeclareTheSameFields is the part plain validation
// cannot do. A Passport allows additionalProperties, so a mistyped json tag
// produces a key the schema simply ignores and a field that quietly vanishes:
// `filesystem` becoming `file_system` would validate perfectly and declare
// nothing. This compares the two lists of names in both directions, which is
// the only way that shows up.
//
// The direction that fails first in practice is the second one: agent-passport
// adds a property, the schema copy is synced, and the struct has no field for
// it. That is the drift this module exists to prevent, one level up from the
// schema copies themselves.
func TestPassportStructAndSchemaDeclareTheSameFields(t *testing.T) {
	data, err := json.Marshal(goldenPassport())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var produced map[string]json.RawMessage
	if err := json.Unmarshal(data, &produced); err != nil {
		t.Fatalf("Unmarshal the golden passport: %v", err)
	}

	raw, err := os.ReadFile("testdata/schema/agent-passport.schema.json")
	if err != nil {
		t.Fatalf("read the schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse the schema: %v", err)
	}
	if len(schema.Properties) == 0 {
		t.Fatal("the schema declares no properties at all, so this test compared nothing")
	}

	for key := range produced {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("the struct emits %q, which the canonical schema does not declare: a typo in a json tag looks exactly like this, since additionalProperties is true and nothing rejects it", key)
		}
	}
	for key := range schema.Properties {
		if _, ok := produced[key]; !ok {
			t.Errorf("the canonical schema declares %q and the struct has no field that emits it: the spec moved and this binding did not", key)
		}
	}
}

// The negative cases below check the SCHEMA, not the struct, so the guard is
// meaningful in both directions: a Go-side relaxation of Parse would still be
// caught here. They mirror event/conformance_test.go's shape.

func TestPassportConformanceRejectsMissingOwner(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot"}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject a passport missing owner, got nil")
	}
}

// TestPassportConformanceRejectsInvalidAgentID pins the id pattern the
// package's own ValidateAgentURI mirrors: the two must never silently diverge.
func TestPassportConformanceRejectsInvalidAgentID(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"not-a-valid-agent-uri","owner":"team-x"}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject a malformed agent id, got nil")
	}
}

func TestPassportConformanceRejectsBadAttestationMethod(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":"team-x","attestation":{"method":"vibes"}}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject an out-of-enum attestation method, got nil")
	}
}

// TestPassportConformanceRejectsBadFilesystemMode and the two that follow are
// the SPEC 4.4 and 4.5 rules at the library level. They are the same rules
// cmd/agent-conform enforces on somebody else's file, checked here against the
// schema this package's own types are bound to, so the tool and the library
// cannot end up disagreeing about what a valid declaration is.
func TestPassportConformanceRejectsBadFilesystemMode(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":"team-x","filesystem":[{"path":"/data","mode":"delete"}]}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject a filesystem mode outside read|write, got nil")
	}
}

func TestPassportConformanceRejectsFilesystemEntryMissingPath(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":"team-x","filesystem":[{"mode":"read"}]}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject a filesystem entry with no path, got nil")
	}
}

func TestPassportConformanceRejectsModelMissingProvider(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":"team-x","models":[{"model":"claude-sonnet-4-5"}]}`)
	if err := validate(t, data); err == nil {
		t.Error("expected the schema to reject a models entry with no provider, got nil")
	}
}
