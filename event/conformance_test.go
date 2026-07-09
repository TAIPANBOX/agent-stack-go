package event

import (
	"bytes"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// This file is the single-source-of-truth guard described in the wave-2
// architecture note: the canonical wire contract lives in the JSON Schema
// (testdata/agent-event.v0.2.schema.json, a local copy of
// TAIPANBOX/agent-passport's schemas/agent-event.v0.2.schema.json), and this
// package's Event struct is just a Go binding of it. If the two ever drift
// apart, this test is what catches it. github.com/santhosh-tekuri/jsonschema/v6
// is a test-only dependency: nothing in event.go imports it.

// loadV02Schema compiles the embedded copy of the canonical v0.2 schema
// from testdata. Compiling reads only the local file: the schema has no
// $ref, so its $id (an https:// URL) is never dereferenced over the
// network, and its $schema meta-schema (2020-12) ships embedded in the
// jsonschema module itself.
func loadV02Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("testdata/agent-event.v0.2.schema.json")
	if err != nil {
		t.Fatalf("compile testdata/agent-event.v0.2.schema.json: %v", err)
	}
	return sch
}

// TestConformanceV02 builds a golden Event (source wardryx, type
// policy_deny, a valid agent_id, severity high), marshals it with this
// package's own Marshal, and validates the JSON against the canonical
// schema.
func TestConformanceV02(t *testing.T) {
	golden := Event{
		Schema:   SchemaV02,
		TS:       "2026-07-09T03:12:44.100Z",
		Source:   "wardryx",
		Type:     "policy_deny",
		AgentID:  "agent://acme-bank.example/support/tier1-bot",
		Severity: SeverityHigh,
		RunID:    "run-8842",
		OnBehalfOf: []string{
			"user://acme-bank.example/j.doe",
		},
		Data: map[string]any{
			"tool":   "shell.exec",
			"policy": "no-shell-in-prod",
		},
	}

	data, err := Marshal(golden)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if err := loadV02Schema(t).Validate(inst); err != nil {
		t.Errorf("golden event does not conform to the v0.2 schema: %v\nevent json: %s", err, data)
	}
}

// TestConformanceV02RejectsMissingAgentID makes sure the schema itself, not
// just this package's Unmarshal, enforces the required-field rule, so the
// conformance guard is meaningful in both directions: a Go-side relaxation
// of Unmarshal would still be caught here.
func TestConformanceV02RejectsMissingAgentID(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"wardryx","type":"policy_deny"}`)

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if err := loadV02Schema(t).Validate(inst); err == nil {
		t.Error("expected the schema to reject an envelope missing agent_id, got nil")
	}
}

// TestConformanceV02RejectsInvalidAgentID pins the agent_id pattern/maxLength
// constraint the passport package's ValidateAgentURI mirrors: the two must
// never silently diverge.
func TestConformanceV02RejectsInvalidAgentID(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"wardryx","type":"policy_deny","agent_id":"not-a-valid-agent-uri"}`)

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if err := loadV02Schema(t).Validate(inst); err == nil {
		t.Error("expected the schema to reject a malformed agent_id, got nil")
	}
}

// TestConformanceV02RejectsBadSeverity pins the severity enum.
func TestConformanceV02RejectsBadSeverity(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot","severity":"catastrophic"}`)

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if err := loadV02Schema(t).Validate(inst); err == nil {
		t.Error("expected the schema to reject an out-of-enum severity, got nil")
	}
}
