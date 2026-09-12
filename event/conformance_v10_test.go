package event

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// An Event stamped v1.0, with a claimed subject, conforms to the vendored v1.0
// schema: v1.0 is v0.3's shape (SPEC 6.4.1), so the claimed form rides in it.
func TestEventWithAClaimedSubjectConformsToV10(t *testing.T) {
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("testdata/agent-event.v1.0.schema.json")
	if err != nil {
		t.Fatalf("compile the vendored v1.0 schema: %v", err)
	}
	e := Event{
		Schema:   SchemaV10,
		TS:       "2026-09-12T16:00:00.000Z",
		Source:   "idryx",
		Type:     "identity_finding",
		Severity: SeverityHigh,
		AgentID:  "claimed:agent://acme.example/support/tier1-bot",
		Data:     map[string]any{"detector": "unmanaged_egress"},
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("a v1.0 event with a claimed subject must conform: %v", err)
	}
}
