package passport

import (
	"errors"
	"strings"
	"testing"
)

// The 1.0 contract: agent-passport SPEC 6.4.1. A consumer MUST accept v0.1 and
// v1.0; under v1.0 a key the schema never named does not validate; under v0.1
// the same key is tolerated, by decision.

func TestParseAcceptsAV10Passport(t *testing.T) {
	p, err := Parse([]byte(`{"schema":"taipanbox.dev/agent-passport/v1.0","id":"agent://acme.example/support/bot","owner":"team-x"}`))
	if err != nil {
		t.Fatalf("a v1.0 passport must parse: %v", err)
	}
	if p.Schema != SchemaV10 {
		t.Fatalf("schema round-tripped as %q, want %q", p.Schema, SchemaV10)
	}
}

func TestParseStillAcceptsAV01Passport(t *testing.T) {
	p, err := Parse([]byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/support/bot","owner":"team-x"}`))
	if err != nil {
		t.Fatalf("a v0.1 passport must keep parsing after 1.0: %v", err)
	}
	if p.Schema != SchemaV01 || RequiredSchema != SchemaV01 {
		t.Fatalf("v0.1 is SchemaV01 and RequiredSchema keeps naming it; got %q", p.Schema)
	}
}

func TestParseRefusesAV10PassportWithAKeyTheSchemaNeverNamed(t *testing.T) {
	_, err := Parse([]byte(`{"schema":"taipanbox.dev/agent-passport/v1.0","id":"agent://acme.example/support/bot","owner":"team-x","agent_id":"agent://acme.example/support/bot"}`))
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("a v1.0 passport carrying agent_id must be refused with ErrUnknownField, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent_id") {
		t.Fatalf("the refusal must name the key, got %v", err)
	}
}

func TestParseToleratesTheSameKeyUnderV01(t *testing.T) {
	if _, err := Parse([]byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/support/bot","owner":"team-x","agent_id":"agent://acme.example/support/bot"}`)); err != nil {
		t.Fatalf("v0.1 keeps its hole by decision (SPEC 6.4.1); got %v", err)
	}
}

func TestParseRefusesAnyOtherSchemaString(t *testing.T) {
	_, err := Parse([]byte(`{"schema":"taipanbox.dev/agent-passport/v2.0","id":"agent://acme.example/support/bot","owner":"team-x"}`))
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("a version this package does not carry must be ErrUnsupportedSchema, got %v", err)
	}
}

func TestAcceptedSchemasNameBothVersionsInOrder(t *testing.T) {
	got := AcceptedSchemas()
	if len(got) != 2 || got[0] != SchemaV01 || got[1] != SchemaV10 {
		t.Fatalf("AcceptedSchemas() = %v, want [v0.1 v1.0]", got)
	}
}
