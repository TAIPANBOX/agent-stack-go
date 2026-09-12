package main

import (
	"fmt"
	"testing"
)

// agent-passport SPEC 6.4.1: the 1.0 shapes, end to end through the embedded
// schemas. A conformance checker validates every version it carries; judging
// what a claimed subject means is a consumer's job, not this tool's.

func TestCheckFileValidPassportV10(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v1.0","id":"agent://acme.example/support/bot","owner":"team-x"}`)
	if !checkFile(s, path, false) {
		t.Error("a valid v1.0 Passport document must conform")
	}
}

func TestCheckFileV10PassportRefusesAKeyTheSchemaNeverNamed(t *testing.T) {
	s := mustLoadSchemas(t)
	raw := []byte(`{"schema":"taipanbox.dev/agent-passport/v1.0","id":"agent://acme.example/support/bot","owner":"team-x","agent_id":"agent://acme.example/support/bot"}`)
	if checkRecord(s.passportV10, raw, "v1.0 with agent_id") {
		t.Error("v1.0 closes its top level: agent_id written where the field is id must not validate")
	}
	path := writeFile(t, "p.json", string(raw))
	if checkFile(s, path, false) {
		t.Error("and checkFile must pick the v1.0 schema for a v1.0 document, so the same file fails there too")
	}
}

func TestCheckFileV01PassportToleratesTheSameKey(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/support/bot","owner":"team-x","agent_id":"agent://acme.example/support/bot"}`)
	if !checkFile(s, path, false) {
		t.Error("v0.1 keeps its hole by decision (SPEC 6.4.1); the same key must still validate there")
	}
}

func TestCheckFileUnrecognizedPassportSchemaFails(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v2.0","id":"agent://acme.example/support/bot","owner":"team-x"}`)
	if checkFile(s, path, false) {
		t.Error("a Passport stamped with a version this tool does not carry must fail, not fall back to another version")
	}
}

func TestCheckFileValidEventStreamV10(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", validEventLine("taipanbox.dev/agent-event/v1.0")+"\n")
	if !checkFile(s, path, false) {
		t.Error("a valid v1.0 event line must conform")
	}
}

func TestCheckFileClaimedSubjectConformsUnderV10(t *testing.T) {
	s := mustLoadSchemas(t)
	claimed := `{"schema":"%s","ts":"2026-09-12T00:00:00.000Z","source":"idryx",` +
		`"type":"identity_finding","agent_id":"claimed:agent://acme.example/support/tier1-bot",` +
		`"severity":"high","data":{"detector":"unmanaged_egress"}}`
	path := writeFile(t, "claimed-v10.ndjson", fmt.Sprintf(claimed, "taipanbox.dev/agent-event/v1.0")+"\n")
	if !checkFile(s, path, false) {
		t.Error("v1.0 is v0.3's shape, so a claimed subject conforms under it")
	}
}
