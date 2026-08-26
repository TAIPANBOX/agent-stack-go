package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

// A member SPEC 5.2 puts beside `data` rather than inside it, which is the
// whole point of the shape: `data` is the producer's free-form room and a
// delegation proof is not free-form. It is also, for that reason, exactly the
// kind of member this package's Event struct does not model.
const proofLine = `{"agent_id":"agent://acme.example/support/tier1-bot",` +
	`"delegation_proof":{"exp":1786000000,"iss":"https://idryx.acme.example",` +
	`"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs","jti":"tok-9"},` +
	`"schema":"taipanbox.dev/agent-event/v0.3","source":"vouchryx",` +
	`"ts":"2026-08-26T09:00:00Z","type":"delegation_issued"}`

// specHash computes SPEC 6.5 from its own words, deliberately without going
// through anything in chain.go: "the RFC 8785 canonical serialization of the
// EVENT OBJECT with the prev_hash field itself removed". A test that computed
// the expected value with the code under test would agree with that code no
// matter what either of them did.
func specHash(t *testing.T, line string) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		t.Fatalf("fixture is not an object: %v", err)
	}
	delete(obj, "prev_hash")
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		t.Fatalf("jcs: %v", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The defect this file exists for. A producer that emits a member the spec
// registers and this struct does not model computes its chain over the whole
// object, because that is what 6.5 says. This package hashed a re-marshal of
// its own struct, so the member vanished before the digest and an honest
// stream was reported as a broken chain: an accusation of tampering, made by
// our own conformance tool, against a producer doing exactly as told.
func TestAChainedStreamSurvivesAMemberThisStructDoesNotModel(t *testing.T) {
	want := specHash(t, proofLine)

	second := `{"agent_id":"agent://acme.example/support/tier1-bot",` +
		`"prev_hash":"` + want + `",` +
		`"schema":"taipanbox.dev/agent-event/v0.3","source":"vouchryx",` +
		`"ts":"2026-08-26T09:00:01Z","type":"delegation_used"}`

	report, err := VerifyChain(strings.NewReader(proofLine + "\n" + second + "\n"))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(report.Breaks) != 0 {
		t.Fatalf("an honestly chained stream was called broken: %+v\n"+
			"the second line carries prev_hash %s, which is SPEC 6.5 over the "+
			"first line as written", report.Breaks, want)
	}
	if report.Chained != 1 {
		t.Fatalf("Chained = %d, want 1 (report: %+v)", report.Chained, report)
	}
}

// The same loss on the WRITE side, and worse there. Resuming a chain reads the
// last line back; if the resumed hash is computed over a lossy re-parse, the
// next event links to a value no other implementation computes, and the chain
// forks silently on disk rather than being reported.
func TestResumingAChainHashesTheLineOnDiskAsWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	if err := os.WriteFile(path, []byte(proofLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	defer cw.Close()

	want := specHash(t, proofLine)
	if got := cw.ResumedFrom(); got != want {
		t.Fatalf("resumed from %s, want %s\nthe writer read a line it could not "+
			"fully model and hashed what it understood rather than what was there",
			got, want)
	}

	if err := cw.Write(Event{
		Schema: "taipanbox.dev/agent-event/v0.3", TS: "2026-08-26T09:00:01Z",
		Source: "vouchryx", Type: "delegation_used",
		AgentID: "agent://acme.example/support/tier1-bot",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := VerifyChain(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(report.Breaks) != 0 || report.Chained != 1 {
		t.Fatalf("the writer forked the chain it appended to: %+v", report)
	}
}
