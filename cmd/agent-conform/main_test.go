package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	if s.passport == nil || s.eventV01 == nil || s.eventV02 == nil || s.eventV03 == nil {
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

// The SPEC 4.4 filesystem and SPEC 4.5 models declarations are the auditable
// declared side of the declared-versus-coded-versus-observed comparison, so a
// malformed entry in either is exactly what somebody runs this tool to find.
// additionalProperties is true on a Passport document, which means a schema
// that does not DECLARE these two fields does not merely check them loosely:
// it does not look at them at all, and reports OK.

func TestCheckFilePassportValidFilesystemAndModels(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","filesystem":[{"path":"/data/reports","mode":"read"},{"path":"/data/out","mode":"write"}],"models":[{"provider":"anthropic","model":"claude-sonnet-4-5","endpoint":"api.anthropic.com"},{"provider":"openai"}]}`)
	if !checkFile(s, path, false) {
		t.Error("expected a Passport declaring well-formed filesystem and models entries to conform")
	}
}

func TestCheckFilePassportMalformedFilesystemMode(t *testing.T) {
	s := mustLoadSchemas(t)
	// mode is an enum of read|write per SPEC 4.4. "delete" is not a mode, and
	// a passport claiming one is a declaration nobody can audit.
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","filesystem":[{"path":"/data/out","mode":"delete"}]}`)
	if checkFile(s, path, false) {
		t.Error("expected a filesystem entry with mode \"delete\" to fail the SPEC 4.4 read|write enum")
	}
}

func TestCheckFilePassportFilesystemEntryMissingPath(t *testing.T) {
	s := mustLoadSchemas(t)
	// path and mode are both required per SPEC 4.4.
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","filesystem":[{"mode":"read"}]}`)
	if checkFile(s, path, false) {
		t.Error("expected a filesystem entry with no path to fail the SPEC 4.4 required-field rule")
	}
}

func TestCheckFilePassportModelMissingProvider(t *testing.T) {
	s := mustLoadSchemas(t)
	// provider is the one required key of a models entry per SPEC 4.5: an
	// endpoint with no provider names nothing an inventory can compare against.
	path := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","models":[{"model":"claude-sonnet-4-5","endpoint":"api.anthropic.com"}]}`)
	if checkFile(s, path, false) {
		t.Error("expected a models entry with no provider to fail the SPEC 4.5 required-field rule")
	}
}

// dpop-key joined the SPEC 4.3 attestation enum in agent-passport, and this
// tool reads the enum out of the vendored schema rather than from a list of
// its own. That makes the test worth having in both directions: a passport
// attested by a DPoP key must conform, and "vibes" must still not, or the
// first half would pass just as well against a schema that had stopped
// constraining the field at all.
func TestCheckFilePassportDpopKeyAttestationConforms(t *testing.T) {
	s := mustLoadSchemas(t)
	ok := writeFile(t, "p.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","attestation":{"method":"dpop-key","detail":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}`)
	if !checkFile(s, ok, false) {
		t.Error("expected an attestation method of dpop-key to conform: SPEC 4.3 lists it")
	}

	bad := writeFile(t, "p-bad.json", `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/data/etl","owner":"team-data@acme.example","attestation":{"method":"vibes"}}`)
	if checkFile(s, bad, false) {
		t.Error("the enum accepted a method it does not list, so the half above proves nothing")
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

// Invariant 9, third version. v0.3 exists so an observer can report a subject a
// PROCESS asserted about itself (SPEC 3.3), and this tool is a conformance
// checker rather than a consumer: it validates the line and does not judge what
// a claim means. A consumer MAY refuse v0.3; refusing HERE would make an honest
// journal fail its whole file under invariant 10.
func TestCheckFileValidEventStreamV03(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "e.ndjson", validEventLine("taipanbox.dev/agent-event/v0.3")+"\n")
	if !checkFile(s, path, false) {
		t.Error("expected a valid v0.3 event line to conform")
	}
}

// The subject form v0.3 exists for, end to end through the real schema. A
// claimed subject is longer than an established one by the eight bytes of the
// marker, which is why v0.3 raises maxLength as well as widening the pattern:
// getting one without the other would refuse the longest real identities.
func TestCheckFileClaimedSubjectConformsOnlyUnderV03(t *testing.T) {
	s := mustLoadSchemas(t)
	claimed := `{"schema":"%s","ts":"2026-07-13T00:00:00.000Z","source":"idryx",` +
		`"type":"identity_finding","agent_id":"claimed:agent://acme.example/support/tier1-bot",` +
		`"severity":"high","data":{"detector":"unrouted_egress"}}`

	ok := writeFile(t, "claimed-v03.ndjson", fmt.Sprintf(claimed, "taipanbox.dev/agent-event/v0.3")+"\n")
	if !checkFile(s, ok, false) {
		t.Error("a claimed subject must conform under v0.3, which is the version that exists for it")
	}

	// And it must NOT pass as v0.2. The version stamp is how a reader knows a
	// claim is possible at all, so a producer that stamped the old version
	// would hand every consumer a self-declaration under the contract that
	// says this field holds an established identity.
	bad := writeFile(t, "claimed-v02.ndjson", fmt.Sprintf(claimed, "taipanbox.dev/agent-event/v0.2")+"\n")
	if checkFile(s, bad, false) {
		t.Error("a claimed subject stamped v0.2 conformed; v0.2's agent_id is an established identity and nothing else")
	}
}

// delegation_proof (SPEC 5.2) is the reason a re-vendor of these schemas is
// more than a file copy, and the shape of it is invariant 13's own story.
// The envelope sets additionalProperties true, so an undeclared field is not
// checked loosely, it is not looked at at all: before the schema carried this
// object, every one of the three lines below was accepted, the malformed ones
// included. Declaring it is what turned reading into checking.
//
// Absent stays valid. The field is optional and its absence means the chain
// was NOT proved, which is a legal thing for an event to say.
func TestCheckFileEventDelegationProofIsCheckedNotWavedThrough(t *testing.T) {
	s := mustLoadSchemas(t)
	const (
		base  = `{"schema":"%s","ts":"2026-07-13T00:00:00.000Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/bot","on_behalf_of":["user://acme.example/j.doe"]%s}`
		whole = `,"delegation_proof":{"jti":"01J8Z3","jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs","iss":"https://tokens.acme.example","exp":1786000000}`
	)

	for _, version := range []string{"taipanbox.dev/agent-event/v0.2", "taipanbox.dev/agent-event/v0.3"} {
		cases := []struct {
			name  string
			tail  string
			want  bool
			wrong string
		}{
			{"complete", whole, true,
				"a complete delegation_proof was refused"},
			{"absent", "", true,
				"an event with no delegation_proof was refused, and absent means not proven, which is legal"},
			{"missing jkt", `,"delegation_proof":{"jti":"01J8Z3","iss":"https://tokens.acme.example","exp":1786000000}`, false,
				"a delegation_proof with no jkt conformed: without the thumbprint the proof does not say who held the token"},
			{"exp as a string", `,"delegation_proof":{"jti":"01J8Z3","jkt":"NzbL","iss":"https://tokens.acme.example","exp":"1786000000"}`, false,
				"a delegation_proof whose exp is a string conformed"},
			{"an extra key", whole[:len(whole)-1] + `,"token":"eyJhbGciOi.."}`, false,
				"a delegation_proof carrying an extra key conformed: additionalProperties is false there precisely so a live credential cannot ride along in a replicated record"},
		}
		for _, c := range cases {
			t.Run(version+"/"+c.name, func(t *testing.T) {
				path := writeFile(t, "e.ndjson", fmt.Sprintf(base, version, c.tail)+"\n")
				if got := checkFile(s, path, false); got != c.want {
					t.Errorf("%s (conformed=%v, want %v)", c.wrong, got, c.want)
				}
			})
		}
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

// ------------------------------------------------------------------
// -chain: the SPEC §5.1 delegation chain carried in on_behalf_of
//
// A separate rule from the prev_hash chain above, and a separate kind of
// failure. The hash chain says the file has not been altered; the delegation
// chain says who an agent was acting for. The event schema constrains only the
// SHAPE of an on_behalf_of entry (an agent:// or user:// URI), with no cap and
// no uniqueness, so every case below is schema-valid and only -chain can
// catch it.
// ------------------------------------------------------------------

// captureStdout runs f with os.Stdout redirected and returns what it printed.
// The two failure kinds have to be distinguishable by somebody reading the
// output, which is a claim about the text, so the text is what is asserted.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	f()
	os.Stdout = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

// delegatedEvent is one chained-stream event carrying a delegation chain.
func delegatedEvent(ts string, onBehalfOf []string) event.Event {
	e := chainEvent(ts, "policy_allow", nil)
	e.OnBehalfOf = onBehalfOf
	return e
}

func TestChainPassesAValidDelegationChain(t *testing.T) {
	s := mustLoadSchemas(t)
	stream := chainLines(t, delegatedEvent("2026-08-05T12:00:00Z", []string{
		"user://acme.example/j.doe",
		"agent://acme.example/support/orchestrator",
	}))
	path := writeFile(t, "ok.ndjson", stream)
	if !checkFile(s, path, true) {
		t.Fatal("a well-formed delegation chain must pass -chain")
	}
}

func TestChainReportsACyclicDelegationChain(t *testing.T) {
	s := mustLoadSchemas(t)
	// The same principal twice: the agent is its own delegate, which SPEC 5.1
	// forbids and which is how a delegation loop looks on the wire.
	stream := chainLines(t, delegatedEvent("2026-08-05T12:00:00Z", []string{
		"user://acme.example/j.doe",
		"agent://acme.example/support/orchestrator",
		"agent://acme.example/support/orchestrator",
	}))
	path := writeFile(t, "cycle.ndjson", stream)
	if checkFile(s, path, true) {
		t.Fatal("a cyclic on_behalf_of must fail -chain")
	}
	if !checkFile(s, path, false) {
		t.Fatal("without -chain the same stream is schema-valid, which is the whole point")
	}
}

// TestChainReportsAnOverlongDelegationChain and its cyclic sibling above are
// deliberately asymmetric now, and the asymmetry is the interesting part.
//
// Until 2026-08-06 both halves of SPEC 5.1 were invisible to the schema, so
// both tests asserted the same thing: -chain catches it, plain validation does
// not. On that day agent-passport encoded the depth bound as maxItems 32 in
// both event schemas, which this repo then vendored. Depth is expressible in
// JSON Schema; acyclicity is not, and the canonical schema says so in its own
// description rather than pretending otherwise.
//
// So an overlong chain is now refused in BOTH modes, and a cyclic one is still
// refused only by -chain. If a future change makes this test's second
// assertion fail, the vendored copies have drifted from a canonical schema
// that dropped the bound, and scripts/schemas-in-sync.sh should be red too.
func TestChainReportsAnOverlongDelegationChain(t *testing.T) {
	s := mustLoadSchemas(t)
	// 33 entries, one past chain.MaxDepth.
	deep := make([]string, 0, 33)
	for i := range 33 {
		deep = append(deep, fmt.Sprintf("agent://acme.example/hop/%d", i))
	}
	stream := chainLines(t, delegatedEvent("2026-08-05T12:00:00Z", deep))
	path := writeFile(t, "deep.ndjson", stream)
	if checkFile(s, path, true) {
		t.Fatal("an on_behalf_of past 32 entries must fail -chain")
	}
	if checkFile(s, path, false) {
		t.Fatal("the canonical schema bounds on_behalf_of at 32, so plain validation must refuse a 33rd entry too")
	}
}

// TestChainReportsTheTwoFailureKindsDistinctly is the point of doing this at
// all. A broken hash chain and a broken delegation chain mean different things
// to whoever reads the report: one says the file was altered after the fact,
// the other says the identity claim inside it never made sense. A single
// "chain: FAIL" line would collapse the two.
func TestChainReportsTheTwoFailureKindsDistinctly(t *testing.T) {
	s := mustLoadSchemas(t)

	cyclic := chainLines(t, delegatedEvent("2026-08-05T12:00:00Z", []string{
		"agent://acme.example/a", "agent://acme.example/a",
	}))
	cyclicPath := writeFile(t, "cycle.ndjson", cyclic)
	delegationOut := captureStdout(t, func() { checkFile(s, cyclicPath, true) })

	tampered := strings.Replace(
		chainLines(t,
			chainEvent("2026-08-05T12:00:00Z", "policy_allow", map[string]any{"policy": "p1"}),
			chainEvent("2026-08-05T12:00:01Z", "policy_deny", map[string]any{"policy": "p1"}),
		),
		`"policy":"p1"`, `"policy":"p2"`, 1)
	tamperedPath := writeFile(t, "tampered.ndjson", tampered)
	hashOut := captureStdout(t, func() { checkFile(s, tamperedPath, true) })

	// Only the FAIL lines: what a reader is told went wrong.
	delegationFails := failLines(delegationOut)
	hashFails := failLines(hashOut)

	switch {
	case !strings.Contains(delegationFails, "delegation chain"):
		t.Errorf("a cyclic delegation chain must be named as one, got:\n%s", delegationOut)
	case strings.Contains(delegationFails, "chain break"):
		t.Errorf("a cyclic delegation chain is not a prev_hash break, got:\n%s", delegationOut)
	case !strings.Contains(hashFails, "chain break"):
		t.Errorf("a tampered line must still be reported as a chain break, got:\n%s", hashOut)
	case strings.Contains(hashFails, "delegation chain"):
		t.Errorf("a tampered line says nothing about delegation, got:\n%s", hashOut)
	}
}

// failLines keeps only the lines reporting a failure.
func failLines(out string) string {
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "FAIL ") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// TestChainDelegationCheckIsOffWithoutTheFlag pins that the delegation check
// rides on -chain and nothing else: without the flag this tool validates
// against the schemas only, and the schemas do not cap or de-duplicate
// on_behalf_of.
func TestChainDelegationCheckIsOffWithoutTheFlag(t *testing.T) {
	s := mustLoadSchemas(t)
	stream := chainLines(t, delegatedEvent("2026-08-05T12:00:00Z", []string{
		"agent://acme.example/a", "agent://acme.example/a",
	}))
	path := writeFile(t, "cycle.ndjson", stream)
	if !checkFile(s, path, false) {
		t.Fatal("no -chain, no delegation check: this stream conforms to the schema")
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
