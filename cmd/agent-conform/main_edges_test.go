package main

import (
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The edges of the payload mode: main's own argument handling on the paths that
// return rather than exit, and the refusals checkFile owes a line or a file it
// could not judge. Each test asserts the text an operator reads, because the
// verdict line is the product here.

// runMain runs main() in this process with args, returning what it printed.
// Only paths that return are driven this way; the exit codes themselves are
// held by TestWatchDirThroughTheRealBinaryExitsWithTheDocumentedCodes.
func runMain(t *testing.T, args ...string) string {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = append([]string{"agent-conform"}, args...)
	return captureStdout(t, main)
}

func TestMainVersionNamesTheBuild(t *testing.T) {
	for _, flag := range []string{"-version", "--version", "version"} {
		out := runMain(t, flag)
		if out != "agent-conform "+version+"\n" {
			t.Errorf("%s printed %q, want the version line alone", flag, out)
		}
	}
}

func TestMainHelpNamesBothModesAndTheExitCodes(t *testing.T) {
	for _, flag := range []string{"-h", "-help", "--help"} {
		out := runMain(t, flag)
		for _, want := range []string{
			"usage: agent-conform [-chain] <file>...",
			"agent-conform watch-dir [flags] <dir>",
			"-chain",
			"Exit codes: 0 conformant, 1 not conformant, 2 could not be read.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s output lacks %q:\n%s", flag, want, out)
			}
		}
	}
}

func TestMainChainFlagChecksBothChainsOfAConformantStream(t *testing.T) {
	stream := chainLines(t,
		chainEvent("2026-07-24T12:00:00Z", "policy_allow", nil),
		chainEvent("2026-07-24T12:00:01Z", "policy_deny", nil),
	)
	path := writeFile(t, "ok.ndjson", stream)
	out := runMain(t, "-chain", path)
	for _, want := range []string{
		"OK   " + path + ":1 (event v0.2)",
		"OK   " + path + ":2 (event v0.2)",
		"PASS " + path + " (hash chain: 1 chained, 1 head(s))",
		"PASS " + path + " (delegation: 2 event(s), 0 carrying a chain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-chain output lacks %q:\n%s", want, out)
		}
	}
	// Without -chain the same file is judged by schema alone.
	plain := runMain(t, path)
	if strings.Contains(plain, "PASS") {
		t.Errorf("without -chain no chain verdict may be printed:\n%s", plain)
	}
}

func TestAddEmbeddedRefusesAMissingSchemaAndASecondRegistration(t *testing.T) {
	c := jsonschema.NewCompiler()
	err := addEmbedded(c, "schemas/no-such.schema.json", "https://example.invalid/x.json")
	if err == nil || !strings.Contains(err.Error(), "read embedded schemas/no-such.schema.json") {
		t.Fatalf("a schema the binary does not carry must be refused by name, got %v", err)
	}
	if err := addEmbedded(c, "schemas/agent-event.schema.json", schemaEventV01); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err = addEmbedded(c, "schemas/agent-event.v0.2.schema.json", schemaEventV01)
	if err == nil || !strings.Contains(err.Error(), "register "+schemaEventV01) {
		t.Fatalf("two schemas under one $id must be refused, got %v", err)
	}
}

// A line longer than the 4 MiB scanner cap is not judged by any of the three
// readers, and each says so and fails the file rather than passing what it
// never read.
func TestCheckFileAnOversizeLineFailsEveryCheckThatCouldNotReadIt(t *testing.T) {
	s := mustLoadSchemas(t)
	huge := `{"schema":"taipanbox.dev/agent-event/v0.2","pad":"` + strings.Repeat("a", 5<<20) + `"}`
	path := writeFile(t, "huge.ndjson", validEventLine("taipanbox.dev/agent-event/v0.2")+"\n"+huge+"\n")
	var ok bool
	out := captureStdout(t, func() { ok = checkFile(s, path, true) })
	if ok {
		t.Fatalf("a file with an unreadable line must fail:\n%s", out)
	}
	for _, want := range []string{
		"FAIL " + path + ": bufio.Scanner: token too long",
		"FAIL " + path + ": chain: ",
		"FAIL " + path + ": delegation chain: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%.2000s", want, out)
		}
	}
	if strings.Contains(out, "PASS") {
		t.Errorf("no check may PASS a file it could not read to the end:\n%.2000s", out)
	}
	// Each reader's own verdict, so one failing cannot hide another passing.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() {
		if checkEventStream(s, raw, path) {
			t.Error("checkEventStream passed a stream it could not read to the end")
		}
		if checkChain(raw, path) {
			t.Error("checkChain passed a stream it could not read to the end")
		}
		if checkDelegation(raw, path) {
			t.Error("checkDelegation passed a stream it could not read to the end")
		}
	})
}

// A blank line in the middle is skipped by every reader, a malformed line fails
// the schema check once and is not reported a second time by the delegation
// check, and the link after it is reported as unverifiable rather than broken.
func TestChainAMalformedLineInTheMiddleIsReportedOnceAndLeavesALinkUnverifiable(t *testing.T) {
	s := mustLoadSchemas(t)
	lines := strings.SplitAfter(chainLines(t,
		chainEvent("2026-07-24T12:00:00Z", "policy_allow", nil),
		chainEvent("2026-07-24T12:00:01Z", "policy_deny", nil),
	), "\n")
	stream := lines[0] + "\n" + "this is not json\n" + lines[1]
	path := writeFile(t, "mid.ndjson", stream)
	var ok bool
	out := captureStdout(t, func() { ok = checkFile(s, path, true) })
	if ok {
		t.Fatalf("a malformed line fails the file:\n%s", out)
	}
	if n := strings.Count(out, "FAIL "); n != 1 || !strings.Contains(out, "FAIL "+path+":3: invalid JSON") {
		t.Errorf("want exactly one FAIL, for line 3, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "NOTE "+path+": 1 unverifiable link(s) at line(s) [4]") {
		t.Errorf("the link after the malformed line must be noted as unverifiable:\n%s", out)
	}
	if !strings.Contains(out, "PASS "+path+" (delegation: 2 event(s)") {
		t.Errorf("the delegation check counts the two events it could read:\n%s", out)
	}
}

func TestChainAFileWithNoParsableEventSaysNoDelegationChainWasChecked(t *testing.T) {
	s := mustLoadSchemas(t)
	path := writeFile(t, "junk.ndjson", "not json\nnor this\n")
	var ok bool
	out := captureStdout(t, func() { ok = checkFile(s, path, true) })
	if ok {
		t.Fatalf("a file with no event in it must fail:\n%s", out)
	}
	if !strings.Contains(out, "NOTE "+path+": no parsable event, so no delegation chain was checked") {
		t.Errorf("the delegation check must say it measured nothing:\n%s", out)
	}
	if strings.Contains(out, "(delegation:") {
		t.Errorf("no delegation verdict may be printed over zero events:\n%s", out)
	}
}

func TestCheckFileAnInvalidV10EventFailsAgainstItsOwnSchema(t *testing.T) {
	s := mustLoadSchemas(t)
	bad := `{"schema":"taipanbox.dev/agent-event/v1.0","ts":"2026-07-13T00:00:00.000Z","source":"qryx","type":"crypto_finding","agent_id":"agent://acme.example/bot","severity":"catastrophic"}`
	path := writeFile(t, "v10.ndjson", validEventLine("taipanbox.dev/agent-event/v1.0")+"\n"+bad+"\n")
	var ok bool
	out := captureStdout(t, func() { ok = checkFile(s, path, false) })
	if ok {
		t.Fatalf("a v1.0 line with a severity the schema does not name must fail:\n%s", out)
	}
	if !strings.Contains(out, "OK   "+path+":1 (event v1.0)") || !strings.Contains(out, "FAIL "+path+":2 (event v1.0)") {
		t.Errorf("want line 1 OK and line 2 FAIL, both under v1.0:\n%s", out)
	}
}
