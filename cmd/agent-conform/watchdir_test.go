package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// The scenarios these tests bind to are in features/watch-dir.feature. The
// fixtures are written with the library's own ChainedWriter, never by hand, so
// "an honestly chained stream" means what every producer on the bus means by it.

type watchRun struct {
	code           int
	stdout, stderr string
}

func runWatch(t *testing.T, args ...string) watchRun {
	t.Helper()
	watchNow = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }
	var so, se bytes.Buffer
	code := runWatchDir(args, &so, &se)
	return watchRun{code: code, stdout: so.String(), stderr: se.String()}
}

func fixtureEvent(stem string, i int) event.Event {
	return event.Event{
		Schema:   event.SchemaV10,
		TS:       fmt.Sprintf("2026-10-04T10:00:%02dZ", i),
		Source:   stem,
		Type:     "policy_deny",
		AgentID:  "agent://acme.example/biller",
		Severity: event.SeverityMedium,
		Data:     map[string]any{"seq": i},
	}
}

// chainedStream writes n events to dir/<stem>.ndjson with the library's own
// ChainedWriter and returns the path.
func chainedStream(t *testing.T, dir, stem string, n int) string {
	t.Helper()
	path := filepath.Join(dir, stem+".ndjson")
	w, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if err := w.Write(fixtureEvent(stem, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// unchainedStream writes n events with the plain Writer: no prev_hash anywhere.
func unchainedStream(t *testing.T, dir, stem string, n int) string {
	t.Helper()
	path := filepath.Join(dir, stem+".ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if err := w.Write(fixtureEvent(stem, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// flipByte changes the `m` of `medium` to `n` on the given 1-based line: the
// tamper the 2026-09-17 appliance run did by hand. The line stays valid JSON
// and keeps its required fields, so the edit is invisible to everything that
// only parses.
func flipByte(t *testing.T, path string, line int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if line < 1 || line > len(lines) || !bytes.Contains(lines[line-1], []byte(`"medium"`)) {
		t.Fatalf("line %d of %s has no \"medium\" to flip", line, path)
	}
	lines[line-1] = bytes.Replace(lines[line-1], []byte(`"medium"`), []byte(`"nedium"`), 1)
	if err := os.WriteFile(path, bytes.Join(lines, nil), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// snapshot is the hash of every regular file in dir, by name.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			out[e.Name()] = sum(t, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func names(m map[string]string) []string {
	var n []string
	for k := range m {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func busOut(t *testing.T, dir string) []event.Event {
	t.Helper()
	path := filepath.Join(dir, "agent-conform.ndjson")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// ---------------------------------------------------------------------------
// the clean case
// ---------------------------------------------------------------------------

func TestWatchDirACleanChainedFileReportsNothing(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 6)
	chainedStream(t, dir, "tokenfuse", 4)
	before := snapshot(t, dir)

	r := runWatch(t, dir)

	if r.code != 0 {
		t.Fatalf("clean bus: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	if got := busOut(t, dir); len(got) != 0 {
		t.Fatalf("clean bus: %d event(s) written to the output, want none: %+v", len(got), got)
	}
	if after := snapshot(t, dir); strings.Join(names(after), ",") != strings.Join(names(before), ",") {
		t.Fatalf("a clean run created files: before %v, after %v", names(before), names(after))
	}
	if !strings.Contains(r.stdout, "PASS wardryx.ndjson") || !strings.Contains(r.stdout, "PASS tokenfuse.ndjson") {
		t.Fatalf("a clean run must say what it verified, got:\n%s", r.stdout)
	}
}

// ---------------------------------------------------------------------------
// a flipped byte
// ---------------------------------------------------------------------------

func TestWatchDirOneFlippedByteInAMiddleLineIsChainBrokenAtTheRightLine(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 6)
	chainedStream(t, dir, "tokenfuse", 3)
	flipByte(t, path, 3) // the edit is on line 3; the line that no longer chains is 4

	r := runWatch(t, dir)

	if r.code != 1 {
		t.Fatalf("one flipped byte: exit %d, want 1\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 1 {
		t.Fatalf("want exactly one alert for one broken file, got %d: %+v", len(got), got)
	}
	e := got[0]
	if e.Type != "chain_broken" || e.Severity != event.SeverityHigh || e.Source != "agent-conform" {
		t.Errorf("alert shape: type=%q severity=%q source=%q, want chain_broken/high/agent-conform", e.Type, e.Severity, e.Source)
	}
	if e.Data["file"] != "wardryx.ndjson" {
		t.Errorf("alert names file %v, want wardryx.ndjson", e.Data["file"])
	}
	if e.Data["line"] != float64(4) {
		t.Errorf("alert names line %v, want 4 (the first line whose prev_hash no longer matches)", e.Data["line"])
	}
	if e.Data["kind"] != "prev_hash_mismatch" {
		t.Errorf("alert kind %v, want prev_hash_mismatch", e.Data["kind"])
	}
	if !strings.Contains(r.stdout, "wardryx.ndjson:4") {
		t.Errorf("the run must say where on stdout too:\n%s", r.stdout)
	}
}

func TestWatchDirTheAlertItWritesConformsAndIsItselfChained(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 5), 2)
	unchainedStream(t, dir, "legacy", 3)

	if r := runWatch(t, dir); r.code != 1 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	out := filepath.Join(dir, "agent-conform.ndjson")
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}
	schemas := mustLoadSchemas(t)
	n := 0
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
		if err != nil {
			t.Fatalf("output line is not JSON: %v", err)
		}
		if err := schemas.eventV10.Validate(inst); err != nil {
			t.Errorf("an alert does not conform to the v1.0 event schema: %v\n%s", err, line)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("want 2 alerts (one broken, one unchained), got %d", n)
	}
	rep, err := event.VerifyChain(bytes.NewReader(raw))
	if err != nil || !rep.Ok() || rep.Chained != 1 {
		t.Fatalf("the verifier's own output must be a chain the library verifies: %+v err=%v", rep, err)
	}
}

// ---------------------------------------------------------------------------
// once, and only once
// ---------------------------------------------------------------------------

func TestWatchDirASecondRunDoesNotAlertAgainForTheSameBreak(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)

	if r := runWatch(t, dir); r.code != 1 {
		t.Fatalf("first run: exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	outBefore := sum(t, filepath.Join(dir, "agent-conform.ndjson"))

	r := runWatch(t, dir)
	if r.code != 0 {
		t.Fatalf("second run over the same break: exit %d, want 0 (nothing NEW)\n%s%s", r.code, r.stdout, r.stderr)
	}
	if outAfter := sum(t, filepath.Join(dir, "agent-conform.ndjson")); outAfter != outBefore {
		t.Fatalf("a second run appended to the output: the same (file, line) was alerted twice")
	}
	if !strings.Contains(r.stdout, "already reported") {
		t.Errorf("the second run should say the break is known, got:\n%s", r.stdout)
	}
	// And a third, because a state file that is only read correctly once is the
	// shape of the bug where the first run writes it and the second rewrites it empty.
	if r3 := runWatch(t, dir); r3.code != 0 || sum(t, filepath.Join(dir, "agent-conform.ndjson")) != outBefore {
		t.Fatalf("third run: exit %d, output changed", r3.code)
	}
}

func TestWatchDirNamesTheFirstBreakOfSeveralAndCountsThemAll(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 9)
	flipByte(t, path, 2) // breaks at 3
	flipByte(t, path, 6) // and at 7

	if r := runWatch(t, dir); r.code != 1 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 1 {
		t.Fatalf("want one alert per file, got %d: %+v", len(got), got)
	}
	if got[0].Data["line"] != float64(3) {
		t.Errorf("the alert names line %v, want 3, the FIRST break", got[0].Data["line"])
	}
	if got[0].Data["breaks"] != float64(2) {
		t.Errorf("the alert counts %v break(s), want 2", got[0].Data["breaks"])
	}
}

func TestWatchDirABreakThatMovesIsANewAlert(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 8)
	flipByte(t, path, 5) // first break at line 6
	if r := runWatch(t, dir); r.code != 1 {
		t.Fatalf("first run: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Somebody repairs the file and breaks it somewhere earlier.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	path = chainedStream(t, dir, "wardryx", 8)
	flipByte(t, path, 2) // first break at line 3

	r := runWatch(t, dir)
	if r.code != 1 {
		t.Fatalf("a break at a different line is a different finding: exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 2 || got[1].Data["line"] != float64(3) {
		t.Fatalf("want a second alert for line 3, got %+v", got)
	}
}

func TestWatchDirAnOutputThatCannotBeOpenedLosesNothing(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)
	state := filepath.Join(t.TempDir(), "state.json")
	badOut := filepath.Join(t.TempDir(), "no-such-dir", "agent-conform.ndjson")

	r := runWatch(t, "-out", badOut, "-state", state, dir)
	if r.code != 2 {
		t.Fatalf("an output that could not be opened: exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
	}
	goodOut := filepath.Join(t.TempDir(), "agent-conform.ndjson")
	r = runWatch(t, "-out", goodOut, "-state", state, dir)
	if r.code != 1 {
		t.Fatalf("the retry: exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	if evs, _ := event.ReadFile(goodOut); len(evs) != 1 {
		t.Fatalf("the retry delivered %d alert(s), want 1", len(evs))
	}
}

// failingSecondWrite delegates to the real writer and fails the second Write.
type failingSecondWrite struct {
	real alertWriter
	n    int
}

func (f *failingSecondWrite) Write(e event.Event) error {
	f.n++
	if f.n == 2 {
		return fmt.Errorf("disk full, said the test")
	}
	return f.real.Write(e)
}
func (f *failingSecondWrite) Close() error { return f.real.Close() }

func TestWatchDirAnAlertThatFailedToWriteIsNotRecordedAsReported(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "tokenfuse", 5), 2)
	flipByte(t, chainedStream(t, dir, "wardryx", 5), 2)

	real := openAlertWriter
	t.Cleanup(func() { openAlertWriter = real })
	openAlertWriter = func(path string) (alertWriter, error) {
		w, err := real(path)
		return &failingSecondWrite{real: w}, err
	}
	r := runWatch(t, dir)
	if r.code != 2 {
		t.Fatalf("one alert not written: exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
	}
	if got := busOut(t, dir); len(got) != 1 || got[0].Data["file"] != "tokenfuse.ndjson" {
		t.Fatalf("only the first alert reached the bus: %+v", got)
	}

	// The second alert never reached the bus, so the next run, with a working
	// writer, must deliver it, and only it. Recording it as reported before
	// the write succeeded would have made that a silent loss.
	openAlertWriter = real
	r = runWatch(t, dir)
	if r.code != 1 {
		t.Fatalf("the retry: exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 2 || got[1].Data["file"] != "wardryx.ndjson" {
		t.Fatalf("the retry should deliver exactly the lost alert: %+v", got)
	}
}

func TestWatchDirDoesNotFollowASymlinkOutOfTheBus(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 4)
	elsewhere := flipByte2(t)
	if err := os.Symlink(elsewhere, filepath.Join(dir, "planted.ndjson")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	r := runWatch(t, dir)
	if r.code != 0 || len(busOut(t, dir)) != 0 {
		t.Fatalf("a link is not part of the bus and is not followed: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "planted.ndjson: not a regular file") {
		t.Errorf("the skipped link should be named: %s", r.stdout)
	}
}

func flipByte2(t *testing.T) string {
	t.Helper()
	p := chainedStream(t, t.TempDir(), "outside", 5)
	flipByte(t, p, 2)
	return p
}

// ---------------------------------------------------------------------------
// no chain at all is not a broken chain
// ---------------------------------------------------------------------------

func TestWatchDirAnUnchainedFileIsReportedOnceAtLowAndNotAsBroken(t *testing.T) {
	dir := t.TempDir()
	unchainedStream(t, dir, "legacy", 4)
	chainedStream(t, dir, "wardryx", 3)

	r := runWatch(t, dir)
	if r.code != 0 {
		t.Fatalf("an unchained file is not a break: exit %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 1 {
		t.Fatalf("want one alert, got %d: %+v", len(got), got)
	}
	if got[0].Type != "chain_unchained" || got[0].Severity != event.SeverityLow || got[0].Data["file"] != "legacy.ndjson" {
		t.Errorf("unchained alert: %+v", got[0])
	}
	for _, e := range got {
		if e.Type == "chain_broken" {
			t.Errorf("an unchained file was reported as broken: %+v", e)
		}
	}

	// Once.
	outBefore := sum(t, filepath.Join(dir, "agent-conform.ndjson"))
	if r2 := runWatch(t, dir); r2.code != 0 || sum(t, filepath.Join(dir, "agent-conform.ndjson")) != outBefore {
		t.Fatalf("the unchained file was reported again: exit %d", r2.code)
	}
}

func TestWatchDirAFileWithOneEventIsNotYetJudged(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 1) // a chain's head has no prev_hash by design
	unchainedStream(t, dir, "mockryx", 1)

	r := runWatch(t, dir)
	if r.code != 0 || len(busOut(t, dir)) != 0 {
		t.Fatalf("one event cannot be unchained or broken: exit %d, alerts %+v\n%s", r.code, busOut(t, dir), r.stdout)
	}
}

// ---------------------------------------------------------------------------
// an empty or missing bus is an error, never a pass
// ---------------------------------------------------------------------------

func TestWatchDirAnEmptyOrMissingDirectoryIsAnErrorNotASilentPass(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	onlyOthers := t.TempDir()
	if err := os.WriteFile(filepath.Join(onlyOthers, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	onlyOwn := t.TempDir()
	if err := os.WriteFile(filepath.Join(onlyOwn, "agent-conform.ndjson"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":                t.TempDir(),
		"missing":              filepath.Join(t.TempDir(), "nope"),
		"a file, not a dir":    notDir,
		"no ndjson":            onlyOthers,
		"only its own output":  onlyOwn,
		"only a nested stream": nestedOnly(t),
		"a symlinked stream":   symlinkedOnly(t),
	}
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			r := runWatch(t, dir)
			if r.code != 2 {
				t.Fatalf("exit %d, want 2\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
			}
			if r.stderr == "" {
				t.Fatal("an error must say what it is")
			}
		})
	}
}

func nestedOnly(t *testing.T) string {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	chainedStream(t, sub, "wardryx", 3)
	return dir
}

func symlinkedOnly(t *testing.T) string {
	dir := t.TempDir()
	target := chainedStream(t, t.TempDir(), "wardryx", 3)
	if err := os.Symlink(target, filepath.Join(dir, "wardryx.ndjson")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	return dir
}

func TestWatchDirDoesNotDescendIntoSubdirectories(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 3)
	sub := filepath.Join(dir, "archive")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	flipByte(t, chainedStream(t, sub, "old", 5), 2)

	r := runWatch(t, dir)
	if r.code != 0 || len(busOut(t, dir)) != 0 {
		t.Fatalf("the bus is one flat directory; a broken file one level down is not part of it: exit %d\n%s", r.code, r.stdout)
	}
}

// ---------------------------------------------------------------------------
// it never writes anywhere but its own output and state
// ---------------------------------------------------------------------------

func TestWatchDirNeverModifiesAFileItReads(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)
	chainedStream(t, dir, "tokenfuse", 4)
	unchainedStream(t, dir, "legacy", 3)
	if err := os.WriteFile(filepath.Join(dir, "empty.ndjson"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "garbage.ndjson"), []byte("\x00\x01not json\n{\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)

	for i := 0; i < 2; i++ {
		runWatch(t, dir)
	}

	after := snapshot(t, dir)
	own := map[string]bool{"agent-conform.ndjson": true, "agent-conform.state.json": true}
	for name, h := range before {
		if after[name] != h {
			t.Errorf("%s was modified (or removed) by the verifier", name)
		}
	}
	for name := range after {
		if _, existed := before[name]; !existed && !own[name] {
			t.Errorf("the verifier created %s, which is neither its output nor its state", name)
		}
	}
}

func TestWatchDirCanRunAgainstAReadOnlyBusWithItsOutputElsewhere(t *testing.T) {
	bus := t.TempDir()
	flipByte(t, chainedStream(t, bus, "wardryx", 6), 3)
	chainedStream(t, bus, "tokenfuse", 3)
	before := snapshot(t, bus)
	if err := os.Chmod(bus, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bus, 0o755) })

	work := t.TempDir()
	out := filepath.Join(work, "agent-conform.ndjson")
	r := runWatch(t, "-out", out, "-state", filepath.Join(work, "state.json"), bus)
	if r.code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", r.code, r.stdout, r.stderr)
	}
	if evs, _ := event.ReadFile(out); len(evs) != 1 || evs[0].Type != "chain_broken" {
		t.Fatalf("alert not in the separate output: %+v", evs)
	}
	after := snapshot(t, bus)
	if strings.Join(names(after), ",") != strings.Join(names(before), ",") {
		t.Fatalf("the read-only bus gained or lost files: %v -> %v", names(before), names(after))
	}
	for n, h := range before {
		if after[n] != h {
			t.Errorf("%s changed", n)
		}
	}
}

func TestWatchDirRefusesAnOutputThatIsAnotherWritersStream(t *testing.T) {
	dir := t.TempDir()
	victim := chainedStream(t, dir, "wardryx", 4)
	flipByte(t, chainedStream(t, dir, "tokenfuse", 4), 2)
	before := sum(t, victim)

	r := runWatch(t, "-out", victim, dir)
	if r.code != 2 {
		t.Fatalf("exit %d, want 2: an output named like another stream would put alerts into it\n%s%s", r.code, r.stdout, r.stderr)
	}
	if sum(t, victim) != before {
		t.Fatal("the verifier wrote into another writer's stream")
	}

	for _, bad := range []string{"state.ndjson", "wardryx.ndjson"} {
		if r := runWatch(t, "-state", filepath.Join(dir, bad), dir); r.code != 2 {
			t.Errorf("-state %s: exit %d, want 2 (a state file must not look like a stream)", bad, r.code)
		}
	}
}

// ---------------------------------------------------------------------------
// hostile input
// ---------------------------------------------------------------------------

func TestWatchDirSurvivesHostileInput(t *testing.T) {
	huge := bytes.Repeat([]byte("a"), 3<<20) // over the 1 MiB line cap, under the file cap
	deep := bytes.Repeat([]byte("["), 200000)
	cases := []struct {
		name string
		body []byte
		want int // exit code
	}{
		{"empty file", nil, 0},
		{"only newlines", []byte("\n\n\n\n"), 0},
		{"invalid json", []byte("{not json\n}{\n\"\n"), 0},
		{"binary", append([]byte{0x00, 0xff, 0xfe, 0x80, '\n'}, bytes.Repeat([]byte{0x00, 0x1b, 0xc3, 0x28}, 4096)...), 0},
		{"deeply nested array", append(deep, '\n'), 0},
		{"huge line with a newline", append(append([]byte{}, huge...), '\n'), 2},
		{"huge line, no newline at all", huge, 2},
		{"a line that is a bare quote", []byte(`"` + "\n"), 0},
		{"json that is not an object", []byte("[1,2,3]\n42\nnull\ntrue\n"), 0},
		{"crlf line endings", []byte("{\"a\":1}\r\n{\"b\":2}\r\n"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			chainedStream(t, dir, "wardryx", 3) // a good neighbour, so the dir is never empty
			path := filepath.Join(dir, "hostile.ndjson")
			if err := os.WriteFile(path, tc.body, 0o644); err != nil {
				t.Fatal(err)
			}
			before := sum(t, path)
			r := runWatch(t, dir) // a panic here fails the test
			if r.code != tc.want {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%.400s", r.code, tc.want, r.stdout, r.stderr)
			}
			if tc.want == 2 && !strings.Contains(r.stderr, "hostile.ndjson") {
				t.Errorf("a file that could not be verified must be named on stderr: %.400s", r.stderr)
			}
			if sum(t, path) != before {
				t.Error("the hostile file was modified")
			}
			if len(busOut(t, dir)) != 0 {
				t.Errorf("hostile input produced a chain alert it has no basis for: %+v", busOut(t, dir))
			}
		})
	}
}

func TestWatchDirAHugeLineDoesNotHideABreakThatCameBeforeIt(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 5)
	flipByte(t, path, 2)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(bytes.Repeat([]byte("z"), 2<<20), '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r := runWatch(t, dir)
	if r.code != 2 {
		t.Fatalf("exit %d, want 2: the file could not be read to its end\n%s%s", r.code, r.stdout, r.stderr)
	}
	got := busOut(t, dir)
	if len(got) != 1 || got[0].Type != "chain_broken" || got[0].Data["line"] != float64(3) {
		t.Fatalf("the break before the oversize line must still be alerted: %+v", got)
	}
}

func TestWatchDirCapsTheBytesItReadsPerFile(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 12)
	flipByte(t, path, 11) // the break is on line 12, past the cap below
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	r := runWatch(t, "-max-file-bytes", fmt.Sprint(st.Size()/2), dir)
	if r.code != 2 {
		t.Fatalf("a file over the cap is not a clean pass: exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "wardryx.ndjson") || !strings.Contains(r.stderr, "cap") {
		t.Errorf("stderr must say which file was not read to its end and why: %q", r.stderr)
	}
	if len(busOut(t, dir)) != 0 {
		t.Errorf("a break beyond the cap cannot have been seen")
	}

	// The same file under a cap that holds it is read in full.
	r = runWatch(t, "-max-file-bytes", fmt.Sprint(st.Size()), dir)
	if r.code != 1 {
		t.Fatalf("under a sufficient cap the break is found: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestWatchDirAnOversizeClaimedPrevHashDoesNotInflateTheAlert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardryx.ndjson")
	good := chainedStream(t, t.TempDir(), "wardryx", 2)
	b, _ := os.ReadFile(good)
	lines := bytes.SplitAfter(b, []byte("\n"))
	forged := fmt.Sprintf(`{"schema":"%s","ts":"2026-10-04T10:00:09Z","source":"wardryx","type":"policy_deny","agent_id":"agent://acme.example/x","prev_hash":"%s"}`+"\n",
		event.SchemaV10, strings.Repeat("f", 500000))
	if err := os.WriteFile(path, append(append(lines[0], lines[1]...), []byte(forged)...), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runWatch(t, dir)
	if r.code != 1 {
		t.Fatalf("exit %d\n%.300s%.300s", r.code, r.stdout, r.stderr)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent-conform.ndjson"))
	if len(raw) > 4096 {
		t.Fatalf("the alert is %d bytes: attacker-chosen content was copied into the bus", len(raw))
	}
	if len(r.stdout) > 4096 {
		t.Fatalf("stdout is %d bytes for one finding", len(r.stdout))
	}
}

// ---------------------------------------------------------------------------
// the verifier's own output is a stream like any other
// ---------------------------------------------------------------------------

func TestWatchDirVerifiesItsOwnOutputToo(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 5), 2)
	unchainedStream(t, dir, "legacy", 3)
	if r := runWatch(t, dir); r.code != 1 {
		t.Fatalf("setup run: exit %d", r.code)
	}
	// Tamper with the alerts themselves. Streams are walked in name order, so
	// the first alert is legacy's (low) and a second line follows it.
	own := filepath.Join(dir, "agent-conform.ndjson")
	b, _ := os.ReadFile(own)
	if err := os.WriteFile(own, bytes.Replace(b, []byte(`"low"`), []byte(`"lxw"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runWatch(t, dir)
	if r.code != 1 {
		t.Fatalf("a tampered alert file is a broken chain like any other: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	evs := busOut(t, dir)
	last := evs[len(evs)-1]
	if last.Type != "chain_broken" || last.Data["file"] != "agent-conform.ndjson" {
		t.Fatalf("the new alert should name the verifier's own file: %+v", last)
	}
}

// ---------------------------------------------------------------------------
// usage and state
// ---------------------------------------------------------------------------

func TestWatchDirUsageErrorsExitTwo(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 2)
	for name, args := range map[string][]string{
		"no directory":                    {},
		"two directories":                 {dir, dir},
		"unknown flag":                    {"-nope", dir},
		"zero line cap":                   {"-max-line-bytes", "0", dir},
		"line cap over the library's own": {"-max-line-bytes", fmt.Sprint(5 << 20), dir},
		"zero file cap":                   {"-max-file-bytes", "0", dir},
		"flag after the dir":              {dir, "-out", "x.ndjson"},
	} {
		t.Run(name, func(t *testing.T) {
			if r := runWatch(t, args...); r.code != 2 {
				t.Fatalf("exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestWatchDirACorruptStateFileIsAnErrorNotAFreshStart(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)
	state := filepath.Join(dir, "agent-conform.state.json")
	if err := os.WriteFile(state, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runWatch(t, dir)
	if r.code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
	}
	if len(busOut(t, dir)) != 0 {
		t.Fatal("alerts were written against a state file nobody could read")
	}
	if got, _ := os.ReadFile(state); string(got) != "{not json" {
		t.Fatal("the unreadable state file was overwritten")
	}
}

func TestWatchDirSurvivesARestartOfTheVerifier(t *testing.T) {
	// State is the only memory: a different process, a different clock, the
	// same files. Nothing in-process may be what suppresses the second alert.
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)
	runWatch(t, dir)
	watchNow = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	var so, se bytes.Buffer
	if code := runWatchDir([]string{dir}, &so, &se); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, so.String(), se.String())
	}
	if len(busOut(t, dir)) != 1 {
		t.Fatalf("restart re-alerted: %+v", busOut(t, dir))
	}
}

// ---------------------------------------------------------------------------
// the real binary, because main() is where the exit code is decided
// ---------------------------------------------------------------------------

func TestWatchDirThroughTheRealBinaryExitsWithTheDocumentedCodes(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "agent-conform")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	run := func(args ...string) (int, string) {
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running %v: %v", args, err)
		}
		return code, string(out)
	}

	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 6), 3)
	chainedStream(t, dir, "tokenfuse", 4)

	if code, out := run("watch-dir", dir); code != 1 || !strings.Contains(out, "wardryx.ndjson:4") {
		t.Fatalf("first run: exit %d, want 1 naming wardryx.ndjson:4\n%s", code, out)
	}
	if code, out := run("watch-dir", dir); code != 0 {
		t.Fatalf("second run: exit %d, want 0\n%s", code, out)
	}
	if code, out := run("watch-dir", filepath.Join(dir, "missing")); code != 2 {
		t.Fatalf("missing dir: exit %d, want 2\n%s", code, out)
	}
	if code, _ := run("watch-dir"); code != 2 {
		t.Fatalf("no dir: exit %d, want 2", code)
	}
	if code, out := run("-h"); code != 0 || !strings.Contains(out, "watch-dir") {
		t.Fatalf("-h should name the mode: exit %d\n%s", code, out)
	}
}

// ---------------------------------------------------------------------------
// -every: the loop for an image that has no shell to loop in
// ---------------------------------------------------------------------------

func TestWatchDirEveryLoopsAndStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	path := chainedStream(t, dir, "wardryx", 8)

	real := watchSleep
	t.Cleanup(func() { watchSleep = real })
	sleeps := 0
	watchSleep = func(ctx context.Context, d time.Duration) bool {
		sleeps++
		if d != 30*time.Second {
			t.Errorf("slept %v, want the -every interval", d)
		}
		switch sleeps {
		case 1:
			flipByte(t, path, 3) // a clean pass, then a break appears
			return true
		case 2:
			return true // the break was reported; a pass that finds it again is quiet
		default:
			return false // told to stop
		}
	}
	r := runWatch(t, "-every", "30s", dir)
	if r.code != 0 {
		t.Fatalf("a loop that was told to stop exits 0, got %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if sleeps != 3 {
		t.Fatalf("want 3 passes' worth of sleeping, got %d", sleeps)
	}
	if got := busOut(t, dir); len(got) != 1 || got[0].Type != "chain_broken" {
		t.Fatalf("the break that appeared mid-loop is alerted once: %+v", got)
	}
	// Three passes ran: the first prints its report, the second found something,
	// the third was quiet and must print nothing. One summary line per printed pass.
	if n := strings.Count(r.stdout, "agent-conform watch-dir: "); n != 2 {
		t.Errorf("want 2 printed passes out of 3, got %d:\n%s", n, r.stdout)
	}
}

func TestWatchDirEveryExitsTwoWhenAPassCannotDoItsJob(t *testing.T) {
	dir := t.TempDir() // an empty bus: nothing to verify
	real := watchSleep
	t.Cleanup(func() { watchSleep = real })
	watchSleep = func(ctx context.Context, d time.Duration) bool {
		t.Error("a loop whose pass failed must not sleep and carry on")
		return false
	}
	r := runWatch(t, "-every", "30s", dir)
	if r.code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", r.code, r.stdout, r.stderr)
	}
}
