package main

// `agent-conform watch-dir <dir>`: the chain verifier that runs ON a box.
//
// WHY IT EXISTS
//
// Measured 2026-09-17 on the appliance proving run (agent-stack-go#64): one
// byte flipped on an already-sealed line of the shared events bus was seen by
// nothing. The planes were past the line by offset and cursor, and
// `agent-conform -chain` would have named the break, but it existed only as
// source in this repository, so nothing on the box could run it. This mode is
// the same verification (event.VerifyChain, the library's own) turned into
// something a CronJob or a compose loop can run and that ALERTS: a broken
// chain becomes an event on the bus, where heraldyx and the console already
// look, instead of a line on a terminal nobody has open.
//
// WHAT IT DOES
//
// It walks every `*.ndjson` in ONE flat directory (the bus is flat: genaryx,
// heraldyx and idryx all read one level, so this does too, and a subdirectory
// is not part of the bus) and verifies each file's prev_hash chain from its
// first line. For each file it reports at most one thing:
//
//   - chain_broken (severity high): a prev_hash that does not match the hash
//     of the line before it. The event names the file, the line of the FIRST
//     break and the kind of break.
//   - chain_unchained (severity low): two or more events and not one of them
//     carries a prev_hash. That is not a break, the field is optional by SPEC
//     6.5, but a stream nobody can verify is a stream a forger need not
//     bother to chain, and the operator should know which streams those are.
//
// Each finding is written ONCE: the (file, kind, line) is remembered in a
// small state file, so a cron that runs every minute does not repeat an alert
// every minute. The alert goes to this tool's own stream, written with the
// library's own ChainedWriter, so the verifier's output is a chained stream
// like every other and is itself verified on the next run.
//
// WHAT IT NEVER DOES
//
// It never writes to any file but its own output (`agent-conform.ndjson`) and
// its own state (and the state's temporary sibling). It opens every stream
// read-only, refuses an output path that is named like another writer's
// stream, and refuses a state path that looks like a stream, so it cannot be
// pointed at somebody else's file by a typo in a manifest. An empty or missing
// directory is an error and not a pass: a verifier that finds nothing to
// verify and says OK has measured nothing.
//
// ONE-SHOT BY DEFAULT. `-every <duration>` repeats the pass inside one process,
// for an image whose base has no shell (distroless/static) and for a compose
// service; see watchLoop. A CronJob uses the default.
//
// EXIT CODES
//
//	0  every stream verified; nothing NEW to report (an unchained stream, or a
//	   break already reported, does not change that)
//	1  at least one NEW chain_broken was reported
//	2  usage error, or something could not be done: a missing directory, no
//	   stream in it, a file that could not be read to its end (over a cap, an
//	   oversize line), an output or state that could not be written. 2 wins
//	   over 1 when both happen: the alerts are on the bus either way, and a run
//	   that could not finish its job must not look like one that could.
//
// HONEST LIMITS, stated here because the README repeats them
//
//   - prev_hash is tamper-evidence, not tamper-proof (invariant 8). A writer
//     compromised in its own uid can forge its own stream with a valid chain,
//     and so can anybody who can rewrite a whole file. This catches a partial
//     edit, a dropped line, a reordered shipment.
//   - Only genuine mismatches are breaks (invariant 7). A line whose prev_hash
//     was stripped reads as a chain restart, and a line replaced by garbage
//     makes the next one unverifiable; both are counted into the alert's data
//     but neither raises one, because a crash mid-write produces exactly the
//     second shape and a verifier that cried wolf on it would be switched off.
//   - Only the FIRST break per file is reported, and a later one is not until
//     the first is gone. The count of breaks rides in the alert.
//   - Truncating a stream from the end changes no hash in what remains.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

const (
	// The registry name of this producer (agent-passport SPEC 6.2). The stem of
	// its output file is the same word, which is what the readers' "source must
	// match the stream" rule (BUS-DESIGN layer 2) will check.
	watchSource     = "agent-conform"
	watchOutputName = watchSource + ".ndjson"
	watchStateName  = watchSource + ".state.json"
	watchAgentID    = "agent://agent-conform.internal/verifier"

	typeChainBroken    = "chain_broken"
	typeChainUnchained = "chain_unchained"

	kindMismatch  = "prev_hash_mismatch"
	kindUnchained = "no_prev_hash"

	stateSchema = "agent-conform/watch-state/v1"

	// A line cap of 1 MiB is the library's own `resumeWindow` reasoning: real
	// envelopes are hundreds of bytes and this is orders of magnitude beyond
	// any line the stack writes. It may be raised to the library readers' own
	// scanner limit (4 MiB) and no further, because above that VerifyChain
	// would refuse the line itself.
	defaultMaxLine  = 1 << 20
	libraryMaxLine  = 4 << 20
	defaultMaxFile  = 256 << 20
	maxStateBytes   = 4 << 20
	maxClippedField = 96
)

// watchNow is the clock, replaceable so a test can say what time an alert
// carries. Nothing else reads the time.
var watchNow = time.Now

// alertWriter is what an alert is written with. In production it is always the
// library's own ChainedWriter; the seam exists so a test can make ONE write
// fail after the open succeeded, which is the path where "recorded as reported
// although it never reached the bus" would hide. Every other test runs the real
// writer and verifies the chain it leaves.
type alertWriter interface {
	Write(event.Event) error
	Close() error
}

var openAlertWriter = func(path string) (alertWriter, error) { return event.NewChainedWriter(path) }

// stream is one file of the bus, as the walk found it.
type stream struct {
	name string // the base name: the bus is flat
	path string
}

// verdict is what verifying one stream produced.
type verdict struct {
	stream stream
	report event.ChainReport
	err    error // the file could not be read to its end
	events int   // well-formed events seen
}

// watchState is the only memory between runs.
type watchState struct {
	Schema   string     `json:"schema"`
	Reported []reported `json:"reported"`
}

type reported struct {
	File string `json:"file"`
	Type string `json:"type"`
	Line int    `json:"line,omitempty"`
	At   string `json:"at"`
}

func (r reported) key() string { return fmt.Sprintf("%s\x00%s\x00%d", r.File, r.Type, r.Line) }

// finding is something to put on the bus.
type finding struct {
	file    string
	typ     string
	line    int
	brk     event.ChainBreak // the first break, for a chain_broken
	verdict verdict
}

func (f finding) key() string { return reported{File: f.file, Type: f.typ, Line: f.line}.key() }

func watchUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: agent-conform watch-dir [flags] <dir>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Verifies the prev_hash chain of every *.ndjson in <dir> (one flat directory, not")
	fmt.Fprintln(w, "recursive) and appends ONE agent-event per newly found problem to its own stream:")
	fmt.Fprintln(w, "  chain_broken     (high) the first line whose prev_hash does not match, per file")
	fmt.Fprintln(w, "  chain_unchained  (low)  two or more events and no prev_hash at all, per file")
	fmt.Fprintln(w, "Each finding is written once; a state file remembers what was already reported.")
	fmt.Fprintln(w, "It writes nothing but its own output and state, and never to a stream it reads.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  -out <path>            its own stream (default <dir>/agent-conform.ndjson; the")
	fmt.Fprintln(w, "                         file must be named agent-conform.ndjson)")
	fmt.Fprintln(w, "  -state <path>          its memory (default agent-conform.state.json beside -out)")
	fmt.Fprintln(w, "  -max-line-bytes <n>    longest line it will read (default 1048576, at most 4194304)")
	fmt.Fprintln(w, "  -max-file-bytes <n>    most bytes it will read per file (default 268435456)")
	fmt.Fprintln(w, "  -every <duration>      keep running, one pass per interval (at least 10s), for a")
	fmt.Fprintln(w, "                         container with no shell to loop in; exits 2 when a pass")
	fmt.Fprintln(w, "                         cannot do its job so a supervisor restarts it, 0 on SIGTERM")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags go before <dir>. One run, then exit: a CronJob or a loop drives the schedule.")
	fmt.Fprintln(w, "Exit codes: 0 nothing new, 1 a NEW chain_broken was reported, 2 usage or I/O error.")
}

// watchConfig is what the flags resolved to.
type watchConfig struct {
	dir, outPath, statePath string
	maxLine                 int
	maxFile                 int64
	every                   time.Duration
}

// minEvery is the shortest loop interval. Below it a typo (`-every 1`) would
// turn a verifier into a busy loop on the bus it is meant to watch.
const minEvery = 10 * time.Second

// runWatchDir is the whole mode, returning the process exit code. It takes its
// streams so a test can read them, and it reads no environment variable.
func runWatchDir(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent-conform watch-dir", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "")
	statePath := fs.String("state", "", "")
	maxLine := fs.Int("max-line-bytes", defaultMaxLine, "")
	maxFile := fs.Int64("max-file-bytes", defaultMaxFile, "")
	every := fs.Duration("every", 0, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			watchUsage(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "agent-conform watch-dir: %v\n", err)
		watchUsage(stderr)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "agent-conform watch-dir: want exactly one directory (flags go before it)")
		watchUsage(stderr)
		return 2
	}
	dir := fs.Arg(0)
	if *maxLine < 1 || *maxLine > libraryMaxLine {
		fmt.Fprintf(stderr, "agent-conform watch-dir: -max-line-bytes must be between 1 and %d\n", libraryMaxLine)
		return 2
	}
	if *maxFile < 1 {
		fmt.Fprintln(stderr, "agent-conform watch-dir: -max-file-bytes must be at least 1")
		return 2
	}
	if *every < 0 || (*every > 0 && *every < minEvery) {
		fmt.Fprintf(stderr, "agent-conform watch-dir: -every must be 0 (one pass, then exit) or at least %s\n", minEvery)
		return 2
	}

	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(dir, watchOutputName)
	}
	if filepath.Base(outPath) != watchOutputName {
		fmt.Fprintf(stderr, "agent-conform watch-dir: -out must be a file named %s, not %q: its name is the source its events claim, and any other name would put alerts into another writer's stream or a stream nobody reads as this one\n",
			watchOutputName, filepath.Base(outPath))
		return 2
	}
	sPath := *statePath
	if sPath == "" {
		sPath = filepath.Join(filepath.Dir(outPath), watchStateName)
	}
	if strings.HasSuffix(sPath, ".ndjson") {
		fmt.Fprintf(stderr, "agent-conform watch-dir: -state %q looks like an event stream (*.ndjson); the walk would read it as one\n", sPath)
		return 2
	}

	cfg := watchConfig{dir: dir, outPath: outPath, statePath: sPath, maxLine: *maxLine, maxFile: *maxFile, every: *every}
	if cfg.every > 0 {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return watchLoop(ctx, cfg, stdout, stderr)
	}
	code, _ := watchPass(cfg, stdout, stderr)
	return code
}

// watchSleep waits for d and reports whether the wait ran its course; false
// means the context ended first. A variable so a test can run a loop without
// waiting.
var watchSleep = func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// watchLoop is `-every`: the same pass, repeated, for a container whose image
// has no shell to loop in (the base is distroless/static) and for a compose
// service. It exits 0 when told to stop. It exits 2 the moment a pass cannot do
// its job, on purpose: a supervisor restarting the container is how an
// operator sees that the verifier is not verifying, where a loop that logged
// the error and carried on would look healthy from outside. 0 and 1 are passes
// that finished, so the loop continues. The full report is printed for the
// first pass and afterwards only when something happened, so a minute-by-minute
// loop does not write a screenful per stream per minute into the container log.
func watchLoop(ctx context.Context, cfg watchConfig, stdout, stderr io.Writer) int {
	for pass := 0; ; pass++ {
		var buf bytes.Buffer
		code, fresh := watchPass(cfg, &buf, stderr)
		if pass == 0 || code != 0 || fresh > 0 {
			_, _ = stdout.Write(buf.Bytes())
		}
		if code == 2 {
			return 2
		}
		if !watchSleep(ctx, cfg.every) {
			return 0
		}
	}
}

// watchPass is one verification of the bus. It returns the exit code the pass
// earned and how many alerts it wrote.
func watchPass(cfg watchConfig, stdout, stderr io.Writer) (int, int) {
	dir, outPath, sPath := cfg.dir, cfg.outPath, cfg.statePath
	info, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(stderr, "agent-conform watch-dir: %v\n", err)
		return 2, 0
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "agent-conform watch-dir: %s is not a directory\n", dir)
		return 2, 0
	}

	state, err := loadWatchState(sPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-conform watch-dir: state %s: %v\n", sPath, err)
		return 2, 0
	}
	known := map[string]bool{}
	for _, r := range state.Reported {
		known[r.key()] = true
	}

	streams, skipped, err := listStreams(dir)
	if err != nil {
		fmt.Fprintf(stderr, "agent-conform watch-dir: %v\n", err)
		return 2, 0
	}
	for _, s := range skipped {
		fmt.Fprintf(stdout, "NOTE %s: not a regular file, so not read\n", s)
	}
	// The verifier's own output is a stream like any other. When it lives
	// beside the bus the walk already has it; when -out points elsewhere it is
	// added, so tampering with the alerts is not a place to hide.
	haveOwn := false
	others := 0
	for _, s := range streams {
		if s.name == watchOutputName {
			haveOwn = true
		} else {
			others++
		}
	}
	if others == 0 {
		fmt.Fprintf(stderr, "agent-conform watch-dir: no *.ndjson stream in %s to verify (an empty bus is not a clean bus: nothing was measured)\n", dir)
		return 2, 0
	}
	if !haveOwn && filepath.Dir(outPath) != filepath.Clean(dir) {
		if st, err := os.Lstat(outPath); err == nil && st.Mode().IsRegular() {
			streams = append(streams, stream{name: watchOutputName, path: outPath})
		}
	}

	code := 0
	var findings []finding
	for _, s := range streams {
		v := verifyStream(s, cfg.maxLine, cfg.maxFile)
		if v.err != nil {
			fmt.Fprintf(stderr, "ERROR %s: %v\n", s.name, v.err)
			code = 2
		}
		switch {
		case len(v.report.Breaks) > 0:
			b := v.report.Breaks[0]
			f := finding{file: s.name, typ: typeChainBroken, line: b.Line, brk: b, verdict: v}
			status := "alert pending"
			if known[f.key()] {
				status = "already reported"
			} else {
				findings = append(findings, f)
			}
			fmt.Fprintf(stdout, "FAIL %s:%d: chain break (%s), %d break(s) in all; %s\n",
				s.name, b.Line, kindMismatch, len(v.report.Breaks), status)
		case isUnchained(v):
			f := finding{file: s.name, typ: typeChainUnchained, verdict: v}
			status := "alert pending"
			if known[f.key()] {
				status = "already reported"
			} else {
				findings = append(findings, f)
			}
			fmt.Fprintf(stdout, "NOTE %s: unchained, %d events and no prev_hash; %s\n", s.name, v.events, status)
		case v.err != nil:
			// Already said on stderr; no PASS for a file read only in part.
		case v.events == 0:
			fmt.Fprintf(stdout, "NOTE %s: no event to verify (%d line(s), %d malformed)\n", s.name, v.report.Lines, v.report.Malformed)
		default:
			fmt.Fprintf(stdout, "PASS %s (hash chain: %d chained, %d head(s))\n", s.name, v.report.Chained, len(v.report.HeadLines))
		}
	}

	newBroken, written := 0, 0
	if len(findings) > 0 {
		w, err := openAlertWriter(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "agent-conform watch-dir: cannot open output: %v\n", err)
			return 2, 0
		}
		for _, f := range findings {
			if err := w.Write(alertFor(f)); err != nil {
				// Not recorded as reported: the alert never reached the bus, and
				// remembering it would turn a failed delivery into a silent loss.
				fmt.Fprintf(stderr, "ERROR %s: alert not written: %v\n", f.file, err)
				code = 2
				continue
			}
			state.Reported = append(state.Reported, reported{
				File: f.file, Type: f.typ, Line: f.line,
				At: watchNow().UTC().Format(time.RFC3339),
			})
			written++
			if f.typ == typeChainBroken {
				newBroken++
			}
			// Saved after every alert, not once at the end: the event is on the
			// bus the moment it is written, and a crash between two alerts must
			// cost one duplicate at worst, never a loss.
			if err := saveWatchState(sPath, state); err != nil {
				fmt.Fprintf(stderr, "ERROR state %s: %v (the alert for %s is on the bus and may be repeated)\n", sPath, err, f.file)
				code = 2
			}
		}
		if err := w.Close(); err != nil {
			fmt.Fprintf(stderr, "agent-conform watch-dir: closing output: %v\n", err)
			code = 2
		}
	}

	fmt.Fprintf(stdout, "agent-conform watch-dir: %d stream(s), %d new alert(s) written (%d chain_broken)\n",
		len(streams), written, newBroken)
	if code == 2 {
		return 2, written
	}
	if newBroken > 0 {
		return 1, written
	}
	return 0, written
}

// listStreams returns the regular `*.ndjson` files of one directory, sorted,
// and the names of `*.ndjson` entries that are not regular files (a symlink, a
// directory), which are reported and never followed: a link on a bus the
// verifier mounts read-only is a way to make it read a file nobody put there.
func listStreams(dir string) (streams []stream, skipped []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		if !e.Type().IsRegular() {
			skipped = append(skipped, e.Name())
			continue
		}
		streams = append(streams, stream{name: e.Name(), path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].name < streams[j].name })
	return streams, skipped, nil
}

// isUnchained: at least two well-formed events and not one carries a
// prev_hash. HeadLines holds exactly the events without one, so every
// well-formed event being a head is the whole condition. A single event is
// never judged: the first line of every chain has no prev_hash by design.
func isUnchained(v verdict) bool {
	return v.events >= 2 && len(v.report.HeadLines) == v.events
}

type lineTooLongError struct {
	line, max int
}

func (e *lineTooLongError) Error() string {
	return fmt.Sprintf("line %d is longer than the %d-byte line cap, so the file was not read to its end", e.line, e.max)
}

// lineCapReader fails the read the moment one line passes the cap, so the
// library's scanner is never handed a line it would buffer without bound.
type lineCapReader struct {
	r    io.Reader
	max  int
	run  int // bytes since the last newline
	line int // 1-based number of the line in progress
}

func (l *lineCapReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	for i := 0; i < n; i++ {
		if p[i] == '\n' {
			l.run = 0
			l.line++
			continue
		}
		l.run++
		if l.run > l.max {
			return i, &lineTooLongError{line: l.line, max: l.max}
		}
	}
	return n, err
}

// byteCapReader stops after max bytes and records whether there was more.
type byteCapReader struct {
	r         io.Reader
	max, n    int64
	truncated bool
}

func (b *byteCapReader) Read(p []byte) (int, error) {
	if b.n >= b.max {
		var one [1]byte
		if k, _ := b.r.Read(one[:]); k > 0 {
			b.truncated = true
		}
		return 0, io.EOF
	}
	if rem := b.max - b.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

// verifyStream reads one file, read-only and bounded, through the library's
// own VerifyChain. A file that is swapped for a link between the listing and
// the open is refused rather than followed.
func verifyStream(s stream, maxLine int, maxFile int64) verdict {
	v := verdict{stream: s}
	lst, err := os.Lstat(s.path)
	if err != nil {
		v.err = err
		return v
	}
	if !lst.Mode().IsRegular() {
		v.err = errors.New("not a regular file")
		return v
	}
	f, err := os.Open(s.path) // #nosec G304 -- the operator's own directory, listed and checked regular above
	if err != nil {
		v.err = err
		return v
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil || !os.SameFile(lst, fst) {
		v.err = errors.New("changed identity while being opened")
		return v
	}

	capped := &byteCapReader{r: f, max: maxFile}
	report, err := event.VerifyChain(&lineCapReader{r: capped, max: maxLine, line: 1})
	v.report = report
	v.events = report.Lines - report.Malformed
	if err != nil {
		var long *lineTooLongError
		if errors.As(err, &long) {
			v.err = long
		} else {
			v.err = err
		}
	}
	if capped.truncated {
		if v.err == nil {
			v.err = fmt.Errorf("larger than the %d-byte file cap, so only its first %d bytes were verified", maxFile, maxFile)
		}
	}
	return v
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// alertFor builds the event. Nothing from inside the offending file is copied
// into it except two hash strings, clipped: a forger controls what a prev_hash
// holds, and an alert that quoted it whole would let the forgery decide how big
// the bus's next line is.
func alertFor(f finding) event.Event {
	r := f.verdict.report
	data := map[string]any{
		"file":               f.file,
		"verifier":           "agent-conform " + version,
		"malformed_lines":    r.Malformed,
		"unverifiable_links": len(r.Unverifiable),
	}
	e := event.Event{
		Schema:  event.SchemaV10,
		TS:      watchNow().UTC().Format(time.RFC3339),
		Source:  watchSource,
		Type:    f.typ,
		AgentID: watchAgentID,
		Data:    data,
	}
	switch f.typ {
	case typeChainBroken:
		b := f.brk
		e.Severity = event.SeverityHigh
		data["line"] = b.Line
		data["kind"] = kindMismatch
		data["breaks"] = len(r.Breaks)
		data["restarts"] = max(len(r.HeadLines)-1, 0)
		data["expected"] = clip(b.Expected, maxClippedField)
		data["found"] = clip(b.Found, maxClippedField)
	case typeChainUnchained:
		e.Severity = event.SeverityLow
		data["kind"] = kindUnchained
		data["events"] = f.verdict.events
	}
	return e
}

// loadWatchState reads the state file. Absent is a first run; present and
// unreadable is an error and never a fresh start, because starting over would
// re-send every alert ever sent and, worse, would hide that something rewrote
// the one file that decides what the operator is told.
func loadWatchState(path string) (*watchState, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own flag
	if errors.Is(err, os.ErrNotExist) {
		return &watchState{Schema: stateSchema}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxStateBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxStateBytes)
	}
	var st watchState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("not valid state: %w", err)
	}
	if st.Schema != stateSchema {
		return nil, fmt.Errorf("schema %q, want %q", st.Schema, stateSchema)
	}
	return &st, nil
}

// saveWatchState writes the state through a temporary sibling and a rename, so
// a reader (or a crash) never sees half of it.
func saveWatchState(path string, st *watchState) error {
	st.Schema = stateSchema
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil { // #nosec G306 -- state is not secret
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
