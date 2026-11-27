package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The edges of watch-dir that invariant 25 names in one sentence each: a pass
// that cannot do its job is exit 2 and never a pass, an alert already on the bus
// whose state could not be saved is said out loud, and the verifier's own stream
// is verified wherever it lives.

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file, so the unreadable case cannot be built")
	}
}

func TestWatchDirHelpGoesToStdoutAndExitsZero(t *testing.T) {
	r := runWatch(t, "-h")
	if r.code != 0 {
		t.Fatalf("-h: exit %d, want 0\n%s", r.code, r.stderr)
	}
	if !strings.HasPrefix(r.stdout, "usage: agent-conform watch-dir [flags] <dir>") || r.stderr != "" {
		t.Fatalf("-h prints the usage to stdout and nothing to stderr:\nstdout %q\nstderr %q", r.stdout, r.stderr)
	}
	bad := runWatch(t, "-nope", t.TempDir())
	if !strings.Contains(bad.stderr, "flag provided but not defined: -nope") || !strings.Contains(bad.stderr, "usage: agent-conform watch-dir") {
		t.Fatalf("an unknown flag names itself and prints the usage to stderr:\n%s", bad.stderr)
	}
}

func TestWatchDirEveryOutsideItsRangeIsAUsageError(t *testing.T) {
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 2)
	for _, every := range []string{"-1s", "1ms", "9s"} {
		r := runWatch(t, "-every", every, dir)
		if r.code != 2 || !strings.Contains(r.stderr, "-every must be 0 (one pass, then exit) or at least 10s") {
			t.Errorf("-every %s: exit %d, want 2 naming the range\n%s", every, r.code, r.stderr)
		}
	}
	if len(busOut(t, dir)) != 0 {
		t.Fatal("a usage error wrote to the bus")
	}
}

// -out elsewhere: the alerts stream is still a stream, and a break in it is
// found like a break anywhere else.
func TestWatchDirVerifiesItsOwnStreamWhenItLivesOutsideTheBus(t *testing.T) {
	bus := t.TempDir()
	chainedStream(t, bus, "wardryx", 3)
	work := t.TempDir()
	own := chainedStream(t, work, "agent-conform", 4)
	flipByte(t, own, 2)

	r := runWatch(t, "-out", own, "-state", filepath.Join(work, "state.json"), bus)
	if r.code != 1 {
		t.Fatalf("a break in the verifier's own stream is a new break: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "2 stream(s)") {
		t.Errorf("the walk must count the bus stream and the verifier's own:\n%s", r.stdout)
	}
	var broken []event.Event
	for _, e := range readStream(t, own) {
		if e.Type == "chain_broken" {
			broken = append(broken, e)
		}
	}
	if len(broken) != 1 || broken[0].Data["file"] != "agent-conform.ndjson" {
		t.Fatalf("want one chain_broken naming agent-conform.ndjson, got %+v", broken)
	}
}

func TestWatchDirAnAlertWhoseStateCannotBeSavedIsExitTwoAndStillOnTheBus(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 5), 3)
	state := filepath.Join(t.TempDir(), "gone", "state.json") // its directory does not exist

	r := runWatch(t, "-state", state, dir)
	if r.code != 2 {
		t.Fatalf("a state that could not be saved is exit 2, got %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "the alert for wardryx.ndjson is on the bus and may be repeated") {
		t.Errorf("the operator must be told the alert may repeat:\n%s", r.stderr)
	}
	if got := busOut(t, dir); len(got) != 1 || got[0].Type != "chain_broken" {
		t.Fatalf("the alert was written before the state, so it is on the bus: %+v", got)
	}
}

func TestWatchDirARefusalWhoseStateCannotBeSavedIsExitTwo(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newWdSigner(t)
	stream := filepath.Join(dir, "wardryx.ndjson")
	wdCheckpointed(t, dir, ck, s, "wardryx.ndjson", 3)
	b, err := os.ReadFile(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stream, []byte(strings.Replace(string(b), ":", ": ", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "gone", "state.json")

	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", wdKeysFile(t, dir, s), "-state", state, dir)
	if r.code != 2 || !strings.Contains(r.stderr, "a checkpoint refusal may be repeated") {
		t.Fatalf("a refusal that could not be remembered is exit 2 and says so: exit %d\n%s", r.code, r.stderr)
	}
}

func TestWatchDirAnOutputThatCannotBeOpenedIsExitTwo(t *testing.T) {
	dir := t.TempDir()
	flipByte(t, chainedStream(t, dir, "wardryx", 5), 3)
	out := filepath.Join(t.TempDir(), "gone", "agent-conform.ndjson")

	r := runWatch(t, "-out", out, dir)
	if r.code != 2 || !strings.Contains(r.stderr, "cannot open output") {
		t.Fatalf("a break with nowhere to report it is exit 2, never 1 or 0: exit %d\n%s", r.code, r.stderr)
	}
}

func TestWatchDirAStateFileItDidNotWriteIsAnError(t *testing.T) {
	for name, c := range map[string]struct{ content, why string }{
		"another schema": {`{"schema":"agent-conform/watch-state/v0","reported":[]}`, `schema "agent-conform/watch-state/v0", want "agent-conform/watch-state/v1"`},
		"oversize":       {`{"schema":"agent-conform/watch-state/v1","pad":"` + strings.Repeat("x", 4<<20) + `"}`, "larger than 4194304 bytes"},
	} {
		content := c.content
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			flipByte(t, chainedStream(t, dir, "wardryx", 5), 3)
			state := filepath.Join(dir, "agent-conform.state.json")
			if err := os.WriteFile(state, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			r := runWatch(t, dir)
			if r.code != 2 || !strings.Contains(r.stderr, "agent-conform watch-dir: state "+state+": "+c.why) {
				t.Fatalf("exit %d, want 2 naming the state file and %q\n%s", r.code, c.why, r.stderr)
			}
			if len(busOut(t, dir)) != 0 {
				t.Fatal("alerts were written against a state file this verifier did not write")
			}
		})
	}
	st, err := loadWatchState(filepath.Join(t.TempDir(), "x.json"))
	if err != nil || st.Schema != stateSchema || len(st.Reported) != 0 {
		t.Fatalf("an absent state is a first run: %+v, %v", st, err)
	}
	if _, err := loadWatchState(t.TempDir()); err == nil {
		t.Fatal("a directory where the state file should be is an error, not a first run")
	}
}

func TestWatchDirAnUnreadableStateOrBusIsAnError(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	chainedStream(t, dir, "wardryx", 3)
	state := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(state, []byte(`{"schema":"agent-conform/watch-state/v1"}`), 0o000); err != nil {
		t.Fatal(err)
	}
	if r := runWatch(t, "-state", state, dir); r.code != 2 || !strings.Contains(r.stderr, "permission denied") {
		t.Fatalf("an unreadable state: exit %d, want 2\n%s", r.code, r.stderr)
	}

	bus := t.TempDir()
	chainedStream(t, bus, "wardryx", 3)
	if err := os.Chmod(bus, 0o300); err != nil { // enter, not list
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bus, 0o755) })
	work := t.TempDir()
	r := runWatch(t, "-out", filepath.Join(work, "agent-conform.ndjson"), "-state", filepath.Join(work, "s.json"), bus)
	if r.code != 2 || !strings.Contains(r.stderr, "permission denied") {
		t.Fatalf("a bus that cannot be listed: exit %d, want 2\n%s", r.code, r.stderr)
	}
}

func TestVerifyStreamRefusesWhatItCannotOpenAsARegularFile(t *testing.T) {
	dir := t.TempDir()
	if v := verifyStream(stream{name: "gone.ndjson", path: filepath.Join(dir, "gone.ndjson")}, defaultMaxLine, defaultMaxFile); !errors.Is(v.err, os.ErrNotExist) {
		t.Errorf("a stream gone between the listing and the read: %v, want not-exist", v.err)
	}
	sub := filepath.Join(dir, "d.ndjson")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if v := verifyStream(stream{name: "d.ndjson", path: sub}, defaultMaxLine, defaultMaxFile); v.err == nil || v.err.Error() != "not a regular file" {
		t.Errorf("a directory in a stream's place: %v, want not a regular file", v.err)
	}
	skipIfRoot(t)
	locked := chainedStream(t, dir, "locked", 2)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	if v := verifyStream(stream{name: "locked.ndjson", path: locked}, defaultMaxLine, defaultMaxFile); !errors.Is(v.err, os.ErrPermission) {
		t.Errorf("an unreadable stream: %v, want permission denied", v.err)
	}
}

// ---------------------------------------------------------------------------
// the checkpoint sidecar's edges
// ---------------------------------------------------------------------------

func ckSetup(t *testing.T) (dir, ck string, s *wdSigner) {
	t.Helper()
	dir = t.TempDir()
	ck = filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, ck, newWdSigner(t)
}

func TestWatchDirAStreamWithNoSidecarIsANoteNotAFailure(t *testing.T) {
	dir, ck, s := ckSetup(t)
	chainedStream(t, dir, "wardryx", 3)
	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", wdKeysFile(t, dir, s), dir)
	if r.code != 0 || !strings.Contains(r.stdout, "NOTE wardryx.ndjson: no checkpoint sidecar") {
		t.Fatalf("exit %d, want 0 with a note\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestWatchDirASidecarItCannotVerifyIsExitTwo(t *testing.T) {
	for name, c := range map[string]struct {
		build func(t *testing.T, side string)
		why   string
	}{
		"a directory": {why: "the sidecar is not a regular file", build: func(t *testing.T, side string) {
			if err := os.Mkdir(side, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		"empty": {why: "no checkpoint record to verify", build: func(t *testing.T, side string) {
			if err := os.WriteFile(side, nil, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			dir, ck, s := ckSetup(t)
			chainedStream(t, dir, "wardryx", 3)
			c.build(t, filepath.Join(ck, event.CheckpointFileName("wardryx.ndjson")))
			r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", wdKeysFile(t, dir, s), dir)
			if r.code != 2 || !strings.Contains(r.stderr, "ERROR wardryx.ndjson: checkpoints: ") || !strings.Contains(r.stderr, c.why) {
				t.Fatalf("a sidecar that checked nothing is exit 2: exit %d\n%s%s", r.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestCheckStreamCheckpointsRefusesWhatItCannotRead(t *testing.T) {
	dir, ck, s := ckSetup(t)
	wdCheckpointed(t, dir, ck, s, "wardryx.ndjson", 4)
	ks := map[string]*ecdsa.PublicKey{s.kid: &s.key.PublicKey}

	st := stream{name: "wardryx.ndjson", path: filepath.Join(dir, "wardryx.ndjson")}
	// Lines after the last record's count are outside every checkpoint; they
	// only make the stream outgrow its sidecar for the cap case below.
	if err := appendText(st.path, `{"pad":"`+strings.Repeat("x", 4096)+`"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	if _, present, err := checkStreamCheckpoints(st, ck, ks, defaultMaxFile); err != nil || !present {
		t.Fatalf("control: an intact sidecar verifies: present %v, %v", present, err)
	}
	// A cap the sidecar fits in exactly and the stream does not: every record is
	// read, the stream is not read to its end, and that is not a pass.
	side, err := os.Stat(filepath.Join(ck, event.CheckpointFileName("wardryx.ndjson")))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.Stat(st.path)
	if err != nil || body.Size() <= side.Size() {
		t.Fatalf("fixture: the stream (%v) must be larger than its sidecar (%d bytes)", body, side.Size())
	}
	_, present, err := checkStreamCheckpoints(st, ck, ks, side.Size())
	if err == nil || !present || !strings.Contains(err.Error(), fmt.Sprintf("larger than the %d-byte file cap", side.Size())) {
		t.Fatalf("a stream over the cap was not checked to its end and must say so: present %v, %v", present, err)
	}
	gone := stream{name: "wardryx.ndjson", path: filepath.Join(dir, "moved.ndjson")}
	if _, present, err := checkStreamCheckpoints(gone, ck, ks, defaultMaxFile); !errors.Is(err, os.ErrNotExist) || !present {
		t.Fatalf("a stream that vanished after the listing: present %v, %v", present, err)
	}
	skipIfRoot(t)
	sidePath := filepath.Join(ck, event.CheckpointFileName("wardryx.ndjson"))
	if err := os.Chmod(sidePath, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, present, err := checkStreamCheckpoints(st, ck, ks, defaultMaxFile); !errors.Is(err, os.ErrPermission) || present {
		t.Fatalf("an unreadable sidecar is an error, never absent: present %v, %v", present, err)
	}
}

func TestLoadCheckpointKeysRefusesAFileItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadCheckpointKeys(filepath.Join(dir, "none.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing keys file: %v", err)
	}
	if _, err := loadCheckpointKeys(dir); err == nil {
		t.Error("a directory as the keys file must be refused")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`{"k":"`+strings.Repeat("x", 64<<10)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpointKeys(big); err == nil || err.Error() != "larger than 65536 bytes" {
		t.Errorf("an oversize keys file: %v", err)
	}
}

func TestARestartAtTheHeadIsNeverExplained(t *testing.T) {
	if explainedBy([]int{0}, 0) {
		t.Fatal("a restart with no line before it cannot be explained by a resume record, even one naming line 0")
	}
	if !explainedBy([]int{2, 5}, 5) || explainedBy([]int{2, 5}, 4) {
		t.Fatal("a restart after line N is explained by a resume record naming N, and only N")
	}
}

// readStream reads every event of one stream file.
func readStream(t *testing.T, path string) []event.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []event.Event
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if e, err := event.Unmarshal([]byte(line)); err == nil {
			out = append(out, e)
		}
	}
	return out
}
