package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests hold the shared-file half of the chain: a ChainedWriter stamps
// prev_hash from the last line ON DISK, under a lock on the file, so writers
// that share one file produce one chain. The ones that need a real
// cross-process lock are in chain_lock_flock_test.go.

// writerEvent is one event from writer w, numbered seq, padded so its line is
// roughly pad bytes longer than an ordinary envelope.
func writerEvent(w, seq, pad int) Event {
	e := Event{
		Schema: SchemaV10, TS: "2026-10-14T12:00:00Z", Source: "chain-lock-test",
		Type: "appended", AgentID: fmt.Sprintf("agent://test.internal/writer-%d", w),
		Data: map[string]any{"writer": w, "seq": seq},
	}
	if pad > 0 {
		e.Data["pad"] = strings.Repeat("p", pad)
	}
	return e
}

// fileLines returns the non-blank lines of path, trimmed, as VerifyChain
// counts them.
func fileLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out [][]byte
	for line := range bytes.Lines(raw) {
		if l := bytes.TrimSpace(line); len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// assertOneChain requires path to hold exactly want events forming ONE
// unbroken chain: one head at line 1, no break, no restart, nothing malformed
// and nothing unverifiable.
func assertOneChain(t *testing.T, path string, want int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	r, err := VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(r.Breaks) > 0 {
		t.Fatalf("%d chain breaks in %d lines, the first at line %d (expected %s, found %s)",
			len(r.Breaks), r.Lines, r.Breaks[0].Line, r.Breaks[0].Expected, r.Breaks[0].Found)
	}
	if r.Lines != want || r.Malformed != 0 || r.Chained != want-1 ||
		len(r.HeadLines) != 1 || r.HeadLines[0] != 1 || len(r.Unverifiable) != 0 {
		t.Fatalf("want one chain of %d events, got %d lines, %d malformed, %d chained, heads %v, unverifiable %v",
			want, r.Lines, r.Malformed, r.Chained, r.HeadLines, r.Unverifiable)
	}
}

func mustWriter(t *testing.T, path string) *ChainedWriter {
	t.Helper()
	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	t.Cleanup(func() { cw.Close() })
	return cw
}

// The interleaving a shared bus produces, made deterministic: A writes, B (a
// second writer on the same file, another process in production) writes, and
// A writes again. A's second event must chain from B's line, which is what is
// on disk, and not from A's own previous line, which is what A remembers.
func TestAWriteChainsFromTheLineAnotherWriterAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	a := mustWriter(t, path)
	b := mustWriter(t, path)

	for i, step := range []struct {
		cw *ChainedWriter
		e  Event
	}{{a, writerEvent(0, 0, 0)}, {b, writerEvent(1, 0, 0)}, {a, writerEvent(0, 1, 0)}} {
		if err := step.cw.Write(step.e); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	lines := fileLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	last, err := Unmarshal(lines[2])
	if err != nil {
		t.Fatalf("line 3: %v", err)
	}
	want, err := ChainHashRaw(lines[1])
	if err != nil {
		t.Fatalf("hash line 2: %v", err)
	}
	if last.PrevHash != want {
		t.Fatalf("line 3 chains from %s, want the hash of line 2 (the other writer's) %s", last.PrevHash, want)
	}
	assertOneChain(t, path, 3)
}

// A writer killed in the middle of a line leaves a fragment with no newline.
// The next append must not be glued onto it: the fragment stays one malformed
// line, and the new event is a line of its own that starts a fresh chain,
// which VerifyChain reports as a restart and never as a break.
func TestAWriteAfterATornTailStartsALineOfItsOwn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)
	if err := cw.Write(writerEvent(0, 0, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	torn, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := torn.WriteString(`{"schema":"taipanbox.dev/agent-event/v1.0","ts":"2026-`); err != nil {
		t.Fatalf("tear: %v", err)
	}
	torn.Close()

	after := mustWriter(t, path)
	if err := after.Write(writerEvent(1, 0, 0)); err != nil {
		t.Fatalf("write after the tear: %v", err)
	}

	events, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want both events readable after the fragment, got %d", len(events))
	}
	if events[1].PrevHash != "" {
		t.Fatalf("the event after a fragment must start a fresh chain, got prev_hash %s", events[1].PrevHash)
	}
	f, _ := os.Open(path)
	defer f.Close()
	r, err := VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !r.Ok() || r.Lines != 3 || r.Malformed != 1 || len(r.HeadLines) != 2 || r.HeadLines[1] != 3 {
		t.Fatalf("want 3 lines, the fragment malformed and a restart at line 3, got %+v", r)
	}
}

// A last line longer than the first read from the end is still found, by
// reading further back, and the next event chains from it.
func TestALastLineLongerThanOneReadStillChains(t *testing.T) {
	for _, pad := range []int{tailChunk - 200, tailChunk, 3 * tailChunk, resumeWindow - 4096} {
		t.Run(fmt.Sprint(pad), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bus.ndjson")
			cw := mustWriter(t, path)
			for i, e := range []Event{writerEvent(0, 0, 0), writerEvent(0, 1, pad), writerEvent(0, 2, 0)} {
				if err := cw.Write(e); err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
			}
			assertOneChain(t, path, 3)
		})
	}
}

// A last line longer than resumeWindow is longer than VerifyChain will read,
// so nothing could verify a link to it: the next event starts a fresh chain
// rather than the writer reading without bound.
func TestALastLineLongerThanTheWindowStartsAFreshChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)
	if err := cw.Write(writerEvent(0, 0, resumeWindow)); err != nil {
		t.Fatalf("write the long line: %v", err)
	}
	if err := cw.Write(writerEvent(0, 1, 0)); err != nil {
		t.Fatalf("write after it: %v", err)
	}
	lines := fileLines(t, path)
	if len(lines) != 2 || len(lines[0]) <= resumeWindow {
		t.Fatalf("want a line over the window and one after it, got %d lines", len(lines))
	}
	e, err := Unmarshal(lines[1])
	if err != nil {
		t.Fatalf("line 2: %v", err)
	}
	if e.PrevHash != "" {
		t.Fatalf("an event after a line over the window must start fresh, got %s", e.PrevHash)
	}
}

// Blank lines at the end of a file are not lines: a writer chains from the
// last event before them, and a file of nothing but blank lines is a head.
func TestBlankLinesAtTheEndAreSkippedAndABlankFileIsAHead(t *testing.T) {
	t.Run("after an event", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bus.ndjson")
		cw := mustWriter(t, path)
		if err := cw.Write(writerEvent(0, 0, 0)); err != nil {
			t.Fatalf("write: %v", err)
		}
		pad := "\n \n\t\r\n" + strings.Repeat(" ", 3*tailChunk) + "\n"
		if err := appendRaw(path, pad); err != nil {
			t.Fatalf("pad: %v", err)
		}
		if err := cw.Write(writerEvent(0, 1, 0)); err != nil {
			t.Fatalf("write: %v", err)
		}
		assertOneChain(t, path, 2)
	})
	t.Run("only blanks", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bus.ndjson")
		if err := os.WriteFile(path, []byte("\n  \n\t"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		cw := mustWriter(t, path)
		if cw.ResumedFrom() != "" {
			t.Fatalf("a blank file resumes nothing, got %s", cw.ResumedFrom())
		}
		if err := cw.Write(writerEvent(0, 0, 0)); err != nil {
			t.Fatalf("write: %v", err)
		}
		f, _ := os.Open(path)
		defer f.Close()
		r, err := VerifyChain(f)
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		// Physical line 4: three blank lines, the last given its newline.
		if !r.Ok() || r.Lines != 1 || r.Malformed != 0 || len(r.HeadLines) != 1 || r.HeadLines[0] != 4 {
			t.Fatalf("want one head event on line 4, got %+v", r)
		}
	})
}

func appendRaw(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(s)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Nothing is appended when the file cannot be locked: an unlocked append to a
// shared file is the fault the lock exists to prevent. A writer whose file
// cannot be locked at all fails when it is opened, not on its first event.
func TestNothingIsWrittenWhenTheFileCannotBeLocked(t *testing.T) {
	denied := errors.New("lock denied")
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)
	if err := cw.Write(writerEvent(0, 0, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}

	lockForAppend = func(*os.File) error { return denied }
	t.Cleanup(func() { lockForAppend = lockExclusive })

	if err := cw.Write(writerEvent(0, 1, 0)); !errors.Is(err, denied) {
		t.Fatalf("Write with the lock refused: got %v, want %v", err, denied)
	}
	if n := len(fileLines(t, path)); n != 1 {
		t.Fatalf("an event was appended without the lock: %d lines", n)
	}
	if _, err := NewChainedWriter(path); !errors.Is(err, denied) {
		t.Fatalf("NewChainedWriter on a file that cannot be locked: got %v, want %v", err, denied)
	}
}

// A failure to RELEASE the lock is reported, though the line is on disk: a
// lock that may still be held stalls every other writer of the file.
func TestAFailureToReleaseTheLockIsReported(t *testing.T) {
	stuck := errors.New("unlock failed")
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)

	unlockAfterAppend = func(f *os.File) error {
		unlockFile(f)
		return stuck
	}
	t.Cleanup(func() { unlockAfterAppend = unlockFile })

	if err := cw.Write(writerEvent(0, 0, 0)); !errors.Is(err, stuck) {
		t.Fatalf("Write: got %v, want %v", err, stuck)
	}
	if n := len(fileLines(t, path)); n != 1 {
		t.Fatalf("the line should be on disk despite the unlock error: %d lines", n)
	}
	if _, err := NewChainedWriter(path); !errors.Is(err, stuck) {
		t.Fatalf("NewChainedWriter: got %v, want %v", err, stuck)
	}
}

// A tail that cannot be read leaves nothing to chain from, and nothing is
// written: guessing a head there would hide whatever made the read fail.
func TestNothingIsWrittenWhenTheTailCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	lockForAppend = func(*os.File) error { return nil }
	unlockAfterAppend = func(*os.File) error { return nil }
	t.Cleanup(func() { lockForAppend, unlockAfterAppend = lockExclusive, unlockFile })

	cw.file.Close() // every read of it now fails
	if err := cw.Write(writerEvent(0, 0, 0)); err == nil || !strings.Contains(err.Error(), "read tail") {
		t.Fatalf("Write over an unreadable tail: got %v, want a read tail error", err)
	}
}

// An event whose line could not be hashed by the next writer would end the
// chain at it, so it is refused rather than written.
func TestAnEventTheNextWriterCouldNotHashIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	cw := mustWriter(t, path)
	e := writerEvent(0, 0, 0)
	e.Data["n"] = json.Number("1e999")
	if err := cw.Write(e); err == nil {
		t.Fatalf("Write of an event JCS cannot canonicalize: got nil")
	}
	if n := len(fileLines(t, path)); n != 0 {
		t.Fatalf("a refused event reached the file: %d lines", n)
	}
}
