package event

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These tests hold the plain Writer's half of the shared-file rule: a Writer
// that another process also appends to takes the same exclusive lock on the
// file that ChainedWriter takes, for the length of one append. The tests that
// need a real flock(2) probe are in writer_lock_flock_test.go.

// writerTestEvent is one event numbered seq, for the plain Writer tests.
func writerTestEvent(seq int) Event {
	return Event{
		Schema: SchemaV10, TS: "2026-10-14T12:00:00Z", Source: "writer-lock-test",
		Type: "appended", AgentID: "agent://test.internal/writer",
		Data: map[string]any{"seq": seq},
	}
}

// Nothing is appended when the Writer cannot take the file lock: an unlocked
// append to a shared file is the fault the lock exists to prevent.
func TestNothingIsWrittenWhenTheWriterCannotBeLocked(t *testing.T) {
	denied := errors.New("lock denied")
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if err := w.Write(writerTestEvent(0)); err != nil {
		t.Fatalf("write: %v", err)
	}

	lockForWrite = func(*os.File) error { return denied }
	t.Cleanup(func() { lockForWrite = lockExclusive })

	if err := w.Write(writerTestEvent(1)); !errors.Is(err, denied) {
		t.Fatalf("Write with the lock refused: got %v, want %v", err, denied)
	}
	if n := len(fileLines(t, path)); n != 1 {
		t.Fatalf("an event was appended without the lock: %d lines, want 1", n)
	}
}

// A failure to RELEASE the lock is reported, although the line is on disk: a
// lock that may still be held stalls every other writer of the file, so the
// caller must learn of it.
func TestAFailureToReleaseTheWriterLockIsReported(t *testing.T) {
	stuck := errors.New("unlock failed")
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	unlockAfterWrite = func(*os.File) error { return stuck }
	t.Cleanup(func() { unlockAfterWrite = unlockFile })

	if err := w.Write(writerTestEvent(0)); !errors.Is(err, stuck) {
		t.Fatalf("Write with the unlock failing: got %v, want %v", err, stuck)
	}
	if n := len(fileLines(t, path)); n != 1 {
		t.Fatalf("the line is not on disk after a failed unlock: %d lines, want 1", n)
	}
}
