//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package event

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// probeWriterLock asks, without waiting, whether another open file description
// of path could take the exclusive lock right now. A nil result means it could,
// and the probe then gives the lock back. Two descriptors of one file exclude
// each other under flock(2) exactly as two processes do.
func probeWriterLock(t *testing.T, path string) error {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s for the probe: %v", path, err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// Another open file cannot take the lock while a plain Writer appends. This is
// the property that stops two nodes on an NFS share from overwriting each
// other's lines, and it is measured on the probe, not inferred from timing.
func TestTheWriterLockIsHeldWhileTheLineIsAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	var seen error
	testHookWriterBeforeAppend = func() { seen = probeWriterLock(t, path) }
	t.Cleanup(func() { testHookWriterBeforeAppend = func() {} })

	if err := w.Write(writerTestEvent(1)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !errors.Is(seen, syscall.EWOULDBLOCK) {
		t.Fatalf("another open file could lock the file while the line was being appended (probe: %v)", seen)
	}
	if err := probeWriterLock(t, path); err != nil {
		t.Fatalf("the lock was still held after Write returned: %v", err)
	}
}

// A plain Writer waits for a lock another writer holds, rather than appending
// over it. The other holder is a second open file of the same path, standing
// in for a writer in another process.
func TestAWriteWaitsForAnotherWritersLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("holder takes the lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.Write(writerTestEvent(1)) }()
	select {
	case err := <-done:
		t.Fatalf("Write returned (%v) while another open file held the lock", err)
	case <-time.After(200 * time.Millisecond):
	}

	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("holder releases the lock: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write after the lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write did not return after the other lock was released")
	}
	if n := len(fileLines(t, path)); n != 1 {
		t.Fatalf("lines after the waited write: %d, want 1", n)
	}
}

// A panic while appending still releases the lock, so a recovering caller
// cannot leave every other writer of the file waiting. The probe runs first,
// so the test also shows the lock was held when the panic came.
func TestTheWriterLockIsReleasedWhenAnAppendPanics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	var seen error
	testHookWriterBeforeAppend = func() {
		seen = probeWriterLock(t, path)
		panic("append aborted")
	}
	t.Cleanup(func() { testHookWriterBeforeAppend = func() {} })

	func() {
		defer func() { _ = recover() }()
		_ = w.Write(writerTestEvent(1))
	}()
	if !errors.Is(seen, syscall.EWOULDBLOCK) {
		t.Fatalf("the lock was not held when the append panicked (probe: %v)", seen)
	}
	if err := probeWriterLock(t, path); err != nil {
		t.Fatalf("the lock was still held after the panic: %v", err)
	}
}
