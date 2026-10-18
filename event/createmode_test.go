package event

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Scenarios: features/checkpoints.feature (F-021: writers create 0640 and never
// create a file in a directory they do not own).

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s: mode %o, want %o", path, got, want)
	}
}

func TestNewWriterCreatesTheStreamMode0640(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wardryx.ndjson")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	assertMode(t, path, 0o640)
}

func TestNewChainedWriterCreatesTheStreamMode0640(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wardryx.ndjson")
	w, err := NewChainedWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	assertMode(t, path, 0o640)
}

func TestAWriterCreatesNoFileInADirectoryItDoesNotOwn(t *testing.T) {
	ckForeignDir(t)
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.ndjson")
	if _, err := NewWriter(plain); err == nil {
		t.Fatalf("NewWriter created a stream in a directory this process does not own")
	}
	if _, err := os.Stat(plain); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file appeared in a foreign directory: %v", err)
	}
	chained := filepath.Join(dir, "chained.ndjson")
	if _, err := NewChainedWriter(chained); err == nil {
		t.Fatalf("NewChainedWriter created a stream in a directory this process does not own")
	}
	if _, err := os.Stat(chained); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file appeared in a foreign directory: %v", err)
	}
}

func TestAWriterStillAppendsToAnExistingStreamInAForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	path := ckStream(t, dir, "wardryx.ndjson", 1)
	ckForeignDir(t)
	w, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("an existing stream is opened even where its directory is not ours: %v", err)
	}
	if err := w.Write(ckEvent(2)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if n := len(fileLines(t, path)); n != 2 {
		t.Fatalf("want 2 lines, got %d", n)
	}
}
