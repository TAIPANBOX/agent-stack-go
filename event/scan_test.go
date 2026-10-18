package event

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

// The line scanner under the checkpoint writer and verifier: its digests are
// taken at line boundaries, a fragment after the last LF is undone by settle, and
// a line over its cap is emitted long and still hashed.

func TestALineScannerTakesEachDigestAtItsLineBoundary(t *testing.T) {
	in := "one\ntwo\nthr"
	sum := sha256.New()
	sc := newLineScanner(sum, 0, nil, 0, 100, true)
	var got []string
	err := sc.run(strings.NewReader(in), func(line []byte, long bool, end int64) error {
		want := sha256.Sum256([]byte(in[:end]))
		if !bytes.Equal(sum.Sum(nil), want[:]) {
			t.Fatalf("at offset %d the digest is not the digest of the bytes through that LF", end)
		}
		got = append(got, string(line))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("two complete lines, got %q", got)
	}
	if err := sc.settle(); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("one\ntwo\n"))
	if !bytes.Equal(sum.Sum(nil), want[:]) {
		t.Fatalf("settle must undo the fragment after the last LF")
	}
}

func TestALineOverItsCapIsEmittedLongAndStillHashed(t *testing.T) {
	in := "short\n" + strings.Repeat("y", 50) + "\nafter\n"
	sum := sha256.New()
	sc := newLineScanner(sum, 0, nil, 0, 10, true)
	var lines []string
	var longs []bool
	err := sc.run(strings.NewReader(in), func(line []byte, long bool, end int64) error {
		lines = append(lines, string(line))
		longs = append(longs, long)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0] != "short" || !longs[1] || lines[1] != "" || lines[2] != "after" {
		t.Fatalf("the long line is emitted without content and the others as they are: %q %v", lines, longs)
	}
	want := sha256.Sum256([]byte(in))
	if !bytes.Equal(sum.Sum(nil), want[:]) {
		t.Fatalf("a long line's bytes are still part of the prefix")
	}
}

// A fragment with no LF at all leaves no boundary to return to: settle goes back to
// the fresh digest.
func TestSettleWithNoLineBoundaryReturnsToTheFreshDigest(t *testing.T) {
	sum := sha256.New()
	sc := newLineScanner(sum, 0, nil, 0, 100, true)
	if err := sc.run(strings.NewReader("no newline here"), func([]byte, bool, int64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := sc.settle(); err != nil {
		t.Fatal(err)
	}
	fresh := sha256.Sum256(nil)
	if !bytes.Equal(sum.Sum(nil), fresh[:]) {
		t.Fatalf("with no LF the digest must be the fresh one")
	}
}
