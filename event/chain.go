// The prev_hash integrity chain (agent-passport SPEC §6.5).
//
// Where a product maintains a chain, each event's prev_hash MUST be
//
//	"sha256:" + hex(sha256(C))
//
// where C is the RFC 8785 (JSON Canonicalization Scheme) serialization of
// the PREVIOUS event object with its own prev_hash field removed. The chain
// makes an append-only NDJSON stream tamper-evident: editing or dropping a
// line breaks every hash after it, and a verifier (VerifyChain here, or
// `agent-conform -chain`) can say exactly where.
//
// Honest limits, stated up front: prev_hash is tamper-EVIDENCE, not
// tamper-PROOF. An attacker who can rewrite the whole file can re-chain it;
// the chain's value is that a partial edit, an accidental truncation, or a
// reordered shipment no longer passes silently. The spec keeps the field
// optional, so a stream may legally contain chain restarts (an event with no
// prev_hash after line one - a process restart that could not resume, say);
// VerifyChain reports those separately from breaks, and only a genuine
// mismatch is a break.

package event

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gowebpki/jcs"
)

// ChainHashPrefix is the required prefix of every prev_hash value
// (SPEC §6.5: `^sha256:[0-9a-f]{64}$`).
const ChainHashPrefix = "sha256:"

// resumeWindow is how far back NewChainedWriter reads when seeding the
// chain from an existing file's tail. One complete event line always fits:
// the schema caps nothing, but real envelopes are hundreds of bytes; 1 MiB
// of slack is orders of magnitude beyond any line this stack writes (and
// matches Scan's own max line buffer).
const resumeWindow = 1 << 20

// Canonicalize returns the RFC 8785 (JCS) canonical serialization of e with
// the prev_hash field removed - the exact byte string SPEC §6.5 defines as
// the hash input. The removal is by construction, not by string surgery:
// the field is cleared on a copy before marshaling, and `omitempty` keeps
// it out of the JSON entirely.
func Canonicalize(e Event) ([]byte, error) {
	e.PrevHash = ""
	data, err := Marshal(e)
	if err != nil {
		return nil, err
	}
	canonical, err := jcs.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("event: canonicalize: %w", err)
	}
	return canonical, nil
}

// ChainHash returns the SPEC §6.5 hash of e: the value the NEXT event in a
// chained stream carries as its prev_hash.
func ChainHash(e Event) (string, error) {
	canonical, err := Canonicalize(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return ChainHashPrefix + hex.EncodeToString(sum[:]), nil
}

// ChainedWriter is Writer plus the SPEC §6.5 prev_hash chain: every event
// written carries the hash of the event before it, under the same mutex
// that already serializes the underlying NDJSON writes (a chain needs a
// single serialization point, and the writer's lock is exactly that).
//
// The writer is the chain's authority: whatever a caller left in
// Event.PrevHash is overwritten (head events get none). On open, an
// existing file's tail is re-parsed to RESUME its chain, so one file stays
// one chain across process restarts; an unreadable or malformed tail
// starts a fresh chain instead of refusing to write - the exporters this
// package mirrors are fail-open by contract, and a verifier will surface
// the restart honestly rather than the process going quiet.
type ChainedWriter struct {
	mu   sync.Mutex
	file *os.File
	// prev_hash for the NEXT event; "" while at a chain head.
	next string
	// what the chain resumed from at open ("" = fresh chain).
	resumedFrom string
}

// NewChainedWriter opens path for append (creating it if absent) and seeds
// the chain from the last well-formed event line already in the file, if
// any.
func NewChainedWriter(path string) (*ChainedWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("event: open %s: %w", path, err)
	}
	cw := &ChainedWriter{file: f}
	if last, ok := tailEvent(f); ok {
		if h, err := ChainHash(last); err == nil {
			cw.next = h
			cw.resumedFrom = h
		}
	}
	return cw, nil
}

// ResumedFrom reports the hash this writer's chain resumed from at open, or
// "" when it started fresh (empty file, or an unreadable/malformed tail).
func (cw *ChainedWriter) ResumedFrom() string {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.resumedFrom
}

// Write stamps e with the chain's current prev_hash (none at a head),
// appends it as one NDJSON line, and advances the chain to hash(e). Safe
// for concurrent use; on a write error the chain does not advance, so the
// next successful write re-links to the last line actually on disk.
func (cw *ChainedWriter) Write(e Event) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	e.PrevHash = cw.next
	data, err := Marshal(e)
	if err != nil {
		return err
	}
	next, err := ChainHash(e)
	if err != nil {
		return err
	}
	if _, err := cw.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("event: write: %w", err)
	}
	cw.next = next
	return nil
}

// Close closes the underlying file.
func (cw *ChainedWriter) Close() error {
	return cw.file.Close()
}

// tailEvent returns the last well-formed event in f, reading at most
// resumeWindow bytes from the end. false when the file is empty or its last
// non-blank line does not parse as an event.
func tailEvent(f *os.File) (Event, bool) {
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return Event{}, false
	}
	start := info.Size() - resumeWindow
	skipFirst := start > 0 // a mid-file cut: the first scanned line is partial
	if start < 0 {
		start = 0
	}
	buf := make([]byte, info.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return Event{}, false
	}

	var last []byte
	first := true
	for line := range bytes.Lines(buf) {
		if first && skipFirst {
			first = false
			continue
		}
		first = false
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			last = trimmed
		}
	}
	if last == nil {
		return Event{}, false
	}
	e, err := Unmarshal(last)
	if err != nil {
		return Event{}, false
	}
	return e, true
}

// ChainBreak is one genuine chain violation: an event whose prev_hash is
// present but does not match the hash of the event on the line before it.
type ChainBreak struct {
	// 1-based physical line number in the stream.
	Line int
	// The hash of the preceding event (what prev_hash should have been).
	Expected string
	// What the line actually carried.
	Found string
}

// ChainReport is VerifyChain's summary of one NDJSON stream.
type ChainReport struct {
	// Physical non-blank lines seen, and how many of them failed to parse
	// as events (malformed lines also make the FOLLOWING event
	// unverifiable, since there is no previous event to hash).
	Lines     int
	Malformed int
	// Events carrying a prev_hash that verified against the previous event.
	Chained int
	// Chain heads: events with no prev_hash. Line one is the expected head;
	// each later head is a chain restart (legal per the spec, worth seeing).
	HeadLines []int
	// Events whose prev_hash could not be checked because the preceding
	// line was malformed (1-based line numbers).
	Unverifiable []int
	// Genuine mismatches.
	Breaks []ChainBreak
}

// Ok reports whether the stream contained no genuine breaks. Restarts and
// unverifiable lines do not fail a stream: the field is optional by spec,
// and a malformed line is already reported as malformed.
func (r ChainReport) Ok() bool {
	return len(r.Breaks) == 0
}

// VerifyChain checks the SPEC §6.5 chain over one NDJSON stream. Blank
// lines are skipped; malformed lines are counted (and poison verification
// of exactly the next chained event, reported in Unverifiable). It reads
// the whole stream; the caller owns rewinding/closing r.
func VerifyChain(r io.Reader) (ChainReport, error) {
	var report ChainReport

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNo := 0
	prevHash := ""    // hash of the previous well-formed event
	prevSeen := false // any previous event at all? (a rotated segment may open mid-chain)
	prevKnown := true // false right after a malformed line
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		report.Lines++

		e, err := Unmarshal(line)
		if err != nil {
			report.Malformed++
			prevKnown = false
			continue
		}

		switch {
		case e.PrevHash == "":
			report.HeadLines = append(report.HeadLines, lineNo)
		case !prevSeen || !prevKnown:
			// A prev_hash with nothing checkable before it: either the
			// stream OPENS mid-chain (a rotated segment) or the preceding
			// line was malformed. Reported, never called a break - there is
			// no expected value to accuse it of missing.
			report.Unverifiable = append(report.Unverifiable, lineNo)
		case e.PrevHash == prevHash:
			report.Chained++
		default:
			report.Breaks = append(report.Breaks, ChainBreak{
				Line:     lineNo,
				Expected: prevHash,
				Found:    e.PrevHash,
			})
		}
		prevSeen = true

		h, err := ChainHash(e)
		if err != nil {
			// Hashing our own parsed event cannot realistically fail
			// (Marshal of a decoded Event), but stay honest if it does.
			prevKnown = false
			continue
		}
		prevHash = h
		prevKnown = true
	}
	if err := sc.Err(); err != nil {
		return report, fmt.Errorf("event: verify chain: %w", err)
	}
	return report, nil
}
