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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"unicode"

	"github.com/gowebpki/jcs"
)

// ChainHashPrefix is the required prefix of every prev_hash value
// (SPEC §6.5: `^sha256:[0-9a-f]{64}$`).
const ChainHashPrefix = "sha256:"

// resumeWindow is the longest last line a ChainedWriter will look back for
// when it reads the tail of its file, which it does before every append. It
// is VerifyChain's own line cap, so any line the verifier can judge, a writer
// can chain from; a last line longer than this starts a fresh chain, which
// VerifyChain reports as a restart and never as a break. Real envelopes are
// hundreds of bytes, so the search almost always ends in its first read.
const resumeWindow = 4 << 20

// tailChunk is the first read from the end of the file, doubled while the
// last line has not been found and resumeWindow has not been reached.
const tailChunk = 8 << 10

// Canonicalize returns the RFC 8785 (JCS) canonical serialization of e with
// the prev_hash field removed. The removal is by construction, not by string
// surgery: the field is cleared on a copy before marshaling, and `omitempty`
// keeps it out of the JSON entirely.
//
// USE THIS ONLY WHERE THE STRUCT IS THE ORIGIN of the line, which is to say
// where you are about to write e and nothing else has ever been in it. SPEC
// §6.5 defines the hash over "the event object", and an Event is a MODEL of
// an event object, not the object: a member the spec registers and this
// struct does not carry is dropped by Marshal and is therefore absent from
// the digest.
//
// That is not hypothetical. `delegation_proof` (SPEC §5.2) is a top-level
// sibling of `data` precisely because `data` is the producer's free-form room
// and a proof is not free-form, and it went into the schemas on 2026-08-26
// with nothing in this struct to hold it. Canonicalizing a PARSED event
// therefore produced a digest over what this package understood rather than
// over what was written, and VerifyChain reported an honest stream as a
// broken chain: our own conformance tool accusing a conformant producer of
// tampering.
//
// For a line that came from anywhere else, use CanonicalizeRaw.
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

// ChainHash returns the hash of e: the value the NEXT event in a chained
// stream carries as its prev_hash. It carries Canonicalize's restriction in
// full, so read that doc comment before reaching for this one.
func ChainHash(e Event) (string, error) {
	canonical, err := Canonicalize(e)
	if err != nil {
		return "", err
	}
	return digest(canonical), nil
}

// CanonicalizeRaw returns the RFC 8785 (JCS) canonical serialization of one
// event LINE with its prev_hash member removed: the exact byte string SPEC
// §6.5 defines as the hash input, over the object as written rather than over
// this package's model of it.
//
// Members are held as json.RawMessage rather than decoded into `any`. Two
// reasons, and the second is the one that bites: an unmodelled member reaches
// the digest byte for byte, and a large integer keeps its value instead of
// going through float64, where an id or a timestamp beyond 2^53 would come
// back a different number. JCS then normalizes what is genuinely normalizable.
//
// This is what every verification and every chain resume uses. A digest over
// a re-marshal is only correct where the struct was the origin.
func CanonicalizeRaw(line []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil, fmt.Errorf("event: canonicalize raw: %w", err)
	}
	delete(obj, "prev_hash")
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("event: canonicalize raw: %w", err)
	}
	canonical, err := jcs.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("event: canonicalize raw: %w", err)
	}
	return canonical, nil
}

// ChainHashRaw returns the SPEC §6.5 hash of one event line as written: the
// value the NEXT event in the stream carries as its prev_hash.
func ChainHashRaw(line []byte) (string, error) {
	canonical, err := CanonicalizeRaw(line)
	if err != nil {
		return "", err
	}
	return digest(canonical), nil
}

func digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return ChainHashPrefix + hex.EncodeToString(sum[:])
}

// ChainedWriter is Writer plus the SPEC §6.5 prev_hash chain: every event
// written carries the hash of the event before it in the FILE.
//
// The file is the chain's authority, not this value. Every Write takes an
// exclusive lock on the file (flock(2), see lock_flock.go), reads the last
// line actually on disk, stamps prev_hash from it, appends, and only then
// releases the lock. So any number of writers, in one process or in many, on
// one host or on several hosts sharing one file, produce ONE chain, in the
// order the lock granted them. Whatever a caller left in Event.PrevHash is
// overwritten (a head event gets none).
//
// It was not always so, and the way it failed is worth keeping. Until v1.1.0
// a writer stamped prev_hash from the hash of ITS OWN previous write, held in
// memory. That is right only while it is the file's only writer, and a shared
// events bus does not guarantee that: a pod being replaced keeps appending
// through its termination grace period while its successor has already
// resumed the chain, and a service and its CronJob append to one file by
// design. Each such interleaving was a chain_broken on an honest stream.
//
// Durability: Write does not fsync. Ordering and visibility to the next
// writer are what the chain needs, and the lock provides both (on a local
// file the page cache is shared, and a Linux NFS client writes back what was
// written under a lock when it is released). What survives the loss of the
// host's power is a separate property no writer in the estate has claimed,
// and a truncated tail resumes cleanly: the next writer chains from whatever
// is last on disk.
//
// On open, an existing file's tail is read under the same lock, and
// ResumedFrom reports it; an unreadable or malformed tail starts a fresh
// chain instead of refusing to write - the exporters this package mirrors
// are fail-open by contract, and a verifier will surface the restart honestly
// rather than the process going quiet.
//
// mu serializes this writer's own goroutines, which the file lock does not:
// the lock belongs to the open file, and every goroutine here shares one.
//
// The fields keep the names, types and layout 1.0 recorded in api/surface.txt,
// whose reader prints unexported fields too; next keeps its meaning, the
// prev_hash for the next event, but is now read from the file at the start of
// each Write rather than carried over from the last one.
type ChainedWriter struct {
	mu   sync.Mutex
	file *os.File
	// prev_hash for the NEXT event; "" while at a chain head.
	next string
	// what the chain resumed from at open ("" = fresh chain).
	resumedFrom string
}

// The lock is taken and released through these two, so a test can make
// either fail. Nothing else assigns them.
var (
	lockForAppend     = lockExclusive
	unlockAfterAppend = unlockFile
)

// testHookBeforeAppend runs under the file lock, after prev_hash has been
// read from the file and immediately before the line is appended. A test sets
// it to observe that the lock is still held there; it does nothing otherwise.
var testHookBeforeAppend = func() {}

// NewChainedWriter opens path for append (creating it if absent) and reads
// the last well-formed event line already in the file, if any, under the
// file lock. It fails when the file cannot be locked at all, because every
// Write would: better that a service learns so when it starts than from a
// stream that goes quiet.
func NewChainedWriter(path string) (*ChainedWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("event: open %s: %w", path, err)
	}
	if err := lockForAppend(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("event: lock %s: %w", path, err)
	}
	cw := &ChainedWriter{file: f}
	if t, err := readTail(f); err == nil && t.line != nil {
		if h, err := ChainHashRaw(t.line); err == nil {
			cw.resumedFrom = h
		}
	}
	if err := unlockAfterAppend(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("event: unlock %s: %w", path, err)
	}
	return cw, nil
}

// ResumedFrom reports the hash this writer's chain resumed from at open, or
// "" when it started fresh (empty file, or an unreadable/malformed tail).
// It is what the file held then; every Write reads the file again.
func (cw *ChainedWriter) ResumedFrom() string {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.resumedFrom
}

// Write takes the file lock, stamps e with the hash of the last event line on
// disk (none when the file holds no well-formed event at its end), appends e
// as one NDJSON line and releases the lock. Safe for concurrent use, from
// goroutines sharing this writer and from other writers on the same file.
//
// A file whose last byte is not a newline (a writer killed mid-line) gets one
// before e, so e is never glued onto a fragment: the fragment stays one
// malformed line and e starts a fresh chain after it, a restart and not a
// break.
//
// Nothing is written when the lock cannot be taken or the tail cannot be
// read: an unlocked append to a shared file is the fault this type exists to
// prevent. An error from releasing the lock is returned even though the line
// is on disk, because a lock that may still be held stalls every other writer
// of the file and the caller should hear about it.
func (cw *ChainedWriter) Write(e Event) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if err := lockForAppend(cw.file); err != nil {
		return fmt.Errorf("event: lock: %w", err)
	}
	// Released below in the ordinary case. The deferred release is for a
	// panic in between: a caller that recovers (net/http does, per request)
	// would otherwise go on holding the lock, and every writer of the file,
	// on every node, would wait on it.
	released := false
	defer func() {
		if !released {
			unlockAfterAppend(cw.file)
		}
	}()
	err := cw.appendLocked(e)
	released = true
	if uerr := unlockAfterAppend(cw.file); uerr != nil && err == nil {
		err = fmt.Errorf("event: unlock: %w", uerr)
	}
	return err
}

// appendLocked is Write's body, run with cw.mu and the file lock held.
func (cw *ChainedWriter) appendLocked(e Event) error {
	t, err := readTail(cw.file)
	if err != nil {
		return fmt.Errorf("event: read tail: %w", err)
	}
	cw.next = ""
	if t.line != nil {
		if h, err := ChainHashRaw(t.line); err == nil {
			cw.next = h
		}
	}
	e.PrevHash = cw.next
	data, err := Marshal(e)
	if err != nil {
		return err
	}
	// A line the next writer could not hash would end the chain at it, so it
	// is refused here rather than written. This struct is the origin of the
	// line, so hashing the bytes and hashing the struct agree; hashing the
	// bytes keeps the question from arising.
	if _, err := ChainHashRaw(data); err != nil {
		return err
	}
	line := make([]byte, 0, len(data)+2)
	if !t.endsNewline {
		line = append(line, '\n')
	}
	line = append(line, data...)
	line = append(line, '\n')

	testHookBeforeAppend()
	if _, err := cw.file.Write(line); err != nil {
		return fmt.Errorf("event: write: %w", err)
	}
	return nil
}

// Close closes the underlying file, which also releases a lock if one were
// still held.
func (cw *ChainedWriter) Close() error {
	return cw.file.Close()
}

// tail is what readTail found at the end of a file.
type tail struct {
	// The last non-blank line, as written, when it parses as an event; nil
	// when the file is empty, blank, ends in a line that is not an event, or
	// ends in a line longer than resumeWindow.
	line []byte
	// Whether the file is empty or its last byte is a newline, so that an
	// append starts a line of its own.
	endsNewline bool
}

// readTail reads backwards from the end of f, tailChunk bytes first and
// doubling up to resumeWindow, until it holds the whole last non-blank line.
// Only an I/O error is an error; every shape of file is an answer.
//
// It returns the line's bytes and not an Event on purpose. The caller chains
// from this line, and that hash has to be the one every other reader of the
// file computes, which means it is taken over the object as written. It
// still PARSES the line, because a resume point has to be a well-formed event
// and not merely the last bytes before EOF, but the parse is the check and the
// bytes are the answer.
func readTail(f *os.File) (tail, error) {
	info, err := f.Stat()
	if err != nil {
		return tail{}, err
	}
	size := info.Size()
	if size == 0 {
		return tail{endsNewline: true}, nil
	}

	var buf []byte // the bytes [size-len(buf), size) of the file
	for n := int64(tailChunk); ; n *= 2 {
		n = min(n, size, resumeWindow)
		if more := n - int64(len(buf)); more > 0 {
			chunk := make([]byte, more, n)
			// Every byte of the range was inside the size just measured, so
			// a short read (io.EOF included) means the file shrank under the
			// lock, which no append-only writer does: an error, not a guess.
			if _, err := f.ReadAt(chunk, size-n); err != nil {
				return tail{}, err
			}
			buf = append(chunk, buf...)
		}
		t := tail{endsNewline: buf[len(buf)-1] == '\n'}

		end := len(bytes.TrimRightFunc(buf, isSpace))
		start := bytes.LastIndexByte(buf[:end], '\n') + 1
		atStart := n == size // buf begins at the first byte of the file
		switch {
		case end == 0 && atStart:
			return t, nil // nothing but blank lines
		case start > 0 || atStart:
			if end > 0 {
				line := bytes.TrimSpace(buf[start:end])
				if _, err := Unmarshal(line); err == nil {
					t.line = line
				}
			}
			return t, nil
		case n == resumeWindow:
			return t, nil // a last line longer than the window: a fresh chain
		}
	}
}

func isSpace(r rune) bool { return unicode.IsSpace(r) }

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

		// The LINE, not the parse of it. SPEC 6.5 hashes the event object,
		// and `e` is this package's model of one: a member the spec registers
		// and Event does not carry would vanish here and take the digest with
		// it, which is how an honest stream came to be reported as broken.
		h, err := ChainHashRaw(line)
		if err != nil {
			// The line already unmarshalled once, so this is close to
			// impossible, but a digest we could not compute is not a digest
			// the next line can be judged against.
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
