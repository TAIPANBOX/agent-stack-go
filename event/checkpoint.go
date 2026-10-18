package event

// The checkpoint sidecar, agent-passport SPEC 6.5.1, format v1 (keyryx wave 2).
//
// A producer that signs its stream writes beside it a checkpoint file that only
// it may write. Each record names how many lines the stream held (count), the
// chain hash of the last of them (head), and the SHA-256 of every byte through
// them (prefix), and is signed (ES256). Verifying a record needs only the stream,
// the record and the public key, and a verifier that kept an earlier record can
// tell whether any byte it covers was changed since.
//
// Two rules hold this file together. The bytes of a record are the JCS (RFC 8785)
// serialization of its object, so a Go writer and a Rust writer that agree on the
// members agree on the bytes. And the prefix is hashed from the stream as it
// stands, never from what this writer believes it wrote, so a line another writer
// appended is covered too.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	checkpointVersion        = 1
	checkpointAlg            = "ES256"
	checkpointKindCheckpoint = "checkpoint"
	checkpointKindClose      = "close"
	checkpointKindResume     = "resume"
	checkpointKeyExpired     = "key_expired"

	defaultCheckpointEvery    = 64
	defaultCheckpointInterval = 10 * time.Second

	// checkpointRecordCap bounds one record. A record is a few hundred bytes.
	checkpointRecordCap = 1 << 20
)

var (
	checkpointGenesis = "sha256:" + strings.Repeat("0", 64)
	checkpointHashRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	checkpointAtRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	checkpointNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.ndjson$`)
)

// CheckpointSigner signs the signing input of a checkpoint record.
//
// KeyID is the RFC 7638 thumbprint of the signing key. Sign returns the 64-byte
// raw ES256 signature over the SHA-256 of signingInput (r then s, 32 bytes each).
// When the key may no longer sign, Sign returns ErrCheckpointKeyExpired and the
// record is written unsigned, with unsigned_reason key_expired. Any other error
// writes no record.
type CheckpointSigner interface {
	KeyID() string
	Sign(signingInput []byte) ([]byte, error)
}

// ErrCheckpointKeyExpired is what a CheckpointSigner returns when its key is
// past its validity and the record must be written unsigned.
var ErrCheckpointKeyExpired = errors.New("event: checkpoint key expired")

// ErrNoCheckpoints is VerifyCheckpoints' answer for a sidecar with no record in
// it: nothing was measured, which is not a pass.
var ErrNoCheckpoints = errors.New("event: no checkpoint record to verify")

// CheckpointConfig configures the sidecar a ChainedWriter writes beside its stream.
type CheckpointConfig struct {
	// Dir is the checkpoints directory, separate from the events directory. It
	// must already exist and belong to this process, or be the directory where
	// the sidecar may be created.
	Dir string
	// Signer signs the records.
	Signer CheckpointSigner
	// Every is the number of lines between checkpoints. Zero means 64.
	Every int
	// Interval is the longest time between checkpoints while lines are written.
	// Zero means 10 seconds. It is checked when a line is written: a stream that
	// stops writes gets no time-based record until it writes again or closes.
	Interval time.Duration
	// Now is the clock for the at member. Nil means time.Now.
	Now func() time.Time
}

// CheckpointStatus is what VerifyCheckpoints made of one record.
type CheckpointStatus int

const (
	// CheckpointRefused: the record failed a check. Refusal says the first one.
	CheckpointRefused CheckpointStatus = iota
	// CheckpointValid: a signed record that passed every check.
	CheckpointValid
	// CheckpointUnsigned: a record written after its key expired, consistent
	// with the stream. It is never reported as valid.
	CheckpointUnsigned
)

// CheckpointResult is one record's verdict.
type CheckpointResult struct {
	// Index is the record's 1-based position in the sidecar.
	Index int
	Kind  string
	Count int
	// Status is valid, unsigned or refused.
	Status CheckpointStatus
	// Refusal names the first check the record failed, in SPEC 6.5.1 words.
	Refusal string
	// Truncated is true when the record was refused because the stream is
	// shorter than the record's N bytes.
	Truncated bool
}

// CheckpointReport is VerifyCheckpoints' summary of one sidecar.
type CheckpointReport struct {
	// StreamLines is the number of newline-terminated lines in the stream.
	StreamLines int
	// Records is every record in the sidecar, in order.
	Records []CheckpointResult
}

// ResumeCounts lists the count of every valid resume record. A restart at line
// L is explained when one of these is the last well-formed line before L.
func (r CheckpointReport) ResumeCounts() []int {
	var out []int
	for _, rec := range r.Records {
		if rec.Kind == checkpointKindResume && rec.Status == CheckpointValid {
			out = append(out, rec.Count)
		}
	}
	return out
}

// CheckpointFileName is the name of a stream's sidecar: <stream>.ckpt.ndjson,
// where <stream> is the stream's full file name.
func CheckpointFileName(stream string) string {
	return stream + ".ckpt.ndjson"
}

// NewChainedWriterWithCheckpoints is NewChainedWriter, with the sidecar of
// SPEC 6.5.1 written beside the stream.
//
// On open, a stream whose last line is not an event (a crash left a fragment, say)
// gets a resume record naming the last well-formed event before it, because the
// next line will start a fresh chain there. Then a record is written every Every
// lines or every Interval while lines are written, and a close record on Close.
// An error from a checkpoint is returned from Write after the event is on disk:
// the event is written, the checkpoint is what failed, and the caller must not
// send the event again.
func NewChainedWriterWithCheckpoints(path string, cfg CheckpointConfig) (*CheckpointedWriter, error) {
	if cfg.Dir == "" {
		return nil, errors.New("event: checkpoints need a directory")
	}
	if cfg.Signer == nil {
		return nil, errors.New("event: checkpoints need a signer")
	}
	cw, ck, err := openChainedWriter(path, &cfg)
	if err != nil {
		return nil, err
	}
	return &CheckpointedWriter{cw: cw, ck: ck}, nil
}

// CheckpointedWriter is a ChainedWriter that also writes the sidecar of SPEC
// 6.5.1 beside its stream. It writes events exactly as the ChainedWriter does.
type CheckpointedWriter struct {
	cw *ChainedWriter
	ck *checkpointer
}

// Write appends e and, when one is due, writes a checkpoint. An error from the
// checkpoint is returned after the event is on disk: the event is written, and the
// caller must not send it again.
func (w *CheckpointedWriter) Write(e Event) error {
	return w.cw.write(e, w.ck)
}

// ResumedFrom is the ChainedWriter's ResumedFrom.
func (w *CheckpointedWriter) ResumedFrom() string {
	return w.cw.ResumedFrom()
}

// Close writes the close record, under the file lock, then closes the sidecar and
// the stream.
func (w *CheckpointedWriter) Close() error {
	w.cw.mu.Lock()
	defer w.cw.mu.Unlock()
	var err error
	if lerr := lockForAppend(w.cw.file); lerr != nil {
		err = fmt.Errorf("event: checkpoint: lock: %w", lerr)
	} else {
		err = w.ck.closeLocked(w.cw.file)
		if uerr := unlockAfterAppend(w.cw.file); uerr != nil && err == nil {
			err = fmt.Errorf("event: checkpoint: unlock: %w", uerr)
		}
	}
	if cerr := w.ck.file.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := w.cw.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// checkpointFields are the members of one record before its signature.
type checkpointFields struct {
	Kind, Stream string
	Count        int
	Head, Prefix string
	At, Prev     string
}

func (f checkpointFields) body() map[string]any {
	return map[string]any{
		"v":      checkpointVersion,
		"kind":   f.Kind,
		"stream": f.Stream,
		"count":  f.Count,
		"head":   f.Head,
		"prefix": f.Prefix,
		"at":     f.At,
		"prev":   f.Prev,
	}
}

// canonicalJSON is the RFC 8785 serialization of v.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// encodeCheckpoint builds one record. It returns the signing input (the JCS of
// the record without sig; nil for an unsigned record) and the record's bytes,
// without the LF. The bytes are the same for every implementation that agrees on
// the members.
func encodeCheckpoint(f checkpointFields, s CheckpointSigner) (signingInput, record []byte, err error) {
	body := f.body()
	body["alg"] = checkpointAlg
	body["kid"] = s.KeyID()
	input, err := canonicalJSON(body)
	if err != nil {
		return nil, nil, err
	}
	raw, err := s.Sign(input)
	switch {
	case errors.Is(err, ErrCheckpointKeyExpired):
		delete(body, "alg")
		delete(body, "kid")
		body["unsigned_reason"] = checkpointKeyExpired
		record, err := canonicalJSON(body)
		return nil, record, err
	case err != nil:
		return nil, nil, fmt.Errorf("event: checkpoint signature: %w", err)
	case len(raw) != 64:
		return nil, nil, fmt.Errorf("event: checkpoint signature is %d bytes, not 64", len(raw))
	}
	body["sig"] = base64.RawURLEncoding.EncodeToString(raw)
	record, err = canonicalJSON(body)
	if err != nil {
		return nil, nil, err
	}
	return input, record, nil
}

// wellFormedLine reports whether line is an event the chain can hash: at most
// the library's line cap and an event by Unmarshal. It is the test VerifyChain
// applies, on the same bytes.
func wellFormedLine(line []byte) bool {
	if len(line) > resumeWindow {
		return false
	}
	_, err := Unmarshal(bytes.TrimSpace(line))
	return err == nil
}

// checkpointer is the sidecar writer of one ChainedWriter. It is used only under
// the stream's file lock.
type checkpointer struct {
	cfg    CheckpointConfig
	stream string
	file   *os.File // the sidecar, for append
	size   int64    // the sidecar's length, to undo a torn append
	sum    hash.Hash
	last   []byte // sum's state at off, marshalled; nil for a fresh sum
	off    int64  // stream bytes hashed, through the last LF
	count  int    // stream lines through off
	head   string // chain hash of line count, or "" when that line is not an event
	prev   string // the previous record's bytes, hashed; the genesis value at first
	// pending is the lines written since the last record.
	pending int
	lastAt  time.Time
}

func (cfg CheckpointConfig) withDefaults() CheckpointConfig {
	if cfg.Every <= 0 {
		cfg.Every = defaultCheckpointEvery
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultCheckpointInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}

// openCheckpointFor sizes the stream and prepares its sidecar writer, under the
// stream's lock.
func openCheckpointFor(events *os.File, streamPath string, cfg *CheckpointConfig) (*checkpointer, error) {
	fi, err := events.Stat()
	if err != nil {
		return nil, fmt.Errorf("event: stat %s: %w", streamPath, err)
	}
	return openCheckpointer(events, fi.Size(), streamPath, cfg.withDefaults())
}

// openCheckpointer prepares the sidecar of the stream at streamPath, whose file is
// events and holds size bytes, under the stream's lock. It hashes the whole stream
// once, which is the only full read the writer makes.
func openCheckpointer(events *os.File, size int64, streamPath string, cfg CheckpointConfig) (*checkpointer, error) {
	stream := filepath.Base(streamPath)
	side := filepath.Join(cfg.Dir, CheckpointFileName(stream))
	sf, err := openAppend(side, os.O_WRONLY)
	if err != nil {
		return nil, err
	}
	ck := &checkpointer{cfg: cfg, stream: stream, file: sf, sum: sha256.New(), prev: checkpointGenesis, lastAt: cfg.Now()}
	prev, complete, err := sidecarTail(side)
	if err != nil {
		sf.Close()
		return nil, err
	}
	if prev != "" {
		ck.prev = prev
	}
	// A torn final record is not a record: cut it off, or the next record would
	// be glued onto it.
	if fi, err := sf.Stat(); err == nil && fi.Size() > complete {
		if err := sf.Truncate(complete); err != nil {
			sf.Close()
			return nil, err
		}
	}
	ck.size = complete

	var (
		goodCount int
		goodHead  string
		goodState []byte
		lastHead  string
	)
	sc := newLineScanner(ck.sum, 0, nil, 0, resumeWindow, true)
	err = sc.run(io.NewSectionReader(events, 0, size), func(line []byte, long bool, end int64) error {
		lastHead = ""
		if !long && wellFormedLine(line) {
			h, err := ChainHashRaw(bytes.TrimSpace(line))
			if err != nil {
				return err
			}
			lastHead = h
			goodCount, goodHead, goodState = sc.lines, h, sc.marshal()
		}
		return nil
	})
	if err != nil {
		sf.Close()
		return nil, fmt.Errorf("event: read %s: %w", streamPath, err)
	}
	if err := sc.settle(); err != nil {
		sf.Close()
		return nil, err
	}
	ck.sum, ck.last, ck.off, ck.count, ck.head = sc.sum, sc.last, sc.off, sc.lines, lastHead

	// The next line starts a fresh chain when the last line is not an event. A
	// resume record names the last event before that restart, so a verifier can
	// tell a crash from a stream that was rewritten.
	if ck.count > 0 && ck.head == "" && goodCount > 0 {
		h := sha256.New()
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(goodState); err != nil {
			sf.Close()
			return nil, err
		}
		if err := ck.writeRecord(checkpointKindResume, goodCount, goodHead, h.Sum(nil)); err != nil {
			sf.Close()
			return nil, err
		}
	}
	return ck, nil
}

// sidecarTail reads the sidecar and returns the hash of its last complete record
// ("" when there is none), and the length of its complete records.
func sidecarTail(path string) (prev string, complete int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	sc := newLineScanner(sha256.New(), 0, nil, 0, checkpointRecordCap, false)
	var last []byte
	err = sc.run(io.LimitReader(f, fi.Size()), func(line []byte, long bool, end int64) error {
		if long {
			return fmt.Errorf("event: checkpoint record in %s is longer than %d bytes", path, checkpointRecordCap)
		}
		last = line
		complete = end
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if last == nil {
		return "", complete, nil
	}
	sum := sha256.Sum256(last)
	return "sha256:" + hex.EncodeToString(sum[:]), complete, nil
}

// at is the clock in the form the at member takes.
func (c *checkpointer) at() string {
	return c.cfg.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// writeRecord builds, signs and appends one record, then chains the next one from
// it. A failed append is cut off again, so the sidecar never keeps a torn record.
func (c *checkpointer) writeRecord(kind string, count int, head string, prefix []byte) error {
	f := checkpointFields{
		Kind:   kind,
		Stream: c.stream,
		Count:  count,
		Head:   head,
		Prefix: "sha256:" + hex.EncodeToString(prefix),
		At:     c.at(),
		Prev:   c.prev,
	}
	_, rec, err := encodeCheckpoint(f, c.cfg.Signer)
	if err != nil {
		return err
	}
	line := append(rec, '\n')
	if _, err := c.file.Write(line); err != nil {
		_ = c.file.Truncate(c.size)
		return fmt.Errorf("event: write checkpoint: %w", err)
	}
	c.size += int64(len(line))
	sum := sha256.Sum256(rec)
	c.prev = "sha256:" + hex.EncodeToString(sum[:])
	c.lastAt = c.cfg.Now()
	c.pending = 0
	return nil
}

// advance hashes the stream from off through its last LF, which includes the lines
// another writer appended since, and returns how many lines it added.
func (c *checkpointer) advance(events *os.File) (int, error) {
	fi, err := events.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Size() < c.off {
		// The stream shrank under this writer. SPEC 6.5.1: no checkpoint until the
		// file has been hashed again from byte zero, so it is, and the next checkpoint
		// covers what the file holds now.
		c.sum.Reset()
		c.off, c.count, c.head, c.last = 0, 0, "", nil
	}
	if fi.Size() == c.off {
		return 0, nil
	}
	head := c.head
	sc := newLineScanner(c.sum, c.off, c.last, c.count, resumeWindow, true)
	added := 0
	err = sc.run(io.NewSectionReader(events, c.off, fi.Size()-c.off), func(line []byte, long bool, end int64) error {
		added++
		head = ""
		if !long && wellFormedLine(line) {
			h, err := ChainHashRaw(bytes.TrimSpace(line))
			if err != nil {
				return err
			}
			head = h
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := sc.settle(); err != nil {
		return 0, err
	}
	c.sum, c.last, c.off = sc.sum, sc.last, sc.off
	c.count += added
	if added > 0 {
		c.head = head
	}
	return added, nil
}

// afterAppend runs under the lock, after a line was written, and writes a
// checkpoint when one is due.
func (c *checkpointer) afterAppend(events *os.File) error {
	n, err := c.advance(events)
	if err != nil {
		return fmt.Errorf("event: checkpoint: %w", err)
	}
	c.pending += n
	if c.pending == 0 {
		return nil
	}
	if c.pending < c.cfg.Every && c.cfg.Now().Sub(c.lastAt) < c.cfg.Interval {
		return nil
	}
	if c.head == "" {
		// The last line is not an event, so there is no head to name. The next
		// line that is one will be checkpointed.
		return nil
	}
	if err := c.writeRecord(checkpointKindCheckpoint, c.count, c.head, c.sum.Sum(nil)); err != nil {
		return fmt.Errorf("event: checkpoint: %w", err)
	}
	return nil
}

// closeLocked writes the close record, under the lock.
func (c *checkpointer) closeLocked(events *os.File) error {
	if _, err := c.advance(events); err != nil {
		return err
	}
	if c.count == 0 || c.head == "" {
		return nil
	}
	return c.writeRecord(checkpointKindClose, c.count, c.head, c.sum.Sum(nil))
}

// VerifyCheckpoints checks every record of a sidecar against the stream it names.
//
// stream is the stream's bytes and streamName its file name, which a record must
// name. sidecar is the checkpoint file. keys returns the public key for a kid, or
// false when the verifier holds none, and a record under an unknown key is refused.
//
// Each record gets one verdict, in SPEC 6.5.1 order: canonical bytes, members,
// stream name, count against the stream (a truncation when the stream is
// shorter), head, prefix, prev, at, then the signature (or unsigned_reason). The
// stream is read once. It returns ErrNoCheckpoints for a sidecar with no record.
func VerifyCheckpoints(stream, sidecar io.Reader, streamName string, keys func(kid string) (*ecdsa.PublicKey, bool)) (CheckpointReport, error) {
	recs, err := readSidecar(sidecar)
	if err != nil {
		return CheckpointReport{}, err
	}
	if len(recs) == 0 {
		return CheckpointReport{}, ErrNoCheckpoints
	}

	needed := map[int]bool{}
	kinds := make([]string, len(recs))
	counts := make([]int, len(recs))
	for i, r := range recs {
		kinds[i], counts[i] = peekKindCount(r.raw)
		if counts[i] >= 1 {
			needed[counts[i]] = true
		}
	}
	prefixAt := map[int][]byte{}
	headAt := map[int]string{}
	ss := newLineScanner(sha256.New(), 0, nil, 0, resumeWindow, false)
	lines := 0
	err = ss.run(stream, func(line []byte, long bool, end int64) error {
		lines++
		if needed[lines] {
			prefixAt[lines] = ss.sum.Sum(nil)
			if !long && wellFormedLine(line) {
				h, err := ChainHashRaw(bytes.TrimSpace(line))
				if err != nil {
					return err
				}
				headAt[lines] = h
			}
		}
		return nil
	})
	if err != nil {
		return CheckpointReport{}, fmt.Errorf("event: read stream: %w", err)
	}

	report := CheckpointReport{StreamLines: lines}
	var prevRaw []byte
	for i, r := range recs {
		res := CheckpointResult{Index: i + 1, Kind: kinds[i], Count: counts[i]}
		expectPrev := checkpointGenesis
		if prevRaw != nil {
			sum := sha256.Sum256(prevRaw)
			expectPrev = "sha256:" + hex.EncodeToString(sum[:])
		}
		refusal, truncated, signed := checkRecord(r, lines, headAt, prefixAt, expectPrev, streamName, keys)
		res.Truncated = truncated
		switch {
		case refusal != "":
			res.Status, res.Refusal = CheckpointRefused, refusal
		case signed:
			res.Status = CheckpointValid
		default:
			res.Status = CheckpointUnsigned
		}
		report.Records = append(report.Records, res)
		prevRaw = r.raw
	}
	return report, nil
}

// ckRecordLine is one complete line of a sidecar.
type ckRecordLine struct {
	raw  []byte
	long bool
}

// peekKindCount reads kind and count from a record for the report, whether or
// not the record is otherwise sound. Zero values when they cannot be read.
func peekKindCount(raw []byte) (kind string, count int) {
	var w struct {
		Kind  string `json:"kind"`
		Count int    `json:"count"`
	}
	_ = json.Unmarshal(raw, &w)
	return w.Kind, w.Count
}

// readSidecar returns the complete lines of a sidecar, in order. A torn final
// line is not a record and is left out.
func readSidecar(r io.Reader) ([]ckRecordLine, error) {
	var out []ckRecordLine
	sc := newLineScanner(sha256.New(), 0, nil, 0, checkpointRecordCap, false)
	err := sc.run(r, func(line []byte, long bool, end int64) error {
		out = append(out, ckRecordLine{raw: line, long: long})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("event: read sidecar: %w", err)
	}
	return out, nil
}

// checkRecord returns the first refusal of one record ("" when none), whether the
// stream was too short for it, and whether it is signed.
func checkRecord(r ckRecordLine, lines int, headAt map[int]string, prefixAt map[int][]byte,
	expectPrev, streamName string, keys func(kid string) (*ecdsa.PublicKey, bool)) (refusal string, truncated, signed bool) {
	fail := func(msg string) (string, bool, bool) { return msg, false, false }
	if r.long {
		return fail("record is longer than the record cap")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.raw, &m); err != nil {
		return fail("record is not a JSON object")
	}
	if canon, err := jcs.Transform(r.raw); err != nil || !bytes.Equal(canon, r.raw) {
		return fail("record is not the canonical serialization of its object (RFC 8785 order and whitespace)")
	}
	var w struct {
		V        *int    `json:"v"`
		Kind     *string `json:"kind"`
		Stream   *string `json:"stream"`
		Count    *int    `json:"count"`
		Head     *string `json:"head"`
		Prefix   *string `json:"prefix"`
		At       *string `json:"at"`
		Prev     *string `json:"prev"`
		Alg      *string `json:"alg"`
		Kid      *string `json:"kid"`
		Sig      *string `json:"sig"`
		Unsigned *string `json:"unsigned_reason"`
	}
	if err := json.Unmarshal(r.raw, &w); err != nil {
		return fail("record has a member of the wrong type")
	}
	common := w.V != nil && w.Kind != nil && w.Stream != nil && w.Count != nil &&
		w.Head != nil && w.Prefix != nil && w.At != nil && w.Prev != nil
	switch {
	case common && w.Alg != nil && w.Kid != nil && w.Sig != nil && w.Unsigned == nil:
		signed = true
	case common && w.Alg == nil && w.Kid == nil && w.Sig == nil && w.Unsigned != nil:
	default:
		return fail("record has members outside format v1: a signed record has alg, kid and sig, an unsigned one has unsigned_reason")
	}
	if *w.V != checkpointVersion {
		return fail("record has v other than 1")
	}
	switch *w.Kind {
	case checkpointKindCheckpoint, checkpointKindClose, checkpointKindResume:
	default:
		return fail(fmt.Sprintf("record has kind %q, which is not checkpoint, close or resume", *w.Kind))
	}
	if *w.Stream != streamName {
		return fail(fmt.Sprintf("record names stream %q, not %q", *w.Stream, streamName))
	}
	if *w.Count < 1 {
		return fail("count is not an integer of at least 1")
	}
	count := *w.Count
	if count > lines {
		return fmt.Sprintf("record is refused: the stream is shorter than the record's N bytes (it holds %d lines, the record counts %d), so the record is a truncation", lines, count), true, false
	}
	if !checkpointHashRE.MatchString(*w.Head) {
		return fail("head is not sha256 followed by 64 lowercase hex digits")
	}
	if h := headAt[count]; h == "" {
		return fail(fmt.Sprintf("line %d is not a well-formed event, so no head can name it", count))
	} else if *w.Head != h {
		return fail(fmt.Sprintf("head does not equal the chain hash of line %d under 6.5", count))
	}
	if !checkpointHashRE.MatchString(*w.Prefix) {
		return fail("prefix is not sha256 followed by 64 lowercase hex digits")
	}
	if *w.Prefix != "sha256:"+hex.EncodeToString(prefixAt[count]) {
		return fail("prefix does not match the SHA-256 of the first N bytes of the stream (N is the offset after line " + fmt.Sprint(count) + "'s LF)")
	}
	if *w.Prev != expectPrev {
		return fail("prev does not chain from the record before it")
	}
	if !checkpointAtRE.MatchString(*w.At) {
		return fail("at is not in the form YYYY-MM-DDTHH:MM:SS.sssZ")
	}
	if !signed {
		if *w.Unsigned != checkpointKeyExpired {
			return fail(fmt.Sprintf("unsigned_reason %q is not key_expired, the only v1 value", *w.Unsigned))
		}
		return "", false, false
	}
	if *w.Alg != checkpointAlg {
		return fail("alg is not ES256")
	}
	raw, err := base64.RawURLEncoding.DecodeString(*w.Sig)
	if err != nil || len(raw) != 64 {
		return fail("sig is not 64 bytes of base64url")
	}
	var pub *ecdsa.PublicKey
	ok := false
	if keys != nil {
		pub, ok = keys(*w.Kid)
	}
	if !ok || pub == nil {
		return fail(fmt.Sprintf("record is under key %q, which the verifier does not hold", *w.Kid))
	}
	delete(m, "sig")
	body, err := json.Marshal(m)
	if err != nil {
		return fail("record cannot be re-serialized")
	}
	input, err := jcs.Transform(body)
	if err != nil {
		return fail("record cannot be re-serialized")
	}
	digest := sha256.Sum256(input)
	rr := new(big.Int).SetBytes(raw[:32])
	ss := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(pub, digest[:], rr, ss) {
		return fail("signature does not verify under the key its kid names")
	}
	return "", false, true
}
