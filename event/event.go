// Package event defines the shared agent-event envelope: one JSON object
// per event, NDJSON when batched, plus an append-only writer and tolerant
// reader helpers for it.
//
// This package is a public mirror of Idryx's internal ingest/tokenfuse
// envelope decoding, and of the append-only exporters already shipping in
// the stack: TokenFuse's tokenfuse-core::agent_event::Exporter (Rust) and
// Engram's engram.events.EventLog (Python). All three write the same
// shape: one NDJSON line per event, guarded by a mutex, fail-open. This
// package is the Go binding of that same contract for services (Wardryx,
// Mockryx, and others) that live outside Idryx's internal/ tree.
package event

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Schema identifiers this package understands.
//
// SchemaV02 is the version for ordinary traffic: the open source registry and
// the delegation-chain cycle rule (see package chain) were both introduced in
// v0.2. SchemaV01 remains valid per the compatibility rule: consumers MUST
// accept either schema string; a producer emitting v0.1 is not required to
// upgrade before a consumer can read it.
//
// SchemaV03 is NOT the successor to v0.2 in the usual sense, and treating it as
// one is the mistake this comment exists to prevent. It is the version an
// observer stamps when, and only when, `agent_id` carries a CLAIMED subject:
// `claimed:agent://<domain>/<path>`, read out of a process's own
// AGENT_PASSPORT_ID (agent-passport SPEC 3.3, 6.4). A producer MUST NOT stamp
// it on an event whose subject is established, because the version is how a
// reader knows a claim is possible at all.
//
// The asymmetry that follows from that: a consumer MUST accept v0.1 and v0.2,
// and MAY refuse v0.3. Refusing is the correct answer for a reader that has not
// decided what a self-declaration means to it, and this package deliberately
// does not decide that for anybody (see Unmarshal).
//
// SchemaV10 (SPEC 6.4.1, 2026-09-12) is v0.3's shape with the version string
// changed, and it is the successor to v0.2 for ordinary traffic. A consumer
// MUST accept v0.1, v0.2 and v1.0; the refusal it owes moves from the version
// to the subject: a consumer that has not decided what a claimed subject means
// refuses and counts an event whose agent_id carries the `claimed:` marker,
// whatever version stamped it. A producer stamps v1.0 on every event from the
// release in which it adopts 1.0, claimed subject or not.
const (
	SchemaV02 = "taipanbox.dev/agent-event/v0.2"
	SchemaV01 = "taipanbox.dev/agent-event/v0.1"
	SchemaV03 = "taipanbox.dev/agent-event/v0.3"
	SchemaV10 = "taipanbox.dev/agent-event/v1.0"
)

// Severity values for the Event.Severity field.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Sentinel errors returned by Unmarshal. Wrapped with additional context,
// so callers can still branch on failure kind with errors.Is.
var (
	// ErrInvalidJSON means the input was not well-formed JSON.
	ErrInvalidJSON = errors.New("event: invalid json")
	// ErrMissingSchema means the envelope had no schema field.
	ErrMissingSchema = errors.New("event: missing required field: schema")
	// ErrMissingTS means the envelope had no ts field.
	ErrMissingTS = errors.New("event: missing required field: ts")
	// ErrMissingSource means the envelope had no source field.
	ErrMissingSource = errors.New("event: missing required field: source")
	// ErrMissingType means the envelope had no type field.
	ErrMissingType = errors.New("event: missing required field: type")
	// ErrMissingAgentID means the envelope had no agent_id field.
	ErrMissingAgentID = errors.New("event: missing required field: agent_id")
)

// Event is one agent-event envelope. Field order matches the wire example
// in the spec, which json.Marshal preserves (struct fields are emitted in
// declaration order, not sorted), so the output shape matches the Rust and
// Python exporters.
type Event struct {
	Schema     string         `json:"schema"`
	TS         string         `json:"ts"`
	Source     string         `json:"source"`
	Type       string         `json:"type"`
	AgentID    string         `json:"agent_id"`
	Severity   string         `json:"severity,omitempty"`
	RunID      string         `json:"run_id,omitempty"`
	OnBehalfOf []string       `json:"on_behalf_of,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	PrevHash   string         `json:"prev_hash,omitempty"`
}

// Marshal encodes e as its canonical JSON form: one object, no trailing
// newline. Callers that want an NDJSON line append "\n" themselves; Writer
// does this for the append-only file case.
func Marshal(e Event) ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("event: marshal: %w", err)
	}
	return data, nil
}

// Unmarshal decodes one Event and validates that the required envelope
// fields (schema, ts, source, type, agent_id) are non-empty. It does not
// otherwise validate field shape, e.g. ts as RFC 3339 or agent_id as a
// well-formed agent:// URI (see package passport for that) or on_behalf_of
// as an acyclic chain (see package chain): Unmarshal only enforces the
// envelope's required-field rule.
func Unmarshal(data []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch {
	case e.Schema == "":
		return Event{}, ErrMissingSchema
	case e.TS == "":
		return Event{}, ErrMissingTS
	case e.Source == "":
		return Event{}, ErrMissingSource
	case e.Type == "":
		return Event{}, ErrMissingType
	case e.AgentID == "":
		return Event{}, ErrMissingAgentID
	}
	return e, nil
}

// Writer is an append-only NDJSON writer for the agent-event envelope: one
// line per event. Concurrent callers in this process are serialized by a
// mutex, and every append holds an exclusive lock on the file, so writers in
// other processes that share the file do not overwrite its lines. Fail-open:
// Write returns an error to the caller to log and drop, and it never panics.
// A writer whose file cannot be locked appends nothing (see appendLocked).
type Writer struct {
	mu   sync.Mutex
	file *os.File
}

// NewWriter opens path for append, creating it if it does not already
// exist. The file handle is kept open for the Writer's lifetime; callers
// must call Close when done with it.
func NewWriter(path string) (*Writer, error) {
	f, err := openAppend(path, os.O_WRONLY)
	if err != nil {
		return nil, fmt.Errorf("event: open %s: %w", path, err)
	}
	return &Writer{file: f}, nil
}

// Write marshals e and appends it as one NDJSON line. Safe for concurrent
// use: writes are serialized by an internal mutex, matching the Rust and
// Python exporters this package mirrors.
func (w *Writer) Write(e Event) error {
	data, err := Marshal(e)
	if err != nil {
		return err
	}
	line := append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(line)
}

// appendLocked appends line under an exclusive flock(2) on the file and
// releases the lock. The lock is what makes the append safe when another
// process also appends to the file: O_APPEND alone does not serialize two
// writers on an NFS share, and each one can overwrite the other's bytes. A lock
// that cannot be taken appends nothing. A panic in between still releases it.
func (w *Writer) appendLocked(line []byte) error {
	if err := lockForWrite(w.file); err != nil {
		return fmt.Errorf("event: lock: %w", err)
	}
	released := false
	defer func() {
		if !released {
			_ = unlockAfterWrite(w.file)
		}
	}()
	testHookWriterBeforeAppend()
	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("event: write: %w", err)
	}
	released = true
	if err := unlockAfterWrite(w.file); err != nil {
		return fmt.Errorf("event: unlock: %w", err)
	}
	return nil
}

// The file lock of a Writer is taken and released through these two, so a
// test can make either fail. Nothing else assigns them.
var (
	lockForWrite     = lockExclusive
	unlockAfterWrite = unlockFile
)

// testHookWriterBeforeAppend runs immediately before the line is appended, under
// the file lock. A test sets it to observe that the lock is held there.
var testHookWriterBeforeAppend = func() {}

// Close closes the underlying file.
func (w *Writer) Close() error {
	return w.file.Close()
}

// ScanResult reports how many lines Scan (and, transitively, ReadFile)
// processed and how many were malformed and skipped, mirroring Idryx's
// tolerant connectors (internal/ingest/tokenfuse, internal/ingest/passport):
// one bad line is counted, never fatal to the rest of the batch.
type ScanResult struct {
	Lines     int
	Malformed int
}

// Scan reads NDJSON lines from r, calling fn with each successfully decoded
// Event. Blank lines are skipped silently. A line that is not valid JSON,
// or that fails Unmarshal's required-field check, is counted in the
// returned ScanResult.Malformed and skipped rather than aborting the scan.
//
// fn returning an error DOES stop the scan: that is the caller's own logic
// signaling it is done, not wire-format tolerance, and the error is
// returned wrapped.
func Scan(r io.Reader, fn func(Event) error) (ScanResult, error) {
	var res ScanResult
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		res.Lines++
		e, err := Unmarshal(line)
		if err != nil {
			res.Malformed++
			continue
		}
		if err := fn(e); err != nil {
			return res, fmt.Errorf("event: scan callback: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("event: scan: %w", err)
	}
	return res, nil
}

// ReadFile reads every NDJSON line in path and returns the successfully
// decoded Events, in file order. Malformed lines are skipped, per Scan;
// ReadFile only returns an error for I/O failures (missing file, read
// error, or a callback error, though ReadFile's own callback never
// returns one).
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("event: open %s: %w", path, err)
	}
	defer f.Close()

	var events []Event
	if _, err := Scan(f, func(e Event) error {
		events = append(events, e)
		return nil
	}); err != nil {
		return nil, err
	}
	return events, nil
}
