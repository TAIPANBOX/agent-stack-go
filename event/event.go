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
// SchemaV02 is the current wire version: the open source registry and the
// delegation-chain cycle rule (see package chain) were both introduced in
// v0.2. SchemaV01 remains valid per the compatibility rule: consumers MUST
// accept either schema string; a producer emitting v0.1 is not required to
// upgrade before a consumer can read it.
const (
	SchemaV02 = "taipanbox.dev/agent-event/v0.2"
	SchemaV01 = "taipanbox.dev/agent-event/v0.1"
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
// line per event, guarded by a mutex so concurrent callers never interleave
// partial lines, fail-open (Write returns an error to the caller to log and
// drop; it never panics and never blocks the caller's own request path on
// disk trouble beyond the single write).
type Writer struct {
	mu   sync.Mutex
	file *os.File
}

// NewWriter opens path for append, creating it if it does not already
// exist. The file handle is kept open for the Writer's lifetime; callers
// must call Close when done with it.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
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
	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("event: write: %w", err)
	}
	return nil
}

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
