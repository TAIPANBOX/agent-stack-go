package event

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cross-language pinned vectors (testdata/chain-vectors.json). These
// constants are the normative values; the testdata file is the portable copy
// the Rust and Python implementations pin the SAME numbers from, and
// TestVectorFileMatchesPinnedConstants keeps the two from drifting apart.
const (
	vecC1 = `{"agent_id":"agent://acme.example/support/tier1-bot","data":{"policy":"finance-guard","reason":"deny_tool: shell"},"run_id":"run-0001","schema":"taipanbox.dev/agent-event/v0.2","severity":"high","source":"wardryx","ts":"2026-07-24T12:00:00Z","type":"policy_deny"}`
	vecH1 = "sha256:b43502c0ed6893238f2635be7a909cde89df1c2eecaef4d84871b83cf21cb31b"
	vecC2 = `{"agent_id":"agent://acme.example/support/tier1-bot","data":{"budget_usd":12.5,"n":3,"nested":{"a":1,"b":2},"note":"обмеження діє"},"on_behalf_of":["user://acme.example/alice","agent://acme.example/orchestrator"],"run_id":"run-0001","schema":"taipanbox.dev/agent-event/v0.2","severity":"critical","source":"tokenfuse","ts":"2026-07-24T12:00:01Z","type":"budget_exhausted"}`
	vecH2 = "sha256:488f1017967bf9510c62d7c31b9d5a0086ff2000d90a7d4266f171a131430243"
	vecC3 = `{"agent_id":"agent://acme.example/support/tier1-bot","data":{"algo":"ML-DSA-87"},"schema":"taipanbox.dev/agent-event/v0.2","severity":"info","source":"qryx","ts":"2026-07-24T12:00:02Z","type":"evidence_signed"}`
	vecH3 = "sha256:998cbc146b07e115318ce378e0579fcd1927066ef4316900ec7d66ba157e7c4b"
)

func vecEvent1() Event {
	return Event{
		Schema: SchemaV02, TS: "2026-07-24T12:00:00Z", Source: "wardryx",
		Type: "policy_deny", AgentID: "agent://acme.example/support/tier1-bot",
		Severity: "high", RunID: "run-0001",
		Data: map[string]any{"policy": "finance-guard", "reason": "deny_tool: shell"},
	}
}

func vecEvent2() Event {
	return Event{
		Schema: SchemaV02, TS: "2026-07-24T12:00:01Z", Source: "tokenfuse",
		Type: "budget_exhausted", AgentID: "agent://acme.example/support/tier1-bot",
		Severity: "critical", RunID: "run-0001",
		OnBehalfOf: []string{"user://acme.example/alice", "agent://acme.example/orchestrator"},
		Data: map[string]any{
			"budget_usd": 12.5, "n": 3, "note": "обмеження діє",
			"nested": map[string]any{"b": 2, "a": 1},
		},
	}
}

func vecEvent3() Event {
	return Event{
		Schema: SchemaV02, TS: "2026-07-24T12:00:02Z", Source: "qryx",
		Type: "evidence_signed", AgentID: "agent://acme.example/support/tier1-bot",
		Severity: "info", Data: map[string]any{"algo": "ML-DSA-87"},
	}
}

func mustCanonical(t *testing.T, e Event) string {
	t.Helper()
	c, err := Canonicalize(e)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	return string(c)
}

func mustHash(t *testing.T, e Event) string {
	t.Helper()
	h, err := ChainHash(e)
	if err != nil {
		t.Fatalf("ChainHash: %v", err)
	}
	return h
}

func TestPinnedVectors(t *testing.T) {
	cases := []struct {
		event     Event
		canonical string
		hash      string
	}{
		{vecEvent1(), vecC1, vecH1},
		{vecEvent2(), vecC2, vecH2},
		{vecEvent3(), vecC3, vecH3},
	}
	for i, c := range cases {
		if got := mustCanonical(t, c.event); got != c.canonical {
			t.Errorf("vector %d canonical drifted:\n got %s\nwant %s", i+1, got, c.canonical)
		}
		if got := mustHash(t, c.event); got != c.hash {
			t.Errorf("vector %d hash drifted: got %s want %s", i+1, got, c.hash)
		}
	}
}

// The testdata file is what the Rust and Python implementations pin from; a
// drift between it and the constants above would fork the truth.
func TestVectorFileMatchesPinnedConstants(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "chain-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Vectors []struct {
			Event     json.RawMessage `json:"event"`
			Canonical string          `json:"canonical"`
			Hash      string          `json:"hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) != 3 {
		t.Fatalf("expected 3 vectors, got %d", len(file.Vectors))
	}
	wantCanonical := []string{vecC1, vecC2, vecC3}
	wantHash := []string{vecH1, vecH2, vecH3}
	for i, v := range file.Vectors {
		if v.Canonical != wantCanonical[i] {
			t.Errorf("vector %d: file canonical differs from pinned constant", i+1)
		}
		if v.Hash != wantHash[i] {
			t.Errorf("vector %d: file hash differs from pinned constant", i+1)
		}
		// The event object in the file must itself canonicalize to the
		// pinned bytes: proves the file's event and the constants agree.
		e, err := Unmarshal(v.Event)
		if err != nil {
			t.Fatalf("vector %d: event: %v", i+1, err)
		}
		if got := mustCanonical(t, e); got != wantCanonical[i] {
			t.Errorf("vector %d: file event canonicalizes differently:\n got %s", i+1, got)
		}
	}
}

func TestCanonicalizeStripsPrevHash(t *testing.T) {
	e := vecEvent1()
	e.PrevHash = "sha256:" + strings.Repeat("ab", 32)
	got := mustCanonical(t, e)
	if strings.Contains(got, "prev_hash") {
		t.Fatalf("canonical form must not contain prev_hash: %s", got)
	}
	if got != vecC1 {
		t.Fatalf("canonical with prev_hash set must equal canonical without it")
	}
	// And so the hash is prev-hash-independent: chained or not, an event
	// hashes the same.
	if mustHash(t, e) != vecH1 {
		t.Fatalf("hash must be independent of the event's own prev_hash")
	}
}

func TestChainedWriterChainsResumesAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")

	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	if cw.ResumedFrom() != "" {
		t.Fatalf("fresh file must start a fresh chain, got %q", cw.ResumedFrom())
	}
	if err := cw.Write(vecEvent1()); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := cw.Write(vecEvent2()); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].PrevHash != "" {
		t.Fatalf("head event must carry no prev_hash, got %q", events[0].PrevHash)
	}
	if events[1].PrevHash != vecH1 {
		t.Fatalf("second event prev_hash: got %q want %q", events[1].PrevHash, vecH1)
	}

	// Reopen: the chain resumes from the tail across a process restart.
	cw2, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if cw2.ResumedFrom() != vecH2 {
		t.Fatalf("resume: got %q want %q", cw2.ResumedFrom(), vecH2)
	}
	if err := cw2.Write(vecEvent3()); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	if err := cw2.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	report, err := VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Ok() || report.Chained != 2 || len(report.HeadLines) != 1 || report.HeadLines[0] != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestChainedWriterStartsFreshOnMalformedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	if err := os.WriteFile(path, []byte("{not json at all\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	if cw.ResumedFrom() != "" {
		t.Fatalf("malformed tail must start a fresh chain (fail-open), got %q", cw.ResumedFrom())
	}
	if err := cw.Write(vecEvent1()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, _ := os.Open(path)
	defer f.Close()
	report, err := VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	// One malformed line, then a fresh head: reported, and still Ok (no
	// genuine break anywhere).
	if report.Malformed != 1 || len(report.HeadLines) != 1 || !report.Ok() {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestChainedWriterResumesAcrossALargeTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	cw, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	// Push the file well past resumeWindow so reopening exercises the
	// mid-file cut (the skipFirst partial-line path in tailEvent).
	e := vecEvent1()
	e.Data = map[string]any{"pad": strings.Repeat("x", 4096)}
	for range 300 {
		if err := cw.Write(e); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	var last string
	if last, err = ChainHash(e); err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Size() <= resumeWindow {
		t.Fatalf("test file too small to exercise the window: %d", info.Size())
	}

	cw2, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer cw2.Close()
	if cw2.ResumedFrom() != last {
		t.Fatalf("large-tail resume: got %q want %q", cw2.ResumedFrom(), last)
	}
}

func chainOf(t *testing.T, events ...Event) []string {
	t.Helper()
	var lines []string
	prev := ""
	for _, e := range events {
		e.PrevHash = prev
		data, err := Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lines = append(lines, string(data))
		prev = mustHash(t, e)
	}
	return lines
}

func TestVerifyChainFlagsATamperedLine(t *testing.T) {
	lines := chainOf(t, vecEvent1(), vecEvent2(), vecEvent3())
	// Tamper with line 2's payload but keep its recorded prev_hash: line 2
	// still verifies against line 1, but line 3's stored prev_hash no
	// longer matches the hash of what line 2 NOW says.
	lines[1] = strings.Replace(lines[1], "12.5", "999.5", 1)
	report, err := VerifyChain(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Ok() || len(report.Breaks) != 1 || report.Breaks[0].Line != 3 {
		t.Fatalf("expected exactly one break at line 3, got %+v", report)
	}
	if report.Breaks[0].Found != vecH2 {
		t.Fatalf("break must show the stored (now-stale) hash: %+v", report.Breaks[0])
	}
}

func TestVerifyChainRestartIsReportedNotBroken(t *testing.T) {
	first := chainOf(t, vecEvent1(), vecEvent2())
	second := chainOf(t, vecEvent3()) // a fresh head mid-stream (restart)
	stream := strings.Join(append(first, second...), "\n") + "\n"
	report, err := VerifyChain(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Ok() {
		t.Fatalf("a restart is not a break: %+v", report)
	}
	if len(report.HeadLines) != 2 || report.HeadLines[1] != 3 || report.Chained != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestVerifyChainMidStreamOpenIsUnverifiable(t *testing.T) {
	lines := chainOf(t, vecEvent1(), vecEvent2(), vecEvent3())
	// Drop line 1, as a rotated segment would: line 2 opens the stream with
	// a prev_hash nothing can check.
	stream := strings.Join(lines[1:], "\n") + "\n"
	report, err := VerifyChain(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Ok() || len(report.Unverifiable) != 1 || report.Unverifiable[0] != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	// Line 2 of the segment still verifies against line 1 of the segment.
	if report.Chained != 1 {
		t.Fatalf("expected the rest of the segment to chain: %+v", report)
	}
}

func TestVerifyChainMalformedLinePoisonsExactlyTheNextLink(t *testing.T) {
	lines := chainOf(t, vecEvent1(), vecEvent2(), vecEvent3())
	lines[1] = "{malformed"
	stream := strings.Join(lines, "\n") + "\n"
	report, err := VerifyChain(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Malformed != 1 {
		t.Fatalf("expected one malformed line: %+v", report)
	}
	if len(report.Unverifiable) != 1 || report.Unverifiable[0] != 3 {
		t.Fatalf("the event after a malformed line is unverifiable: %+v", report)
	}
	if !report.Ok() {
		t.Fatalf("no genuine break here: %+v", report)
	}
}
