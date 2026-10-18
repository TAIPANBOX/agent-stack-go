package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scenarios: features/checkpoints.feature. One refusal, one test: each check in
// SPEC 6.5.1 is named by the message the verifier gives, and a record broken in
// exactly that member gets exactly that message.

func TestEachRefusalOfARecordIsNamedForItsMember(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	valid := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	var base map[string]any
	if err := json.Unmarshal([]byte(valid), &base); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(m map[string]any)
		want string
	}{
		{"v is 2", func(m map[string]any) { m["v"] = 2 }, "v other than 1"},
		{"kind is unknown", func(m map[string]any) { m["kind"] = "bogus" }, "which is not checkpoint, close or resume"},
		{"stream is another", func(m map[string]any) { m["stream"] = "other.ndjson" }, "names stream"},
		{"count is zero", func(m map[string]any) { m["count"] = 0 }, "count is not an integer of at least 1"},
		{"head is not a hash", func(m map[string]any) { m["head"] = "sha256:xyz" }, "head is not sha256"},
		{"prefix is not a hash", func(m map[string]any) { m["prefix"] = "sha256:xyz" }, "prefix is not sha256"},
		{"at is not the form", func(m map[string]any) { m["at"] = "2026-10-18" }, "at is not in the form"},
		{"alg is RS256", func(m map[string]any) { m["alg"] = "RS256" }, "alg is not ES256"},
		{"sig is short", func(m map[string]any) { m["sig"] = "AAAA" }, "sig is not 64 bytes"},
		{"kid is unknown", func(m map[string]any) { m["kid"] = "nobody-holds-this" }, "does not hold"},
		{"a member is missing", func(m map[string]any) { delete(m, "prefix") }, "members outside format v1"},
		{"count is past the stream", func(m map[string]any) { m["count"] = 9 }, "shorter than the record's N bytes"},
	}
	for _, c := range cases {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		c.edit(m)
		// Re-canonicalized, so the member under test is the one that refuses and
		// not the canonical-bytes check that runs first.
		canon, err := canonicalJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		rep := ckVerifyBytes(t, stream, ckSidecarOf(string(canon)), s, "wardryx.ndjson")
		got := ckRec(t, rep, 0)
		if got.Status != CheckpointRefused || !strings.Contains(got.Refusal, c.want) {
			t.Fatalf("%s: want a refusal containing %q, got %+v", c.name, c.want, got)
		}
	}
}

func TestAnUnsignedRecordNamesItsOwnReasonOnlyWhenItIsKeyExpired(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	f := ckFields(stream, heads, 2)
	body := map[string]any{"v": 1, "kind": f.Kind, "stream": f.Stream, "count": f.Count, "head": f.Head,
		"prefix": f.Prefix, "at": f.At, "prev": f.Prev, "unsigned_reason": "key_expired"}
	b, _ := canonicalJSON(body)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(string(b)), s, "wardryx.ndjson")
	if got := ckRec(t, rep, 0); got.Status != CheckpointUnsigned {
		t.Fatalf("key_expired is the one reason v1 allows: %+v", got)
	}
}

func TestATornSidecarTailIsCutBeforeTheNextRecord(t *testing.T) {
	dir := t.TempDir()
	stream := ckStream(t, dir, "wardryx.ndjson", 2)
	side := ckSidecarPath(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(3)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	// A crash left a fragment after the complete records.
	if err := appendText(side, `{"v":1,"kind":"chec`); err != nil {
		t.Fatal(err)
	}
	w2, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Write(ckEvent(4)); err != nil {
		t.Fatal(err)
	}
	_ = w2.Close()
	raw, err := os.ReadFile(side)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`chec{`)) || bytes.Contains(raw, []byte(`"chec`+"\n")) {
		t.Fatalf("the torn fragment was glued onto a record: %s", raw)
	}
	rep := ckVerify(t, stream, side, s)
	if rep.Refusal() != "" {
		t.Fatalf("after a torn tail the sidecar must still verify: %s", rep.Refusal())
	}
}

// A writer does not re-read the bytes it has already hashed, so it cannot see a
// rewrite of them. The verifier can: a record written before the rewrite must be
// refused against the stream as it now stands.
func TestAStreamRewrittenUnderAWriterIsRefusedByTheVerifier(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stream, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	if rep.Refusal() == "" {
		t.Fatalf("a record written before the stream was rewritten must be refused against it: %+v", rep.Records)
	}
}

func TestTheResumedFromOfACheckpointedWriterIsTheStreamsTail(t *testing.T) {
	dir := t.TempDir()
	stream := ckStream(t, dir, "wardryx.ndjson", 2)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.ResumedFrom() == "" {
		t.Fatal("a checkpointed writer resumes its stream's chain like any other")
	}
}

func TestAStreamLineLongerThanTheWindowIsNotAnEvent(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	huge := strings.Repeat("x", resumeWindow+1)
	// Line 2 is replaced by a line the library cannot chain from: longer than its window.
	lines := strings.SplitAfter(stream, "\n")
	bad := lines[0] + huge + "\n" + lines[2]
	rep := ckVerifyBytes(t, bad, ckSidecarOf(ckSignedRecord(t, s, ckFields(stream, heads, 2))), s, "wardryx.ndjson")
	if got := ckRec(t, rep, 0); got.Status != CheckpointRefused || !strings.Contains(got.Refusal, "not a well-formed event") {
		t.Fatalf("a line over the window cannot be the head of a checkpoint: %+v", got)
	}
}

func TestTheRemainingRefusalsOfAMalformedRecordAreNamed(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	valid := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	var base map[string]any
	if err := json.Unmarshal([]byte(valid), &base); err != nil {
		t.Fatal(err)
	}
	withMember := func(k string, v any) string {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		b, err := canonicalJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct {
		name, line, want string
	}{
		{"not an object", "[1,2,3]", "not a JSON object"},
		{"count is a string", withMember("count", "2"), "member of the wrong type"},
		{"sig is not base64", withMember("sig", "!!!"), "sig is not 64 bytes"},
		{"a record over the cap", strings.Repeat("z", checkpointRecordCap+1), "longer than the record cap"},
	}
	for _, c := range cases {
		rep := ckVerifyBytes(t, stream, ckSidecarOf(c.line), s, "wardryx.ndjson")
		if got := ckRec(t, rep, 0); got.Status != CheckpointRefused || !strings.Contains(got.Refusal, c.want) {
			t.Fatalf("%s: want a refusal containing %q, got %+v", c.name, c.want, got)
		}
	}
}

func TestAVerifierWithNoKeysRefusesEverySignature(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	rep, err := VerifyCheckpoints(strings.NewReader(stream), strings.NewReader(ckSidecarOf(rec)), "wardryx.ndjson", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ckRec(t, rep, 0); got.Status != CheckpointRefused || !strings.Contains(got.Refusal, "does not hold") {
		t.Fatalf("with no key every signed record is refused: %+v", got)
	}
}

// failingReader fails after its first read.
type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n > 0 {
		return 0, errTestRead
	}
	f.n++
	return copy(p, "x"), nil
}

var errTestRead = errTestReadT{}

type errTestReadT struct{}

func (errTestReadT) Error() string { return "read failed" }

func TestAReadErrorOnTheStreamOrSidecarIsAnErrorNotAVerdict(t *testing.T) {
	s := newCkSigner(t)
	if _, err := VerifyCheckpoints(&failingReader{}, strings.NewReader(ckSidecarOf("{}")), "wardryx.ndjson", s.keys); err == nil {
		t.Fatal("a stream that cannot be read is not a verdict")
	}
	if _, err := VerifyCheckpoints(strings.NewReader("x\n"), &failingReader{}, "wardryx.ndjson", s.keys); err == nil {
		t.Fatal("a sidecar that cannot be read is not a verdict")
	}
}

func TestACheckpointSignatureOfTheWrongLengthIsAWriterError(t *testing.T) {
	dir := t.TempDir()
	w, err := NewChainedWriterWithCheckpoints(filepath.Join(dir, "wardryx.ndjson"), CheckpointConfig{Dir: dir, Signer: shortSigner{kid: "k"}, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err == nil || !strings.Contains(err.Error(), "not 64") {
		t.Fatalf("a signature that is not 64 bytes writes no record and is returned: %v", err)
	}
	_ = w.Close()
}

type shortSigner struct{ kid string }

func (s shortSigner) KeyID() string               { return s.kid }
func (s shortSigner) Sign([]byte) ([]byte, error) { return make([]byte, 63), nil }

func TestTheCheckpointedWriterNeedsADirectoryAndASigner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardryx.ndjson")
	if _, err := NewChainedWriterWithCheckpoints(path, CheckpointConfig{Signer: newCkSigner(t)}); err == nil {
		t.Fatal("checkpoints without a directory are refused")
	}
	if _, err := NewChainedWriterWithCheckpoints(path, CheckpointConfig{Dir: dir}); err == nil {
		t.Fatal("checkpoints without a signer are refused")
	}
}

// SPEC 6.5.1: a writer that finds its stream shorter than the bytes it hashed
// hashes it again from byte zero before it writes another checkpoint.
func TestAShrunkStreamIsHashedAgainFromByteZeroBeforeTheNextCheckpoint(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Truncate(stream, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(3)); err != nil {
		t.Fatalf("a shrunk stream is hashed again, not refused for ever: %v", err)
	}
	_ = w.Close()
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	last := ckRec(t, rep.CheckpointReport, len(rep.Records)-1)
	if last.Status != CheckpointValid {
		t.Fatalf("the checkpoint after the rehash verifies against the stream as it now is: %+v", last)
	}
	if rep.Records[0].Status != CheckpointRefused {
		t.Fatalf("the checkpoint written before the rewrite must be refused against the stream now: %+v", rep.Records[0])
	}
}

func TestASidecarRecordOverTheCapStopsTheWriter(t *testing.T) {
	dir := t.TempDir()
	stream := ckStream(t, dir, "wardryx.ndjson", 1)
	side := ckSidecarPath(dir, "wardryx.ndjson")
	if err := os.WriteFile(side, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := appendText(side, strings.Repeat("z", checkpointRecordCap+1)+"\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: (&ckClock{now: ckT0()}).Now}); err == nil {
		t.Fatal("a sidecar record over the cap is not silently rewritten")
	}
}

func TestTheDefaultClockStampsRecordsAndTheyVerify(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 64; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	if rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s); rep.Refusal() != "" || len(rep.Records) < 2 {
		t.Fatalf("records stamped by the default clock must verify: %+v", rep.Records)
	}
}

// A file another writer creates between this writer's open and its create is
// opened, never re-moded: the exclusive create fails and the existing file is used.
func TestAFileCreatedByAnotherWriterInTheMeantimeIsOpenedNotRecreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardryx.ndjson")
	prev := dirOwner
	t.Cleanup(func() { dirOwner = prev })
	dirOwner = func(d string) (bool, error) {
		// The other writer wins the race: it creates the file as its own.
		if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
			return false, err
		}
		return true, nil
	}
	w, err := NewChainedWriter(path)
	if err != nil {
		t.Fatalf("the race is not an error: %v", err)
	}
	_ = w.Close()
	assertMode(t, path, 0o600)
}

// Closing a checkpointed writer whose lock cannot be taken says so, and still
// closes its files.
func TestClosingACheckpointedWriterReportsALockThatCannotBeTaken(t *testing.T) {
	dir := t.TempDir()
	w, err := NewChainedWriterWithCheckpoints(filepath.Join(dir, "wardryx.ndjson"), CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	prev := lockForAppend
	t.Cleanup(func() { lockForAppend = prev })
	lockForAppend = func(*os.File) error { return errors.New("no lock here") }
	if err := w.Close(); err == nil || !strings.Contains(err.Error(), "checkpoint: lock") {
		t.Fatalf("a close that cannot lock must say so: %v", err)
	}
}

// A checkpointer cannot be opened over a stream it cannot size.
func TestACheckpointerCannotBeOpenedOverAClosedStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardryx.ndjson")
	f, err := openAppend(path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := openCheckpointFor(f, path, &CheckpointConfig{Dir: dir, Signer: newCkSigner(t)}); err == nil {
		t.Fatal("a closed stream has no size to checkpoint")
	}
}
