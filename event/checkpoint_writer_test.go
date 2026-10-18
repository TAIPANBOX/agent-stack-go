package event

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Scenarios: features/checkpoints.feature.

func ckRecords(t *testing.T, path string) []string {
	t.Helper()
	raw := ckReadFile(t, path)
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestACheckpointIsWrittenEverySixtyFourEvents(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	clk := &ckClock{now: ckT0()}
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 64; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	recs := ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))
	if len(recs) < 1 {
		t.Fatalf("64 events wrote no checkpoint record")
	}
	if !strings.Contains(recs[0], `"count":64`) || !strings.Contains(recs[0], `"kind":"checkpoint"`) {
		t.Fatalf("the first record should be a checkpoint over 64 lines, got %s", recs[0])
	}
}

func TestACheckpointIsWrittenAfterTenSecondsEvenBelowSixtyFourEvents(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	clk := &ckClock{now: ckT0()}
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	if n := len(ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))); n != 0 {
		t.Fatalf("one event, no time passed: want no record, got %d", n)
	}
	clk.now = clk.now.Add(10 * time.Second)
	if err := w.Write(ckEvent(2)); err != nil {
		t.Fatal(err)
	}
	recs := ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))
	if len(recs) != 1 || !strings.Contains(recs[0], `"count":2`) {
		t.Fatalf("ten seconds later the writer should checkpoint its two lines, got %v", recs)
	}
	_ = w.Close()
}

func TestACloseWritesACloseRecordForTheWholeStream(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	recs := ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))
	last := recs[len(recs)-1]
	if !strings.Contains(last, `"kind":"close"`) || !strings.Contains(last, `"count":5`) {
		t.Fatalf("the last record should be a close over five lines, got %s", last)
	}
	res := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	if res.Refusal() != "" {
		t.Fatalf("a writer's own records must verify: %s", res.Refusal())
	}
}

func TestEveryRecordsPrefixIsTheStreamBytesThroughItsCount(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 2, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 7; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	if len(rep.Records) != 4 { // checkpoints at 2, 4, 6, then close at 7
		t.Fatalf("want 4 records (every two lines, then close), got %d", len(rep.Records))
	}
	for _, r := range rep.Records {
		if r.Status != CheckpointValid {
			t.Fatalf("record %d should be valid: %s", r.Index, r.Refusal)
		}
	}
}

func TestTwoWritersOnOneStreamKeepOneHonestPrefix(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	s := newCkSigner(t)
	clk := &ckClock{now: ckT0()}
	a, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Every: 3, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	// Another writer, with no checkpoints, appends two lines to the same file.
	b, err := NewChainedWriter(stream)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 3; i++ {
		if err := b.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = b.Close()
	// The first writer now writes; its prefix must cover the other writer's lines.
	for i := 4; i <= 6; i++ {
		if err := a.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.Close()
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	if len(rep.Records) == 0 {
		t.Fatalf("no records verified")
	}
	for _, r := range rep.Records {
		if r.Status != CheckpointValid {
			t.Fatalf("record %d over a shared stream must verify: %s", r.Index, r.Refusal)
		}
	}
}

// expiringSigner says the key may no longer sign.
type expiringSigner struct{ kid string }

func (e expiringSigner) KeyID() string               { return e.kid }
func (e expiringSigner) Sign([]byte) ([]byte, error) { return nil, ErrCheckpointKeyExpired }

func TestAnExpiredKeyWritesAnUnsignedRecordThatIsNotValid(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: expiringSigner{kid: "k"}, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	recs := ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))
	if len(recs) == 0 {
		t.Fatal("an expired key must still write a record, unsigned")
	}
	first := recs[0]
	if !strings.Contains(first, `"unsigned_reason":"key_expired"`) || strings.Contains(first, `"sig"`) || strings.Contains(first, `"alg"`) {
		t.Fatalf("want an unsigned record carrying unsigned_reason only, got %s", first)
	}
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), newCkSigner(t))
	if len(rep.Records) == 0 || rep.Records[0].Status != CheckpointUnsigned {
		t.Fatalf("an unsigned record is reported unsigned, never valid; got %+v", rep.Records)
	}
}

// failingSigner fails for a reason that is not expiry.
type failingSigner struct{ kid string }

func (f failingSigner) KeyID() string               { return f.kid }
func (f failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("signer unreachable") }

func TestASignerFailureWritesNoRecordAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: failingSigner{kid: "k"}, Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	werr := w.Write(ckEvent(1))
	if werr == nil || !strings.Contains(werr.Error(), "checkpoint") {
		t.Fatalf("a failed checkpoint must be returned, got %v", werr)
	}
	_ = w.Close()
	if n := len(ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))); n != 0 {
		t.Fatalf("a failed signature wrote %d record(s)", n)
	}
	if n := len(fileLines(t, stream)); n != 1 {
		t.Fatalf("the event itself is on disk even when its checkpoint fails: want 1 line, got %d", n)
	}
}

func TestAResumeRecordNamesTheLastWellFormedEvent(t *testing.T) {
	dir := t.TempDir()
	stream := ckStream(t, dir, "wardryx.ndjson", 2)
	if err := appendRaw(stream, "not an event at all\n"); err != nil {
		t.Fatal(err)
	}
	s := newCkSigner(t)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: s, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	recs := ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson"))
	if len(recs) == 0 || !strings.Contains(recs[0], `"kind":"resume"`) || !strings.Contains(recs[0], `"count":2`) {
		t.Fatalf("a writer that reopens a tail it cannot chain from writes a resume naming the last good line (2), got %v", recs)
	}
	rep := ckVerify(t, stream, ckSidecarPath(dir, "wardryx.ndjson"), s)
	if got := rep.ResumeCounts(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("the resume record should verify and name line 2, got %v (%+v)", got, rep.Records)
	}
}

func TestNoResumeRecordWhenTheTailChains(t *testing.T) {
	dir := t.TempDir()
	stream := ckStream(t, dir, "wardryx.ndjson", 2)
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	for _, r := range ckRecords(t, ckSidecarPath(dir, "wardryx.ndjson")) {
		if strings.Contains(r, `"kind":"resume"`) {
			t.Fatalf("a chainable tail is not a resume: %s", r)
		}
	}
}

func TestACheckpointIsNotCreatedInADirectoryItDoesNotOwn(t *testing.T) {
	ckForeignDir(t)
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	if _, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Now: (&ckClock{now: ckT0()}).Now}); err == nil {
		t.Fatalf("a checkpoints directory this process does not own must not gain a file")
	}
	if _, err := os.Stat(ckSidecarPath(dir, "wardryx.ndjson")); !os.IsNotExist(err) {
		t.Fatalf("the sidecar was created in a foreign directory: %v", err)
	}
}

func TestTheSidecarIsCreatedMode0640(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	w, err := NewChainedWriterWithCheckpoints(stream, CheckpointConfig{Dir: dir, Signer: newCkSigner(t), Every: 1, Now: (&ckClock{now: ckT0()}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(ckEvent(1)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	assertMode(t, ckSidecarPath(dir, "wardryx.ndjson"), 0o640)
}
