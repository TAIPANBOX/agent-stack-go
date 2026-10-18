package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Scenarios: features/checkpoints.feature. Each test plants one fault in a record
// (re-signed where the fault is in a signed member, so the signature is not what
// refuses it) or in the stream, and requires the verifier to refuse it for the
// reason named.

// ckSignedRecord writes one signed record with the given fields, using the real
// encoder and signer, and returns the line without its LF.
func ckSignedRecord(t *testing.T, s *ckSigner, f checkpointFields) string {
	t.Helper()
	_, rec, err := encodeCheckpoint(f, s)
	if err != nil {
		t.Fatal(err)
	}
	return string(rec)
}

// ckSidecarOf joins records into a sidecar file body.
func ckSidecarOf(records ...string) string {
	var b strings.Builder
	for _, r := range records {
		b.WriteString(r)
		b.WriteString("\n")
	}
	return b.String()
}

// ckVerifyBytes verifies stream bytes against sidecar bytes.
func ckVerifyBytes(t *testing.T, stream, sidecar string, s *ckSigner, name string) CheckpointReport {
	t.Helper()
	rep, err := VerifyCheckpoints(strings.NewReader(stream), strings.NewReader(sidecar), name, s.keys)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// ckThreeLines is a stream of three chained lines, and their chain hashes.
func ckThreeLines(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	path := ckStream(t, dir, "wardryx.ndjson", 3)
	raw := ckReadFile(t, path)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	heads := make([]string, len(lines))
	for i, l := range lines {
		h, err := ChainHashRaw([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		heads[i] = h
	}
	return string(raw), heads
}

func ckPrefix(stream string, count int) string {
	lines := strings.SplitAfter(stream, "\n")
	sum := sha256.Sum256([]byte(strings.Join(lines[:count], "")))
	return "sha256:" + bytesHex(sum[:])
}

func bytesHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func ckFields(stream string, heads []string, count int) checkpointFields {
	return checkpointFields{
		Kind:   "checkpoint",
		Stream: "wardryx.ndjson",
		Count:  count,
		Head:   heads[count-1],
		Prefix: ckPrefix(stream, count),
		At:     "2026-10-18T09:00:10.000Z",
		Prev:   "sha256:" + strings.Repeat("0", 64),
	}
}

func TestVerifyCheckpointsAcceptsARecordThatIsRightInEveryMember(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	rep := ckVerifyBytes(t, stream, ckSidecarOf(rec), s, "wardryx.ndjson")
	if len(rep.Records) != 1 || ckRec(t, rep, 0).Status != CheckpointValid {
		t.Fatalf("a right record must verify: %+v", rep.Records)
	}
}

func TestVerifyCheckpointsRefusesABadSignature(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	var m map[string]any
	_ = json.Unmarshal([]byte(rec), &m)
	sig, ok := m["sig"].(string)
	if !ok {
		t.Fatal("the encoder produced no signed record to corrupt")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(sig)
	raw[5] ^= 0x01
	m["sig"] = base64.RawURLEncoding.EncodeToString(raw)
	bad, _ := json.Marshal(m)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(string(bad)), s, "wardryx.ndjson")
	if ckRec(t, rep, 0).Status != CheckpointRefused || !strings.Contains(ckRec(t, rep, 0).Refusal, "signature does not verify") {
		t.Fatalf("a flipped signature byte must be refused, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsRefusesAHeadThatNamesAnotherLine(t *testing.T) {
	// Signed by the right key: only the head is wrong. A verifier that never
	// compared head would accept this.
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	f := ckFields(stream, heads, 2)
	f.Head = heads[0]
	rep := ckVerifyBytes(t, stream, ckSidecarOf(ckSignedRecord(t, s, f)), s, "wardryx.ndjson")
	if !strings.Contains(ckRec(t, rep, 0).Refusal, "head does not equal") {
		t.Fatalf("a head naming another line must be refused as a head, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsRefusesAPrefixOfOtherBytes(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	f := ckFields(stream, heads, 2)
	f.Prefix = ckPrefix(stream, 3)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(ckSignedRecord(t, s, f)), s, "wardryx.ndjson")
	if !strings.Contains(ckRec(t, rep, 0).Refusal, "prefix does not match") {
		t.Fatalf("a prefix of other bytes must be refused, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsRefusesAPrevThatDoesNotChain(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	first := ckSignedRecord(t, s, ckFields(stream, heads, 1))
	f := ckFields(stream, heads, 2)
	f.Prev = "sha256:" + strings.Repeat("1", 64)
	second := ckSignedRecord(t, s, f)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(first, second), s, "wardryx.ndjson")
	if ckRec(t, rep, 1).Status != CheckpointRefused || !strings.Contains(ckRec(t, rep, 1).Refusal, "prev does not chain") {
		t.Fatalf("a prev that does not chain must be refused, got %+v", ckRec(t, rep, 1))
	}
}

func TestVerifyCheckpointsRefusesARecordThatIsNotItsOwnCanonicalBytes(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(rec), &m)
	// The same members, in a different order, with a space: the same JSON.
	var b bytes.Buffer
	b.WriteString("{")
	first := true
	for _, k := range []string{"sig", "v", "stream", "prev", "prefix", "kid", "kind", "head", "count", "at", "alg"} {
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(`"` + k + `": `)
		b.Write(m[k])
	}
	b.WriteString("}")
	rep := ckVerifyBytes(t, stream, ckSidecarOf(b.String()), s, "wardryx.ndjson")
	if !strings.Contains(ckRec(t, rep, 0).Refusal, "not the canonical serialization") {
		t.Fatalf("a record that is not its own JCS bytes must be refused, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsRefusesAnotherStreamsRecord(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	f := ckFields(stream, heads, 2)
	f.Stream = "costcrew.ndjson"
	rep := ckVerifyBytes(t, stream, ckSidecarOf(ckSignedRecord(t, s, f)), s, "wardryx.ndjson")
	if !strings.Contains(ckRec(t, rep, 0).Refusal, "names stream") {
		t.Fatalf("a record for another stream must be refused, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsRefusesAnUnknownKid(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	other := newCkSigner(t)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(ckSignedRecord(t, other, ckFields(stream, heads, 2))), s, "wardryx.ndjson")
	if ckRec(t, rep, 0).Status != CheckpointRefused {
		t.Fatalf("a record under a key the verifier does not hold must be refused, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsReportsATruncatedStream(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 3))
	short := strings.SplitAfter(stream, "\n")[0] + strings.SplitAfter(stream, "\n")[1]
	rep := ckVerifyBytes(t, short, ckSidecarOf(rec), s, "wardryx.ndjson")
	if !ckRec(t, rep, 0).Truncated || !strings.Contains(ckRec(t, rep, 0).Refusal, "shorter than") {
		t.Fatalf("a stream shorter than the record's N bytes is a truncation, got %+v", ckRec(t, rep, 0))
	}
}

func TestVerifyCheckpointsIgnoresATornFinalLine(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	rec := ckSignedRecord(t, s, ckFields(stream, heads, 2))
	rep := ckVerifyBytes(t, stream, ckSidecarOf(rec)+`{"v":1,"kind":"chec`, s, "wardryx.ndjson")
	if len(rep.Records) != 1 || ckRec(t, rep, 0).Status != CheckpointValid {
		t.Fatalf("a torn final line is not a record and must not be refused as one: %+v", rep.Records)
	}
}

func TestVerifyCheckpointsOfAnEmptySidecarMeasuredNothing(t *testing.T) {
	stream, _ := ckThreeLines(t)
	s := newCkSigner(t)
	if _, err := VerifyCheckpoints(strings.NewReader(stream), strings.NewReader(""), "wardryx.ndjson", s.keys); err != ErrNoCheckpoints {
		t.Fatalf("no record is measured nothing, not a pass: got %v", err)
	}
}

func TestAnUnsignedRecordWithAnotherReasonIsRefused(t *testing.T) {
	stream, heads := ckThreeLines(t)
	s := newCkSigner(t)
	f := ckFields(stream, heads, 2)
	body := map[string]any{"v": 1, "kind": f.Kind, "stream": f.Stream, "count": f.Count, "head": f.Head,
		"prefix": f.Prefix, "at": f.At, "prev": f.Prev, "unsigned_reason": "because"}
	b, _ := json.Marshal(body)
	rep := ckVerifyBytes(t, stream, ckSidecarOf(string(b)), s, "wardryx.ndjson")
	if ckRec(t, rep, 0).Status != CheckpointRefused {
		t.Fatalf("an unsigned record must name the one reason v1 allows, got %+v", ckRec(t, rep, 0))
	}
}

// ckRec is record i of a report, failing the test rather than panicking when the
// verifier returned fewer records than the test expects.
func ckRec(t *testing.T, rep CheckpointReport, i int) CheckpointResult {
	t.Helper()
	if i >= len(rep.Records) {
		t.Fatalf("want record %d, the report has %d", i+1, len(rep.Records))
	}
	return rep.Records[i]
}
