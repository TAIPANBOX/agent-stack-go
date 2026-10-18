package event

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
)

// The vendored vectors are byte-identical to examples/checkpoint-vectors.json in
// TAIPANBOX/agent-passport (scripts/checkpoint-vectors-in-sync.sh holds that).
// These tests hold this package's encoder and verifier to them. Scenario:
// features/checkpoints.feature.

type vecFile struct {
	Key struct {
		Kid string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"key"`
	Stream struct {
		Name  string   `json:"name"`
		Lines []string `json:"lines"`
	} `json:"stream"`
	Checkpoints []struct {
		SigningInput string `json:"signing_input"`
		Record       string `json:"record"`
	} `json:"checkpoints"`
	NegativeVariants map[string]struct {
		Lines    []string          `json:"lines"`
		Refused  map[string]string `json:"refused"`
		Accepted []int             `json:"accepted"`
	} `json:"negative_variants"`
}

const vecPath = "testdata/checkpoint-vectors.json"

func loadVectors(t *testing.T) vecFile {
	t.Helper()
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vecFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Checkpoints) == 0 || len(v.Stream.Lines) == 0 {
		t.Fatalf("the vendored vectors carry no records: measured nothing")
	}
	return v
}

// vecSigner signs with the vector's own signature for the vector's own signing
// input, and with nothing else: the encoder's bytes are compared, not a key.
type vecSigner struct {
	kid  string
	sigs map[string][]byte
	gone bool
}

func (s vecSigner) KeyID() string { return s.kid }

func (s vecSigner) Sign(in []byte) ([]byte, error) {
	if s.gone {
		return nil, ErrCheckpointKeyExpired
	}
	sig, ok := s.sigs[string(in)]
	if !ok {
		return nil, errors.New("the vector has no signature for this signing input")
	}
	return sig, nil
}

func vecStreamBytes(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

func TestTheEncoderReproducesEveryVendoredRecordByteForByte(t *testing.T) {
	v := loadVectors(t)
	for i, c := range v.Checkpoints {
		var rec map[string]any
		if err := json.Unmarshal([]byte(c.Record), &rec); err != nil {
			t.Fatal(err)
		}
		f := checkpointFields{
			Kind:   rec["kind"].(string),
			Stream: rec["stream"].(string),
			Count:  int(rec["count"].(float64)),
			Head:   rec["head"].(string),
			Prefix: rec["prefix"].(string),
			At:     rec["at"].(string),
			Prev:   rec["prev"].(string),
		}
		s := vecSigner{kid: v.Key.Kid, sigs: map[string][]byte{}}
		if sig, ok := rec["sig"].(string); ok {
			raw, err := base64.RawURLEncoding.DecodeString(sig)
			if err != nil {
				t.Fatal(err)
			}
			s.sigs[c.SigningInput] = raw
		} else {
			s.gone = true
		}
		in, out, err := encodeCheckpoint(f, s)
		if err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
		if s.gone {
			if in != nil {
				t.Fatalf("record %d: an unsigned record has no signing input", i+1)
			}
		} else if string(in) != c.SigningInput {
			t.Fatalf("record %d: signing input differs\n got %s\nwant %s", i+1, in, c.SigningInput)
		}
		if string(out) != c.Record {
			t.Fatalf("record %d: bytes differ\n got %s\nwant %s", i+1, out, c.Record)
		}
	}
}

func TestTheVendoredRecordsVerifyOnTheirStream(t *testing.T) {
	v := loadVectors(t)
	s := vecVerifier(t, v)
	rep, err := VerifyCheckpoints(strings.NewReader(vecStreamBytes(v.Stream.Lines)), strings.NewReader(vecSidecar(v)), v.Stream.Name, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Records) != len(v.Checkpoints) {
		t.Fatalf("want %d records, got %d", len(v.Checkpoints), len(rep.Records))
	}
	for _, r := range rep.Records {
		want := CheckpointValid
		if r.Index == len(v.Checkpoints) {
			want = CheckpointUnsigned
		}
		if r.Status != want {
			t.Fatalf("record %d: status %d (%s), want %d", r.Index, r.Status, r.Refusal, want)
		}
	}
}

func TestTheVendoredNegativeVariantsAreRefusedExactlyAsNamed(t *testing.T) {
	v := loadVectors(t)
	s := vecVerifier(t, v)
	if len(v.NegativeVariants) == 0 {
		t.Fatal("no negative variants: measured nothing")
	}
	for name, nv := range v.NegativeVariants {
		rep, err := VerifyCheckpoints(strings.NewReader(vecStreamBytes(nv.Lines)), strings.NewReader(vecSidecar(v)), v.Stream.Name, s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for idx, reason := range nv.Refused {
			r := ckRec(t, rep, atoi(t, idx))
			if r.Status != CheckpointRefused || !strings.Contains(r.Refusal, reason) {
				t.Fatalf("%s: record %d must be refused with %q, got %+v", name, atoi(t, idx)+1, reason, r)
			}
		}
		for _, i := range nv.Accepted {
			if r := ckRec(t, rep, i); r.Status == CheckpointRefused {
				t.Fatalf("%s: record %d must be accepted, got refusal %q", name, i+1, r.Refusal)
			}
		}
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not an index: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func vecPublicKey(t *testing.T, v vecFile) *ecdsa.PublicKey {
	t.Helper()
	x, err := base64.RawURLEncoding.DecodeString(v.Key.X)
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(v.Key.Y)
	if err != nil {
		t.Fatal(err)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

func vecVerifier(t *testing.T, v vecFile) func(string) (*ecdsa.PublicKey, bool) {
	t.Helper()
	pub := vecPublicKey(t, v)
	return func(kid string) (*ecdsa.PublicKey, bool) {
		if kid == v.Key.Kid {
			return pub, true
		}
		return nil, false
	}
}

func vecSidecar(v vecFile) string {
	var b bytes.Buffer
	for _, c := range v.Checkpoints {
		b.WriteString(c.Record)
		b.WriteString("\n")
	}
	return b.String()
}
