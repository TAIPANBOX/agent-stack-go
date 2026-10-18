package event

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The scenarios these tests bind to are in features/checkpoints.feature.
// Signatures are real ES256 over a key generated for each test, so a record
// that verifies here verifies under any ES256 implementation.

type ckSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newCkSigner(t *testing.T) *ckSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &ckSigner{key: key, kid: ckThumbprint(&key.PublicKey)}
}

func (s *ckSigner) KeyID() string { return s.kid }

func (s *ckSigner) Sign(in []byte) ([]byte, error) {
	d := sha256.Sum256(in)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	sv.FillBytes(raw[32:])
	return raw, nil
}

// keys answers VerifyCheckpoints for this signer's kid only.
func (s *ckSigner) keys(kid string) (*ecdsa.PublicKey, bool) {
	if kid == s.kid {
		return &s.key.PublicKey, true
	}
	return nil, false
}

// ckThumbprint is RFC 7638 for an EC key, written out so it does not share code
// with the thing it checks.
func ckThumbprint(pub *ecdsa.PublicKey) string {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	in := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(in))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ckClock is a clock a test moves by hand.
type ckClock struct{ now time.Time }

func (c *ckClock) Now() time.Time { return c.now }

func ckT0() time.Time { return time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC) }

func ckEvent(i int) Event {
	return Event{
		Schema:   SchemaV10,
		TS:       fmt.Sprintf("2026-10-18T09:00:%02d.000Z", i%60),
		Source:   "wardryx",
		Type:     "policy_allow",
		AgentID:  "agent://acme-bank.example/support/tier1-bot",
		Severity: SeverityInfo,
		Data:     map[string]any{"seq": i},
	}
}

// ckStream writes n chained events with a writer that has no checkpoints, and
// returns the stream path.
func ckStream(t *testing.T, dir, name string, n int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	w, err := NewChainedWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if err := w.Write(ckEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func ckReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ckSidecarPath(dir, stream string) string {
	return filepath.Join(dir, CheckpointFileName(stream))
}

// ckRep is a verification with the helpers a test reads it through.
type ckRep struct {
	CheckpointReport
}

// Refusal is the first refusal of any record, or "" when none was refused.
func (r ckRep) Refusal() string {
	for _, rec := range r.Records {
		if rec.Status == CheckpointRefused {
			return rec.Refusal
		}
	}
	return ""
}

// ckVerify verifies the sidecar at sidecar against the stream at stream, with
// the keys of signer, and fails the test on a read error.
func ckVerify(t *testing.T, stream, sidecar string, s *ckSigner) ckRep {
	t.Helper()
	sf, err := os.Open(stream)
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	cf, err := os.Open(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Close()
	rep, err := VerifyCheckpoints(sf, cf, filepath.Base(stream), s.keys)
	if err != nil {
		t.Fatal(err)
	}
	return ckRep{rep}
}

// ckForeignDir makes every directory look owned by somebody else for the rest
// of the test.
func ckForeignDir(t *testing.T) {
	t.Helper()
	prev := dirOwner
	dirOwner = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { dirOwner = prev })
}
