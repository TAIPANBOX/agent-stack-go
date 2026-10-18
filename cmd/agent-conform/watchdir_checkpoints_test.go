package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// Scenarios: features/watch-dir.feature, the restart and checkpoint scenarios.
// The checkpoint fixtures are written with the library's own writer and signed
// with a real ES256 key, so what this verifier reads is what a producer writes.

type wdSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newWdSigner(t *testing.T) *wdSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	in := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(in))
	return &wdSigner{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:])}
}

func (s *wdSigner) KeyID() string { return s.kid }

func (s *wdSigner) Sign(in []byte) ([]byte, error) {
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

// wdKeysFile writes the public key of s as the -checkpoint-keys file.
func wdKeysFile(t *testing.T, dir string, s *wdSigner) string {
	t.Helper()
	x := s.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := s.key.PublicKey.Y.FillBytes(make([]byte, 32))
	b, _ := json.Marshal(map[string]map[string]string{
		s.kid: {"crv": "P-256", "kty": "EC",
			"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)},
	})
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// wdEvents writes n events to stream with the chained writer, which has no
// checkpoints.
func wdEvents(t *testing.T, stream string, from, n int) {
	t.Helper()
	w, err := event.NewChainedWriter(stream)
	if err != nil {
		t.Fatal(err)
	}
	for i := from; i < from+n; i++ {
		if err := w.Write(fixtureEvent(filepath.Base(stream), i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func wdClock() func() time.Time {
	t0 := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	return func() time.Time { return t0 }
}

// wdCheckpointed writes n events with a checkpointing writer into ckDir.
func wdCheckpointed(t *testing.T, dir, ckDir string, s event.CheckpointSigner, stream string, n int) {
	t.Helper()
	w, err := event.NewChainedWriterWithCheckpoints(filepath.Join(dir, stream), event.CheckpointConfig{
		Dir: ckDir, Signer: s, Every: 2, Now: wdClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if err := w.Write(fixtureEvent(stream, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func wdAlerts(t *testing.T, dir, typ string) []event.Event {
	t.Helper()
	var out []event.Event
	for _, e := range busOut(t, dir) {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func wdLine(e event.Event) string {
	return fmt.Sprint(e.Data["line"])
}

func TestWatchDirReportsAChainRestartAsChainRestarted(t *testing.T) {
	dir := t.TempDir()
	stream := filepath.Join(dir, "wardryx.ndjson")
	wdEvents(t, stream, 1, 2)
	plain, err := event.NewWriter(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Write(fixtureEvent("wardryx", 3)); err != nil { // line 3: a head
		t.Fatal(err)
	}
	_ = plain.Close()
	wdEvents(t, stream, 4, 1) // line 4: chained to line 3

	r := runWatch(t, dir)
	if r.code != 0 {
		t.Fatalf("a restart is not a break: exit %d\n%s", r.code, r.stdout)
	}
	got := wdAlerts(t, dir, "chain_restarted")
	if len(got) != 1 || wdLine(got[0]) != "3" || got[0].Severity != event.SeverityHigh {
		t.Fatalf("one unexplained restart at line 3 must be a high chain_restarted, got %+v", got)
	}
}

func TestWatchDirAChainRestartExplainedByAResumeCheckpointIsMedium(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	stream := filepath.Join(dir, "wardryx.ndjson")
	wdEvents(t, stream, 1, 2)
	if err := appendText(stream, "not an event at all\n"); err != nil {
		t.Fatal(err)
	}
	s := newWdSigner(t)
	w, err := event.NewChainedWriterWithCheckpoints(stream, event.CheckpointConfig{Dir: ck, Signer: s, Now: wdClock()})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()             // writes a resume record naming line 2
	wdEvents(t, stream, 3, 1) // line 4: a head after the malformed line 3
	keys := wdKeysFile(t, dir, s)

	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", keys, dir)
	if r.code != 0 {
		t.Fatalf("an explained restart is not a failure: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	got := wdAlerts(t, dir, "chain_restarted")
	if len(got) != 1 || wdLine(got[0]) != "4" || got[0].Severity != event.SeverityMedium {
		t.Fatalf("a restart the resume checkpoint explains is medium, got %+v", got)
	}
}

func TestWatchDirRefusesAForgedPrefixCheckpointAndExitsOne(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newWdSigner(t)
	stream := filepath.Join(dir, "wardryx.ndjson")
	wdCheckpointed(t, dir, ck, s, "wardryx.ndjson", 3)
	keys := wdKeysFile(t, dir, s)
	// One space after the first colon: every chain hash unchanged, the bytes not.
	b, err := os.ReadFile(stream)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(b), ":", ": ", 1)
	if err := os.WriteFile(stream, []byte(forged), 0o640); err != nil {
		t.Fatal(err)
	}

	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", keys, dir)
	if r.code != 1 || !strings.Contains(r.stdout, "prefix does not match") {
		t.Fatalf("a rewritten earlier line must be refused by its checkpoint: exit %d\n%s", r.code, r.stdout)
	}
	if got := wdAlerts(t, dir, "chain_broken"); len(got) != 0 {
		t.Fatalf("the chain still passes, so no chain_broken: %+v", got)
	}
	again := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", keys, dir)
	if again.code != 0 {
		t.Fatalf("a refusal already reported is not new: exit %d\n%s", again.code, again.stdout)
	}
}

func TestWatchDirCheckpointsWithoutKeysIsAUsageError(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	wdEvents(t, filepath.Join(dir, "wardryx.ndjson"), 1, 2)
	r := runWatch(t, "-checkpoints", ck, dir)
	if r.code != 2 || !strings.Contains(r.stderr, "checkpoint-keys") {
		t.Fatalf("checkpoints that cannot be verified are not a pass, and the usage must name -checkpoint-keys: exit %d\n%s", r.code, r.stderr)
	}
}

func TestWatchDirATruncatedStreamIsRefusedAsATruncation(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newWdSigner(t)
	stream := filepath.Join(dir, "wardryx.ndjson")
	wdCheckpointed(t, dir, ck, s, "wardryx.ndjson", 3)
	b, _ := os.ReadFile(stream)
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(stream, []byte(lines[0]+lines[1]), 0o640); err != nil {
		t.Fatal(err)
	}
	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", wdKeysFile(t, dir, s), dir)
	if r.code != 1 || !strings.Contains(r.stdout, "shorter than") {
		t.Fatalf("a stream shorter than its checkpoint is a truncation: exit %d\n%s", r.code, r.stdout)
	}
}

func TestWatchDirAnUnsignedCheckpointIsNotAFailure(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newWdSigner(t)
	wdEvents(t, filepath.Join(dir, "wardryx.ndjson"), 1, 2)
	w, err := event.NewChainedWriterWithCheckpoints(filepath.Join(dir, "wardryx.ndjson"), event.CheckpointConfig{
		Dir: ck, Signer: expiredWd{kid: s.kid}, Every: 1, Now: wdClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", wdKeysFile(t, dir, s), dir); r.code != 0 {
		t.Fatalf("an unsigned checkpoint after key expiry is reported, not failed: exit %d\n%s", r.code, r.stdout)
	}
}

type expiredWd struct{ kid string }

func (e expiredWd) KeyID() string               { return e.kid }
func (e expiredWd) Sign([]byte) ([]byte, error) { return nil, event.ErrCheckpointKeyExpired }

func TestWatchDirRestartsOfAnUnchainedStreamAreNotReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardryx.ndjson")
	w, err := event.NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		if err := w.Write(fixtureEvent("wardryx", i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	_ = runWatch(t, dir)
	if got := wdAlerts(t, dir, "chain_restarted"); len(got) != 0 {
		t.Fatalf("an unchained stream is one chain_unchained, not a restart at every line: %+v", got)
	}
}

// appendText appends s to path.
func appendText(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(s)
	return err
}

// A key filed under a kid it does not carry is refused at start: the kid is the
// key's RFC 7638 thumbprint, so a key cannot be trusted under a name it does not hold.
func TestWatchDirRefusesAKeyFiledUnderAnotherKid(t *testing.T) {
	dir := t.TempDir()
	ck := filepath.Join(dir, "ckpt")
	if err := os.Mkdir(ck, 0o755); err != nil {
		t.Fatal(err)
	}
	wdEvents(t, filepath.Join(dir, "wardryx.ndjson"), 1, 2)
	s := newWdSigner(t)
	keys := wdKeysFile(t, dir, s)
	raw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	misfiled := strings.Replace(string(raw), s.kid, "not-the-thumbprint", 1)
	if err := os.WriteFile(keys, []byte(misfiled), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runWatch(t, "-checkpoints", ck, "-checkpoint-keys", keys, dir)
	if r.code != 2 || !strings.Contains(r.stderr, "RFC 7638") {
		t.Fatalf("a key under a kid that is not its thumbprint must stop the run: exit %d\n%s", r.code, r.stderr)
	}
}

// loadCheckpointKeys refuses every key that is not a P-256 point under its own
// thumbprint, and an empty set.
func TestTheKeysFileRefusesEveryKeyThatIsNotAPointUnderItsThumbprint(t *testing.T) {
	s := newWdSigner(t)
	good := wdKeysFile(t, t.TempDir(), s)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]string
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	inner := doc[s.kid]
	mutate := func(f func(m map[string]string)) string {
		m := map[string]string{}
		for k, v := range inner {
			m[k] = v
		}
		f(m)
		b, _ := json.Marshal(map[string]map[string]string{s.kid: m})
		p := filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"not json":       "not json",
		"no keys":        "{}",
		"not P-256":      mutate(func(m map[string]string) { m["crv"] = "P-384" }),
		"x of 31 bytes":  mutate(func(m map[string]string) { m["x"] = m["x"][:42] }),
		"y not base64":   mutate(func(m map[string]string) { m["y"] = "!!!" }),
		"not on a curve": mutate(func(m map[string]string) { m["y"] = m["x"] }),
	}
	for name, path := range cases {
		if strings.HasPrefix(path, "{") || path == "not json" {
			p := filepath.Join(t.TempDir(), "keys.json")
			if err := os.WriteFile(p, []byte(path), 0o600); err != nil {
				t.Fatal(err)
			}
			path = p
		}
		if _, err := loadCheckpointKeys(path); err == nil {
			t.Fatalf("%s: a keys file that holds a bad key must be refused", name)
		}
	}
	if _, err := loadCheckpointKeys(good); err != nil {
		t.Fatalf("the right key loads: %v", err)
	}
}

func TestWatchDirCheckpointsMustBeADirectory(t *testing.T) {
	dir := t.TempDir()
	wdEvents(t, filepath.Join(dir, "wardryx.ndjson"), 1, 2)
	s := newWdSigner(t)
	notDir := filepath.Join(dir, "a-file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runWatch(t, "-checkpoints", notDir, "-checkpoint-keys", wdKeysFile(t, dir, s), dir); r.code != 2 {
		t.Fatalf("-checkpoints must name a directory: exit %d", r.code)
	}
}
