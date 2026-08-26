package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The whole point of A2, held as tests: an enforcement point can check one of
// these with what it already has, and it cannot accidentally check it as a
// bearer token.

const (
	vIss = "https://vouchryx.acme.example"
	vAud = "https://wardryx.acme.example"
	vURL = "https://wardryx.acme.example/v1/decide"
)

type fixture struct {
	issuer *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
	set    Set
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	iss, holder := newECKey(t), newECKey(t)
	return &fixture{
		issuer: iss,
		holder: holder,
		set:    Set{Keys: []JWK{FromPublic(&iss.PublicKey, "v-1")}},
		now:    time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mint builds what vouchryx issues.
func (f *fixture) mint(t *testing.T, over map[string]any) string {
	t.Helper()
	jkt, err := Thumbprint(FromPublic(&f.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	act, err := BuildAct([]string{"agent://acme/triage", "agent://acme/runbook"})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": vIss, "sub": "user://acme/alice", "aud": vAud,
		"iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(),
		"jti": "tok-1", "act": act,
		"cnf": map[string]any{"jkt": jkt},
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok, err := SignES256(f.issuer, "v-1", claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) proofFrom(t *testing.T, k *ecdsa.PrivateKey, jti string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": FromPublic(&k.PublicKey, ""),
	})
	claims, _ := json.Marshal(map[string]any{
		"htm": "POST", "htu": vURL, "iat": f.now.Unix(), "jti": jti,
	})
	signing := vb64(header) + "." + vb64(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + vb64(append(vpad(r), vpad(s)...))
}

func (f *fixture) opts(proof string) Options {
	return Options{
		Keys: f.set, Issuer: vIss, Audience: vAud, Now: f.now,
		Proof: proof, Method: "POST", URL: vURL,
	}
}

func TestAnEnforcementPointVerifiesWithWhatItAlreadyHolds(t *testing.T) {
	f := newFixture(t)
	got, err := Verify(f.mint(t, nil), f.opts(f.proofFrom(t, f.holder, "p1")))
	if err != nil {
		t.Fatalf("a good token was refused: %v", err)
	}
	if got.Subject != "user://acme/alice" {
		t.Fatalf("subject: %q", got.Subject)
	}
	want := "user://acme/alice,agent://acme/triage,agent://acme/runbook"
	if strings.Join(got.Chain, ",") != want {
		t.Fatalf("chain:\n got %v\nwant %s", got.Chain, want)
	}
	if len(got.Actors) != 2 {
		t.Fatalf("`act` holds actors only: %v", got.Actors)
	}
	if got.JTI != "tok-1" || got.ExpiresAt != f.now.Add(5*time.Minute).Unix() {
		t.Fatalf("%+v", got)
	}
}

// THE ONE THAT MAKES THIS WORTH HAVING. A stolen token is bytes; without this
// check every enforcement point in the estate honours them.
func TestATokenPresentedByTheWrongHolderIsRefused(t *testing.T) {
	f := newFixture(t)
	thief := newECKey(t)
	_, err := Verify(f.mint(t, nil), f.opts(f.proofFrom(t, thief, "p2")))
	if err == nil {
		t.Fatal("a stolen token was accepted by somebody who does not hold its key")
	}
}

// The failure that looks like it is working. An enforcement point that simply
// forgot to pass a proof would otherwise verify a sender-constrained token as a
// bearer token and report success.
func TestASenderConstrainedTokenCheckedWithoutAProofIsRefused(t *testing.T) {
	f := newFixture(t)
	o := f.opts("")
	if _, err := Verify(f.mint(t, nil), o); err != ErrNoProof {
		t.Fatalf("a bound token was checked as a bearer token: %v", err)
	}
	// And a caller that named no request cannot have the binding checked
	// either, so that is refused rather than checked partially.
	o = f.opts(f.proofFrom(t, f.holder, "p3"))
	o.Method, o.URL = "", ""
	if _, err := Verify(f.mint(t, nil), o); err == nil {
		t.Fatal("the binding was checked against a request nobody named")
	}
}

func TestAnUnboundTokenIsRefusedRatherThanTreatedAsSomethingElse(t *testing.T) {
	// vouchryx binds every token it mints, so one without `cnf` is either from
	// somewhere else or from a version that stopped binding. Both are worth
	// refusing loudly.
	f := newFixture(t)
	if _, err := Verify(f.mint(t, map[string]any{"cnf": nil}), f.opts(f.proofFrom(t, f.holder, "p4"))); err != ErrNotBound {
		t.Fatalf("an unbound token was accepted: %v", err)
	}
}

func TestAnExpiredOrEndlessDelegationIsRefused(t *testing.T) {
	// Endless as well as expired: this scheme's whole answer to a stolen token
	// is that it stops working.
	f := newFixture(t)
	for name, over := range map[string]map[string]any{
		"expired": {"exp": f.now.Add(-time.Second).Unix()},
		"endless": {"exp": nil},
	} {
		if _, err := Verify(f.mint(t, over), f.opts(f.proofFrom(t, f.holder, "e-"+name))); err != ErrExpired {
			t.Fatalf("an %s token was accepted: %v", name, err)
		}
	}
}

func TestATokenFromAnotherIssuerOrForAnotherAudienceIsRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := Verify(f.mint(t, map[string]any{"iss": "https://evil.example"}),
		f.opts(f.proofFrom(t, f.holder, "i1"))); err != ErrIssuer {
		t.Fatalf("wrong issuer accepted: %v", err)
	}
	if _, err := Verify(f.mint(t, map[string]any{"aud": "https://elsewhere.example"}),
		f.opts(f.proofFrom(t, f.holder, "a1"))); err != ErrAudience {
		t.Fatalf("wrong audience accepted: %v", err)
	}
	// And an issuer is matched exactly. A prefix is how a service trusts
	// `vouchryx.acme.example.evil.test`.
	o := f.opts(f.proofFrom(t, f.holder, "i2"))
	o.Issuer = vIss + ".evil.test"
	if _, err := Verify(f.mint(t, nil), o); err != ErrIssuer {
		t.Fatalf("issuer matched loosely: %v", err)
	}
}

func TestARevokedDelegationIsRefusedThoughItsSignatureIsPerfect(t *testing.T) {
	// The whole reason a revocation list exists: the token is valid, and the
	// authority behind it is gone.
	f := newFixture(t)
	o := f.opts(f.proofFrom(t, f.holder, "r1"))
	var askedJTI, askedSub string
	o.Revoked = func(jti, sub string, _ int64) bool {
		askedJTI, askedSub = jti, sub
		return true
	}
	if _, err := Verify(f.mint(t, nil), o); err != ErrRevoked {
		t.Fatalf("a revoked delegation was honoured: %v", err)
	}
	if askedJTI != "tok-1" || askedSub != "user://acme/alice" {
		t.Fatalf("the list was asked the wrong question: %q %q", askedJTI, askedSub)
	}
}

func TestRevocationIsNotConsultedForATokenThatFailedEarlier(t *testing.T) {
	// The order is deliberate: each step is cheaper than the next thing it
	// protects. A revocation lookup on a forged token is work an attacker
	// chose, and on a busy enforcement point that is the shape of a cheap
	// denial of service.
	f := newFixture(t)
	forged, err := SignES256(newECKey(t), "v-1", map[string]any{"sub": "x", "exp": f.now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	o := f.opts(f.proofFrom(t, f.holder, "r2"))
	o.Revoked = func(string, string, int64) bool { asked = true; return false }
	if _, err := Verify(forged, o); err == nil {
		t.Fatal("a forged token verified")
	}
	if asked {
		t.Fatal("the revocation list was consulted for a token whose signature failed")
	}
}

func TestTheSameProofIsNotAcceptedTwiceWhenACacheIsGiven(t *testing.T) {
	f := newFixture(t)
	o := f.opts(f.proofFrom(t, f.holder, "once"))
	o.Proofs = NewVerifier()
	if _, err := Verify(f.mint(t, nil), o); err != nil {
		t.Fatalf("the first presentation was refused: %v", err)
	}
	if _, err := Verify(f.mint(t, nil), o); err == nil {
		t.Fatal("the same proof was accepted twice")
	}
}

func TestVerificationTouchesNothingOutsideTheProcess(t *testing.T) {
	// A2's whole reason. `Options` has no URL, no client and no fetcher, so a
	// check cannot become a round trip by accident, and the token service does
	// not become a hard dependency of every enforcement point at once. Asserted
	// on the SHAPE, because a test that only observed no network today would
	// pass on the day somebody added one.
	var o Options
	raw, err := json.Marshal(struct{ Fields []string }{fieldsOf(o)})
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"Client", "HTTP", "Fetch", "Endpoint", "Timeout"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("Options grew something that reaches out: %s", raw)
		}
	}

	// And the list above is itself checked, which it was not until 2026-08-26.
	// It was written out on purpose, so that adding a field would be a visible
	// edit in the place somebody has to think about it, and that reasoning is
	// kept. What it lacked is the other half: nothing made the edit REQUIRED,
	// so a `Client` field added to Options and not added here would have left
	// this test scanning a list that no longer described the struct, passing,
	// for exactly the reason it exists to prevent. A hand-written list of what
	// to check is itself unchecked until something compares it with the
	// subject.
	actual := make([]string, 0, reflect.TypeOf(o).NumField())
	for i := 0; i < reflect.TypeOf(o).NumField(); i++ {
		actual = append(actual, reflect.TypeOf(o).Field(i).Name)
	}
	if strings.Join(actual, ",") != strings.Join(fieldsOf(o), ",") {
		t.Fatalf("Options has changed shape and the list this test scans has not:\n"+
			" struct: %v\n   list: %v", actual, fieldsOf(o))
	}
}

func fieldsOf(Options) []string {
	// Written out rather than reflected so that adding a field is a visible
	// edit here, which is where somebody would have to think about it. The
	// caller compares this against the real struct, so the edit is required
	// rather than merely invited.
	return []string{"Keys", "Issuer", "Audience", "Now", "Proof", "Method", "URL", "Proofs", "Revoked"}
}

func vb64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func vpad(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
