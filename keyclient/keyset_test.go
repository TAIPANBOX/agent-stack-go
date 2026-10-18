package keyclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

const (
	issuer      = "vouchryx"
	audience    = "tokenfuse"
	verifyURL   = "https://tokenfuse.internal/v1/token"
	setName     = "vouchryx"
	holderProof = "proof-1"
)

// dpopProof is the RFC 9449 proof a holder presents with a bound token: signed by
// the holder's own key, carrying that key in its header, for one request.
func dpopProof(t *testing.T, holder *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	jwk := delegation.FromPublic(&holder.PublicKey, "")
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	claims := map[string]any{"htm": "POST", "htu": verifyURL, "iat": now.Unix(), "jti": holderProof}
	return signJWT(t, holder, header, claims)
}

func signJWT(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h := mustJSON(t, header)
	p := mustJSON(t, claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256Sum([]byte(signing))
	sig := rawSign(t, key, sum)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tokenAndProof issues a delegation token under the key with kid, bound to a
// fresh holder, and returns the token with the proof the holder presents.
func tokenAndProof(t *testing.T, key *ecdsa.PrivateKey, kid string, now time.Time) (string, string) {
	t.Helper()
	holder, holderJWK := newKey(t, elliptic.P256())
	jkt, err := delegation.Thumbprint(holderJWK)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": issuer, "aud": audience, "sub": "user://alice", "jti": "token-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"cnf": map[string]any{"jkt": jkt},
		// A delegation names the actor it was passed to: an empty act is refused as malformed.
		"act": map[string]any{"sub": "agent://broker.internal"},
	}
	token, err := delegation.SignES256(key, kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token, dpopProof(t, holder, now)
}

func verifyAgainst(j *JWKS, token, proof string, now time.Time) (delegation.Verified, error) {
	return delegation.Verify(token, delegation.Options{
		Keys: j.Set(), Issuer: issuer, Audience: audience, Now: now,
		Proof: proof, Method: "POST", URL: verifyURL,
	})
}

func newJWKS(t *testing.T, s *stubCustody, clk *clock) (*Client, *JWKS) {
	t.Helper()
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	j, err := c.JWKS(setName)
	if err != nil {
		t.Fatal(err)
	}
	return c, j
}

func TestAPolledKeyVerifiesATokenThroughDelegation(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	key, jwk := newKey(t, elliptic.P256())
	s.setJWKS(jwk)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	token, proof := tokenAndProof(t, key, jwk.Kid, clk.Now())
	v, err := verifyAgainst(j, token, proof, clk.Now())
	if err != nil {
		t.Fatalf("delegation.Verify with the polled set: %v", err)
	}
	if v.Subject != "user://alice" {
		t.Fatalf("subject %q, want user://alice", v.Subject)
	}
}

func TestWhenCustodyIsDownTheCachedKeysStillVerify(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	key, jwk := newKey(t, elliptic.P256())
	s.setJWKS(jwk)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.srv.Close()
	if err := j.Refresh(context.Background()); err == nil {
		t.Fatal("a poll against a stopped custody reported success")
	}
	token, proof := tokenAndProof(t, key, jwk.Kid, clk.Now())
	if _, err := verifyAgainst(j, token, proof, clk.Now()); err != nil {
		t.Fatalf("a token signed by a cached key was refused while custody was down: %v", err)
	}
}

func TestAnUnknownKidIsRefusedFromTheCache(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, jwkA := newKey(t, elliptic.P256())
	keyB, jwkB := newKey(t, elliptic.P256())
	s.setJWKS(jwkA)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokenB, proofB := tokenAndProof(t, keyB, jwkB.Kid, clk.Now())
	check := func(stage string) {
		t.Helper()
		if _, err := j.Lookup(jwkB.Kid); !errors.Is(err, delegation.ErrUnknownKid) {
			t.Fatalf("%s: Lookup of a kid the cache never held = %v; want ErrUnknownKid", stage, err)
		}
		if _, err := verifyAgainst(j, tokenB, proofB, clk.Now()); !errors.Is(err, delegation.ErrUnknownKid) {
			t.Fatalf("%s: a token under a kid the cache never held = %v; want ErrUnknownKid", stage, err)
		}
		if _, err := j.Lookup(jwkA.Kid); err != nil {
			t.Fatalf("%s: the key the cache holds was not found: %v", stage, err)
		}
	}
	check("custody up")
	if _, err := j.Lookup(""); !errors.Is(err, delegation.ErrNoKid) {
		t.Fatalf("Lookup of an empty kid = %v; want ErrNoKid", err)
	}
	s.srv.Close()
	check("custody down")
}

// TestAP384KeyInTheSetIsCachedAsP384 is the curve other than the ES256 one in
// the cache's own check, so a P-384 name verifies under the right size of point.
func TestAP384KeyInTheSetIsCachedAsP384(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, jwk := newKey(t, elliptic.P384())
	s.setJWKS(jwk)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatalf("a P-384 key was refused: %v", err)
	}
	got, err := j.Lookup(jwk.Kid)
	if err != nil || got.Crv != "P-384" {
		t.Fatalf("Lookup = %+v, %v; want the P-384 key", got, err)
	}
}

func TestAMalformedSetIsRefusedWholeAndTheCacheKept(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, jwkA := newKey(t, elliptic.P256())
	_, jwkB := newKey(t, elliptic.P256())
	s.setJWKS(jwkA)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	wrongKid := jwkB
	wrongKid.Kid = "not-the-thumbprint"

	offCurve := jwkB
	offCurve.X = base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))
	offCurve.Y = base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))
	if kid, err := delegation.Thumbprint(offCurve); err == nil {
		offCurve.Kid = kid
	}

	cases := map[string]string{
		"no keys member":               "{}",
		"keys is null":                 `{"keys":null}`,
		"not JSON":                     "<html>gateway</html>",
		"a key id repeated":            bodyOf(jwkB, jwkB),
		"a key id that is not its key": bodyOf(wrongKid),
		"a point not on its curve":     bodyOf(offCurve),
		"a key that is not EC":         `{"keys":[{"kty":"AKP","kid":"mldsa","pub":"AAAA"}]}`,
		"a good key beside a bad one":  bodyOf(jwkB, wrongKid),
	}
	for name, body := range cases {
		s.setRaw(body)
		if err := j.Refresh(context.Background()); err == nil {
			t.Errorf("%s: Refresh installed the set", name)
		}
		if _, err := j.Lookup(jwkA.Kid); err != nil {
			t.Errorf("%s: the cache lost the key it held: %v", name, err)
		}
		if _, err := j.Lookup(jwkB.Kid); !errors.Is(err, delegation.ErrUnknownKid) {
			t.Errorf("%s: the cache holds a key from a set it refused: %v", name, err)
		}
	}
}

func TestAnEmptySetInstallsAndVerifiesNothing(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	keyA, jwkA := newKey(t, elliptic.P256())
	s.setJWKS(jwkA)
	_, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.setRaw(`{"keys":[]}`)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatalf("an empty set is a valid answer and was refused: %v", err)
	}
	if n := len(j.Set().Keys); n != 0 {
		t.Fatalf("the cache holds %d keys after an empty set, want 0", n)
	}
	token, proof := tokenAndProof(t, keyA, jwkA.Kid, clk.Now())
	if _, err := verifyAgainst(j, token, proof, clk.Now()); !errors.Is(err, delegation.ErrUnknownKid) {
		t.Fatalf("a token under a key the empty set no longer names = %v; want ErrUnknownKid", err)
	}
}

func TestReadingTheCacheNeverReachesCustody(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, jwk := newKey(t, elliptic.P256())
	s.setJWKS(jwk)
	c, j := newJWKS(t, s, clk)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.setBearer("tok")
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	before := s.requestCount()
	for i := 0; i < 1000; i++ {
		_ = j.Set()
		_, _ = j.Lookup(jwk.Kid)
		_, _ = d.Sign([]byte("checkpoint"))
	}
	if got := s.requestCount(); got != before {
		t.Fatalf("reading the cache and signing locally made %d requests to custody, want none", got-before)
	}
}

// Run is not on any verification path, so the tests here only keep its loop
// honest: it stops when told to and it reports what it was asked to report.
func TestRunStopsWhenItsContextEnds(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, jwk := newKey(t, elliptic.P256())
	s.setJWKS(jwk)
	_, j := newJWKS(t, s, clk)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		j.Run(ctx, time.Second, nil)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for j.Fetched().IsZero() {
		select {
		case <-deadline:
			t.Fatal("Run never installed the set it was started with")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return when its context ended")
	}
}

func TestRunWithAFloorIntervalRefusesToStart(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	_, j := newJWKS(t, s, clk)
	var reported error
	j.Run(context.Background(), time.Millisecond, func(err error) { reported = err })
	if reported == nil {
		t.Fatal("Run started with a one-millisecond interval and reported nothing")
	}
	if s.requestCount() != 0 {
		t.Fatal("Run polled custody with an interval below its floor")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var _ = http.StatusOK
