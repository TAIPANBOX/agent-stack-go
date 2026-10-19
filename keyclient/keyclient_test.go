package keyclient

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clientFor(t *testing.T, base string, clk *clock, cred Credential) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: base, Consumer: consumerName, Credential: cred, Now: clk.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// statementClaims reads the claims out of a statement's payload, the way a
// verifier would before checking the signatures.
func statementClaims(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var s struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(s.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(p, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func mustRenew(t *testing.T, d *Delegated) {
	t.Helper()
	ok, err := d.RenewIfDue(context.Background())
	if !ok || err != nil {
		t.Fatalf("RenewIfDue = %v, %v; want a renewal with no error", ok, err)
	}
}

func TestDelegationCertifiesAKeyTheConsumerHolds(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	k, err := d.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if want, _ := delegation.Thumbprint(k.JWK); k.Kid != want || k.JWK.Kid != want {
		t.Fatalf("kid %q is not the thumbprint %q of the key it certifies", k.Kid, want)
	}
	if got := statementClaims(t, k.Statement)["kid"]; got != k.Kid {
		t.Fatalf("the statement certifies kid %v, the consumer holds %q", got, k.Kid)
	}
	sig, err := d.Sign([]byte("checkpoint"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Kid != k.Kid || sig.Alg != "ES256" || len(sig.Sig) != 64 {
		t.Fatalf("signature is %s by %q with %d bytes; want ES256 by %q with 64", sig.Alg, sig.Kid, len(sig.Sig), k.Kid)
	}
	pub, err := publicOf(k.JWK)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("checkpoint"))
	if !verifyRaw(pub, sum[:], sig.Sig) {
		t.Fatal("the local signature does not verify under the key custody certified")
	}
}

func TestRenewalIsAskedForAtHalfLife(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	clk.Advance(30*time.Minute - time.Second)
	if ok, err := d.RenewIfDue(context.Background()); ok || err != nil {
		t.Fatalf("RenewIfDue before half its life = %v, %v; want no renewal", ok, err)
	}
	if got := s.delegateCount(); got != 1 {
		t.Fatalf("custody received %d delegate requests before half life, want 1", got)
	}
	clk.Advance(time.Second)
	mustRenew(t, d)
	if got := s.delegateCount(); got != 2 {
		t.Fatalf("custody received %d delegate requests at half life, want 2", got)
	}
}

func TestAPublishAheadKeyIsNotUsedBeforeItsNotBefore(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	first, err := d.Current()
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(30 * time.Minute)
	s.setAhead(10 * time.Minute)
	mustRenew(t, d)

	clk.Advance(time.Minute) // t0+31m: the renewal does not begin until t0+40m
	sig, err := d.Sign([]byte("a"))
	if err != nil {
		t.Fatalf("Sign before the renewal begins: %v", err)
	}
	if sig.Kid != first.Kid {
		t.Fatalf("signed with %q before the renewal began, want the key still valid %q", sig.Kid, first.Kid)
	}

	clk.Advance(10 * time.Minute) // t0+41m
	second, err := d.Current()
	if err != nil {
		t.Fatal(err)
	}
	if second.Kid == first.Kid {
		t.Fatal("the renewed key was not picked up once its not_before had passed")
	}
	sig, err = d.Sign([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Kid != second.Kid {
		t.Fatalf("signed with %q after the renewal began, want %q", sig.Kid, second.Kid)
	}
}

func TestAnExpiredStatementIsNeverUsedToSign(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	s.setRefuse(http.StatusServiceUnavailable)
	clk.Advance(time.Hour + time.Second)
	if sig, err := d.Sign([]byte("late")); !errors.Is(err, ErrNoValidKey) {
		t.Fatalf("Sign after the statement ran out = %v, %v; want ErrNoValidKey and no signature", sig.Kid, err)
	}
	if _, err := d.Current(); !errors.Is(err, ErrNoValidKey) {
		t.Fatalf("Current after the statement ran out = %v; want ErrNoValidKey", err)
	}
}

func TestAFailedRenewalIsRetriedAfterAWaitNotAtOnce(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	clk.Advance(30 * time.Minute)
	s.setRefuse(http.StatusServiceUnavailable)
	ctx := context.Background()
	if ok, err := d.RenewIfDue(ctx); !ok || err == nil {
		t.Fatalf("a refused renewal = %v, %v; want an attempt and an error", ok, err)
	}
	if ok, err := d.RenewIfDue(ctx); ok || err != nil {
		t.Fatalf("a second attempt at once = %v, %v; want no attempt while waiting", ok, err)
	}
	if got := s.delegateCount(); got != 2 {
		t.Fatalf("custody received %d delegate requests, want 2 (the first, then the refused one)", got)
	}
	clk.Advance(5 * time.Minute)
	if ok, err := d.RenewIfDue(ctx); !ok || err == nil {
		t.Fatalf("after the wait = %v, %v; want another attempt", ok, err)
	}
	if got := s.delegateCount(); got != 3 {
		t.Fatalf("custody received %d delegate requests after the wait, want 3", got)
	}
}

func TestAStatementForAnotherKeyIsRefused(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.setWrongKid(true)
	if ok, err := d.RenewIfDue(context.Background()); !ok || err == nil {
		t.Fatalf("a statement for another key = %v, %v; want it refused", ok, err)
	}
	if _, err := d.Current(); !errors.Is(err, ErrNoValidKey) {
		t.Fatalf("after a refused statement Current = %v; want ErrNoValidKey", err)
	}
}

func TestAStatementForAnotherConsumerIsRefused(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.setWrongOwner(true)
	if ok, err := d.RenewIfDue(context.Background()); !ok || err == nil {
		t.Fatalf("a statement naming another consumer = %v, %v; want it refused", ok, err)
	}
	if _, err := d.Current(); !errors.Is(err, ErrNoValidKey) {
		t.Fatalf("after a refused statement Current = %v; want ErrNoValidKey", err)
	}
}

func TestAStatementOfAnotherLifetimeIsRefused(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.setWrongLife(true)
	if ok, err := d.RenewIfDue(context.Background()); !ok || err == nil {
		t.Fatalf("a statement of another life = %v, %v; want it refused", ok, err)
	}
	if _, err := d.Current(); !errors.Is(err, ErrNoValidKey) {
		t.Fatalf("after a refused statement Current = %v; want ErrNoValidKey", err)
	}
}

func TestALifetimeBelowTheMinimumIsRefusedBeforeAnyRequest(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	if _, err := c.Delegated("stream-key", "ES256", 5*time.Minute); err == nil {
		t.Fatal("a five-minute life was accepted; custody's floor is ten minutes")
	}
	if _, err := c.Delegated("stream-key", "ES256", time.Hour+time.Millisecond); err == nil {
		t.Fatal("a life that is not whole seconds was accepted")
	}
	if _, err := c.Delegated("stream-key", "ES512", time.Hour); err == nil {
		t.Fatal("an algorithm custody does not certify was accepted")
	}
	if got := s.requestCount(); got != 0 {
		t.Fatalf("custody received %d requests for refused configurations, want none", got)
	}
}

func TestAHeldKeyIsSignedByCustody(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	sig, err := c.Sign(context.Background(), "approval", []byte("the message"), "checkpoint")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Alg != "ES256" || sig.Kid != s.heldKid {
		t.Fatalf("answer is %s by %q; want ES256 by the held key %q", sig.Alg, sig.Kid, s.heldKid)
	}
	calls := s.signs()
	if len(calls) != 1 || string(calls[0].msg) != "the message" || calls[0].purpose != "checkpoint" {
		t.Fatalf("custody received %+v; want the message and its purpose once", calls)
	}
	sum := sha256.Sum256([]byte("the message"))
	if !verifyRaw(&s.heldKey.PublicKey, sum[:], sig.Sig) {
		t.Fatal("the signature custody answered does not verify under its held key")
	}
}

func TestEveryRequestCarriesTheCredentialFileAsItIsNow(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	path := tokenFile(t, "tok-1\n")
	s.setBearer("tok-1")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: path})
	if _, err := c.Sign(context.Background(), "approval", []byte("a"), "p"); err != nil {
		t.Fatalf("first sign: %v", err)
	}
	if err := os.WriteFile(path, []byte("tok-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.setBearer("tok-2")
	if _, err := c.Sign(context.Background(), "approval", []byte("b"), "p"); err != nil {
		t.Fatalf("sign after the token was rotated: %v", err)
	}
}

func TestTheSocketCredentialSendsNoBearer(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "k.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s.handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.setBearer("") // the stub refuses any Authorization header it is not expecting to see
	c, err := New(Config{BaseURL: "http://keyryx", Consumer: consumerName, Credential: Credential{Socket: sock}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(context.Background(), "approval", []byte("a"), "p"); err != nil {
		t.Fatalf("a sign over the consumer's socket: %v", err)
	}
	if got := len(s.signs()); got != 1 {
		t.Fatalf("custody received %d signs over the socket, want 1", got)
	}
}

func TestACredentialNamingTwoWaysOrNoneIsRefused(t *testing.T) {
	cases := map[string]Credential{
		"a socket and a key file": {Socket: "/run/keyryx/k.sock", BearerFile: "/run/keyryx/token"},
		"neither":                 {},
		"a relative socket path":  {Socket: "k.sock"},
	}
	for name, cred := range cases {
		if _, err := New(Config{BaseURL: "http://keyryx:4340", Consumer: consumerName, Credential: cred}); err == nil {
			t.Errorf("%s: New accepted the configuration", name)
		}
	}
	if _, err := New(Config{BaseURL: "http://keyryx:4340", Consumer: "Not A Name", Credential: Credential{BearerFile: "/t"}}); err == nil {
		t.Error("an invalid consumer name was accepted")
	}
	if _, err := New(Config{BaseURL: "http://keyryx:4340/v1", Consumer: consumerName, Credential: Credential{BearerFile: "/t"}}); err == nil {
		t.Error("a base URL with a path was accepted")
	}
	if _, err := New(Config{BaseURL: "ftp://keyryx", Consumer: consumerName, Credential: Credential{BearerFile: "/t"}}); err == nil {
		t.Error("a base URL that is not http or https was accepted")
	}
	c := clientFor(t, "http://keyryx:4340", newClock(), Credential{BearerFile: "/t"})
	if _, err := c.JWKS("Bad Name"); err == nil {
		t.Error("a key set name outside custody's grammar was accepted")
	}
}

func TestAnErrorNeverCarriesTheCredential(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	const canary = "CANARY-TOKEN-VALUE-7f3a"
	s.setBearer("another-token")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, canary+"\n")})
	_, err := c.Sign(context.Background(), "approval", []byte("a"), "p")
	if err == nil {
		t.Fatal("custody refused the credential and the sign succeeded")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("the error carries the credential: %v", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusForbidden {
		t.Fatalf("error is %v; want a StatusError with 403", err)
	}
}

func TestARedirectIsNotFollowedWithTheCredential(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)
	s.setRedirect(other.URL + "/v1/keys/approval/sign")
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	_, err := c.Sign(context.Background(), "approval", []byte("a"), "p")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusTemporaryRedirect {
		t.Fatalf("error is %v; want the redirect reported as a StatusError with 307", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the other host received %d requests, want none", got)
	}
}

// TestAStatementThatDisagreesWithTheRequestIsRefused covers each claim the client
// reads back against what it asked for: a statement is refused, and nothing is
// kept, whichever of them custody gets wrong.
func TestAStatementThatDisagreesWithTheRequestIsRefused(t *testing.T) {
	_, other := newKey(t, elliptic.P256())
	cases := map[string]func(map[string]any){
		"another version":    func(c map[string]any) { c["v"] = 2 },
		"another issuer":     func(c map[string]any) { c["iss"] = "someone" },
		"another name":       func(c map[string]any) { c["name"] = "other-key" },
		"another key kid":    func(c map[string]any) { c["jwk"].(map[string]any)["kid"] = other.Kid },
		"another key point":  func(c map[string]any) { c["jwk"].(map[string]any)["x"] = other.X },
		"another not_before": func(c map[string]any) { c["not_before"] = c["not_before"].(int64) + 1 },
		"another not_after":  func(c map[string]any) { c["not_after"] = c["not_after"].(int64) + 1 },
	}
	for name, tamper := range cases {
		clk := newClock()
		s := newStubCustody(t, clk)
		s.setBearer("tok")
		s.setTamper(tamper)
		c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
		d, err := c.Delegated("stream-key", "ES256", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := d.RenewIfDue(context.Background()); !ok || err == nil {
			t.Errorf("%s: the statement was accepted: %v, %v", name, ok, err)
		}
		if _, err := d.Current(); !errors.Is(err, ErrNoValidKey) {
			t.Errorf("%s: a refused statement left a key behind: %v", name, err)
		}
	}
}

// TestAnES384KeyIsCertifiedAndSignsWithA96ByteSignature keeps the ES384 half of
// the algorithm choice honest: its curve, its digest and its signature size.
func TestAnES384KeyIsCertifiedAndSignsWithA96ByteSignature(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES384", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustRenew(t, d)
	k, err := d.Current()
	if err != nil {
		t.Fatal(err)
	}
	if k.JWK.Crv != "P-384" || k.JWK.Alg != "ES384" {
		t.Fatalf("certified key is %s on %s; want ES384 on P-384", k.JWK.Alg, k.JWK.Crv)
	}
	sig, err := d.Sign([]byte("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Alg != "ES384" || len(sig.Sig) != 96 {
		t.Fatalf("signature is %s with %d bytes; want ES384 with 96", sig.Alg, len(sig.Sig))
	}
	pub, err := publicOf(k.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyRaw(pub, digestFor("ES384", []byte("checkpoint")), sig.Sig) {
		t.Fatal("the ES384 signature does not verify under the certified key")
	}
}

// TestTheRunLoopRenewsAndStops starts the loop, sees the first key certified, and
// stops it through its context.
func TestTheRunLoopRenewsAndStops(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.Run(ctx, nil)
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := d.Current(); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run never certified a first key")
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

// TestTheRunLoopReportsARefusedRenewal checks that a refused renewal reaches the
// caller's error hook, and that the loop does not return on it.
func TestTheRunLoopReportsARefusedRenewal(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	s.setBearer("tok")
	s.setRefuse(http.StatusServiceUnavailable)
	c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: tokenFile(t, "tok")})
	d, err := c.Delegated("stream-key", "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.Run(ctx, func(err error) {
			select {
			case reported <- err:
			default:
			}
		})
		close(done)
	}()
	select {
	case err := <-reported:
		var se *StatusError
		if !errors.As(err, &se) || se.Code != http.StatusServiceUnavailable {
			t.Fatalf("reported %v; want the 503 as a StatusError", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a refused renewal was never reported")
	}
	cancel()
	<-done
}

// TestACredentialFileThatIsEmptyOrMissingIsRefusedBeforeAnyRequest: a credential
// the client cannot read is a refusal before a request goes out, not a request
// with no credential in it.
func TestACredentialFileThatIsEmptyOrMissingIsRefusedBeforeAnyRequest(t *testing.T) {
	clk := newClock()
	s := newStubCustody(t, clk)
	missing := filepath.Join(t.TempDir(), "absent")
	for name, path := range map[string]string{"missing": missing, "empty": tokenFile(t, " \n")} {
		c := clientFor(t, s.srv.URL, clk, Credential{BearerFile: path})
		if _, err := c.Sign(context.Background(), "approval", []byte("a"), "p"); err == nil {
			t.Errorf("%s: a sign went ahead without a credential", name)
		}
	}
	if got := s.requestCount(); got != 0 {
		t.Fatalf("custody received %d requests without a credential, want none", got)
	}
}
