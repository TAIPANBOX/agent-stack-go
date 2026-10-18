package delegation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// An agent's own token (RFC 9068, typ at+jwt), held as tests. The constants are
// tokenfuse's `crates/delegation/src/testing.rs` fixture, so a reader comparing
// the Rust suite with this one compares like with like.
const (
	atIss   = "https://vouchryx.acme.example"
	atAud   = "https://tokenfuse.acme.example"
	atURL   = "https://tokenfuse.acme.example/v1/messages"
	atAgent = "agent://acme/triage"
	atUnit  = "ops"
	atOrg   = "default"
	atJTI   = "agent-tok-1"
	atNow   = int64(1_800_000_000)
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signCompact builds a compact JWS by hand, so a test controls every header
// member. The digest follows the header's alg and the signature width follows
// the key's curve, which is what lets a test ask what happens when the two
// disagree.
func signCompact(t testing.TB, k *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64url(h) + "." + b64url(p)
	alg, _ := header["alg"].(string)
	r, s, err := ecdsa.Sign(rand.Reader, k, digestFor(alg, []byte(signing)))
	if err != nil {
		t.Fatal(err)
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	return signing + "." + b64url(append(pad(r.Bytes(), size), pad(s.Bytes(), size)...))
}

// signHS256 is the forged token a real attacker sends: an HMAC under whatever
// bytes they choose to call the key.
func signHS256(t testing.TB, secret []byte, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	signing := b64url(h) + "." + b64url(p)
	return signing + "." + b64url(hmacSHA256(secret, signing))
}

func thumbOf(t testing.TB, k *ecdsa.PrivateKey) string {
	t.Helper()
	j, err := Thumbprint(FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// agentTokenClaims is what vouchryx's client_credentials grant mints: the agent
// as sub and client_id, one audience, five minutes, bound to `holder`, and the
// registry's unit, org and auth_src. `over` replaces claims; a nil value
// removes one.
func agentTokenClaims(t testing.TB, holder *ecdsa.PrivateKey, iat int64, over map[string]any) map[string]any {
	t.Helper()
	claims := map[string]any{
		"iss": atIss, "sub": atAgent, "client_id": atAgent, "aud": atAud,
		"iat": iat, "exp": iat + 300, "jti": atJTI,
		"cnf":  map[string]any{"jkt": thumbOf(t, holder)},
		"unit": atUnit, "org": atOrg, "auth_src": "enrolment-key",
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return claims
}

// mintAgent signs claims the way vouchryx does. An empty typ leaves the member
// out of the header altogether.
func mintAgent(t testing.TB, issuer *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "kid": kid}
	if typ != "" {
		header["typ"] = typ
	}
	return signCompact(t, issuer, header, claims)
}

// athOf is RFC 9449's ath of a token, computed here rather than by the
// function under test, so an expectation cannot come from the code it checks.
func athOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return b64url(sum[:])
}

// dpopProof is what a client sends beside its token: a proof by `k` for one
// request at one moment, naming `tok` in ath when `tok` is not empty.
func dpopProof(t testing.TB, k *ecdsa.PrivateKey, iat int64, method, u, jti, tok string) string {
	t.Helper()
	claims := map[string]any{"htm": method, "htu": u, "iat": iat, "jti": jti}
	if tok != "" {
		claims["ath"] = athOf(tok)
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": FromPublic(&k.PublicKey, "")}
	return signCompact(t, k, header, claims)
}

func neverRevoked(string, string, int64) bool { return false }

type agentFixture struct {
	issuer *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
	set    Set
	now    time.Time
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	iss := newECKey(t)
	return &agentFixture{
		issuer: iss,
		holder: newECKey(t),
		set:    Set{Keys: []JWK{FromPublic(&iss.PublicKey, "v-1")}},
		now:    time.Unix(atNow, 0),
	}
}

func (f *agentFixture) token(t *testing.T, over map[string]any) string {
	t.Helper()
	return mintAgent(t, f.issuer, "v-1", AgentTokenTyp, agentTokenClaims(t, f.holder, f.now.Unix(), over))
}

func (f *agentFixture) proof(t *testing.T, tok, jti string) string {
	t.Helper()
	return dpopProof(t, f.holder, f.now.Unix(), "POST", atURL, jti, tok)
}

// opts gives every call its own replay cache, so a test that verifies twice
// says so by sharing one.
func (f *agentFixture) opts(proof string) AccessOptions {
	return AccessOptions{
		Keys: f.set, Issuer: atIss, Audience: atAud, Now: f.now,
		Proof: proof, Method: "POST", URL: atURL,
		Proofs: NewReplayCache(16), Revoked: neverRevoked,
	}
}

func (f *agentFixture) verify(tok, proof string) (VerifiedAgent, error) {
	return VerifyAccess(tok, f.opts(proof))
}

// The door's view of a good agent token: the agent, and the unit and org the
// registry gave it, never a header's.
func TestAnAgentTokenVerifiesAndCarriesItsUnitAndOrg(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	got, err := f.verify(tok, f.proof(t, tok, "pa-1"))
	if err != nil {
		t.Fatalf("a good agent token was refused: %v", err)
	}
	want := VerifiedAgent{
		Subject: atAgent, Unit: atUnit, Org: atOrg, JTI: atJTI,
		JKT: thumbOf(t, f.holder), ProofJTI: "pa-1",
		IssuedAt: atNow, ExpiresAt: atNow + 300,
	}
	if got != want {
		t.Fatalf("verified:\n got %+v\nwant %+v", got, want)
	}
}

// typ both ways. The second half is the one that changes an existing function:
// before it, Verify read an at+jwt token carrying a delegation's claims as a
// delegation, so the same signed bytes answered to two different questions.
func TestADelegationTokenIsNeverAnAgentTokenAndTheReverse(t *testing.T) {
	f := newAgentFixture(t)
	claims := agentTokenClaims(t, f.holder, atNow, nil)
	for _, typ := range []string{"JWT", "", "AT+JWT", "application/at+jwt", "dpop+jwt"} {
		tok := mintAgent(t, f.issuer, "v-1", typ, claims)
		if _, err := f.verify(tok, f.proof(t, tok, "pa-2")); !errors.Is(err, ErrMalformed) {
			t.Errorf("typ %q verified as an agent token: %v", typ, err)
		}
		if IsAgentToken(tok) {
			t.Errorf("typ %q read as an agent token", typ)
		}
	}

	delegationOpts := func(tok string) Options {
		return Options{
			Keys: f.set, Issuer: atIss, Audience: atAud, Now: f.now,
			Proof: f.proof(t, tok, "pd-1"), Method: "POST", URL: atURL,
		}
	}
	agent := f.token(t, nil)
	if !IsAgentToken(agent) {
		t.Fatal("an at+jwt token was not recognised as one")
	}
	if _, err := Verify(agent, delegationOpts(agent)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an agent token verified as a delegation: %v", err)
	}
	// The shape that matters: at+jwt over a delegation's own claims. Without
	// the typ rule this is a perfectly good chain of two.
	chained := mintAgent(t, f.issuer, "v-1", AgentTokenTyp, map[string]any{
		"iss": atIss, "sub": "user://acme/alice", "aud": atAud,
		"iat": atNow, "exp": atNow + 300, "jti": "tok-1",
		"cnf": map[string]any{"jkt": thumbOf(t, f.holder)},
		"act": map[string]any{"sub": atAgent},
	})
	if _, err := Verify(chained, delegationOpts(chained)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an at+jwt token carrying a chain verified as a delegation: %v", err)
	}
	// And the control: the same claims typed JWT are still a delegation.
	plain := mintAgent(t, f.issuer, "v-1", "JWT", map[string]any{
		"iss": atIss, "sub": "user://acme/alice", "aud": atAud,
		"iat": atNow, "exp": atNow + 300, "jti": "tok-1",
		"cnf": map[string]any{"jkt": thumbOf(t, f.holder)},
		"act": map[string]any{"sub": atAgent},
	})
	if _, err := Verify(plain, delegationOpts(plain)); err != nil {
		t.Errorf("a delegation typed JWT stopped verifying: %v", err)
	}
}

// Required and exact: an empty configured audience accepts nothing, and a
// token for another resource, a prefix of this one, or none is refused.
func TestAnAgentTokensAudienceIsRequiredAndExact(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	o := f.opts(f.proof(t, tok, "pa-4"))
	o.Audience = ""
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrAudience) {
		t.Fatalf("an empty configured audience accepted a token: %v", err)
	}
	// The one token an empty audience would "match": aud "" itself.
	blank := f.token(t, map[string]any{"aud": ""})
	o = f.opts(f.proof(t, blank, "pa-4b"))
	o.Audience = ""
	if _, err := VerifyAccess(blank, o); !errors.Is(err, ErrAudience) {
		t.Fatalf("an empty configured audience accepted a token for the empty audience: %v", err)
	}
	for _, aud := range []any{
		"https://other.acme.example",
		"https://tokenfuse.acme.exampl",
		"https://tokenfuse.acme.example.evil",
		"https://tokenfuse.acme.example/",
		[]any{"https://other.acme.example"},
		[]any{},
		42,
		nil, // no aud claim at all
	} {
		tk := f.token(t, map[string]any{"aud": aud})
		if _, err := f.verify(tk, f.proof(t, tk, "pa-5")); !errors.Is(err, ErrAudience) {
			t.Errorf("aud %#v: %v", aud, err)
		}
	}
	// RFC 9068 allows an array; one that names this resource is for it.
	tk := f.token(t, map[string]any{"aud": []any{"https://other.acme.example", atAud}})
	if _, err := f.verify(tk, f.proof(t, tk, "pa-6")); err != nil {
		t.Errorf("an audience array naming this resource was refused: %v", err)
	}
}

func TestAnAgentTokenFromAnotherIssuerIsRefused(t *testing.T) {
	f := newAgentFixture(t)
	for _, iss := range []any{
		"https://vouchryx.evil.example",
		"https://vouchryx.acme.example/",
		"https://vouchryx.acme.example.evil",
		"HTTPS://VOUCHRYX.ACME.EXAMPLE",
		[]any{atIss},
		nil,
	} {
		tk := f.token(t, map[string]any{"iss": iss})
		if _, err := f.verify(tk, f.proof(t, tk, "pa-6")); !errors.Is(err, ErrIssuer) {
			t.Errorf("iss %#v: %v", iss, err)
		}
	}
	tok := f.token(t, nil)
	o := f.opts(f.proof(t, tok, "pa-6"))
	o.Issuer = ""
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrIssuer) {
		t.Errorf("an empty configured issuer accepted a token: %v", err)
	}
}

// A JWKS holds two keys during a rotation. Each token verifies by the key its
// kid names, and nothing else: not another key in the set, not an algorithm
// the header asks for that the key type does not permit.
func TestTheKeyIsTheOneItsKidNamesAndTheAlgorithmComesFromIt(t *testing.T) {
	f := newAgentFixture(t)
	next := newECKey(t)
	f.set.Keys = append(f.set.Keys, FromPublic(&next.PublicKey, "v-2"))
	claims := agentTokenClaims(t, f.holder, atNow, nil)
	for kid, k := range map[string]*ecdsa.PrivateKey{"v-1": f.issuer, "v-2": next} {
		tok := mintAgent(t, k, kid, AgentTokenTyp, claims)
		if _, err := f.verify(tok, f.proof(t, tok, "pk-"+kid)); err != nil {
			t.Errorf("a token signed by %s was refused: %v", kid, err)
		}
	}
	refused := map[string]struct {
		tok  string
		want error
	}{
		"signed by v-2, named v-1": {mintAgent(t, next, "v-1", AgentTokenTyp, claims), ErrBadSignature},
		"a kid nobody holds":       {mintAgent(t, next, "v-9", AgentTokenTyp, claims), ErrUnknownKid},
		"no kid":                   {signCompact(t, f.issuer, map[string]any{"alg": "ES256", "typ": AgentTokenTyp}, claims), ErrNoKid},
		"ES384 over a P-256 key":   {signCompact(t, f.issuer, map[string]any{"alg": "ES384", "typ": AgentTokenTyp, "kid": "v-1"}, claims), ErrAlgNotAllowed},
		"HS256 with the public key as the secret": {signHS256(t,
			[]byte(f.set.Keys[0].X+f.set.Keys[0].Y),
			map[string]any{"alg": "HS256", "typ": AgentTokenTyp, "kid": "v-1"}, claims), ErrAlgNotAllowed},
		"alg none": {func() string {
			h, _ := json.Marshal(map[string]any{"alg": "none", "typ": AgentTokenTyp, "kid": "v-1"})
			p, _ := json.Marshal(claims)
			return b64url(h) + "." + b64url(p) + "."
		}(), ErrAlgNotAllowed},
	}
	for name, c := range refused {
		if _, err := f.verify(c.tok, f.proof(t, c.tok, "pk-x")); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
	// A key set that lists a symmetric key, and an HS256 token naming it: no
	// asymmetric verifier accepts a shared secret it never agreed to share,
	// even one its own set lists. Kept out of the shared table on purpose: a
	// symmetric key in a published set is the secret itself.
	secret := []byte("a shared secret nobody agreed to")
	f.set.Keys = append(f.set.Keys, JWK{Kty: "oct", Kid: "oct-1"})
	hs := signHS256(t, secret, map[string]any{"alg": "HS256", "typ": AgentTokenTyp, "kid": "oct-1"}, claims)
	if _, err := f.verify(hs, f.proof(t, hs, "pk-oct")); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("an HS256 token naming a symmetric key in the set: %v", err)
	}
}

// Thirty seconds past exp is the edge: one second inside it verifies, the edge
// itself does not. The clock is read in whole seconds, as the Rust door reads
// it, so a fraction of a second never moves either edge.
func TestAnAgentTokenExpiresAtItsLeewayAndNotBefore(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	exp := atNow + 300
	leeway := int64(AgentTokenLeeway / time.Second)
	at := func(now time.Time, jti string) error {
		o := f.opts(dpopProof(t, f.holder, now.Unix(), "POST", atURL, jti, tok))
		o.Now = now
		_, err := VerifyAccess(tok, o)
		return err
	}
	if err := at(time.Unix(exp+leeway-1, 0), "pa-7"); err != nil {
		t.Fatalf("29 s past exp is inside the 30 s leeway: %v", err)
	}
	if err := at(time.Unix(exp+leeway-1, 999_000_000), "pa-7b"); err != nil {
		t.Fatalf("29.999 s past exp is still 29 s on a clock read in seconds: %v", err)
	}
	if err := at(time.Unix(exp+leeway, 0), "pa-8"); !errors.Is(err, ErrExpired) {
		t.Fatalf("30 s past exp verified: %v", err)
	}
	if err := at(time.Unix(exp+3600, 0), "pa-8b"); !errors.Is(err, ErrExpired) {
		t.Fatalf("an hour past exp verified: %v", err)
	}
	// No exp at all is a permanent grant, and never verifies.
	noExp := f.token(t, map[string]any{"exp": nil})
	if _, err := f.verify(noExp, f.proof(t, noExp, "pa-8c")); !errors.Is(err, ErrExpired) {
		t.Fatalf("a token with no exp verified: %v", err)
	}
	// A proof exactly a window old at a clock half a second past the second:
	// the Rust door, reading whole seconds, accepts it, and so must this one.
	o := f.opts(dpopProof(t, f.holder, atNow-60, "POST", atURL, "pa-8d", tok))
	o.Now = time.Unix(atNow, 500_000_000)
	if _, err := VerifyAccess(tok, o); err != nil {
		t.Fatalf("a proof exactly one window old was refused on a fraction of a second: %v", err)
	}
}

// A token issued more than the leeway ahead of this clock is refused; at the
// leeway it is not.
func TestAnAgentTokenIssuedInTheFutureIsRefusedPastTheLeeway(t *testing.T) {
	f := newAgentFixture(t)
	leeway := int64(AgentTokenLeeway / time.Second)
	ahead := mintAgent(t, f.issuer, "v-1", AgentTokenTyp, agentTokenClaims(t, f.holder, atNow+leeway+1, nil))
	if _, err := f.verify(ahead, f.proof(t, ahead, "pa-9")); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("an iat 31 s ahead: %v", err)
	}
	edge := mintAgent(t, f.issuer, "v-1", AgentTokenTyp, agentTokenClaims(t, f.holder, atNow+leeway, nil))
	if _, err := f.verify(edge, f.proof(t, edge, "pa-10")); err != nil {
		t.Fatalf("an iat exactly 30 s ahead was refused: %v", err)
	}
}

// An agent token names an agent acting for nobody: sub an agent:// URI with
// something after the scheme, equal to client_id, a jti, and no act.
func TestAnAgentTokenNamesOneAgentAndNobodyElse(t *testing.T) {
	f := newAgentFixture(t)
	for _, over := range []map[string]any{
		{"client_id": "agent://acme/other"},
		{"client_id": nil},
		{"client_id": ""},
		{"sub": "user://acme/alice", "client_id": "user://acme/alice"},
		{"sub": "agent://", "client_id": "agent://"},
		{"sub": "agentx://acme/triage", "client_id": "agentx://acme/triage"},
		{"sub": "AGENT://acme/triage", "client_id": "AGENT://acme/triage"},
		{"sub": nil, "client_id": nil},
		{"act": map[string]any{"sub": "agent://acme/runbook"}},
		{"act": map[string]any{}},
		{"jti": nil},
		{"jti": ""},
	} {
		tk := f.token(t, over)
		if _, err := f.verify(tk, f.proof(t, tk, "pa-15")); !errors.Is(err, ErrMalformed) {
			t.Errorf("%v: %v", over, err)
		}
	}
	// A JSON null act is no act: the Rust verifier reads it as absent, so must
	// this one, or the two disagree about a token vouchryx could mint.
	tk := f.token(t, map[string]any{"act": json.RawMessage("null")})
	if _, err := f.verify(tk, f.proof(t, tk, "pa-15b")); err != nil {
		t.Errorf("act: null was refused: %v", err)
	}
}

// The binding: no proof, a stranger's proof, a proof for another request or
// moment, and a token with no cnf.jkt at all.
func TestAnAgentTokenNeedsItsHoldersProofAndABinding(t *testing.T) {
	f := newAgentFixture(t)
	thief := newECKey(t)
	tok := f.token(t, nil)
	if _, err := f.verify(tok, ""); !errors.Is(err, ErrNoProof) {
		t.Fatalf("a bound token with no proof: %v", err)
	}
	for _, o := range []func(*AccessOptions){
		func(o *AccessOptions) { o.Method = "" },
		func(o *AccessOptions) { o.URL = "" },
	} {
		opts := f.opts(f.proof(t, tok, "pa-12"))
		o(&opts)
		if _, err := VerifyAccess(tok, opts); !errors.Is(err, ErrNoProof) {
			t.Errorf("a proof checked without the request it is for: %v", err)
		}
	}
	for name, p := range map[string]string{
		"a stranger's proof":      dpopProof(t, thief, atNow, "POST", atURL, "pa-13", tok),
		"another URL":             dpopProof(t, f.holder, atNow, "POST", "https://tokenfuse.acme.example/v1/chat/completions", "pa-13", tok),
		"another method":          dpopProof(t, f.holder, atNow, "GET", atURL, "pa-13", tok),
		"the method in lowercase": dpopProof(t, f.holder, atNow, "post", atURL, "pa-13", tok),
		"61 s old":                dpopProof(t, f.holder, atNow-61, "POST", atURL, "pa-13", tok),
		"61 s ahead":              dpopProof(t, f.holder, atNow+61, "POST", atURL, "pa-13", tok),
		"no jti":                  dpopProof(t, f.holder, atNow, "POST", atURL, "", tok),
		"not a proof at all":      tok,
	} {
		if _, err := f.verify(tok, p); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, cnf := range []any{nil, map[string]any{}, map[string]any{"jkt": ""}} {
		unbound := f.token(t, map[string]any{"cnf": cnf})
		if _, err := f.verify(unbound, f.proof(t, unbound, "pa-14")); !errors.Is(err, ErrNotBound) {
			t.Errorf("cnf %#v: %v", cnf, err)
		}
	}
}

// RFC 9449 section 4.2: the proof must name THIS token. A proof naming none,
// another token of the same holder, or this token's hash spelled another way
// is refused.
func TestAProofThatDoesNotNameThisTokenIsRefused(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	other := f.token(t, map[string]any{"jti": "agent-tok-2"})
	sum := sha256.Sum256([]byte(tok))
	padded := map[string]any{
		"htm": "POST", "htu": atURL, "iat": atNow, "jti": "pa-11c",
		"ath": base64.URLEncoding.EncodeToString(sum[:]),
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": FromPublic(&f.holder.PublicKey, "")}
	for name, p := range map[string]string{
		"no ath":                   dpopProof(t, f.holder, atNow, "POST", atURL, "pa-11", ""),
		"another token's ath":      dpopProof(t, f.holder, atNow, "POST", atURL, "pa-12", other),
		"this token's ath, padded": signCompact(t, f.holder, header, padded),
	} {
		if _, err := f.verify(tok, p); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A client chooses its proof's jti and the replay cache stores it, so a door
// refuses one too long to be worth remembering. 256 bytes is tokenfuse's bound.
func TestAProofWhoseJtiIsTooLongToRememberIsRefused(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	if _, err := f.verify(tok, f.proof(t, tok, strings.Repeat("j", maxProofJTIBytes+1))); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a 257-byte proof jti: %v", err)
	}
	if _, err := f.verify(tok, f.proof(t, tok, strings.Repeat("j", maxProofJTIBytes))); err != nil {
		t.Fatalf("a 256-byte proof jti was refused: %v", err)
	}
}

// The hook is asked about the agent, by the token's jti, its subject and its
// iat, once, after everything else verified.
func TestARevokedAgentTokenIsRefusedByItsSubjectOrItsJti(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	var asked []string
	o := f.opts(f.proof(t, tok, "pa-16"))
	o.Revoked = func(jti, sub string, iat int64) bool {
		asked = append(asked, fmt.Sprintf("%s|%s|%d", jti, sub, iat))
		return sub == atAgent
	}
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked by subject: %v", err)
	}
	if want := []string{fmt.Sprintf("%s|%s|%d", atJTI, atAgent, atNow)}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("the hook was asked %v, want %v", asked, want)
	}
	o = f.opts(f.proof(t, tok, "pa-17"))
	o.Revoked = func(jti, _ string, _ int64) bool { return jti == atJTI }
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked by jti: %v", err)
	}
	// The negative control: a hook naming somebody else refuses nobody.
	o = f.opts(f.proof(t, tok, "pa-18"))
	o.Revoked = func(jti, sub string, _ int64) bool { return sub == "agent://acme/other" || jti == "other" }
	if _, err := VerifyAccess(tok, o); err != nil {
		t.Fatalf("a revocation of another agent refused this one: %v", err)
	}
}

// A revocation lookup on a token that already failed is work the presenter
// chose, so the hook is asked last. And a refused presentation leaves its
// proof unspent: the replay cache records a proof only once everything else,
// the revocation hook included, has said yes.
func TestRevocationIsAskedLastAndOnlyForATokenThatPassedEverythingElse(t *testing.T) {
	f := newAgentFixture(t)
	thief := newECKey(t)
	good := f.token(t, nil)
	cases := map[string]struct{ tok, proof string }{
		"typ JWT":        {mintAgent(t, f.issuer, "v-1", "JWT", agentTokenClaims(t, f.holder, atNow, nil)), ""},
		"another issuer": {f.token(t, map[string]any{"iss": "https://vouchryx.evil.example"}), ""},
		"expired":        {f.token(t, map[string]any{"exp": atNow - 31}), ""},
		"unbound":        {f.token(t, map[string]any{"cnf": nil}), ""},
		"no proof":       {good, "-"},
		"a stolen proof": {good, dpopProof(t, thief, atNow, "POST", atURL, "pr-1", good)},
		"no ath":         {good, dpopProof(t, f.holder, atNow, "POST", atURL, "pr-2", "")},
	}
	for name, c := range cases {
		p := c.proof
		switch p {
		case "":
			p = f.proof(t, c.tok, "pr-0")
		case "-":
			p = ""
		}
		calls := 0
		o := f.opts(p)
		o.Revoked = func(string, string, int64) bool { calls++; return true }
		if _, err := VerifyAccess(c.tok, o); err == nil || errors.Is(err, ErrRevoked) {
			t.Errorf("%s: want its own refusal, got %v", name, err)
		}
		if calls != 0 {
			t.Errorf("%s: the revocation hook was asked %d time(s) about a token that had already failed", name, calls)
		}
	}

	cache := NewReplayCache(16)
	p := f.proof(t, good, "pr-3")
	o := f.opts(p)
	o.Proofs = cache
	o.Revoked = func(string, string, int64) bool { return true }
	if _, err := VerifyAccess(good, o); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked token: %v", err)
	}
	o.Revoked = neverRevoked
	if _, err := VerifyAccess(good, o); err != nil {
		t.Fatalf("the proof of a refused presentation was spent: %v", err)
	}
}

// One proof, one use: presented again inside its window, it is refused, and a
// fresh proof from the same holder still verifies.
func TestAProofPresentedTwiceIsRefusedTheSecondTime(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	cache := NewReplayCache(16)
	o := f.opts(f.proof(t, tok, "pa-19"))
	o.Proofs = cache
	if _, err := VerifyAccess(tok, o); err != nil {
		t.Fatalf("first presentation: %v", err)
	}
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrReplay) {
		t.Fatalf("the same proof presented twice: %v", err)
	}
	o.Now = f.now.Add(59 * time.Second)
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrReplay) {
		t.Fatalf("the same proof 59 s later: %v", err)
	}
	o = f.opts(f.proof(t, tok, "pa-20"))
	o.Proofs = cache
	if _, err := VerifyAccess(tok, o); err != nil {
		t.Fatalf("a fresh proof from the same holder: %v", err)
	}
	// One cache, every door of the process: a proof spent at one is spent at
	// all of them, which is why the cache is the caller's and not the call's.
	full := NewReplayCache(1)
	o = f.opts(f.proof(t, tok, "pa-21"))
	o.Proofs = full
	if _, err := VerifyAccess(tok, o); err != nil {
		t.Fatalf("a cache of one admits one: %v", err)
	}
	o = f.opts(f.proof(t, tok, "pa-22"))
	o.Proofs = full
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("a full cache: %v", err)
	}
}

// Forgetting the replay cache or the revocation hook is a door that checks
// less while reporting success. Both are refused before any token is read.
func TestAVerifierWithoutAReplayCacheOrARevocationHookRefusesEverything(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	o := f.opts(f.proof(t, tok, "pa-23"))
	o.Proofs = nil
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no replay cache: %v", err)
	}
	o = f.opts(f.proof(t, tok, "pa-24"))
	o.Revoked = nil
	if _, err := VerifyAccess(tok, o); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no revocation hook: %v", err)
	}
	o = f.opts("")
	o.Revoked = nil
	if _, err := VerifyRelayedAccess(tok, o); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("relayed with no revocation hook: %v", err)
	}
	o = f.opts("")
	o.Proofs = nil
	if _, err := VerifyRelayedAccess(tok, o); err != nil {
		t.Errorf("a relayed token needs no replay cache, it came with no proof: %v", err)
	}
}

// The relay: a token another door of this deployment verified with its proof
// is checked again on everything but the proof.
func TestARelayedAgentTokenSkipsTheProofAndNothingElse(t *testing.T) {
	f := newAgentFixture(t)
	tok := f.token(t, nil)
	got, err := VerifyRelayedAccess(tok, f.opts(""))
	if err != nil {
		t.Fatalf("a relayed agent token was refused: %v", err)
	}
	want := VerifiedAgent{
		Subject: atAgent, Unit: atUnit, Org: atOrg, JTI: atJTI,
		JKT: thumbOf(t, f.holder), IssuedAt: atNow, ExpiresAt: atNow + 300,
	}
	if got != want {
		t.Fatalf("relayed:\n got %+v\nwant %+v", got, want)
	}
	// A proof handed to the relayed verifier is not consulted: a stranger's
	// does not refuse it and is not recorded.
	cache := NewReplayCache(16)
	o := f.opts(dpopProof(t, newECKey(t), atNow, "POST", atURL, "pr-9", tok))
	o.Proofs = cache
	if _, err := VerifyRelayedAccess(tok, o); err != nil {
		t.Fatalf("the relayed verifier read a proof: %v", err)
	}
	if err := cache.CheckAndRecord("pr-9", f.now); err != nil {
		t.Fatalf("the relayed verifier recorded a proof: %v", err)
	}

	expired := f.opts("")
	expired.Now = time.Unix(atNow+300+int64(AgentTokenLeeway/time.Second), 0)
	noAud := f.opts("")
	noAud.Audience = ""
	revoked := f.opts("")
	revoked.Revoked = func(_, sub string, _ int64) bool { return sub == atAgent }
	for name, c := range map[string]struct {
		tok  string
		o    AccessOptions
		want error
	}{
		"unbound":     {f.token(t, map[string]any{"cnf": nil}), f.opts(""), ErrNotBound},
		"expired":     {tok, expired, ErrExpired},
		"typ JWT":     {mintAgent(t, f.issuer, "v-1", "JWT", agentTokenClaims(t, f.holder, atNow, nil)), f.opts(""), ErrMalformed},
		"revoked":     {tok, revoked, ErrRevoked},
		"no audience": {tok, noAud, ErrAudience},
		"a user":      {f.token(t, map[string]any{"sub": "user://acme/alice", "client_id": "user://acme/alice"}), f.opts(""), ErrMalformed},
	} {
		if _, err := VerifyRelayedAccess(c.tok, c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

// RFC 9449 section 7.1's own example, written out from the RFC rather than
// computed here, so the expectation cannot come from the function under test.
// The test's own oracle is held to it as well.
func TestTheAccessTokenHashIsRfc9449sOwnExample(t *testing.T) {
	const tok, ath = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	if got := AccessTokenHash(tok); got != ath {
		t.Fatalf("AccessTokenHash: got %q, want %q", got, ath)
	}
	if got := athOf(tok); got != ath {
		t.Fatalf("the test oracle: got %q, want %q", got, ath)
	}
}

// Hostile input never panics the agent-token verifiers and never verifies.
// The seed and the generator are tokenfuse's, so the two suites throw the same
// shapes.
func TestTwoHundredHostileStringsNeverPanicTheAgentTokenVerifiers(t *testing.T) {
	f := newAgentFixture(t)
	seed := uint64(20261018)
	next := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for i := 0; i < 200; i++ {
		n := 1 + int(next()%512)
		b := make([]byte, n)
		for j := range b {
			b[j] = byte(next() % 256)
		}
		candidate := string(b)
		if i%2 == 1 {
			a, c := n/3, 2*n/3
			candidate = b64url(b[:a]) + "." + b64url(b[a:c]) + "." + b64url(b[c:])
		}
		_ = IsAgentToken(candidate)
		if _, err := f.verify(candidate, f.proof(t, candidate, "ph-1")); err == nil {
			t.Fatalf("case %d verified", i)
		}
		if _, err := VerifyRelayedAccess(candidate, f.opts("")); err == nil {
			t.Fatalf("case %d verified relayed", i)
		}
		if _, err := f.verify(f.token(t, nil), candidate); err == nil {
			t.Fatalf("case %d verified as a proof", i)
		}
	}
}

// Invariant 15, for the agent-token verifier: AccessOptions has nothing that
// reaches out, asserted on the shape, and the list of fields this test scans
// is compared with the struct, so a field added there is an edit required here.
func TestTheAgentTokenVerifierTouchesNothingOutsideTheProcess(t *testing.T) {
	typ := reflect.TypeOf(AccessOptions{})
	var actual []string
	for i := 0; i < typ.NumField(); i++ {
		actual = append(actual, typ.Field(i).Name+" "+typ.Field(i).Type.String())
	}
	listed := []string{
		"Keys delegation.Set", "Issuer string", "Audience string", "Now time.Time",
		"Proof string", "Method string", "URL string",
		"Proofs *delegation.ReplayCache", "Revoked func(string, string, int64) bool",
	}
	if strings.Join(actual, ",") != strings.Join(listed, ",") {
		t.Fatalf("AccessOptions changed shape and the list this test scans has not:\n struct: %v\n   list: %v", actual, listed)
	}
	for _, f := range listed {
		for _, banned := range []string{"Client", "HTTP", "Fetch", "Endpoint", "Timeout", "Context", "context."} {
			if strings.Contains(f, banned) {
				t.Fatalf("AccessOptions grew something that reaches out: %s", f)
			}
		}
	}
}

// The replay cache is shared by every door of a process, so it is used from
// many goroutines at once: one jti presented by fifty at the same moment is
// admitted exactly once.
func TestTheReplayCacheAdmitsAJtiOnceUnderConcurrentUse(t *testing.T) {
	c := NewReplayCache(1024)
	now := time.Unix(atNow, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.CheckAndRecord("same", now) == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("one jti was admitted %d times", admitted)
	}
}

// The Rust verifier deserializes an agent token's claims into typed fields, so
// a claim of the wrong JSON type is a token it cannot read and refuses. Before
// this, the Go side read such a claim as absent and verified the token: an
// iat that is a string, a unit that is a number. Only the issuer can sign
// these, which is why the shared table leaves them out (the two name the
// refusal differently); what must agree is that both refuse.
func TestAClaimTheRustVerifierCannotReadIsRefusedHereToo(t *testing.T) {
	f := newAgentFixture(t)
	for _, over := range []map[string]any{
		{"iat": "soon"},
		{"iat": json.RawMessage("null")},
		{"iat": float64(atNow) + 0.5},
		{"exp": "later"},
		{"exp": json.RawMessage("null")},
		{"exp": float64(atNow+300) + 0.5},
		{"exp": 1e19},
		{"exp": -1e19},
		{"unit": 5},
		{"unit": json.RawMessage("null")},
		{"org": []any{"default"}},
	} {
		tk := f.token(t, over)
		if _, err := f.verify(tk, f.proof(t, tk, "pt-1")); err == nil {
			t.Errorf("%v verified", over)
		}
	}
	// The controls: an absent iat, unit or org is what the Rust verifier
	// defaults, and verifies.
	for _, over := range []map[string]any{{"iat": nil}, {"unit": nil}, {"org": nil}} {
		tk := f.token(t, over)
		if _, err := f.verify(tk, f.proof(t, tk, "pt-2")); err != nil {
			t.Errorf("%v was refused: %v", over, err)
		}
	}
}

// Rust's saturating arithmetic, which the expiry and the replay generation
// both lean on: an absurd clock or date reads as far away, never as its
// opposite.
func TestTheClockArithmeticSaturatesRatherThanWrapping(t *testing.T) {
	for _, c := range []struct {
		got, want int64
		what      string
	}{
		{saturatingAdd(1_800_000_300, 30), 1_800_000_330, "an ordinary add"},
		{saturatingAdd(math.MaxInt64, 30), math.MaxInt64, "add past the top"},
		{saturatingAdd(math.MinInt64, -1), math.MinInt64, "add past the bottom"},
		{saturatingSub(1_000_120, 1_000_000), 120, "an ordinary subtraction"},
		{saturatingSub(math.MaxInt64, -1), math.MaxInt64, "subtract a negative past the top"},
		{saturatingSub(math.MinInt64, 1), math.MinInt64, "subtract past the bottom"},
		{saturatingSub(0, math.MinInt64), math.MaxInt64, "the cache's very first rotation"},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.what, c.got, c.want)
		}
	}
}
