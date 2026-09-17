package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

const (
	method = "POST"
	url    = "https://vouchryx.internal/v1/token"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// proof builds what a correct client sends. Every negative test below is this
// with one thing changed, so each failure names exactly one property.
func proof(t *testing.T, signer *ecdsa.PrivateKey, embed JWK, claims map[string]any, typ string) string {
	t.Helper()
	header := map[string]any{"typ": typ, "alg": "ES256", "jwk": embed}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, signer, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(pad32(r), pad32(s)...)
	return signing + "." + enc(sig)
}

func good(t *testing.T, k *ecdsa.PrivateKey, now time.Time) string {
	return proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Unix(), "jti": "one",
	}, "dpop+jwt")
}

func TestACorrectProofYieldsTheThumbprintOfItsOwnKey(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	got, err := NewVerifier().Check(good(t, k, now), method, url, now)
	if err != nil {
		t.Fatalf("a correct proof was refused: %v", err)
	}
	want, _ := Thumbprint(FromPublic(&k.PublicKey, ""))
	if got != want {
		t.Fatalf("bound to the wrong key: %q, want %q", got, want)
	}
}

// THE ONE THE WHOLE SCHEME RESTS ON. Without it anybody staples a victim's
// public key to a proof they signed themselves, and is issued a token bound to
// a key they do not hold: the binding becomes decorative.
func TestAProofSignedByAKeyOtherThanTheOneItCarriesIsRefused(t *testing.T) {
	victim, attacker := newKey(t), newKey(t)
	now := time.Now()
	stapled := proof(t, attacker, FromPublic(&victim.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Unix(), "jti": "x",
	}, "dpop+jwt")
	if _, err := NewVerifier().Check(stapled, method, url, now); err == nil {
		t.Fatal("a proof signed by a different key verified: the binding is decorative")
	}
}

func TestAProofForAnotherRequestIsRefused(t *testing.T) {
	// A proof is for ONE request. Without this, one captured from a call to a
	// harmless endpoint is replayed against this one.
	k := newKey(t)
	now := time.Now()
	p := good(t, k, now)
	if _, err := NewVerifier().Check(p, "GET", url, now); err == nil {
		t.Fatal("a proof for a POST verified a GET")
	}
	if _, err := NewVerifier().Check(p, method, "https://vouchryx.internal/v1/revoke", now); err == nil {
		t.Fatal("a proof for one path verified another")
	}
}

func TestAQueryStringDoesNotBreakAnHonestClient(t *testing.T) {
	// RFC 9449 section 4.3: `htu` is the request URI without query or fragment.
	// A server that compared them whole would refuse every proof for a URL
	// carrying a cache-buster, which an operator diagnoses as "DPoP is broken".
	k := newKey(t)
	now := time.Now()
	if _, err := NewVerifier().Check(good(t, k, now), method, url+"?trace=1", now); err != nil {
		t.Fatalf("a query string broke an honest client: %v", err)
	}
}

func TestAProofOutsideTheWindowIsRefusedInBothDirections(t *testing.T) {
	// Both directions: a client whose clock is FAST would otherwise be refused
	// every time, which gets diagnosed as a broken feature rather than a wrong
	// clock. And one with no freshness at all is a bearer token in a proof's
	// clothes.
	k := newKey(t)
	now := time.Now()
	for _, skew := range []time.Duration{-2 * Window, 2 * Window} {
		p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
			"htm": method, "htu": url, "iat": now.Add(skew).Unix(), "jti": "s",
		}, "dpop+jwt")
		if _, err := NewVerifier().Check(p, method, url, now); err == nil {
			t.Fatalf("a proof %v out verified", skew)
		}
	}
	noIat := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "jti": "s",
	}, "dpop+jwt")
	if _, err := NewVerifier().Check(noIat, method, url, now); err == nil {
		t.Fatal("a proof with no iat verified")
	}
}

func TestTheSameProofIsAcceptedOnceAndNotTwice(t *testing.T) {
	// The window bounds a replay; this closes it.
	k := newKey(t)
	now := time.Now()
	v := NewVerifier()
	p := good(t, k, now)
	if _, err := v.Check(p, method, url, now); err != nil {
		t.Fatalf("the first presentation was refused: %v", err)
	}
	if _, err := v.Check(p, method, url, now); err == nil {
		t.Fatal("the same proof was accepted twice")
	}
}

func TestAProofWithNoJtiIsRefusedRatherThanRememberedAsEmpty(t *testing.T) {
	// With nothing to remember, a proof replays freely inside its window, and
	// an empty key in the seen-set would make every such proof collide with
	// every other, which reads as replay protection and is not.
	k := newKey(t)
	now := time.Now()
	p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Unix(),
	}, "dpop+jwt")
	if _, err := NewVerifier().Check(p, method, url, now); err == nil {
		t.Fatal("a proof with no jti verified")
	}
}

func TestAnAccessTokenIsNotAProof(t *testing.T) {
	// The `typ` is what stops a token being a proof. Without it an access
	// token this service issued could be presented back to it as a proof of
	// possession of its own key.
	k := newKey(t)
	now := time.Now()
	p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Unix(), "jti": "t",
	}, "JWT")
	if _, err := NewVerifier().Check(p, method, url, now); err == nil {
		t.Fatal("a JWT was accepted as a DPoP proof")
	}
}

func TestAClientLeakingItsPrivateKeyIsRefusedRatherThanHelped(t *testing.T) {
	// RFC 9449 requires the PUBLIC key. A `d` member is a client handing us its
	// signing key, and a service that accepted it becomes a place private keys
	// collect. Checked on the raw JSON, because the struct has no field for `d`
	// and would drop it in silence.
	k := newKey(t)
	now := time.Now()
	pub := FromPublic(&k.PublicKey, "")
	raw, _ := json.Marshal(pub)
	var members map[string]any
	_ = json.Unmarshal(raw, &members)
	priv, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	members["d"] = enc(priv)

	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": members})
	claims, _ := json.Marshal(map[string]any{"htm": method, "htu": url, "iat": now.Unix(), "jti": "d"})
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, _ := ecdsa.Sign(rand.Reader, k, sum[:])
	leaky := signing + "." + enc(append(pad32(r), pad32(s)...))

	if _, err := NewVerifier().Check(leaky, method, url, now); err != ErrPrivate {
		t.Fatalf("a proof carrying a private key was not refused by name: %v", err)
	}
}

func TestAProofCannotDowngradeItselfToNone(t *testing.T) {
	// The alg-confusion family reaches proofs too. `VerifyWith` keeps the
	// algorithm tied to the key type, and this holds that it still does.
	k := newKey(t)
	now := time.Now()
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "none", "jwk": FromPublic(&k.PublicKey, ""),
	})
	claims, _ := json.Marshal(map[string]any{"htm": method, "htu": url, "iat": now.Unix(), "jti": "n"})
	if _, err := NewVerifier().Check(enc(header)+"."+enc(claims)+".", method, url, now); err == nil {
		t.Fatal("an unsigned proof verified")
	}
}

func TestTheSeenSetDoesNotGrowWithoutBound(t *testing.T) {
	// It is in memory and bounded by the window. A set that only ever grew
	// would be a slow leak on the busiest path this service has.
	k := newKey(t)
	v := NewVerifier()
	start := time.Now()
	for i := 0; i < 50; i++ {
		at := start.Add(time.Duration(i) * 10 * time.Second)
		p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
			"htm": method, "htu": url, "iat": at.Unix(), "jti": string(rune('a'+i%26)) + string(rune('0'+i/26)),
		}, "dpop+jwt")
		if _, err := v.Check(p, method, url, at); err != nil {
			t.Fatalf("proof %d refused: %v", i, err)
		}
	}
	v.mu.Lock()
	n := len(v.seen)
	v.mu.Unlock()
	if n > 12 {
		t.Fatalf("the seen-set kept %d entries for a %v window", n, Window)
	}
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// The key in a proof is whatever the presenter put there, and the issuer's
// token door checks the proof BEFORE it authenticates anything else. So the
// cost of verifying the proof is a cost anybody can impose. A 48 KiB modulus
// fits under vouchryx's 64 KiB body cap and, unbounded, costs 1.34 seconds of
// one core per request (measured 2026-09-16); this proof must be refused in
// the time it takes to read its header, not in the time it takes to
// exponentiate.
func TestAProofCarryingAnOversizedRsaKeyIsRefusedBeforeAnyArithmetic(t *testing.T) {
	n := make([]byte, 48<<10)
	for i := range n {
		n[i] = 0xff
	}
	embed := JWK{Kty: "RSA", N: enc(n), E: enc([]byte{1, 0, 1})}
	header := map[string]any{"typ": "dpop+jwt", "alg": "RS256", "jwk": embed}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(map[string]any{
		"htm": method, "htu": url, "iat": time.Now().Unix(), "jti": "oversized",
	})
	sig := make([]byte, len(n))
	for i := range sig {
		sig[i] = 0x7f
	}
	proof := enc(h) + "." + enc(p) + "." + enc(sig)

	started := time.Now()
	_, err := NewVerifier().Check(proof, method, url, time.Now())
	took := time.Since(started)

	if err == nil {
		t.Fatal("a proof carrying a 48 KiB RSA key verified")
	}
	// The bound is generous on purpose: the fixed path does no big-number
	// arithmetic at all and finishes in microseconds, the unfixed one took
	// 1.34 s here and longer under the race detector. Anything near the bound
	// means the modulus reached the exponentiation.
	if took > 100*time.Millisecond {
		t.Fatalf("refusing the proof took %v, which means the oversized modulus was exponentiated "+
			"rather than refused at the door", took)
	}
}

// F3 (2026-09-17 delegation review): remember pruned an entry Window after
// the moment it was first seen rather than Window after the iat it was seen
// with, so a proof presented up to Window ahead of now was forgotten before
// its own freshness ran out and could then be replayed for as long as that
// freshness had left. Swept over every integer skew because the bug was in
// the boundary itself, not in one instance of it.
func TestAFutureDatedProofIsRememberedUntilItsOwnFreshnessEnds(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1800000000, 0)
	for skew := 1; skew <= 60; skew++ {
		v := NewVerifier()
		p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
			"htm": method, "htu": url, "iat": now.Unix() + int64(skew), "jti": "same-proof",
		}, "dpop+jwt")
		if _, err := v.Check(p, method, url, now); err != nil {
			t.Fatalf("skew=%d: the first presentation was refused: %v", skew, err)
		}
		if _, err := v.Check(p, method, url, now.Add(61*time.Second)); !errors.Is(err, ErrReplay) {
			t.Fatalf("skew=%d: replayed at +61s instead of being remembered: %v", skew, err)
		}
		lastFresh := now.Add(Window + time.Duration(skew)*time.Second)
		if _, err := v.Check(p, method, url, lastFresh); !errors.Is(err, ErrReplay) {
			t.Fatalf("skew=%d: not remembered at its own last fresh instant %v: %v", skew, lastFresh, err)
		}
		pastFresh := lastFresh.Add(time.Second)
		if _, err := v.Check(p, method, url, pastFresh); !errors.Is(err, ErrStale) {
			t.Fatalf("skew=%d: accepted or misclassified one second past its last fresh instant: %v", skew, err)
		}
	}
}

// The other direction: an entry must not outlive its own freshness either.
// Read under v.mu the way TestTheSeenSetDoesNotGrowWithoutBound does, since
// the seen-set has no other way to be inspected from outside the package.
func TestABackwardDatedProofIsForgottenNoLaterThanItsOwnFreshnessEnds(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1800000000, 0)
	v := NewVerifier()
	backJti := "back-dated"
	p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Add(-30 * time.Second).Unix(), "jti": backJti,
	}, "dpop+jwt")
	if _, err := v.Check(p, method, url, now); err != nil {
		t.Fatalf("the backward-dated proof was refused at its first presentation: %v", err)
	}

	later := now.Add(31 * time.Second)
	// Any presentation at `later` sweeps the seen-set with `later` as the
	// clock, which is what actually prunes it; nothing prunes on a timer.
	other := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": later.Unix(), "jti": "other",
	}, "dpop+jwt")
	if _, err := v.Check(other, method, url, later); err != nil {
		t.Fatalf("an unrelated proof at %v was refused: %v", later, err)
	}

	v.mu.Lock()
	_, stillHeld := v.seen[backJti]
	v.mu.Unlock()
	if stillHeld {
		t.Fatalf("the backward-dated proof was still in the seen-set at %v, past its own freshness", later)
	}

	if _, err := v.Check(p, method, url, later); !errors.Is(err, ErrStale) {
		t.Fatalf("the backward-dated proof was not refused as stale at %v: %v", later, err)
	}
}

// F6 (2026-09-17 delegation review): EqualFold ran over the whole method and
// the whole URL. RFC 9110 methods are case sensitive, so a proof bound to
// POST must not also verify a request logged as post or Post.
func TestTheMethodBindingIsCaseSensitive(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	for _, got := range []string{"post", "Post", "POst"} {
		if _, err := NewVerifier().Check(good(t, k, now), got, url, now); !errors.Is(err, ErrBinding) {
			t.Errorf("method %q verified a proof bound to %s: %v", got, method, err)
		}
	}
}

// RFC 9449 section 4.3 read with RFC 3986 section 6.2.2.1: only the scheme
// and the host fold case. The path does not, so a proof for /v1/token must
// not verify /v1/TOKEN.
func TestThePathBindingIsCaseSensitive(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	for _, got := range []string{"https://vouchryx.internal/v1/TOKEN", "/V1/token"} {
		if _, err := NewVerifier().Check(good(t, k, now), method, got, now); !errors.Is(err, ErrBinding) {
			t.Errorf("url %q verified a proof bound to %s: %v", got, url, err)
		}
	}
}

// The control: scheme and host still fold, or the fix over-refuses an
// honest client sitting behind a load balancer that upcases its own host.
func TestTheSchemeAndHostStillFoldCase(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	if _, err := NewVerifier().Check(good(t, k, now), method, "HTTPS://VOUCHRYX.INTERNAL/v1/token", now); err != nil {
		t.Fatalf("folding the scheme and host broke an honest client: %v", err)
	}
}

// A claimed htu that is relative, or that net/url cannot parse at all, binds
// to nothing rather than to everything: sameURL must refuse it rather than
// let an empty comparison pass by accident.
func TestARelativeOrUnparseableHtuIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	for _, claimed := range []string{"/v1/token", "https://[::1/v1/token"} {
		p := proof(t, k, FromPublic(&k.PublicKey, ""), map[string]any{
			"htm": method, "htu": claimed, "iat": now.Unix(), "jti": "bad-htu",
		}, "dpop+jwt")
		if _, err := NewVerifier().Check(p, method, url, now); !errors.Is(err, ErrBinding) {
			t.Errorf("claimed htu %q was not refused as a binding mismatch: %v", claimed, err)
		}
	}
}

// F7 confirmed from the DPoP side: a P-384 key claiming ES256 must be
// refused here too, not only by VerifyToken. Check does not surface which
// check inside VerifyWith failed (every such failure comes back as
// ErrSignature, on purpose: see the package doc), so this asserts only that
// it is refused, the same way the other proof-forgery tests in this file do.
func TestADPoPProofCarryingAP384KeyIsRefusedUnderTheNameES256(t *testing.T) {
	k384 := ecKeyOnCurve(t, elliptic.P384())
	now := time.Now()
	p := proof(t, k384, FromPublic(&k384.PublicKey, ""), map[string]any{
		"htm": method, "htu": url, "iat": now.Unix(), "jti": "p384",
	}, "dpop+jwt")
	if _, err := NewVerifier().Check(p, method, url, now); err == nil {
		t.Fatal("a P-384 key verified a DPoP proof under the name ES256")
	}
	// Pinned at the layer that can name it: VerifyWith is what Check calls
	// internally, and unlike Check it does not collapse the reason to
	// ErrSignature, so the same proof asked here must say ErrAlgNotAllowed.
	if _, err := VerifyWith(p, FromPublic(&k384.PublicKey, "")); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("VerifyWith did not refuse the same proof as ErrAlgNotAllowed: %v", err)
	}
}

// Second-model review, 2026-09-17: nothing asserted the host or the scheme
// on their own. Folding strings.EqualFold(pa.Host, pb.Host) to a bare true,
// or the scheme fold to a bare true, passes the whole suite without this: a
// proof captured for one host or scheme must not verify a request to
// another.
func TestAProofForAnotherHostOrSchemeIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	for _, got := range []string{"https://evil.internal/v1/token", "http://vouchryx.internal/v1/token"} {
		if _, err := NewVerifier().Check(good(t, k, now), method, got, now); !errors.Is(err, ErrBinding) {
			t.Errorf("url %q verified a proof bound to %s: %v", got, url, err)
		}
	}
}

// Second-model review, 2026-09-17: EscapedPath, not the decoded Path.
// /v1%2Ftoken and /v1/token decode to the identical Path but are different
// requests on the wire; comparing the decoded form would treat an escaped
// path separator as though it were a literal one.
func TestAnEscapedPathSeparatorDoesNotMatchADecodedOne(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	if _, err := NewVerifier().Check(good(t, k, now), method, "https://vouchryx.internal/v1%2Ftoken", now); !errors.Is(err, ErrBinding) {
		t.Fatalf("an escaped path separator verified a proof bound to a literal one: %v", err)
	}
}
