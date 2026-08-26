package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	members["d"] = enc(k.D.Bytes())

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
