package delegation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return k
}

func TestASignedTokenVerifiesAgainstItsOwnKey(t *testing.T) {
	k := key(t)
	tok, err := SignES256(k, "kid-1", map[string]any{"sub": "agent://a/b", "exp": 4102444800})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("a JWS has three parts: %q", tok)
	}
	set := Set{Keys: []JWK{FromPublic(&k.PublicKey, "kid-1")}}
	claims, err := VerifyToken(tok, set)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if claims["sub"] != "agent://a/b" {
		t.Fatalf("claims did not survive: %v", claims)
	}
}

// The defence tokenfuse's oidc.rs already carries, restated here because this
// service is the one issuing. The allowed algorithms come from the KEY TYPE and
// never from the token header, which is attacker-controlled. Without it, an
// attacker takes the public EC key everybody can fetch from our own JWKS,
// signs an HMAC with it as the secret, sets alg to HS256, and the token
// verifies.
func TestTheAlgorithmComesFromTheKeyAndNeverFromTheHeader(t *testing.T) {
	k := key(t)
	set := Set{Keys: []JWK{FromPublic(&k.PublicKey, "kid-1")}}

	// A token whose header claims a symmetric algorithm, signed with the
	// public key bytes as the HMAC secret: the classic downgrade.
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	forged := hs256(t, "kid-1", map[string]any{"sub": "attacker"}, pub)
	if _, err := VerifyToken(forged, set); err == nil {
		t.Fatal("an HS256 token verified against an EC key: alg confusion is open")
	}

	// And "none", which is the other half of the same family.
	none := unsigned(t, "kid-1", map[string]any{"sub": "attacker"})
	if _, err := VerifyToken(none, set); err == nil {
		t.Fatal("an unsigned token verified")
	}
}

func TestAnUnknownKidIsRefusedRatherThanTriedAgainstEveryKey(t *testing.T) {
	// Trying every key would turn one compromised key into a skeleton key for
	// every issuer this service trusts.
	k := key(t)
	tok, err := SignES256(k, "kid-1", map[string]any{"sub": "a"})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	other := key(t)
	set := Set{Keys: []JWK{FromPublic(&other.PublicKey, "kid-2")}}
	if _, err := VerifyToken(tok, set); err == nil {
		t.Fatal("a token signed by an unknown key verified")
	}
}

func TestATokenWithNoKidIsRefused(t *testing.T) {
	// A JWS with no `kid` cannot be matched to a key, and picking one for it
	// is the same skeleton-key mistake by another route.
	k := key(t)
	tok, err := SignES256(k, "", map[string]any{"sub": "a"})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	set := Set{Keys: []JWK{FromPublic(&k.PublicKey, "kid-1")}}
	if _, err := VerifyToken(tok, set); err == nil {
		t.Fatal("a token with no kid verified")
	}
}

func TestATamperedPayloadDoesNotVerify(t *testing.T) {
	k := key(t)
	tok, _ := SignES256(k, "kid-1", map[string]any{"sub": "agent://a/b"})
	parts := strings.Split(tok, ".")
	parts[1] = jb64(t, map[string]any{"sub": "agent://a/root"})
	set := Set{Keys: []JWK{FromPublic(&k.PublicKey, "kid-1")}}
	if _, err := VerifyToken(strings.Join(parts, "."), set); err == nil {
		t.Fatal("a rewritten payload verified")
	}
}

// RFC 7638. The thumbprint is what binds an issued token to a holder's key, so
// two different keys producing one thumbprint would let a stolen token be
// replayed by a different holder.
func TestTheThumbprintIsTheRfc7638Value(t *testing.T) {
	// The example key from RFC 7638 section 3.1 and its stated thumbprint.
	var j JWK
	if err := json.Unmarshal([]byte(`{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`), &j); err != nil {
		t.Fatalf("parsing the RFC's own key: %v", err)
	}
	got, err := Thumbprint(j)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("RFC 7638 section 3.1 says %q, got %q", want, got)
	}
}

func TestTwoKeysNeverShareAThumbprint(t *testing.T) {
	a, b := key(t), key(t)
	ta, err := Thumbprint(FromPublic(&a.PublicKey, "x"))
	if err != nil {
		t.Fatal(err)
	}
	tb, err := Thumbprint(FromPublic(&b.PublicKey, "y"))
	if err != nil {
		t.Fatal(err)
	}
	if ta == tb {
		t.Fatal("two keys shared a thumbprint: a stolen token becomes replayable")
	}
	// And the `kid` is not part of it: RFC 7638 hashes the required members
	// only, so renaming a key must not change what a token is bound to.
	tsame, _ := Thumbprint(FromPublic(&a.PublicKey, "renamed"))
	if ta != tsame {
		t.Fatal("the thumbprint moved when the kid did")
	}
}

func TestAPrivateKeyNeverReachesTheJwkSet(t *testing.T) {
	// The set is published at /.well-known/jwks.json. A `d` member there is
	// the signing key, in public, forever.
	k := key(t)
	set := Set{Keys: []JWK{FromPublic(&k.PublicKey, "kid-1")}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`} {
		if strings.Contains(string(raw), member) {
			t.Fatalf("a private member reached the published set: %s", raw)
		}
	}
}

// helpers that build the tokens a real attacker would.

func jb64(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func hs256(t *testing.T, kid string, claims map[string]any, secret []byte) string {
	t.Helper()
	h := jb64(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid})
	p := jb64(t, claims)
	mac := hmacSHA256(secret, h+"."+p)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func unsigned(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	return jb64(t, map[string]any{"alg": "none", "typ": "JWT", "kid": kid}) + "." + jb64(t, claims) + "."
}

// The RSA path, which was untested until 2026-08-26 and is the one a customer's
// IdP most likely uses. Every defence has to hold on both key types or the
// weaker one becomes the way in.

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaJWK(pub *rsa.PublicKey, kid string) JWK {
	e := big.NewInt(int64(pub.E)).Bytes()
	return JWK{Kty: "RSA", N: b64(pub.N.Bytes()), E: b64(e), Kid: kid, Use: "sig"}
}

func signRS256(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h := jb64(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	p := jb64(t, claims)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAnRsaTokenVerifies(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, "idp-1", map[string]any{"sub": "user://a/b"})
	claims, err := VerifyToken(tok, Set{Keys: []JWK{rsaJWK(&k.PublicKey, "idp-1")}})
	if err != nil {
		t.Fatalf("an RS256 token from a configured IdP was refused: %v", err)
	}
	if claims["sub"] != "user://a/b" {
		t.Fatalf("%v", claims)
	}
}

func TestAnRsaKeyCannotBeDowngradedEither(t *testing.T) {
	// The alg-confusion attack was FIRST described against RSA: take the public
	// modulus everybody can fetch, use it as an HMAC secret, set alg to HS256.
	// A service that closed it for EC and left it open for RSA would have
	// closed the less likely half.
	k := rsaKey(t)
	set := Set{Keys: []JWK{rsaJWK(&k.PublicKey, "idp-1")}}
	forged := hs256(t, "idp-1", map[string]any{"sub": "attacker"}, k.PublicKey.N.Bytes())
	if _, err := VerifyToken(forged, set); err == nil {
		t.Fatal("an HS256 token verified against an RSA key: the original alg confusion is open")
	}
	if _, err := VerifyToken(unsigned(t, "idp-1", map[string]any{"sub": "x"}), set); err == nil {
		t.Fatal("an unsigned token verified against an RSA key")
	}
}

func TestAnRsaSignatureOverOtherBytesDoesNotVerify(t *testing.T) {
	k := rsaKey(t)
	tok := signRS256(t, k, "idp-1", map[string]any{"sub": "user://a/b"})
	parts := strings.Split(tok, ".")
	parts[1] = jb64(t, map[string]any{"sub": "user://a/root"})
	if _, err := VerifyToken(strings.Join(parts, "."), Set{Keys: []JWK{rsaJWK(&k.PublicKey, "idp-1")}}); err == nil {
		t.Fatal("a rewritten RSA payload verified")
	}
}

func TestAnAbsurdRsaExponentIsRefusedRatherThanComputed(t *testing.T) {
	// `e` comes off a JWKS an operator configured, but a compromised or
	// mistyped one should not put this process into a modular exponentiation
	// with a 64-bit exponent on every verification.
	j := JWK{Kty: "RSA", N: b64([]byte{1, 2, 3}), E: b64([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255}), Kid: "k"}
	tok := "e30.e30.e30"
	if _, err := VerifyToken(tok, Set{Keys: []JWK{j}}); err == nil {
		t.Fatal("an oversized exponent was accepted")
	}
}

func TestAnOffCurvePointIsRefused(t *testing.T) {
	// Not a typo: an invalid-curve attack. A point off the curve turns ECDSA
	// verification into arithmetic in a group the attacker chose.
	k := key(t)
	j := FromPublic(&k.PublicKey, "kid-1")
	j.Y = b64([]byte{1, 2, 3, 4})
	tok, _ := SignES256(k, "kid-1", map[string]any{"sub": "a"})
	if _, err := VerifyToken(tok, Set{Keys: []JWK{j}}); err == nil {
		t.Fatal("an off-curve public key was used to verify")
	}
}

func TestASymmetricKeyInASetIsRefusedOutright(t *testing.T) {
	// An `oct` entry in a JWKS is a shared secret this service never agreed to
	// share. Refused by key type, before any algorithm is considered.
	j := JWK{Kty: "oct", Kid: "k"}
	if allowed(j.Kty, "HS256") {
		t.Fatal("a symmetric key type is permitted an algorithm")
	}
	if _, err := VerifyToken(hs256(t, "k", map[string]any{"sub": "x"}, []byte("secret")), Set{Keys: []JWK{j}}); err == nil {
		t.Fatal("an oct key verified a token")
	}
}

// Found by a planted mutant, not by review. Making `Set.Find` return the first
// key whatever the `kid` survived the whole suite, because every set here had
// ONE key in it and the signature check then failed for a different reason:
// the test passed, and passed for the wrong reason.
//
// The property is not "an unknown kid is refused". It is that a token naming
// key A must be verified with key A ONLY, even when the key that actually
// signed it is also in the set. Without it, an issuer whose oldest key leaked
// can mint tokens that verify under the `kid` of its newest, and one
// compromised key becomes a skeleton key for every issuer this service trusts.
func TestATokenIsVerifiedWithTheKeyItNamesAndNoOther(t *testing.T) {
	a, b := key(t), key(t)
	set := Set{Keys: []JWK{
		FromPublic(&a.PublicKey, "key-a"),
		FromPublic(&b.PublicKey, "key-b"),
	}}

	// Signed by B, claiming to be A's. Both are in the set, so a verifier that
	// tried them in turn would accept it.
	forged, err := SignES256(b, "key-a", map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(forged, set); err == nil {
		t.Fatal("a token naming key A verified with key B: one leaked key opens every issuer")
	}

	// And the honest cases still work, or the property above is just a refusal.
	for kid, signer := range map[string]*ecdsa.PrivateKey{"key-a": a, "key-b": b} {
		tok, err := SignES256(signer, kid, map[string]any{"sub": "ok"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyToken(tok, set); err != nil {
			t.Fatalf("an honest token under %s was refused: %v", kid, err)
		}
	}
}
