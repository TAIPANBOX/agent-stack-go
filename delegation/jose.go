// Package delegation is the estate's one implementation of the delegation
// token: how it is signed, how it is verified, and what a verified one means.
//
// # Why it lives here and not in the issuer
//
// `vouchryx` mints these tokens; `wardryx`, `idryx`, `scopyx`, `heraldyx` and
// `mockryx` have to check them. A JOSE implementation in the issuer plus a copy
// in every verifier is exactly the drift this module exists to prevent
// (CLAUDE.md invariant 3), and it is the worst place for drift there is: two
// implementations of "is this signature valid" that disagree is a hole nobody
// sees until somebody walks through it.
//
// # Why a library and not a network call
//
// wardryx decides at a 3.2 ms p50 and audits every decision. Putting signature
// verification behind an HTTP round trip taxes every decision in the estate and
// makes the token service a hard dependency of every enforcement point at once,
// which is the shape `dependency_failed` was cut to record. Enforcement points
// verify locally, from a key set they already hold, and hand the PDP facts that
// are already true.
//
// # Written on the standard library, and here it is not a preference
//
// CLAUDE.md invariant 1: a dependency added to a library package lands in seven
// consumers at once. Beyond that, the security-critical part of this is not the
// signing but the REFUSING -- which algorithms a key may be used with, which key
// a token is matched to, what a token is bound to -- and each of those is a
// decision this module would otherwise be trusting rather than making.
//
// # The one defence that matters most
//
// [Verify] derives the permitted algorithms from the KEY TYPE and never from
// the token header. The header is written by whoever presents the token. Without
// this, an attacker fetches the public EC key from our own
// `/.well-known/jwks.json`, signs an HMAC using those public bytes as the
// secret, sets `alg` to `HS256`, and the token verifies: the classic alg
// confusion downgrade. tokenfuse's `crates/cloud/src/oidc.rs` already carries
// this defence for the Rust side and the two must not diverge.
//
// It signs ES256 only. It VERIFIES ES256/ES384 and RS256/384/512,
// because the tokens it accepts as input come from a customer's own IdP and
// that is what those issue.
package delegation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Errors a caller may want to tell apart. Everything else is a bad token and
// says so without saying which part was bad, because a verifier that narrates
// its reasoning to whoever presented the token is an oracle.
var (
	ErrNoKid         = errors.New("delegation: the token carries no kid, so no key can be matched to it")
	ErrUnknownKid    = errors.New("delegation: no key in the set has that kid")
	ErrBadSignature  = errors.New("delegation: the signature did not verify")
	ErrAlgNotAllowed = errors.New("delegation: that algorithm is not permitted for this key type")
)

// JWK is one key in a set. Only the members this service reads are here: an
// unknown member is carried through JSON and ignored, which is what RFC 7517
// requires and what keeps a stricter issuer from being unusable.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// Set is a JWK Set (RFC 7517).
type Set struct {
	Keys []JWK `json:"keys"`
}

// Find returns the key with this `kid`, or false.
//
// By `kid` and never by trying every key in turn: a verifier that tried them
// all would turn one compromised key into a skeleton key for every issuer this
// service trusts.
func (s Set) Find(kid string) (JWK, bool) {
	for _, k := range s.Keys {
		if k.Kid != "" && k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

// FromPublic renders an EC public key as a JWK.
//
// Public members only. There is no overload of this that takes a private key,
// on purpose: the result of this function is published at
// `/.well-known/jwks.json`, and a `d` member there is the signing key, in
// public, forever.
func FromPublic(pub *ecdsa.PublicKey, kid string) JWK {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return JWK{
		Kty: "EC",
		Crv: curveName(pub.Curve),
		X:   b64(pad(pub.X.Bytes(), size)),
		Y:   b64(pad(pub.Y.Bytes(), size)),
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
	}
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url without padding.
//
// This is what an issued token is BOUND to (`cnf.jkt`, RFC 9449), so what it
// hashes decides whether a stolen token can be replayed by a different holder.
// RFC 7638 hashes the required members only, in lexicographic order, with no
// whitespace: `crv, kty, x, y` for EC and `e, kty, n` for RSA. `kid`, `use` and
// `alg` are excluded, which is why renaming a key does not change what a live
// token is bound to.
func Thumbprint(j JWK) (string, error) {
	var canonical string
	switch j.Kty {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	default:
		return "", fmt.Errorf("delegation: no thumbprint defined for kty %q", j.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:]), nil
}

// SignES256 produces a compact JWS over `claims`.
func SignES256(key *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	// The JWS form is the fixed-width concatenation R‖S, not an ASN.1
	// sequence: a DER signature here verifies nowhere.
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := append(pad(r.Bytes(), size), pad(s.Bytes(), size)...)
	return signing + "." + b64(sig), nil
}

// VerifyToken checks a compact JWS against `set` and returns its claims.
//
// Named apart from [Verify], which is the whole delegation check: this one
// answers "were these bytes signed by a key in this set", and a caller that
// stopped there would have a valid signature over claims it never looked at.
//
// It does NOT check `exp`, `iss` or `aud`: those are the caller's policy and
// live where the policy is. What this promises is that the bytes were signed by
// a key in the set, with an algorithm that key is allowed to be used with.
func VerifyToken(token string, set Set) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrBadSignature
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrBadSignature
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, ErrBadSignature
	}
	if header.Kid == "" {
		return nil, ErrNoKid
	}
	jwk, ok := set.Find(header.Kid)
	if !ok {
		return nil, ErrUnknownKid
	}

	// THE DEFENCE. The permitted algorithms come from the key's own type, not
	// from `header.Alg`, which whoever presented this token wrote. `none` and
	// every symmetric algorithm fall out of the bottom of this switch and are
	// refused, because no asymmetric key type permits them.
	if !allowed(jwk.Kty, header.Alg) {
		return nil, ErrAlgNotAllowed
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrBadSignature
	}
	signing := []byte(parts[0] + "." + parts[1])
	if err := check(jwk, header.Alg, signing, sig); err != nil {
		return nil, err
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadSignature
	}
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, ErrBadSignature
	}
	return claims, nil
}

// VerifyWith checks a compact JWS against ONE key that the caller already has,
// skipping the `kid` lookup.
//
// It exists for RFC 9449 proofs, which carry their key in the header rather
// than naming one in a set, and it keeps every other defence [Verify] has: the
// permitted algorithms still come from the key type, so a proof cannot downgrade
// itself to `none` or to an HMAC any more than a token can.
//
// The `kid` requirement is the ONLY thing relaxed, and only because there is no
// set to match against: the caller has decided which key this is, and for a DPoP
// proof that decision is "the one the proof carries", which is exactly the
// binding the scheme is about.
func VerifyWith(token string, key JWK) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrBadSignature
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrBadSignature
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, ErrBadSignature
	}
	if !allowed(key.Kty, header.Alg) {
		return nil, ErrAlgNotAllowed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrBadSignature
	}
	if err := check(key, header.Alg, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadSignature
	}
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, ErrBadSignature
	}
	return claims, nil
}

// allowed reports whether a key of this type may be used with this algorithm.
//
// The whole allowlist is here, in one place, keyed on the KEY and not on the
// token. Adding a case is a decision about what this service accepts; there is
// no path that reaches a verifier without passing through it.
func allowed(kty, alg string) bool {
	switch kty {
	case "EC":
		return alg == "ES256" || alg == "ES384"
	case "RSA":
		return alg == "RS256" || alg == "RS384" || alg == "RS512"
	default:
		// Symmetric keys and OKP are refused outright rather than handled: a
		// service that accepted an `oct` key from a JWKS would be accepting a
		// shared secret it never agreed to share.
		return false
	}
}

func check(j JWK, alg string, signing, sig []byte) error {
	switch j.Kty {
	case "EC":
		pub, err := ecPublic(j)
		if err != nil {
			return ErrBadSignature
		}
		digest, size := digestFor(alg, signing), len(sig)/2
		if len(sig)%2 != 0 || size == 0 {
			return ErrBadSignature
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return ErrBadSignature
		}
		return nil
	case "RSA":
		pub, err := rsaPublic(j)
		if err != nil {
			return ErrBadSignature
		}
		hash := hashFor(alg)
		if err := rsa.VerifyPKCS1v15(pub, hash, digestFor(alg, signing), sig); err != nil {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrAlgNotAllowed
	}
}

func digestFor(alg string, b []byte) []byte {
	switch alg {
	case "ES384", "RS384":
		sum := sha512.Sum384(b)
		return sum[:]
	case "RS512":
		sum := sha512.Sum512(b)
		return sum[:]
	default:
		sum := sha256.Sum256(b)
		return sum[:]
	}
}

func hashFor(alg string) crypto.Hash {
	switch alg {
	case "RS384":
		return crypto.SHA384
	case "RS512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func ecPublic(j JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("delegation: unsupported curve %q", j.Crv)
	}
	x, err := unb64(j.X)
	if err != nil {
		return nil, err
	}
	y, err := unb64(j.Y)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		// An off-curve point is not a typo, it is an invalid-curve attack.
		return nil, errors.New("delegation: the point is not on the curve")
	}
	return pub, nil
}

func rsaPublic(j JWK) (*rsa.PublicKey, error) {
	n, err := unb64(j.N)
	if err != nil {
		return nil, err
	}
	e, err := unb64(j.E)
	if err != nil {
		return nil, err
	}
	if len(e) > 8 {
		return nil, errors.New("delegation: exponent too large")
	}
	var padded [8]byte
	copy(padded[8-len(e):], e)
	exp := binary.BigEndian.Uint64(padded[:])
	if exp > 1<<31 {
		return nil, errors.New("delegation: exponent too large")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp)}, nil
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P384():
		return "P-384"
	default:
		return "P-256"
	}
}

func pad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// hmacSHA256 exists for the tests, which have to be able to build the forged
// token a real attacker would send. Nothing in this package's own paths calls
// it, and that is the point: there is no symmetric verification here to reach.
func hmacSHA256(secret []byte, signing string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signing))
	return m.Sum(nil)
}
