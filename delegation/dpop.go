// Package dpop verifies the sender-constraint proof of RFC 9449.
//
// # What the proof is for
//
// A bearer token is a bearer token: anybody holding the bytes may use them. A
// delegation token that says "this agent may act for that person" is exactly the
// kind of bytes worth stealing, and every enforcement point in this estate would
// honour a stolen one. DPoP binds an issued token to a key the holder proves
// possession of, so the bytes alone are not enough.
//
// The proof is a small JWS the client signs per request, carrying its public key
// in the header. This package verifies that proof and returns the RFC 7638
// thumbprint of the key, which the issuer then puts in `cnf.jkt` on the token it
// issues. An enforcement point later compares the thumbprint on the token with
// the thumbprint of the key that signed the proof in front of it.
//
// # What it refuses, and why each one is not paranoia
//
//   - **A proof whose header carries no `jwk`.** There is nothing to bind to.
//   - **A proof signed by a key other than the one in its header.** Otherwise
//     anybody can staple somebody else's public key to their own proof and be
//     issued a token bound to a key they do not hold.
//   - **A private member in the embedded `jwk`.** RFC 9449 requires the public
//     key. A `d` there is a client leaking its own signing key to us, and
//     accepting it makes this service a place private keys collect.
//   - **`htm` or `htu` that do not match the request in front of us.** A proof
//     is for ONE request. Without this, a proof captured from a call to a
//     harmless endpoint is replayed against this one.
//   - **An `iat` outside the window.** A proof with no freshness is a bearer
//     token wearing a proof's clothes.
//   - **A `jti` already seen inside that window.** The window bounds a replay;
//     this closes it.
package delegation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Window is how far an `iat` may be from now, either way.
//
// Either way, and not only into the past: a client whose clock is fast would
// otherwise be refused every time, which an operator diagnoses as "DPoP is
// broken" rather than "our clock is wrong". RFC 9449 leaves the value to the
// server; 60 seconds is short enough that the replay cache stays small and long
// enough to survive ordinary clock drift.
const Window = 60 * time.Second

var (
	ErrNoKey     = errors.New("delegation: the proof carries no jwk to bind to")
	ErrPrivate   = errors.New("delegation: the proof's jwk carries a private member")
	ErrSignature = errors.New("delegation: the proof is not signed by the key it carries")
	ErrBinding   = errors.New("delegation: the proof is not for this request")
	ErrStale     = errors.New("delegation: the proof is outside the freshness window")
	ErrReplay    = errors.New("delegation: this proof has been presented before")
)

// Verifier checks proofs and remembers the ones it has seen.
//
// The seen-set is in memory and bounded by [Window], which is a deliberate
// limit rather than an oversight: a restart forgets, and for the length of one
// window after a restart a captured proof could be replayed once. Making that
// durable means a store on the request path of every token issue, and the
// window is sixty seconds. It is written down in the README rather than left
// for somebody to discover.
type Verifier struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewVerifier() *Verifier {
	return &Verifier{seen: make(map[string]time.Time)}
}

// Check verifies a proof for one request and returns the thumbprint of the key
// that signed it.
//
// `method` and `url` are what THIS server received, never what the proof says:
// comparing the proof against itself would be no check at all.
func (v *Verifier) Check(proof, method, url string, now time.Time) (string, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", ErrSignature
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrSignature
	}
	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return "", ErrSignature
	}
	if header.Typ != "dpop+jwt" {
		// The typ is what stops a proof being a token and a token being a
		// proof. Without it, an access token this service issued could be
		// presented back to it as a proof of possession of its own key.
		return "", ErrSignature
	}
	if len(header.JWK) == 0 {
		return "", ErrNoKey
	}
	if hasPrivateMember(header.JWK) {
		return "", ErrPrivate
	}
	var key JWK
	if err := json.Unmarshal(header.JWK, &key); err != nil {
		return "", ErrSignature
	}

	// Verified against the key the proof itself carries, and this is the step
	// the whole scheme rests on: without it, anybody staples somebody else's
	// public key to their own proof and is issued a token bound to a key they
	// do not hold.
	//
	// `VerifyWith` and not `Verify`, because a proof names no `kid`
	// and there is no set to match against. Every other defence is the same
	// one: the algorithm still comes from the key type, so a proof cannot
	// downgrade itself to `none` any more than a token can.
	thumb, err := Thumbprint(key)
	if err != nil {
		return "", ErrSignature
	}
	claims, err := VerifyWith(proof, key)
	if err != nil {
		return "", ErrSignature
	}

	if s, _ := claims["htm"].(string); !strings.EqualFold(s, method) {
		return "", ErrBinding
	}
	if s, _ := claims["htu"].(string); !sameURL(s, url) {
		return "", ErrBinding
	}
	iat, ok := numeric(claims["iat"])
	if !ok {
		return "", ErrStale
	}
	drift := now.Sub(time.Unix(iat, 0))
	if drift < -Window || drift > Window {
		return "", ErrStale
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		// Without a `jti` there is nothing to remember, so a proof could be
		// replayed freely inside its window.
		return "", ErrReplay
	}
	if err := v.remember(jti, now); err != nil {
		return "", err
	}
	return thumb, nil
}

func (v *Verifier) remember(jti string, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, at := range v.seen {
		if now.Sub(at) > Window {
			delete(v.seen, id)
		}
	}
	if _, ok := v.seen[jti]; ok {
		return ErrReplay
	}
	v.seen[jti] = now
	return nil
}

// hasPrivateMember reports whether a JWK carries anything only its holder
// should have. Checked on the RAW JSON rather than on the parsed struct,
// because the struct has no field for `d` and would drop it silently: a client
// leaking its private key would then be accepted, and this service would become
// a place private keys collect.
func hasPrivateMember(raw json.RawMessage) bool {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return true
	}
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := members[m]; ok {
			return true
		}
	}
	return false
}

func sameURL(a, b string) bool {
	// Compared without the query and fragment, per RFC 9449 section 4.3: `htu`
	// is the request URI with those removed, and a server that compared them
	// would refuse every proof for a URL carrying a cache-buster.
	return strings.EqualFold(trim(a), trim(b))
}

func trim(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

func numeric(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}
