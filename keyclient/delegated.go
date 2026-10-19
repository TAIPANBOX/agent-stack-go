package keyclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

const (
	// minLifetime is custody's floor for a statement's life (internal/policy
	// MinLifetime). Custody refuses a shorter one; this client refuses it first,
	// so a misconfigured consumer makes no request at all.
	minLifetime = 10 * time.Minute
	// maxLifetime is the longest life custody's policy can grant a name
	// (internal/policy MaxLifetime). A name's own maximum is custody's to enforce.
	maxLifetime = 7 * 24 * time.Hour
	// defaultRetry is the wait after a failed renewal before the next attempt.
	defaultRetry = 5 * time.Minute
)

// Delegated is one delegated key name: the keys this process has had certified
// for it, and the one it signs with at the clock's time. A process holds the
// private keys in memory only; a restart makes new ones, and custody certifies
// them again.
type Delegated struct {
	c        *Client
	name     string
	alg      string
	lifetime time.Duration
	retry    time.Duration

	renewMu sync.Mutex // one renewal at a time; signing never waits on it
	mu      sync.Mutex
	keys    []*certified
	nextTry time.Time
}

// Key is the delegated key valid now, with the statement that certifies it.
// Verifiers take the statement as the evidence.
type Key struct {
	Kid       string
	JWK       delegation.JWK
	Statement json.RawMessage
	NotBefore time.Time
	NotAfter  time.Time
}

// certified is one key this process generated and custody certified.
type certified struct {
	key       Key
	priv      *ecdsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
}

// halfLife is the moment a renewal is due: halfway through the statement's life.
func (c *certified) halfLife() time.Time {
	return c.notBefore.Add(c.notAfter.Sub(c.notBefore) / 2)
}

// Delegated declares a delegated key of name, of algorithm ES256 or ES384 and
// the given life. The life must be whole seconds and at least ten minutes.
func (c *Client) Delegated(name, alg string, lifetime time.Duration) (*Delegated, error) {
	if !nameRe.MatchString(name) {
		return nil, errors.New("keyclient: the key name is outside custody's name grammar")
	}
	if alg != "ES256" && alg != "ES384" {
		return nil, fmt.Errorf("keyclient: a delegated key is ES256 or ES384, not %q", alg)
	}
	if lifetime < minLifetime || lifetime > maxLifetime || lifetime%time.Second != 0 {
		return nil, fmt.Errorf("keyclient: a life of %s is outside custody's range of %s to %s, in whole seconds", lifetime, minLifetime, maxLifetime)
	}
	return &Delegated{c: c, name: name, alg: alg, lifetime: lifetime, retry: defaultRetry}, nil
}

// RenewIfDue asks custody for a new key and statement when the newest one has
// reached half its life, or when no key is valid. It reports whether it asked.
// After a failure it waits before asking again, so a custody that is down is
// not hammered.
func (d *Delegated) RenewIfDue(ctx context.Context) (bool, error) {
	d.renewMu.Lock()
	defer d.renewMu.Unlock()
	d.mu.Lock()
	due := d.dueLocked(d.c.now())
	d.mu.Unlock()
	if !due {
		return false, nil
	}
	k, err := d.renew(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.nextTry = d.c.now().Add(d.retry)
		return true, err
	}
	d.nextTry = time.Time{}
	now := d.c.now()
	kept := d.keys[:0]
	for _, old := range d.keys {
		if now.Before(old.notAfter) {
			kept = append(kept, old)
		}
	}
	d.keys = append(kept, k)
	return true, nil
}

// Current returns the key valid at the clock's time, with its statement.
func (d *Delegated) Current() (Key, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := d.validLocked(d.c.now())
	if k == nil {
		return Key{}, ErrNoValidKey
	}
	out := k.key
	out.Statement = slices.Clone(k.key.Statement)
	return out, nil
}

// Sign signs msg locally with the key valid at the clock's time. It fails with
// ErrNoValidKey rather than sign with a key whose statement has run out or has
// not yet begun.
func (d *Delegated) Sign(msg []byte) (Signature, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := d.validLocked(d.c.now())
	if k == nil {
		return Signature{}, ErrNoValidKey
	}
	sig, err := ecSign(k.priv, digestFor(d.alg, msg))
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: d.alg, Kid: k.key.Kid, Sig: sig}, nil
}

// Run renews the key as it falls due until ctx is done. Each failed attempt is
// reported to onErr when that is not nil. It sleeps until the next renewal is
// due, and never less than a second.
func (d *Delegated) Run(ctx context.Context, onErr func(error)) {
	for {
		if _, err := d.RenewIfDue(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		if ctx.Err() != nil {
			return
		}
		d.mu.Lock()
		next := d.nextDueLocked(d.c.now())
		d.mu.Unlock()
		wait := max(next.Sub(d.c.now()), time.Second)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// dueLocked reports whether a renewal should be asked for now.
func (d *Delegated) dueLocked(now time.Time) bool {
	if now.Before(d.nextTry) {
		return false
	}
	newest := d.newestLocked()
	return newest == nil || !now.Before(newest.halfLife())
}

// nextDueLocked is when the next renewal should be asked for.
func (d *Delegated) nextDueLocked(now time.Time) time.Time {
	if now.Before(d.nextTry) {
		return d.nextTry
	}
	newest := d.newestLocked()
	if newest == nil {
		return now
	}
	return newest.halfLife()
}

// newestLocked is the key with the latest not_before.
func (d *Delegated) newestLocked() *certified {
	var newest *certified
	for _, c := range d.keys {
		if newest == nil || c.notBefore.After(newest.notBefore) {
			newest = c
		}
	}
	return newest
}

// validLocked is the key whose statement is valid at now: started, and not yet
// run out. When two are valid, the one that started last is used. The bounds
// are the ones custody's ValidAt uses, from not_before up to not_after.
func (d *Delegated) validLocked(now time.Time) *certified {
	var best *certified
	for _, c := range d.keys {
		if now.Before(c.notBefore) || !now.Before(c.notAfter) {
			continue
		}
		if best == nil || c.notBefore.After(best.notBefore) {
			best = c
		}
	}
	return best
}

// renew generates a key, proves to custody that it is held, and checks the
// statement custody answers. Nothing is kept unless every check passes.
func (d *Delegated) renew(ctx context.Context) (*certified, error) {
	priv, err := ecdsa.GenerateKey(curveFor(d.alg), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := delegation.FromPublic(&priv.PublicKey, "")
	kid, err := delegation.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	jwk := delegation.JWK{Kty: "EC", Crv: pub.Crv, X: pub.X, Y: pub.Y, Kid: kid, Alg: d.alg, Use: "sig"}

	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := d.c.do(ctx, http.MethodPost, "/v1/keys/"+d.name+"/challenge", nil, &ch); err != nil {
		return nil, err
	}
	if ch.Challenge == "" {
		return nil, errors.New("keyclient: custody answered a challenge with none")
	}
	proof, err := ecSign(priv, digestFor(d.alg, proofInput(d.name, d.c.consumer, kid, ch.Challenge)))
	if err != nil {
		return nil, err
	}

	in := struct {
		JWK       delegation.JWK `json:"jwk"`
		Challenge string         `json:"challenge"`
		Proof     string         `json:"proof_b64"`
		Lifetime  int64          `json:"lifetime_s"`
	}{jwk, ch.Challenge, base64.StdEncoding.EncodeToString(proof), int64(d.lifetime / time.Second)}
	var out struct {
		Statement json.RawMessage `json:"statement"`
		Kid       string          `json:"kid"`
		NotBefore int64           `json:"not_before"`
		NotAfter  int64           `json:"not_after"`
	}
	if err := d.c.do(ctx, http.MethodPost, "/v1/keys/"+d.name+"/delegate", in, &out); err != nil {
		return nil, err
	}
	if out.Kid != kid {
		return nil, errors.New("keyclient: custody certified a key id other than the one offered")
	}
	if err := d.checkStatement(out.Statement, jwk, out.NotBefore, out.NotAfter); err != nil {
		return nil, err
	}
	return &certified{
		key: Key{Kid: kid, JWK: jwk, Statement: out.Statement,
			NotBefore: time.Unix(out.NotBefore, 0), NotAfter: time.Unix(out.NotAfter, 0)},
		priv:      priv,
		notBefore: time.Unix(out.NotBefore, 0),
		notAfter:  time.Unix(out.NotAfter, 0),
	}, nil
}

// checkStatement reads the claims of the statement custody answered and refuses
// one that does not certify this key, this name and this consumer, or that does
// not have the life asked for. It does not check the root signatures: those are
// a verifier's to check, against the delegation root's published keys (see the
// README's NOT PROVEN list).
func (d *Delegated) checkStatement(raw json.RawMessage, jwk delegation.JWK, notBefore, notAfter int64) error {
	var env struct {
		Payload    string            `json:"payload"`
		Signatures []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.Payload == "" || len(env.Signatures) == 0 {
		return errors.New("keyclient: the statement is not of the known shape")
	}
	p, err := base64.RawURLEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return errors.New("keyclient: the statement payload is not base64url")
	}
	var cl struct {
		V         int            `json:"v"`
		Iss       string         `json:"iss"`
		Name      string         `json:"name"`
		Owner     string         `json:"owner"`
		Kid       string         `json:"kid"`
		JWK       delegation.JWK `json:"jwk"`
		NotBefore int64          `json:"not_before"`
		NotAfter  int64          `json:"not_after"`
	}
	if err := json.Unmarshal(p, &cl); err != nil {
		return errors.New("keyclient: the statement claims are not of the known shape")
	}
	switch {
	case cl.V != 1 || cl.Iss != "keyryx":
		return errors.New("keyclient: the statement is not a version 1 statement from keyryx")
	case cl.Name != d.name || cl.Owner != d.c.consumer:
		return errors.New("keyclient: the statement certifies another name or consumer")
	case cl.Kid != jwk.Kid || cl.JWK.Kid != jwk.Kid:
		return errors.New("keyclient: the statement certifies another key")
	case cl.JWK.Kty != jwk.Kty || cl.JWK.Crv != jwk.Crv || cl.JWK.X != jwk.X || cl.JWK.Y != jwk.Y || cl.JWK.Alg != d.alg:
		return errors.New("keyclient: the statement's key is not the key offered")
	case cl.NotBefore != notBefore || cl.NotAfter != notAfter:
		return errors.New("keyclient: the statement's times are not the times custody answered")
	case notAfter-notBefore != int64(d.lifetime/time.Second):
		return errors.New("keyclient: the statement's life is not the life asked for")
	}
	return nil
}

// proofInput is what the key being certified signs to show it is held. It is
// custody's input (keyryx internal/statement, ProofInput): a domain separator,
// then the name, the consumer, the key's kid and the challenge, each ended by a
// NUL so no field can borrow from its neighbour.
func proofInput(name, consumer, kid, challenge string) []byte {
	return []byte("keyryx/delegate/v1\x00" + name + "\x00" + consumer + "\x00" + kid + "\x00" + challenge)
}

func curveFor(alg string) elliptic.Curve {
	if alg == "ES384" {
		return elliptic.P384()
	}
	return elliptic.P256()
}

// digestFor is the hash the algorithm signs: SHA-256 for ES256, SHA-384 for ES384.
func digestFor(alg string, b []byte) []byte {
	if alg == "ES384" {
		d := sha512.Sum384(b)
		return d[:]
	}
	d := sha256.Sum256(b)
	return d[:]
}

// ecSign is an ECDSA signature as R||S, each half padded to the curve size. It
// is the form custody checks, and the form a JWS carries.
func ecSign(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	return append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...), nil
}
