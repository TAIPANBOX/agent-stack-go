package delegation

import (
	"errors"
	"fmt"
	"time"
)

// Refusals a caller may want to tell apart, because each sends the operator
// somewhere different. A signature failure is a security event; an expiry is a
// client that needs to refresh; a revocation is somebody's deliberate act.
var (
	ErrExpired   = errors.New("delegation: the token has expired")
	ErrIssuer    = errors.New("delegation: the token was not issued by the expected issuer")
	ErrAudience  = errors.New("delegation: the token was not minted for this audience")
	ErrNotBound  = errors.New("delegation: the token carries no cnf.jkt, so it is a bearer token")
	ErrWrongKey  = errors.New("delegation: the presenter does not hold the key this token is bound to")
	ErrRevoked   = errors.New("delegation: this delegation has been revoked")
	ErrNoProof   = errors.New("delegation: a sender-constrained token was presented with no proof")
	ErrMalformed = errors.New("delegation: the token is not a delegation token")
)

// Verified is what an enforcement point may rely on after a successful check.
//
// Every field here is either signed by the issuer or derived from something
// that is. Nothing on this struct came off an unverified header.
type Verified struct {
	// Subject is who the token is FOR: the `sub` claim.
	Subject string
	// Actors is the delegation chain read out of `act`, in the order this
	// module records chains.
	//
	// **Read, not verified.** CLAUDE.md invariant 5: root-first ordering is a
	// property of how a chain was BUILT and cannot be checked from the finished
	// list. What the signature guarantees is that the issuer put these names in
	// this nesting; that the nesting means what the issuer intended is the
	// issuer's to get right, and `vouchryx` has a test for it. A verifier that
	// claimed to check the order would be claiming something no verifier can.
	Actors []string
	// Chain is `Subject` followed by `Actors`: the `on_behalf_of` an
	// agent-passport event carries. Same caveat as `Actors`.
	Chain []string
	// JKT is the thumbprint the token is bound to, and it MATCHED the proof.
	JKT string
	// JTI, IssuedAt and ExpiresAt are what a revocation list is checked against.
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
	// Scope is the `scope` claim, or empty.
	Scope string
}

// Options is what an enforcement point already holds locally.
//
// There is no URL here for fetching anything. That is the point of A2: every
// field is something the process has before the request arrives, so a check
// costs no round trip and the token service is not a hard dependency of every
// enforcement point at once.
type Options struct {
	// Keys is the issuer's public set, held locally.
	Keys Set
	// Issuer is the exact `iss` required. Not a prefix: a prefix is how a
	// service ends up trusting `vouchryx.acme.example.evil.test`.
	Issuer string
	// Audience is the `aud` required, or empty to accept any. Empty is a real
	// choice for a single-tenant deployment and a mistake in a shared one, so
	// it is explicit rather than defaulted.
	Audience string
	// Now is the clock. Injected so an expiry is testable without sleeping.
	Now time.Time

	// Proof is the RFC 9449 header the caller presented, and Method and URL
	// are what THIS server received. Together they prove the caller holds the
	// key the token is bound to.
	//
	// Leaving Proof empty means the caller is NOT checking sender-constraint,
	// and [Verify] then refuses any token that carries a `cnf.jkt`: a
	// sender-constrained token checked as a bearer token is the failure this
	// whole scheme exists to prevent, and silently downgrading would be the
	// worst way to meet it.
	Proof       string
	Method, URL string
	// Proofs is the replay cache. Optional, and its absence is a real
	// weakening: without it a captured proof works as often as it is presented
	// inside its window.
	Proofs *Verifier

	// Revoked is consulted after the signature checks pass. Optional; when it
	// is nil, revocation is NOT checked, and a caller that leaves it nil has
	// decided that a valid signature is enough.
	Revoked func(jti, subject string, issuedAt int64) bool
}

// Verify checks a delegation token and everything that makes it more than a
// bearer token.
//
// The order is deliberate and each step is cheaper than the next thing it
// protects: shape, signature, issuer, audience, expiry, binding, revocation. A
// revocation lookup on a forged token would be work an attacker chose.
func Verify(token string, o Options) (Verified, error) {
	claims, err := VerifyToken(token, o.Keys)
	if err != nil {
		return Verified{}, err
	}

	iss, _ := claims["iss"].(string)
	if o.Issuer == "" || iss != o.Issuer {
		return Verified{}, ErrIssuer
	}
	if o.Audience != "" && !audienceHas(claims["aud"], o.Audience) {
		return Verified{}, ErrAudience
	}

	exp, ok := asUnix(claims["exp"])
	if !ok {
		// A delegation with no expiry is a permanent grant, and this scheme's
		// whole answer to a stolen token is that it stops working.
		return Verified{}, ErrExpired
	}
	if o.Now.Unix() >= exp {
		return Verified{}, ErrExpired
	}
	iat, _ := asUnix(claims["iat"])

	sub, _ := claims["sub"].(string)
	jti, _ := claims["jti"].(string)
	if sub == "" || jti == "" {
		return Verified{}, ErrMalformed
	}

	// THE STEP THAT MAKES THIS NOT A BEARER TOKEN.
	jkt := confirmationKey(claims)
	switch {
	case jkt == "" && o.Proof == "":
		// Neither side is doing sender-constraint. Refused rather than
		// permitted: this module verifies DELEGATION tokens, every one of which
		// vouchryx binds, so an unbound one is either from somewhere else or
		// from a version that stopped binding.
		return Verified{}, ErrNotBound
	case jkt == "":
		return Verified{}, ErrNotBound
	case o.Proof == "":
		// The token is bound and the caller did not check. Downgrading here
		// would turn every sender-constrained token in the estate into a bearer
		// token, silently, at whichever enforcement point forgot.
		return Verified{}, ErrNoProof
	}
	presented, err := o.checkProof()
	if err != nil {
		return Verified{}, err
	}
	if presented != jkt {
		return Verified{}, ErrWrongKey
	}

	if o.Revoked != nil && o.Revoked(jti, sub, iat) {
		return Verified{}, ErrRevoked
	}

	var act Act
	if err := decodeAct(claims["act"], &act); err != nil {
		return Verified{}, ErrMalformed
	}
	actors, err := ReadAct(&act)
	if err != nil {
		return Verified{}, ErrMalformed
	}
	chain, err := Chain(sub, &act)
	if err != nil {
		return Verified{}, ErrMalformed
	}

	scope, _ := claims["scope"].(string)
	return Verified{
		Subject:   sub,
		Actors:    actors,
		Chain:     chain,
		JKT:       jkt,
		JTI:       jti,
		IssuedAt:  iat,
		ExpiresAt: exp,
		Scope:     scope,
	}, nil
}

// checkProof verifies the presented DPoP proof, using the caller's replay cache
// when it has one.
func (o Options) checkProof() (string, error) {
	if o.Method == "" || o.URL == "" {
		// A proof is bound to one request, and a caller that did not say which
		// request cannot have that checked. Refused rather than checked
		// partially: a partial check reads like a check.
		return "", ErrNoProof
	}
	v := o.Proofs
	if v == nil {
		// No replay cache is a real weakening and not an error: a caller may
		// legitimately have none, for instance a batch verifier reading a log.
		// A throwaway verifier gives the signature and binding checks without
		// the replay one, which is what "no cache" honestly means.
		v = NewVerifier()
	}
	thumb, err := v.Check(o.Proof, o.Method, o.URL, o.Now)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	return thumb, nil
}

// confirmationKey reads `cnf.jkt` (RFC 9449 section 6).
func confirmationKey(claims map[string]any) string {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func audienceHas(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, one := range v {
			if s, ok := one.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func asUnix(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}
