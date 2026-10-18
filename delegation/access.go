package delegation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// AgentTokenTyp is the JWS `typ` of an agent's own access token, RFC 9068
// section 2.1: what vouchryx's `client_credentials` grant mints. It is checked
// exactly and both ways: [VerifyAccess] refuses any other `typ`, and [Verify]
// refuses this one, so neither token is ever read as the other. tokenfuse's
// `AGENT_TOKEN_TYP` is the same string and the shared table pins both.
const AgentTokenTyp = "at+jwt"

// AgentTokenLeeway is how far past `exp` an agent token still verifies, and how
// far ahead of the verifier's clock its `iat` may sit. Two hosts' clocks drift,
// and a refusal in the second a token turns over is an outage rather than a
// defence. The token lives five minutes, so this is a tenth of it. tokenfuse's
// `AGENT_TOKEN_LEEWAY_SECS` is the same number and the shared table pins both.
const AgentTokenLeeway = 30 * time.Second

// Refusals the agent-token verifier adds to the ones [Verify] already names.
var (
	ErrNotYetValid     = errors.New("delegation: the token was issued further ahead of this clock than the leeway allows")
	ErrNotConfigured   = errors.New("delegation: the agent-token verifier was given no replay cache or no revocation hook, so it checks nothing")
	ErrReplayCacheFull = errors.New("delegation: the proof replay cache is full, so single use can no longer be promised")
)

// AccessOptions is what a door already holds when an agent's own token
// arrives. Like [Options] there is no client, no fetching URL and no timeout:
// the check is local.
type AccessOptions struct {
	// Keys is vouchryx's public set, held locally. It may hold more than one
	// key during a rotation; the token's `kid` names the one that verifies it.
	Keys Set
	// Issuer is the exact `iss` required.
	Issuer string
	// Audience is the exact `aud` required, and it is REQUIRED: an empty
	// audience refuses every token rather than accepting any resource, which is
	// where this differs from [Options.Audience].
	Audience string
	// Now is the clock. It is read in whole seconds, the unit the Rust door
	// reads it in, so the two cannot disagree about an edge by a fraction.
	Now time.Time

	// Proof is the RFC 9449 header presented with the token, and Method and URL
	// are what THIS server received. [VerifyRelayedAccess] ignores all three.
	Proof       string
	Method, URL string
	// Proofs makes a proof single use. Required by [VerifyAccess]: a door that
	// forgot it would accept a captured proof for as long as it stays fresh.
	// One cache per process, shared by every door of that process.
	Proofs *ReplayCache

	// Revoked is asked last, with the token's `jti`, the agent and the token's
	// `iat`. Required: a door that has decided a valid signature is enough
	// says so with a function that answers false, never by leaving this nil.
	Revoked func(jti, subject string, issuedAt int64) bool
}

// VerifiedAgent is what a door may rely on after an agent's own token verified:
// who the agent is, and the unit and org the registry put it in. Every field is
// signed by the issuer or derived from something that is.
type VerifiedAgent struct {
	// Subject is `sub`, an `agent://` URI, equal to the token's `client_id`.
	Subject string
	// Unit is the registry's unit for the agent: what the call is billed to.
	Unit string
	// Org is the registry's org for the agent.
	Org string
	// JTI is the token's own `jti`.
	JTI string
	// JKT is the thumbprint the token is bound to.
	JKT string
	// ProofJTI is the `jti` of the proof presented with the token, already
	// recorded as used. Empty for a relayed token, which came with no proof.
	ProofJTI  string
	IssuedAt  int64
	ExpiresAt int64
}

// maxProofJTIBytes is the longest proof `jti` a door will remember: a client
// chooses it and the replay cache stores it. tokenfuse's `MAX_JTI_BYTES`.
const maxProofJTIBytes = 256

// IsAgentToken reports whether the token's header declares it an agent token.
//
// Read WITHOUT verifying anything, so it may decide only WHICH verifier a door
// runs, never whether the token is trusted: [VerifyAccess] reads the same
// header again and checks the signature behind it.
func IsAgentToken(token string) bool {
	typ, ok := headerTyp(token)
	return ok && typ == AgentTokenTyp
}

// headerTyp reads the JWS header's `typ` from a compact token, and reports
// whether the header could be read at all.
func headerTyp(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", false
	}
	return h.Typ, true
}

// AccessTokenHash is the `ath` RFC 9449 section 4.2 requires of a proof
// presented with `token`: the base64url (no padding) SHA-256 of its ASCII
// bytes. Without it a proof binds a request to a KEY and not to a token, so a
// proof the holder made beside one of its tokens is good beside any other.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64(sum[:])
}

// agentClaimSet is what [agentClaims] read and checked.
type agentClaimSet struct {
	sub, jti, jkt, unit, org string
	iat, exp                 int64
}

// agentClaims is every check an agent token is held to before its proof, shared
// by the door that sees the proof and the one a token is relayed to, in
// tokenfuse's order: `typ`, the key the `kid` names with the algorithm from its
// type and the signature (an empty configured audience refuses before any of
// that), the exact `iss`, the REQUIRED exact `aud`, `exp` with
// [AgentTokenLeeway], `iat` no further ahead than that, `sub` an `agent://` URI
// with something after the scheme and equal to `client_id`, a `jti`, no `act`,
// and a `cnf.jkt` to bind it.
func agentClaims(token string, o AccessOptions, now int64) (agentClaimSet, error) {
	if typ, ok := headerTyp(token); !ok || typ != AgentTokenTyp {
		return agentClaimSet{}, ErrMalformed
	}
	if o.Audience == "" {
		// Required, not defaulted to "any": a door nobody told its own
		// resource would otherwise accept a token minted for every other one.
		return agentClaimSet{}, ErrAudience
	}
	claims, err := VerifyToken(token, o.Keys)
	if err != nil {
		return agentClaimSet{}, err
	}
	iss, _ := claims["iss"].(string)
	if o.Issuer == "" || iss != o.Issuer {
		return agentClaimSet{}, ErrIssuer
	}
	// Present and naming this resource: a token with no `aud` was minted for
	// no resource, which is not this one.
	if !audienceHas(claims["aud"], o.Audience) {
		return agentClaimSet{}, ErrAudience
	}
	leeway := int64(AgentTokenLeeway / time.Second)
	exp, ok := wholeSecond(claims["exp"])
	if !ok || now >= saturatingAdd(exp, leeway) {
		return agentClaimSet{}, ErrExpired
	}
	// An absent iat is 0, as the Rust verifier defaults it; a present one it
	// cannot read as a whole second is refused, as it refuses one.
	var iat int64
	if v, present := claims["iat"]; present {
		if iat, ok = wholeSecond(v); !ok {
			return agentClaimSet{}, ErrMalformed
		}
	}
	if iat > saturatingAdd(now, leeway) {
		return agentClaimSet{}, ErrNotYetValid
	}
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	jti, _ := claims["jti"].(string)
	agent, isAgent := strings.CutPrefix(sub, "agent://")
	// A JSON null `act` is no act, as it is to the Rust verifier; any other
	// value names a chain, and an agent token acts for nobody.
	if !isAgent || agent == "" || clientID != sub || jti == "" || claims["act"] != nil {
		return agentClaimSet{}, ErrMalformed
	}
	jkt := confirmationKey(claims)
	if jkt == "" {
		return agentClaimSet{}, ErrNotBound
	}
	unit, okUnit := optionalString(claims, "unit")
	org, okOrg := optionalString(claims, "org")
	if !okUnit || !okOrg {
		return agentClaimSet{}, ErrMalformed
	}
	return agentClaimSet{sub: sub, jti: jti, jkt: jkt, unit: unit, org: org, iat: iat, exp: exp}, nil
}

func (a agentClaimSet) verified(proofJTI string) VerifiedAgent {
	return VerifiedAgent{
		Subject: a.sub, Unit: a.unit, Org: a.org, JTI: a.jti, JKT: a.jkt,
		ProofJTI: proofJTI, IssuedAt: a.iat, ExpiresAt: a.exp,
	}
}

// VerifyAccess verifies an agent's own token and the proof presented with it,
// at a door, and records the proof as used.
//
// [agentClaims]'s checks; then the proof, which must verify for this request
// at this moment, carry a `jti` short enough to remember, be signed by the key
// the token is bound to, and name THIS token in its `ath`; then the revocation
// hook for the token's `jti`, its agent and its `iat`, last of the token
// checks, as tokenfuse asks it; and only then the replay cache, so a proof
// spent on a refused presentation is not spent at all and nobody who cannot
// sign for a bound key can fill the cache.
//
// Each proof failure is [ErrWrongKey], wrapping the proof's own reason for an
// operator's log; a replayed proof is [ErrReplay] and a full cache
// [ErrReplayCacheFull]. What reaches a caller over the wire should not tell
// these apart: a verifier that narrates which check failed is an oracle.
func VerifyAccess(token string, o AccessOptions) (VerifiedAgent, error) {
	if o.Proofs == nil || o.Revoked == nil {
		return VerifiedAgent{}, ErrNotConfigured
	}
	now := time.Unix(o.Now.Unix(), 0)
	a, err := agentClaims(token, o, now.Unix())
	if err != nil {
		return VerifiedAgent{}, err
	}
	if o.Proof == "" || o.Method == "" || o.URL == "" {
		return VerifiedAgent{}, ErrNoProof
	}
	p, err := verifyProof(o.Proof, o.Method, o.URL, now)
	if err != nil {
		return VerifiedAgent{}, fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	if len(p.jti) > maxProofJTIBytes {
		return VerifiedAgent{}, fmt.Errorf("%w: %w", ErrWrongKey, ErrBinding)
	}
	if p.thumb != a.jkt {
		return VerifiedAgent{}, ErrWrongKey
	}
	if p.ath != AccessTokenHash(token) {
		return VerifiedAgent{}, fmt.Errorf("%w: the proof does not name this token", ErrWrongKey)
	}
	if o.Revoked(a.jti, a.sub, a.iat) {
		return VerifiedAgent{}, ErrRevoked
	}
	if err := o.Proofs.CheckAndRecord(p.jti, now); err != nil {
		return VerifiedAgent{}, err
	}
	return a.verified(p.jti), nil
}

// VerifyRelayedAccess verifies an agent token another door of this deployment
// already verified WITH its proof, relayed here by a credential that door
// holds: every check [VerifyAccess] makes except the proof. The token is still
// bound, still in its life, still for this audience, and still not revoked.
// The caller decides who may relay; this function only knows that nobody here
// can check the proof again. Proof, Method, URL and Proofs are not read.
func VerifyRelayedAccess(token string, o AccessOptions) (VerifiedAgent, error) {
	if o.Revoked == nil {
		return VerifiedAgent{}, ErrNotConfigured
	}
	a, err := agentClaims(token, o, o.Now.Unix())
	if err != nil {
		return VerifiedAgent{}, err
	}
	if o.Revoked(a.jti, a.sub, a.iat) {
		return VerifiedAgent{}, ErrRevoked
	}
	return a.verified(""), nil
}

// wholeSecond reads a NumericDate the way the Rust verifier's i64 does: a JSON
// number with no fraction that fits in 64 bits. Anything else is refused there
// by deserialization, and converting an out-of-range float to int64 in Go has
// no defined answer, so it is refused here before any conversion.
func wholeSecond(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f < math.MinInt64 || f >= math.MaxInt64 {
		return 0, false
	}
	return int64(f), true
}

// optionalString reads a string claim the way the Rust verifier's defaulted
// String does: absent is empty, a string is itself, and anything else, null
// included, is a token it cannot read.
func optionalString(claims map[string]any, name string) (string, bool) {
	v, present := claims[name]
	if !present {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

// saturatingAdd is a + b without wrapping, as Rust's saturating_add.
func saturatingAdd(a, b int64) int64 {
	s := a + b
	if b > 0 && s < a {
		return math.MaxInt64
	}
	if b < 0 && s > a {
		return math.MinInt64
	}
	return s
}
