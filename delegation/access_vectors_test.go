package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shared agent-token table: the cases the Go verifier here and tokenfuse's
// Rust verifier must answer the same way, as DATA rather than as two suites
// that happen to agree today. Its tokens and proofs are minted once, by
// test-only keys the file itself carries, so a reader in another language
// needs no signer to run it: every case is fixed bytes, a clock, and an
// expected answer.
//
// The file is canonical here and found by its `$source`, the convention
// estate-gates C14 reads to hold every vendored copy to the canonical one.
//
// Regenerate it (new signatures, the same keys) with:
//
//	go test ./delegation -run TestRegenerateAgentTokenVectors -update-agent-vectors
var updateAgentVectors = flag.Bool("update-agent-vectors", false,
	"rewrite testdata/agent-token-vectors.json from the cases in access_vectors_test.go, keeping its test-only keys")

const (
	agentVectorsPath   = "testdata/agent-token-vectors.json"
	agentVectorsSource = "agent-stack-go/delegation/testdata/agent-token-vectors.json"
)

type agentVectors struct {
	Source       string                 `json:"$source"`
	WhySource    string                 `json:"$why_source"`
	Comment      string                 `json:"comment"`
	Outcomes     map[string]string      `json:"outcomes"`
	ReplayAnswer map[string]string      `json:"replay_outcomes"`
	NotHere      []string               `json:"not_in_this_table"`
	Constants    vectorConstants        `json:"constants"`
	TestOnlyKeys map[string]testOnlyKey `json:"test_only_keys"`
	Config       vectorConfig           `json:"config"`
	Cases        []agentCase            `json:"cases"`
	Replay       []replaySequence       `json:"replay"`
}

type vectorConstants struct {
	Typ                  string `json:"typ"`
	LeewaySecs           int64  `json:"leeway_secs"`
	ProofWindowSecs      int64  `json:"proof_window_secs"`
	MaxProofJTIBytes     int    `json:"max_proof_jti_bytes"`
	ReplayGenerationSecs int64  `json:"replay_generation_secs"`
}

// testOnlyKey is a private key that exists for this table and for nothing
// else. Its name says so, and `scripts/test-keys-stay-test-only.sh` holds the
// name and the place.
type testOnlyKey struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type vectorConfig struct {
	Issuer   string          `json:"issuer"`
	Audience string          `json:"audience"`
	Method   string          `json:"method"`
	URL      string          `json:"url"`
	JWKS     json.RawMessage `json:"jwks"`
}

type agentCase struct {
	Name       string          `json:"name"`
	Why        string          `json:"why"`
	Verifier   string          `json:"verifier"`
	Now        int64           `json:"now"`
	JWS        string          `json:"jws"`
	DPoP       string          `json:"dpop,omitempty"`
	Method     string          `json:"method,omitempty"`
	URL        string          `json:"url,omitempty"`
	Audience   *string         `json:"audience,omitempty"`
	Revoke     *revokeSpec     `json:"revoke,omitempty"`
	Expect     string          `json:"expect"`
	Verified   *verifiedVector `json:"verified,omitempty"`
	Divergence *divergence     `json:"known_divergence,omitempty"`
}

type revokeSpec struct {
	JTI     string `json:"jti,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type verifiedVector struct {
	Subject   string `json:"subject"`
	Unit      string `json:"unit"`
	Org       string `json:"org"`
	JTI       string `json:"jti"`
	JKT       string `json:"jkt"`
	ProofJTI  string `json:"proof_jti"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// divergence records what tokenfuse's verifier answers for a case where it
// does not answer as this table states, read from its source rather than run.
// A Rust suite that vendors the table can expect these to fail by name until
// they are closed, instead of discovering them as noise.
type divergence struct {
	Tokenfuse string `json:"tokenfuse_ddf8dc5"`
	Why       string `json:"why"`
}

type replaySequence struct {
	Name  string       `json:"name"`
	Why   string       `json:"why"`
	Cap   int          `json:"cap"`
	Steps []replayStep `json:"steps"`
}

type replayStep struct {
	JTI    string `json:"jti"`
	Now    int64  `json:"now"`
	Expect string `json:"expect"`
}

func loadAgentVectors(t testing.TB) agentVectors {
	t.Helper()
	raw, err := os.ReadFile(agentVectorsPath)
	if err != nil {
		t.Fatalf("the shared agent-token table is unreadable: %v", err)
	}
	var doc agentVectors
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the shared agent-token table is not JSON this test can read: %v", err)
	}
	return doc
}

// refusalName maps this package's errors onto the table's vocabulary, which is
// tokenfuse's `Refusal`, snake_cased. Go keeps its finer errors (a missing kid
// and an unknown one are told apart here); the table names the class both
// languages must agree on. Order matters: a proof's own failure is wrapped in
// ErrWrongKey, so that is asked first.
func refusalName(err error) string {
	switch {
	case err == nil:
		return "accept"
	case errors.Is(err, ErrWrongKey):
		return "wrong_key"
	case errors.Is(err, ErrNoProof):
		return "no_proof"
	case errors.Is(err, ErrNotBound):
		return "not_bound"
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrIssuer):
		return "issuer"
	case errors.Is(err, ErrAudience):
		return "audience"
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrNoKid):
		return "malformed"
	case errors.Is(err, ErrUnknownKid), errors.Is(err, ErrBadSignature), errors.Is(err, ErrAlgNotAllowed):
		return "bad_signature"
	}
	return "unmapped: " + err.Error()
}

func replayName(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrReplay):
		return "seen"
	case errors.Is(err, ErrReplayCacheFull):
		return "full"
	}
	return "unmapped: " + err.Error()
}

func runAgentCase(t *testing.T, set Set, cfg vectorConfig, c agentCase) (VerifiedAgent, error) {
	t.Helper()
	aud, method, u := cfg.Audience, cfg.Method, cfg.URL
	if c.Audience != nil {
		aud = *c.Audience
	}
	if c.Method != "" {
		method = c.Method
	}
	if c.URL != "" {
		u = c.URL
	}
	hook := func(jti, sub string, _ int64) bool {
		if c.Revoke == nil {
			return false
		}
		return (c.Revoke.JTI != "" && jti == c.Revoke.JTI) ||
			(c.Revoke.Subject != "" && sub == c.Revoke.Subject)
	}
	now := time.Unix(c.Now, 0)
	switch c.Verifier {
	case "agent":
		return VerifyAccess(c.JWS, AccessOptions{
			Keys: set, Issuer: cfg.Issuer, Audience: aud, Now: now,
			Proof: c.DPoP, Method: method, URL: u,
			Proofs: NewReplayCache(16), Revoked: hook,
		})
	case "relayed":
		return VerifyRelayedAccess(c.JWS, AccessOptions{
			Keys: set, Issuer: cfg.Issuer, Audience: aud, Now: now, Revoked: hook,
		})
	case "delegation":
		_, err := Verify(c.JWS, Options{
			Keys: set, Issuer: cfg.Issuer, Audience: aud, Now: now,
			Proof: c.DPoP, Method: method, URL: u, Revoked: hook,
		})
		return VerifiedAgent{}, err
	}
	t.Fatalf("case %q names verifier %q, which this table does not define", c.Name, c.Verifier)
	return VerifiedAgent{}, nil
}

func TestEveryAgentTokenVectorIsAnsweredAsItStates(t *testing.T) {
	doc := loadAgentVectors(t)
	if len(doc.Cases) == 0 {
		t.Fatal("the shared table holds no cases, so this test measured nothing")
	}
	var set Set
	if err := json.Unmarshal(doc.Config.JWKS, &set); err != nil || len(set.Keys) == 0 {
		t.Fatalf("the table's key set is unreadable or empty: %v", err)
	}
	names := map[string]bool{}
	answered := map[string]bool{}
	verifiers := map[string]bool{}
	for _, c := range doc.Cases {
		if names[c.Name] {
			t.Fatalf("two cases are named %q", c.Name)
		}
		names[c.Name] = true
		if _, ok := doc.Outcomes[c.Expect]; !ok {
			t.Fatalf("case %q expects %q, which the table's vocabulary does not define", c.Name, c.Expect)
		}
		answered[c.Expect] = true
		verifiers[c.Verifier] = true
		t.Run(c.Name, func(t *testing.T) {
			got, err := runAgentCase(t, set, doc.Config, c)
			if name := refusalName(err); name != c.Expect {
				t.Fatalf("expected %s, got %s (%v)", c.Expect, name, err)
			}
			if c.Verified == nil {
				return
			}
			want := VerifiedAgent{
				Subject: c.Verified.Subject, Unit: c.Verified.Unit, Org: c.Verified.Org,
				JTI: c.Verified.JTI, JKT: c.Verified.JKT, ProofJTI: c.Verified.ProofJTI,
				IssuedAt: c.Verified.IssuedAt, ExpiresAt: c.Verified.ExpiresAt,
			}
			if got != want {
				t.Fatalf("verified:\n got %+v\nwant %+v", got, want)
			}
		})
	}
	// A table that quietly lost a whole class of answer still passes case by
	// case, so the classes are counted too.
	for outcome := range doc.Outcomes {
		if !answered[outcome] {
			t.Errorf("no case in the table is answered %q", outcome)
		}
	}
	for _, v := range []string{"agent", "relayed", "delegation"} {
		if !verifiers[v] {
			t.Errorf("no case in the table runs the %s verifier", v)
		}
	}
}

func TestEveryReplayVectorIsAnsweredAsItStates(t *testing.T) {
	doc := loadAgentVectors(t)
	if len(doc.Replay) == 0 {
		t.Fatal("the shared table holds no replay sequences, so this test measured nothing")
	}
	answered := map[string]bool{}
	for _, seq := range doc.Replay {
		t.Run(seq.Name, func(t *testing.T) {
			c := NewReplayCache(seq.Cap)
			for i, s := range seq.Steps {
				if got := replayName(c.CheckAndRecord(s.JTI, time.Unix(s.Now, 0))); got != s.Expect {
					t.Fatalf("step %d (%s at %d): expected %s, got %s", i, s.JTI, s.Now, s.Expect, got)
				}
			}
		})
		for _, s := range seq.Steps {
			answered[s.Expect] = true
		}
	}
	for outcome := range doc.ReplayAnswer {
		if !answered[outcome] {
			t.Errorf("no replay step in the table is answered %q", outcome)
		}
	}
}

// The keys in the table are test-only by name, its key set is their public
// halves and nothing else, and the numbers it states are this package's
// constants, so the table cannot drift from the code it describes without
// this going red.
func TestTheVectorsFileNamesItsKeysTestOnlyAndPinsTheConstants(t *testing.T) {
	doc := loadAgentVectors(t)
	if doc.Source != agentVectorsSource {
		t.Errorf("$source is %q, want %q: C14 finds copies by it", doc.Source, agentVectorsSource)
	}
	want := vectorConstants{
		Typ:                  AgentTokenTyp,
		LeewaySecs:           int64(AgentTokenLeeway / time.Second),
		ProofWindowSecs:      int64(Window / time.Second),
		MaxProofJTIBytes:     maxProofJTIBytes,
		ReplayGenerationSecs: int64(replayGeneration / time.Second),
	}
	if doc.Constants != want {
		t.Errorf("constants:\n table %+v\n code  %+v", doc.Constants, want)
	}
	if len(doc.TestOnlyKeys) == 0 {
		t.Fatal("the table carries no test-only keys, so nothing here measured them")
	}
	byKid := map[string]testOnlyKey{}
	for name, k := range doc.TestOnlyKeys {
		if !strings.HasPrefix(name, "TEST_ONLY_") {
			t.Errorf("key %q is not named TEST_ONLY_", name)
		}
		if k.Kty == "EC" {
			priv := testOnlyPrivate(t, name, k)
			pub := FromPublic(&priv.PublicKey, "")
			if pub.X != k.X || pub.Y != k.Y || k.Crv != "P-256" {
				t.Errorf("key %q: its public half is not what its d derives", name)
			}
		}
		if k.Kid != "" {
			byKid[k.Kid] = k
		}
	}
	var set struct {
		Keys []testOnlyKey `json:"keys"`
	}
	if err := json.Unmarshal(doc.Config.JWKS, &set); err != nil || len(set.Keys) == 0 {
		t.Fatalf("the table's key set is unreadable or empty: %v", err)
	}
	for _, pub := range set.Keys {
		k, ok := byKid[pub.Kid]
		if !ok {
			t.Errorf("the key set's %q is no test-only key's public half", pub.Kid)
			continue
		}
		if pub.D != "" {
			t.Errorf("the key set's %q publishes a private member", pub.Kid)
		}
		if pub.Kty != k.Kty || pub.X != k.X || pub.Y != k.Y {
			t.Errorf("the key set's %q is not its test-only key's public half", pub.Kid)
		}
	}
}

func testOnlyPrivate(t testing.TB, name string, k testOnlyKey) *ecdsa.PrivateKey {
	t.Helper()
	d, err := unb64(k.D)
	if err != nil {
		t.Fatalf("key %q: d is not base64url: %v", name, err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatalf("key %q: %v", name, err)
	}
	return priv
}

func newTestOnlyEC(t testing.TB, kid string) testOnlyKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pub := FromPublic(&priv.PublicKey, "")
	return testOnlyKey{Kid: kid, Kty: "EC", Crv: "P-256", X: pub.X, Y: pub.Y, D: b64url(d)}
}

// TestRegenerateAgentTokenVectors rewrites the table. It keeps the test-only
// keys the file already carries, so a regeneration changes signatures and
// nothing a reader relies on; with no file it makes new ones.
func TestRegenerateAgentTokenVectors(t *testing.T) {
	if !*updateAgentVectors {
		t.Skip("rewrites the shared table; run with -update-agent-vectors")
	}
	old := map[string]testOnlyKey{}
	if raw, err := os.ReadFile(agentVectorsPath); err == nil {
		var doc agentVectors
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("the table exists and does not parse, so its keys cannot be kept: %v", err)
		}
		old = doc.TestOnlyKeys
	}
	keys := map[string]testOnlyKey{}
	for name, kid := range map[string]string{
		"TEST_ONLY_issuer_v1": "v-1", "TEST_ONLY_issuer_v2": "v-2",
		"TEST_ONLY_holder": "", "TEST_ONLY_thief": "", "TEST_ONLY_stranger": "",
	} {
		if k, ok := old[name]; ok {
			keys[name] = k
		} else {
			keys[name] = newTestOnlyEC(t, kid)
		}
	}
	doc := buildAgentVectors(t, keys)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(agentVectorsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentVectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d cases, %d replay sequences", agentVectorsPath, len(doc.Cases), len(doc.Replay))
}

func strp(s string) *string { return &s }

func buildAgentVectors(t *testing.T, keys map[string]testOnlyKey) agentVectors {
	t.Helper()
	iss1 := testOnlyPrivate(t, "TEST_ONLY_issuer_v1", keys["TEST_ONLY_issuer_v1"])
	iss2 := testOnlyPrivate(t, "TEST_ONLY_issuer_v2", keys["TEST_ONLY_issuer_v2"])
	holder := testOnlyPrivate(t, "TEST_ONLY_holder", keys["TEST_ONLY_holder"])
	thief := testOnlyPrivate(t, "TEST_ONLY_thief", keys["TEST_ONLY_thief"])
	stranger := testOnlyPrivate(t, "TEST_ONLY_stranger", keys["TEST_ONLY_stranger"])

	var jwks struct {
		Keys []testOnlyKey `json:"keys"`
	}
	for _, name := range []string{"TEST_ONLY_issuer_v1", "TEST_ONLY_issuer_v2"} {
		k := keys[name]
		k.D = ""
		jwks.Keys = append(jwks.Keys, k)
	}
	rawJWKS, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	const N = atNow
	leeway := int64(AgentTokenLeeway / time.Second)
	claims := func(iat int64, over map[string]any) map[string]any {
		return agentTokenClaims(t, holder, iat, over)
	}
	tok := func(over map[string]any) string {
		return mintAgent(t, iss1, "v-1", AgentTokenTyp, claims(N, over))
	}
	pf := func(tk, jti string) string { return dpopProof(t, holder, N, "POST", atURL, jti, tk) }
	good := tok(nil)
	verified := func(proofJTI string) *verifiedVector {
		return &verifiedVector{
			Subject: atAgent, Unit: atUnit, Org: atOrg, JTI: atJTI,
			JKT: thumbOf(t, holder), ProofJTI: proofJTI,
			IssuedAt: N, ExpiresAt: N + 300,
		}
	}
	agent := func(name, why, tk, proof, expect string) agentCase {
		return agentCase{Name: name, Why: why, Verifier: "agent", Now: N, JWS: tk, DPoP: proof, Expect: expect}
	}
	// agentP proves the token it is handed, so the proof's ath names THESE
	// bytes: two mints of one claim set are two tokens, ECDSA being randomised.
	agentP := func(name, why, tk, jti, expect string) agentCase {
		return agent(name, why, tk, pf(tk, jti), expect)
	}
	relayed := func(name, why, tk, expect string) agentCase {
		return agentCase{Name: name, Why: why, Verifier: "relayed", Now: N, JWS: tk, Expect: expect}
	}
	with := func(c agentCase, f func(*agentCase)) agentCase { f(&c); return c }
	chainClaims := map[string]any{
		"iss": atIss, "sub": "user://acme/alice", "aud": atAud,
		"iat": N, "exp": N + 300, "jti": "tok-1",
		"cnf": map[string]any{"jkt": thumbOf(t, holder)},
		"act": map[string]any{"sub": atAgent},
	}
	chained := mintAgent(t, iss1, "v-1", AgentTokenTyp, chainClaims)
	plain := mintAgent(t, iss1, "v-1", "JWT", chainClaims)
	withKid := func(k *ecdsa.PrivateKey, kid string) string {
		return mintAgent(t, k, kid, AgentTokenTyp, claims(N, nil))
	}
	header := func(alg string) map[string]any {
		return map[string]any{"alg": alg, "typ": AgentTokenTyp, "kid": "v-1"}
	}
	expiredAt := N + 300 + leeway

	cases := []agentCase{
		with(agentP("a good agent token verifies with its holder's proof",
			"The shape vouchryx mints. If this refuses, every agent is locked out.",
			good, "pa-1", "accept"), func(c *agentCase) { c.Verified = verified("pa-1") }),
		agentP("the second key of a rotating set verifies by its own kid",
			"A key set holds two keys during a rotation; the kid names the one that signed.",
			withKid(iss2, "v-2"), "pa-2", "accept"),
		agentP("an audience array that names this resource is accepted",
			"RFC 9068 allows aud to be an array; one naming this resource is for it.",
			tok(map[string]any{"aud": []any{"https://other.acme.example", atAud}}), "pa-3", "accept"),
		with(agent("twenty-nine seconds past exp is inside the leeway",
			"Two hosts' clocks drift; a refusal in the second a token turns over is an outage.",
			good, dpopProof(t, holder, expiredAt-1, "POST", atURL, "pa-4", good), "accept"),
			func(c *agentCase) { c.Now = expiredAt - 1 }),
		agentP("an iat exactly the leeway ahead is accepted",
			"The leeway applies to a fast issuer clock as well as a slow door.",
			mintAgent(t, iss1, "v-1", AgentTokenTyp, claims(N+leeway, nil)), "pa-5", "accept"),
		with(agentP("a query string on the request is not a different request",
			"htu is the request URI without its query (RFC 9449 4.3).",
			good, "pa-6", "accept"), func(c *agentCase) { c.URL = atURL + "?trace=1" }),
		agentP("a revocation naming another agent does not refuse this one",
			"The negative control for the revocation cases: a hook that refused everything would pass them.",
			good, "pa-7", "accept"),

		agentP("typ JWT is not an agent token",
			"typ decides, both ways: a delegation token or an ID-JAG is never an agent token.",
			mintAgent(t, iss1, "v-1", "JWT", claims(N, nil)), "pb-1", "malformed"),
		agentP("a token with no typ is not an agent token",
			"An absent typ is not at+jwt.",
			mintAgent(t, iss1, "v-1", "", claims(N, nil)), "pb-2", "malformed"),
		agentP("the long media type application/at+jwt is not accepted",
			"Both verifiers compare the short form exactly, which is what vouchryx mints. RFC 9068 2.1 also allows the long form; accepting it is a decision for both languages at once.",
			mintAgent(t, iss1, "v-1", "application/at+jwt", claims(N, nil)), "pb-3", "malformed"),
		{Name: "an agent token is not a delegation", Verifier: "delegation", Now: N, JWS: good, DPoP: pf(good, "pb-4"), Expect: "malformed",
			Why: "The delegation verifier refuses typ at+jwt, so an agent token is never read as a chain of one."},
		{Name: "an at+jwt token carrying a chain is not a delegation", Verifier: "delegation", Now: N, JWS: chained, DPoP: pf(chained, "pb-5"), Expect: "malformed",
			Why: "The shape the typ rule exists for: a delegation's claims under the agent token's typ."},
		{Name: "a delegation typed JWT still verifies as a delegation", Verifier: "delegation", Now: N, JWS: plain, DPoP: pf(plain, "pb-6"), Expect: "accept",
			Why: "The control for the two cases above: the typ rule refuses one typ, not every delegation."},
		agentP("a token with no kid is malformed",
			"No kid, no key: there is nothing to match, and trying every key would make one compromised key a skeleton key.",
			signCompact(t, iss1, map[string]any{"alg": "ES256", "typ": AgentTokenTyp}, claims(N, nil)), "pc-1", "malformed"),
		agentP("a kid no key in the set has is refused",
			"The kid names one key; a kid naming none verifies nothing.",
			withKid(iss2, "v-9"), "pc-2", "bad_signature"),
		agentP("a token signed by a key other than the one its kid names is refused",
			"The second key of the set signs, the token names the first.",
			withKid(iss2, "v-1"), "pc-3", "bad_signature"),
		agentP("a token signed by a key outside the set is refused",
			"A stranger's key under the issuer's kid.",
			withKid(stranger, "v-1"), "pc-4", "bad_signature"),
		agentP("HS256 with the issuer's public key as the secret is refused",
			"The classic algorithm confusion: the algorithm comes from the key type, never from the header.",
			signHS256(t, []byte(keys["TEST_ONLY_issuer_v1"].X+keys["TEST_ONLY_issuer_v1"].Y), header("HS256"), claims(N, nil)),
			"pc-5", "bad_signature"),
		agentP("ES384 over a P-256 key is refused",
			"An algorithm name means one curve; a P-256 key does not verify under ES384.",
			signCompact(t, iss1, header("ES384"), claims(N, nil)), "pc-7", "bad_signature"),

		agentP("a token from another issuer is refused",
			"iss is exact.",
			tok(map[string]any{"iss": "https://vouchryx.evil.example"}), "pd-1", "issuer"),
		agentP("an issuer with a trailing slash is refused",
			"Exact means exact: no normalisation of iss.",
			tok(map[string]any{"iss": atIss + "/"}), "pd-2", "issuer"),
		with(agentP("an issuer written as an array is refused",
			"iss is one string. RFC 7519 4.1.1 defines it as a single StringOrURI.",
			tok(map[string]any{"iss": []any{atIss}}), "pd-3", "issuer"),
			func(c *agentCase) {
				c.Divergence = &divergence{Tokenfuse: "accept",
					Why: "jsonwebtoken 10.4.0 validation.rs:317-329 accepts an issuer array that intersects the configured issuer; tokenfuse passes its validation through decode_claims."}
			}),

		agentP("a token for another resource is refused",
			"aud is required and exact.",
			tok(map[string]any{"aud": "https://other.acme.example"}), "pe-1", "audience"),
		agentP("a token for a prefix of this resource is refused",
			"A prefix match is how a service ends up trusting a neighbour.",
			tok(map[string]any{"aud": "https://tokenfuse.acme.exampl"}), "pe-2", "audience"),
		agentP("a token for this resource with more after it is refused",
			"The other direction of a prefix match.",
			tok(map[string]any{"aud": atAud + ".evil"}), "pe-3", "audience"),
		agentP("an audience array that does not name this resource is refused",
			"An array is accepted only when it names this resource.",
			tok(map[string]any{"aud": []any{"https://other.acme.example"}}), "pe-4", "audience"),
		with(agentP("a token with no audience is refused",
			"Required means present: a token minted for no resource is not minted for this one.",
			tok(map[string]any{"aud": nil}), "pe-5", "audience"),
			func(c *agentCase) {
				c.Divergence = &divergence{Tokenfuse: "accept",
					Why: "jsonwebtoken 10.4.0 validation.rs:334-357 checks aud only when the claim is present unless \"aud\" is a required spec claim, and decode_claims requires only exp and iss."}
			}),
		with(agentP("a door with no audience configured refuses a good token",
			"An empty configured audience refuses everything rather than accepting any resource.",
			good, "pe-6", "audience"), func(c *agentCase) { c.Audience = strp("") }),
		with(agentP("a door with no audience configured refuses a token for the empty audience",
			"The one token an empty configured audience could be read to match is still refused.",
			tok(map[string]any{"aud": ""}), "pe-7", "audience"), func(c *agentCase) { c.Audience = strp("") }),

		with(agent("thirty seconds past exp is expired",
			"The leeway's edge: now >= exp + 30 refuses.",
			good, dpopProof(t, holder, expiredAt, "POST", atURL, "pf-1", good), "expired"),
			func(c *agentCase) { c.Now = expiredAt }),
		agentP("an iat thirty-one seconds ahead is not yet valid",
			"Past the leeway a token from the future is refused.",
			mintAgent(t, iss1, "v-1", AgentTokenTyp, claims(N+leeway+1, nil)), "pf-2", "not_yet_valid"),

		agentP("a sub that is a user is malformed",
			"An agent token names an agent.",
			tok(map[string]any{"sub": "user://acme/alice", "client_id": "user://acme/alice"}), "pg-1", "malformed"),
		agentP("a sub that names no agent after the scheme is malformed",
			"agent:// alone names nobody.",
			tok(map[string]any{"sub": "agent://", "client_id": "agent://"}), "pg-2", "malformed"),
		agentP("a client_id that is another agent is malformed",
			"RFC 9068 2.2: the agent is the client, so the two are one string.",
			tok(map[string]any{"client_id": "agent://acme/other"}), "pg-3", "malformed"),
		agentP("a token with no client_id is malformed",
			"client_id is required by RFC 9068 2.2.",
			tok(map[string]any{"client_id": nil}), "pg-4", "malformed"),
		agentP("a token with no jti is malformed",
			"jti is what revocation names a token by.",
			tok(map[string]any{"jti": nil}), "pg-5", "malformed"),
		agentP("a token with an act claim is malformed",
			"An agent token acts for nobody; a chain belongs to a delegation token.",
			tok(map[string]any{"act": map[string]any{"sub": "agent://acme/runbook"}}), "pg-6", "malformed"),

		agentP("a token with no cnf is not bound",
			"vouchryx binds everything it mints; an unbound token is from somewhere else.",
			tok(map[string]any{"cnf": nil}), "ph-1", "not_bound"),
		agentP("a token with an empty cnf.jkt is not bound",
			"An empty thumbprint binds to nothing.",
			tok(map[string]any{"cnf": map[string]any{"jkt": ""}}), "ph-2", "not_bound"),
		agent("a bound token with no proof is refused",
			"A sender-constrained token is never checked as a bearer token.",
			good, "", "no_proof"),
		agent("a stranger's proof is the wrong key",
			"The bytes of a stolen token are not enough.",
			good, dpopProof(t, thief, N, "POST", atURL, "pi-1", good), "wrong_key"),
		agent("a proof with no ath is the wrong key",
			"RFC 9449 4.2: a proof beside an access token names it.",
			good, dpopProof(t, holder, N, "POST", atURL, "pi-2", ""), "wrong_key"),
		agent("a proof naming another token of the same holder is the wrong key",
			"Without ath a proof binds a request to a key, not to a token.",
			good, dpopProof(t, holder, N, "POST", atURL, "pi-3", tok(map[string]any{"jti": "agent-tok-2"})), "wrong_key"),
		agent("a proof for another URL is the wrong key",
			"A proof is for one request.",
			good, dpopProof(t, holder, N, "POST", "https://tokenfuse.acme.example/v1/chat/completions", "pi-4", good), "wrong_key"),
		agent("a proof for another method is the wrong key",
			"A proof is for one request.",
			good, dpopProof(t, holder, N, "GET", atURL, "pi-5", good), "wrong_key"),
		agent("a proof sixty-one seconds old is the wrong key",
			"A proof is for one moment, within sixty seconds either way.",
			good, dpopProof(t, holder, N-61, "POST", atURL, "pi-6", good), "wrong_key"),
		agent("a proof whose jti is longer than 256 bytes is the wrong key",
			"A client chooses its jti and the replay cache stores it.",
			good, dpopProof(t, holder, N, "POST", atURL, strings.Repeat("j", maxProofJTIBytes+1), good), "wrong_key"),
		agent("a proof with no jti is the wrong key",
			"Without a jti nothing can make a proof single use.",
			good, dpopProof(t, holder, N, "POST", atURL, "", good), "wrong_key"),
		with(agent("a proof whose method is written in lower case is the wrong key",
			"RFC 9110 methods are case sensitive (agent-stack-go invariant 24).",
			good, dpopProof(t, holder, N, "post", atURL, "pi-7", good), "wrong_key"),
			func(c *agentCase) {
				c.Divergence = &divergence{Tokenfuse: "accept",
					Why: "crates/dpop/src/lib.rs verify_proof compares htm with eq_ignore_ascii_case."}
			}),
		with(agent("a proof whose host is written in upper case is the same request",
			"RFC 9449 4.3 applies RFC 3986 6.2.2.1: scheme and host compare without case (agent-stack-go invariant 24).",
			good, dpopProof(t, holder, N, "POST", "https://TOKENFUSE.ACME.EXAMPLE/v1/messages", "pi-8", good), "accept"),
			func(c *agentCase) {
				c.Divergence = &divergence{Tokenfuse: "wrong_key",
					Why: "crates/dpop/src/lib.rs verify_proof compares htu and the URL as strings, query trimmed, with no case fold of scheme or host."}
			}),

		with(agent("a token whose agent is revoked is refused",
			"Stopping one agent is one revocation naming it.",
			good, pf(good, "pj-1"), "revoked"), func(c *agentCase) { c.Revoke = &revokeSpec{Subject: atAgent} }),
		with(agentP("a token whose jti is revoked is refused",
			"A revocation may name one token.",
			good, "pj-2", "revoked"), func(c *agentCase) { c.Revoke = &revokeSpec{JTI: atJTI} }),
		with(agent("a revocation does not mask a stolen proof",
			"The hook is asked last, so a token failing its proof is refused for the proof.",
			good, dpopProof(t, thief, N, "POST", atURL, "pj-3", good), "wrong_key"),
			func(c *agentCase) { c.Revoke = &revokeSpec{Subject: atAgent} }),

		with(relayed("a relayed token verifies without a proof",
			"Another door of this deployment checked the proof; everything else is checked again.",
			good, "accept"), func(c *agentCase) { c.Verified = verified("") }),
		relayed("a relayed token with no cnf is not bound",
			"Relayed skips the proof, never the binding.",
			tok(map[string]any{"cnf": nil}), "not_bound"),
		with(relayed("a relayed token past its leeway is expired",
			"Relayed skips the proof, never the clock.",
			good, "expired"), func(c *agentCase) { c.Now = expiredAt }),
		relayed("a relayed token typed JWT is malformed",
			"Relayed skips the proof, never the typ.",
			mintAgent(t, iss1, "v-1", "JWT", claims(N, nil)), "malformed"),
		with(relayed("a relayed revoked token is refused",
			"Relayed skips the proof, never the revocation list.",
			good, "revoked"), func(c *agentCase) { c.Revoke = &revokeSpec{Subject: atAgent} }),
		with(relayed("a relayed token at a door with no audience is refused",
			"Relayed skips the proof, never the audience.",
			good, "audience"), func(c *agentCase) { c.Audience = strp("") }),
	}
	// The revocation control names somebody else.
	for i := range cases {
		if cases[i].Name == "a revocation naming another agent does not refuse this one" {
			cases[i].Revoke = &revokeSpec{Subject: "agent://acme/other", JTI: "agent-tok-9"}
		}
	}

	win := int64(Window / time.Second)
	gen := int64(replayGeneration / time.Second)
	replay := []replaySequence{
		{Name: "a second use of one jti is refused", Why: "A proof is single use inside its window.", Cap: 16,
			Steps: []replayStep{{"j1", 1_000, "ok"}, {"j1", 1_000, "seen"}, {"j1", 1_010, "seen"}}},
		{Name: "distinct jtis are all admitted", Why: "The negative control: a cache that refused everything would pass the case above.", Cap: 16,
			Steps: func() []replayStep {
				var s []replayStep
				for _, j := range []string{"j0", "j1", "j2", "j3", "j4", "j5", "j6", "j7", "j8", "j9"} {
					s = append(s, replayStep{j, 1_000, "ok"})
				}
				return s
			}()},
		{Name: "a jti survives every moment a proof carrying it could still be fresh", Cap: 16,
			Why:   "A proof's iat may sit a window ahead of now and now a window past iat, so a generation is two windows.",
			Steps: []replayStep{{"j1", 1_000_000, "ok"}, {"j1", 1_000_000 + 2*win, "seen"}, {"j1", 1_000_000 + 8*win, "ok"}}},
		{Name: "a jti recorded in the last second of a generation outlives the next one", Cap: 16,
			Why: "The rotation boundary: the previous generation is consulted for a whole generation more.",
			Steps: []replayStep{{"j0", 1_000_000, "ok"}, {"late", 1_000_000 + gen - 1, "ok"},
				{"late", 1_000_000 + gen, "seen"}, {"late", 1_000_000 + gen - 1 + 2*win, "seen"}}},
		{Name: "a full cache refuses rather than forgetting", Cap: 2,
			Why: "Forgetting under pressure is a replay guard that stops guarding exactly when somebody pushes on it.",
			Steps: []replayStep{{"j1", 1_000, "ok"}, {"j2", 1_000, "ok"}, {"j3", 1_000, "full"}, {"j1", 1_000, "seen"},
				{"j3", 1_000 + gen, "ok"}, {"j1", 1_000 + gen, "seen"}}},
		{Name: "a clock that walks backwards does not empty the cache", Cap: 16,
			Why:   "A start time that only moves forward: stepping a clock back never rotates the generations.",
			Steps: []replayStep{{"j1", 1_000_000, "ok"}, {"j1", 1_000_000 - 10*win, "seen"}, {"j1", 1_000_000 + win, "seen"}}},
	}

	return agentVectors{
		Source: agentVectorsSource,
		WhySource: "The canonical copy lives at the path above. Every other language VENDORS this file byte for byte and is found by this field " +
			"rather than by a list somebody maintains (estate-gates C14).",
		Comment: "Cross-language vectors for an agent's own access token (RFC 9068, typ at+jwt, DPoP-bound by RFC 9449), as vouchryx's " +
			"client_credentials grant mints it. Every verifier (Go: this repository's delegation.VerifyAccess, VerifyRelayedAccess and Verify; " +
			"Rust: tokenfuse's crates/delegation verify_agent_token, verify_relayed_agent_token and verify_delegation) MUST answer each case as " +
			"stated. A case is fixed bytes: `jws` is the token, `dpop` the proof (absent means no proof), `now` the verifier's clock in Unix " +
			"seconds. `verifier` is `agent` (the token and its proof, with a fresh replay cache), `relayed` (the token alone, no proof) or " +
			"`delegation` (the delegation-chain verifier, which must refuse typ at+jwt). `method`, `url` and `audience` override `config` when " +
			"present, and an `audience` of \"\" is a door with none configured. `revoke` is the revocation hook: it answers true for a call naming " +
			"its `jti` or its `subject`, and false for anything else or when absent. `expect` is `accept` or the refusal, named in tokenfuse's " +
			"Refusal vocabulary snake_cased; `verified` is what an accepted agent token yields. A `known_divergence` records, from source " +
			"reading, a verifier that does not yet answer as stated. `replay` holds sequences for the proof replay cache: one cache of `cap` " +
			"per sequence, each step a jti recorded at `now`. The keys under `test_only_keys` exist for this table alone and sign nothing else.",
		Outcomes: map[string]string{
			"accept":        "Verified.",
			"malformed":     "Not this kind of token: wrong or absent typ, no kid, or claims an agent token never carries or always carries.",
			"bad_signature": "No key in the set verifies it: an unknown kid, another key's signature, or an algorithm the key type does not permit.",
			"issuer":        "iss is not exactly the configured issuer.",
			"audience":      "aud does not name the configured audience, or none is configured.",
			"expired":       "now >= exp + leeway_secs.",
			"not_yet_valid": "iat > now + leeway_secs.",
			"not_bound":     "No cnf.jkt: a bearer token.",
			"no_proof":      "A bound token presented with no proof.",
			"wrong_key":     "The proof fails, is by another key, or does not name this token in ath.",
			"revoked":       "The revocation hook named the token's jti or its agent.",
		},
		ReplayAnswer: map[string]string{
			"ok":   "Recorded as used.",
			"seen": "Used before inside the window.",
			"full": "The current generation is at its cap; nothing is forgotten to make room.",
		},
		NotHere: []string{
			"Shapes both verifiers refuse under different internal names, so a case would test a library's error mapping rather than a rule:",
			"a header with alg none or no alg (Rust: malformed, its header parser knows no such algorithm; Go: bad_signature);",
			"a token with no iss or no exp, or a claim of the wrong JSON type (Rust: bad_signature, from deserialization; Go: issuer, expired or the rule the claim feeds);",
			"a JSON member repeated (Rust refuses it in deserialization; Go keeps the last) and dates written as fractions.",
			"All of these are signed bytes only the issuer can produce.",
		},
		Constants: vectorConstants{
			Typ:                  AgentTokenTyp,
			LeewaySecs:           int64(AgentTokenLeeway / time.Second),
			ProofWindowSecs:      int64(Window / time.Second),
			MaxProofJTIBytes:     maxProofJTIBytes,
			ReplayGenerationSecs: int64(replayGeneration / time.Second),
		},
		TestOnlyKeys: keys,
		Config: vectorConfig{
			Issuer: atIss, Audience: atAud, Method: "POST", URL: atURL, JWKS: rawJWKS,
		},
		Cases:  cases,
		Replay: replay,
	}
}
