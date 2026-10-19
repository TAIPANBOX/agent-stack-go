package keyclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// clock is the test's time. Every component reads it through Config.Now, so a
// statement's life and a half-life pass without a sleep.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// stubCustody answers the custody routes the way Keyryx does, as far as this
// client needs: a challenge, a delegate that checks the proof of possession by
// its own construction of the proof input, a held sign, and a published key
// set. It keeps every switch a test needs to make it refuse or misbehave.
type stubCustody struct {
	t     *testing.T
	clock *clock
	srv   *httptest.Server

	mu         sync.Mutex
	requests   int
	delegates  int
	challenges map[string]string
	heldKey    *ecdsa.PrivateKey
	heldKid    string
	signCalls  []signCall
	jwksKeys   []delegation.JWK
	jwksRaw    []byte
	nextAhead  time.Duration
	refuse     int // when not zero, every delegate answers this status
	wrongKid   bool
	wrongLife  bool
	wrongOwner bool
	tamper     func(claims map[string]any)
	expectAuth string // the bearer the client must send; "" means no header
	redirectTo string
}

type signCall struct {
	msg     []byte
	purpose string
}

func newStubCustody(t *testing.T, clk *clock) *stubCustody {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &stubCustody{t: t, clock: clk, challenges: map[string]string{}, heldKey: k}
	pub := delegation.FromPublic(&k.PublicKey, "")
	s.heldKid, _ = delegation.Thumbprint(pub)
	s.srv = httptest.NewServer(s.handler())
	t.Cleanup(s.srv.Close)
	return s
}

// handler is the stub's mux, with the request counter in front of it.
func (s *stubCustody) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys/{name}/challenge", s.challenge)
	mux.HandleFunc("POST /v1/keys/{name}/delegate", s.delegate)
	mux.HandleFunc("POST /v1/keys/{name}/sign", s.sign)
	mux.HandleFunc("GET /v1/jwks/{name}", s.jwks)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		s.mu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

func (s *stubCustody) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *stubCustody) delegateCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delegates
}

// authOK refuses a request whose bearer is not the one the test expects, the
// way custody refuses a credential that resolves to nobody.
func (s *stubCustody) authOK(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	want := s.expectAuth
	s.mu.Unlock()
	got := r.Header.Get("Authorization")
	if want == "" && got == "" {
		return true
	}
	if got != "Bearer "+want {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *stubCustody) redirectIfSet(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	to := s.redirectTo
	s.mu.Unlock()
	if to == "" {
		return false
	}
	http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	return true
}

func (s *stubCustody) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(w, r) || s.redirectIfSet(w, r) {
		return
	}
	name := r.PathValue("name")
	c := randomString(s.t, 24)
	s.mu.Lock()
	s.challenges[name+"\x00"+c] = c
	s.mu.Unlock()
	writeJSONTest(w, map[string]any{"challenge": c, "expires_at": s.clock.Now().Add(time.Minute).Unix()})
}

// delegate checks the proof of possession under the input custody builds, then
// issues a statement: an ES384 and an ML-DSA half are stood in for by placeholder
// signatures, which the client does not verify (that is custody's own check).
func (s *stubCustody) delegate(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(w, r) || s.redirectIfSet(w, r) {
		return
	}
	s.mu.Lock()
	s.delegates++
	refuse, wrongKid, wrongLife, wrongOwner, ahead := s.refuse, s.wrongKid, s.wrongLife, s.wrongOwner, s.nextAhead
	s.nextAhead = 0
	s.mu.Unlock()
	if refuse != 0 {
		http.Error(w, "refused", refuse)
		return
	}
	name := r.PathValue("name")
	var req struct {
		JWK       delegation.JWK `json:"jwk"`
		Challenge string         `json:"challenge"`
		Proof     string         `json:"proof_b64"`
		Lifetime  int64          `json:"lifetime_s"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	issued := s.challenges[name+"\x00"+req.Challenge]
	delete(s.challenges, name+"\x00"+req.Challenge)
	s.mu.Unlock()
	if issued == "" {
		http.Error(w, "no challenge", http.StatusForbidden)
		return
	}
	pub, err := publicOf(req.JWK)
	if err != nil {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	// The proof input, as custody builds it: a domain separator and then the
	// name, the consumer, the key's kid and the challenge, each ended by a NUL.
	input := []byte("keyryx/delegate/v1\x00" + name + "\x00" + consumerName + "\x00" + req.JWK.Kid + "\x00" + req.Challenge)
	sig, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || !verifyRaw(pub, stubDigest(req.JWK.Alg, input), sig) {
		http.Error(w, "proof", http.StatusForbidden)
		return
	}
	kid := req.JWK.Kid
	if wrongKid {
		kid = "someone-else-kid"
	}
	now := s.clock.Now()
	notBefore := now.Add(ahead)
	notAfter := notBefore.Add(time.Duration(req.Lifetime) * time.Second)
	if wrongLife {
		notAfter = notAfter.Add(time.Minute)
	}
	owner := consumerName
	if wrongOwner {
		owner = "someone-else"
	}
	claims := map[string]any{
		"v": 1, "iss": "keyryx", "name": name, "owner": owner, "kid": kid,
		"jwk": map[string]any{"kty": "EC", "crv": req.JWK.Crv, "x": req.JWK.X, "y": req.JWK.Y,
			"kid": req.JWK.Kid, "alg": req.JWK.Alg, "use": "sig"},
		"not_before": notBefore.Unix(), "not_after": notAfter.Unix(), "issued_at": now.Unix(),
		"jti":   randomString(s.t, 16),
		"roots": map[string]any{"ES384": "root-es384", "ML-DSA-65": "root-mldsa"},
	}
	s.mu.Lock()
	tamper := s.tamper
	s.mu.Unlock()
	if tamper != nil {
		tamper(claims)
	}
	payload, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(payload)
	statement := map[string]any{"payload": p, "signatures": []any{
		map[string]any{"protected": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES384"}`)), "signature": base64.RawURLEncoding.EncodeToString([]byte("stub-es384"))},
		map[string]any{"protected": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ML-DSA-65"}`)), "signature": base64.RawURLEncoding.EncodeToString([]byte("stub-mldsa"))},
	}}
	writeJSONTest(w, map[string]any{"statement": statement, "kid": kid,
		"not_before": notBefore.Unix(), "not_after": notAfter.Unix()})
}

// consumerName is the consumer every stub test runs as.
const consumerName = "tokenfuse-gateway"

func (s *stubCustody) sign(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(w, r) || s.redirectIfSet(w, r) {
		return
	}
	var req struct {
		Statement string `json:"statement_b64"`
		Purpose   string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	msg, err := base64.StdEncoding.DecodeString(req.Statement)
	if err != nil {
		http.Error(w, "bad base64", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.signCalls = append(s.signCalls, signCall{msg: msg, purpose: req.Purpose})
	s.mu.Unlock()
	sum := sha256.Sum256(msg)
	sig := rawSign(s.t, s.heldKey, sum[:])
	writeJSONTest(w, map[string]any{"alg": "ES256", "kid": s.heldKid,
		"signature_b64": base64.StdEncoding.EncodeToString(sig)})
}

func (s *stubCustody) jwks(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	raw, keys := s.jwksRaw, s.jwksKeys
	s.mu.Unlock()
	if raw != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}
	writeJSONTest(w, map[string]any{"keys": keys})
}

func (s *stubCustody) setJWKS(keys ...delegation.JWK) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksKeys = keys
	s.jwksRaw = nil
}

func (s *stubCustody) setRaw(raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksRaw = []byte(raw)
}

func (s *stubCustody) setBearer(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectAuth = token
}

func (s *stubCustody) setRefuse(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = code
}

func (s *stubCustody) setWrongKid(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrongKid = on
}

func (s *stubCustody) setWrongOwner(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrongOwner = on
}

func (s *stubCustody) setTamper(f func(map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamper = f
}

func (s *stubCustody) setWrongLife(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrongLife = on
}

func (s *stubCustody) setAhead(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAhead = d
}

func (s *stubCustody) setRedirect(to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectTo = to
}

func (s *stubCustody) signs() []signCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]signCall(nil), s.signCalls...)
}

// publicOf reads a JWK's point as an ECDSA public key, refusing a point that is
// not on its curve.
func publicOf(j delegation.JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("curve %q", j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, err
	}
	point := append(append([]byte{4}, x...), y...)
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}

func stubDigest(alg string, b []byte) []byte {
	if alg == "ES384" {
		d := sha512.Sum384(b)
		return d[:]
	}
	d := sha256.Sum256(b)
	return d[:]
}

// rawSign is an ECDSA signature as R||S, each half padded to the curve size.
func rawSign(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	return append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
}

func verifyRaw(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return false
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, digest, r, s)
}

func randomString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSONTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newKey makes a key of the given curve and returns it with its JWK and kid.
func newKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, delegation.JWK) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := delegation.FromPublic(&k.PublicKey, "")
	kid, err := delegation.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = kid
	return k, j
}

// bodyOf renders a set as custody publishes it, for a test that serves raw bodies.
func bodyOf(keys ...delegation.JWK) string {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return string(b)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
