// Package keyclient is the consumer side of Keyryx, the key custody service of
// the estate. A consumer uses it for three things, all off the request path:
//
//   - a delegated key: an ES256 or ES384 key this process generates, which
//     custody certifies for this consumer and name. The consumer renews it at
//     half its life and signs locally, but only while its statement is valid;
//   - a held key: signed by custody on request (POST .../sign), so the private
//     key never leaves custody;
//   - the published key set of a name (GET /v1/jwks/{name}), polled and cached
//     so that delegation.Verify can check tokens with what the process holds.
//
// Nothing here runs per token or per decision. Reading a cached key set and
// signing with a delegated key touch memory only. Custody is called on the
// caller's schedule (Run) or at human rate (a held sign).
//
// The package is standard library only (CLAUDE.md invariant 1), and nothing in
// delegation imports it (invariant 31): verification stays a function of what
// the process already holds.
package keyclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Credential says how this process proves to custody which consumer it is
// (D1 b in the Keyryx design). Exactly one field is set. Custody answers only
// for the consumer the policy binds to that credential, so nothing here
// chooses between the two.
type Credential struct {
	// Socket is the unix socket custody gave this consumer. Custody names the
	// consumer by the socket a connection arrives on, so no secret is sent.
	Socket string
	// BearerFile is a file holding the consumer's key (stack-up) or its Kubernetes
	// projected service-account token (stack-k8s, audience keyryx). It is read on
	// every request, so a rotated token or key file is picked up without a restart.
	BearerFile string
}

// Config is what New needs.
type Config struct {
	// BaseURL is the custody API, for example http://keyryx:4340. Over a socket
	// it is only a host name for the request line, so http://keyryx does.
	BaseURL string
	// Consumer is the consumer name custody's policy grants keys to. It is part
	// of every delegation proof, so it must be the name the credential resolves to.
	Consumer string
	// Credential is how the consumer identifies itself.
	Credential Credential
	// Now is the clock. Nil means time.Now. Tests inject one; a process does not.
	Now func() time.Time
}

// StatusError is a refusal from custody. Its reason stays in custody's log; the
// status is all this error carries, and never the credential.
type StatusError struct {
	Route string
	Code  int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("keyclient: custody refused %s with status %d", e.Route, e.Code)
}

// Signature is what a sign produced: the algorithm, the key id that signed it,
// and the raw signature (R||S for the ECDSA algorithms).
type Signature struct {
	Alg string
	Kid string
	Sig []byte
}

// ErrNoValidKey means no delegated key of the name is valid at the clock's
// time: none has started, or the last one has run out. Signing fails closed.
var ErrNoValidKey = errors.New("keyclient: no delegated key is valid now")

// Client talks to one custody service as one consumer.
type Client struct {
	base     string
	consumer string
	cred     Credential
	hc       *http.Client
	now      func() time.Time
}

// New checks the configuration and returns a client. A configuration with both
// credentials, with neither, or with a relative socket path is refused, and the
// refusal happens before any request.
func New(cfg Config) (*Client, error) {
	if !nameRe.MatchString(cfg.Consumer) {
		return nil, errors.New("keyclient: the consumer name is outside custody's name grammar")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("keyclient: the base URL must be an http or https origin with no path or query")
	}
	socket, bearerFile := cfg.Credential.Socket, cfg.Credential.BearerFile
	switch {
	case socket != "" && bearerFile != "":
		return nil, errors.New("keyclient: name one credential, a socket or a key file, not both")
	case socket == "" && bearerFile == "":
		return nil, errors.New("keyclient: no credential is named, and a client never runs without one")
	case socket != "" && !filepath.IsAbs(socket):
		return nil, errors.New("keyclient: the socket path must be absolute")
	}
	tr := &http.Transport{Proxy: nil} // a proxy would see the credential, so none is used
	if socket != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base:     strings.TrimRight(cfg.BaseURL, "/"),
		consumer: cfg.Consumer,
		cred:     cfg.Credential,
		now:      now,
		hc: &http.Client{
			Timeout:   requestTimeout,
			Transport: tr,
			// Custody never redirects. Following one would send the credential
			// to whatever host the redirect names, so the redirect is the answer.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// do makes one call to custody. A non-200 answer is a StatusError, and the
// body of a refusal is not read into the error: the reason is custody's to log.
func (c *Client) do(ctx context.Context, method, route string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+route, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cred.BearerFile != "" {
		tok, err := c.bearer()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("keyclient: %s: %w", route, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("keyclient: reading the answer to %s: %w", route, err)
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("keyclient: the answer to %s is over its size cap", route)
	}
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Route: route, Code: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("keyclient: the answer to %s is not of the known shape: %w", route, err)
	}
	return nil
}

// bearer reads the credential file as it is now. It is read on every request
// so that a rotated Kubernetes projected token or key file is used at once. A
// file that is empty or holds more than one word is refused, and the error does
// not say what the file held.
func (c *Client) bearer() (string, error) {
	b, err := os.ReadFile(c.cred.BearerFile)
	if err != nil {
		return "", fmt.Errorf("keyclient: reading the credential file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return "", errors.New("keyclient: the credential file is empty or holds more than one word")
	}
	return tok, nil
}

// Sign asks custody to sign msg with the held key name. purpose is recorded in
// custody's use log, so it names the job the signature is for (a short token,
// such as "checkpoint"). Custody refuses a message over its size cap.
func (c *Client) Sign(ctx context.Context, name string, msg []byte, purpose string) (Signature, error) {
	if !nameRe.MatchString(name) || !purposeRe.MatchString(purpose) || len(msg) == 0 {
		return Signature{}, errors.New("keyclient: the key name, the purpose or the message is refused before any request")
	}
	in := struct {
		Statement string `json:"statement_b64"`
		Purpose   string `json:"purpose"`
	}{base64.StdEncoding.EncodeToString(msg), purpose}
	var out struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Sig string `json:"signature_b64"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/keys/"+name+"/sign", in, &out); err != nil {
		return Signature{}, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(out.Sig)
	if err != nil || out.Alg == "" || out.Kid == "" || len(sig) == 0 {
		return Signature{}, errors.New("keyclient: custody's signature answer is not of the known shape")
	}
	return Signature{Alg: out.Alg, Kid: out.Kid, Sig: sig}, nil
}

// nameRe is custody's name grammar (internal/policy): a key name, a consumer
// name, a key set name.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// purposeRe is the grammar custody holds a sign's purpose to.
var purposeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// maxResponse bounds what this client reads from custody in one answer.
const maxResponse = 256 << 10

// requestTimeout bounds one call to custody.
const requestTimeout = 10 * time.Second
