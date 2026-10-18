package keyclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

// JWKS is the key set a name publishes at GET /v1/jwks/{name}, cached in memory.
// Refresh talks to custody. Set, Lookup and Fetched never do, so a verifier
// reads its keys with no call that could fail.
type JWKS struct {
	c    *Client
	name string

	mu      sync.RWMutex
	set     delegation.Set
	byKid   map[string]delegation.JWK
	fetched time.Time
}

// JWKS returns the cache for the key set of name: a delegated name, or the
// delegation root.
func (c *Client) JWKS(name string) (*JWKS, error) {
	if !nameRe.MatchString(name) {
		return nil, errors.New("keyclient: the key set name is outside custody's name grammar")
	}
	return &JWKS{c: c, name: name, byKid: map[string]delegation.JWK{}}, nil
}

// Refresh fetches the set and installs it when every key in it is well formed.
// Anything else (a set with no keys member, a key id repeated, a key that is not
// EC, a point off its curve, a kid that is not the key's thumbprint) is refused
// whole, and the cache keeps what it held. An empty set is installed: a name
// that publishes nothing verifies nothing.
func (j *JWKS) Refresh(ctx context.Context) error {
	var out struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := j.c.do(ctx, http.MethodGet, "/v1/jwks/"+j.name, nil, &out); err != nil {
		return err
	}
	if len(out.Keys) == 0 || bytes.Equal(bytes.TrimSpace(out.Keys), []byte("null")) {
		return errors.New("keyclient: the key set has no keys member, so it is not read as an empty one")
	}
	var keys []delegation.JWK
	if err := json.Unmarshal(out.Keys, &keys); err != nil {
		return errors.New("keyclient: the key set's keys are not of the known shape")
	}
	set, byKid, err := checkSet(keys)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.set = set
	j.byKid = byKid
	j.fetched = j.c.now()
	return nil
}

// checkSet refuses the whole of a set if any one key is not one a verifier can
// use, and returns the set and an index by kid.
func checkSet(keys []delegation.JWK) (delegation.Set, map[string]delegation.JWK, error) {
	byKid := make(map[string]delegation.JWK, len(keys))
	for _, k := range keys {
		var curve elliptic.Curve
		var size int
		var alg string
		switch k.Crv {
		case "P-256":
			curve, size, alg = elliptic.P256(), 32, "ES256"
		case "P-384":
			curve, size, alg = elliptic.P384(), 48, "ES384"
		default:
			return delegation.Set{}, nil, fmt.Errorf("keyclient: a key of curve %q is not one this client verifies", k.Crv)
		}
		if k.Kty != "EC" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != alg) {
			return delegation.Set{}, nil, errors.New("keyclient: a key in the set is not an EC signing key of its curve")
		}
		if k.Kid == "" {
			return delegation.Set{}, nil, errors.New("keyclient: a key in the set has no kid")
		}
		x, errX := base64.RawURLEncoding.Strict().DecodeString(k.X)
		y, errY := base64.RawURLEncoding.Strict().DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != size || len(y) != size {
			return delegation.Set{}, nil, errors.New("keyclient: a key's coordinates are not the size of its curve")
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...)); err != nil {
			return delegation.Set{}, nil, errors.New("keyclient: a key is not a point on its curve")
		}
		thumb, err := delegation.Thumbprint(k)
		if err != nil || thumb != k.Kid {
			return delegation.Set{}, nil, errors.New("keyclient: a key's kid is not its RFC 7638 thumbprint")
		}
		if _, dup := byKid[k.Kid]; dup {
			return delegation.Set{}, nil, errors.New("keyclient: a key id appears twice in the set")
		}
		byKid[k.Kid] = k
	}
	return delegation.Set{Keys: slices.Clone(keys)}, byKid, nil
}

// Set returns the cached keys for delegation.Options.Keys. It never fetches.
func (j *JWKS) Set() delegation.Set {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return delegation.Set{Keys: slices.Clone(j.set.Keys)}
}

// Lookup returns the cached key with kid. A kid the cache never installed is
// delegation.ErrUnknownKid, whatever custody says now: a cache that fell back to
// some other key here would verify a token nobody certified.
func (j *JWKS) Lookup(kid string) (delegation.JWK, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if kid == "" {
		return delegation.JWK{}, delegation.ErrNoKid
	}
	k, ok := j.byKid[kid]
	if !ok {
		return delegation.JWK{}, delegation.ErrUnknownKid
	}
	return k, nil
}

// Fetched is when the cache last installed a set, zero if it never has.
func (j *JWKS) Fetched() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.fetched
}

// Run refreshes the cache every interval until ctx is done, starting now. Each
// failed refresh is reported to onErr when that is not nil. An interval under
// one second is refused, and reported as the only thing Run does.
func (j *JWKS) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	if every < time.Second {
		if onErr != nil {
			onErr(errors.New("keyclient: the poll interval is under one second"))
		}
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if err := j.Refresh(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
