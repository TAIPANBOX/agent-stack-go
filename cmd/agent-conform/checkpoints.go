package main

// The checkpoint side of `agent-conform watch-dir` (SPEC 6.5.1).
//
// A producer that signs its stream writes a sidecar beside it, in a directory
// the operator names with -checkpoints. This file reads the keys the verifier
// trusts (-checkpoint-keys), reads each stream's sidecar, and asks the library
// whether every record still holds: the bytes through its count, the head, the
// chain, the signature. A record that does not hold is a refusal, and so is a
// stream shorter than a record counts, which is a truncation.
//
// The keys are a file for now: a JSON object from kid to the EC P-256 public key,
// and a kid must be the RFC 7638 thumbprint of its key, so a key cannot be filed
// under a name it does not carry. Key statements from the custody service replace
// the file, and their format is that service's to define (keyryx, design K3).

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// maxKeysBytes bounds the keys file.
const maxKeysBytes = 64 << 10

// loadCheckpointKeys reads the keys file. It refuses an empty set: a verifier that
// holds no key can check nothing, and reporting success over that is a pass that
// measured nothing.
func loadCheckpointKeys(path string) (map[string]*ecdsa.PublicKey, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own flag
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeysBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeysBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxKeysBytes)
	}
	var doc map[string]struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("not a JSON object of keys: %w", err)
	}
	if len(doc) == 0 {
		return nil, errors.New("holds no key, so no signature could be checked")
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc))
	for kid, j := range doc {
		if j.Crv != "P-256" || j.Kty != "EC" {
			return nil, fmt.Errorf("key %q is not an EC P-256 key", kid)
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil || len(x) != 32 {
			return nil, fmt.Errorf("key %q: x is not 32 bytes of base64url", kid)
		}
		y, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil || len(y) != 32 {
			return nil, fmt.Errorf("key %q: y is not 32 bytes of base64url", kid)
		}
		// ecdh validates the point is on the curve; ecdsa does not.
		if _, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...)); err != nil {
			return nil, fmt.Errorf("key %q is not a point on P-256", kid)
		}
		if thumb := rfc7638P256(j.X, j.Y); thumb != kid {
			return nil, fmt.Errorf("key %q is not the RFC 7638 thumbprint of its own x and y (%s)", kid, thumb)
		}
		keys[kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	return keys, nil
}

// rfc7638P256 is the RFC 7638 thumbprint of an EC P-256 key. The members are
// written in the order the thumbprint requires, and x and y are base64url, which
// needs no escaping.
func rfc7638P256(x, y string) string {
	in := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(in))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkStreamCheckpoints verifies the sidecar of one stream in ckDir against the
// stream itself, read read-only and bounded. present is false when the stream has
// no sidecar, which is a note and not a failure. A sidecar with no record, or a
// stream larger than the byte cap, is an error: nothing was checked.
func checkStreamCheckpoints(s stream, ckDir string, keys map[string]*ecdsa.PublicKey, maxFile int64) (rep event.CheckpointReport, present bool, err error) {
	side := filepath.Join(ckDir, event.CheckpointFileName(s.name))
	sf, err := os.Open(side) // #nosec G304 -- the operator's own directory, named by a flag
	if errors.Is(err, os.ErrNotExist) {
		return rep, false, nil
	}
	if err != nil {
		return rep, false, err
	}
	defer sf.Close()
	if st, err := sf.Stat(); err != nil || !st.Mode().IsRegular() {
		return rep, true, errors.New("the sidecar is not a regular file")
	}
	capSide := &byteCapReader{r: sf, max: maxFile}

	stf, err := os.Open(s.path) // #nosec G304 -- listed and checked regular by the walk
	if err != nil {
		return rep, true, err
	}
	defer stf.Close()
	capStream := &byteCapReader{r: stf, max: maxFile}

	lookup := func(kid string) (*ecdsa.PublicKey, bool) {
		k, ok := keys[kid]
		return k, ok
	}
	rep, err = event.VerifyCheckpoints(capStream, capSide, s.name, lookup)
	if err != nil {
		return rep, true, err
	}
	if capStream.truncated || capSide.truncated {
		return rep, true, fmt.Errorf("larger than the %d-byte file cap, so it was not checked to its end", maxFile)
	}
	return rep, true, nil
}

// explainedBy reports whether a restart after line `after` is explained by a
// valid resume checkpoint naming that line.
func explainedBy(resumes []int, after int) bool {
	if after <= 0 {
		return false
	}
	for _, c := range resumes {
		if c == after {
			return true
		}
	}
	return false
}
