// Package passport defines the shared Agent Passport wire type
// (taipanbox.dev/agent-passport/v0.1) and the agent:// / user:// URI helpers
// used across the TAIPANBOX agent-governance stack.
//
// A Passport is a small, static JSON document describing one agent: its
// identity, owning team, runtime, static provisioning parent, and
// attestation posture. It is metadata, not a token: nothing at runtime
// depends on fetching it.
//
// This package is a public mirror of Idryx's internal ingest/passport
// package. Idryx's types live under internal/ and cannot be imported by
// sibling services (Wardryx, Mockryx, and others), so this module is the
// single importable source of the wire contract.
package passport

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Passport schema versions this package accepts (agent-passport SPEC 6.4.1).
//
// SchemaV10 is v0.1 with the document's top level closed: a key the schema
// never named does not validate, so Parse refuses one under v1.0 with
// ErrUnknownField. SchemaV01 stays accepted, and keeps tolerating such a key,
// by decision: every document written against it was valid when written. A
// consumer MUST accept both; a producer moves at its own release.
const (
	SchemaV01 = "taipanbox.dev/agent-passport/v0.1"
	SchemaV10 = "taipanbox.dev/agent-passport/v1.0"
)

// RequiredSchema names v0.1 and is kept for callers that pinned it before 1.0.
// It is no longer the only version Parse accepts; see AcceptedSchemas.
const RequiredSchema = SchemaV01

// AcceptedSchemas lists the Passport schema strings Parse accepts, oldest
// first. The slice is fresh on every call, so a caller cannot widen it.
func AcceptedSchemas() []string { return []string{SchemaV01, SchemaV10} }

// maxURIBytes is the maximum length, in bytes, of an agent:// or user://
// URI (agent-passport SPEC §3.1).
const maxURIBytes = 255

// agentURIPattern and userURIPattern are compiled once and reused by
// ValidateAgentURI and ValidateUserURI.
var (
	agentURIPattern = regexp.MustCompile(`^agent://[a-z0-9.-]+/[a-z0-9._/-]+$`)
	userURIPattern  = regexp.MustCompile(`^user://[a-z0-9.-]+/[a-z0-9._/-]+$`)
)

// Sentinel errors returned by Parse, ValidateAgentURI, and ValidateUserURI.
// Wrapped with additional context via fmt.Errorf's %w verb, so callers can
// still branch on failure kind with errors.Is rather than string matching.
var (
	// ErrInvalidJSON means the input was not well-formed JSON.
	ErrInvalidJSON = errors.New("passport: invalid json")
	// ErrUnsupportedSchema means the document's schema field was missing or
	// named a version this package does not carry (see AcceptedSchemas).
	ErrUnsupportedSchema = errors.New("passport: unsupported schema")
	// ErrUnknownField means a v1.0 document carried a top-level key the
	// schema never named (SPEC 6.4.1). Under v0.1 the same key is tolerated.
	ErrUnknownField = errors.New("passport: field the schema never named")
	// ErrMissingID means the document had no id field.
	ErrMissingID = errors.New("passport: missing required field: id")
	// ErrMissingOwner means the document had no owner field.
	ErrMissingOwner = errors.New("passport: missing required field: owner")
	// ErrInvalidURI means a value was not a well-formed agent:// or user://
	// URI: wrong scheme, disallowed characters, or over the length cap.
	ErrInvalidURI = errors.New("passport: invalid uri")
)

// Attestation records how an organization binds a Passport's id to a
// workload. Method is one of: none, oidc, spiffe-svid, enclave-key,
// mtls-cert, dpop-key. Detail is a method-specific reference, e.g. a SPIFFE
// ID, an issuer URL, or an RFC 7638 key thumbprint.
//
// The list is the SPEC 4.3 enum, and this comment is a copy of it rather than
// the thing itself: the enum is enforced by the vendored schema, which
// scripts/schemas-in-sync.sh holds byte-identical to agent-passport's. Method
// is a plain string here on purpose, so a Passport attested by a method this
// build predates still parses.
type Attestation struct {
	Method string `json:"method"`
	Detail string `json:"detail,omitempty"`
}

// FsScope is one declared filesystem access entry (SPEC.md 4.4): a folder the
// agent is declared to reach, with a read or write mode. A declaration of
// intent for audit, not an enforced control.
type FsScope struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// Model is one declared LLM the agent is meant to use (SPEC.md 4.5): a
// provider, and optionally a specific model and API endpoint. A declaration
// for audit and inventory, not an enforced control. It is the declared side of
// a three-source AI inventory (declared here, coded in the agent's source,
// observed on the network).
type Model struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// Passport is the wire shape of one Agent Passport document.
type Passport struct {
	Schema      string            `json:"schema"`
	ID          string            `json:"id"`
	Owner       string            `json:"owner"`
	DisplayName string            `json:"display_name,omitempty"`
	Runtime     string            `json:"runtime,omitempty"`
	Parent      string            `json:"parent,omitempty"`
	Attestation *Attestation      `json:"attestation,omitempty"`
	Filesystem  []FsScope         `json:"filesystem,omitempty"`
	Models      []Model           `json:"models,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
}

// ValidateAgentURI reports whether s is a well-formed agent:// URI: scheme
// agent://, a lowercase trust-domain, and one or more path segments,
// max 255 bytes total.
func ValidateAgentURI(s string) error {
	return validateURI(s, agentURIPattern)
}

// ValidateUserURI reports whether s is a well-formed user:// URI: scheme
// user://, a lowercase trust-domain, and one or more path segments naming
// the human subject, max 255 bytes total.
func ValidateUserURI(s string) error {
	return validateURI(s, userURIPattern)
}

// ClaimedPrefix marks a subject a PROCESS asserted about itself, read out of
// its own AGENT_PASSPORT_ID environment variable (agent-passport SPEC 3.3).
//
// It lives here because this package owns the identifier grammar, and a second
// copy of the string in each consumer is the drift every repository in this
// estate has an invariant against. idryx has carried this exact convention
// on-host since the sensor was written; SPEC 3.3 made it the wire form too, so
// the sensor's own graph string now travels unchanged instead of being
// translated at the boundary.
const ClaimedPrefix = "claimed:"

// IsClaimedSubject reports whether s is a claimed subject rather than an
// established one.
//
// It is a prefix test and nothing more, on purpose. Deciding what a claim MEANS
// belongs to the consumer: SPEC 3.3 says only that it must never satisfy a
// control requiring an attested identity, and this package does not know which
// controls a caller has.
func IsClaimedSubject(s string) bool {
	return strings.HasPrefix(s, ClaimedPrefix)
}

// ValidateSubject reports whether s is a well-formed envelope subject: either
// an established agent:// URI, or a claimed one under the `claimed:` marker.
//
// This is what an agent-event consumer wants, and ValidateAgentURI is what an
// AUTHORIZATION path wants. Keeping them apart is deliberate: a caller deciding
// whether an identity may do something must never be handed a function that
// accepts a self-declaration, and the way to make that hard is to give the two
// questions two names.
func ValidateSubject(s string) error {
	if inner, ok := strings.CutPrefix(s, ClaimedPrefix); ok {
		return ValidateAgentURI(inner)
	}
	return ValidateAgentURI(s)
}

// ClaimedInner returns the agent:// URI inside a claimed subject, and reports
// whether s was claimed at all.
//
// The identity it returns is one a PROCESS asserted about itself. A caller that
// strips the marker takes on the obligation the marker carried, and SPEC 3.3 is
// explicit that the result must not satisfy a control requiring an attested
// identity. Use it to compare a claim against an inventory, never to act on it.
func ClaimedInner(s string) (string, bool) {
	return strings.CutPrefix(s, ClaimedPrefix)
}

func validateURI(s string, pattern *regexp.Regexp) error {
	if len(s) > maxURIBytes {
		return fmt.Errorf("%w: %q exceeds %d bytes", ErrInvalidURI, s, maxURIBytes)
	}
	if !pattern.MatchString(s) {
		return fmt.Errorf("%w: %q", ErrInvalidURI, s)
	}
	return nil
}

// Parse decodes one Passport JSON document. It returns an error, wrapping
// one of this package's sentinel errors, when the document isn't valid
// JSON, its schema is not one of AcceptedSchemas, either of the required
// fields beyond schema (id, owner) is missing, id is not a well-formed
// agent:// URI, or, under v1.0 only, a top-level key appears that the schema
// never named. Every other field is optional.
func Parse(data []byte) (Passport, error) {
	var p Passport
	if err := json.Unmarshal(data, &p); err != nil {
		return Passport{}, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch p.Schema {
	case SchemaV01:
	case SchemaV10:
		if err := refuseUnknownTopLevelKeys(data); err != nil {
			return Passport{}, err
		}
	default:
		return Passport{}, fmt.Errorf("%w: got %q, want one of %q", ErrUnsupportedSchema, p.Schema, AcceptedSchemas())
	}
	if p.ID == "" {
		return Passport{}, ErrMissingID
	}
	if p.Owner == "" {
		return Passport{}, ErrMissingOwner
	}
	if err := ValidateAgentURI(p.ID); err != nil {
		return Passport{}, fmt.Errorf("passport: invalid id: %w", err)
	}
	return p, nil
}

// knownTopLevelKeys are the JSON names Passport declares, read from the
// struct's own tags so that adding a field here is the only edit a new key
// needs; a hand-kept second list is the drift this module has met before.
var knownTopLevelKeys = func() map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeFor[Passport]()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}()

// refuseUnknownTopLevelKeys is SPEC 6.4.1's one narrowing: under v1.0 the
// document's top level is closed. Nested objects are not walked, exactly as
// the schema's additionalProperties is set at the top level and nowhere else.
func refuseUnknownTopLevelKeys(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	var unknown []string
	for k := range raw {
		if !knownTopLevelKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%w: %q under %s", ErrUnknownField, unknown, SchemaV10)
}
