package passport

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	data := []byte(`{
		"schema": "taipanbox.dev/agent-passport/v0.1",
		"id": "agent://acme-bank.example/support/tier1-bot",
		"display_name": "Tier-1 support bot",
		"owner": "team-support@acme-bank.example",
		"runtime": "langgraph",
		"parent": "agent://acme-bank.example/support/orchestrator",
		"attestation": {
			"method": "spiffe-svid",
			"detail": "spiffe://acme-bank.example/agent/support/tier1-bot"
		},
		"labels": { "env": "prod", "cost_center": "cs-eu" },
		"created_at": "2026-07-09T00:00:00Z"
	}`)

	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Passport{
		Schema:      RequiredSchema,
		ID:          "agent://acme-bank.example/support/tier1-bot",
		Owner:       "team-support@acme-bank.example",
		DisplayName: "Tier-1 support bot",
		Runtime:     "langgraph",
		Parent:      "agent://acme-bank.example/support/orchestrator",
		CreatedAt:   "2026-07-09T00:00:00Z",
	}
	switch {
	case p.Schema != want.Schema,
		p.ID != want.ID,
		p.Owner != want.Owner,
		p.DisplayName != want.DisplayName,
		p.Runtime != want.Runtime,
		p.Parent != want.Parent,
		p.CreatedAt != want.CreatedAt:
		t.Errorf("Parse = %+v, want %+v", p, want)
	}
	wantAttestation := Attestation{Method: "spiffe-svid", Detail: "spiffe://acme-bank.example/agent/support/tier1-bot"}
	if p.Attestation == nil || *p.Attestation != wantAttestation {
		t.Errorf("Attestation = %+v, want %+v", p.Attestation, wantAttestation)
	}
	wantLabels := map[string]string{"env": "prod", "cost_center": "cs-eu"}
	if len(p.Labels) != len(wantLabels) || p.Labels["env"] != wantLabels["env"] || p.Labels["cost_center"] != wantLabels["cost_center"] {
		t.Errorf("Labels = %+v, want %+v", p.Labels, wantLabels)
	}
}

// TestParseFilesystemAndModels covers the SPEC 4.4/4.5 declaration arrays:
// filesystem scopes and declared models parse into their typed slices, and
// an entry's optional model/endpoint fields stay empty when absent.
func TestParseFilesystemAndModels(t *testing.T) {
	data := []byte(`{
		"schema": "taipanbox.dev/agent-passport/v0.1",
		"id": "agent://acme.example/data/etl",
		"owner": "team-data@acme.example",
		"filesystem": [
			{ "path": "/data/reports", "mode": "read" },
			{ "path": "/data/out", "mode": "write" }
		],
		"models": [
			{ "provider": "anthropic", "model": "claude-sonnet-4-5", "endpoint": "api.anthropic.com" },
			{ "provider": "openai" }
		]
	}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Filesystem) != 2 || p.Filesystem[0] != (FsScope{Path: "/data/reports", Mode: "read"}) || p.Filesystem[1] != (FsScope{Path: "/data/out", Mode: "write"}) {
		t.Errorf("Filesystem = %+v", p.Filesystem)
	}
	if len(p.Models) != 2 {
		t.Fatalf("Models len = %d, want 2 (%+v)", len(p.Models), p.Models)
	}
	if p.Models[0] != (Model{Provider: "anthropic", Model: "claude-sonnet-4-5", Endpoint: "api.anthropic.com"}) {
		t.Errorf("Models[0] = %+v", p.Models[0])
	}
	// The bare-provider entry keeps model and endpoint empty.
	if p.Models[1] != (Model{Provider: "openai"}) {
		t.Errorf("Models[1] = %+v, want only provider set", p.Models[1])
	}
}

// TestParseMinimal covers the SPEC's required-field rule: schema, id, and
// owner are required, everything else is optional and must parse cleanly
// when absent.
func TestParseMinimal(t *testing.T) {
	data := []byte(`{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":"team@acme.example"}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Attestation != nil {
		t.Errorf("Attestation = %+v, want nil", p.Attestation)
	}
	if p.Labels != nil {
		t.Errorf("Labels = %+v, want nil", p.Labels)
	}
	if p.Runtime != "" || p.Parent != "" || p.DisplayName != "" || p.CreatedAt != "" {
		t.Errorf("unexpected non-empty optional field: %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantErr error
	}{
		{
			name:    "not json",
			data:    `not json`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "missing schema",
			data:    `{"id":"agent://acme.example/bot","owner":"team@acme.example"}`,
			wantErr: ErrUnsupportedSchema,
		},
		{
			name:    "wrong schema version",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.2","id":"agent://acme.example/bot","owner":"team@acme.example"}`,
			wantErr: ErrUnsupportedSchema,
		},
		{
			name:    "missing id",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","owner":"team@acme.example"}`,
			wantErr: ErrMissingID,
		},
		{
			name:    "empty id",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"","owner":"team@acme.example"}`,
			wantErr: ErrMissingID,
		},
		{
			name:    "missing owner",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot"}`,
			wantErr: ErrMissingOwner,
		},
		{
			name:    "empty owner",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example/bot","owner":""}`,
			wantErr: ErrMissingOwner,
		},
		{
			name:    "invalid id: wrong scheme",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"user://acme.example/bot","owner":"team@acme.example"}`,
			wantErr: ErrInvalidURI,
		},
		{
			name:    "invalid id: uppercase trust domain",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://ACME.example/bot","owner":"team@acme.example"}`,
			wantErr: ErrInvalidURI,
		},
		{
			name:    "invalid id: no path",
			data:    `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://acme.example","owner":"team@acme.example"}`,
			wantErr: ErrInvalidURI,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.data))
			if err == nil {
				t.Fatal("Parse: expected an error, got nil")
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("Parse error = %v, want wrapping %v", err, c.wantErr)
			}
		})
	}
}

func TestValidateAgentURI(t *testing.T) {
	valid := []string{
		"agent://acme-bank.example/support/tier1-bot",
		"agent://acme.example/eng/ci-fixer/instance-7",
		"agent://a.b/c",
		"agent://acme.example/a.b_c-d/e",
	}
	for _, s := range valid {
		if err := ValidateAgentURI(s); err != nil {
			t.Errorf("ValidateAgentURI(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"agent://",
		"agent://Acme.example/bot",
		"user://acme.example/bot",
		"agent://acme.example",
		"http://acme.example/bot",
		"agent://acme.example/bot with spaces",
	}
	for _, s := range invalid {
		err := ValidateAgentURI(s)
		if err == nil {
			t.Errorf("ValidateAgentURI(%q) = nil, want an error", s)
			continue
		}
		if !errors.Is(err, ErrInvalidURI) {
			t.Errorf("ValidateAgentURI(%q) error = %v, want wrapping ErrInvalidURI", s, err)
		}
	}
}

func TestValidateUserURI(t *testing.T) {
	valid := []string{
		"user://acme-bank.example/j.doe",
		"user://acme.example/team/alice",
	}
	for _, s := range valid {
		if err := ValidateUserURI(s); err != nil {
			t.Errorf("ValidateUserURI(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"agent://acme.example/bot", // wrong scheme
		"user://ACME.example/bot",  // uppercase
		"user://acme.example",      // no path
	}
	for _, s := range invalid {
		err := ValidateUserURI(s)
		if err == nil {
			t.Errorf("ValidateUserURI(%q) = nil, want an error", s)
			continue
		}
		if !errors.Is(err, ErrInvalidURI) {
			t.Errorf("ValidateUserURI(%q) error = %v, want wrapping ErrInvalidURI", s, err)
		}
	}
}

// TestValidateAgentURILength pins the 255-byte cap (agent-passport SPEC
// §3.1): exactly 255 bytes is allowed, 256 is not.
func TestValidateAgentURILength(t *testing.T) {
	base := "agent://a.b/"
	ok := base + strings.Repeat("c", maxURIBytes-len(base))
	if len(ok) != maxURIBytes {
		t.Fatalf("test setup: len = %d, want %d", len(ok), maxURIBytes)
	}
	if err := ValidateAgentURI(ok); err != nil {
		t.Errorf("ValidateAgentURI(%d bytes) = %v, want nil", maxURIBytes, err)
	}

	tooLong := ok + "c"
	if err := ValidateAgentURI(tooLong); err == nil {
		t.Errorf("ValidateAgentURI(%d bytes) = nil, want an error", maxURIBytes+1)
	}
}
