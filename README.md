<div align="center">

# agent-stack-go - Shared Go Contract

**One Go module for Agent Passport identity and the agent-event NDJSON envelope, so every service in the stack speaks the same wire language instead of reimplementing it.**

[![CI](https://github.com/TAIPANBOX/agent-stack-go/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/agent-stack-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/TAIPANBOX/agent-stack-go.svg)](https://pkg.go.dev/github.com/TAIPANBOX/agent-stack-go)
![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)
![tests](https://img.shields.io/badge/tests-85-brightgreen.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/status-v0.5.0-success.svg)

<img src="docs/architecture.png" alt="agent-stack-go: the passport, event and chain packages compose one shared contract, imported by tag by Idryx, Wardryx, Mockryx, Qryx, heraldyx and terraform-provider-taipan" width="960">

</div>

agent-stack-go is the public, importable home of the wire types every Go
service in the TAIPANBOX agent-governance stack (Wardryx, Mockryx, and
future siblings) needs to speak the same identity and event language as
TokenFuse, Idryx, Qryx, and Engram. Idryx's equivalents live under
`internal/` and cannot be imported outside that repo, which is why this
module exists: one shared source, not four drifting copies.

The stack this module supports is a defensive, self-protection system: it
exists so an organization running AI agents can govern and audit its own
agents, never to attack, surveil, or act against anyone else.

---

## Where this fits in the stack

agent-stack-go is the shared-contract plane of the TAIPANBOX agent-governance stack: the Go bindings for Agent Passport identity and the agent-event NDJSON envelope that the stack's other Go services import instead of reimplementing.

```mermaid
flowchart TB
  Agent["AI agent (any framework)"] -->|"LLM call (base-URL swap)"| TF["TokenFuse proxy: spend + enforcement"]
  TF -->|"POST /v1/decide (PEP)"| WX["Wardryx: policy PDP"]
  WX -.->|"allow / deny / hold"| TF
  TF -->|"cheapest model, budget OK"| LLM[("LLM provider")]
  TF -->|"CallRecords"| CL["TokenFuse Cloud: control plane, incidents, replay, evidence, kill-switch"]
  TF ==>|"agent-event NDJSON"| BUS{{"agent-event bus + Agent Passport"}}
  WX ==> BUS
  ENG["Engram: memory"] -->|"reflect via base_url"| TF
  ENG ==> BUS
  BUS ==> IDX["Idryx: identity graph, detectors, Agent-BOM"]
  BUS ==> QX["Qryx: crypto / PQC, passport + hash-chain scan"]
  BUS ==> VX["Verdryx: quality / drift"]
  VX ==>|"quality events"| BUS
  TF -->|"outcome-tagged traces"| VX
  MX["Mockryx: pre-prod safety rehearsal"] -->|"hostile scenarios"| TF
  MX ==>|"sim events"| BUS
  BUS ==> HX["heraldyx: reads the log, mails you"]
  HX -->|"one mail, a view and never an action"| OPS["your mailbox"]
  YOU(["you, in a browser over your own tunnel"]) --> GX[["Genaryx: the console over all of it"]]
  GX -->|"signed commands: the kill, an approval, a policy"| CL
  GX -->|"signed commands"| WX
  GX -.->|"reads it"| IDX
  GX -.->|"reads it"| QX
  GX -.->|"reads it"| VX
  GX -.->|"reads it"| MX
  GX -.->|"reads it"| ENG
  TFP["terraform-provider-taipan"] -->|"budgets + passports as code"| CL
  ASG[["agent-stack-go: shared Go contract"]] -.->|imported by| IDX
  ASG -.->|imported by| WX
  ASG -.->|imported by| MX
  ASG -.->|imported by| TFP
  ASG -.->|imported by| HX
  ASG -.->|imported by| QX
  SPEC[["agent-passport: the spec"]] -.->|governs| BUS
```

- **Consumes**: the **agent-passport** spec, which its `passport` and `event` packages conform to (each checked by its own schema conformance test, against the canonical schema rather than against a copy of our own beliefs).
- **Produces**: shared Go types for the Agent Passport document, the agent-event NDJSON envelope, and delegation-chain validation.
- **Talks to**: imported by **Idryx**, **Wardryx**, **Mockryx**, **Qryx**, **heraldyx** and **terraform-provider-taipan**, so all six speak the same identity and event language as **TokenFuse** and **Engram**, which reach it through their own languages.

The full stack is TokenFuse (spend), Wardryx (policy), Engram (memory), Idryx (access), Qryx (crypto), Verdryx (quality), Mockryx (pre-prod) and heraldyx (the mail out), on the shared Agent Passport + agent-event contract (agent-stack-go / agent-passport), configured via terraform-provider-taipan and driven from Genaryx, the console over all of it. Trailryx, the record plane, is built and not wired into this yet.

Run the whole open stack locally with one command via [**stack-up**](https://github.com/TAIPANBOX/stack-up); the stack's home on the web is [**it-rat.com**](https://it-rat.com).

---

## The shared contract

<div align="center">
<img src="docs/contract.png" alt="The event envelope's required and optional fields, the Passport identity and runtime fields, the Attestation binding, and the chain package's delegation helpers" width="900">
</div>

Three packages, one contract, stdlib plus exactly one vetted dependency
(`github.com/gowebpki/jcs`, the RFC 8785/JCS canonicalization the
`prev_hash` integrity chain hashes over - canonical JSON is precisely the
kind of wheel not to hand-roll):

| Package | Wire schema | What it defines |
|---|---|---|
| `passport` | `taipanbox.dev/agent-passport/v0.1` | the Agent Passport document: identity, owner, runtime, provisioning parent, attestation posture |
| `event` | `taipanbox.dev/agent-event/v0.2` (v0.1 still accepted) | the agent-event NDJSON envelope, plus an append-only `Writer`, tolerant `Scan`/`ReadFile` readers, and the `ChainedWriter`/`VerifyChain` SPEC 6.5 `prev_hash` integrity chain (`Canonicalize`/`ChainHash`) |
| `chain` | n/a (a v0.2 normative rule) | delegation-chain helpers: acyclic, root-first, capped at `chain.MaxDepth` (32) entries |

### `event.Event` - the agent-event envelope

| Field | JSON key | Type | Required | Notes |
|---|---|---|---|---|
| `Schema` | `schema` | `string` | yes | `SchemaV02` or `SchemaV01` |
| `TS` | `ts` | `string` | yes | timestamp, not shape-validated by `Unmarshal` |
| `Source` | `source` | `string` | yes | the emitting service |
| `Type` | `type` | `string` | yes | the event type |
| `AgentID` | `agent_id` | `string` | yes | `agent://` URI of the acting agent |
| `Severity` | `severity` | `string` | no | `info` · `low` · `medium` · `high` · `critical` |
| `RunID` | `run_id` | `string` | no | correlates events within one run |
| `OnBehalfOf` | `on_behalf_of` | `[]string` | no | the delegation chain (see package `chain`) |
| `Data` | `data` | `map[string]any` | no | the event payload |
| `PrevHash` | `prev_hash` | `string` | no | the SPEC §6.5 integrity-chain link; stamped by `ChainedWriter`, verified by `VerifyChain` |

`Unmarshal` returns a sentinel error (`ErrMissingSchema`, `ErrMissingTS`,
`ErrMissingSource`, `ErrMissingType`, `ErrMissingAgentID`) for any missing
required field, checkable with `errors.Is`. Struct fields are declared in
wire order, so `json.Marshal`'s output matches the Rust
(`tokenfuse-core::agent_event`) and Python (`engram.events`) exporters
shipping elsewhere in the stack.

### The `prev_hash` integrity chain (SPEC §6.5)

`ChainedWriter` is `Writer` plus the chain: every appended event carries
`sha256:` + hex(sha256(C)) of the PREVIOUS event, where C is its RFC 8785
(JCS) canonical serialization with the `prev_hash` field removed. One
file is one chain: reopening resumes from the tail, so a process restart
does not fork the chain (an unreadable tail starts fresh, fail-open, and
a verifier shows the restart honestly). `Canonicalize`/`ChainHash` are
the exported primitives; `VerifyChain` walks a stream and reports
genuine breaks separately from legal restarts and unverifiable links (a
rotated segment's first line, or the line after a malformed one).
`agent-conform -chain <file>` runs the same verification from the CLI,
alongside the `on_behalf_of` delegation check described under
[`agent-conform`](#command-line-tool-agent-conform): two different chains,
reported apart.
The chain is tamper-EVIDENCE, not tamper-proof: whole-file rewrites can
re-chain; partial edits, truncation and reordering no longer pass
silently. Cross-language pinned vectors live in
`event/testdata/chain-vectors.json`; the Rust (`tokenfuse`) and Python
(`engram`, `verdryx`) emitters pin the same bytes.

### `passport.Passport` - the Agent Passport document

| Field | JSON key | Type | Required | Notes |
|---|---|---|---|---|
| `Schema` | `schema` | `string` | yes | must equal `RequiredSchema` |
| `ID` | `id` | `string` | yes | `agent://` URI, checked by `ValidateAgentURI` |
| `Owner` | `owner` | `string` | yes | the owning team or human |
| `DisplayName` | `display_name` | `string` | no | |
| `Runtime` | `runtime` | `string` | no | |
| `Parent` | `parent` | `string` | no | static provisioning parent |
| `Attestation` | `attestation` | `*Attestation` | no | how the id is bound to a workload |
| `Labels` | `labels` | `map[string]string` | no | |
| `CreatedAt` | `created_at` | `string` | no | |

`Attestation.Method` is one of `none` · `oidc` · `spiffe-svid` ·
`enclave-key` · `mtls-cert`; `Attestation.Detail` is a method-specific
reference (a SPIFFE ID, an issuer URL, …).

| Function | Signature | Behavior |
|---|---|---|
| `LoadDir` | `LoadDir[T any](dirOrGlob string, parse func([]byte) (T, error), id func(T) string) ([]T, Report, error)` | reads every file under a directory/glob/literal path in sorted order, decoding each with `parse`; a file that fails `parse` is counted in `Report.Malformed` and skipped, never fatal; duplicate `id` keys keep the first occurrence in sorted-path order |

`LoadDir` is generic over the parsed type, not tied to `Passport`: pass
`passport.Parse` and an `ID`-extractor for a batch of Passport documents
(the shape Wardryx's `internal/passports` and Idryx's
`internal/ingest/passport` both need), or any other `func([]byte) (T, error)`
for a different kind of file batch.

### `chain` - delegation-chain helpers

| Function | Signature | Behavior |
|---|---|---|
| `Append` | `Append(chain []string, principal string) ([]string, error)` | returns a new chain with `principal` appended; never mutates the input; `ErrCycle` if already present, `ErrTooDeep` past `MaxDepth` |
| `Validate` | `Validate(chain []string) error` | checks acyclic, ≤ `MaxDepth` (32), every entry an `agent://` or `user://` URI |

A nil or empty chain is valid: per the spec, it means the agent acts
autonomously.

---

## Install

```sh
go get github.com/TAIPANBOX/agent-stack-go@v0.5.0
```

Pin to a tagged release, not to `@latest` and never to a local `replace`
(see [Versioning](#versioning)).

### The `agent-conform` binary, without a Go toolchain

That line above serves anybody already writing Go. It served nobody who simply
wanted to check a payload once, which is the more common reason to touch this
repository at all: `agent-conform` decides whether a passport or an event stream
conforms, and needing to install a compiler to run a checker is backwards.

Prebuilt binaries for Linux, macOS and Windows, on x86_64 and arm64, are
published on the [Releases page](https://github.com/TAIPANBOX/agent-stack-go/releases)
for every `v*` tag, with a `SHA256SUMS` beside them.

**The asset names carry no version**, so `releases/latest/download/<name>` is a
permanent address for the current build. You never look up a version number,
and a link to one of these does not rot.

```sh
P=$(uname -s | tr A-Z a-z)_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
U=https://github.com/TAIPANBOX/agent-stack-go/releases/latest/download

curl -fsSLO $U/agent-conform_$P.tar.gz
curl -fsSLO $U/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

tar -xzf agent-conform_$P.tar.gz
./agent-conform_$P/agent-conform -version
./agent-conform_$P/agent-conform passport.json
./agent-conform_$P/agent-conform -chain events.ndjson
```

The version is still there, in the binary rather than in the filename:
`-version` prints the tag it was built from. That is the harder of the two
places to fake, since anything between us and you can rename a file.

### The two paths give the same bytes, and you can check that

Downloading the binary and building it yourself are not a choice between trust
and effort. **They produce an identical file**, so you can take the fast path and
still have somebody verify it afterwards. That matters more here than in most
places: this tool's output is a verdict about *your* system, and a verdict is
worth what its checker is worth.

```sh
# ours, unpacked ANYWHERE EXCEPT the checkout (see the warning below)
mkdir -p /tmp/verify && cd /tmp/verify
curl -fsSLO https://github.com/TAIPANBOX/agent-stack-go/releases/latest/download/agent-conform_darwin_arm64.tar.gz
tar -xzf agent-conform_darwin_arm64.tar.gz

# yours, from a clean tree
cd /path/to/your/agent-stack-go
git checkout v0.5.0
git status --porcelain      # must print nothing at all
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X main.version=v0.5.0" -o /tmp/verify/mine ./cmd/agent-conform

sha256sum /tmp/verify/mine \
  /tmp/verify/agent-conform_darwin_arm64/agent-conform
# macOS ships shasum -a 256 rather than sha256sum, and this example builds for
# darwin, so that is probably the one you want
```

Two identical digests. Measured on 5 August 2026 from a fresh clone against the
real `v0.5.0` assets, cross-compiled on an Ubuntu runner and rebuilt on macOS:
`fe8ccb5e1606129818981bfd6a7369a5a9dbc640bbec40640762d8d01c888ff5`.

**Build from a clean tree, and do not unpack our archive inside it.** Go stamps
`vcs.modified` into the binary, and **one untracked file anywhere in the
checkout flips it to true**, which changes the bytes. The release is built from
a clean CI checkout, so it carries `vcs.modified=false`. Unpacking the download
into the repository before building is enough to break the comparison on its
own: measured, `fe8ccb5e…` clean versus `ae64cf9b…` with a single untracked
file beside it. `git status --porcelain` is in the recipe for that reason and
is not decoration.

The same trap has a second door. Building from a `git archive` extraction or a
detached `git worktree` leaves Go unable to read the VCS at all, so it stamps no
revision and records the module as `(devel)`. Both doors lead to a binary that
legitimately differs from the release, and the difference looks enormous because
a version string one byte shorter shifts everything after it. It is one field,
not a different program.

**Compare the binaries, not the archives.** `SHA256SUMS` on the release page
lists the `.tar.gz` and `.zip` files, and it answers a different question: did
your download arrive intact. It cannot answer this one, because `tar` and
`gzip` stamp times into the archive, so the archive is not reproducible even
when every byte of the binary inside it is. An earlier version of this recipe
said to compare `mine` against `SHA256SUMS` directly. Anybody who followed it
got two digests that could never match and a good reason to think we were
lying.

Three flags make that work, `CGO_ENABLED=0`, `-trimpath` and `-s -w`, and losing
any one would break it **silently**: the build would still succeed and only
somebody trying to verify us would find out. So on every push CI does two things
(`scripts/reproducible-build.sh`): it reads the build command out of the release
workflow and refuses if any of the three flags is missing there, and it builds
the same source in two directories of different lengths and refuses if a byte
differs. The first of those exists because the flags have to agree in two files,
and until 5 August 2026 only one of the two was ever checked. The same three
flags were measured
against real published artifacts in the sibling repositories qryx and idryx on
5 August 2026, each rebuilding to its release byte for byte from a different
host OS.

A different Go version will not reproduce these bytes either. `go.mod` pins the
toolchain, and a digest is only meaningful beside the compiler that made it.

## Usage

```go
package main

import (
	"fmt"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/agent-stack-go/passport"
)

func main() {
	e := event.Event{
		Schema:   event.SchemaV02,
		TS:       "2026-07-09T03:12:44.100Z",
		Source:   "wardryx",
		Type:     "policy_deny",
		AgentID:  "agent://acme-bank.example/support/tier1-bot",
		Severity: event.SeverityHigh,
		RunID:    "run-8842",
		Data:     map[string]any{"reason": "budget_exceeded"},
	}
	line, err := event.Marshal(e)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(line))

	p, err := passport.Parse([]byte(`{
		"schema": "taipanbox.dev/agent-passport/v0.1",
		"id": "agent://acme-bank.example/support/tier1-bot",
		"owner": "user://acme-bank.example/support-team"
	}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(p.ID, p.Owner)
}
```

## Command-line tool: `agent-conform`

```sh
go install github.com/TAIPANBOX/agent-stack-go/cmd/agent-conform@v0.5.0
agent-conform passport.json events.ndjson
```

(It landed after `v0.2.0` and shipped in `v0.4.0`, so a tag is the right way
to install it now, per [Versioning](#versioning).)

The standalone conformance checker: validates Passport documents and
agent-event NDJSON streams against the canonical JSON Schemas, the check
agent-passport's own README names as not existing yet ("conformance is
verified per-repo... by hand"). Stricter than `passport.Parse`/
`event.Unmarshal` (which only enforce required-field presence) -- full
schema validation, including patterns like the `agent://` URI grammar and
`prev_hash`'s exact 64-hex-char form. Each file is classified by its own
`schema` field, not extension, mirroring the same convention every
connector in the stack already uses. Exit code 0 means every file (and
every line within an event stream) conforms; 1 means at least one did not.

`-chain` checks the two things "chain" means in this spec, and reports them
apart because they answer different questions:

| Check | Rule | What a failure means |
|---|---|---|
| `prev_hash` integrity chain | SPEC 6.5, via `event.VerifyChain` | the file was altered, truncated or reordered after it was written |
| `on_behalf_of` delegation chain | SPEC 5.1, via `chain.Validate`: acyclic, at most 32 entries, every entry an `agent://` or `user://` URI | the identity claim inside the event never made sense, which points at the emitter rather than at whoever has held the file since |

A stream can pass either one and fail the other, which is the reason for two
verdicts rather than one. Root-first ordering is deliberately not claimed: it
is a property of how a chain was built, one entry appended per hop, and a list
of URIs after the fact carries nothing that could distinguish a root-first
chain from a reversed one.

## Design notes

- Stdlib only at runtime for `passport` and `chain`: no third-party
  dependency is ever required to import and use them. `event` additionally
  requires `github.com/gowebpki/jcs` (RFC 8785/JCS canonicalization) at
  runtime, for the `prev_hash` integrity chain (`ChainedWriter`/
  `VerifyChain`, see above). `github.com/santhosh-tekuri/jsonschema/v6` is
  used by `event`'s conformance test and, as a real (non-test) dependency,
  by `cmd/agent-conform` -- a consumer importing only the library packages
  never pulls in jsonschema; only building the standalone tool does. The same
  holds for `passport`'s conformance test, which is why
  `scripts/deps-layering.sh` reads non-test imports only.
- Each package mirrors an existing internal implementation elsewhere in the
  stack (Idryx's `internal/ingest/passport` and `internal/ingest/tokenfuse`,
  TokenFuse's `tokenfuse-core::agent_event`, Engram's `engram.events`) rather
  than inventing new semantics, so adopting it is a rename, not a rewrite.
- Errors are sentinel values, checkable with `errors.Is`, not opaque strings,
  so callers can branch on failure kind without string matching.
- Malformed input is tolerated the same way the existing Idryx connectors
  tolerate it: a bad NDJSON line or passport document is skipped and
  counted, never fatal to the rest of a batch.

The canonical JSON Schemas live in the `TAIPANBOX/agent-passport` repo.
`event/testdata/agent-event.v0.2.schema.json` and
`passport/testdata/schema/agent-passport.schema.json` are local copies used only by
those packages' conformance tests, so the Go bindings can never silently drift
out of lockstep with the schemas that define the wire contract.
`cmd/agent-conform/schemas/*.json` are separate local copies of all three
schemas (Passport, event v0.1, event v0.2), embedded into that tool via
`go:embed` for the same reason.

Copies drift, so on every push CI checks out agent-passport beside this repo
and compares every one of them against the file it was copied from, byte for
byte (`scripts/schemas-in-sync.sh`). That check exists because the vendored
Passport schema had drifted: it was missing the `filesystem` (SPEC 4.4) and
`models` (SPEC 4.5) declarations, and a Passport document allows
`additionalProperties`, so a property the schema does not declare is not
checked loosely, it is not looked at at all. A passport whose filesystem entry
said `"mode": "delete"`, a mode the spec does not have, passed with `OK`. The
schema is synced and both fields are now enforced; the gate is there so the
next divergence is caught by CI rather than by a reader.

## Versioning

This module follows SemVer, starting at `v0.1.0`. Breaking the wire contract
(the `passport` or `event` schema) is a spec version bump, never a silent
change; the Go types version alongside the module itself. Consumers pin it
by tag (`go get github.com/TAIPANBOX/agent-stack-go@v0.5.0`), never a local
`replace`.

---

## Status

- [x] `passport`: `Parse`, `ValidateAgentURI`, `ValidateUserURI`, sentinel errors
- [x] `event`: `Marshal`, `Unmarshal`, append-only `Writer`, `Scan`/`ReadFile` NDJSON readers, `ChainedWriter`/`VerifyChain` SPEC 6.5 `prev_hash` integrity chain, `Canonicalize`/`ChainHash`
- [x] `chain`: `Append`, `Validate`, `MaxDepth` = 32, acyclic + root-first
- [x] conformance tests against the canonical JSON Schemas, one per bound type:
  `event` against `agent-event` v0.2, `passport` against `agent-passport` v0.1,
  including a both-directions check that the struct's json tags and the schema's
  properties name the same set (a mistyped tag validates fine, since
  `additionalProperties` is true, and declares nothing)
- [x] `passport.LoadDir`: shared batch loader (resolve dir/glob/file, sorted, tolerant, first-seen-id dedup), extracted out of Wardryx's and Idryx's independent copies
- [x] `v0.5.0` tagged, the first release to publish `agent-conform` as a binary; CI green on `gofmt`, `go vet`, `staticcheck`, `go test -race`, `go build`, `govulncheck`
- [x] `cmd/agent-conform`: standalone conformance-check CLI, full JSON Schema
  validation (Passport documents + event v0.1/v0.2) against embedded copies
  of the canonical schemas; live-verified against real fixtures elsewhere
  in the stack, catching a real 63-vs-64-hex-char `prev_hash` defect

This module's package set (`passport`, `event`, `chain`) covers everything the
stack's current Go consumers need; it is not a fixed, closed list, and grows
opportunistically the same way `passport.LoadDir` did (extracted once two
independent copies existed, not speculatively).

## Validation

What has actually been checked about this contract, what a real cluster run
confirmed, and what is explicitly NOT validated: [`VALIDATION.md`](VALIDATION.md).
The short version is that `agent-conform` caught a real 63-versus-64 hex
character `prev_hash` defect in another service's output, which is the whole
reason this tooling exists.

## License

[Apache-2.0](./LICENSE).
