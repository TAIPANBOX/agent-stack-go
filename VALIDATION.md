# Validation

Every other repository in this stack carries a `VALIDATION.md`, and this one
did not, which was an omission rather than a decision. This file says what has
actually been checked about the shared contract, and what has not.

The contract is a small thing that everything else depends on, so the useful
question is not "does it pass its tests" but "does it agree with the six other
implementations that import it, on real files they produced".

## Its own test suite

167 tests across `passport`, `event`, `chain`, `delegation` and `cmd/agent-conform`, green on
`go test ./... -count=1`. CI additionally gates on `gofmt`, `go vet`,
`staticcheck`, `go test -race`, `go build`, `govulncheck`, and on the two
claims this file used to make in prose: that the vendored schemas still match
the repository that owns them (`scripts/schemas-in-sync.sh`) and that this
number is the number (`scripts/readme-numbers.sh`, which reads both this file
and the README badge, because the count went stale here first).

The one worth naming: a conformance test that validates this module's own types
against the **canonical `agent-event` JSON Schemas** from the
[agent-passport](https://github.com/TAIPANBOX/agent-passport) spec, rather than
against a copy of its own beliefs. A contract library that only checks itself
proves nothing.

## Where it has been checked against real output

`agent-conform` carries embedded copies of the canonical schemas and has been
run against real fixtures produced by other services in the stack, not against
files written to please it.

**It caught a real defect that way:** a `prev_hash` value 63 hex characters
long where the chain requires 64. That is exactly the class of bug this tooling
exists for. It is invisible to the eye, it does not break any consumer that
merely reads the field, and it silently destroys the integrity chain's meaning,
because a chain nobody verifies is a chain that proves nothing. Nothing else in
the stack would have found it.

Two deliberate properties made that possible and are worth stating, because
both are the opposite of the convenient choice:

- **Unrecognised content is a FAIL, never a skip.** Files are classified by
  their own `schema` field, and anything the checker does not recognise fails
  the run. A conformance tool that quietly skips what it does not understand
  reports success on the files it never looked at.
- **Exit 0 or exit 1, and nothing in between.** It is meant to sit in CI, so
  the interface is an exit code, not a report somebody has to read.

## In a live cluster

`agent-conform -chain` verifies a journal in one command, and was used that way
on the five-node clusters run across Hetzner, AWS and GCP between 25 and 27
July 2026 (see [stack-k8s](https://github.com/TAIPANBOX/stack-k8s)). Every
governance event the stack emits carries the SHA-256 of the event before it,
computed over RFC 8785 canonical JSON, across restarts, and the chain those
records sit in verifies.

Canonical JSON is load-bearing here rather than stylistic: the chain hashes
over the canonical form, so two encoders that disagree about key order or
number formatting would produce two different hashes for the same event and
break the chain without either of them being wrong about JSON.

## What is NOT validated

Stated plainly, because the omissions matter more than the passes:

- **This is metadata, not a token.** A Passport is not a credential, the spec
  is not an authentication protocol, and nothing here verifies that an agent is
  who its passport says it is. Attestation is a field, not a proof.
- **No performance claims.** Nothing here has been benchmarked, because nothing
  in this module sits in a hot path: it parses, validates and appends.
- **The chain proves ordering and integrity, not honesty.** It shows that a
  journal has not been altered after the fact. It cannot show that what was
  written was true when it was written.
