# agent-stack-go

**Shared Go contract types for the TAIPANBOX agent-governance stack.** This is
the public, importable home of the wire types every Go service in the stack
(Wardryx, Mockryx, and future siblings) needs to speak the same identity and
event language as TokenFuse, Idryx, Qryx, and Engram. Idryx's equivalents
live under `internal/` and cannot be imported outside that repo, which is why
this module exists: one shared source, not four drifting copies.

The stack this module supports is a defensive, self-protection system: it
exists so an organization running AI agents can govern and audit its own
agents, never to attack, surveil, or act against anyone else.

[![CI](https://github.com/TAIPANBOX/agent-stack-go/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/agent-stack-go/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)

## Packages

- **`passport`**: the Agent Passport document (`taipanbox.dev/agent-passport/v0.1`),
  one small, static JSON file per agent describing its identity, owner,
  runtime, static provisioning parent, and attestation posture. `Parse`
  decodes and validates a document; `ValidateAgentURI` and `ValidateUserURI`
  check the `agent://` / `user://` identifier format.
- **`event`**: the agent-event NDJSON envelope (`taipanbox.dev/agent-event/v0.2`,
  with `v0.1` still accepted per the compatibility rule). `Marshal` and
  `Unmarshal` for one envelope, plus an append-only `Writer` and `Scan` /
  `ReadFile` reader helpers for NDJSON files. Mirrors the Rust
  (`tokenfuse-core::agent_event`) and Python (`engram.events`) exporters
  already shipping elsewhere in the stack: one line per event, mutex-guarded,
  fail-open.
- **`chain`**: delegation-chain helpers (`Append`, `Validate`) implementing
  the v0.2 normative rule: a chain is acyclic, root-first, and capped at
  `chain.MaxDepth` (32) entries.

The canonical JSON Schemas live in the `TAIPANBOX/agent-passport` repo.
`event/testdata/agent-event.v0.2.schema.json` is a local copy used only by
this module's conformance test, so the Go bindings can never silently drift
out of lockstep with the schema that defines the wire contract.

## Install

```sh
go get github.com/TAIPANBOX/agent-stack-go
```

## Design notes

- Stdlib only at runtime: no third-party dependency is ever required to
  import and use `passport`, `event`, or `chain`. The one exception is
  `github.com/santhosh-tekuri/jsonschema/v6`, a test-only dependency used
  solely by `event`'s conformance test.
- Each package mirrors an existing internal implementation elsewhere in the
  stack (Idryx's `internal/ingest/passport` and `internal/ingest/tokenfuse`,
  TokenFuse's `tokenfuse-core::agent_event`, Engram's `engram.events`) rather
  than inventing new semantics, so adopting it is a rename, not a rewrite.
- Errors are sentinel values, checkable with `errors.Is`, not opaque strings,
  so callers can branch on failure kind without string matching.
- Malformed input is tolerated the same way the existing Idryx connectors
  tolerate it: a bad NDJSON line or passport document is skipped and
  counted, never fatal to the rest of a batch.

## Versioning

This module follows SemVer, starting at `v0.1.0`. Breaking the wire contract
(the `passport` or `event` schema) is a spec version bump, never a silent
change; the Go types version alongside the module itself.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
