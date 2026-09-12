# Security Policy

agent-stack-go implements identity parsing, delegation-chain validation, and
event encoding used by every consuming service, so a bug here (e.g. a chain
that should be rejected as cyclic but isn't) is a security bug in all of them
at once. This document covers how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately, not in public issues or PRs:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/agent-stack-go/security/advisories/new>

Include the affected version/commit, a description, and a minimal reproduction.
We aim to acknowledge within a few days and to fix high-severity issues before
any public disclosure. There is no bug-bounty program; we credit reporters in
the advisory unless you prefer otherwise.

## Supported versions

The newest minor gets every fix; the previous minor gets security-relevant
fixes for 90 days after the newer one is tagged (SPEC 10 / the support
sentence decided 2026-09-12).

## Verifying a build

Every change must pass the full gate before merge: `gofmt -l .` clean,
`go vet ./...`, `go build ./...`, and `go test -race ./...`. See
[CONTRIBUTING.md](CONTRIBUTING.md).
