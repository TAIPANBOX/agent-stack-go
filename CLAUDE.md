# CLAUDE.md, working instructions for agent-stack-go

These instructions apply to any model working in this repo. Read this file
before writing code. It holds process and invariants only: **no status.**
Status goes stale, and a stale instruction file is worse than none. For where
the code actually is, read the git tags, `VALIDATION.md`, and the README.

## Read before you change anything

1. `README.md`, specifically the "Where this fits in the stack" diagram. This
   module is a contract, not a service, and the diagram says who depends on it.
2. The **agent-passport SPEC** in the sibling repo `TAIPANBOX/agent-passport`.
   This module implements it; the spec is normative and this code is not. When
   the two disagree, the spec wins and the code is the bug.
3. `cmd/agent-conform/schemas/`. The vendored JSON schemas are the machine
   form of the spec, and the conformance tests run against them.
4. `VALIDATION.md` for what has actually been measured versus asserted.

There is no prose architecture document in this repo. `docs/` holds the
rendered diagrams only. If you need the reasoning behind a wire-format choice,
it is in the agent-passport SPEC, not here.

## What this module is, and why it exists

One Go module holding the Agent Passport identity types, the agent-event NDJSON
envelope, the delegation chain, and the `prev_hash` integrity chain, so every Go
service in the stack speaks one wire language.

It exists because Idryx's equivalents live under `internal/` and cannot be
imported. Without this module the stack would carry four drifting copies of the
same types. **Preventing that drift is the entire point of the repo**, and it is
the lens for every change here.

The stack this module serves is defensive: it exists so an organization can
govern and audit its own agents. Never describe it, in code comments, docs, or
commit messages, as tooling for acting against anyone else.

## Blast radius, read this before calling a change routine

This module is imported **by tag** by at least four repos: `idryx`, `wardryx`,
`mockryx`, `terraform-provider-taipan`. A change to an exported type, an error
value, or a hashing rule is a change to all of them at once, and consumers pin
by tag specifically so they do not get it by surprise.

Consequence: there is no such thing as a small change to a public signature in
this repo. Either it is additive and backward compatible, or it is a version
decision that needs the user before it is written.

## The working loop

This repo uses **PR flow**, not push to main (unlike idryx and qryx).

1. Branch off `main`, one logical increment per branch.
2. Run every gate below. All must pass locally before the push.
3. Commit with Conventional Commits. End the message with the standard
   co-author trailer naming the model that actually did the work.
4. Push the branch, open a PR with `gh`.
5. Wait for all CI checks to go green. Fix forward, do not force-push over red.
6. **Ask the user before merging.** Do not self-merge.

If you are working in parallel with another session, use `git worktree add`.
The main checkout is shared.

## Gates

```sh
test -z "$(gofmt -l .)"
go vet ./...
staticcheck ./...
go test -race ./...
go build ./...
./scripts/deps-layering.sh
```

`make lint` runs gofmt plus vet plus staticcheck. Note that `make staticcheck`
**skips silently** when staticcheck is not installed, so a green `make lint` on
a machine without it proves less than it looks. CI installs it and does not
skip. Install locally with
`go install honnef.co/go/tools/cmd/staticcheck@latest`.

CI additionally runs `govulncheck ./...` in a separate `security` job. Run it
before touching `go.mod`.

## Hard invariants

Each one carries how it is held today. Three markers only, and `(not enforced)`
is used wherever it is true. An invariant with no check, written as though it
had one, is worse than an absent invariant.

1. **Library packages stay dependency-clean.** `passport` and `chain` import
   the standard library only. `event` has exactly one third-party import,
   `github.com/gowebpki/jcs`, and it is there because RFC 8785 canonicalization
   is required by SPEC 6.5. `github.com/santhosh-tekuri/jsonschema/v6` is for
   `cmd/agent-conform` and tests only and must never appear in a library
   package. A dependency added here lands in four consumers at once.
   *(gate: `scripts/deps-layering.sh`)*
2. **A change to an exported type, constant, or error value is a version
   decision, not an edit.** Consumers pin by tag. Additive and backward
   compatible, or ask the user first. *(not enforced)*
3. **This module is the single source of the wire types.** If a consumer needs
   a type that is nearly one of these, the answer is to widen the type here,
   never to copy it there. *(not enforced)*
4. **`chain.Append` never mutates or aliases its input.** It always allocates
   its own backing array, so two chains derived from one parent cannot corrupt
   each other. *(test: `TestAppendDoesNotMutateInput`,
   `TestAppendNoAliasingBetweenSiblingChains`)*
5. **Delegation-chain rules are the spec's, not ours:** acyclic, at most
   `MaxDepth` (32) entries, every entry an `agent://` or `user://` URI, and an
   empty chain is valid and means the agent acts autonomously. A service
   appends exactly one entry, its own principal, and rejects a chain already
   containing it. *(test: `TestAppend`, `TestAppendCycle`)*
6. **`prev_hash` is computed over RFC 8785 canonical JSON with the `prev_hash`
   field removed by construction, never by string surgery**, and always
   carries the `sha256:` prefix. Removing the field textually is the bug this
   invariant exists to prevent. *(test: `TestChainPassesACleanStream`,
   `TestChainFailsOnATamperedLine`)*
7. **A chain restart is not a chain break.** The spec keeps `prev_hash`
   optional, so a stream may legally restart, for example after a process
   restart that could not resume. Report restarts separately from breaks, and
   only a genuine mismatch is a break. *(test: `TestChainRestartIsNotAFailure`)*
8. **`prev_hash` is tamper-evidence, not tamper-proof.** Somebody who can
   rewrite the whole file can re-chain it. The value is that a partial edit, a
   truncation, or a reordered shipment stops passing silently. Never let a
   README, doc comment, or commit message imply more than that.
   *(not enforced)*
9. **Both event schema versions keep passing.** `v0.1` and `v0.2` streams are
   both valid input; dropping support for the older one is a breaking change
   under invariant 2. *(test: `TestCheckFileValidEventStreamV01`,
   `TestCheckFileValidEventStreamV02`)*
10. **One bad line fails the whole file.** `agent-conform` does not partially
    accept a stream. Blank lines are skipped and are not content.
    *(test: `TestCheckFileEventOneBadLineFailsWholeFile`,
    `TestCheckFileBlankLinesSkippedNotCountedAsContent`)*

11. **A published `agent-conform` can be rebuilt, byte for byte, by the person
    receiving its verdict.** This tool decides whether somebody else's payload
    conforms to the contract, and a verdict is worth what its checker is worth,
    so the checker is the first thing a careful reader pins down. "The source is
    open" is not an answer to them; it always was. Three flags hold it,
    `CGO_ENABLED=0`, `-trimpath` and `-s -w`, and they must stay identical in
    `scripts/reproducible-build.sh` and `.github/workflows/release.yml`. Losing
    one breaks the property in **silence**: the build still succeeds, the
    binaries stop matching, and the only person who finds out is the one trying
    to verify us.
    *(gate: `scripts/reproducible-build.sh`, in two halves. It reads the `go
    build` command out of `.github/workflows/release.yml`, joining backslash
    continuations first so it judges the whole command, and refuses if any of
    the three flags is absent there or if no build command is found at all.
    Then it builds the same source in two directories of deliberately different
    lengths and refuses if a byte differs. Verified by breaking, four ways:
    deleting each flag from the workflow in turn, and swapping the hand-rolled
    matrix for a tool, each of which fails it. The same three flags were
    measured against real published artifacts in qryx and idryx on 2026-08-05,
    each rebuilding to its release byte for byte from a different host OS.)*

    The first half was added on 2026-08-05 because the sentence above claimed
    the two files agree and nothing compared them. The script kept all three
    flags, so it kept passing, and it would have gone on passing while the
    workflow lost one. A gate that holds only its own side of an agreement is
    not holding the agreement.

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Held by this file alone: invariants 2, 3 and 8.** All three are judgement
calls about intent, not structure, and they probably stay judgement. Nothing
can mechanically tell an additive type change from a breaking one in the sense
that matters to a consumer, and nothing can tell an honest README from an
over-claiming one.

Invariant 1 used to be on this list. It is now `scripts/deps-layering.sh`, and
that script is the ONE copy of the check: the local hook and CI both call it,
never their own inline version, because two copies of one check always diverge.

When you add an invariant here, ask whether it is structure or judgement. If it
is structure, it belongs in a script the same session, not on this list.

## Standing rule

An approved architecture decision is **not finished** until it is two things: a
numbered invariant in this file, and a gate in a script if it can be checked
structurally. Until then it is a document, and documents do not stop code.

When the user approves a decision, add it here in the same session. Do not defer
it to "later", because later is where the drift lives.

## Escalate, do not push through

Stop and tell the user, then wait, when a task hits any of these:

- Any change to an exported type, error value, or hashing rule. See blast
  radius above.
- Cutting a tag or a release, or any other outward-facing action.
- Adding a dependency to `go.mod`.
- Any disagreement between this code and the agent-passport SPEC, because the
  resolution may belong in the spec repo instead.

Routine work that does not need escalation: tests, doc comments, internal
refactors that keep every exported signature identical, and additions to
`cmd/agent-conform` that do not change library packages.

## Conventions

- **No long dashes** anywhere: not in code comments, docs, commit messages, or
  PR bodies. Use a comma, a colon, parentheses, or a short hyphen.
- Nothing paid or metered gets enabled without telling the user first and
  getting agreement. This includes anything that would start metering CI.
- Do not delete or revoke keys, tokens, or certificates on your own initiative.
