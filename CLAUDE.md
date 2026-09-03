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
imported. Without this module the stack would carry six drifting copies of the
same types, one per importer in the table below. **Preventing that drift is the entire point of the repo**, and it is
the lens for every change here.

The stack this module serves is defensive: it exists so an organization can
govern and audit its own agents. Never describe it, in code comments, docs, or
commit messages, as tooling for acting against anyone else.

## Blast radius, read this before calling a change routine

This module is imported **by tag** by eight repos: `idryx`, `wardryx`,
`mockryx`, `qryx`, `heraldyx`, `scopyx`, `terraform-provider-taipan` and
`vouchryx`.

It said six until 2026-08-10 and seven until 2026-08-26, and each time the
newest importer had already been importing it. vouchryx was created on
2026-08-26 and imported this module the same day, which is the shortest that
gap has ever been and still long enough for all three places below to
disagree. scopyx joined the estate on 2026-08-09 and this paragraph, the README's
sentence and the architecture diagram's alt text all went on naming six, which
is the same shape the section below already describes about the version table:
a list kept by hand in a file that holds no status has no owner and no clock.

The count is not the fix, and writing it here again would repeat the mistake.
What found it is `estate-gates` C1, which reads every consumer's `go.mod` and
names each one it refuses. Run that rather than trusting this sentence.

A change to an exported type, an error value, or a hashing rule is a change to
all six, and consumers pin by tag specifically so they do not get it by
surprise. **They do not move together**, so "everyone gets it at once" is false
in timing and true in obligation, and the tag that has to keep working is the
oldest anybody is still on rather than the newest one cut.

**Which tag each is on is not written here, and that is the change.** This
section carried a table of it until 2026-08-09, measured by hand on 2026-08-06.
By the time it was removed every one of its six rows was wrong: five went stale
the day the consumers moved to `v0.6.0`, and the sixth had been wrong since some
earlier bump with nothing to notice, because a figure kept by hand in a file
that says it holds no status has no owner and no clock.

The owner is `estate-gates` C1, which reads the `go.mod` of every consumer and
refuses when one falls a minor behind:

```sh
cd ../estate-gates && ./run-gates.py --mode ref --ref origin/main
```

What stays here is the part that does not rot: the six NAMES, which the
README's importer list and the `docs/architecture` diagram also carry. Three
places name these repos, all three disagreed on 2026-08-05, and keeping them in
step is still somebody's job. Versions are not, any more.

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
./scripts/features-are-bound.sh
./scripts/schemas-in-sync.sh   # needs TAIPANBOX/agent-passport checked out beside this repo
./scripts/readme-numbers.sh
./scripts/reproducible-build.sh
./scripts/gates-have-teeth.sh   # invariant 14; needs a clean tree, run it after committing
```

`readme-numbers.sh` and `reproducible-build.sh` were CI-only until 2026-08-06
and were missing from this list, which meant "run every gate below" was a
smaller instruction than CI's. Every script named above runs locally and in CI.
(The sentence here used to count them, and the count went stale the moment the
list grew. A number in prose beside the thing it counts is invariant 12's shape
one file in.) Note that `reproducible-build.sh` builds from
`git archive HEAD`, so it judges the last commit and not the working tree: run
it after committing, or it will tell you about code you have already changed.

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
   package. A dependency added here lands in six consumers at once.
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
   containing it. Root-first ordering is a property of how a chain was BUILT
   and cannot be verified from the finished list, so nothing here may claim to
   check it. *(test: `TestAppend`, `TestAppendCycle`, and from the CLI side
   `TestChainReportsACyclicDelegationChain`,
   `TestChainReportsAnOverlongDelegationChain`,
   `TestChainReportsTheTwoFailureKindsDistinctly`)*
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
9. **Every event schema version keeps passing.** `v0.1`, `v0.2` and `v0.3`
   streams are all valid input to this tool; dropping support for an older one
   is a breaking change under invariant 2.

   **`agent-conform` accepts v0.3 and a CONSUMER may refuse it, and the two are
   not in tension.** v0.3 is the version an observer stamps when `agent_id`
   carries a claimed subject (SPEC 3.3, 6.4), and a consumer that has not
   decided what a self-declaration means to it is right to refuse. This tool is
   a conformance checker rather than a consumer: refusing here would make an
   honest journal fail its whole file under invariant 10, which would say the
   producer broke the contract when it did not.
   *(test: `TestCheckFileValidEventStreamV01`,
   `TestCheckFileValidEventStreamV02`, `TestCheckFileValidEventStreamV03`,
   `TestCheckFileClaimedSubjectConformsOnlyUnderV03`)*
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

12. **The release asset names carry no version, and that is a contract with
    the outside world rather than a style choice.** it-rat.com links straight to
    `releases/latest/download/<name>`, an address that resolves only while the
    name is stable, so putting a version back into `out=` in `release.yml` turns
    every download link on that site into a 404 at the next tag. Nothing in CI
    would say so; the person who finds out is somebody trying to install this.
    The version is not lost, it moves into the binary, where `-X main.version`
    already puts it and where `agent-conform -version` reads it back. That is the harder of
    the two places to fake: anything between us and a reader can rename a file,
    and nothing between us and a reader can restamp the bytes.
    *(gate: `scripts/reproducible-build.sh`, which reads `out=` out of the
    workflow and refuses if it contains VERSION, and refuses just as loudly if it
    finds no asset name at all, because a check that goes green once its subject
    has vanished is worse than no check. Verified by breaking: putting the version
    back fails it in all four repositories that share this shape.)*

13. **Every vendored schema is byte-identical to the copy agent-passport
    owns.** This module does not define the wire contract, it implements one,
    and the schemas under `cmd/agent-conform/schemas/` and in the packages'
    `testdata/` are copies, vendored so the tool is one static binary and the
    tests run offline. Copies drift; preventing exactly that is why this repo
    exists, so a copy of somebody else's file with nothing comparing the two is
    this repo's own failure mode one level down.
    *(gate: `scripts/schemas-in-sync.sh`, which compares every tracked file
    named like a canonical schema against `../agent-passport/schemas/`, byte
    for byte. Copies are discovered rather than listed, so a new one is covered
    the day it is committed. It refuses when the sibling is absent, when it
    found nothing to compare, and when this repo holds a schema-shaped file
    agent-passport does not own. Verified by breaking, three ways: a drifted
    copy, a missing sibling, and a canonical set sharing no names with ours,
    each of which fails it. CI checks the sibling out beside this repo in the
    `schemas` job.)*

    Added 2026-08-05, after the vendored Passport schema was found to be 69
    lines against the canonical 114: the whole `filesystem` (SPEC 4.4) and
    `models` (SPEC 4.5) declarations were missing. The way it failed is the
    part worth keeping. A Passport allows `additionalProperties`, so a property
    the schema does not DECLARE is not checked loosely, it is not looked at at
    all: `agent-conform` read `"mode": "delete"`, a mode SPEC 4.4 does not
    have, and printed `OK` under what the README calls full schema validation.
    A silent pass on a field nobody validates is worse than a missing check,
    because it is indistinguishable from a real one.

    The canonical is read from its default branch, unpinned. A change over
    there turns this red with no change here, and that is the signal rather
    than the bug. A recorded digest was the alternative and was rejected: it
    holds our own side of the agreement only, which is the shape invariant 11
    exists to name.

14. **A check must be able to tell "did not fail" from "did not run", and every
    gate here has been made to fail on purpose to prove it can.** Three of the
    four gates above already refuse when their subject is absent, and
    invariants 11, 12 and 13 each say so in a sentence. Those sentences were
    true. Every one of them was established by hand, once, in the session that
    wrote the script, and nothing re-ran them.

    That is the shape this invariant is about rather than any one gate. A text
    parser does not break loudly: it stops matching and reports success. The
    mutants that proved these gates lived in commit messages and in the
    `*(gate: ...)*` markers above, which is a record of what was true once.

    Across idryx and tokenfuse on 2026-08-09 the same harness caught five
    mutations that changed no bytes, and three of the five had been verified by
    hand against the same gate minutes earlier. The hand version and the
    harness version differ only in how many layers of quoting sit between the
    text and python. So every mutation asserts it applied: a case whose edit
    changed nothing is a failure, not a pass.
    *(gate: `scripts/gates-have-teeth.sh`, 18 cases: eight real faults each gate
    must catch, four non-faults they must not, and six subjects taken away
    entirely, where the gate must say it measured nothing rather than report
    OK. It said 12 until `features-are-bound.sh` arrived on 2026-08-26 with four
    cases of its own, and it said 16 until the version-badge half of
    `readme-numbers.sh` arrived on 2026-09-03 with two cases of its own, which is
    invariant 12's shape inside the file that holds it: the count is updated in
    the commit that changes it, because somebody looks.
    `./scripts/gates-have-teeth.sh | grep -c '^ok '` is the command. The third non-fault arrived on 2026-08-26 and is the first here that
    runs a gate under a HOOK'S ENVIRONMENT rather than in a plain shell,
    because the fault it pins exists only there: `schemas-in-sync.sh` reads
    another repository, git exports GIT_DIR into a hook, and `git -C` keeps it. It runs in the `schemas` CI job rather than `build`, because one of the
    four gates needs the sibling repository checked out beside this one, and in
    `build` that case would fail for the wrong reason.)*

    **What it does not cover.** It cannot test itself; nothing watches this one
    fail. It proves each gate catches the faults named in it, not every fault
    of that kind. And it found no hole in any of the four, which is the result
    to expect from a ratchet on the day it is installed.

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

15. **`delegation` verifies with what the process already holds, and never
    reaches out.** `Options` carries a key set, an issuer, an audience, a
    clock, a proof and two optional hooks. There is no client, no URL and no
    timeout, so a check cannot become a network round trip by accident. wardryx
    decides at a 3.2 ms p50 and audits every decision; putting signature
    verification behind a round trip taxes every decision in the estate and
    makes the token service a hard dependency of every enforcement point at
    once, which is the shape `dependency_failed` was cut to record.
    *(test: `TestVerificationTouchesNothingOutsideTheProcess`, which asserts the
    SHAPE of `Options` rather than observing no traffic today)*

16. **A sender-constrained token is never checked as a bearer token.** A token
    carrying `cnf.jkt` presented with no proof is REFUSED, not accepted with
    the binding skipped. An enforcement point that simply forgot to pass a
    proof would otherwise report success while honouring a stolen token, and
    that is the failure this whole scheme exists to prevent.
    *(test: `TestASenderConstrainedTokenCheckedWithoutAProofIsRefused`,
    `TestATokenPresentedByTheWrongHolderIsRefused`)*

17. **`delegation` READS a chain and does not claim to verify its order.**
    Invariant 5 already says root-first ordering is a property of how a chain
    was BUILT and cannot be checked from the finished list. The signature
    guarantees the issuer put those names in that nesting; that the nesting
    means what the issuer intended is the issuer's to get right. `Verified`
    says so in its own doc comment, because a field called `Chain` on a struct
    called `Verified` invites exactly the wrong reading.
    *(not enforced; it is a claim this module declines to make)*

18. **The chain hash is computed over the object as written, never over a
    re-marshal of this package's model of it.** SPEC 6.5 says `C` is the JCS
    serialization of "the event object" with `prev_hash` removed. An `Event` is
    a MODEL of an event object, and the two stop being the same thing the
    moment the spec registers a member this struct does not carry.

    `delegation_proof` (SPEC 5.2) did exactly that on 2026-08-26, and it is a
    top-level sibling of `data` rather than a member of it precisely because
    `data` is the producer's free-form room and a proof is not free-form. So
    the one decision that made the field trustworthy also walked it into the
    one place this package was lossy: `data` is `map[string]any` and survives,
    the top level does not.

    Two call sites had the line in hand and hashed the parse of it instead.
    `VerifyChain` reported an honestly chained stream as a break, which is our
    own conformance tool accusing a conformant producer of tampering. Worse,
    `NewChainedWriter` resumed a chain from the same lossy digest, so appending
    to a file whose tail carried the member FORKED the chain on disk rather
    than reporting anything. A false accusation is loud; a silent fork is not.

    `Canonicalize` and `ChainHash` are kept and are correct where the struct is
    the ORIGIN of the line, which is the producer's case and nothing else.
    Their doc comments say so at length. `CanonicalizeRaw` and `ChainHashRaw`
    take the line, and every verification and every resume goes through them.
    *(test: `TestAChainedStreamSurvivesAMemberThisStructDoesNotModel`,
    `TestResumingAChainHashesTheLineOnDiskAsWritten`. Nothing STOPS a future
    call site from reaching for the struct-shaped pair; the names and the doc
    comments are what stand between it and this bug returning.)*


19. **A list somebody can be told about is a list something reads, and its AGE
    is a decision rather than an accident.** vouchryx has served
    `GET /v1/revocations` since the day it was written, with an `as_of` cursor
    put there so a poller could tell an empty list from a failed fetch. Measured
    2026-08-26: nothing polled it. No consumer of this module set
    `Options.Revoked`, tokenfuse's two doors passed a closure answering false,
    and four documents in two repositories said in the present tense that every
    enforcement point consults it. This module's README was one of them, and it
    is corrected in the same wave: the rule here is to change the text rather
    than to narrate the change.

    `Revocations` is the local cache `Options.Revoked` is filled from.
    **Invariant 15 is intact and this is the seam that keeps it so: the FETCH is
    out of band and the CHECK is local.** `Check`, `Hook`, `Age`, `AsOf` and
    `RejectedBackwards` take no `context.Context` and return no `error`, so they
    cannot block and have nowhere to send a request; `Fetch` and `Refresh` take
    one, because they can. That is a shape rather than a promise, and the test
    asserts the shape from both sides, since a check that found no context
    anywhere would pass on a package with no network code at all.

    **Age decides what a MISS means and never what a HIT means.** The estate has
    answered "a dependency is unreachable" twice, both times with an
    operator-chosen fail mode defaulting to open. `FailMode` here is the same
    word and DELIBERATELY not the same default, and the difference is stated
    rather than hidden: an unreachable PDP says nothing, so opening decides a
    question no answer was coming for, while an unreachable revocation list
    says one narrow thing, which is that this authority can no longer be
    confirmed. Open there is also an attack primitive, since it makes revoking
    conditional on one service being reachable and does so silently. What a
    revocation list adds on top is that a stale list is still mostly right: one
    from four minutes ago holds every revocation older than four minutes. So a hit
    stands at any age, because nothing un-revokes a token and discarding one we
    hold would call a token we know is dead a live one. A miss is an inference
    from the list being COMPLETE, completeness is what expires, and past
    `DefaultRevocationMaxAge` the fail mode answers a miss instead.

    **One minute is the number, and it is the window in which a revoked token
    still works.** It comes from the token rather than from taste: vouchryx
    mints at a five-minute default TTL and caps at an hour, so a list allowed to
    outlive a token would let one minted after the last poll be revoked and go
    on working for its whole life, which makes the control decorative for a
    whole generation of tokens rather than merely late.

    **Never fetched is not stale, and an older answer never replaces a newer
    one.** `BasisNever` and `BasisStale` both defer to the fail mode and are
    different faults: a poller nobody wired does not clear itself and nothing
    else in the estate will mention it. A snapshot whose `as_of` moved backwards
    is refused and counted, because installing it would reset the age and a view
    that had stopped moving would start reading as fresh, which turns every
    other rule here off. Equal cursors ARE accepted: `as_of` is a Unix second
    and refusing that would break any poller faster than 1 Hz.
    *(scenarios: `features/revocation.feature`, each bound to a named test, held
    by `scripts/features-are-bound.sh`, which is invariant 20. Test:
    twenty-five in `delegation`, of which
    `TestARevokedDelegationIsRefusedByVerifyAfterAPollPicksItUp` is the one this
    exists for, running the whole path over a real socket, and
    `TestATokenTheListDoesNotNameIsNotRefused` is its negative control, since a
    cache that refused everything would pass it. Every one of the twenty-five was run against
    a `Check` stubbed to what a nil `Options.Revoked` does today, and sixteen
    went red there, verbatim among them `after the revocation Verify must refuse
    it, got <nil>`. Fifteen of the sixteen were run in one pass before the code
    existed; the sixteenth,
    `TestANonTwoHundredAnswerIsNeverReadAsAnEmptyList`, was written afterwards to
    close a surviving mutant and was run against the same stub separately rather
    than being folded into that count on the strength of an argument.

    Eleven mutants planted in the product code on 2026-08-26. Ten were caught
    and **one survived, which is the finding worth keeping**: with the HTTP
    status check deleted, the whole suite stayed green, because the test that
    was supposed to hold it served a 500 whose body was not JSON, so the PARSER
    was doing the refusing and the status check could have been removed in
    silence. `TestANonTwoHundredAnswerIsNeverReadAsAnEmptyList` closes it with a
    503 carrying a perfectly well-formed body, which is what a gateway, a mesh
    or a cache in front of vouchryx actually answers, and it goes red under that
    mutant.)*

    **Where it says nothing.** Nothing here polls: a caller runs `Refresh` on
    its own schedule, and no consumer of this module does yet, so this is a
    cache with no poller exactly as `Verify` is a verifier with no caller. It
    holds no store, so a restart starts at `BasisNever` and the fail mode
    governs until the first poll lands. And it cannot tell a vouchryx that
    restarted and forgot its whole list from one whose entries legitimately
    expired: both answer an empty list with a current cursor, and vouchryx's own
    README names the in-memory store under NOT PROVEN for that reason.

20. **Every scenario names a test that exists, and every scenario names one at
    all.** A scenario bound to nothing is a paragraph describing what somebody
    wanted and proves nothing about the code; a binding pointing at a renamed or
    deleted test is worse, because it reads as held and no reader can tell
    without grepping. Two different lies, and only one of them is visible from
    either side alone.

    Not a BDD runner, deliberately: godog here, cucumber-rs in the Rust repos
    and pytest-bdd in the Python ones would be three runners and three
    step-definition styles across an estate whose ask was readability, which the
    binding delivers at a fraction of the surface. tokenfuse and vouchryx
    reached the same conclusion and this script is vouchryx's, with the counting
    made safe on a machine without `bc`.

    What it does NOT do is check that a test asserts what its scenario says, and
    nothing mechanical can: the steps are prose and the binding is a pointer.
    What it catches is the pointer breaking, which is the failure that happens
    on its own while nobody is looking.
    *(gate: `scripts/features-are-bound.sh`, with four cases in
    `gates-have-teeth.sh`: a binding renamed to a test that does not exist, a
    scenario with no binding, a test named in PROSE which must NOT fire it, and
    every feature file removed, where it must say it measured nothing rather
    than report OK on an empty set)*

21. **The door never hands out a chain the record will refuse, and the two
    enforce that twice on purpose.** `chain.Validate` is what the RECORD
    applies. `delegation.Chain` is what a DOOR applies to a token it has just
    verified. `scripts/deps-layering.sh` requires `delegation` to depend on the
    standard library alone, so it cannot call `chain.Validate`: the rules exist
    in two places by construction, and two rules that must agree with nothing
    comparing them is the shape this estate found nine times in two days.

    Measured 2026-08-27, twice in one afternoon. The DEPTH cap: the door bounded
    ACTORS at 32 while the record counts ENTRIES, so a subject plus 32 actors
    verified and every record it produced was refused as 33 entries. The CYCLE
    rule: the record has refused a repeated principal since it was written and
    the door did not, so a chain naming one principal twice verified and its
    trail could not be written.

    The second is the trap `BuildAct` invites. Its doc example passes a whole
    root-first chain, root included, so the root lands inside `act` while also
    being the token's `sub`. vouchryx does not do that, measured on a live token
    the same day, which is why it was a trap and not an outage. A documented
    trap is not a removed one, so the door refuses the shape instead.
    **A third rule was hidden by the gate's own alias.** Its first draft mapped
    the record's `ErrInvalidEntry` onto the door's `ErrNoSubject`, and those are
    not the same rule: the record refuses an entry that is not an `agent://` or
    `user://` URI, and the door refused only an EMPTY one. So a token naming
    `mailto:alice` verified and its trail could not be written, while the gate
    reported agreement. **A gate that agrees over a weaker check is worse than no
    gate, because it says the question was asked.** The door has the rule now,
    the alias map is empty, and an alias may go back only where two packages
    genuinely name ONE rule two ways.
    *(gate: `scripts/door-and-record-agree.sh`, which DISCOVERS the record's
    rules from the errors `Validate` can return rather than listing them, and
    strips comments before reading either side. Its own first draft did not:
    it scanned the whole file, `delegation/chain.go` names its errors in the doc
    comments above them, and renaming a rule away left the name in prose and the
    gate went on agreeing. Three teeth cases in `gates-have-teeth.sh`)*
