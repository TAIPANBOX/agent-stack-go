#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY
#
# Every gate here parses text, and a text parser does not break loudly: it
# stops matching and reports success. The mutants that proved each one existed
# as prose, in commit messages and in the `*(gate: ...)*` markers in CLAUDE.md,
# which is a record of what was true once. Nothing ran them again.
#
# A gate that has quietly stopped catching anything looks exactly like a gate
# with nothing to catch, and stays that way until the fault it guards ships.
#
# WHY THE THIRD PROPERTY IS SEPARATE FROM THE FIRST
#
# Three of these four gates already refuse when their subject is absent, and
# CLAUDE.md says so in invariants 11, 12 and 13. Those sentences were true and
# nothing re-established them. A check that cannot tell "did not fail" from
# "did not run" is the most expensive recurring mistake in this estate's
# tooling, and it lives in tooling rather than product code because tooling is
# where a silent pass looks like a result.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success.
#
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# No case proves anything if the gate was already failing before the mutation.
# So every case runs the gate on the UNMUTATED tree first and reports
# UNJUDGEABLE. Found on 2026-08-09 in it-rat, where one gate was legitimately
# red and a case against it would have been indistinguishable from a working
# one.
#
# It covered only the fail-cases at first, which left the mirror of the same
# bug: on a red gate a pass-case reports OVEREAGER, "the gate failed on
# something it must not catch", and sends the reader to look at a harmless
# mutation. The verdict was being given without the predicate it depends on.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file. A case whose edit applied nothing is
# a failure here, not a pass. That is not hypothetical: five such mutations
# were caught across idryx and tokenfuse on 2026-08-09, and three of the five
# had been verified BY HAND against the same gate minutes earlier. The hand
# version and the harness version differ only in how many layers of quoting sit
# between the text and python, which is exactly the difference nobody sees.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

# Untracked files too: a mutation may RENAME a tracked file, and `git checkout`
# restores the original while leaving the new name behind. And the INDEX, since
# a gate may read `git ls-files` rather than the disk, so a mutation has to move
# the file in both. Safe because this
# script refuses to start unless the tree is clean, so anything untracked
# during a run was created by the run. `-x` is deliberately absent: ignored
# build output is not ours to delete.
restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
}
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first
# rather than adding to it. Writing them separately disarmed `restore` on
# every interrupt path, which would leave a mutated tree behind on Ctrl-C.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM


failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The needle separates "it failed" from "it failed for the reason this case is
# about". Without it, a case expecting failure is satisfied by any failure,
# including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	# The baseline applies to EVERY case, not only the ones expecting a failure.
	# It was `fail`-only until 2026-08-09, which left the mirror of the bug it was
	# written for: on a gate that is already red, a `pass` case reports OVEREAGER,
	# "the gate failed on something it must not catch", and sends the reader to
	# look at a harmless mutation while the gate was failing without it. Neither
	# verdict means anything on a red gate, so neither is given.
	skip_baseline=0
	if [ "$expect" = fail_env ]; then
		# `fail` with the baseline skipped, for cases whose fault IS the command
		# rather than a mutation: red before and after is the point there.
		expect=fail
		skip_baseline=1
	fi

	if [ "$skip_baseline" = 0 ]; then
		local key base_out
		key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
		if [ ! -f "$key" ]; then
			if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
		fi
		base_out="$(cat "$key")"
		if [ "$base_out" = red ]; then
			printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so neither a\n             failure nor a pass after the mutation would prove anything\n' "$name"
			failures=$((failures + 1))
			return
		fi
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
		printf '%s\n' "$out" | head -4 | sed 's/^/           /'
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

echo "=== faults each gate must catch ==="

# invariant 1. The import is one the module already has, so go.mod does not
# move and the package still resolves: a mutation that stops the tree building
# fails the gate on the BUILD and proves nothing about the check.
run_case "deps-layering: a library package takes a third-party import" fail \
	'./scripts/deps-layering.sh' \
	"$(py 'edit("passport/load.go", "import (", "import (\n\t_ \"github.com/gowebpki/jcs\"")')" \
	"imports third-party"

run_case "readme-numbers: a stale test badge" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-(\d+)-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/tests-%d-" % (int(m.group(1))+7), 1))')" \
	"the badge says"

# invariant 11: the three flags must be in the workflow, not only in the script.
run_case "reproducible-build: the workflow loses a build flag" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "go build -trimpath", "go build")')" \
	"builds the release without"

# invariant 12: the published name is an address other people link to.
run_case "reproducible-build: a version back in the asset name" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "out=\"agent-conform_", "out=\"agent-conform_${VERSION}_")')" \
	"carries the version"

# invariant 13: a vendored copy that drifted from the owner of the contract.
# This check reads ANOTHER repository, and git hands a hook GIT_DIR pointing at
# the repository being pushed. `git -C <elsewhere>` keeps that variable, so
# every ref this script resolves and every blob it reads would come out of THIS
# repository's object database while pointed at agent-passport's working tree.
#
# Measured 2026-08-26, before and after the fix, with AGENT_PASSPORT_DIR set:
# the old script exits 0 in a shell and 1 under a leaked GIT_DIR; the fixed one
# exits 0 in both. That difference is what this case pins, and only running the
# gate under a hook's environment can see it.
#
# No matching `fail` case putting the leak back: this gate needs a real
# agent-passport checkout, which CI provides and a bare machine may not, so a
# case whose subject is conditional would report TOOTHLESS where it is absent.
# The fail direction is pinned by the measurement in schemas-in-sync.sh's own
# comment. tokenfuse and trailryx reached the same shape on the same day.
run_case "schemas-in-sync: the same answer under a hook's environment" pass \
	'GIT_DIR="$PWD/.git" ./scripts/schemas-in-sync.sh' \
	""

run_case "schemas-in-sync: a vendored schema drifts from the canonical" fail \
	'./scripts/schemas-in-sync.sh' \
	"$(py 'edit("cmd/agent-conform/schemas/agent-passport.schema.json", "\"type\"", "\"TYPE\"")')" \
	"has drifted from the canonical"

echo
echo "=== and what they must NOT catch ==="

run_case "deps-layering: a stdlib import added to a library package" pass \
	'./scripts/deps-layering.sh' \
	"$(py 'edit("passport/load.go", "import (", "import (\n\t_ \"sort\"")')"

run_case "readme-numbers: a badge-shaped number elsewhere in the README" pass \
	'./scripts/readme-numbers.sh' \
	"$(py 'edit("README.md", "## ", "Once badge/tests-11- was the figure, long ago.\n\n## ")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "readme-numbers: no badge left to compare against" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-\d+-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/nothing-", 1))')" \
	"nothing to compare against"

run_case "readme-numbers: VALIDATION.md stops stating the same figure" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("VALIDATION.md").read()
m = re.search(r"^\d+ tests across", s, re.M)
assert m, "VALIDATION.md does not open with an N-tests line"
open("VALIDATION.md","w").write(s.replace(m.group(0), "Many tests across", 1))')" \
	"measured nothing"

run_case "reproducible-build: no build command left to read" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "go build -trimpath", "go vet -trimpath")')" \
	"no 'go build' command found"

run_case "schemas-in-sync: no vendored copy left to compare" fail \
	'./scripts/schemas-in-sync.sh' \
	"$(py 'import subprocess
out = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
n = 0
for f in out:
    if f.endswith(".schema.json"):
        # git mv, not os.rename: this gate lists copies with `git ls-files`, so
        # a file moved only on disk is still named by the index and reads as a
        # drifted copy rather than an absent one.
        subprocess.run(["git", "mv", f, f[:-len(".schema.json")] + ".vendored.json"], check=True)
        n += 1
assert n, "no schema-shaped file tracked in this repo"')" \
	"measured nothing"

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
