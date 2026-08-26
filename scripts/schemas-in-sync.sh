#!/usr/bin/env bash
# Enforces invariant 13 of CLAUDE.md: every copy of a schema this repo keeps is
# byte-identical to the copy in the repo that OWNS it, TAIPANBOX/agent-passport.
#
# WHY THIS IS WORTH A GATE RATHER THAN A SENTENCE
#
# This module does not define the wire contract, it implements it. The schemas
# under cmd/agent-conform/schemas/ and in the packages' testdata are copies,
# vendored so the tool can be one static binary and the tests can run offline.
# A copy of somebody else's file, with nothing comparing the two, drifts. That
# is not a hypothesis here: on 2026-08-05 the vendored Passport schema was 69
# lines against the canonical 114, missing the whole filesystem (SPEC 4.4) and
# models (SPEC 4.5) declarations, and had been for three weeks.
#
# The way it fails is the part worth writing down. A Passport document allows
# additionalProperties, so a property the schema does not DECLARE is not checked
# loosely, it is not looked at at all. agent-conform read a passport whose
# filesystem entry said `"mode": "delete"`, a mode SPEC 4.4 does not have, and
# printed OK. The README calls that "full schema validation". Every layer above
# it was honest; the file underneath had quietly stopped being the contract.
#
# WHAT THIS CHECKS
#
# Every file in this repository whose name matches a schema agent-passport ships
# is compared, byte for byte, against agent-passport's own copy. Copies are
# DISCOVERED among the files git tracks, not listed: a fifth copy added next
# year is covered the day it is committed, and a list nobody updates is how this
# class of bug arrives in the first place. Tracked files only, on purpose, the
# same rule reproducible-build.sh uses: a stray file in somebody's working tree
# is not part of this repository and must not be able to change the answer.
#
# It also refuses when it found nothing to compare, and when this repo holds a
# schema-shaped file agent-passport does not own. A check that goes green once
# its subject has vanished is worse than no check.
#
# WHY THE SIBLING REPO AND NOT A PINNED DIGEST
#
# A digest recorded here would hold our own side of the agreement only: it says
# the vendored file has not been edited, which is not the question. The question
# is whether it still equals a file another repo owns, and only that repo's file
# can answer it. Recording a digest instead would rebuild, exactly, the failure
# invariant 11 was written about, a gate holding one side of a two-sided rule.
#
# The cost is real and is accepted deliberately: the canonical is read from its
# default branch, unpinned, so a change over there turns this red with no change
# here. That is the signal, not the bug. This module's entire reason to exist is
# that copies drift, and the day the spec moves is the day this repo needs to
# know.
#
# WHICH agent-passport, AND THIS PART IS NOT A DETAIL
#
# The comparison is against the sibling's DEFAULT BRANCH, read out of git, not
# against the files sitting in its working tree. A developer with that repo
# checked out on a feature branch is looking at a proposal, not at the contract,
# and half-finished work next door must not be able to fail this repo or, worse,
# get vendored in as though it were published. That is not hypothetical: this
# check was written on 2026-08-05 and immediately went red against an unmerged
# branch adding maxItems to both event schemas. Real, correct, and not yet the
# contract.
#
# It does not fetch. A gate that reaches the network fails for reasons that have
# nothing to do with the code, so this reads the remote-tracking ref already on
# disk and prints its date; CI checks the repo out fresh, so there it is current
# by construction.
#
# TWO CALLERS, ONE COPY: the schemas job in .github/workflows/ci.yml and any
# local run. The workflow checks agent-passport out BESIDE this repo, exactly as
# it sits on a developer's machine, and the `cd .. && pwd` below finds it, the
# same layout and the same reasoning as catalog's templates-load.sh.
#
# REQUIRES THE SIBLING. If it is missing this FAILS rather than skipping,
# because a skipped check reports silence as health.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

ROOT="$(pwd)"
CANON_REPO="${AGENT_PASSPORT_DIR:-$(cd .. && pwd)/agent-passport}"

# ASKING agent-passport A QUESTION NEEDS THE ENVIRONMENT CLEARED, AND THE
# FAILURE HERE IS QUIETER THAN THE ONE THAT WAS FOUND ELSEWHERE.
#
# git runs a hook with GIT_DIR set to the repository being pushed, and `git -C
# <elsewhere>` changes the DIRECTORY without clearing it. Every command below
# would then resolve refs and read blobs out of THIS repository's object
# database while pointed at agent-passport's working tree.
#
# What that does to this particular check is the part worth writing down.
# `show "$CANON_REF:$canon"` would look up a canonical schema path in
# agent-stack-go's own objects. Where two repositories hold a file at the same
# path, that SUCCEEDS and returns the wrong content, and a check comparing a
# vendored copy against its original would compare the copy against itself and
# report agreement. @measured 2026-08-26 it does not succeed here, because this
# repository vendors those schemas at different paths, so every file is skipped
# and the `compared -eq 0` guard below fails loudly instead. That guard is why
# this was a nuisance rather than a hole, and it is not a reason to leave the
# cause in place: the paths could line up tomorrow.
#
# Latent rather than live today: this repository installs no git hook, so
# nothing runs this script with GIT_DIR set. That is a fact about the repository
# on this date and not about the script. Found by estate-gates C9, which was
# written after the same fault cost trailryx three push attempts.
canongit() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git "$@"; }

problems=0
note() {
	echo "FAIL: $1"
	problems=$((problems + 1))
}

if [ ! -d "$CANON_REPO/.git" ]; then
	echo "FAIL: the canonical repository is not here: $CANON_REPO"
	echo
	echo "This compares every vendored schema against the repository that owns"
	echo "the format. Without that repository it can compare nothing, and a"
	echo "check that passes because it looked at nothing is worse than no check."
	echo
	echo "  git clone https://github.com/TAIPANBOX/agent-passport \\"
	echo "    $(cd .. 2>/dev/null && pwd)/agent-passport"
	echo
	echo "Or point AGENT_PASSPORT_DIR at an existing checkout."
	exit 1
fi

# The published contract, in preference order: what the remote calls its
# default branch, then main, then whatever is checked out. Each candidate is
# resolved rather than assumed, so a shallow CI clone and a full local one land
# in the same place.
CANON_REF=""
for candidate in "$(canongit -C "$CANON_REPO" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)" origin/main main HEAD; do
	[ -n "$candidate" ] || continue
	if canongit -C "$CANON_REPO" rev-parse --verify --quiet "$candidate^{commit}" >/dev/null; then
		CANON_REF="$candidate"
		break
	fi
done

if [ -z "$CANON_REF" ]; then
	echo "FAIL: $CANON_REPO has no commit this could read the schemas from."
	exit 1
fi

printf 'canonical: TAIPANBOX/agent-passport %s at %s (%s)\n' \
	"$CANON_REF" \
	"$(canongit -C "$CANON_REPO" rev-parse --short "$CANON_REF")" \
	"$(canongit -C "$CANON_REPO" log -1 --format=%cs "$CANON_REF")"

head_ref="$(canongit -C "$CANON_REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [ "$CANON_REF" != "HEAD" ] && [ -n "$head_ref" ] && [ "$head_ref" != "${CANON_REF#origin/}" ]; then
	printf 'note: that checkout is on %s; this compares against %s on purpose, since\n' "$head_ref" "$CANON_REF"
	printf '      an unmerged branch over there is a proposal and not the contract.\n'
fi

# The canonical set, read from the owner rather than assumed here.
canonical=()
while IFS= read -r f; do
	[ -n "$f" ] && canonical+=("$f")
done < <(canongit -C "$CANON_REPO" ls-tree -r --name-only "$CANON_REF" -- schemas/ | grep '\.schema\.json$' | sort)

if [ ${#canonical[@]} -eq 0 ]; then
	note "$CANON_REPO at $CANON_REF holds no schemas/*.schema.json at all, so this compared nothing"
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# Every copy in this repo, found by name rather than from a list.
compared=0
for canon in "${canonical[@]}"; do
	base="$(basename "$canon")"
	ref_copy="$work/$base"
	if ! canongit -C "$CANON_REPO" show "$CANON_REF:$canon" >"$ref_copy" 2>/dev/null; then
		note "could not read $canon out of $CANON_REF"
		continue
	fi
	found=0
	while IFS= read -r copy; do
		[ -n "$copy" ] || continue
		found=$((found + 1))
		compared=$((compared + 1))
		if ! cmp -s "$copy" "$ref_copy"; then
			note "${copy#"$ROOT"/} has drifted from the canonical $base"
			echo "      diff (ours, then TAIPANBOX/agent-passport $CANON_REF):"
			diff -u "$copy" "$ref_copy" | sed 's/^/      /' | head -40
			echo "      Copy it over rather than editing it here. This repo"
			echo "      implements the contract; agent-passport defines it."
		fi
	done < <(git ls-files -- "*/$base" "$base" | sed "s|^|$ROOT/|" | sort)
	if [ "$found" -eq 0 ]; then
		echo "note: no copy of $base in this repo (nothing to compare, nothing wrong)"
	fi
done

if [ "$compared" -eq 0 ]; then
	note "this repo holds no copy of any canonical schema, which means this check measured nothing"
	echo "      If the vendored schemas moved or were removed, this check has to"
	echo "      move with them. Silence here is not health."
fi

# A schema-shaped file here that agent-passport does not own is either a new
# canonical schema nobody upstreamed, or a local invention wearing the contract's
# clothes. Both are worth stopping for.
while IFS= read -r copy; do
	[ -n "$copy" ] || continue
	base="$(basename "$copy")"
	if [ ! -f "$work/$base" ]; then
		note "${copy} looks like a canonical schema but agent-passport does not ship $base"
		echo "      Either it belongs upstream, or it should not be named as though"
		echo "      the spec owned it."
	fi
done < <(git ls-files -- '*.schema.json' | sort)

if [ "$problems" -ne 0 ]; then
	echo
	echo "Preventing drift is the entire point of this repository, and a schema"
	echo "copy that no longer matches the schema is the same defect one level"
	echo "down. See CLAUDE.md invariant 13."
	exit 1
fi

printf 'OK: %d vendored schema copy/copies match TAIPANBOX/agent-passport byte for byte.\n' "$compared"
