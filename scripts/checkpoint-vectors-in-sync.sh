#!/usr/bin/env bash
# Enforces invariant 30 of CLAUDE.md: the checkpoint test vectors this module vendors
# (event/testdata/checkpoint-vectors.json) are byte-identical to the file TAIPANBOX/
# agent-passport owns (examples/checkpoint-vectors.json on its default branch).
#
# WHY IT IS A SEPARATE GATE FROM schemas-in-sync.sh
#
# schemas-in-sync.sh compares files named like a canonical schema. The vectors are
# not a schema, so that discovery never sees them, and a vendored copy of them would
# be a copy with nothing comparing it to its owner: the failure invariant 13 names,
# one file over. The vectors are the bytes SPEC 6.5.1 says every writer must
# reproduce, so a copy that drifted would make this module's encoder agree with
# itself while disagreeing with every other implementation.
#
# WHICH agent-passport, AND WHY THE DEFAULT BRANCH
#
# As schemas-in-sync.sh: the comparison reads the sibling's default branch out of git,
# not its working tree, so an unmerged proposal over there cannot fail this repo or be
# vendored as if it were published. It does not fetch. It refuses when the sibling is
# missing, when the canonical file is not on that branch, and when the vendored copy is
# not tracked or not there, because a check that compares nothing must not report OK.
#
# THE ENVIRONMENT IS CLEARED FOR EVERY QUESTION ASKED OF THE SIBLING. A hook runs git
# with GIT_DIR set to this repository, and `git -C <elsewhere>` keeps it.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

CANON_PATH="examples/checkpoint-vectors.json"
COPY_PATH="event/testdata/checkpoint-vectors.json"
CANON_REPO="${AGENT_PASSPORT_DIR:-$(cd .. && pwd)/agent-passport}"

canongit() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git "$@"; }

if [ ! -d "$CANON_REPO/.git" ]; then
	echo "FAIL: the canonical repository is not here: $CANON_REPO"
	echo "      It owns $CANON_PATH, the vectors this module must reproduce, so without it"
	echo "      nothing can be compared and this check measured nothing."
	echo "      git clone https://github.com/TAIPANBOX/agent-passport $CANON_REPO"
	echo "      or point AGENT_PASSPORT_DIR at an existing checkout."
	exit 1
fi

CANON_REF=""
for candidate in "$(canongit -C "$CANON_REPO" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)" origin/main main HEAD; do
	[ -n "$candidate" ] || continue
	if canongit -C "$CANON_REPO" rev-parse --verify --quiet "$candidate^{commit}" >/dev/null; then
		CANON_REF="$candidate"
		break
	fi
done
if [ -z "$CANON_REF" ]; then
	echo "FAIL: $CANON_REPO has no commit this could read $CANON_PATH from."
	exit 1
fi

CANON_TMP="$(mktemp)"
trap 'rm -f "$CANON_TMP"' EXIT
if ! canongit -C "$CANON_REPO" show "$CANON_REF:$CANON_PATH" >"$CANON_TMP" 2>/dev/null; then
	echo "FAIL: $CANON_PATH is not on $CANON_REF of $CANON_REPO, so there is nothing to compare the vendored vectors with."
	exit 1
fi

if ! git ls-files --error-unmatch -- "$COPY_PATH" >/dev/null 2>&1; then
	echo "FAIL: $COPY_PATH is not tracked by this repository, so the vendored vectors are missing and this check measured nothing."
	exit 1
fi
if [ ! -f "$COPY_PATH" ]; then
	echo "FAIL: $COPY_PATH is tracked but not on disk."
	exit 1
fi

printf 'canonical: TAIPANBOX/agent-passport %s at %s (%s)\n' \
	"$CANON_REF" \
	"$(canongit -C "$CANON_REPO" rev-parse --short "$CANON_REF")" \
	"$(canongit -C "$CANON_REPO" log -1 --format=%cs "$CANON_REF")"

if ! cmp -s "$COPY_PATH" "$CANON_TMP"; then
	echo "FAIL: $COPY_PATH differs from $CANON_PATH on $CANON_REF."
	echo "      A vendored copy of the vectors that drifts makes this module agree with"
	echo "      itself while disagreeing with every other implementation of SPEC 6.5.1."
	echo "      Re-vendor from $CANON_REPO, or change the canonical file there first."
	exit 1
fi

echo "OK: $COPY_PATH is byte-identical to $CANON_PATH on $CANON_REF."
