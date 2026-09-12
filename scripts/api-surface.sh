#!/usr/bin/env bash
# Enforces invariant 2 of CLAUDE.md: a change to an exported type, constant or
# error value is a version decision, not an edit.
#
# api/surface.txt is the exported surface this module promised at 1.0, one
# declaration per line, read out of the source by internal/apisurface. The test
# in that package compares the two:
#
#   - a line that disappeared or changed is a BREAKING change: it fails, unless
#     this script is run with --major, which is how a new major is cut on
#     purpose (a flag, not an environment variable: this module reads none);
#   - a line that appeared is ADDITIVE: it fails only until the file records it,
#     so the addition lands in the same commit (go test ./internal/apisurface -update);
#   - no file, an empty file, or a read that yielded nothing is "measured
#     nothing" and fails rather than passing over an empty comparison.
#
# A script and not only a test, so CI, the pre-push hook and gates-have-teeth.sh
# all run the same command.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ ! -f api/surface.txt ]; then
	printf 'FAIL: api/surface.txt is not there, so this check has no promised surface and measured nothing.\n'
	printf '      Regenerate it: go test ./internal/apisurface -update\n'
	exit 1
fi

extra=""
if [ "${1:-}" = "--major" ]; then
	extra="-args -major"
fi
# shellcheck disable=SC2086
if ! out=$(go test ./internal/apisurface -run TestTheSurfaceFileIsWhatTheSourceExports -count=1 $extra 2>&1); then
	printf '%s\n' "$out" | grep -v -E '^(FAIL|ok|---)' | sed 's/^/    /'
	printf 'FAIL: the exported surface is not what api/surface.txt promises (CLAUDE.md invariant 2).\n'
	exit 1
fi

count=$(grep -c . api/surface.txt)
printf 'OK: %s exported declarations across chain, delegation, event and passport, exactly what api/surface.txt promises.\n' "$count"
