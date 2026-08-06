#!/usr/bin/env bash
# Every number this README states about this repository, checked against the
# repository.
#
# WHY THIS EXISTS
#
# A number on a README is a claim with no owner. It is right the day it is
# written and nothing tells anybody when it stops being right, because the
# suite grows in a commit that never opens the README.
#
# That is not hypothetical here. On 2026-08-05 the it-rat.com service pages were
# audited against the repositories they describe and FOUR OF SEVEN figures were
# stale: trailryx by 33 tests, tokenfuse by 196, engram by 42, verdryx by 75.
# None was wrong when written. The site now has a gate; this is the same idea at
# the source, where the number actually changes.
#
# WHAT "TESTS" MEANS HERE, because a number needs a definition more than it
# needs a badge
#
# `go test ./... -list '.*'` enumerates test FUNCTIONS. It does not count
# subtests created with `t.Run`, and it does not count table cases inside one
# function. So the figure is "test functions in this module", which is a real
# and checkable quantity, and it is deliberately not called "assertions" or
# "cases", both of which would be larger and neither of which anybody can
# reproduce.
#
# It also does not run them. This is a claim about how much test code exists,
# not about it passing: `go test -race ./...` in CI is what says they pass, and
# conflating the two would let a green badge mean a red suite.

#
# TWO FILES STATE IT, SO TWO FILES ARE CHECKED. The badge in README.md was
# gated from the day this script was written and VALIDATION.md was not, so on
# 2026-08-06 the badge was right and VALIDATION.md's opening line still said 67
# against a suite of 85. A gate on one of two copies of a number is how the
# other copy becomes the stale one: nobody looks at the file that has no check.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
validation="VALIDATION.md"
problems=0

note() {
	printf '%s\n' "$1"
	problems=$((problems + 1))
}

actual=$(go test ./... -list '.*' 2>/dev/null | grep -cE '^Test')
if [ "${actual:-0}" -eq 0 ]; then
	note "the module reported no test functions at all, which means this check measured nothing"
	exit 1
fi

stated=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*' | head -1)
if [ -z "$stated" ]; then
	note "the README carries no tests badge, so this check has nothing to compare against"
	note "add: ![tests](https://img.shields.io/badge/tests-${actual}-brightgreen)"
	exit 1
fi

[ "$stated" = "$actual" ] ||
	note "the badge says $stated test functions and \`go test -list\` counts $actual"

# VALIDATION.md opens with the same number in prose: "N tests across ...".
if [ ! -f "$validation" ]; then
	note "$validation is missing, and this check was written because it carries the same number as the badge"
else
	claimed=$(grep -oE '^[0-9]+ tests across' "$validation" | grep -oE '^[0-9]+' | head -1)
	if [ -z "$claimed" ]; then
		note "$validation no longer opens with an \"N tests across ...\" line, so this half of the check measured nothing"
		note "either restore the sentence or delete this half deliberately, but do not let it pass by looking at nothing"
	else
		[ "$claimed" = "$actual" ] ||
			note "$validation says $claimed test functions and \`go test -list\` counts $actual"
	fi
fi

if [ "$problems" -gt 0 ]; then
	printf '\n%d number(s) this repository states about itself that it does not support.\n' "$problems"
	printf 'Update them in the same commit as the tests. That is the whole point: the\n'
	printf 'suite changes in a commit that never opens README.md or VALIDATION.md, and\n'
	printf 'this is what makes that impossible.\n'
	exit 1
fi

printf '%s test functions, and both the badge and %s say so.\n' "$actual" "$validation"
