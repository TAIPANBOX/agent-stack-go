#!/usr/bin/env bash
# Enforces invariant 1 of CLAUDE.md: the importable library packages stay
# dependency-clean, because anything added here lands in six consumers at once.
#
#   passport, chain -> standard library only
#   event           -> standard library plus github.com/gowebpki/jcs (RFC 8785,
#                      required by agent-passport SPEC 6.5)
#
# github.com/santhosh-tekuri/jsonschema/v6 is for cmd/agent-conform and tests
# only, and must never appear in a library package.
#
# Non-test files only: `go list` .Imports excludes _test.go, which is what we
# want, since event/conformance_test.go legitimately uses jsonschema.
#
# This file is the ONE copy of this check. The local hook and CI both call it.
# Two copies of one check always diverge, so do not inline it anywhere.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# A Go import is standard library when its first path segment carries no dot.
check_pkg() {
	local pkg="$1"
	shift
	local allowed=("$@")

	local imports
	imports="$(go list -f '{{join .Imports "\n"}}' "./$pkg")"

	while IFS= read -r imp; do
		[ -n "$imp" ] || continue
		# stdlib: first segment has no dot
		case "${imp%%/*}" in
		*.*) ;;
		*) continue ;;
		esac

		local ok=0
		for a in ${allowed[@]+"${allowed[@]}"}; do
			[ "$imp" = "$a" ] && ok=1 && break
		done

		if [ "$ok" -eq 0 ]; then
			echo "FAIL: package '$pkg' imports third-party '$imp'"
			if [ "${#allowed[@]}" -eq 0 ]; then
				echo "      '$pkg' is allowed the standard library only."
			else
				echo "      '$pkg' is allowed only: ${allowed[*]}"
			fi
			echo "      See CLAUDE.md invariant 1. Put it in an adapter or in cmd/, not here."
			fail=1
		fi
	done <<<"$imports"
}

check_pkg passport
check_pkg chain
check_pkg event github.com/gowebpki/jcs

if [ "$fail" -ne 0 ]; then
	echo
	echo "Library layering violated. This check exists because agent-stack-go is"
	echo "imported by tag by idryx, wardryx, mockryx, qryx, heraldyx and"
	echo "terraform-provider-taipan. See CLAUDE.md's blast-radius section; which"
	echo "tag each of them is on is measured by estate-gates C1, not written down."
	exit 1
fi

echo "OK: library packages are dependency-clean (passport, chain, event)."
