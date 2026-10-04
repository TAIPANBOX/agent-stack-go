#!/usr/bin/env bash
# Every FROM in the Dockerfile names its base image by digest, not by a tag
# alone. A tag can move under an operator without anyone choosing that (a
# registry can repoint `golang:1.27` under this image tomorrow); a digest
# cannot. This is what a signed, attested image is actually signing: a build
# whose *inputs* were also pinned, not only its own output.
#
# The same gate vouchryx runs, for the same reason: the image this repository
# publishes (ghcr.io/taipanbox/agent-conform) is what a launcher schedules to
# verify a shared events bus, and a verifier whose own build could change under
# the operator is a poor thing to trust with that.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f Dockerfile ] || { echo "FAIL: no Dockerfile; this gate measures nothing" >&2; exit 1; }

froms=$(grep -E '^FROM[[:space:]]' Dockerfile || true)
[ -n "$froms" ] || { echo "FAIL: Dockerfile has no FROM line; this gate measures nothing" >&2; exit 1; }

bad=0
count=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  count=$((count + 1))
  # FROM [--platform=...] <image>[:<tag>][@sha256:<digest>] [AS <name>]
  image=$(echo "$line" | sed -E 's/^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?//' | awk '{print $1}')
  case "$image" in
  *"@sha256:"*) ;;
  *)
    echo "FAIL: '$line' names no @sha256: digest" >&2
    bad=$((bad + 1))
    ;;
  esac
done <<<"$froms"

[ "$bad" = "0" ] || exit 1
echo "base images: $count FROM line(s), every one pinned by digest"
