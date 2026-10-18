#!/usr/bin/env bash
# A private key committed to this repository is a TEST-ONLY key: named so,
# kept under testdata/, inside the member that says what it is for, and read
# by tests alone (CLAUDE.md invariant 36).
#
# WHY THIS EXISTS
#
# The shared agent-token table, delegation/testdata/agent-token-vectors.json,
# carries the private halves of the keys that minted its cases, so a suite in
# another language can mint more of them and a reader can re-derive every
# public key in it. That is the right call for a table and the wrong habit for
# a repository: the next private key to arrive here should not be able to sit
# beside them unnamed, outside testdata, or be read by product code, which is
# the step from "a fixture" to "a key something trusts".
#
# WHAT IT READS
#
# Every TRACKED .json file, parsed, and every object in it that has a `kty`
# and carries a private JWK member (d, p, q, dp, dq, qi, k). Discovered, never
# listed, so a new file is covered the day it is committed. Then every tracked
# Go file that is not a test, for the base name of any file that holds one.
#
# WHAT IT DOES NOT DO
#
# Look at PEM blocks, which the estate's secretscan already refuses by shape,
# or at keys in any form other than a JWK.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - <<'PY'
import json, os, subprocess, sys

PRIVATE = ("d", "p", "q", "dp", "dq", "qi", "k")


def tracked(pattern):
    out = subprocess.run(["git", "ls-files", "-z", "--", pattern], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


problems = []
holders = set()
found = 0


def walk(node, path, file):
    global found
    if isinstance(node, dict):
        if "kty" in node and any(m in node for m in PRIVATE):
            found += 1
            holders.add(file)
            where = "/".join(path) or "(top level)"
            if "testdata" not in file.split("/")[:-1]:
                problems.append(f"{file}: a private key at {where} lives outside a testdata/ directory")
            if len(path) < 2 or path[-2] != "test_only_keys" or not path[-1].startswith("TEST_ONLY_"):
                problems.append(f"{file}: a private key at {where} is not named TEST_ONLY_* inside test_only_keys")
        for k, v in node.items():
            walk(v, path + [str(k)], file)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + [str(i)], file)


for f in tracked("*.json"):
    with open(f, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        doc = json.loads(text)
    except ValueError:
        # A deliberately malformed fixture cannot be walked. It is refused only
        # when its text looks like it holds a key, since a file nobody can
        # parse is a file nobody checked.
        if '"kty"' in text and any(f'"{m}"' in text for m in PRIVATE):
            problems.append(f"{f}: not JSON this gate can parse, and its text looks like it carries a private key")
        continue
    walk(doc, [], f)

if found == 0:
    print("FAIL: no tracked file carries a test-only key, so this gate measured nothing.")
    print("      The shared agent-token table carries them; if it moved or lost them, say so here.")
    sys.exit(1)

names = {os.path.basename(h) for h in holders}
for g in tracked("*.go"):
    if g.endswith("_test.go"):
        continue
    with open(g, encoding="utf-8") as fh:
        body = fh.read()
    for n in sorted(names):
        if n in body:
            problems.append(f"{g}: names {n}, a file of test-only keys, outside a test")

if problems:
    for p in problems:
        print("FAIL: " + p)
    sys.exit(1)

print(f"OK: {found} private key(s) in {len(holders)} file(s), every one TEST_ONLY_* in test_only_keys under testdata/, read by tests alone.")
PY
