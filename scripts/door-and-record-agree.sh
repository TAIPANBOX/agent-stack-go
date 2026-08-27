#!/usr/bin/env bash
# The door and the record enforce the same rules, and they have to do it twice.
#
# WHY TWICE, WHICH IS THE POINT
#
# `chain.Validate` is what the RECORD applies. `delegation.Chain` is what a
# DOOR applies to a token it has just verified. `scripts/deps-layering.sh`
# requires `delegation` to depend on the standard library alone, so it cannot
# call `chain.Validate`, and the rules exist in two places on purpose.
#
# Two rules that must agree, with nothing comparing them, is the defect shape
# this estate found nine times in two days. This is the something.
#
# WHAT IT FOUND WHEN IT WAS WRITTEN
#
# Measured 2026-08-27, twice in one afternoon:
#
#   - the DEPTH cap: `delegation` bounded ACTORS at 32 and the record counts
#     ENTRIES, so a subject plus 32 actors verified at the door and every
#     record it produced was refused as 33 entries;
#   - the CYCLE rule: `chain.Validate` has refused a repeated principal since
#     it was written, and `delegation.Chain` did not, so a chain naming one
#     principal twice verified and its trail could not be written.
#
# Both are the same sentence: the door handed out a chain the record refuses.
#
# HOW THE SUBJECTS ARE FOUND
#
# The record's rules are DISCOVERED from the errors `chain.Validate` can
# return, not from a list here. A rule added there with no counterpart in
# `delegation` is a finding the day it lands, rather than the day somebody
# remembers this file.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, pathlib


def code_only(text: str) -> str:
    """The file with its comments removed.

    Written after this gate's own first draft failed its first teeth case. It
    scanned the whole file, and `delegation/chain.go` NAMES its errors in the
    doc comments above them, so renaming a rule away left the name in prose and
    the gate went on agreeing. The subject is CODE.

    That is the third time in two days this estate has read prose as code, and
    the second time in one afternoon. Crude on purpose: it can only make this
    gate see LESS, and seeing nothing at all is a separate finding above.
    """
    out, in_block = [], False
    for line in text.split("\n"):
        if in_block:
            end = line.find("*/")
            if end < 0:
                continue
            line, in_block = line[end + 2 :], False
        start = line.find("/*")
        while start >= 0:
            end = line.find("*/", start + 2)
            if end < 0:
                line, in_block = line[:start], True
                break
            line = line[:start] + line[end + 2 :]
            start = line.find("/*")
        i = line.find("//")
        if i >= 0:
            line = line[:i]
        out.append(line)
    return "\n".join(out)

RECORD = pathlib.Path("chain/chain.go")
DOOR = pathlib.Path("delegation/chain.go")

record_src = code_only(RECORD.read_text())
door_src = code_only(DOOR.read_text())

# Every error `Validate` can return: the record's rule set, read off the
# function rather than declared here.
m = re.search(r"func Validate\(chain \[\]string\) error \{(.*?)\n\}", record_src, re.S)
if not m:
    print(f"{RECORD}: no `func Validate` to read the record's rules from, so this")
    print("gate measured nothing. Either the validator moved or this script's")
    print("discovery broke; both need a person, and neither is a pass.")
    sys.exit(1)
rules = sorted(set(re.findall(r"\b(Err[A-Za-z]+)\b", m.group(1))))
if not rules:
    print(f"{RECORD}: `Validate` returns no named error, so there is nothing to")
    print("compare. That is a finding rather than agreement.")
    sys.exit(1)

# What the door refuses, by the errors `Chain` and everything it calls can
# return. `Chain` is the entry point an enforcement point uses.
door_errors = set(re.findall(r"\b(Err[A-Za-z]+)\b", door_src))

# No aliases, and the empty map is the point.
#
# The first draft carried `ErrInvalidEntry -> ErrNoSubject`, and those are NOT
# the same rule: the record refuses an entry that is not an `agent://` or
# `user://` URI, and the door refused only an EMPTY one. The gate reported
# agreement over a weaker check, which is worse than no gate, because it says
# the question was asked. The door has the rule now and the alias is gone.
#
# An alias may go back if the two packages ever genuinely name one rule two
# ways, since a NAME is the only part of this that cannot be discovered. It is
# not a place to record that one side is weaker.
ALIASES: dict[str, str] = {}

missing = []
for rule in rules:
    want = ALIASES.get(rule, rule)
    if want not in door_errors:
        missing.append((rule, want))

for rule, want in missing:
    print(f"{RECORD}: `Validate` can refuse with `{rule}` and {DOOR} has no `{want}`.")
    print("  The record applies this rule and the door does not, so the door can")
    print("  hand out a chain whose trail cannot be written. Add the rule to")
    print(f"  `delegation.Chain`, or record an alias for it in {pathlib.Path(__file__).name}.")

n = len(rules)
if missing:
    print()
    print(f"{len(missing)} of {n} record rule(s) have no counterpart at the door.")
    sys.exit(1)
print(f"{n} rule(s) the record enforces: every one of them has a counterpart at the door.")
PY
