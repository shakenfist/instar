#!/bin/bash
# Summarise one distro-matrix entry into $GITHUB_STEP_SUMMARY.
#
# A red matrix must name the distro AND the qemu-img version it ran
# against, because that is what separates "instar broke" from "instar
# diverges at this qemu version boundary" -- the distinction phases 2,
# 2b and 3 spent their whole budget establishing. Without the version in
# the summary, every red row needs a log dive to attribute.
#
# Usage:
#   tools/ci/summarise-matrix-entry.sh <name> <image> <exit-code> <log>
#
# Writes a Markdown table row to $GITHUB_STEP_SUMMARY (creating the
# table header on first call), and a human line to stdout. When
# GITHUB_STEP_SUMMARY is unset it prints the row to stdout instead, so
# this is runnable locally.
#
# Parses, from the runner's own output:
#   - `qemu-img version 10.0.11 (...)` in its "Versions under test"
#     block, emitted before the suite starts. Reported as "unknown" if
#     the run died before reaching it -- that itself is a signal.
#   - stestr's totals block (`Ran: N tests`, ` - Passed: N`, and so on).
#
# It never decides pass/fail itself: the exit code passed in is the
# runner's, which already accounts for the truncated-run guards. Parsed
# totals are for humans, not for gating.

set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <name> <image> <exit-code> <log>" >&2
    exit 2
fi

NAME="$1"
IMAGE="$2"
RC="$3"
LOG="$4"

if [ ! -f "$LOG" ]; then
    echo "Warning: log $LOG missing; reporting without detail" >&2
    LOG=/dev/null
fi

# qemu-img prints "qemu-img version 10.0.11 (Debian 1:10.0.11+ds-0...)".
QEMU=$(sed -n 's/^qemu-img version \([^ ]*\).*/\1/p' "$LOG" | head -n1)
QEMU="${QEMU:-unknown}"

field() {
    # $1: the stestr totals label, e.g. "Passed". Absent means the run
    # never got that far.
    sed -n "s/^ *- $1: \([0-9]*\)$/\1/p" "$LOG" | tail -n1
}

RAN=$(sed -n 's/^Ran: \([0-9]*\) tests.*/\1/p' "$LOG" | tail -n1)
PASSED=$(field Passed)
SKIPPED=$(field Skipped)
FAILED=$(field Failed)

if [ "$RC" -eq 0 ]; then
    RESULT='PASS'
else
    RESULT="FAIL (exit $RC)"
fi

TOTALS="${RAN:-?} ran, ${PASSED:-?} passed, ${SKIPPED:-?} skipped, ${FAILED:-?} failed"

echo "$NAME ($IMAGE): $RESULT -- qemu-img $QEMU -- $TOTALS"

if [ -z "${GITHUB_STEP_SUMMARY:-}" ]; then
    exit 0
fi

# One header per job, not per entry. Each matrix entry is its own job
# with its own summary file, so this is always the first write.
if [ ! -s "$GITHUB_STEP_SUMMARY" ]; then
    {
        echo '### Distro matrix'
        echo ''
        echo '| Distro | Image | qemu-img | Ran | Passed | Skipped | Failed | Result |'
        echo '| ------ | ----- | -------- | --- | ------ | ------- | ------ | ------ |'
    } >> "$GITHUB_STEP_SUMMARY"
fi

echo "| $NAME | \`$IMAGE\` | $QEMU | ${RAN:-?} | ${PASSED:-?} | ${SKIPPED:-?} | ${FAILED:-?} | $RESULT |" \
    >> "$GITHUB_STEP_SUMMARY"
