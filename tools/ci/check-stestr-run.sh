#!/usr/bin/env bash
#
# Decide whether a stestr run is a result at all.
#
# A stestr worker that dies mid-stream drops every remaining test in
# that worker, and stestr then prints a totals block for the tests it
# did see and exits 0 if none of them failed. The run looks green and
# ran a fraction of the suite: a 454-of-3253 run exited 0 here once.
# The subunit v2 packet-size limit is one real cause (a test attaching
# more than ~4MB of captured output raises "ValueError: Length too
# long"); a worker that crashes for any other reason shows up as an
# elapsed time of N/A in the summary.
#
# A selection in which every test skipped is the complement: a skip
# reports a result, so it counts towards "Ran", and a run that executed
# nothing satisfies any length floor exactly as a run that executed
# everything.
#
# These checks lived only inside tools/test-package-functional.sh, so
# the single pull-request job that runs every integration test --
# `integration-core` -- was the one job that could not tell a full run
# from a truncated one (#663). They are here so both callers share one
# implementation.
#
# Usage: tools/ci/check-stestr-run.sh OUTPUT_FILE EXPECTED
#
#   OUTPUT_FILE  the captured stdout+stderr of `stestr run`
#   EXPECTED     how many test ids the selection's discovery found: a
#                number, or the word "in-output" to read it from the
#                "selection contains N tests" line the run printed
#                before running. The run must have executed at least
#                that many; load-time cases make a real run longer than
#                the listing, never shorter, so fewer means truncated.
#
# EXPECTED used to be optional, and the one caller that could leave it
# off did. `integration-core` ran the four shape guards below with no
# length floor at all -- the one guard the 454-of-3253 run actually
# needed -- while the step above it claimed the run was checked for
# truncation. A floor that can be omitted is a floor that will be, so
# it is now required and there is no mode that silently checks less.
#
# Exits 0 with a one-line summary when the run is trustworthy, 1 when
# it is not, naming which guard refused it, and 2 when it was called
# wrongly (no output file, a non-numeric EXPECTED) -- never a pass.
#
# It reads the totals block subunit-trace prints, which is stestr's
# default. A run invoked with --no-subunit-trace prints "Ran N tests"
# with no colon and no worker balance, and is refused here for having
# no totals block rather than passed on a format this cannot read.
set -uo pipefail

OUTPUT_FILE="${1:-}"
EXPECTED="${2:-}"

if [ -z "$OUTPUT_FILE" ] || [ -z "$EXPECTED" ]; then
    echo "usage: $0 OUTPUT_FILE EXPECTED|in-output" >&2
    exit 2
fi
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Error: no stestr output at $OUTPUT_FILE, so nothing can be" >&2
    echo "checked. Treat it as a failure rather than a pass." >&2
    exit 2
fi
if [ "$EXPECTED" = 'in-output' ]; then
    # The count the run itself printed. Both callers print it in the
    # same words, from the same `stestr list` of the same selection, so
    # a caller that cannot derive a count cannot accidentally run with
    # the floor switched off: the line is missing and this refuses.
    EXPECTED=$(sed -n "s/^selection contains \([0-9]*\) tests$/\1/p" \
        "$OUTPUT_FILE" | tail -n1)
    if [ -z "$EXPECTED" ]; then
        echo "" >&2
        echo "Error: the run printed no \"selection contains N tests\"" >&2
        echo "line, so the length floor has nothing to check against." >&2
        echo "The caller is expected to list the selection before running" >&2
        echo "it; a run whose size is unknown is a failure here, not a" >&2
        echo "run with one guard switched off." >&2
        exit 1
    fi
    if [ "$EXPECTED" -eq 0 ]; then
        echo "" >&2
        echo "Error: the selection matched no tests at all. A selector" >&2
        echo "that matches nothing exits zero with everything passing," >&2
        echo "which is indistinguishable from a green run." >&2
        exit 1
    fi
elif ! [ "$EXPECTED" -ge 0 ] 2>/dev/null; then
    echo "Error: EXPECTED must be a number or 'in-output', got" >&2
    echo "'$EXPECTED'" >&2
    exit 2
fi

# Anchored on the traceback shape rather than the bare phrase: the
# whole captured output is searched, so a test that prints or asserts
# "Length too long" in its own output would otherwise make a complete
# run unreportable -- including a future test of this guard.
if grep -qE "(ValueError|subunit).*Length too long" "$OUTPUT_FILE"; then
    echo "" >&2
    echo "Error: a stestr worker died on the subunit packet-size limit" >&2
    echo "(a test attached >4MB of captured output). The run is PARTIAL:" >&2
    echo "the tests remaining in that worker never executed." >&2
    exit 1
fi

if grep -qE "^ - Worker [0-9]+ \([0-9]+ tests\) => N/A" "$OUTPUT_FILE"; then
    echo "" >&2
    echo "Error: stestr reported a worker with no elapsed time (N/A)," >&2
    echo "which means that worker crashed rather than finishing. The run" >&2
    echo "is PARTIAL and its result is not trustworthy." >&2
    exit 1
fi

RAN=$(sed -n "s/^Ran: \([0-9]*\) tests.*/\1/p" "$OUTPUT_FILE" | tail -n1)
if [ -z "$RAN" ]; then
    echo "" >&2
    echo "Error: stestr printed no \"Ran: N tests\" total, so the run" >&2
    echo "length cannot be checked. Treat it as a failure." >&2
    exit 1
fi

if [ "$RAN" -lt "$EXPECTED" ]; then
    echo "" >&2
    echo "Error: run executed $RAN tests, fewer than the $EXPECTED ids" >&2
    echo "discovery found for this selection. Since load-time cases make" >&2
    echo "a real run longer than the listing, not shorter, the run was" >&2
    echo "truncated; treat it as a failure, not a pass." >&2
    exit 1
fi

# Skip floor, the complement of the length floor above. The rule is
# "nothing executed at all" and not "fewer than some fraction", because
# there is no legitimate skip rate to compare against: skips are a
# property of the distro, not of the change, and the full suite
# legitimately skips hundreds. Zero executed tests needs no tuning, is
# never legitimate, and is the shape every realistic cause of a
# silently-empty run takes.
SKIPPED=$(sed -n "s/^ *- Skipped: \([0-9]*\).*/\1/p" "$OUTPUT_FILE" | tail -n1)
SKIPPED=${SKIPPED:-0}
EXECUTED=$((RAN - SKIPPED))
if [ "$EXECUTED" -le 0 ]; then
    echo "" >&2
    echo "Error: all $RAN tests in this selection skipped; nothing was" >&2
    echo "actually executed. A skip counts towards the \"Ran\" total" >&2
    echo "that stestr prints, so this run passes the length floor above" >&2
    echo "while testing nothing at all. The usual cause is missing test" >&2
    echo "fixtures, so check the testdata preparation rather than the" >&2
    echo "tests." >&2
    exit 1
fi

echo "check-stestr-run: $EXECUTED of $RAN tests executed," \
    "$SKIPPED skipped, against $EXPECTED discovered; no worker lost."
