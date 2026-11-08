#!/usr/bin/env bash
#
# Tests for tools/ci/check-stestr-run.sh.
#
# The guard's whole value is that it fails on a run that stestr itself
# calls a success, so every case here is a totals block copied from the
# shape stestr really prints -- a clean run, a run whose worker died on
# the subunit packet-size limit, a run with a crashed worker reported
# as N/A elapsed, a run with no totals block at all, a run shorter than
# its own discovery, and a run in which every test skipped.
#
# The risk the guard carries is the opposite: refusing a legitimate run
# that merely skipped a lot, which is normal on a distro whose qemu
# cannot build some fixtures. That case is asserted here too, along
# with the other way a legitimate run could be refused: a test whose
# own output contains the words the packet-size guard looks for.
#
# The cases that assert the discovery count is mandatory are what stop
# the #663 defect coming back in the shape the #882 review found it:
# a caller that invokes the guard with no floor, and reports that the
# run was checked for truncation.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-stestr-run.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# expect_rc DESCRIPTION WANTED_RC FILE [EXPECTED]
expect_rc() {
    local description="$1" wanted="$2"
    shift 2
    local output rc
    output="$("${CHECK}" "$@" 2>&1)"
    rc=$?
    if [ "${rc}" -eq "${wanted}" ]; then
        ok "${description} (rc ${rc})"
    else
        fail "${description}: wanted rc ${wanted}, got ${rc}: ${output}"
    fi
}

# expect_message DESCRIPTION PATTERN FILE [EXPECTED]
expect_message() {
    local description="$1" pattern="$2"
    shift 2
    local output
    output="$("${CHECK}" "$@" 2>&1)"
    if echo "${output}" | grep -qE "${pattern}"; then
        ok "${description}"
    else
        fail "${description}: no match for '${pattern}' in: ${output}"
    fi
}

# The line both callers print before running, which "in-output" reads.
selection() { echo "selection contains $1 tests"; }

# A totals block in the shape stestr prints, with the worker summary.
totals() {
    local ran="$1" skipped="$2" worker_elapsed="${3:-0:00:04.123456}"
    cat <<EOF
running=test_info.TestInfo.test_qcow2
======
Totals
======
Ran: ${ran} tests in 12.3456 sec.
 - Passed: $((ran - skipped))
 - Skipped: ${skipped}
 - Expected Fail: 0
 - Unexpected Success: 0
 - Failed: 0
Sum of execute time for each test: 10.0000 sec.

==============
Worker Balance
==============
 - Worker 0 (${ran} tests) => ${worker_elapsed}
EOF
}

start "a clean run"
totals 1273 41 > "${WORK}/clean.txt"
expect_rc "passes when it reached its discovery count" 0 \
    "${WORK}/clean.txt" 1273
expect_rc "passes when it exceeded its discovery count" 0 \
    "${WORK}/clean.txt" 1200

start "a run whose worker died on the subunit packet-size limit"
{
    echo 'ValueError: Length too long: 4194400'
    totals 454 0
} > "${WORK}/length.txt"
expect_rc "refuses the partial run" 1 "${WORK}/length.txt" 454
expect_rc "refuses it even against a lower floor" 1 "${WORK}/length.txt" 100
{
    echo 'subunit.ParseError: Length too long: 4194400'
    totals 454 0
} > "${WORK}/length-subunit.txt"
expect_rc "refuses it when subunit names the limit" 1 \
    "${WORK}/length-subunit.txt" 454

start "a run whose packet-size failure is not a traceback line"
{
    # The bare message as a whole line: a shape the package suite's own
    # copy caught and the first version of this guard did not.
    echo 'Length too long: 4194400'
    totals 454 0
} > "${WORK}/length-bare.txt"
expect_rc "refuses the limit reported on a line of its own" 1 \
    "${WORK}/length-bare.txt" 454
expect_message "names the packet-size limit for the bare line too" \
    'subunit packet-size limit' "${WORK}/length-bare.txt" 454

start "a complete run that merely mentions the phrase"
{
    echo '{2} tools.test_guard.TestGuard.test_length_too_long ... ok'
    echo 'captured stdout: refuses a worker lost to Length too long'
    totals 1273 41
} > "${WORK}/phrase.txt"
expect_rc "passes: the phrase is not a traceback" 0 "${WORK}/phrase.txt" 1273

start "a file holding two runs"
{
    totals 454 0
    totals 1273 41
} > "${WORK}/two-runs.txt"
expect_rc "refuses a file with two totals blocks" 1 \
    "${WORK}/two-runs.txt" 1273
expect_message "says it checks one run per file" \
    'one run' "${WORK}/two-runs.txt" 1273
# The point of refusing: read with tail -n1, the truncated first run
# would be invisible behind a clean second one.
expect_rc "refuses it even though the last run is clean" 1 \
    "${WORK}/two-runs.txt" 454

start "a run with a crashed worker"
totals 454 0 'N/A' > "${WORK}/crashed.txt"
expect_rc "refuses a worker with no elapsed time" 1 "${WORK}/crashed.txt" 454

start "a run with no totals block"
echo 'running=test_info.TestInfo.test_qcow2' > "${WORK}/nototals.txt"
expect_rc "refuses a run it cannot measure" 1 "${WORK}/nototals.txt" 100

start "a run shorter than its own discovery"
totals 454 0 > "${WORK}/short.txt"
expect_rc "refuses 454 of 3253" 1 "${WORK}/short.txt" 3253

start "a run in which every test skipped"
totals 120 120 > "${WORK}/allskip.txt"
expect_rc "refuses a run that executed nothing" 1 "${WORK}/allskip.txt" 120
expect_rc "refuses it although it met its discovery count" 1 \
    "${WORK}/allskip.txt" 100

start "a legitimate run with many skips"
totals 1273 900 > "${WORK}/manyskip.txt"
expect_rc "passes: some tests executed" 0 "${WORK}/manyskip.txt" 1273

start "the count taken from the run's own output"
{
    selection 1100
    totals 1273 41
} > "${WORK}/inoutput.txt"
expect_rc "passes when the run exceeded the count it printed" 0 \
    "${WORK}/inoutput.txt" in-output
{
    selection 3253
    totals 454 0
} > "${WORK}/inoutput-short.txt"
expect_rc "refuses a run shorter than the count it printed" 1 \
    "${WORK}/inoutput-short.txt" in-output
expect_message "names the discovered count it compared against" \
    "fewer than the 3253 ids" "${WORK}/inoutput-short.txt" in-output
expect_rc "refuses a run that printed no count at all" 1 \
    "${WORK}/clean.txt" in-output
expect_message "says the count line is what is missing" \
    "selection contains N tests" "${WORK}/clean.txt" in-output
# A count of zero with a full totals block, which is the shape that
# matters: a selector that lists nothing but runs everything -- an
# `--exclude-regex` typo excluding the whole suite from the listing, say
# -- yields a floor of zero that any run clears. Every other guard here
# passes this run, so the zero check is the only thing that refuses it.
{
    selection 0
    totals 120 0
} > "${WORK}/inoutput-zero.txt"
expect_rc "refuses a selection that matched nothing" 1 \
    "${WORK}/inoutput-zero.txt" in-output

start "the discovery count is mandatory"
expect_rc "exits 2 when called with no count" 2 "${WORK}/clean.txt"
expect_message "the usage line names the count" \
    "usage:.*OUTPUT_FILE EXPECTED" "${WORK}/clean.txt"
# A count of zero spelled as a number, which the in-output path refused
# and this one accepted. The run below is clean and long, so every
# other guard passes it: only the zero check can refuse it.
expect_rc "refuses a numeric count of zero" 1 "${WORK}/clean.txt" 0
expect_message "refuses it in the same words as in-output" \
    "selection matched no tests at all" "${WORK}/clean.txt" 0

start "a run whose totals block this cannot read"
# What --no-subunit-trace prints: "Ran N tests" with no colon and no
# worker balance. The header says such a run is refused for having no
# totals block rather than passed on a format this cannot read, and a
# future Makefile edit is what would produce it.
{
    echo 'test_info.TestInfo.test_qcow2 ... ok'
    echo 'Ran 1273 tests in 12.3456 sec.'
    echo 'OK (skipped=41)'
} > "${WORK}/nocolon.txt"
expect_rc "refuses the no-subunit-trace shape" 1 "${WORK}/nocolon.txt" 1273
expect_message "says the totals block is what is missing" \
    "no \"Ran: N tests\" total" "${WORK}/nocolon.txt" 1273

start "called wrongly"
expect_rc "exits 2 with no argument" 2
expect_rc "exits 2 on a missing file" 2 "${WORK}/nonexistent.txt" 100
expect_rc "exits 2 on a non-numeric expected count" 2 \
    "${WORK}/clean.txt" "lots"

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-stestr-run: ${FAILURES} failure(s)" >&2
    exit 1
fi
echo "test-check-stestr-run: all cases pass"
