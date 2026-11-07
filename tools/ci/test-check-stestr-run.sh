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
# cannot build some fixtures. That case is asserted here too.

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
expect_rc "passes with no expected count" 0 "${WORK}/clean.txt"
expect_rc "passes when it reached its discovery count" 0 \
    "${WORK}/clean.txt" 1273
expect_rc "passes when it exceeded its discovery count" 0 \
    "${WORK}/clean.txt" 1200

start "a run whose worker died on the subunit packet-size limit"
{
    echo 'ValueError: Length too long: 4194400'
    totals 454 0
} > "${WORK}/length.txt"
expect_rc "refuses the partial run" 1 "${WORK}/length.txt"
expect_rc "refuses it even against a lower floor" 1 "${WORK}/length.txt" 100

start "a run with a crashed worker"
totals 454 0 'N/A' > "${WORK}/crashed.txt"
expect_rc "refuses a worker with no elapsed time" 1 "${WORK}/crashed.txt"

start "a run with no totals block"
echo 'running=test_info.TestInfo.test_qcow2' > "${WORK}/nototals.txt"
expect_rc "refuses a run it cannot measure" 1 "${WORK}/nototals.txt"

start "a run shorter than its own discovery"
totals 454 0 > "${WORK}/short.txt"
expect_rc "refuses 454 of 3253" 1 "${WORK}/short.txt" 3253
expect_rc "passes the same run with no floor to check" 0 "${WORK}/short.txt"

start "a run in which every test skipped"
totals 120 120 > "${WORK}/allskip.txt"
expect_rc "refuses a run that executed nothing" 1 "${WORK}/allskip.txt"
expect_rc "refuses it although it met its discovery count" 1 \
    "${WORK}/allskip.txt" 120

start "a legitimate run with many skips"
totals 1273 900 > "${WORK}/manyskip.txt"
expect_rc "passes: some tests executed" 0 "${WORK}/manyskip.txt" 1273

start "called wrongly"
expect_rc "exits 2 with no argument" 2
expect_rc "exits 2 on a missing file" 2 "${WORK}/nonexistent.txt"
expect_rc "exits 2 on a non-numeric expected count" 2 \
    "${WORK}/clean.txt" "lots"

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-stestr-run: ${FAILURES} failure(s)" >&2
    exit 1
fi
echo "test-check-stestr-run: all cases pass"
