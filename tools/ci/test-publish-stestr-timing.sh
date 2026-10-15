#!/usr/bin/env bash
#
# Tests for tools/ci/publish-stestr-timing.sh.
#
# The publisher runs unattended once a night, and the two ways it can be
# wrong are both invisible: it opens a pull request every morning for
# noise until someone disables the nightly, or it opens none ever and the
# committed scheduling hint rots while CI stays green. So the verdict for
# each class of measurement is asserted here rather than reasoned about.
#
# Every case runs with --dry-run, so no git branch is created, nothing is
# pushed, and no GitHub API call is made. The measurements are built from
# the repository's own committed tests/stestr-timing.txt, which also
# means a malformed committed file fails this test rather than a nightly.
#
# Needs bash, coreutils and python3. No docker, no venv, no testdata.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUBLISHER="${REPO_ROOT}/tools/ci/publish-stestr-timing.sh"
COMMITTED="${REPO_ROOT}/tests/stestr-timing.txt"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() {
    echo "--- $1"
}

ok() {
    echo "    ok: $1"
}

fail() {
    echo "    FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

run_publisher() {
    # run_publisher OUTFILE ARGS... -- returns the exit status, writes
    # combined output to OUTFILE.
    local out="$1"
    shift
    local status=0
    "${PUBLISHER}" "$@" > "${out}" 2>&1 || status=$?
    return "${status}"
}

if [ ! -f "${COMMITTED}" ]; then
    echo "FAIL: ${COMMITTED} is missing; the publisher has nothing to compare against" >&2
    exit 1
fi

# The heaviest test in the committed file, found rather than named, so
# this keeps working when the suite's shape changes. One awk pass rather
# than `sort | head`: under `set -o pipefail` the head closing the pipe
# makes sort exit on SIGPIPE and takes the whole script with it.
HEAVIEST="$(awk -F '\t' '$2 > max { max = $2; id = $1 } END { print id }' "${COMMITTED}")"
if [ -z "${HEAVIEST}" ]; then
    echo "FAIL: could not find the heaviest test in ${COMMITTED}" >&2
    exit 1
fi
echo "heaviest committed test: ${HEAVIEST}"
echo ""

# --- An unchanged measurement stays quiet ------------------------------
start "a measurement identical to the committed file publishes nothing"
cp "${COMMITTED}" "${WORK}/identical.txt"
OUT="${WORK}/identical.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/identical.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "an unchanged measurement exited ${STATUS}; it is the normal case and must succeed"
else
    ok "exited zero"
fi
if grep -q "have not moved enough" "${OUT}"; then
    ok "reported the change as immaterial"
else
    fail "did not report the change as immaterial"
fi
if grep -q "would publish" "${OUT}"; then
    fail "offered to publish an unchanged measurement"
else
    ok "published nothing"
fi

# --- A heavy test halving is published ---------------------------------
start "a heavy test halving opens a pull request"
awk -F '\t' -v id="${HEAVIEST}" 'BEGIN { OFS = "\t" }
    $1 == id { $2 = sprintf("%.2f", $2 / 2); print; next }
    { print }' "${COMMITTED}" > "${WORK}/halved.txt"
if cmp -s "${COMMITTED}" "${WORK}/halved.txt"; then
    fail "fixture did not change the heaviest test's duration"
fi
OUT="${WORK}/halved.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a material measurement exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "did not offer to publish a material change"
fi
if grep -q "${HEAVIEST}" "${OUT}"; then
    ok "the body names the test that moved"
else
    fail "the body does not name the test that moved"
fi
if grep -q "Why this is material" "${OUT}"; then
    ok "the body states which rule fired"
else
    fail "the body does not state which rule fired"
fi

# --- A uniformly slower run stays quiet --------------------------------
# The property the comparison is built on, asserted end to end through
# the publisher as well as in the comparison's own unit tests: stestr's
# bin packing is scale-free, so a contended runner must not open a pull
# request even though every number in the file changed.
start "a uniformly 25% slower measurement publishes nothing"
awk -F '\t' 'BEGIN { OFS = "\t" } { $2 = sprintf("%.2f", $2 * 1.25); print }' \
    "${COMMITTED}" > "${WORK}/slower.txt"
OUT="${WORK}/slower.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/slower.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a uniformly slower measurement exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    fail "offered to publish a uniform slowdown, which changes no scheduling decision"
else
    ok "published nothing"
fi

# --- --force overrides the quiet default -------------------------------
start "--force publishes an immaterial measurement"
OUT="${WORK}/forced.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/slower.txt" --dry-run --force || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "--force exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "--force did not publish"
fi
if grep -q "force" "${OUT}"; then
    ok "the body says the refresh was forced"
else
    fail "the body does not say the refresh was forced"
fi

# --- Bad input fails loudly --------------------------------------------
start "a malformed measurement is an error, not a quiet no-op"
printf 'test_info.TestInfo.test_a 1.00\n' > "${WORK}/malformed.txt"
OUT="${WORK}/malformed.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/malformed.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a malformed measurement reported success"
else
    ok "exited ${STATUS}"
fi

start "an empty measurement is an error"
: > "${WORK}/empty.txt"
OUT="${WORK}/empty.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/empty.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "an empty measurement reported success"
else
    ok "exited ${STATUS}"
fi

start "a missing measurement file is an error"
OUT="${WORK}/missing.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/not-there.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a missing measurement reported success"
else
    ok "exited ${STATUS}"
fi

start "bad arguments are rejected"
if "${PUBLISHER}" > /dev/null 2>&1; then
    fail "no arguments were accepted"
else
    ok "no arguments rejected"
fi
if "${PUBLISHER}" a b --dry-run > /dev/null 2>&1; then
    fail "two measurement files were accepted"
else
    ok "two positional arguments rejected"
fi
if "${PUBLISHER}" "${WORK}/identical.txt" --nonsense > /dev/null 2>&1; then
    fail "an unknown flag was accepted"
else
    ok "unknown flag rejected"
fi

# --- Nothing was written -----------------------------------------------
# --dry-run must leave the tree exactly as it found it: these cases run
# inside the repository, and a publisher that copied the measurement over
# the committed file before deciding would be invisible here otherwise.
start "--dry-run left the committed file and the branch alone"
if git -C "${REPO_ROOT}" diff --quiet -- tests/stestr-timing.txt; then
    ok "tests/stestr-timing.txt is unmodified"
else
    fail "tests/stestr-timing.txt was modified by a dry run"
fi
if git -C "${REPO_ROOT}" rev-parse --verify --quiet "stestr-timing/refresh" > /dev/null; then
    fail "a dry run created the publishing branch"
else
    ok "no publishing branch was created"
fi

echo ""
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
