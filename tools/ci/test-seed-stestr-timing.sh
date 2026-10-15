#!/usr/bin/env bash
#
# Tests for tools/ci/seed-stestr-timing.sh.
#
# The two cases that matter are the ones tools/test-package-functional.sh
# depends on: a committed timing file is actually consumed (the
# scheduler has to get real durations out of it, not just see the
# script exit 0), and a missing file is not an error (a developer
# checkout, or a tree where the nightly job has not published timing
# data yet, must still run the suite). Both are asserted against the
# real script and a real stestr repository -- not by reading the shell.
#
# stestr and its subunit/testtools dependencies are not assumed to be on
# the host (PEP 668), so this creates its own throwaway venv from the
# same tests/requirements.txt the suite itself uses, keeping the
# versions under test identical to production rather than a second,
# driftable pin.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SEED="${REPO_ROOT}/tools/ci/seed-stestr-timing.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

start "set up a throwaway venv with the suite's own stestr pin"
VENV="${WORK}/venv"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install -q --upgrade pip
"${VENV}/bin/pip" install -q -r "${REPO_ROOT}/tests/requirements.txt"
STESTR="${VENV}/bin/stestr"
if [ -x "${STESTR}" ]; then
    ok "venv ready: $("${STESTR}" --version 2>&1)"
else
    fail "stestr did not install into the venv"
    echo "1 failure(s)" >&2
    exit 1
fi

# A fixture in the committed format: "<test id><TAB><duration>" lines,
# sorted, two test ids with distinct, known durations. This is the
# shape tools/ci/seed-stestr-timing.sh documents TIMING_FILE as -- a
# plain text fixture written directly, not through any library, since
# the format itself is just that.
FIXTURE="${WORK}/timing.txt"
printf 'demo.TestSeed.test_long\t12.50\ndemo.TestSeed.test_short\t0.25\n' >"${FIXTURE}"
if [ ! -s "${FIXTURE}" ]; then
    fail "could not write the fixture timing text"
fi

# query_duration REPO_DIR TEST_ID -- print the duration stestr's own
# repository reports for TEST_ID, or "MISSING" if it has none. Reads
# through stestr's repository module rather than times.dbm directly, so
# this does not depend on that file's on-disk format.
query_duration() {
    local repo_dir="$1" test_id="$2"
    "${VENV}/bin/python3" - "${repo_dir}" "${test_id}" <<'PY'
import sys

from stestr.repository import util

repo_dir, test_id = sys.argv[1], sys.argv[2]
repo = util.get_repo_open(repo_url=repo_dir)
times = repo.get_test_times([test_id])
known = times["known"]
print(known[test_id] if test_id in known else "MISSING")
PY
}

start "a missing timing file is not an error"
RUNDIR="${WORK}/run-missing"
mkdir -p "${RUNDIR}"
(
    cd "${RUNDIR}" &&
        "${SEED}" "${STESTR}" "${WORK}/does-not-exist.txt" \
            >"${WORK}/missing.out" 2>"${WORK}/missing.err"
)
RC=$?
if [ "${RC}" -ne 0 ]; then
    fail "missing timing file exited ${RC}, expected 0"
elif [ -e "${RUNDIR}/.stestr" ]; then
    fail "missing timing file still created a .stestr repository"
elif ! grep -q "no committed stestr timing data" "${WORK}/missing.out"; then
    fail "missing timing file did not explain itself on stdout"
else
    ok "exits 0, creates no repository, and says why"
fi

start "a committed timing file is loaded into a fresh repository"
RUNDIR="${WORK}/run-present"
mkdir -p "${RUNDIR}"
(
    cd "${RUNDIR}" &&
        "${SEED}" "${STESTR}" "${FIXTURE}" \
            >"${WORK}/present.out" 2>"${WORK}/present.err"
)
RC=$?
if [ "${RC}" -ne 0 ]; then
    fail "present timing file exited ${RC}, expected 0"
    sed 's/^/      /' "${WORK}/present.err" >&2
elif [ ! -d "${RUNDIR}/.stestr" ]; then
    fail "present timing file did not create a .stestr repository"
else
    ok "exits 0 and creates a repository (--force-init on a fresh tree)"
fi

start "the repository actually has the committed durations, not just a file"
LONG="$(query_duration "${RUNDIR}" "demo.TestSeed.test_long")"
SHORT="$(query_duration "${RUNDIR}" "demo.TestSeed.test_short")"
# float comparison via awk: stestr round-trips through
# str(timedelta.total_seconds()), so exact equality is not guaranteed.
if [ "${LONG}" = "MISSING" ]; then
    fail "demo.TestSeed.test_long has no recorded duration after loading"
elif ! awk -v d="${LONG}" 'BEGIN { exit !(d > 12.0 && d < 13.0) }'; then
    fail "demo.TestSeed.test_long duration is ${LONG}, expected ~12.5"
else
    ok "demo.TestSeed.test_long recorded as ${LONG}s (expected ~12.5s)"
fi
if [ "${SHORT}" = "MISSING" ]; then
    fail "demo.TestSeed.test_short has no recorded duration after loading"
elif ! awk -v d="${SHORT}" 'BEGIN { exit !(d > 0.0 && d < 1.0) }'; then
    fail "demo.TestSeed.test_short duration is ${SHORT}, expected ~0.25"
else
    ok "demo.TestSeed.test_short recorded as ${SHORT}s (expected ~0.25s)"
fi

start "the scheduler actually uses the seeded durations to bin-pack"
# This is the point of the whole mechanism, so assert it end to end: a
# fresh repository seeded with one much longer test gives that test its
# own worker in a 2-worker partition, rather than round-robin pairing it
# with another test as a blind scheduler would with these two test ids.
PART_OUT="$(
    cd "${RUNDIR}" &&
        "${VENV}/bin/python3" - <<'PY'
from stestr import scheduler
from stestr.repository import util

repo = util.get_repo_open(repo_url=".")
ids = ["demo.TestSeed.test_long", "demo.TestSeed.test_short"]
partitions = scheduler.partition_tests(ids, 2, repo, None)
for i, partition in enumerate(partitions):
    print(i, sorted(partition))
PY
)"
if echo "${PART_OUT}" | grep -q "0 \['demo.TestSeed.test_long'\]"; then
    ok "the long test was given a worker to itself"
else
    fail "scheduler did not isolate the long test onto its own worker:"
    printf '%s\n' "${PART_OUT}" >"${WORK}/partition.out"
    sed 's/^/      /' "${WORK}/partition.out" >&2
fi

start "wrong argument count is refused with a usage message"
if "${SEED}" "${STESTR}" >"${WORK}/usage.out" 2>"${WORK}/usage.err"; then
    fail "one argument exited 0"
elif ! grep -q "^usage:" "${WORK}/usage.err"; then
    fail "one argument was refused but printed no usage message"
else
    ok "one argument is refused with a usage message"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all seed-stestr-timing tests passed"
