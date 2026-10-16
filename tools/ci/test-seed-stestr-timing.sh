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
# A third case matters for the same reason the second does: this script
# runs at the head of every testdata job, so a malformed committed file
# must be a warning and a blind partition rather than a hard failure
# across all of them at once. Both halves of that are asserted -- a file
# with some bad lines still seeds the good ones, and a file with no
# usable line at all exits zero.
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

# --- A corrupt timing file must not take CI down -----------------------
# This script runs at the head of every testdata job, so a malformed
# committed file -- one bad line from an unattended nightly refresh --
# would otherwise hard-fail all of them at once, under `set -e`, for a
# file that changes which worker a test runs on and nothing about what is
# tested. The absence of the file is explicitly not an error, so its
# corruption must not be either.
start "a malformed line is skipped and the rest of the file still loads"
MIXED="${WORK}/timing-mixed.txt"
{
    printf 'demo.TestMixed.test_good_long\t11.75\n'
    printf 'demo.TestMixed.test_no_tab 4.00\n'
    printf 'demo.TestMixed.test_not_a_number\tbanana\n'
    printf 'demo.TestMixed.test_negative\t-3.00\n'
    printf 'demo.TestMixed.test_good_short\t0.20\n'
} >"${MIXED}"
RUNDIR="${WORK}/run-mixed"
mkdir -p "${RUNDIR}"
(
    cd "${RUNDIR}" &&
        "${SEED}" "${STESTR}" "${MIXED}" \
            >"${WORK}/mixed.out" 2>"${WORK}/mixed.err"
)
RC=$?
if [ "${RC}" -ne 0 ]; then
    fail "a file with three bad lines exited ${RC}; it must fail open"
    sed 's/^/      /' "${WORK}/mixed.err" >&2
elif [ ! -d "${RUNDIR}/.stestr" ]; then
    fail "the usable lines were not loaded into a repository"
else
    ok "exits 0 and still seeds the repository"
fi
if grep -q "skipping" "${WORK}/mixed.err"; then
    ok "said which lines it skipped"
else
    fail "skipped lines silently"
fi
if [ -d "${RUNDIR}/.stestr" ]; then
    GOOD_LONG="$(query_duration "${RUNDIR}" "demo.TestMixed.test_good_long")"
    GOOD_SHORT="$(query_duration "${RUNDIR}" "demo.TestMixed.test_good_short")"
    if [ "${GOOD_LONG}" = "MISSING" ] || [ "${GOOD_SHORT}" = "MISSING" ]; then
        fail "a bad line cost the good lines their durations (${GOOD_LONG}, ${GOOD_SHORT})"
    elif ! awk -v d="${GOOD_LONG}" 'BEGIN { exit !(d > 11.0 && d < 12.5) }'; then
        fail "demo.TestMixed.test_good_long duration is ${GOOD_LONG}, expected ~11.75"
    else
        ok "both good lines kept their durations (${GOOD_LONG}s, ${GOOD_SHORT}s)"
    fi
    for BAD in test_no_tab test_not_a_number test_negative; do
        if [ "$(query_duration "${RUNDIR}" "demo.TestMixed.${BAD}")" = "MISSING" ]; then
            ok "demo.TestMixed.${BAD} was not invented a duration"
        else
            fail "demo.TestMixed.${BAD} got a duration from an unusable line"
        fi
    done
fi

start "a wholly unusable timing file warns and partitions blind"
GARBAGE="${WORK}/timing-garbage.txt"
printf 'this is not a timing file at all\nnor is this\n' >"${GARBAGE}"
RUNDIR="${WORK}/run-garbage"
mkdir -p "${RUNDIR}"
(
    cd "${RUNDIR}" &&
        "${SEED}" "${STESTR}" "${GARBAGE}" \
            >"${WORK}/garbage.out" 2>"${WORK}/garbage.err"
)
RC=$?
if [ "${RC}" -ne 0 ]; then
    fail "an unusable timing file exited ${RC}; every testdata job would have failed"
    sed 's/^/      /' "${WORK}/garbage.err" >&2
else
    ok "exits 0"
fi
if grep -q "partition this run blind" "${WORK}/garbage.err"; then
    ok "warned that the run will be partitioned blind"
else
    fail "did not say what it was going to do instead"
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
