#!/usr/bin/env bash
#
# Tests for tools/ci/generate-stestr-timing.py.
#
# The point of that script is that the committed timing file is
# *derived* from a real stestr run, not hand-maintained -- so this
# test builds a real, tiny test tree with its own .stestr.conf, runs
# the real suite runner over it (stestr actually executes the two
# toy tests and records how long they took), and only then runs the
# generator against the repository that real run produced. The
# generator's output is checked against the durations stestr itself
# recorded for that run, not against a value this test invents.
#
# stestr and its subunit/testtools dependencies are not assumed to be
# on the host (PEP 668), so this creates its own throwaway venv from
# tests/requirements.txt, keeping the versions under test identical to
# production rather than a second, driftable pin.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENERATE="${REPO_ROOT}/tools/ci/generate-stestr-timing.py"

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

start "produce a real stestr run to derive from"
# Two toy unittests with deliberately different durations, discovered
# through a throwaway .stestr.conf -- not fixtures copied from the
# real suite, so this test has no dependency on tests/ or testdata.
TOYTESTS="${WORK}/toytests"
mkdir -p "${TOYTESTS}"
cat >"${TOYTESTS}/.stestr.conf" <<'EOF'
[DEFAULT]
test_path=.
top_dir=.
EOF
cat >"${TOYTESTS}/test_toy.py" <<'EOF'
import time
import unittest


class TestToy(unittest.TestCase):
    def test_long(self):
        time.sleep(1.5)

    def test_short(self):
        time.sleep(0.1)
EOF
(cd "${TOYTESTS}" && "${STESTR}" run --concurrency 1 >"${WORK}/toyrun.out" 2>"${WORK}/toyrun.err")
RC=$?
if [ "${RC}" -ne 0 ]; then
    fail "the toy run itself failed (exit ${RC})"
    sed 's/^/      /' "${WORK}/toyrun.err" >&2
    echo "1 failure(s)" >&2
    exit 1
fi
ok "toy run completed, repository at ${TOYTESTS}/.stestr holds real durations"

# recorded_duration TEST_ID -- what stestr itself recorded for TEST_ID
# in the toy run's repository, read through stestr's own repository
# module rather than parsing times.dbm's on-disk format directly.
recorded_duration() {
    local test_id="$1"
    # get_repo_open takes the directory that HOLDS .stestr/, not
    # .stestr/ itself -- it appends that suffix internally.
    "${VENV}/bin/python3" - "${TOYTESTS}" "${test_id}" <<'PY'
import sys

from stestr.repository import util

repo_dir, test_id = sys.argv[1], sys.argv[2]
repo = util.get_repo_open(repo_url=repo_dir)
times = repo.get_test_times([test_id])
known = times["known"]
print(known[test_id] if test_id in known else "MISSING")
PY
}

LONG_RECORDED="$(recorded_duration "test_toy.TestToy.test_long")"
SHORT_RECORDED="$(recorded_duration "test_toy.TestToy.test_short")"

start "the generator writes sorted, rounded, tab-separated text"
DERIVED="${WORK}/derived.txt"
if ! "${VENV}/bin/python3" "${GENERATE}" "${TOYTESTS}/.stestr" "${DERIVED}" \
    >"${WORK}/generate.out" 2>"${WORK}/generate.err"; then
    fail "generator exited non-zero against a populated repository"
    sed 's/^/      /' "${WORK}/generate.err" >&2
elif [ ! -s "${DERIVED}" ]; then
    fail "generator produced an empty or missing output file"
elif ! grep -qE $'^test_toy\\.TestToy\\.test_long\t[0-9]+\\.[0-9]{2}$' "${DERIVED}" ||
    ! grep -qE $'^test_toy\\.TestToy\\.test_short\t[0-9]+\\.[0-9]{2}$' "${DERIVED}"; then
    fail "output is not <test id><TAB><duration rounded to 0.01> per line:"
    sed 's/^/      /' "${DERIVED}" >&2
else
    ok "generator wrote ${DERIVED} in the committed format"
fi

start "the file is sorted by test id"
if sort -c "${DERIVED}" 2>"${WORK}/sort.err"; then
    ok "sort -c confirms the file is already in sorted order"
else
    fail "output is not sorted by test id"
    sed 's/^/      /' "${WORK}/sort.err" >&2
fi

start "generating twice from the same repository is byte-identical"
# This is the whole reason the format is text with rounding rather than
# the full-precision subunit stream it used to be: a nightly refresh
# must mostly reproduce the last file so git history stays a small
# diff, not a new ~700 KB blob every run. Prove it rather than assume
# it -- a dict iteration order or an unrounded float would jitter the
# output on every regeneration even with nothing timing-wise having
# changed.
DERIVED2="${WORK}/derived2.txt"
"${VENV}/bin/python3" "${GENERATE}" "${TOYTESTS}/.stestr" "${DERIVED2}" >/dev/null 2>&1
if diff -q "${DERIVED}" "${DERIVED2}" >/dev/null 2>&1; then
    ok "two generations from the same repository produced byte-identical output"
else
    fail "two generations from the same repository differ:"
    diff "${DERIVED}" "${DERIVED2}" | sed 's/^/      /' >&2
fi

# recorded_matches_derived TEST_ID RECORDED -- the derived file's line
# for TEST_ID, rounded to 0.01s, must match what stestr itself recorded
# for it to within the rounding this format deliberately applies.
recorded_matches_derived() {
    local test_id="$1" recorded="$2" derived_value
    derived_value="$(grep -P "^$(printf '%s' "${test_id}" | sed 's/[.]/\\./g')\t" "${DERIVED}" |
        cut -f2)"
    if [ -z "${derived_value}" ]; then
        fail "${test_id} has no line in the derived file"
        return
    fi
    if awk -v a="${recorded}" -v b="${derived_value}" \
        'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d < 0.01) }'; then
        ok "${test_id}: recorded ${recorded}s, derived file has ${derived_value}s"
    else
        fail "${test_id}: recorded ${recorded}s but derived file has ${derived_value}s"
    fi
}

start "the derived durations match what stestr itself recorded"
recorded_matches_derived "test_toy.TestToy.test_long" "${LONG_RECORDED}"
recorded_matches_derived "test_toy.TestToy.test_short" "${SHORT_RECORDED}"

start "a repository with no recorded run is refused, not silently empty"
EMPTYREPO="${WORK}/emptyrepo"
mkdir -p "${EMPTYREPO}/.stestr"
if "${VENV}/bin/python3" "${GENERATE}" "${EMPTYREPO}/.stestr" "${WORK}/should-not-exist.txt" \
    >"${WORK}/empty.out" 2>"${WORK}/empty.err"; then
    fail "generator exited 0 against a repository with no recorded durations"
elif [ -e "${WORK}/should-not-exist.txt" ]; then
    fail "generator wrote an output file despite refusing"
else
    ok "an empty repository is refused and writes nothing"
fi

start "a nonexistent repository path is refused"
if "${VENV}/bin/python3" "${GENERATE}" "${WORK}/no-such-repo" "${WORK}/should-not-exist-2.txt" \
    >/dev/null 2>"${WORK}/nodir.err"; then
    fail "generator exited 0 against a nonexistent repository path"
else
    ok "a nonexistent repository path is refused"
fi

start "wrong argument count prints usage"
if "${VENV}/bin/python3" "${GENERATE}" "only-one-arg" >"${WORK}/usage.out" 2>"${WORK}/usage.err"; then
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
echo "all generate-stestr-timing tests passed"
