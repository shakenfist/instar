#!/usr/bin/env bash
#
# Tests for tools/ci/fetch-previous-stestr-timing.sh.
#
# The fetcher decides which earlier night's measurement the publisher's
# persistence check compares against, and the ways it can be wrong are
# quiet: pick the current run's own artifact and every move "persists"
# on its first night; take the artifact a night whose suite FAILED still
# uploads and a heavy test that failed fast becomes the baseline; stop
# at a run that did not measure and no move ever persists; read a
# rejected token as "nothing measured" and a broken scope looks like a
# quiet night; fail the job on an API hiccup and a scheduling hint files
# a failure issue. So each is asserted here against a `gh` stub that
# serves a canned run list, canned job conclusions and canned artifacts
# per run id, and refuses the rest. No network, no API, no testdata.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FETCHER="${REPO_ROOT}/tools/ci/fetch-previous-stestr-timing.sh"

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

STUB_BIN="${WORK}/bin"
GH_LOG="${WORK}/gh-calls.log"
RUNS_JSON="${WORK}/runs.json"
ARTIFACTS="${WORK}/artifacts"
JOBS="${WORK}/jobs"
mkdir -p "${STUB_BIN}" "${ARTIFACTS}" "${JOBS}"

cat > "${STUB_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
# Stand-in for the GitHub CLI. `gh run list` prints the JSON the test
# wrote, or fails if GH_STUB_LIST_FAILS is set. `gh run view ID --json
# jobs` prints GH_STUB_JOBS/ID.json, or fails if GH_STUB_VIEW_FAILS is
# set. `gh run download ID --name NAME --dir DIR` copies the canned
# artifact GH_STUB_ARTIFACTS/ID.txt into DIR/stestr-timing.txt if it
# exists, fails the way the real one does for a run with no such
# artifact, or fails with a 403 if GH_STUB_DOWNLOAD_FAILS is set.
printf '%s\n' "$*" >> "${GH_STUB_LOG}"
case "${1:-} ${2:-}" in
    "run list")
        if [ -n "${GH_STUB_LIST_FAILS:-}" ]; then
            echo "stub: HTTP 403: Resource not accessible by integration" >&2
            exit 1
        fi
        cat "${GH_STUB_RUNS_JSON}"
        ;;
    "run view")
        if [ -n "${GH_STUB_VIEW_FAILS:-}" ]; then
            echo "stub: HTTP 403: Resource not accessible by integration" >&2
            exit 1
        fi
        if [ ! -f "${GH_STUB_JOBS}/$3.json" ]; then
            echo "stub: could not find any workflow run with ID $3" >&2
            exit 1
        fi
        cat "${GH_STUB_JOBS}/$3.json"
        ;;
    "run download")
        if [ -n "${GH_STUB_DOWNLOAD_FAILS:-}" ]; then
            echo "stub: HTTP 403: Resource not accessible by integration" >&2
            exit 1
        fi
        run_id="$3"
        dir=""
        while [ $# -gt 0 ]; do
            if [ "$1" = "--dir" ]; then dir="$2"; fi
            shift
        done
        if [ -f "${GH_STUB_ARTIFACTS}/${run_id}.txt" ]; then
            mkdir -p "${dir}"
            cp "${GH_STUB_ARTIFACTS}/${run_id}.txt" "${dir}/stestr-timing.txt"
        else
            echo "stub: no artifact matches any of the names or patterns provided" >&2
            exit 1
        fi
        ;;
    *)
        echo "stub: unexpected gh invocation: $*" >&2
        exit 1
        ;;
esac
STUB
chmod +x "${STUB_BIN}/gh"

run_fetcher() {
    # run_fetcher OUTFILE ARGS... -- returns the exit status, writes
    # combined output to OUTFILE.
    local out="$1"
    shift
    local status=0
    env PATH="${STUB_BIN}:${PATH}" \
        GH_TOKEN="stub-token" \
        GH_STUB_LOG="${GH_LOG}" \
        GH_STUB_RUNS_JSON="${RUNS_JSON}" \
        GH_STUB_ARTIFACTS="${ARTIFACTS}" \
        GH_STUB_JOBS="${JOBS}" \
        GH_STUB_LIST_FAILS="${GH_STUB_LIST_FAILS:-}" \
        GH_STUB_VIEW_FAILS="${GH_STUB_VIEW_FAILS:-}" \
        GH_STUB_DOWNLOAD_FAILS="${GH_STUB_DOWNLOAD_FAILS:-}" \
        GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
        GITHUB_REF_NAME="${GITHUB_REF_NAME:-}" \
        TIMING_BRANCH="${TIMING_BRANCH:-}" \
        "${FETCHER}" "$@" > "${out}" 2>&1 || status=$?
    return "${status}"
}

# jobs_json CONCLUSION -- a `gh run view --json jobs` body whose
# measuring job concluded CONCLUSION ("null" for one still running),
# alongside a distro leg that failed, which must not matter.
jobs_json() {
    local conclusion="$1"
    [ "${conclusion}" = "null" ] || conclusion="\"${conclusion}\""
    cat <<JSON
{"jobs": [
  {"name": "Build packages", "conclusion": "success"},
  {"name": "Nightly: Rocky 9", "conclusion": "failure"},
  {"name": "Measure: full suite on Debian 13", "conclusion": ${conclusion}}
]}
JSON
}

# Five runs, newest first as gh returns them: 400 is "tonight"; 350 is
# a dispatch still running; 300 is a night whose suite FAILED but which
# still uploaded a timing file, as the `if: always()` upload does; 200
# and 100 both measured.
cat > "${RUNS_JSON}" <<'JSON'
[
  {"databaseId": 400, "createdAt": "2026-10-31T02:00:00Z", "url": "https://example.invalid/runs/400"},
  {"databaseId": 350, "createdAt": "2026-10-30T09:00:00Z", "url": "https://example.invalid/runs/350"},
  {"databaseId": 300, "createdAt": "2026-10-30T02:00:00Z", "url": "https://example.invalid/runs/300"},
  {"databaseId": 200, "createdAt": "2026-10-29T02:00:00Z", "url": "https://example.invalid/runs/200"},
  {"databaseId": 100, "createdAt": "2026-10-28T02:00:00Z", "url": "https://example.invalid/runs/100"}
]
JSON
jobs_json success > "${JOBS}/400.json"
jobs_json null > "${JOBS}/350.json"
jobs_json failure > "${JOBS}/300.json"
jobs_json success > "${JOBS}/200.json"
jobs_json success > "${JOBS}/100.json"
printf 'test_info.TestInfo.test_a\t400.00\n' > "${ARTIFACTS}/400.txt"
printf 'test_info.TestInfo.test_a\t300.00\n' > "${ARTIFACTS}/300.txt"
printf 'test_info.TestInfo.test_a\t200.00\n' > "${ARTIFACTS}/200.txt"
printf 'test_info.TestInfo.test_a\t100.00\n' > "${ARTIFACTS}/100.txt"

start "the current run is skipped and the newest earlier night that measured is chosen"
: > "${GH_LOG}"
OUT="${WORK}/pick.log"
PREV="${WORK}/pick/previous.txt"
STATUS=0
GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}"
    sed 's/^/      /' "${OUT}" >&2
else
    ok "exited zero"
fi
if [ -s "${PREV}" ] && grep -q '200.00' "${PREV}"; then
    ok "took run 200's artifact"
else
    fail "did not take run 200's artifact"
fi
if grep -q 'run download 400' "${GH_LOG}"; then
    fail "tried the current run's own artifact, which always agrees with itself"
else
    ok "never asked for the current run's artifact"
fi
if grep -q 'run view 300 --json jobs' "${GH_LOG}"; then
    ok "asked whether the failed night measured"
else
    fail "skipped run 300 without asking whether it measured"
fi
if grep -q 'run download 300' "${GH_LOG}"; then
    fail "downloaded the artifact of a night whose measuring job failed"
else
    ok "never took the failed night's artifact, though it had one"
fi
if grep -q 'run download 350' "${GH_LOG}"; then
    fail "downloaded the artifact of a run still measuring"
else
    ok "passed over the run still measuring"
fi
if grep -q "Run 300 .*concluded failure" "${OUT}" && grep -q "Run 350 .*concluded unfinished" "${OUT}"; then
    ok "said why each passed-over run did not count"
else
    fail "did not say why the passed-over runs did not count"
fi
if grep -q 'warning' "${OUT}"; then
    fail "warned on a night with nothing wrong"
else
    ok "no warnings"
fi
if grep -q 'run download 100' "${GH_LOG}"; then
    fail "kept downloading after finding a measurement"
else
    ok "stopped at the first measurement found"
fi
if [ -s "${PREV}.source" ] && grep -q 'run 200 on 2026-10-29' "${PREV}.source" \
    && grep -q 'https://example.invalid/runs/200' "${PREV}.source"; then
    ok "the sidecar names the run, its date and its URL"
else
    fail "the sidecar does not name where the measurement came from"
fi
if grep -q 'run list --workflow nightly-matrix.yml --branch develop ' "${GH_LOG}"; then
    ok "listed the nightly workflow's runs on develop"
else
    fail "did not list the nightly workflow's runs on develop"
fi

start "the branch follows the run, and TIMING_BRANCH overrides it"
# A dispatch on a feature branch measures that branch's suite: its runs
# must not stand in for develop's previous night, nor develop's for its.
: > "${GH_LOG}"
GITHUB_REF_NAME=feature-x GITHUB_RUN_ID=400 run_fetcher "${WORK}/branch.log" "${WORK}/branch/previous.txt" \
    || true
if grep -q 'run list .*--branch feature-x ' "${GH_LOG}"; then
    ok "GITHUB_REF_NAME chose the branch"
else
    fail "did not list the current run's branch"
fi
: > "${GH_LOG}"
TIMING_BRANCH=release GITHUB_REF_NAME=feature-x GITHUB_RUN_ID=400 \
    run_fetcher "${WORK}/branch2.log" "${WORK}/branch2/previous.txt" || true
if grep -q 'run list .*--branch release ' "${GH_LOG}"; then
    ok "TIMING_BRANCH overrode it"
else
    fail "TIMING_BRANCH did not choose the branch"
fi

start "with no current run id the newest night that measured is chosen"
: > "${GH_LOG}"
OUT="${WORK}/norun.log"
PREV="${WORK}/norun/previous.txt"
STATUS=0
GITHUB_RUN_ID='' run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ -s "${PREV}" ] && grep -q '400.00' "${PREV}"; then
    ok "took run 400's artifact"
else
    fail "did not take the newest artifact (exit ${STATUS})"
fi

start "no earlier night measured: exit zero, no file, says so"
jobs_json failure > "${JOBS}/200.json"
jobs_json cancelled > "${JOBS}/100.json"
: > "${GH_LOG}"
OUT="${WORK}/none.log"
PREV="${WORK}/none/previous.txt"
STATUS=0
GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}; an empty result is not an error"
else
    ok "exited zero"
fi
if [ -e "${PREV}" ] || [ -e "${PREV}.source" ]; then
    fail "left a file behind with nothing in it to compare against"
else
    ok "left no file"
fi
if grep -q 'No previous measurement' "${OUT}"; then
    ok "said there was nothing to compare against"
else
    fail "did not say why there is no previous measurement"
fi
if grep -q 'warning' "${OUT}"; then
    fail "warned when every night simply failed to measure"
else
    ok "no warnings: nights that did not measure are not an API fault"
fi
if grep -q 'run download' "${GH_LOG}"; then
    fail "downloaded an artifact from a night that did not measure"
else
    ok "downloaded nothing"
fi

start "a stale output from an earlier attempt is removed before looking"
mkdir -p "${WORK}/stale"
printf 'test_info.TestInfo.test_a\t1.00\n' > "${WORK}/stale/previous.txt"
echo "old" > "${WORK}/stale/previous.txt.source"
OUT="${WORK}/stale.log"
STATUS=0
GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${WORK}/stale/previous.txt" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ ! -e "${WORK}/stale/previous.txt" ] && [ ! -e "${WORK}/stale/previous.txt.source" ]; then
    ok "removed the stale file and its sidecar"
else
    fail "a stale previous measurement survived an empty result (exit ${STATUS})"
fi

start "the run list failing is a warning, not a failed night"
: > "${GH_LOG}"
OUT="${WORK}/listfail.log"
PREV="${WORK}/listfail/previous.txt"
STATUS=0
GH_STUB_LIST_FAILS=1 GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}; the publisher must fall back, not the job fail"
else
    ok "exited zero"
fi
if [ -e "${PREV}" ]; then
    fail "produced a file from a failed listing"
else
    ok "left no file"
fi
if grep -q 'warning: could not list' "${OUT}" && grep -q '403' "${OUT}"; then
    ok "warned, and quoted gh's own error"
else
    fail "did not warn with gh's error"
fi

# From here on 200 measured again, so a warning-free empty result would
# mean the fault below was read as "did not measure".
jobs_json success > "${JOBS}/200.json"

start "a download refused for a night that measured is a warning, not 'did not measure'"
# A missing `actions: read` or a rejected token makes every download
# fail. Read as "no artifact", that is a log saying nothing measured --
# a quiet night, not a broken permission.
: > "${GH_LOG}"
OUT="${WORK}/dlfail.log"
PREV="${WORK}/dlfail/previous.txt"
STATUS=0
GH_STUB_DOWNLOAD_FAILS=1 GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ ! -e "${PREV}" ]; then
    ok "exited zero with no file"
else
    fail "a refused download did not fall back (exit ${STATUS})"
fi
if grep -q 'warning: run 200 measured, but its stestr-timing artifact could not be downloaded' "${OUT}" \
    && grep -q '403' "${OUT}"; then
    ok "warned, naming the run and quoting gh's error"
else
    fail "a refused download was not reported with gh's error"
fi
if grep -q 'could not be checked' "${OUT}" && ! grep -q '^No previous measurement' "${OUT}"; then
    ok "the summary says runs could not be checked, not that none measured"
else
    fail "the summary reads as a quiet night"
fi

start "reading a run's jobs failing is a warning, not 'did not measure'"
OUT="${WORK}/viewfail.log"
PREV="${WORK}/viewfail/previous.txt"
STATUS=0
GH_STUB_VIEW_FAILS=1 GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ ! -e "${PREV}" ]; then
    ok "exited zero with no file"
else
    fail "a refused job listing did not fall back (exit ${STATUS})"
fi
if grep -q 'warning: could not read the jobs of run 200' "${OUT}" && grep -q '403' "${OUT}" \
    && grep -q 'could not be checked' "${OUT}"; then
    ok "warned, quoting gh's error"
else
    fail "a refused job listing was not reported with gh's error"
fi

start "a run with no measuring job by that name is a warning"
# A rename of the job in the workflow without TIMING_JOB following it
# would otherwise pass over every night in silence.
OUT="${WORK}/renamed.log"
PREV="${WORK}/renamed/previous.txt"
STATUS=0
TIMING_JOB='Measure: something else' GITHUB_RUN_ID=400 run_fetcher "${OUT}" "${PREV}" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ ! -e "${PREV}" ] \
    && grep -q "warning: run 200 has no job named 'Measure: something else'" "${OUT}"; then
    ok "warned that the job was not found"
else
    fail "a missing measuring job was skipped in silence (exit ${STATUS})"
fi

start "bad arguments are rejected"
if "${FETCHER}" > /dev/null 2>&1; then
    fail "no arguments were accepted"
else
    ok "no arguments rejected"
fi
if "${FETCHER}" a b > /dev/null 2>&1; then
    fail "two arguments were accepted"
else
    ok "two arguments rejected"
fi

echo ""
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
