#!/usr/bin/env bash
#
# Tests for tools/ci/fetch-previous-stestr-timing.sh.
#
# The fetcher decides which earlier night's measurement the publisher's
# persistence check compares against, and the ways it can be wrong are
# quiet: pick the current run's own artifact and every move "persists"
# on its first night; stop at a run that uploaded nothing and no move
# ever persists; fail the job on an API hiccup and a scheduling hint
# files a failure issue. So each is asserted here against a `gh` stub
# that serves a canned run list and a canned artifact for some run ids
# and refuses others. No network, no API, no testdata.

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
mkdir -p "${STUB_BIN}" "${ARTIFACTS}"

cat > "${STUB_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
# Stand-in for the GitHub CLI. `gh run list` prints the JSON the test
# wrote, or fails if GH_STUB_LIST_FAILS is set. `gh run download ID
# --name NAME --dir DIR` copies DIR-independent canned artifact
# GH_STUB_ARTIFACTS/ID.txt into DIR/stestr-timing.txt if it exists, and
# fails the way the real one does for a run with no such artifact.
printf '%s\n' "$*" >> "${GH_STUB_LOG}"
case "${1:-} ${2:-}" in
    "run list")
        if [ -n "${GH_STUB_LIST_FAILS:-}" ]; then
            echo "stub: HTTP 403: Resource not accessible by integration" >&2
            exit 1
        fi
        cat "${GH_STUB_RUNS_JSON}"
        ;;
    "run download")
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
        GH_STUB_LIST_FAILS="${GH_STUB_LIST_FAILS:-}" \
        GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
        "${FETCHER}" "$@" > "${out}" 2>&1 || status=$?
    return "${status}"
}

# Four runs, newest first as gh returns them: 400 is "tonight", 300 is a
# night whose measuring leg failed and uploaded nothing, 200 and 100
# both measured.
cat > "${RUNS_JSON}" <<'JSON'
[
  {"databaseId": 400, "createdAt": "2026-10-31T02:00:00Z", "url": "https://example.invalid/runs/400"},
  {"databaseId": 300, "createdAt": "2026-10-30T02:00:00Z", "url": "https://example.invalid/runs/300"},
  {"databaseId": 200, "createdAt": "2026-10-29T02:00:00Z", "url": "https://example.invalid/runs/200"},
  {"databaseId": 100, "createdAt": "2026-10-28T02:00:00Z", "url": "https://example.invalid/runs/100"}
]
JSON
printf 'test_info.TestInfo.test_a\t400.00\n' > "${ARTIFACTS}/400.txt"
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
if grep -q 'run download 300' "${GH_LOG}"; then
    ok "tried the failed night and moved past it"
else
    fail "skipped run 300 without asking whether it measured"
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
if grep -q 'run list --workflow nightly-matrix.yml' "${GH_LOG}"; then
    ok "listed the nightly workflow's runs"
else
    fail "did not list the nightly workflow's runs"
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
rm -f "${ARTIFACTS}/200.txt" "${ARTIFACTS}/100.txt"
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
