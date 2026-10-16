#!/usr/bin/env bash
#
# Tests for tools/ci/report-nightly-matrix-failure.sh.
#
# The reporter only runs when a nightly leg fails, so nothing else in CI
# ever executes it -- which is exactly how the fuzz crash reporter
# managed to break every nightly fuzz run for a month without anyone
# being told. The failure path is therefore exercised here against
# synthetic logs rather than read and believed.
#
# The GitHub API is stubbed: a `gh` on PATH ahead of the real one records
# what it was asked to do and answers `gh issue list` from a fixture, so
# the filing and the comment-instead-of-duplicate paths are both run
# without creating anything in the repository. The one case that uses no
# stub at all is --dry-run, which must touch no API even if a real,
# authenticated gh is sitting on PATH.
#
# Needs bash, coreutils and jq. No docker, no venv, no testdata.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORTER="${REPO_ROOT}/tools/ci/report-nightly-matrix-failure.sh"

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

# A matrix leg's log, in the shape tools/test-package-functional.sh
# actually produces: the versions block (which is where the qemu-img
# version the issue must quote comes from), stestr's per-test result
# lines, its failure block, then the totals and the worker balance. The
# layout is the test: an excerpt anchored on the end of the file would
# capture the worker balance and none of the failure.
make_log() {
    local path="$1"
    local failing_count="${2:-2}"
    local wide_line="${3:-0}"
    {
        echo "=== Rocky 9 (rockylinux:9) ==="
        echo "--- Versions under test ---"
        echo "instar:   /usr/bin/instar (package instar-0.1.0.rpm)"
        echo "python:   Python 3.12.3 (python3.12)"
        echo "qemu-img version 8.2.2 (qemu-kvm-8.2.2-1.el9)"
        echo "--- Running suite ---"
        for index in $(seq 1 30); do
            echo "{0} test_info.TestInfo.test_case_${index} [0.021034s] ... ok"
        done
        for index in $(seq 1 "${failing_count}"); do
            echo "{1} test_convert.TestConvertVhdToRaw.test_case_${index} [444.812345s] ... FAILED"
            echo ""
            echo "Captured traceback:"
            echo "~~~~~~~~~~~~~~~~~~~"
            echo "    Traceback (most recent call last):"
            echo "      File \"/tmp/instar-tests/test_convert.py\", line 812, in test_case_${index}"
            echo "    self.assertEqual(expected, actual)"
            echo "    AssertionError: qemu-img reported a different map"
        done
        if [ "${wide_line}" -eq 1 ]; then
            # One enormous line of image bytes, the shape that made the
            # fuzz reporter exceed MAX_ARG_STRLEN and kill its whole job.
            python3 -c "print('x' * 400000)"
        fi
        echo "=============================="
        echo "Failed ${failing_count} tests - output below:"
        echo "=============================="
        echo ""
        for index in $(seq 1 "${failing_count}"); do
            echo "test_convert.TestConvertVhdToRaw.test_case_${index}"
            echo "--------------------------------------------------"
            echo "AssertionError: qemu-img reported a different map"
            echo ""
        done
        echo "======"
        echo "Totals"
        echo "======"
        echo "Ran: 3675 tests in 2340.0000 sec."
        echo " - Passed: 3600"
        echo " - Skipped: 73"
        echo " - Failed: ${failing_count}"
        echo ""
        echo "=============="
        echo "Worker Balance"
        echo "=============="
        echo " - Worker 0 (1603 tests) => 0:22:19.123456"
    } > "${path}"
}

# A leg that never reached the tests: the package would not install, so
# there is no stestr output at all and no test to name.
make_install_failure_log() {
    local path="$1"
    {
        echo "=== Fedora latest (fedora:latest) ==="
        echo "--- Installing package and test prerequisites ---"
        echo "Last metadata expiration check: 0:00:01 ago."
        echo "Error: Unable to find a match: qemu-img"
        echo "Error: package install failed"
    } > "${path}"
}

# A `gh` that records its invocations instead of making them. GH_STUB_DIR
# holds one file per call plus any --body-file content, and
# GH_STUB_EXISTING (a JSON array) is what `gh issue list` answers with.
install_gh_stub() {
    local bin="$1"
    mkdir -p "${bin}"
    cat > "${bin}/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${GH_STUB_DIR}/calls"
if [ "${1:-}" = "issue" ] && [ "${2:-}" = "list" ]; then
    cat "${GH_STUB_EXISTING}"
    exit 0
fi
# Keep whatever body was passed, so the test can assert on what a real
# gh would have sent.
previous=""
for arg in "$@"; do
    if [ "${previous}" = "--body-file" ]; then
        cp "${arg}" "${GH_STUB_DIR}/body"
    fi
    previous="${arg}"
done
exit 0
STUB
    chmod +x "${bin}/gh"
}

STUB_BIN="${WORK}/bin"
install_gh_stub "${STUB_BIN}"

# --- The dry run names the distro and the tests ------------------------
start "a dry run reports the distro, the image, the qemu version and the tests"
make_log "${WORK}/rocky.log" 2
OUT="${WORK}/dry.log"
STATUS=0
"${REPORTER}" "Rocky 9" "rockylinux:9" "${WORK}/rocky.log" --dry-run > "${OUT}" 2>&1 \
    || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "the dry run exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would file an issue titled 'Nightly matrix failure: Rocky 9'" "${OUT}"; then
    ok "the title names the distro"
else
    fail "the title does not name the distro"
fi
if grep -q 'test_convert.TestConvertVhdToRaw.test_case_1' "${OUT}" \
    && grep -q 'test_convert.TestConvertVhdToRaw.test_case_2' "${OUT}"; then
    ok "the body names both failing tests"
else
    fail "the body does not name the failing tests"
fi
if grep -q 'qemu-img 8.2.2' "${OUT}"; then
    ok "the body quotes the distro's qemu-img version"
else
    fail "the body does not quote the qemu-img version"
fi
if grep -q 'Ran: 3675 tests' "${OUT}"; then
    ok "the body quotes the totals"
else
    fail "the body does not quote the totals"
fi
if grep -q 'AssertionError: qemu-img reported a different map' "${OUT}"; then
    ok "the excerpt is anchored on the failure, not the worker balance"
else
    fail "the excerpt missed the failure block"
fi

# --- Filing, through the stub ------------------------------------------
start "with no open issue for the distro, one is filed"
export GH_STUB_DIR="${WORK}/stub-file"
mkdir -p "${GH_STUB_DIR}"
export GH_STUB_EXISTING="${WORK}/none.json"
echo '[]' > "${GH_STUB_EXISTING}"
STATUS=0
PATH="${STUB_BIN}:${PATH}" WORKFLOW_URL="https://example.invalid/run/1" \
    "${REPORTER}" "Rocky 9" "rockylinux:9" "${WORK}/rocky.log" > "${WORK}/file.log" 2>&1 \
    || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "filing exited ${STATUS}"
    cat "${WORK}/file.log" >&2
else
    ok "exited zero"
fi
if grep -q "^issue create" "${GH_STUB_DIR}/calls"; then
    ok "called gh issue create"
else
    fail "did not call gh issue create"
fi
if grep -q -- "--label test-failure" "${GH_STUB_DIR}/calls"; then
    ok "labelled test-failure"
else
    fail "did not label the issue test-failure"
fi
if grep -q "Nightly matrix failure: Rocky 9" "${GH_STUB_DIR}/calls"; then
    ok "the filed title names the distro"
else
    fail "the filed title does not name the distro"
fi
if grep -q 'test_convert.TestConvertVhdToRaw.test_case_1' "${GH_STUB_DIR}/body"; then
    ok "the filed body names the failing test"
else
    fail "the filed body does not name the failing test"
fi
if grep -q 'dedup_key: nightly-matrix:Rocky 9' "${GH_STUB_DIR}/body"; then
    ok "the filed body carries the dedup key"
else
    fail "the filed body carries no dedup key"
fi

# --- Dedup: an open issue for the distro is commented on ---------------
start "with an open issue for the distro, it is commented on rather than refiled"
export GH_STUB_DIR="${WORK}/stub-dedup"
mkdir -p "${GH_STUB_DIR}"
export GH_STUB_EXISTING="${WORK}/existing.json"
jq -n --arg title "Nightly matrix failure: Rocky 9" \
    --arg body "something
<!-- dedup_key: nightly-matrix:Rocky 9 -->" \
    '[{number: 904, title: $title, body: $body}]' > "${GH_STUB_EXISTING}"
STATUS=0
PATH="${STUB_BIN}:${PATH}" WORKFLOW_URL="https://example.invalid/run/2" \
    "${REPORTER}" "Rocky 9" "rockylinux:9" "${WORK}/rocky.log" > "${WORK}/dedup.log" 2>&1 \
    || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "the dedup path exited ${STATUS}"
    cat "${WORK}/dedup.log" >&2
else
    ok "exited zero"
fi
if grep -q "^issue comment 904" "${GH_STUB_DIR}/calls"; then
    ok "commented on the existing issue"
else
    fail "did not comment on the existing issue"
fi
if grep -q "^issue create" "${GH_STUB_DIR}/calls"; then
    fail "filed a duplicate issue as well"
else
    ok "filed no duplicate"
fi
if grep -q 'test_convert.TestConvertVhdToRaw.test_case_1' "${GH_STUB_DIR}/body"; then
    ok "the comment names this run's failing tests"
else
    fail "the comment does not name this run's failing tests"
fi
if grep -q 'example.invalid/run/2' "${GH_STUB_DIR}/body"; then
    ok "the comment names the run"
else
    fail "the comment does not name the run"
fi

start "an open issue for a DIFFERENT distro does not suppress the report"
export GH_STUB_DIR="${WORK}/stub-other"
mkdir -p "${GH_STUB_DIR}"
export GH_STUB_EXISTING="${WORK}/other.json"
jq -n --arg title "Nightly matrix failure: Debian 12" \
    --arg body "<!-- dedup_key: nightly-matrix:Debian 12 -->" \
    '[{number: 905, title: $title, body: $body}]' > "${GH_STUB_EXISTING}"
STATUS=0
PATH="${STUB_BIN}:${PATH}" "${REPORTER}" "Rocky 9" "rockylinux:9" "${WORK}/rocky.log" \
    > "${WORK}/other.log" 2>&1 || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}"
fi
if grep -q "^issue create" "${GH_STUB_DIR}/calls"; then
    ok "filed an issue for this distro"
else
    fail "another distro's open issue suppressed this one"
fi

# --- A leg that never reached the tests --------------------------------
start "a leg that failed before the tests still reports, and says so"
make_install_failure_log "${WORK}/fedora.log"
OUT="${WORK}/install.log"
STATUS=0
"${REPORTER}" "Fedora latest" "fedora:latest" "${WORK}/fedora.log" --dry-run \
    > "${OUT}" 2>&1 || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "Nightly matrix failure: Fedora latest" "${OUT}"; then
    ok "the title still names the distro"
else
    fail "the title does not name the distro"
fi
if grep -q "No failing test was identified" "${OUT}"; then
    ok "says no test was identified rather than implying the suite passed"
else
    fail "does not say that no test was identified"
fi
if grep -q "Unable to find a match: qemu-img" "${OUT}"; then
    ok "the excerpt falls back to the end of the log"
else
    fail "the excerpt does not show the install failure"
fi

# --- A missing log file ------------------------------------------------
start "a missing log still reports the distro"
OUT="${WORK}/nolog.log"
STATUS=0
"${REPORTER}" "Rocky 10" "rockylinux/rockylinux:10" "${WORK}/not-there.log" --dry-run \
    > "${OUT}" 2>&1 || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "Nightly matrix failure: Rocky 10" "${OUT}"; then
    ok "reported anyway"
else
    fail "did not report"
fi

# --- A 400KB single log line ------------------------------------------
# The shape that killed the fuzz nightlies: a 400,000 byte line reaching
# a command line. Here it must be clipped, and the report must still
# arrive.
start "a 400KB log line does not break the report"
make_log "${WORK}/wide.log" 1 1
OUT="${WORK}/wide-report.log"
STATUS=0
"${REPORTER}" "Ubuntu 24.04" "ubuntu:24.04" "${WORK}/wide.log" --dry-run \
    > "${OUT}" 2>&1 || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "exited ${STATUS}"
else
    ok "exited zero"
fi
BODY_BYTES="$(wc -c < "${OUT}")"
if [ "${BODY_BYTES}" -lt 20000 ]; then
    ok "the report stayed bounded (${BODY_BYTES} bytes)"
else
    fail "the report is ${BODY_BYTES} bytes; the excerpt caps are not holding"
fi
if grep -q 'test_convert.TestConvertVhdToRaw.test_case_1' "${OUT}"; then
    ok "still names the failing test"
else
    fail "lost the failing test"
fi

# --- A traceback that quotes the word FAILED ---------------------------
start "a traceback mentioning FAILED does not invent a test"
{
    echo "{0} test_info.TestInfo.test_one [0.1s] ... FAILED"
    echo "    AssertionError: expected ... FAILED"
    echo "Ran: 1 tests in 0.1000 sec."
} > "${WORK}/noise.log"
OUT="${WORK}/noise-report.log"
"${REPORTER}" "Debian 13" "debian:13" "${WORK}/noise.log" --dry-run > "${OUT}" 2>&1
if grep -q 'Failing tests (1)' "${OUT}"; then
    ok "counted exactly one failing test"
else
    fail "miscounted the failing tests"
fi

# --- The timing refresh is a different kind of failure -----------------
# The measurement leg can go red without a test failing: it publishes the
# refreshed timings after the suite, and a bug there used to produce a red
# run and no issue at all. The report for it must not read as a distro
# divergence, or a reader spends the morning looking for one.
start "a timing-refresh report says it is the publisher, not a test"
{
    echo "Comparing the measurement against tests/stestr-timing.txt"
    echo "### Verdict: material"
    echo "remote: Permission to shakenfist/instar.git denied to github-actions[bot]."
    echo "fatal: unable to access 'https://github.com/shakenfist/instar/': error 403"
} > "${WORK}/publish.log"
OUT="${WORK}/timing-report.log"
STATUS=0
"${REPORTER}" --kind timing-refresh "Debian 13 (full suite)" "debian:13" \
    "${WORK}/publish.log" --dry-run > "${OUT}" 2>&1 || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "the timing-refresh dry run exited ${STATUS}"
    cat "${OUT}" >&2
else
    ok "exited zero"
fi
if grep -q "would file an issue titled 'Nightly timing refresh failure'" "${OUT}"; then
    ok "the title names the timing refresh"
else
    fail "the title does not name the timing refresh"
fi
if grep -q 'No test failed' "${OUT}" && grep -q 'publish-stestr-timing.sh' "${OUT}"; then
    ok "the body says no test failed and names the publisher"
else
    fail "the body does not make clear that the refresh broke rather than a test"
fi
if grep -q 'qemu-img divergence at this' "${OUT}"; then
    fail "the body still carries the cross-distro reasoning, which does not apply"
else
    ok "the cross-distro reasoning is left out"
fi
if grep -q 'dedup_key: nightly-timing-refresh' "${OUT}"; then
    ok "it dedups on its own key rather than the measurement leg's distro"
else
    fail "the dedup key is not the timing-refresh one"
fi
if grep -q 'error 403' "${OUT}"; then
    ok "the excerpt is the publisher's own output"
else
    fail "the excerpt does not quote the publisher's output"
fi

start "a timing-refresh failure does not collide with the distro report"
# Same leg, same log, default kind: the title and key must be the distro
# ones, so one cannot dedup into the other.
OUT="${WORK}/timing-as-distro.log"
"${REPORTER}" "Debian 13 (full suite)" "debian:13" "${WORK}/publish.log" --dry-run \
    > "${OUT}" 2>&1
if grep -q 'dedup_key: nightly-matrix:Debian 13 (full suite)' "${OUT}"; then
    ok "the default kind still keys on the distro"
else
    fail "the default kind's dedup key changed"
fi

# --- Argument handling -------------------------------------------------
start "bad arguments are rejected"
if "${REPORTER}" "Rocky 9" --dry-run > /dev/null 2>&1; then
    fail "missing arguments were accepted"
else
    ok "missing arguments rejected"
fi
if "${REPORTER}" a b c --nonsense > /dev/null 2>&1; then
    fail "an unknown flag was accepted"
else
    ok "unknown flag rejected"
fi
if "${REPORTER}" a b c --kind publisher > /dev/null 2>&1; then
    fail "an unknown --kind was accepted"
else
    ok "unknown --kind rejected"
fi

echo ""
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
