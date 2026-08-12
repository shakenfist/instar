#!/usr/bin/env bash
#
# Tests for tools/ci/report-fuzz-crash.sh.
#
# The bug this guards against cost a month of nightly fuzzing: a crash
# input of 81KB became a single 370KB log line, which became a 371KB
# argv entry, which exceeded Linux's MAX_ARG_STRLEN, which killed jq,
# which -- under `bash -e` -- killed the whole fuzz step. Nothing in the
# suite would have noticed, because the reporter only runs when a target
# actually crashes. So the shape of the input is synthesised here
# instead, and the properties the workflow depends on are asserted
# directly.
#
# Everything runs with --dry-run, so no GitHub API call is made and no
# token is needed. Run from anywhere; needs bash, jq and coreutils.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORTER="${REPO_ROOT}/tools/ci/report-fuzz-crash.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0
CASE=""

start() {
    CASE="$1"
    echo "--- ${CASE}"
}

ok() {
    echo "    ok: $1"
}

fail() {
    echo "    FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

check() {
    # check DESCRIPTION ACTUAL EXPECTED
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        fail "$1: expected '$3', got '$2'"
    fi
}

# The reporter prints two human-readable lines before the body, so the
# JSON starts at line 3.
run_reporter() {
    "${REPORTER}" "$@" --dry-run | tail -n +3
}

# A libFuzzer log shaped like the real thing: some preamble, the panic
# location and message on separate lines, the SUMMARY, and then the
# `std::fmt::Debug` dump of the input as ONE line of the requested
# width.
make_log() {
    local path="$1" dump_bytes="$2"
    {
        echo "INFO: Running with entropic power schedule"
        echo "#2      INITED cov: 118 ft: 119 corp: 1/1b"
        echo "thread '<unnamed>' panicked at fuzz_targets/" \
            "fuzz_rebase_planners.rs:278:17:"
        echo "Write patch 0 (offset 4096, len 512) exceeds" \
            "total_file_size (4096)"
        echo "note: run with \`RUST_BACKTRACE=1\` for a backtrace"
        echo "==12345== ERROR: libFuzzer: deadly signal"
        echo "SUMMARY: libFuzzer: deadly signal"
        # shellcheck disable=SC2016  # libFuzzer's own wording
        printf 'Output of `std::fmt::Debug`:\n'
        head -c "${dump_bytes}" < /dev/zero | tr '\0' 'a'
        printf '\n'
        echo "artifact_prefix='./'; Test unit written to" \
            "./artifacts/fuzz_rebase_planners/crash-deadbeef"
    } > "${path}"
}

CRASH="${WORK}/crash-deadbeef"
head -c 81920 < /dev/zero | tr '\0' 'x' > "${CRASH}"

# --- The motivating case: one log line far past MAX_ARG_STRLEN --------
start "a 370KB single log line still produces a filable body"
BIG_LOG="${WORK}/big.log"
make_log "${BIG_LOG}" 370000
BODY="${WORK}/big.json"
if run_reporter fuzz_rebase_planners "${CRASH}" "${BIG_LOG}" \
        > "${BODY}" 2>"${WORK}/big.err"; then
    ok "reporter exited 0"
else
    fail "reporter exited non-zero: $(cat "${WORK}/big.err")"
fi

if jq -e . < "${BODY}" > /dev/null 2>&1; then
    ok "body is valid JSON"
else
    fail "body is not valid JSON"
fi

BODY_BYTES="$(wc -c < "${BODY}")"
if [ "${BODY_BYTES}" -lt 60000 ]; then
    ok "body is ${BODY_BYTES} bytes, under the 60000 cap"
else
    fail "body is ${BODY_BYTES} bytes, over the 60000 cap"
fi

# The whole point of clipping per line rather than per byte: the lines
# that identify the crash survive, the dump does not.
if jq -e '.log_excerpt | contains("SUMMARY: libFuzzer")' \
        < "${BODY}" > /dev/null; then
    ok "excerpt keeps the libFuzzer SUMMARY"
else
    fail "excerpt lost the libFuzzer SUMMARY"
fi

if jq -e '.log_excerpt | contains("artifacts/fuzz_rebase_planners")' \
        < "${BODY}" > /dev/null; then
    ok "excerpt keeps the artifact path"
else
    fail "excerpt lost the artifact path"
fi

# --- The cross-workflow contract --------------------------------------
start "the body satisfies fuzz-autofix.yml's validation predicate"
if jq -e '.source and .target and .signature and .reproducer' \
        < "${BODY}" > /dev/null; then
    ok "source, target, signature and reproducer are all present"
else
    fail "a field fuzz-autofix.yml requires is missing or empty"
fi

check "target is the fuzz target" \
    "$(jq -r '.target' < "${BODY}")" "fuzz_rebase_planners"
check "source identifies the workflow" \
    "$(jq -r '.source' < "${BODY}")" "coverage-fuzz"
check "crash_input_size is the real size" \
    "$(jq -r '.crash_input_size' < "${BODY}")" "81920 bytes"

# jq -e treats "" as truthy, so the predicate above passes on an empty
# reproducer. Check the content, since this is the one field a human
# reading the issue has to be able to paste.
check "reproducer names the target and the artifact" \
    "$(jq -r '.reproducer' < "${BODY}")" \
    "cd src/fuzz && cargo fuzz run fuzz_rebase_planners \
artifacts/fuzz_rebase_planners/crash-deadbeef"

# --- The signature carries the message, not just the location ---------
start "the signature includes the panic message"
SIG="$(jq -r '.signature' < "${BODY}")"
case "${SIG}" in
    *fuzz_rebase_planners.rs:278:17*) ok "signature has the location" ;;
    *) fail "signature lost the panic location: ${SIG}" ;;
esac
case "${SIG}" in
    *"exceeds"*) ok "signature has the panic message" ;;
    *) fail "signature lost the panic message: ${SIG}" ;;
esac
SIG_BYTES="$(printf '%s' "${SIG}" | wc -c)"
if [ "${SIG_BYTES}" -le 200 ]; then
    ok "signature is ${SIG_BYTES} bytes, within the 200 byte bound"
else
    fail "signature is ${SIG_BYTES} bytes, over the 200 byte bound"
fi

# --- Raw mutated bytes -------------------------------------------------
start "invalid UTF-8 and NULs in the log do not break jq"
RANDOM_LOG="${WORK}/random.log"
head -c 200000 < /dev/urandom > "${RANDOM_LOG}"
RBODY="${WORK}/random.json"
if run_reporter fuzz_qcow2 "${CRASH}" "${RANDOM_LOG}" > "${RBODY}"; then
    ok "reporter exited 0"
else
    fail "reporter exited non-zero"
fi
if jq -e . < "${RBODY}" > /dev/null 2>&1; then
    ok "body is valid JSON"
else
    fail "body is not valid JSON"
fi

start "a panic message made of raw bytes is still reported"
# The signature is fuzzer-derived too, so it gets the same treatment as
# the excerpt. Deterministic bytes rather than /dev/urandom, so the
# bound and the scrub are actually being measured: 400 ASCII characters
# to overflow the 200 byte cap, and a run of 0xff -- which is invalid
# UTF-8 in any position -- to give the scrub something to remove.
UTF8_LOG="${WORK}/utf8.log"
{
    printf "thread '<unnamed>' panicked at src/lib.rs:1:1:\n"
    printf 'Rejected chunk '
    printf '\377%.0s' $(seq 1 16)
    head -c 400 < /dev/zero | tr '\0' 'M'
    printf '\n'
} > "${UTF8_LOG}"
UBODY="${WORK}/utf8.json"
if run_reporter fuzz_vmdk "${CRASH}" "${UTF8_LOG}" > "${UBODY}"; then
    ok "reporter exited 0"
else
    fail "reporter exited non-zero"
fi
if jq -e '.signature' < "${UBODY}" > /dev/null 2>&1; then
    ok "body is valid JSON with a signature"
else
    fail "body is not valid JSON"
fi
USIG="$(jq -r '.signature' < "${UBODY}")"
# grep without -a decides a log with raw bytes in it is binary and
# prints nothing, which silently turns every such crash into
# 'unknown crash' -- on exactly the logs this reporter exists for.
case "${USIG}" in
    *"Rejected chunk"*) ok "signature survives binary bytes in the log" ;;
    *) fail "signature was lost to binary detection: ${USIG}" ;;
esac
USIG_BYTES="$(printf '%s' "${USIG}" | wc -c)"
if [ "${USIG_BYTES}" -le 200 ]; then
    ok "signature is ${USIG_BYTES} bytes, within the 200 byte bound"
else
    fail "signature is ${USIG_BYTES} bytes, over the 200 byte bound"
fi
# The scrub discards invalid sequences. Without it jq's own leniency
# lets them through as U+FFFD replacement characters, which is then
# what gets interpolated into the fuzz-autofix prompt.
if printf '%s' "${USIG}" | grep -q "$(printf '\357\277\275')"; then
    fail "signature carries U+FFFD; the scrub did not run"
else
    ok "signature carries no U+FFFD replacement characters"
fi
if jq -r '.log_excerpt' < "${UBODY}" \
        | grep -q "$(printf '\357\277\275')"; then
    fail "excerpt carries U+FFFD; the scrub did not run"
else
    ok "excerpt carries no U+FFFD replacement characters"
fi

# --- Degenerate inputs -------------------------------------------------
start "a missing log file reports the crash anyway"
MBODY="${WORK}/missing.json"
if run_reporter fuzz_vhdx "${CRASH}" "${WORK}/nope.log" \
        > "${MBODY}" 2>/dev/null; then
    ok "reporter exited 0"
else
    fail "reporter exited non-zero"
fi
if jq -e '.source and .target and .signature and .reproducer' \
        < "${MBODY}" > /dev/null; then
    ok "body still satisfies the autofix predicate"
else
    fail "body does not satisfy the autofix predicate"
fi
check "signature falls back" \
    "$(jq -r '.signature' < "${MBODY}")" "unknown crash"
check "excerpt is empty" "$(jq -r '.log_excerpt' < "${MBODY}")" ""

start "a log with no panic or SUMMARY falls back to 'unknown crash'"
QUIET_LOG="${WORK}/quiet.log"
echo "INFO: seed corpus: files: 12 min: 1b max: 4096b" > "${QUIET_LOG}"
QBODY="${WORK}/quiet.json"
run_reporter fuzz_vdi "${CRASH}" "${QUIET_LOG}" > "${QBODY}"
check "signature falls back" \
    "$(jq -r '.signature' < "${QBODY}")" "unknown crash"

start "a missing crash file reports an unknown size"
SBODY="${WORK}/nosize.json"
run_reporter fuzz_vdi "${WORK}/gone" "${QUIET_LOG}" > "${SBODY}"
check "crash_input_size falls back" \
    "$(jq -r '.crash_input_size' < "${SBODY}")" "unknown bytes"

# --- The oversize-body escape hatch ------------------------------------
# Unreachable with the default bounds -- 30 lines of 200 bytes cannot
# reach 60000 -- so the branch is only ever exercised by raising them,
# which is exactly what this does.
start "an oversize body drops the excerpt rather than failing"
OBODY="${WORK}/oversize.json"
MAX_LINE_BYTES=100000 MAX_EXCERPT_BYTES=200000 \
    run_reporter fuzz_rebase_planners "${CRASH}" "${BIG_LOG}" \
    > "${OBODY}" 2>/dev/null
if jq -e . < "${OBODY}" > /dev/null 2>&1; then
    ok "body is valid JSON"
else
    fail "body is not valid JSON"
fi
check "excerpt was dropped" "$(jq -r '.log_excerpt' < "${OBODY}")" ""
if jq -e '.source and .target and .signature and .reproducer' \
        < "${OBODY}" > /dev/null; then
    ok "body still satisfies the autofix predicate"
else
    fail "body does not satisfy the autofix predicate"
fi

# --- Duplicate suppression ---------------------------------------------
# These are the only cases that leave --dry-run, because filing is the
# thing under test. A stub `gh` on PATH records what would have been
# called and serves a canned issue list, so still no API is touched.
STUB_BIN="${WORK}/bin"
mkdir -p "${STUB_BIN}"
cat > "${STUB_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
# Records the subcommand to ${GH_LOG} and answers `issue list` from
# ${GH_ISSUES} (a JSON array). Any other subcommand just succeeds.
echo "$1 $2" >> "${GH_LOG}"
if [ "$1 $2" = "issue list" ]; then
    if [ "${GH_LIST_FAILS:-0}" = "1" ]; then
        echo "gh: could not reach api.github.com" >&2
        exit 1
    fi
    cat "${GH_ISSUES}"
fi
exit 0
STUB
chmod +x "${STUB_BIN}/gh"

export GH_LOG GH_ISSUES
GH_ISSUES="${WORK}/issues.json"

# The signature the reporter derives from BIG_LOG, so the canned issue
# body matches the crash being reported.
KNOWN_SIG="$(jq -r '.signature' < "${BODY}")"

FILE_STATUS=0
file_crash() {
    # file_crash LOG [extra args...] -- leaves the reporter's exit code
    # in FILE_STATUS rather than returning it, so a reporter that dies
    # is a reported failure and not the end of this script.
    GH_LOG="${WORK}/gh.log"
    : > "${GH_LOG}"
    FILE_STATUS=0
    PATH="${STUB_BIN}:${PATH}" "${REPORTER}" fuzz_rebase_planners \
        "${CRASH}" "$@" > /dev/null 2>&1 || FILE_STATUS=$?
}

start "an open issue with the same target and signature is not refiled"
jq -n --arg sig "${KNOWN_SIG}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               signature: $sig} | tojson)}]' > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "commented on the existing issue" \
    "$(grep -c 'issue comment' "${GH_LOG}")" "1"
check "did not create a new issue" \
    "$(grep -c 'issue create' "${GH_LOG}")" "0"

start "--no-dedup files even when a duplicate exists"
file_crash "${BIG_LOG}" --no-dedup
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"
check "did not look for duplicates" \
    "$(grep -c 'issue list' "${GH_LOG}")" "0"

start "a different signature on the same target is a new issue"
jq -n '[{number: 42,
         title: "Coverage fuzz crash: fuzz_rebase_planners",
         body: ({source: "coverage-fuzz",
                 target: "fuzz_rebase_planners",
                 signature: "some other panic"} | tojson)}]' \
    > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"
check "did not comment" "$(grep -c 'issue comment' "${GH_LOG}")" "0"

start "a different target with the same signature is a new issue"
jq -n --arg sig "${KNOWN_SIG}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_qcow2",
       body: ({source: "coverage-fuzz",
               target: "fuzz_qcow2",
               signature: $sig} | tojson)}]' > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"

start "a hand-written issue body is not mistaken for a duplicate"
jq -n '[{number: 42,
         title: "Coverage fuzz crash: fuzz_rebase_planners",
         body: "I noticed this crashes, someone should look at it"}]' \
    > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"

start "a hand-written body elsewhere in the list does not break dedup"
# The security-audit label is applied by humans too. One issue whose
# body is not JSON must not stop the match on the one that is.
jq -n --arg sig "${KNOWN_SIG}" \
    '[{number: 41,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: "filed by hand, no JSON here"},
      {number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               signature: $sig} | tojson)}]' > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "commented on the existing issue" \
    "$(grep -c 'issue comment' "${GH_LOG}")" "1"
check "did not create a duplicate" \
    "$(grep -c 'issue create' "${GH_LOG}")" "0"

start "a failed duplicate lookup still files the crash"
# A duplicate issue is a far smaller problem than an unreported crash,
# so a lookup that cannot reach the API must fall through to filing
# rather than abort the reporter.
jq -n '[]' > "${GH_ISSUES}"
GH_LIST_FAILS=1 file_crash "${BIG_LOG}"
check "reporter exited 0" "${FILE_STATUS}" "0"
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"

# --- Argument handling -------------------------------------------------
start "bad arguments are rejected"
if "${REPORTER}" only_one_arg --dry-run > /dev/null 2>&1; then
    fail "missing arguments were accepted"
else
    ok "missing arguments rejected"
fi
if "${REPORTER}" a b c --nonsense > /dev/null 2>&1; then
    fail "an unknown flag was accepted"
else
    ok "unknown flag rejected"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
