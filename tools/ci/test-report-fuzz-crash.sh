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

# A libFuzzer log with the layout of a real one. This shape is copied
# from the 379KB fuzz_rebase_planners.log of run 31358293537, the crash
# that motivated the change: 91 lines, the panic at line 30, a ~30
# frame symbolized stack trace after it, the SUMMARY at line 67, then
# the artifact path, the single-line `std::fmt::Debug` dump, and
# cargo-fuzz's own reproduction block.
#
# The layout is the test, not decoration. An earlier fixture here was
# only ten lines, which let a `tail -n 30` excerpt look correct while
# on the real log it captured 28 stack frames and no panic at all.
make_log() {
    local path="$1" dump_bytes="$2" msg="${3:-}"
    if [ -z "${msg}" ]; then
        msg="qcow2 safe (deferred): Write patch 0"
        msg="${msg} (72057594037927944..72057594037928200) exceeds"
        msg="${msg} total_file_size (281076066929798)"
    fi
    {
        echo "INFO: Running with entropic power schedule"
        echo "#2      INITED cov: 118 ft: 119 corp: 1/1b"
        # 25 lines of libFuzzer progress, so the panic sits well outside
        # any window anchored on the end of the file.
        for i in $(seq 1 25); do
            echo "#${i}00000	REDUCE cov: 316 ft: 580 corp: 152/393Kb" \
                "lim: 90096 exec/s: 130692 rss: 455Mb L: 61485/61486"
        done
        echo "thread '<unnamed>' (47) panicked at" \
            "fuzz_targets/fuzz_rebase_planners.rs:278:17:"
        echo "${msg}"
        echo "note: run with \`RUST_BACKTRACE=1\` for a backtrace"
        echo "==47== ERROR: libFuzzer: deadly signal"
        # Full-width frames on purpose. A real symbolized frame is
        # around 190 bytes, so the 31 line window runs past the 4000
        # byte excerpt cap and the cap decides what survives. With
        # short frames the cap never binds and the test cannot tell
        # head -c from tail -c -- which is the difference between
        # keeping the panic and keeping the last stack frames.
        for i in $(seq 0 29); do
            echo "    #${i} 0x5632290eb561  (/workspace/src/fuzz/target/" \
                "x86_64-unknown-linux-gnu/release/fuzz_rebase_planners" \
                "+0xff561) (BuildId: 478ffff1a6a6a463242d24ca1189da04" \
                "caf37eb5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"
        done
        echo "NOTE: libFuzzer has rudimentary signal handlers."
        echo "SUMMARY: libFuzzer: deadly signal"
        echo "MS: 4 ShuffleBytes-CopyPart-ChangeBit-CMP-; base unit: 79125"
        echo "artifact_prefix='./'; Test unit written to" \
            "./artifacts/fuzz_rebase_planners/crash-deadbeef"
        echo "Failing input:"
        echo "	artifacts/fuzz_rebase_planners/crash-deadbeef"
        # shellcheck disable=SC2016  # libFuzzer's own wording
        printf 'Output of `std::fmt::Debug`:\n'
        head -c "${dump_bytes}" < /dev/zero | tr '\0' 'a'
        printf '\n'
        echo "Reproduce with:"
        echo "	cargo fuzz run fuzz_rebase_planners artifacts/x"
        echo "Minimize test case with:"
        echo "	cargo fuzz tmin fuzz_rebase_planners artifacts/x"
        echo "Error: Fuzz target exited with exit status: 77"
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

# Why the excerpt is windowed on the crash and not on the end of the
# file. On a real log the panic is a third of the way in, with 30 stack
# frames and a reproduction block after it, so a tail-anchored window
# shows neither the panic nor its message -- which is what the excerpt
# is for, since it is the richest field in the issue.
if jq -e '.log_excerpt | contains("panicked at")' \
        < "${BODY}" > /dev/null; then
    ok "excerpt keeps the panic line"
else
    fail "excerpt lost the panic line"
fi

if jq -e '.log_excerpt | contains("exceeds total_file_size")' \
        < "${BODY}" > /dev/null; then
    ok "excerpt keeps the panic message"
else
    fail "excerpt lost the panic message"
fi

# Context before the panic, so the excerpt shows the run reaching it.
if jq -e '.log_excerpt | contains("REDUCE cov:")' \
        < "${BODY}" > /dev/null; then
    ok "excerpt keeps the lines leading up to the panic"
else
    fail "excerpt lost the lines before the panic"
fi

# The whole point of clipping per line rather than per byte: a 370KB
# Debug dump must not be able to crowd anything out. Note the dump line
# is below the window here, so its absence is expected either way; what
# matters is that the excerpt stayed small.
if jq -e '.log_excerpt | length < 5000' < "${BODY}" > /dev/null; then
    ok "excerpt is bounded"
else
    fail "excerpt is not bounded"
fi

# --- The fields a triager needs first -----------------------------------
start "the body carries the fields a triager needs first"
if jq -e '.source and .target and .signature and .reproducer' \
        < "${BODY}" > /dev/null; then
    ok "source, target, signature and reproducer are all present"
else
    fail "a field a triager needs is missing or empty"
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
# what lands in the issue body a person reads.
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
    ok "body still carries the fields a triager needs"
else
    fail "body is missing a field a triager needs"
fi
check "signature falls back" \
    "$(jq -r '.signature' < "${MBODY}")" "unknown crash"
check "excerpt is empty" "$(jq -r '.log_excerpt' < "${MBODY}")" ""

start "a log with no panic or SUMMARY falls back to 'unknown crash'"
QUIET_LOG="${WORK}/quiet.log"
{
    echo "INFO: seed corpus: files: 12 min: 1b max: 4096b"
    for i in $(seq 1 40); do echo "error[E0308]: mismatch ${i}"; done
    echo "error: could not compile fuzz_targets"
} > "${QUIET_LOG}"
QBODY="${WORK}/quiet.json"
run_reporter fuzz_vdi "${CRASH}" "${QUIET_LOG}" > "${QBODY}"
check "signature falls back" \
    "$(jq -r '.signature' < "${QBODY}")" "unknown crash"
check "dedup key falls back too" \
    "$(jq -r '.dedup_key' < "${QBODY}")" "unknown crash"
# With nothing to anchor on -- a build failure, a truncated log -- the
# tail is the best guess at where the trouble is.
if jq -e '.log_excerpt | contains("could not compile")' \
        < "${QBODY}" > /dev/null; then
    ok "excerpt falls back to the tail of the log"
else
    fail "excerpt did not fall back to the tail"
fi

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
# Needs a log with no panic to anchor on, because the anchored window
# sits above the Debug dump and so cannot get near 60000 bytes however
# the caps are set. The fallback tail window can, which is the path
# that has to survive it.
HUGE_LOG="${WORK}/huge.log"
{
    echo "error: could not compile fuzz_targets"
    head -c 200000 < /dev/zero | tr '\0' 'z'
    printf '\n'
} > "${HUGE_LOG}"
OBODY="${WORK}/oversize.json"
MAX_LINE_BYTES=100000 MAX_EXCERPT_BYTES=200000 \
    run_reporter fuzz_rebase_planners "${CRASH}" "${HUGE_LOG}" \
    > "${OBODY}" 2>/dev/null
if jq -e . < "${OBODY}" > /dev/null 2>&1; then
    ok "body is valid JSON"
else
    fail "body is not valid JSON"
fi
check "excerpt was dropped" "$(jq -r '.log_excerpt' < "${OBODY}")" ""
if jq -e '.source and .target and .signature and .reproducer' \
        < "${OBODY}" > /dev/null; then
    ok "body still carries the fields a triager needs"
else
    fail "body is missing a field a triager needs"
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
# ${GH_ISSUES} (a JSON array). GH_LIST_FAILS / GH_CREATE_FAILS /
# GH_COMMENT_FAILS make the matching subcommand fail like a 403 or a
# network error would.
echo "$1 $2" >> "${GH_LOG}"
case "$1 $2" in
    "issue list")
        if [ "${GH_LIST_FAILS:-0}" = "1" ]; then
            echo "gh: could not reach api.github.com" >&2
            exit 1
        fi
        cat "${GH_ISSUES}"
        ;;
    "issue create")
        if [ "${GH_CREATE_FAILS:-0}" = "1" ]; then
            echo "gh: HTTP 403: Resource not accessible" >&2
            exit 1
        fi
        ;;
    "issue comment")
        if [ "${GH_COMMENT_FAILS:-0}" = "1" ]; then
            echo "gh: HTTP 403: Resource not accessible" >&2
            exit 1
        fi
        ;;
esac
exit 0
STUB
chmod +x "${STUB_BIN}/gh"

export GH_LOG GH_ISSUES
GH_ISSUES="${WORK}/issues.json"

# What the reporter derives from BIG_LOG, so a canned issue body can be
# made to match -- or deliberately not match -- the crash being
# reported.
KNOWN_SIG="$(jq -r '.signature' < "${BODY}")"
KNOWN_KEY="$(jq -r '.dedup_key' < "${BODY}")"

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

start "an open issue with the same target and key is not refiled"
jq -n --arg key "${KNOWN_KEY}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               dedup_key: $key} | tojson)}]' > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "commented on the existing issue" \
    "$(grep -c 'issue comment' "${GH_LOG}")" "1"
check "did not create a new issue" \
    "$(grep -c 'issue create' "${GH_LOG}")" "0"

start "the same bug with different fuzz operands is not refiled"
# The case exact-signature matching got wrong, and the reason dedup_key
# exists: a Rust panic message interpolates the values that provoked it,
# so two inputs hitting one assertion produce two different signatures.
# Without normalization this files a fresh issue every single night,
# flooding the security-audit queue with duplicates of one bug.
VARIANT_LOG="${WORK}/variant.log"
VARIANT_MSG="qcow2 safe (deferred): Write patch 7 (99..1234) exceeds"
VARIANT_MSG="${VARIANT_MSG} total_file_size (4096)"
make_log "${VARIANT_LOG}" 1000 "${VARIANT_MSG}"
VBODY="${WORK}/variant.json"
run_reporter fuzz_rebase_planners "${CRASH}" "${VARIANT_LOG}" > "${VBODY}"
VARIANT_SIG="$(jq -r '.signature' < "${VBODY}")"
VARIANT_KEY="$(jq -r '.dedup_key' < "${VBODY}")"
if [ "${VARIANT_SIG}" != "${KNOWN_SIG}" ]; then
    ok "the two signatures genuinely differ"
else
    fail "the fixture does not actually vary the operands"
fi
check "but the dedup keys match" "${VARIANT_KEY}" "${KNOWN_KEY}"
jq -n --arg key "${KNOWN_KEY}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               dedup_key: $key} | tojson)}]' > "${GH_ISSUES}"
file_crash "${VARIANT_LOG}"
check "commented on the existing issue" \
    "$(grep -c 'issue comment' "${GH_LOG}")" "1"
check "did not create a duplicate" \
    "$(grep -c 'issue create' "${GH_LOG}")" "0"

start "an OOM recurring with different inputs is not refiled"
# Not every fuzz failure is a Rust panic. On an OOM, a timeout or a
# deadly signal the anchor is libFuzzer's SUMMARY line, and the line
# after it is the MS: mutation line ending in a per-INPUT
# "base unit: <hex>". Hex survives digit collapsing, so including that
# line would give every recurring OOM a fresh key -- and a fresh issue
# every night, into a queue drained once a day.
make_oom_log() {
    {
        echo "==47== ERROR: libFuzzer: out-of-memory (malloc(4294967296))"
        echo "SUMMARY: libFuzzer: out-of-memory"
        echo "MS: 4 ShuffleBytes-CopyPart-ChangeBit-CMP-; base unit: $2"
        echo "artifact_prefix='./'; Test unit written to ./oom-abc"
    } > "$1"
}
make_oom_log "${WORK}/oom-a.log" 79125abc12
make_oom_log "${WORK}/oom-b.log" aa4f9912cd
OOM_A="$(run_reporter fuzz_qcow2 "${CRASH}" "${WORK}/oom-a.log" \
    | jq -r '.dedup_key')"
OOM_B="$(run_reporter fuzz_qcow2 "${CRASH}" "${WORK}/oom-b.log" \
    | jq -r '.dedup_key')"
check "the two OOM keys match" "${OOM_A}" "${OOM_B}"
case "${OOM_A}" in
    *"base unit"*) fail "key still carries the per-input base unit" ;;
    *out-of-memory*) ok "key is the SUMMARY line: ${OOM_A}" ;;
    *) fail "key does not identify the failure: ${OOM_A}" ;;
esac

start "a varying thread id does not change the key"
# Rust >=1.86 prints "thread '<unnamed>' (47) panicked at ...", and the
# 47 is a thread id that varies between runs.
make_tid_log() {
    {
        echo "thread '<unnamed>' ($2) panicked at src/lib.rs:1:1:"
        echo "boom at offset 4096"
    } > "$1"
}
make_tid_log "${WORK}/tid-a.log" 47
make_tid_log "${WORK}/tid-b.log" 12
TID_A="$(run_reporter fuzz_vhd "${CRASH}" "${WORK}/tid-a.log" \
    | jq -r '.dedup_key')"
TID_B="$(run_reporter fuzz_vhd "${CRASH}" "${WORK}/tid-b.log" \
    | jq -r '.dedup_key')"
check "the two keys match" "${TID_A}" "${TID_B}"
case "${TID_A}" in
    *src/lib.rs:1:1*) ok "key keeps the crash location" ;;
    *) fail "key lost the crash location: ${TID_A}" ;;
esac
# The signature a human reads keeps the thread id; only the key drops
# it.
SIG_A="$(run_reporter fuzz_vhd "${CRASH}" "${WORK}/tid-a.log" \
    | jq -r '.signature')"
case "${SIG_A}" in
    *"(47)"*) ok "signature still shows the thread id" ;;
    *) fail "signature lost the thread id: ${SIG_A}" ;;
esac

start "two assertion sites in one file stay separate"
# The over-merge guard: normalizing the location's line:col would fold
# these into one issue.
make_tid_log "${WORK}/site-a.log" 47
{
    echo "thread '<unnamed>' (47) panicked at src/lib.rs:900:3:"
    echo "boom at offset 4096"
} > "${WORK}/site-b.log"
SITE_A="$(run_reporter fuzz_vhd "${CRASH}" "${WORK}/site-a.log" \
    | jq -r '.dedup_key')"
SITE_B="$(run_reporter fuzz_vhd "${CRASH}" "${WORK}/site-b.log" \
    | jq -r '.dedup_key')"
if [ "${SITE_A}" != "${SITE_B}" ]; then
    ok "different lines in one file get different keys"
else
    fail "two assertion sites collapsed to one key"
fi

start "digits inside identifiers are not collapsed"
# A bare digit collapse would turn qcow2 and qcow3 both into qcowN and
# merge two different bugs into one issue -- the wrong direction to err
# in, since a duplicate issue is only noise.
OTHER_LOG="${WORK}/other.log"
OTHER_MSG="qcow3 safe (deferred): Write patch 0 (1..2) exceeds"
OTHER_MSG="${OTHER_MSG} total_file_size (4096)"
make_log "${OTHER_LOG}" 1000 "${OTHER_MSG}"
OBODY2="${WORK}/other.json"
run_reporter fuzz_rebase_planners "${CRASH}" "${OTHER_LOG}" > "${OBODY2}"
if [ "$(jq -r '.dedup_key' < "${OBODY2}")" != "${KNOWN_KEY}" ]; then
    ok "qcow3 and qcow2 get different keys"
else
    fail "qcow3 and qcow2 collapsed to the same key"
fi
file_crash "${OTHER_LOG}"
check "created a separate issue" \
    "$(grep -c 'issue create' "${GH_LOG}")" "1"

start "an issue filed before dedup_key existed still matches"
# Issues already open when this shipped carry only a signature.
jq -n --arg sig "${KNOWN_SIG}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               signature: $sig} | tojson)}]' > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "commented on the legacy issue" \
    "$(grep -c 'issue comment' "${GH_LOG}")" "1"
check "did not create a duplicate" \
    "$(grep -c 'issue create' "${GH_LOG}")" "0"

start "--no-dedup files even when a duplicate exists"
file_crash "${BIG_LOG}" --no-dedup
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"
check "did not look for duplicates" \
    "$(grep -c 'issue list' "${GH_LOG}")" "0"

start "a different crash on the same target is a new issue"
jq -n '[{number: 42,
         title: "Coverage fuzz crash: fuzz_rebase_planners",
         body: ({source: "coverage-fuzz",
                 target: "fuzz_rebase_planners",
                 dedup_key: "some other panic"} | tojson)}]' \
    > "${GH_ISSUES}"
file_crash "${BIG_LOG}"
check "created an issue" "$(grep -c 'issue create' "${GH_LOG}")" "1"
check "did not comment" "$(grep -c 'issue comment' "${GH_LOG}")" "0"

start "a different target with the same key is a new issue"
jq -n --arg key "${KNOWN_KEY}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_qcow2",
       body: ({source: "coverage-fuzz",
               target: "fuzz_qcow2",
               dedup_key: $key} | tojson)}]' > "${GH_ISSUES}"
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
jq -n --arg key "${KNOWN_KEY}" \
    '[{number: 41,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: "filed by hand, no JSON here"},
      {number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               dedup_key: $key} | tojson)}]' > "${GH_ISSUES}"
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

# --- Never silently green ----------------------------------------------
# The guarantee the whole change rests on: when the reporter cannot tell
# anyone about a crash it must exit non-zero, so the caller's `if ! ...`
# increments REPORT_FAILURES and the final workflow step turns the run
# red. Nothing downstream of here can recover a crash that was neither
# filed nor counted.
start "a failed issue create makes the reporter exit non-zero"
jq -n '[]' > "${GH_ISSUES}"
GH_CREATE_FAILS=1 file_crash "${BIG_LOG}"
if [ "${FILE_STATUS}" -ne 0 ]; then
    ok "reporter exited ${FILE_STATUS}"
else
    fail "reporter exited 0 despite failing to file"
fi

start "a failed issue comment makes the reporter exit non-zero"
jq -n --arg key "${KNOWN_KEY}" \
    '[{number: 42,
       title: "Coverage fuzz crash: fuzz_rebase_planners",
       body: ({source: "coverage-fuzz",
               target: "fuzz_rebase_planners",
               dedup_key: $key} | tojson)}]' > "${GH_ISSUES}"
GH_COMMENT_FAILS=1 file_crash "${BIG_LOG}"
if [ "${FILE_STATUS}" -ne 0 ]; then
    ok "reporter exited ${FILE_STATUS}"
else
    fail "reporter exited 0 despite failing to comment"
fi

start "an unavailable gh makes the reporter exit non-zero"
# Shadow gh specifically. Emptying PATH instead would kill the script
# at its first mktemp, long before gh, and the assertion would pass on
# an unrelated failure -- so a regression making a missing gh non-fatal
# would still look green.
MISSING_BIN="${WORK}/missingbin"
mkdir -p "${MISSING_BIN}"
cat > "${MISSING_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh: command not found" >&2
exit 127
STUB
chmod +x "${MISSING_BIN}/gh"
STATUS=0
PATH="${MISSING_BIN}:${PATH}" "${REPORTER}" fuzz_rebase_planners \
    "${CRASH}" "${BIG_LOG}" > /dev/null 2>&1 || STATUS=$?
check "reporter propagated gh's failure" "${STATUS}" "127"

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
