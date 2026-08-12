#!/usr/bin/env bash
#
# File a GitHub issue describing a crash found by the coverage-fuzz
# workflow.
#
# This used to be an inline block in .github/workflows/coverage-fuzz.yml,
# where it silently broke the entire nightly run. `cargo fuzz` prints the
# failing input as `Output of `std::fmt::Debug`:` followed by ONE line
# holding the whole input; with -max_len=4194304 a large crash input
# produces a single log line hundreds of kilobytes wide. The old code did:
#
#     LOG_TAIL=$(tail -30 "coverage-fuzz-logs/${TARGET}.log")
#     jq -n ... --arg log_excerpt "$LOG_TAIL" ...
#
# and an 81KB crash input in fuzz_rebase_planners made that a 371KB argv
# entry -- past Linux's 128KiB MAX_ARG_STRLEN -- so jq died with
# "Argument list too long". The step runs under `bash -e`, so the whole
# fuzz step aborted at the first crash: no issue filed, the remaining 21
# of 40 targets never fuzzed, and the corpus push skipped. That ran every
# night from 2026-07-16 to 2026-08-11 without anyone being told.
#
# So: the excerpt is bounded in BYTES before it goes anywhere near a
# command line, it is passed via --rawfile (a file, not argv), and it is
# scrubbed of anything that would make jq or the GitHub API reject the
# body. The caller treats a failure here as a warning, not a job-ending
# error -- a fuzz run that cannot file an issue must still fuzz the rest
# of its targets.
#
# Because the run no longer stops at the first crash, a night with N
# crashing targets reports N crashes, and it does so again every night
# until each is fixed. An open issue for the same target and signature
# is therefore commented on rather than refiled, so the security-audit
# queue that fuzz-autofix.yml drains (one issue per day) does not grow a
# duplicate per crash per night.
#
# The JSON field names are a contract with fuzz-autofix.yml, which reads
# .target/.signature/.reproducer/.log_excerpt/.crash_input_size out of
# the issue body and feeds only those fields to Claude. Do not rename
# them without updating that workflow. .dedup_key is read only by this
# script, on its next run.
#
# tools/ci/test-report-fuzz-crash.sh exercises all of this against
# synthetic logs, including the 370KB-single-line case that broke the
# nightlies.
#
# Usage:
#   tools/ci/report-fuzz-crash.sh TARGET CRASH_FILE LOG_FILE \
#       [--dry-run] [--no-dedup]
#
# --dry-run builds the issue body and prints it instead of filing, for
# local testing against a downloaded coverage-fuzz-logs artifact. It
# implies --no-dedup, since it talks to no API at all.
#
# --no-dedup files unconditionally, without looking for an existing open
# issue for the same crash.
#
# Inputs (environment):
#   GH_TOKEN          (required unless --dry-run) for `gh issue create`.
#   WORKFLOW_URL      (optional) run URL recorded in the issue body.
#   MAX_EXCERPT_BYTES (default 4000) byte cap on the whole excerpt.
#   MAX_LINE_BYTES    (default 200) byte cap on each excerpt line.
#
# The two byte caps exist mostly so the tests can drive the
# oversize-body path, which the defaults cannot reach: 30 lines of 200
# bytes cannot approach the 60000 byte guard.

set -euo pipefail

usage() {
    echo "usage: $0 TARGET CRASH_FILE LOG_FILE [--dry-run] [--no-dedup]" \
        >&2
    exit 2
}

DRY_RUN=0
DEDUP=1
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; DEDUP=0 ;;
        --no-dedup) DEDUP=0 ;;
        -*) usage ;;
        *) POSITIONAL+=("$1") ;;
    esac
    shift
done

if [ "${#POSITIONAL[@]}" -ne 3 ]; then
    usage
fi
TARGET="${POSITIONAL[0]}"
CRASH_FILE="${POSITIONAL[1]}"
LOG_FILE="${POSITIONAL[2]}"

if [ -z "${TARGET}" ] || [ -z "${CRASH_FILE}" ] || [ -z "${LOG_FILE}" ]; then
    usage
fi

# Bytes of log tail to quote in the issue. Small on purpose: the useful
# part of a libFuzzer crash is the panic line and the SUMMARY, both of
# which land in the last few hundred bytes ahead of the Debug dump. A
# GitHub issue body is capped at 65536 characters, and the excerpt is
# only one field of the body.
MAX_EXCERPT_BYTES="${MAX_EXCERPT_BYTES:-4000}"

if [ ! -f "${LOG_FILE}" ]; then
    echo "::warning::${LOG_FILE} not found; reporting ${TARGET} crash" \
        "without a log excerpt" >&2
    LOG_FILE=/dev/null
fi

# Pick the scrubber once, up front, rather than writing
# `iconv ... || cat` in the pipeline. That form runs cat on whatever is
# left of the pipe when iconv exits non-zero, so an iconv that died
# partway through would splice the raw, unscrubbed remainder onto the
# converted prefix -- defeating the scrub in exactly the case it exists
# to cover. Deciding here means the fallback is only ever "iconv is not
# installed", where passing stdin through untouched is correct.
if command -v iconv >/dev/null 2>&1; then
    SCRUB=(iconv -c -f UTF-8 -t UTF-8)
else
    SCRUB=(cat)
fi

# The signature is the first panic/SUMMARY line PLUS the line after it:
# Rust prints the location ("panicked at foo.rs:278:17:") and the actual
# message ("Write patch 0 (..) exceeds total_file_size (..)") on separate
# lines, and a location on its own does not identify a crash. Bounded,
# because a panic message can itself carry fuzz data -- and scrubbed the
# same way the excerpt is, since `head -c` can slice a multi-byte
# character in half and this value is also interpolated into the
# fuzz-autofix prompt. grep -m1 into head -c closes the pipe early, so
# tolerate the SIGPIPE/no-match.
#
# -a matters: a fuzz log carries raw mutated bytes, and without it grep
# decides the file is binary and prints nothing at all to stdout, so
# every signature from a log with a stray high byte in it silently
# degrades to 'unknown crash'. Reading it as text is safe here because
# the result is bounded and scrubbed immediately below.
scrub_field() {
    # Bound and scrub one line of fuzzer-derived text for jq.
    tr '\n\t' '  ' | tr -d '\000' | head -c 200 \
        | "${SCRUB[@]}" 2>/dev/null || true
}

# The crash location on its own ("panicked at foo.rs:278:17") and the
# message on its own are each read separately, because they are used
# differently below: both go into the signature, but only the message
# is normalized for the dedup key.
CRASH_HIT="$(grep -a -n -m1 'panicked at\|SUMMARY:' "${LOG_FILE}" \
    2>/dev/null || true)"
CRASH_LINE="${CRASH_HIT%%:*}"
SIG_LOC="$(printf '%s' "${CRASH_HIT#*:}" | scrub_field)"
SIG_MSG=""
if [ -n "${CRASH_LINE}" ]; then
    SIG_MSG="$(sed -n "$((CRASH_LINE + 1))p" "${LOG_FILE}" 2>/dev/null \
        | scrub_field)"
fi

SIGNATURE="$(printf '%s %s' "${SIG_LOC}" "${SIG_MSG}" | scrub_field)"
if [ -z "${SIG_LOC}" ]; then
    SIGNATURE='unknown crash'
fi

# Dedup matches on this, not on the signature, because a Rust panic
# message routinely interpolates the fuzz-derived values that provoked
# it -- the real crash behind this change reads "Write patch 0
# (72057594037927944..72057594037928200) exceeds total_file_size
# (281076066929798)". Two inputs hitting the same assertion produce
# different numbers, so exact-signature matching would file a fresh
# issue every night for one bug. Collapsing standalone numbers in the
# MESSAGE fixes that; the location is left alone, so two different
# assertion sites in one file still get two issues.
#
# \b, so only whole numbers collapse. A bare sed 's/[0-9]*/N/g' would
# also eat the digits inside identifiers -- "qcow2" and "qcow3" would
# both become "qcowN" and two genuinely different bugs would share one
# issue. Over-merging is the worse direction here: a duplicate issue is
# noise, a swallowed crash is a crash nobody hears about.
DEDUP_KEY="$(printf '%s %s' "${SIG_LOC}" \
    "$(printf '%s' "${SIG_MSG}" | sed 's/\b[0-9][0-9]*\b/N/g')" \
    | scrub_field)"
if [ -z "${SIG_LOC}" ]; then
    DEDUP_KEY='unknown crash'
fi

CRASH_SIZE="$(stat -c%s "${CRASH_FILE}" 2>/dev/null || echo unknown)"
REPRO="cd src/fuzz && cargo fuzz run ${TARGET}"
REPRO="${REPRO} artifacts/${TARGET}/$(basename "${CRASH_FILE}")"
TITLE="Coverage fuzz crash: ${TARGET}"

EXCERPT_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
trap 'rm -f "${EXCERPT_FILE}" "${BODY_FILE}"' EXIT

# Window the excerpt on the CRASH, not on the end of the file. A real
# `cargo fuzz run` failure prints, after the panic: a ~30 frame
# symbolized stack trace, the SUMMARY, the MS: mutation line, the
# artifact path, the Debug dump, and cargo-fuzz's own reproduction
# block. In the 379KB log that motivated this change the panic is line
# 30 of 91, so a `tail -n 30` window starts at line 62 and contains no
# panic line and no panic message at all -- 28 stack frames and
# boilerplate instead. Since log_excerpt is the richest field
# fuzz-autofix hands to Claude, anchoring matters more than recency.
#
# Every LINE is clipped first, because bounding by bytes alone would
# hand back the tail of the Debug dump -- raw byte soup -- while the
# lines that matter sit above it. `cut -b` and the byte cap are what
# actually bound the result; a line count cannot, because one line here
# can be 370KB wide.
#
# Then drop NULs and re-encode as UTF-8, discarding invalid sequences:
# fuzz logs carry raw mutated bytes, a byte-wise cut can slice a
# multi-byte character in half, and jq rejects invalid UTF-8 -- as does
# the GitHub API.
MAX_LINE_BYTES="${MAX_LINE_BYTES:-200}"
CONTEXT_BEFORE=5
CONTEXT_AFTER=25

if [ -n "${CRASH_LINE}" ]; then
    WINDOW_START=$((CRASH_LINE - CONTEXT_BEFORE))
    [ "${WINDOW_START}" -lt 1 ] && WINDOW_START=1
    WINDOW_END=$((CRASH_LINE + CONTEXT_AFTER))
    # head -c, not tail -c: the panic is at the TOP of this window, so
    # trimming from the end is what keeps it.
    sed -n "${WINDOW_START},${WINDOW_END}p" "${LOG_FILE}" 2>/dev/null \
        | cut -b "1-${MAX_LINE_BYTES}" \
        | head -c "${MAX_EXCERPT_BYTES}" \
        | tr -d '\000' \
        | "${SCRUB[@]}" 2>/dev/null > "${EXCERPT_FILE}" || true
else
    # No panic or SUMMARY to anchor on -- a build failure, a truncated
    # log. The tail is then the best guess at where the trouble is.
    cut -b "1-${MAX_LINE_BYTES}" "${LOG_FILE}" 2>/dev/null \
        | tail -n 30 \
        | tail -c "${MAX_EXCERPT_BYTES}" \
        | tr -d '\000' \
        | "${SCRUB[@]}" 2>/dev/null > "${EXCERPT_FILE}" || true
fi

# One definition of the body, called twice: the field names are a
# contract with fuzz-autofix.yml, and two copies of them is two things
# to keep in step.
build_body() {
    jq -n \
        --arg source "coverage-fuzz" \
        --arg target "${TARGET}" \
        --arg signature "${SIGNATURE}" \
        --arg dedup_key "${DEDUP_KEY}" \
        --arg reproducer "${REPRO}" \
        --arg crash_input_size "${CRASH_SIZE} bytes" \
        --rawfile log_excerpt "${EXCERPT_FILE}" \
        --arg ci_run "${WORKFLOW_URL:-unknown}" \
        '{source: $source, target: $target,
          signature: $signature, dedup_key: $dedup_key,
          reproducer: $reproducer,
          crash_input_size: $crash_input_size,
          log_excerpt: $log_excerpt, ci_run: $ci_run}' \
        > "${BODY_FILE}"
}

build_body

BODY_BYTES="$(wc -c < "${BODY_FILE}")"
if [ "${BODY_BYTES}" -gt 60000 ]; then
    echo "::warning::issue body for ${TARGET} is ${BODY_BYTES} bytes;" \
        "dropping the log excerpt" >&2
    : > "${EXCERPT_FILE}"
    build_body
fi

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "--dry-run: would file an issue titled '${TITLE}'"
    echo "body is $(wc -c < "${BODY_FILE}") bytes:"
    cat "${BODY_FILE}"
    exit 0
fi

# Comment on the existing issue rather than filing a duplicate. Match on
# target AND dedup key: the same target can crash in more than one way,
# and those want separate issues, but the same crash every night does
# not. Issues filed before dedup_key existed are matched on their
# signature instead. A lookup that fails (no token, API trouble) falls
# through to filing, because a duplicate issue is a much smaller problem
# than an unreported crash.
if [ "${DEDUP}" -eq 1 ]; then
    EXISTING="$(gh issue list \
        --label "security-audit" \
        --state open \
        --json number,title,body \
        --limit 100 2>/dev/null \
        | jq -r --arg title "${TITLE}" --arg sig "${SIGNATURE}" \
            --arg key "${DEDUP_KEY}" \
            'map(select(.title == $title
                        and (.body | fromjson? | . as $b
                             | if $b.dedup_key
                               then $b.dedup_key == $key
                               else $b.signature == $sig end)))
             | .[0].number // empty' 2>/dev/null || true)"

    if [ -n "${EXISTING}" ]; then
        echo "Crash in ${TARGET} already tracked by issue #${EXISTING};" \
            "commenting instead of filing a duplicate"
        COMMENT_FILE="$(mktemp)"
        trap 'rm -f "${EXCERPT_FILE}" "${BODY_FILE}" "${COMMENT_FILE}"' \
            EXIT
        {
            printf 'Seen again in %s.\n\n' "${WORKFLOW_URL:-this run}"
            printf 'Crash input: %s bytes, reproduce with:\n\n' \
                "${CRASH_SIZE}"
            # shellcheck disable=SC2016  # markdown fence, not a command
            printf '```\n%s\n```\n' "${REPRO}"
        } > "${COMMENT_FILE}"
        gh issue comment "${EXISTING}" --body-file "${COMMENT_FILE}"
        exit 0
    fi
fi

gh issue create \
    --label "security-audit" \
    --title "${TITLE}" \
    --body-file "${BODY_FILE}"
