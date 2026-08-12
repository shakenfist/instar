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
# them without updating that workflow.
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
#   GH_TOKEN      (required unless --dry-run) for `gh issue create`.
#   WORKFLOW_URL  (optional) run URL recorded in the issue body.

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
SIGNATURE="$(grep -a -m1 -A1 'panicked at\|SUMMARY:' "${LOG_FILE}" \
    2>/dev/null \
    | tr '\n\t' '  ' | tr -d '\000' | head -c 200 \
    | "${SCRUB[@]}" 2>/dev/null || true)"
if [ -z "${SIGNATURE}" ]; then
    SIGNATURE='unknown crash'
fi

CRASH_SIZE="$(stat -c%s "${CRASH_FILE}" 2>/dev/null || echo unknown)"
REPRO="cd src/fuzz && cargo fuzz run ${TARGET}"
REPRO="${REPRO} artifacts/${TARGET}/$(basename "${CRASH_FILE}")"
TITLE="Coverage fuzz crash: ${TARGET}"

EXCERPT_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
trap 'rm -f "${EXCERPT_FILE}" "${BODY_FILE}"' EXIT

# Truncate every LINE first, then take the last few. Bounding by bytes
# alone would work but would hand back the tail of the Debug dump --
# raw byte soup -- while the lines that matter (the panic, the libFuzzer
# SUMMARY, the artifact path) sit just above it. Clipping each line to
# MAX_LINE_BYTES keeps those intact and reduces the dump to a stub.
# `cut -b` and the trailing byte cap are what actually bound the result;
# `tail -n` alone cannot, because one line here can be 370KB wide.
#
# Then drop NULs and re-encode as UTF-8, discarding invalid sequences:
# fuzz logs carry raw mutated bytes, a byte-wise cut can slice a
# multi-byte character in half, and jq rejects invalid UTF-8 -- as does
# the GitHub API.
MAX_LINE_BYTES="${MAX_LINE_BYTES:-200}"
cut -b "1-${MAX_LINE_BYTES}" "${LOG_FILE}" 2>/dev/null \
    | tail -n 30 \
    | tail -c "${MAX_EXCERPT_BYTES}" \
    | tr -d '\000' \
    | "${SCRUB[@]}" 2>/dev/null > "${EXCERPT_FILE}" || true

# One definition of the body, called twice: the field names are a
# contract with fuzz-autofix.yml, and two copies of them is two things
# to keep in step.
build_body() {
    jq -n \
        --arg source "coverage-fuzz" \
        --arg target "${TARGET}" \
        --arg signature "${SIGNATURE}" \
        --arg reproducer "${REPRO}" \
        --arg crash_input_size "${CRASH_SIZE} bytes" \
        --rawfile log_excerpt "${EXCERPT_FILE}" \
        --arg ci_run "${WORKFLOW_URL:-unknown}" \
        '{source: $source, target: $target,
          signature: $signature, reproducer: $reproducer,
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
# target AND signature: the same target can crash in more than one way,
# and those want separate issues, but the same crash every night does
# not. A lookup that fails (no token, API trouble) falls through to
# filing, because a duplicate issue is a much smaller problem than an
# unreported crash.
if [ "${DEDUP}" -eq 1 ]; then
    EXISTING="$(gh issue list \
        --label "security-audit" \
        --state open \
        --json number,title,body \
        --limit 100 2>/dev/null \
        | jq -r --arg title "${TITLE}" --arg sig "${SIGNATURE}" \
            'map(select(.title == $title
                        and ((.body | fromjson?).signature == $sig)))
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
