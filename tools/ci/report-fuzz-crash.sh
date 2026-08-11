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
# The JSON field names are a contract with fuzz-autofix.yml, which reads
# .target/.signature/.reproducer/.log_excerpt/.crash_input_size out of
# the issue body and feeds only those fields to Claude. Do not rename
# them without updating that workflow.
#
# Usage:
#   tools/ci/report-fuzz-crash.sh TARGET CRASH_FILE LOG_FILE [--dry-run]
#
# --dry-run builds the issue body and prints it instead of filing, for
# local testing against a downloaded coverage-fuzz-logs artifact.
#
# Inputs (environment):
#   GH_TOKEN      (required unless --dry-run) for `gh issue create`.
#   WORKFLOW_URL  (optional) run URL recorded in the issue body.

set -euo pipefail

TARGET="${1:-}"
CRASH_FILE="${2:-}"
LOG_FILE="${3:-}"
DRY_RUN=0
if [ "${4:-}" = "--dry-run" ]; then
    DRY_RUN=1
elif [ -n "${4:-}" ]; then
    echo "usage: $0 TARGET CRASH_FILE LOG_FILE [--dry-run]" >&2
    exit 2
fi

if [ -z "${TARGET}" ] || [ -z "${CRASH_FILE}" ] || [ -z "${LOG_FILE}" ]; then
    echo "usage: $0 TARGET CRASH_FILE LOG_FILE [--dry-run]" >&2
    exit 2
fi

# Bytes of log tail to quote in the issue. Small on purpose: the useful
# part of a libFuzzer crash is the panic line and the SUMMARY, both of
# which land in the last few hundred bytes ahead of the Debug dump. A
# GitHub issue body is capped at 65536 characters, and the excerpt is
# only one field of the body.
MAX_EXCERPT_BYTES="${MAX_EXCERPT_BYTES:-4000}"

if [ ! -f "${LOG_FILE}" ]; then
    echo "::warning::${LOG_FILE} not found; reporting ${TARGET} crash without a log excerpt" >&2
    LOG_FILE=/dev/null
fi

# The signature is the first panic/SUMMARY line PLUS the line after it:
# Rust prints the location ("panicked at foo.rs:278:17:") and the actual
# message ("Write patch 0 (..) exceeds total_file_size (..)") on separate
# lines, and a location on its own does not identify a crash. Bounded,
# because a panic message can itself carry fuzz data. grep -m1 into
# head -c closes the pipe early, so tolerate the SIGPIPE/no-match.
SIGNATURE="$(grep -m1 -A1 'panicked at\|SUMMARY:' "${LOG_FILE}" 2>/dev/null \
    | tr '\n\t' '  ' | head -c 200 || true)"
if [ -z "${SIGNATURE}" ]; then
    SIGNATURE='unknown crash'
fi

CRASH_SIZE="$(stat -c%s "${CRASH_FILE}" 2>/dev/null || echo unknown)"
REPRO="cd src/fuzz && cargo fuzz run ${TARGET} artifacts/${TARGET}/$(basename "${CRASH_FILE}")"

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
    | { iconv -c -f UTF-8 -t UTF-8 2>/dev/null || cat; } > "${EXCERPT_FILE}" || true

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

BODY_BYTES="$(wc -c < "${BODY_FILE}")"
if [ "${BODY_BYTES}" -gt 60000 ]; then
    echo "::warning::issue body for ${TARGET} is ${BODY_BYTES} bytes; dropping the log excerpt" >&2
    : > "${EXCERPT_FILE}"
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
fi

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "--dry-run: would file an issue titled 'Coverage fuzz crash: ${TARGET}'"
    echo "body is $(wc -c < "${BODY_FILE}") bytes:"
    cat "${BODY_FILE}"
    exit 0
fi

gh issue create \
    --label "security-audit" \
    --title "Coverage fuzz crash: ${TARGET}" \
    --body-file "${BODY_FILE}"
