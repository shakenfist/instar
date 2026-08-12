#!/usr/bin/env bash
#
# Choose which file in a libFuzzer artifacts directory to report as the
# reproducer for a crash. Prints the path, or nothing if there is no
# usable artifact; always exits 0, so a caller under `bash -e` can test
# the output rather than the status.
#
# This lived inline in .github/workflows/coverage-fuzz.yml, where two of
# the three bugs behind the month of broken nightlies were hiding:
#
#   * `cargo fuzz tmin` was passed a -max_len it supplies itself, which
#     trips libFuzzer's `assert(MaxInputLen == 0)`, so every
#     minimization failed and left a 0-byte `minimized-from-*` behind;
#   * the selector was an unsorted `find | head -1`, so on a later crash
#     it could pick up one of those 0-byte files and report an empty
#     reproducer.
#
# Both were invisible until a real crash happened. Out here they are
# covered by tools/ci/test-pick-fuzz-artifact.sh.
#
# Usage:
#   tools/ci/pick-fuzz-artifact.sh crash ARTIFACT_DIR
#       The input to minimize and report. Skips empty files and
#       minimized-from-* (see below).
#
#   tools/ci/pick-fuzz-artifact.sh minimized ARTIFACT_DIR
#       The non-empty minimized-from-* left by a successful tmin, if
#       there is one. Prints nothing when minimization failed or was
#       not run, which is the caller's cue to keep the original.

set -euo pipefail

MODE="${1:-}"
DIR="${2:-}"

if [ -z "${MODE}" ] || [ -z "${DIR}" ] || [ "$#" -ne 2 ]; then
    echo "usage: $0 crash|minimized ARTIFACT_DIR" >&2
    exit 2
fi

if [ ! -d "${DIR}" ]; then
    exit 0
fi

case "${MODE}" in
    minimized)
        # -size +0c: a failed tmin leaves an empty file, and reporting
        # that as the reproducer is worse than reporting the original.
        find "${DIR}" -maxdepth 1 -type f -name 'minimized-from-*' \
            -size +0c 2>/dev/null | sort | head -1
        exit 0
        ;;
    crash)
        ;;
    *)
        echo "usage: $0 crash|minimized ARTIFACT_DIR" >&2
        exit 2
        ;;
esac

# libFuzzer writes several kinds of artifact, and they are not equally
# interesting. Take them in an explicit order of preference rather than
# relying on `sort` -- lexicographically `crash-` < `leak-` < `oom-` <
# `slow-unit-` < `timeout-`, which happens to put crashes first but also
# puts slow-unit-* ahead of timeout-*. A slow unit is any input over 10s
# (libFuzzer's default -report_slow_units) and these targets run against
# 4MB inputs, so one can easily be sitting in the directory when a real
# timeout arrives -- and then the reported reproducer is the slow unit,
# not the timeout. The order below says what we mean, and survives
# libFuzzer adding another prefix.
#
# minimized-from-* is excluded here because this is the file tmin is
# about to be pointed AT; the caller asks for `minimized` afterwards.
for PREFIX in 'crash-' 'oom-' 'leak-' 'timeout-' 'slow-unit-'; do
    MATCH="$(find "${DIR}" -maxdepth 1 -type f -name "${PREFIX}*" \
        -size +0c 2>/dev/null | sort | head -1)"
    if [ -n "${MATCH}" ]; then
        echo "${MATCH}"
        exit 0
    fi
done

# Anything else non-empty that is not a minimization leftover: a prefix
# we have not seen before is still better than reporting nothing.
find "${DIR}" -maxdepth 1 -type f ! -name 'minimized-from-*' -size +0c \
    2>/dev/null | sort | head -1
exit 0
