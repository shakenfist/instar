#!/bin/bash
# Run one distro-matrix entry and summarise it.
#
# This is the merge-queue counterpart to running
# tools/test-package-functional.sh by hand: it resolves the right
# package out of the shared build artifact, runs the half of the suite
# MATRIX_SET names in the distro container, and writes the entry's row
# into the job summary. It ran the whole suite until the suite was
# split; "all" is still how you ask for that.
# It exists so the workflow step stays a single call rather than a
# tee/exit-code/parse pipeline embedded in YAML.
#
# Usage:
#   tools/ci/run-matrix-entry.sh <name> <image> <deb|rpm>
#
# Environment:
#   PACKAGE_DIR          directory holding the downloaded .deb/.rpm
#                        (required)
#   TESTDATA_PATH        prepared instar-testdata tree (required; run
#                        tools/ci/prepare-testdata.sh first)
#   MATRIX_CONCURRENCY   stestr workers inside the container (default 4)
#   MATRIX_LOG           where to write the captured log
#                        (default ./matrix-<kind>.log)
#   MATRIX_SET           which half of the matrix split to run:
#                        "queue" (default, what gates a merge) or
#                        "nightly" (the six heavy VHD conversion tests
#                        that do not). Both selections are read out of
#                        the Makefile; see below. "all" passes no
#                        selector at all, which is the whole suite as a
#                        matrix entry ran it before the split -- the
#                        union of the two halves, and the only mode that
#                        measures a duration for every test. The nightly
#                        measurement leg uses it; nothing that gates a
#                        merge does, because the point of the split is
#                        that the gate runs less.
#   MATRIX_SELECT        stestr selection regex; runs only matching
#                        tests. For reproducing one CI entry locally
#                        without paying for the whole suite. CI never
#                        sets it -- a partial run must not be able to
#                        report as a green matrix entry. It is reserved
#                        for that: it overrides MATRIX_SET's selection
#                        rather than narrowing it, so it is not the way
#                        to express the queue/nightly split.
#
# The queue and nightly selections are defined once, in the Makefile's
# test-container-matrix-queue and test-container-matrix-nightly targets,
# because tools/ci/check-test-partition.py reads them from there to
# prove the two are exact complements of what a matrix entry used to
# run. This script lifts the selector out of the named target rather
# than carrying a copy, so no regex is restated here.
#
# What can still drift is how it is lifted: the awk below and the guard's
# own extractor read the same recipe by different rules -- awk takes the
# first recipe line beginning with a double quote, the guard takes the
# first quoted token not preceded by --exclude-regex. They agree on
# today's recipes, and a recipe reformat (--exclude-regex on a line of
# its own, say) could make this script select the exclusion while the
# guard went on validating the selection. That agreement is therefore
# asserted rather than assumed, by
# tools/ci/test_check_test_partition.py, over every test-container-*
# target in the Makefile.
#
# Exits with the functional runner's exit code, so the matrix entry
# fails exactly when the suite does.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <name> <image> <deb|rpm>" >&2
    exit 2
fi

NAME="$1"
IMAGE="$2"
PKG_KIND="$3"

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOG="${MATRIX_LOG:-${PWD}/matrix-${PKG_KIND}.log}"

if [ -z "${PACKAGE_DIR:-}" ]; then
    echo "Error: PACKAGE_DIR is not set (where the artifact was downloaded)." >&2
    exit 2
fi
if [ -z "${TESTDATA_PATH:-}" ]; then
    echo "Error: TESTDATA_PATH is not set; run prepare-testdata.sh first." >&2
    exit 2
fi

# Read the positional stestr selector out of a Makefile
# test-container-* target: skip to the target, then to its `stestr run`
# invocation, then take the first argument that is a bare quoted string
# (an --exclude-regex argument has its flag on the same line, so it is
# not one).
makefile_selector() {
    local target="$1"
    local selector
    selector=$(awk -v tgt="${target}:" '
        index($0, tgt) == 1 { found = 1; next }
        found && /^[A-Za-z0-9_.-]+:/ { exit }
        found && /stestr[ \t]+run/ { in_run = 1; next }
        found && in_run && /^[ \t]+"/ {
            line = $0
            sub(/^[ \t]+"/, "", line)
            sub(/"[ \t]*\\?[ \t]*$/, "", line)
            print line
            exit
        }
    ' "${REPO_ROOT}/Makefile")
    # A recipe writes a literal dollar as "$$" so make passes it
    # through; the selectors anchor each test id with "$", so undo the
    # doubling to get the regex stestr must actually see.
    selector="${selector//\$\$/\$}"
    if [ -z "$selector" ]; then
        echo "Error: no stestr selector found in Makefile target ${target}." >&2
        echo "The queue and nightly selections are defined there and read" >&2
        echo "from there; a parse failure must fail the entry rather than" >&2
        echo "quietly running a different set of tests." >&2
        return 1
    fi
    printf '%s\n' "$selector"
}

case "${MATRIX_SET:-queue}" in
    queue) SELECT_TARGET=test-container-matrix-queue ;;
    nightly) SELECT_TARGET=test-container-matrix-nightly ;;
    # No target, and so no selector: the runner's own default is the
    # whole suite, which is what a matrix entry ran before it was split.
    all) SELECT_TARGET='' ;;
    *)
        echo "Error: MATRIX_SET must be 'queue', 'nightly' or 'all', not '${MATRIX_SET}'." >&2
        exit 2
        ;;
esac

PACKAGE=$("${REPO_ROOT}/tools/ci/resolve-package.sh" "$PKG_KIND" "$PACKAGE_DIR")

echo "=== ${NAME} (${IMAGE}) ==="
echo "package:  ${PACKAGE}"
echo "testdata: ${TESTDATA_PATH}"
echo ""

# The runner's exit code is the entry's result; capture it rather than
# letting `set -e` kill us, so the summary still gets written on failure.
RUNNER_ARGS=(--concurrency "${MATRIX_CONCURRENCY:-4}")
if [ -n "${MATRIX_SELECT:-}" ]; then
    echo "NOTE: MATRIX_SELECT is set -- this is a PARTIAL run, not a" >&2
    echo "matrix result. Never set it in CI." >&2
    echo "" >&2
    RUNNER_ARGS+=(--select "$MATRIX_SELECT")
elif [ -z "$SELECT_TARGET" ]; then
    echo "selection: all (no selector -- the whole suite, both halves of the split)"
else
    SELECTOR=$(makefile_selector "$SELECT_TARGET") || exit 2
    echo "selection: ${MATRIX_SET:-queue} (Makefile ${SELECT_TARGET})"
    RUNNER_ARGS+=(--select "$SELECTOR")
fi

set +e
"${REPO_ROOT}/tools/test-package-functional.sh" \
    "${RUNNER_ARGS[@]}" \
    "$PACKAGE" "$IMAGE" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e

# The summary must never change the verdict. Under `set -e` a summariser
# failure -- an unwritable $GITHUB_STEP_SUMMARY, a sed error on a
# half-written log -- would kill this script before `exit "$RC"` and
# report a passing two-hour matrix entry as a merge-gating failure.
"${REPO_ROOT}/tools/ci/summarise-matrix-entry.sh" "$NAME" "$IMAGE" "$RC" "$LOG" \
    || echo 'warning: summary generation failed; the result below stands' >&2

exit "$RC"
