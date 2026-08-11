#!/bin/bash
# Run one distro-matrix entry and summarise it.
#
# This is the merge-queue counterpart to running
# tools/test-package-functional.sh by hand: it resolves the right
# package out of the shared build artifact, runs the full suite in the
# distro container, and writes the entry's row into the job summary.
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
#   MATRIX_SELECT        stestr selection regex; runs only matching
#                        tests. For reproducing one CI entry locally
#                        without paying for the whole suite. CI never
#                        sets it -- a partial run must not be able to
#                        report as a green matrix entry.
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
fi

set +e
"${REPO_ROOT}/tools/test-package-functional.sh" \
    "${RUNNER_ARGS[@]}" \
    "$PACKAGE" "$IMAGE" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e

"${REPO_ROOT}/tools/ci/summarise-matrix-entry.sh" "$NAME" "$IMAGE" "$RC" "$LOG"

exit "$RC"
