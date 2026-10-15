#!/usr/bin/env bash
#
# Wrapper for the CI test-partition guard. Enumerates the Python
# integration suite with `stestr list` and asserts every test is
# claimed by at least one pull-request job, and that the merge-queue
# and nightly halves of the distro matrix still add up to what an
# unselected matrix entry ran (see tools/ci/check-test-partition.py for
# the rationale).
#
# Pure Python + stestr: needs no /dev/kvm, no testdata, and no built
# instar binary, so it runs on a lightweight runner. Run from the repo
# root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

VENV="$(mktemp -d)/partition-venv"
cleanup() { rm -rf "$(dirname "${VENV}")"; }
trap cleanup EXIT

echo "Setting up venv for stestr discovery..."
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install -q -r tests/requirements.txt

cd tests
# stestr list needs an initialised repository; harmless if it exists.
if [ ! -d .stestr ]; then
  "${VENV}/bin/stestr" init >/dev/null
fi

echo "Discovering tests and checking the CI partition..."
# Both workflows that run the suite: functional-tests.yml holds the
# pull-request jobs and the merge-queue matrix, nightly-matrix.yml holds
# the other half of the matrix split. The guard compares the two halves
# against each other and the two distro lists against each other, so
# dropping either file from this call makes it fail rather than go
# quiet.
"${VENV}/bin/stestr" list 2>/dev/null | python3 "${REPO_ROOT}/tools/ci/check-test-partition.py" \
  --makefile "${REPO_ROOT}/Makefile" \
  --workflow "${REPO_ROOT}/.github/workflows/functional-tests.yml" \
  --workflow "${REPO_ROOT}/.github/workflows/nightly-matrix.yml"
