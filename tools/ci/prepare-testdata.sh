#!/usr/bin/env bash
#
# Prepare the instar-testdata working tree for a CI job.
#
# instar-testdata stores every binary fixture (*.qcow2, *.raw, *.vhd,
# *.vhdx, *.vmdk, *-backing, qemu-img, ...) in git-LFS. A plain clone or
# reset only materialises those objects if the runner's git-lfs smudge
# filter happens to be active; when it is not, every fixture lands on
# disk as a ~131-byte LFS pointer file. The whole suite then fails with
# "file format: unknown" for every image, which reads like a mass instar
# regression but is really a testdata-materialisation failure. This
# script makes LFS handling explicit and fails loudly (as an infra error)
# if the fixtures did not materialise, instead of letting the suite run
# against pointer files. See GitHub issue #451 for the incident this
# guards against.
#
# Inputs (environment):
#   TESTDATA_TOKEN   (required) GitLab oauth2 read token for the
#                    private/instar-testdata repository.
#   TESTDATA_CACHE   (optional) On-runner cache dir, default
#                    /srv/ci/cached/instar-testdata.
#   GITHUB_WORKSPACE (required in Actions) Fresh-clone parent dir.
#   GITHUB_ENV       (optional) When set, the resolved TESTDATA_PATH is
#                    exported to it for later steps.
#
# Output: prints the resolved TESTDATA_PATH and, when GITHUB_ENV is set,
# writes "TESTDATA_PATH=<path>" to it.

set -euo pipefail

TESTDATA_CACHE="${TESTDATA_CACHE:-/srv/ci/cached/instar-testdata}"
REPO_HOST='gitlab.home.stillhq.com'
REPO_PATH='private/instar-testdata.git'

if ! command -v git-lfs >/dev/null 2>&1; then
    echo "::error::git-lfs is not installed on this runner; instar-testdata" \
         "fixtures are LFS-backed and cannot be materialised without it." >&2
    exit 1
fi

if [ -z "${TESTDATA_TOKEN:-}" ]; then
    echo "::error::TESTDATA_TOKEN is not set; cannot authenticate to the" \
         "instar-testdata repository." >&2
    exit 1
fi

if [ -z "${GITHUB_WORKSPACE:-}" ]; then
    echo "::error::GITHUB_WORKSPACE is not set." >&2
    exit 1
fi

# Token only ever appears inside git command arguments below, never in a
# traced or echoed line, so keep shell tracing off.
AUTHED_URL="https://oauth2:${TESTDATA_TOKEN}@${REPO_HOST}/${REPO_PATH}"

if [ -d "${TESTDATA_CACHE}/.git" ]; then
    echo "Using cached testdata at ${TESTDATA_CACHE}, updating in place..."
    cd "${TESTDATA_CACHE}"
    git remote set-url origin "${AUTHED_URL}"
    git fetch --depth 1 origin main
    git reset --hard origin/main
    TESTDATA_PATH="${TESTDATA_CACHE}"
else
    echo "No cache at ${TESTDATA_CACHE}, cloning fresh..."
    TESTDATA_PATH="${GITHUB_WORKSPACE}/instar-testdata"
    git clone --depth 1 "${AUTHED_URL}" "${TESTDATA_PATH}"
    cd "${TESTDATA_PATH}"
fi

# Materialise LFS content explicitly rather than relying on an implicit
# smudge filter. install --local writes the filter config into this
# clone; pull fetches and checks out the actual objects. Both are
# idempotent and cheap when the objects are already present.
git lfs install --local
git lfs pull

# Guard: prove the fixtures are real images, not LFS pointer files. A
# git-LFS pointer begins with the literal "version https://git-lfs...".
# We require at least one canary to exist and every present canary to be
# non-pointer, so a silent LFS miss becomes a clear infra failure here
# instead of 200+ "file format: unknown" test failures downstream.
canaries=(
    "custom/security/qcow2-backing-textfile.qcow2"
    "custom/raw/zeros-1mb.raw"
)
found_canary=0
for rel in "${canaries[@]}"; do
    path="${TESTDATA_PATH}/${rel}"
    [ -f "${path}" ] || continue
    found_canary=1
    if head -c 64 "${path}" | grep -q 'git-lfs.github.com/spec'; then
        echo "::error::testdata LFS not materialised: ${rel} is still a" \
             "git-LFS pointer file. This is an infrastructure problem" \
             "(git-lfs pull did not fetch objects), NOT a test/instar" \
             "regression. Fix LFS auth/availability on the runner and" \
             "re-run; do not modify instar code to match this output." >&2
        exit 1
    fi
done

if [ "${found_canary}" -eq 0 ]; then
    echo "::error::none of the expected testdata canary fixtures were" \
         "found under ${TESTDATA_PATH}; the checkout looks incomplete." >&2
    exit 1
fi

echo "testdata ready at ${TESTDATA_PATH} (LFS materialised, canary verified)"
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "TESTDATA_PATH=${TESTDATA_PATH}" >> "${GITHUB_ENV}"
fi
