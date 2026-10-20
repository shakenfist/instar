#!/bin/bash
#
# Propose a release: the first of a release's two stages.
#
# Creates a release-X.Y.Z branch from the default branch, bumps the
# version, runs pre-commit and the tests, and, after confirmation,
# commits, pushes the branch and opens a pull request. It does not tag.
# The release then goes:
#
#   1. Run this script.
#   2. Get the pull request reviewed, and land it through the merge
#      queue like any other change. The queue's run on the merged commit
#      is the CI result the release's ci-gate job requires.
#   3. Run tools/tag-release.sh X.Y.Z, which tags the merged commit and
#      pushes the tag; that is what starts .github/workflows/release.yml.
#
# The version bump goes through the queue rather than straight onto the
# default branch so that the commit which is tagged has a CI result. A
# bump pushed around the queue has none, and the release gate refuses it.
#
# Usage:
#   tools/propose-release.sh X.Y.Z
#
# Requirements on the host: git, gh signed in (gh auth login), and
# pre-commit, plus whatever the per-repository functions below run.
#
# Template source: shakenfist/development/templates/release-automation-rust/

set -euo pipefail

err() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# --- per-repository settings ---
#
# Adapt these three functions to the repository. Everything after them
# is the same in every repository that uses this template.

# Sets the release version to $1 everywhere the repository records it.
# instar's crates each carry their own copy of the version rather than
# inheriting one from [workspace.package], so the Makefile's set-version
# target rewrites every Cargo.toml in its CARGO_TOML_FILES list, the
# version file among them, and fails if any of them did not take. No
# Cargo.lock is committed, so there is no lockfile to update.
bump_version() {
    make set-version VERSION="$1"
}

# The tests to run on the bumped tree before it is committed. The queue
# runs CI again on the merged commit, so this is a cheap early warning,
# not the release's test result. The Rust unit tests run in the build
# container and need nothing else; the Python integration suite needs
# /dev/kvm and the test images, and the queue runs it on seven distros.
run_tests() {
    make test-rust
}

# Fails if a registry the release publishes to already has version $1.
# Most registries never accept a version twice, so a version one of them
# already has cannot be released, and finding that out here costs
# nothing. Call require_unpublished once per published package, with a
# URL that answers 404 when that version does not exist, for example:
#
#   require_unpublished "https://crates.io/api/v1/crates/<crate>/$1"
#   require_unpublished "https://pypi.org/pypi/<package>/$1/json"
#
# A repository that publishes only to GitHub Releases leaves this empty.
check_unpublished() {
    :
}

# --- end of per-repository settings ---

require_unpublished() {
    local url="$1" code
    code="$(curl -s -o /dev/null -w '%{http_code}' \
        -A 'shakenfist-release-script (https://github.com/shakenfist)' "${url}")"
    case "${code}" in
        404) ;;
        200) err "already published: ${url}" ;;
        *) err "unexpected HTTP ${code} from ${url}" ;;
    esac
}

# --- arguments ---

[[ $# -eq 1 ]] || err "usage: $0 X.Y.Z (e.g. 0.1.0)"
VERSION="$1"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || err "version must be X.Y.Z, got: ${VERSION}"

TAG="v${VERSION}"
RELEASE_BRANCH="release-${VERSION}"

for tool in git gh curl pre-commit; do
    command -v "${tool}" >/dev/null || err "${tool} is not installed"
done

cd "$(dirname "$0")/.."
[[ -x tools/release-version.sh ]] || err "could not find the repository root"

DEFAULT_BRANCH="$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)" \
    || err "could not ask GitHub for the default branch; is gh signed in?"

# --- git state ---

info "Checking git state"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "${BRANCH}" == "${DEFAULT_BRANCH}" ]] \
    || err "must be on ${DEFAULT_BRANCH}, currently on: ${BRANCH}"
[[ -z "$(git status --porcelain)" ]] || err "working tree is dirty; commit or stash first"

git fetch origin "${DEFAULT_BRANCH}" --quiet
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/${DEFAULT_BRANCH}")" ]] \
    || err "local ${DEFAULT_BRANCH} is not in sync with origin/${DEFAULT_BRANCH}"

if git rev-parse --verify --quiet "refs/tags/${TAG}" >/dev/null; then
    err "tag ${TAG} already exists locally"
fi
if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
    err "tag ${TAG} already exists on origin"
fi
if git rev-parse --verify --quiet "refs/heads/${RELEASE_BRANCH}" >/dev/null; then
    err "branch ${RELEASE_BRANCH} already exists locally"
fi
if git ls-remote --heads --exit-code origin "refs/heads/${RELEASE_BRANCH}" >/dev/null 2>&1; then
    err "branch ${RELEASE_BRANCH} already exists on origin"
fi

# --- the version must move forward ---

CURRENT="$(tools/release-version.sh get)"
[[ "${CURRENT}" != "${VERSION}" ]] || err "the repository is already at ${VERSION}"
HIGHEST="$(printf '%s\n%s\n' "${CURRENT}" "${VERSION}" | sort -V | tail -n 1)"
[[ "${HIGHEST}" == "${VERSION}" ]] || err "${VERSION} is older than the current ${CURRENT}"

info "Checking that ${VERSION} is not already published"
check_unpublished "${VERSION}"

# --- the release branch ---

info "Creating ${RELEASE_BRANCH} from ${DEFAULT_BRANCH}"
git switch -c "${RELEASE_BRANCH}"

# Until the push succeeds, any exit puts the checkout back as it was.
CLEANUP_BRANCH=1
cleanup() {
    if [[ "${CLEANUP_BRANCH}" == "1" ]]; then
        info "Cleaning up: switching back to ${DEFAULT_BRANCH} and deleting ${RELEASE_BRANCH}"
        git checkout -- . 2>/dev/null || true
        git switch "${DEFAULT_BRANCH}" 2>/dev/null || true
        git branch -D "${RELEASE_BRANCH}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- bump ---

info "Bumping the version from ${CURRENT} to ${VERSION}"
bump_version "${VERSION}"

# A bump that creates a file would be left out of the commit, which
# stages tracked files only, and left behind by the cleanup.
UNTRACKED="$(git status --porcelain --untracked-files=all | awk '$1 == "??" { print $2 }')"
[[ -z "${UNTRACKED}" ]] \
    || err "the version bump left untracked files, which the release commit would leave out: ${UNTRACKED//$'\n'/ }"

# Linted after the bump, so that the files it changed are checked
# before the pull request opens.
info "Running pre-commit"
pre-commit run --all-files

# The release workflow's own check, run against the tag this release
# will have, so that a bump check-version would refuse never reaches
# review.
tools/release-version.sh check "refs/tags/${TAG}"

info "Running the tests"
run_tests

# --- confirm, commit, push and open the pull request ---

echo
echo "About to propose release ${VERSION} on branch ${RELEASE_BRANCH}."
git diff --stat
echo
read -rp "Commit, push ${RELEASE_BRANCH} and open a pull request? [y/N] " REPLY
[[ "${REPLY}" =~ ^[Yy]$ ]] || {
    info "Aborted at confirmation."
    exit 1
}

# tag-release.sh finds the release by this subject, so it must not
# change. A merge or rebase queue keeps it as written; a squash queue
# appends " (#N)", which tag-release.sh also accepts.
info "Committing"
git add -u
git commit -m "Release ${VERSION}."

info "Pushing ${RELEASE_BRANCH}"
git push --set-upstream origin "${RELEASE_BRANCH}"

# Pushed: leave the checkout on the release branch, whatever happens next.
CLEANUP_BRANCH=0

info "Opening the pull request"
gh pr create --base "${DEFAULT_BRANCH}" --head "${RELEASE_BRANCH}" \
    --title "Release ${VERSION}." \
    --body "Bumps the version to ${VERSION}. Once this has merged through the queue, \`tools/tag-release.sh ${VERSION}\` tags the merged commit and starts the release." \
    || err "the branch is pushed, but opening the pull request failed; open it by hand from ${RELEASE_BRANCH}"

echo
info "Release ${VERSION} proposed."
echo
echo "Next steps:"
echo "  1. Get the pull request reviewed, and land it through the merge queue."
echo "  2. Run 'tools/tag-release.sh ${VERSION}' to tag the merged commit,"
echo "     which starts the release workflow."
