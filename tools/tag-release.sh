#!/bin/bash
#
# Tag a release: the second of a release's two stages, run after the
# release-X.Y.Z pull request that tools/propose-release.sh opened has
# merged through the queue.
#
# Finds the commit that merged the release, checks that it is on the
# default branch's first-parent history and carries version X.Y.Z, and,
# after confirmation, creates an annotated tag vX.Y.Z there and pushes
# it. The push starts .github/workflows/release.yml, which checks CI on
# that commit, builds, waits for approval on the `release` environment,
# signs the tag and publishes.
#
# The commit to tag is not the default branch's tip. Other pull requests
# may have merged since, and what is tagged is what is built and
# published, so it must be what was reviewed as the release: by default,
# the first commit on the first-parent history that contains the commit
# "Release X.Y.Z.", which with a merge queue is the queue's merge of the
# release pull request. Give COMMIT to tag a later commit instead, for
# example when the release gate refused the first one (see the
# template's README for when that happens).
#
# Usage:
#   tools/tag-release.sh X.Y.Z [COMMIT]
#
# Requirements on the host: git, and gh signed in (gh auth login).
#
# Template source: shakenfist/development/templates/release-automation-rust/

set -euo pipefail

err() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# --- arguments ---

[[ $# -ge 1 && $# -le 2 ]] || err "usage: $0 X.Y.Z [COMMIT] (e.g. 0.1.0)"
VERSION="$1"
REQUESTED="${2:-}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || err "version must be X.Y.Z, got: ${VERSION}"
TAG="v${VERSION}"

for tool in git gh; do
    command -v "${tool}" >/dev/null || err "${tool} is not installed"
done

cd "$(dirname "$0")/.."
[[ -x tools/release-version.sh ]] || err "could not find the repository root"

DEFAULT_BRANCH="$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)" \
    || err "could not ask GitHub for the default branch; is gh signed in?"
UPSTREAM="origin/${DEFAULT_BRANCH}"

# --- fetch ---
#
# Tags are force-updated from origin. sign-tag replaces each release tag
# with a Sigstore-signed one at the same commit, so the clone that tagged
# the previous release still holds the unsigned original, and a plain
# --tags fetch refuses to clobber it. origin's release tags are the
# authoritative ones. Not --quiet, which would hide a rejected ref and
# leave only the exit status.

info "Fetching origin"
git fetch origin "${DEFAULT_BRANCH}" '+refs/tags/*:refs/tags/*' \
    || err "fetching origin failed; see git's output above"

if git rev-parse --verify --quiet "refs/tags/${TAG}" >/dev/null; then
    err "tag ${TAG} already exists locally"
fi
if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
    err "tag ${TAG} already exists on origin"
fi

# --- the commit to tag ---

if [[ -n "${REQUESTED}" ]]; then
    TARGET_SHA="$(git rev-parse --verify --quiet "${REQUESTED}^{commit}")" \
        || err "${REQUESTED} is not a commit"
else
    info "Finding the commit that merged release ${VERSION}"
    # awk reads all of git log's output rather than exiting at the match:
    # under pipefail, an early exit kills git log with SIGPIPE, and the
    # whole pipeline then fails with status 141.
    # A squash merge appends " (#N)" to the subject, so that suffix is
    # accepted too, and nothing else.
    RELEASE_SHA="$(git log "${UPSTREAM}" --format='%H%x09%s' \
        | awk -F '\t' -v want="Release ${VERSION}." \
            'found == "" && ($2 == want || (index($2, want " (#") == 1 && $2 ~ /\(#[0-9]+\)$/)) { found = $1 }
             END { if (found != "") print found }')"
    [[ -n "${RELEASE_SHA}" ]] \
        || err "no commit 'Release ${VERSION}.' on ${UPSTREAM}. Has the release-${VERSION} pull request merged?"
    TARGET_SHA=''
    while read -r commit; do
        if git merge-base --is-ancestor "${RELEASE_SHA}" "${commit}"; then
            TARGET_SHA="${commit}"
            break
        fi
    done < <(git rev-list --first-parent --reverse "${UPSTREAM}" --not "${RELEASE_SHA}^@")
    [[ -n "${TARGET_SHA}" ]] || err "could not find where ${RELEASE_SHA} merged into ${UPSTREAM}"
fi

# The release gate counts CI only on the default branch's first-parent
# history, so a tag anywhere else is refused there, after the tag is
# already public. Refuse it here instead. A commit reached only through a
# merge's second parent is a pull request's own commit, which the queue
# never ran on. grep reads to the end, not -q, for the same SIGPIPE
# reason as above.
git rev-list --first-parent "${UPSTREAM}" | grep -x "${TARGET_SHA}" >/dev/null \
    || err "${TARGET_SHA} is not on ${UPSTREAM}'s first-parent history, so the release gate would refuse it"
TARGET_SUBJECT="$(git log -1 --format=%s "${TARGET_SHA}")"

# --- the version there ---

info "Checking the version at ${TARGET_SHA}"
tools/release-version.sh at "${TARGET_SHA}" "${VERSION}"

LATER="$(git log --oneline --first-parent "${TARGET_SHA}..${UPSTREAM}")"

# --- confirm ---

echo
echo "About to tag ${TAG} at ${TARGET_SHA}:"
echo "  ${TARGET_SUBJECT}"
if [[ -n "${LATER}" ]]; then
    echo
    echo "These merged into ${DEFAULT_BRANCH} after it, and are NOT in ${TAG}:"
    while IFS= read -r line; do echo "  ${line}"; done <<< "${LATER}"
fi
echo
echo "Pushing the tag starts the release workflow, which:"
echo "  - checks that CI passed on this commit, and stops if it did not;"
echo "  - builds the release;"
echo "  - waits for approval on the release environment, then signs the"
echo "    tag and publishes. Most registries never accept a version"
echo "    twice: once anything is published, this cannot be undone."
echo
read -rp "Create and push tag ${TAG}? [y/N] " REPLY
[[ "${REPLY}" =~ ^[Yy]$ ]] || {
    info "Aborted."
    exit 1
}

info "Creating annotated tag ${TAG}"
git tag -a "${TAG}" -m "Release ${VERSION}" "${TARGET_SHA}"

info "Pushing ${TAG} (this starts the release workflow)"
PUSHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push origin "refs/tags/${TAG}" || {
    git tag -d "${TAG}" >/dev/null
    err "pushing ${TAG} failed; the local tag was removed, so this can be re-run"
}

# --- watch ---
#
# The run for this tag is the one whose head is the tag and whose event
# is the push, on the tagged commit and created after this push: during
# a recovery, an earlier run for the same tag name may still be listed.
# GitHub can take a few seconds to create it. Failing to find or watch
# it is not a failure of the release, which is already under way, so it
# only says where to look.

info "Waiting for the release workflow to start"
RUN_ID=''
for _ in 1 2 3 4 5 6; do
    sleep 5
    RUN_ID="$(gh run list --workflow=release.yml --branch "${TAG}" --event push \
        --limit 10 --json databaseId,headSha,createdAt \
        --jq "[.[] | select(.headSha == \"${TARGET_SHA}\" and .createdAt >= \"${PUSHED_AT}\")][0].databaseId // empty" \
        2>/dev/null || true)"
    [[ -z "${RUN_ID}" ]] || break
done

if [[ -n "${RUN_ID}" ]]; then
    info "Watching workflow run ${RUN_ID}; approve the release environment when it asks"
    gh run watch "${RUN_ID}" || info "the workflow did not complete cleanly"
    gh release view "${TAG}" --web || true
else
    info "Could not find the workflow run. Check: gh run list --workflow=release.yml"
fi
