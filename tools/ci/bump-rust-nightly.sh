#!/usr/bin/env bash
#
# Weekly Rust nightly pin bump for the instar devcontainer.
#
# The devcontainer Dockerfile pins its Rust nightly (ARG RUST_NIGHTLY=
# nightly-YYYY-MM-DD) because a broken floating nightly breaks every
# from-scratch image build: on 2026-07-24 the then-current nightly ICE'd
# compiling tokio during `cargo install cargo-audit`, failing CI's
# "Build devcontainer" step. Renovate cannot manage rustup toolchain
# pins (there is no datasource for "latest good nightly"), so this
# script moves the pin forward instead:
#
#   1. Find the newest published nightly (probe the static.rust-lang.org
#      channel manifest, walking back up to a week for skipped days).
#   2. If it is not newer than the current pin, exit — nothing to do.
#   3. Rewrite the Dockerfile pin to the candidate.
#   4. Validate the candidate END TO END: full devcontainer image build
#      (every cargo tool layer, including the cargo-audit layer that
#      caught the 2026-07-24 ICE), then `make instar` (guest build-std
#      cross-builds), then `make test-rust` (a nightly that miscompiles
#      can build cleanly and still fail tests — see issue #375).
#   5. Commit the bump, push a bot branch, and open a PR against
#      develop. Any validation failure leaves the pin alone: the job
#      fails, no PR appears, and next week's run tries the then-newest
#      nightly.
#
# A failed docker build never replaces the runner's existing
# `instar-build` tag (docker only retags on success), so a bad candidate
# does not poison other jobs on the same runner.
#
# Usage:
#   tools/ci/bump-rust-nightly.sh [--dry-run]
#
# --dry-run performs discovery, the Dockerfile edit, and the full build
# validation, but skips the commit/push/PR step (for local testing).
# Requires GH_TOKEN (or ambient gh auth) for the PR step.

set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
elif [ -n "${1:-}" ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

DOCKERFILE="src/.devcontainer/Dockerfile"
DIST_URL="https://static.rust-lang.org/dist"

# --- 1. Current pin -------------------------------------------------------
CURRENT="$(sed -nE 's/^ARG RUST_NIGHTLY=(nightly-[0-9]{4}-[0-9]{2}-[0-9]{2})$/\1/p' "${DOCKERFILE}")"
if [ -z "${CURRENT}" ]; then
    echo "ERROR: no 'ARG RUST_NIGHTLY=nightly-YYYY-MM-DD' pin found in ${DOCKERFILE}" >&2
    exit 1
fi
echo "Current pin: ${CURRENT}"

# --- 2. Newest published nightly ------------------------------------------
# Nightlies occasionally skip a day, so walk back up to a week from today
# and take the first date whose channel manifest exists.
CANDIDATE=""
for offset in 0 1 2 3 4 5 6; do
    d="$(date -u -d "-${offset} days" +%F)"
    if curl -sfIL -o /dev/null "${DIST_URL}/${d}/channel-rust-nightly.toml"; then
        CANDIDATE="nightly-${d}"
        break
    fi
done
if [ -z "${CANDIDATE}" ]; then
    echo "ERROR: no published nightly found in the last 7 days (network problem?)" >&2
    exit 1
fi
echo "Newest published nightly: ${CANDIDATE}"

# ISO dates compare correctly as strings.
if [ "${CANDIDATE}" \< "${CURRENT}" ] || [ "${CANDIDATE}" = "${CURRENT}" ]; then
    echo "Pin is already current (${CURRENT} >= ${CANDIDATE}); nothing to do."
    exit 0
fi

# Skip if a bump PR for this candidate is already open (e.g. re-run of
# the schedule while last week's PR awaits review).
BRANCH="rust-nightly-bump/${CANDIDATE}"
if [ "${DRY_RUN}" -eq 0 ] && command -v gh >/dev/null 2>&1; then
    if [ -n "$(gh pr list --state open --head "${BRANCH}" --json number --jq '.[].number')" ]; then
        echo "An open PR for ${CANDIDATE} already exists; nothing to do."
        exit 0
    fi
fi

# --- 3. Rewrite the pin ---------------------------------------------------
sed -i -E "s/^ARG RUST_NIGHTLY=nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$/ARG RUST_NIGHTLY=${CANDIDATE}/" \
    "${DOCKERFILE}"
echo "Rewrote ${DOCKERFILE} pin to ${CANDIDATE}"

# --- 4. Validate the candidate end to end ---------------------------------
echo "Building devcontainer image with ${CANDIDATE}..."
docker build --pull -t instar-build src/.devcontainer

echo "Building instar with ${CANDIDATE}..."
make instar

echo "Running Rust tests with ${CANDIDATE}..."
make test-rust

echo "${CANDIDATE} validated: devcontainer build, instar build, and Rust tests all pass."

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "--dry-run: skipping commit/push/PR. ${DOCKERFILE} is left modified."
    exit 0
fi

# --- 5. Commit, push, PR --------------------------------------------------
git config user.name "shakenfist-bot"
git config user.email "bot@shakenfist.com"

git checkout -b "${BRANCH}"
git add "${DOCKERFILE}"
git commit -m "Bump Rust nightly pin to ${CANDIDATE}.

Weekly automated bump of the devcontainer's pinned Rust nightly
(previously ${CURRENT}). The candidate was validated on the CI
runner before this PR was opened: full devcontainer image build
(including the cargo tool layers), \`make instar\`, and
\`make test-rust\` all pass against it.

Generated by tools/ci/bump-rust-nightly.sh via the
rust-nightly-bump workflow."

git push -f -u origin "${BRANCH}"

PR_BODY="Weekly automated bump of the devcontainer's pinned Rust nightly: \`${CURRENT}\` -> \`${CANDIDATE}\`.

Validation performed on the CI runner before opening this PR:

- Full devcontainer image build (every cargo tool layer, including \`cargo install cargo-audit\` — the layer a broken nightly ICE'd on 2026-07-24)
- \`make instar\` (guest build-std cross-builds on the new nightly)
- \`make test-rust\` (workspace test suite)

If this PR looks fine, merge it; if the new nightly is known-bad for reasons the build cannot see, close it and the workflow will propose the next newest nightly on its following run.

---
Generated by \`tools/ci/bump-rust-nightly.sh\` (rust-nightly-bump workflow)."

gh pr create \
    --base develop \
    --assignee mikalstill \
    --reviewer mikalstill \
    --title "Bump Rust nightly pin to ${CANDIDATE}" \
    --body "${PR_BODY}"

echo "Opened bump PR for ${CANDIDATE}."
