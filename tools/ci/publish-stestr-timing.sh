#!/usr/bin/env bash
#
# Publish a nightly re-measurement of tests/stestr-timing.txt as a pull
# request, when and only when the measurement is worth a human's
# attention.
#
# tests/stestr-timing.txt is the committed per-test duration list
# tools/ci/seed-stestr-timing.sh loads into stestr's repository before a
# run, so the scheduler bin-packs its workers instead of splitting the
# suite round-robin. It must be derived rather than hand-maintained --
# hand-kept figures in this repository have drifted before -- and the
# nightly measurement leg is what derives it, because that leg is the one
# job that still executes the whole suite in a single stestr repository.
#
# Two things this deliberately does NOT do.
#
# It never pushes to the default branch. `develop` is merge-queue
# protected, nothing in this repository writes to it from CI, and a
# scheduling hint is nowhere near a good enough reason to be the first
# thing that does. A refresh arrives as a pull request like any other
# change, and a human merges it.
#
# It stays quiet unless the numbers moved materially, which
# tools/ci/compare-stestr-timing.py defines (in shares of the suite's
# weight, so a uniformly slower runner is not a change -- stestr's bin
# packing is scale-free). A stale hint degrades packing gradually and can
# never make a run wrong, so silence on a night when nothing moved is
# worth far more than a pull request every morning that nobody reads.
#
# THE PULL REQUEST THIS OPENS ARRIVES WITH ITS CHECKS NOT RUNNING, and
# that is not a defect in this script. It is created by `gh pr create`
# with the job's own GITHUB_TOKEN, so its author is
# `github-actions[bot]`, and this repository sets the Actions
# contributor-approval policy to `all_external_contributors`, which a
# bot counts as.
#
# Measured, rather than taken from the lore, on the `rust-nightly-bump`
# pull requests #584, #604, #627 and #656, which are opened in exactly
# this way: every `pull_request` workflow run -- Lint, CodeQL, Supply
# chain, Functional Tests -- IS created, within seconds of the pull
# request, and attempt 1 of each ends `action_required`, queued behind
# an approval that never arrives by itself. On all four a maintainer
# approved them hours later, attempt 2 ran green, and the pull request
# merged through the queue normally.
#
# So the widely-repeated version of this -- that a GITHUB_TOKEN-created
# pull request triggers no workflow runs at all -- is not what this
# repository does; the runs exist and wait. The effect is the same
# either way: `develop` requires those checks, so the refresh cannot
# merge until somebody acts.
#
# What to do about it:
#   - Approve the runs: "Approve and run workflows" on the pull
#     request's checks tab. That is what unblocked all four bump pull
#     requests, and it is the normal path.
#   - Closing and reopening is the usual advice for a pull request whose
#     checks never fired, and is probably not the fix here: the gate is
#     keyed on who authored the pull request, which reopening does not
#     change. It was not what unblocked any of the four.
#   - Open it as a person instead. A PAT for an account with write
#     access is not an external contributor, so it skips the gate (and
#     in repositories that suppress the runs outright rather than
#     queueing them, it is the documented way round that too). It costs
#     a secret to rotate and to leave in reach of this job, which is why
#     this uses the job token and accepts the approval click.
#
# Usage:
#   tools/ci/publish-stestr-timing.sh MEASURED_FILE [--dry-run] [--force]
#
#   MEASURED_FILE  the timing file this run derived, in the format
#                  tools/ci/generate-stestr-timing.py writes.
#   --dry-run      print the verdict, the title and the body, and touch
#                  neither git nor the GitHub API. How
#                  tools/ci/test-publish-stestr-timing.sh exercises the
#                  verdict for each class of measurement; it exercises
#                  the write path below for real, against a throwaway
#                  repository with a file:// remote and a stubbed gh.
#   --force        publish even when the comparison says the change is
#                  immaterial. For a manual dispatch that wants the
#                  refresh anyway; the scheduled run never sets it.
#
# Environment:
#   GH_TOKEN       (required unless --dry-run) for `gh pr create`.
#   WORKFLOW_URL   (optional) run URL recorded in the pull request body.
#   BASE_BRANCH    (default develop) base for the pull request.
#   TIMING_PR_ASSIGNEE
#                  (optional) a login to assign the pull request to,
#                  best-effort. Unset everywhere in CI on purpose: an
#                  unattended nightly must not fail because a login
#                  changed or lost access, and the pull request is the
#                  deliverable -- an assignee is a convenience on top of
#                  it. A failure to assign is a warning, not an error.
#
# Exits non-zero only on a real failure -- bad arguments, an unreadable
# or malformed measurement, a git or gh error. An immaterial measurement
# is a success with nothing to do, because that is the normal case.

set -euo pipefail

usage() {
    echo "usage: $0 MEASURED_FILE [--dry-run] [--force]" >&2
    exit 2
}

DRY_RUN=0
FORCE=0
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        -*) usage ;;
        *) POSITIONAL+=("$1") ;;
    esac
    shift
done

if [ "${#POSITIONAL[@]}" -ne 1 ]; then
    usage
fi
MEASURED="${POSITIONAL[0]}"

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMMITTED_REL="tests/stestr-timing.txt"
COMMITTED="${REPO_ROOT}/${COMMITTED_REL}"
BASE_BRANCH="${BASE_BRANCH:-develop}"
BRANCH="stestr-timing/refresh"

if [ ! -f "${MEASURED}" ]; then
    echo "error: no measured timing file at ${MEASURED}" >&2
    exit 1
fi

# Exit codes rather than parsed prose: 0 material, 10 immaterial, 1 any
# kind of error. An error must not read as "nothing to do" -- a
# half-written measurement that silently published nothing would leave
# the hint rotting with no symptom, which is the shape of defect this
# whole mechanism exists to avoid.
set +e
REPORT=$(python3 "${REPO_ROOT}/tools/ci/compare-stestr-timing.py" "${COMMITTED}" "${MEASURED}")
COMPARE_RC=$?
set -e

case "${COMPARE_RC}" in
    0) MATERIAL=1 ;;
    10) MATERIAL=0 ;;
    *)
        echo "error: comparing ${MEASURED} against ${COMMITTED_REL} failed" >&2
        printf '%s\n' "${REPORT}" >&2
        exit 1
        ;;
esac

printf '%s\n' "${REPORT}"
echo ""

if [ "${MATERIAL}" -eq 0 ] && [ "${FORCE}" -eq 0 ]; then
    echo "Timings have not moved materially; leaving ${COMMITTED_REL} alone."
    echo "Pass --force to publish anyway."
    exit 0
fi
if [ "${MATERIAL}" -eq 0 ]; then
    echo "note: --force set, publishing an immaterial refresh anyway."
fi

TITLE="Refresh the committed stestr test timings"

BODY_FILE="$(mktemp)"
trap 'rm -f "${BODY_FILE}"' EXIT
# Backticks throughout the body below are Markdown code spans, not
# command substitution, so the single quotes are deliberate.
# shellcheck disable=SC2016
{
    printf 'Automated refresh of `%s` from the nightly measurement leg,' \
        "${COMMITTED_REL}"
    printf ' which is the one CI job that still runs the whole Python suite in a'
    printf ' single stestr repository and so the only place these durations can be'
    printf ' measured rather than guessed.\n\n'
    printf 'The file is a scheduling hint: `tools/ci/seed-stestr-timing.sh` loads it'
    printf ' before `stestr run` so the scheduler bin-packs its workers by measured'
    printf ' duration. It changes what runs on which worker and nothing about what is'
    printf ' tested, so this is safe to merge on the strength of the comparison below;'
    printf ' it is equally safe to close, which only leaves the packing as good as it'
    printf ' is today.\n\n'
    printf '%s\n\n' "${REPORT}"
    printf '**Its checks are awaiting approval rather than running, and that is'
    printf ' expected.** This pull request is opened by the nightly job with the'
    printf ' workflow GITHUB_TOKEN, so its author is `github-actions[bot]`, and'
    printf ' this repository requires approval for workflow runs on pull requests'
    printf ' from external contributors. The runs are created and then sit at'
    printf ' `action_required` until a maintainer uses "Approve and run workflows"'
    printf ' on the checks tab; `develop` requires those checks, so nothing merges'
    printf ' until that happens. Every `rust-nightly-bump` pull request behaves the'
    printf ' same way, so it says nothing about this one.\n\n'
    if [ "${MATERIAL}" -eq 0 ]; then
        printf 'Opened with `--force` from a manual dispatch: the comparison above'
        printf ' did not consider the change material.\n\n'
    fi
    printf -- '---\n'
    printf 'Measured by %s, opened by `tools/ci/publish-stestr-timing.sh`.\n' \
        "${WORKFLOW_URL:-the nightly matrix workflow}"
} > "${BODY_FILE}"

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "--dry-run: would publish to branch '${BRANCH}' as '${TITLE}'"
    echo "--- body ---"
    cat "${BODY_FILE}"
    echo "--- end body ---"
    exit 0
fi

cd "${REPO_ROOT}"

cp "${MEASURED}" "${COMMITTED}"
if git diff --quiet -- "${COMMITTED_REL}"; then
    # The comparison said material but the bytes are identical, which
    # can only happen if the committed file was already the measurement.
    # Nothing to publish, and an empty commit would be worse than
    # nothing.
    echo "note: ${COMMITTED_REL} is already byte-identical to the measurement; nothing to publish."
    exit 0
fi

git config user.name "shakenfist-bot"
git config user.email "bot@shakenfist.com"

# One long-lived branch, force-pushed. A branch per night would leave a
# trail of stale refs for a file whose only consumer is the scheduler,
# and re-pushing the same branch updates an already-open pull request in
# place instead of opening a second one for the same thing.
git checkout -B "${BRANCH}"
git add "${COMMITTED_REL}"
git commit -m "Refresh the committed stestr test timings.

Measured by the nightly matrix workflow's measurement leg, which runs
the whole Python suite in one stestr repository and re-derives the
per-test durations tools/ci/seed-stestr-timing.sh loads before a run.
The refresh was published because
tools/ci/compare-stestr-timing.py found the suite's weight had moved
materially; see the pull request body for the comparison.

This changes which worker a test runs on and nothing about what is
tested."

git push -f -u origin "${BRANCH}"

EXISTING="$(gh pr list --state open --head "${BRANCH}" --base "${BASE_BRANCH}" \
    --json number --jq '.[].number' 2>/dev/null || true)"
if [ -n "${EXISTING}" ]; then
    echo "Updated the open timing-refresh pull request #${EXISTING} in place."
    exit 0
fi

gh pr create \
    --base "${BASE_BRANCH}" \
    --title "${TITLE}" \
    --body-file "${BODY_FILE}"

# Assignment is optional, best-effort, and names nobody here. A
# hardcoded login ties an unattended nightly to one account: if it is
# renamed or loses access, `gh pr create` fails, the pull request is
# never opened and the run files a failure issue -- for a scheduling
# hint, and over something that is not even part of the refresh. So the
# login comes from the environment if anyone wants one, and failing to
# set it leaves the pull request alone rather than failing the job.
if [ -n "${TIMING_PR_ASSIGNEE:-}" ]; then
    gh pr edit "${BRANCH}" --add-assignee "${TIMING_PR_ASSIGNEE}" ||
        echo "warning: could not assign ${TIMING_PR_ASSIGNEE}; the pull request stands." >&2
fi
