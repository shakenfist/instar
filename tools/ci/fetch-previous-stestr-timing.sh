#!/usr/bin/env bash
#
# Fetch the most recent earlier measurement of tests/stestr-timing.txt,
# so tools/ci/publish-stestr-timing.sh can ask whether tonight's
# measurement agrees with it before opening a pull request.
#
# The nightly measurement leg uploads every night's derived timing file
# as the `stestr-timing` artifact of its run, kept for 30 days whether
# or not anything was published from it. This walks the recent runs of
# the nightly workflow on one branch, newest first, skipping the run it
# is itself part of, and takes the artifact of the first run whose
# measuring job concluded `success`.
#
# That job conclusion is the same standard tonight's measurement had to
# meet: `publish-timing` refuses a measurement unless `measure`
# succeeded. The artifact alone is not enough to go on, because it is
# uploaded `if: always()` and tools/test-package-functional.sh derives
# the file whenever stestr completed, failed tests included -- a night
# where a heavy test failed in seconds instead of running for minutes
# leaves a timing file that is not a measurement of the suite, and as
# the comparison baseline it would hold back a real refresh or make two
# bad nights agree. A run whose measuring job did not succeed is passed
# over, so "previous" means the previous night that measured, however
# many nights back that was -- a failed night in between does not reset
# the comparison.
#
# Usage:
#   tools/ci/fetch-previous-stestr-timing.sh OUTPUT_FILE
#
#   OUTPUT_FILE    where to put the previous measurement. On success it
#                  holds the file in the format
#                  tools/ci/generate-stestr-timing.py writes, and a
#                  sidecar OUTPUT_FILE.source holds one line naming the
#                  run it came from, which the publisher quotes in the
#                  pull request body.
#
# Environment:
#   GH_TOKEN         (required) for `gh run list` and `gh run download`;
#                    needs `actions: read` on the repository.
#   GITHUB_RUN_ID    (optional) the current run, which is never a
#                    candidate: its own artifact is the measurement being
#                    checked, and a measurement always agrees with itself.
#   TIMING_WORKFLOW  (default nightly-matrix.yml) the workflow whose runs
#                    carry the artifact.
#   TIMING_BRANCH    (default GITHUB_REF_NAME, else develop) the branch
#                    whose runs count. A dispatch on a feature branch
#                    measures a different suite, and must neither become
#                    develop's previous night nor crowd develop's nights
#                    out of the run limit.
#   TIMING_JOB       (default "Measure: full suite on Debian 13") the
#                    display name of the measuring job, whose conclusion
#                    decides whether a run measured. A run that has no
#                    job of that name is a warning, not a silent skip:
#                    it means the job was renamed and this default was
#                    not.
#   TIMING_ARTIFACT  (default stestr-timing) the artifact's name.
#   TIMING_RUN_LIMIT (default 10) how many recent runs to look through.
#
# Exits 0 whether or not a previous measurement was found: OUTPUT_FILE
# exists afterwards if one was, and does not if one was not. A GitHub
# API failure -- listing the runs, reading a run's jobs, or downloading
# the artifact of a run whose measuring job succeeded -- is a warning
# quoting gh's error, and otherwise the same empty result, not an
# error. Those are worded apart from "no earlier night measured" so a
# missing scope or a rejected token does not read as a quiet night. The
# direction of that failure is deliberate. Without a previous measurement
# the publisher falls back to publishing on one night's evidence, which
# is the behaviour this check was added to improve on -- a visible excess
# of pull requests. Failing the job instead would file an issue about the
# refresh being broken when it is not, and silently skipping the publish
# would leave the committed file ageing with nothing to say why, which is
# the one failure this whole mechanism is built to avoid. Exits non-zero
# only on bad usage.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 OUTPUT_FILE" >&2
    exit 2
fi
OUTPUT="$1"
WORKFLOW="${TIMING_WORKFLOW:-nightly-matrix.yml}"
BRANCH="${TIMING_BRANCH:-${GITHUB_REF_NAME:-develop}}"
JOB="${TIMING_JOB:-Measure: full suite on Debian 13}"
ARTIFACT="${TIMING_ARTIFACT:-stestr-timing}"
LIMIT="${TIMING_RUN_LIMIT:-10}"
CURRENT="${GITHUB_RUN_ID:-}"

rm -f "${OUTPUT}" "${OUTPUT}.source"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "${SCRATCH}"' EXIT

# Newest first, which is the order `gh run list` returns. Every run
# conclusion is a candidate: a run that went red because one distro leg
# diverged still measured the suite, and the measuring job's own
# conclusion below is what tells a night that measured from one that
# did not.
if ! gh run list --workflow "${WORKFLOW}" --branch "${BRANCH}" --limit "${LIMIT}" \
        --json databaseId,createdAt,url > "${SCRATCH}/runs.json" 2> "${SCRATCH}/list.err"; then
    echo "warning: could not list recent ${WORKFLOW} runs on ${BRANCH}; no previous measurement to compare against" >&2
    sed 's/^/    /' "${SCRATCH}/list.err" >&2 || true
    exit 0
fi

# One run per line as "id<TAB>createdAt<TAB>url". python3 rather than jq,
# because the job that runs this installs python3 for the comparison
# anyway and jq only on the failure path.
if ! python3 - "${SCRATCH}/runs.json" > "${SCRATCH}/runs.tsv" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    runs = json.load(fh)
for run in runs:
    print(f'{run["databaseId"]}\t{run["createdAt"]}\t{run["url"]}')
PY
then
    echo "warning: could not read the run list; no previous measurement to compare against" >&2
    exit 0
fi

# Prints the conclusion of the job named $2 in the `gh run view --json
# jobs` output at $1, or nothing if the run has no such job. A job still
# running has no conclusion yet, which is not `success` either.
job_conclusion() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    jobs = json.load(fh).get('jobs') or []
for job in jobs:
    if job.get('name') == sys.argv[2]:
        print(job.get('conclusion') or 'unfinished')
        break
PY
}

UNCHECKED=0
while IFS=$'\t' read -r run_id created url; do
    [ -n "${run_id}" ] || continue
    if [ "${run_id}" = "${CURRENT}" ]; then
        continue
    fi

    if ! gh run view "${run_id}" --json jobs > "${SCRATCH}/jobs.json" 2> "${SCRATCH}/view.err" \
            || ! CONCLUSION="$(job_conclusion "${SCRATCH}/jobs.json" "${JOB}" 2>> "${SCRATCH}/view.err")"; then
        echo "warning: could not read the jobs of run ${run_id}; passing over it" >&2
        sed 's/^/    /' "${SCRATCH}/view.err" >&2 || true
        UNCHECKED=$((UNCHECKED + 1))
        continue
    fi
    if [ -z "${CONCLUSION}" ]; then
        echo "warning: run ${run_id} has no job named '${JOB}'; if it was renamed, set TIMING_JOB" >&2
        UNCHECKED=$((UNCHECKED + 1))
        continue
    fi
    if [ "${CONCLUSION}" != "success" ]; then
        echo "Run ${run_id} (${created}): '${JOB}' concluded ${CONCLUSION}, so it did not measure."
        continue
    fi

    rm -rf "${SCRATCH}/download"
    mkdir -p "${SCRATCH}/download"
    if ! gh run download "${run_id}" --name "${ARTIFACT}" --dir "${SCRATCH}/download" \
            > /dev/null 2> "${SCRATCH}/download.err"; then
        # The measuring job succeeded, so the artifact should be there.
        # It can legitimately have expired, but a missing scope or a
        # rejected token fails the same way, so name the run and quote
        # gh rather than reading it as a night that did not measure.
        echo "warning: run ${run_id} measured, but its ${ARTIFACT} artifact could not be downloaded" >&2
        sed 's/^/    /' "${SCRATCH}/download.err" >&2 || true
        UNCHECKED=$((UNCHECKED + 1))
        continue
    fi
    # The artifact is the one file the measuring leg uploads, which
    # download-artifact unpacks under its own name.
    CANDIDATE="$(find "${SCRATCH}/download" -type f -name '*.txt' | head -n 1)"
    if [ -z "${CANDIDATE}" ] || [ ! -s "${CANDIDATE}" ]; then
        echo "warning: run ${run_id} measured, but its ${ARTIFACT} artifact holds no timing file" >&2
        UNCHECKED=$((UNCHECKED + 1))
        continue
    fi
    mkdir -p "$(dirname "${OUTPUT}")"
    cp "${CANDIDATE}" "${OUTPUT}"
    printf 'run %s on %s (%s)\n' "${run_id}" "${created}" "${url}" > "${OUTPUT}.source"
    echo "Previous measurement: $(cat "${OUTPUT}.source")"
    echo "$(wc -l < "${OUTPUT}") test durations, at ${OUTPUT}"
    exit 0
done < "${SCRATCH}/runs.tsv"

if [ "${UNCHECKED}" -gt 0 ]; then
    echo "warning: no previous measurement among the last ${LIMIT} ${WORKFLOW} runs on ${BRANCH}," >&2
    echo "    and ${UNCHECKED} of them could not be checked (see above); nothing to check persistence against." >&2
    exit 0
fi
echo "No previous measurement among the last ${LIMIT} ${WORKFLOW} runs on ${BRANCH}; nothing to check persistence against."
exit 0
