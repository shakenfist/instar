#!/usr/bin/env bash
#
# Fetch the most recent earlier measurement of tests/stestr-timing.txt,
# so tools/ci/publish-stestr-timing.sh can ask whether tonight's
# measurement agrees with it before opening a pull request.
#
# The nightly measurement leg uploads every night's derived timing file
# as the `stestr-timing` artifact of its run, kept for 30 days whether
# or not anything was published from it. This walks the recent runs of
# the nightly workflow, newest first, skipping the run it is itself part
# of, and downloads the first `stestr-timing` artifact it finds. A run
# whose measuring leg failed uploaded no artifact and is skipped, so
# "previous" means the previous night that measured, however many nights
# back that was -- a failed night in between does not reset the
# comparison.
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
#   TIMING_ARTIFACT  (default stestr-timing) the artifact's name.
#   TIMING_RUN_LIMIT (default 10) how many recent runs to look through.
#
# Exits 0 whether or not a previous measurement was found: OUTPUT_FILE
# exists afterwards if one was, and does not if one was not. A GitHub
# API failure is a warning and the same empty result, not an error. The
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
ARTIFACT="${TIMING_ARTIFACT:-stestr-timing}"
LIMIT="${TIMING_RUN_LIMIT:-10}"
CURRENT="${GITHUB_RUN_ID:-}"

rm -f "${OUTPUT}" "${OUTPUT}.source"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "${SCRATCH}"' EXIT

# Newest first, which is the order `gh run list` returns. Every
# conclusion is a candidate: a run that went red because one distro leg
# diverged still measured the suite, and the artifact download below is
# what tells a night that measured from one that did not.
if ! gh run list --workflow "${WORKFLOW}" --limit "${LIMIT}" \
        --json databaseId,createdAt,url > "${SCRATCH}/runs.json" 2> "${SCRATCH}/list.err"; then
    echo "warning: could not list recent ${WORKFLOW} runs; no previous measurement to compare against" >&2
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

while IFS=$'\t' read -r run_id created url; do
    [ -n "${run_id}" ] || continue
    if [ "${run_id}" = "${CURRENT}" ]; then
        continue
    fi
    rm -rf "${SCRATCH}/download"
    mkdir -p "${SCRATCH}/download"
    if ! gh run download "${run_id}" --name "${ARTIFACT}" --dir "${SCRATCH}/download" \
            > /dev/null 2> "${SCRATCH}/download.err"; then
        # No artifact on that run: it did not measure. Keep looking.
        continue
    fi
    # The artifact is the one file the measuring leg uploads, which
    # download-artifact unpacks under its own name.
    CANDIDATE="$(find "${SCRATCH}/download" -type f -name '*.txt' | head -n 1)"
    if [ -z "${CANDIDATE}" ] || [ ! -s "${CANDIDATE}" ]; then
        continue
    fi
    mkdir -p "$(dirname "${OUTPUT}")"
    cp "${CANDIDATE}" "${OUTPUT}"
    printf 'run %s on %s (%s)\n' "${run_id}" "${created}" "${url}" > "${OUTPUT}.source"
    echo "Previous measurement: $(cat "${OUTPUT}.source")"
    echo "$(wc -l < "${OUTPUT}") test durations, at ${OUTPUT}"
    exit 0
done < "${SCRATCH}/runs.tsv"

echo "No previous measurement among the last ${LIMIT} ${WORKFLOW} runs; nothing to check persistence against."
exit 0
