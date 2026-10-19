#!/usr/bin/env bash
#
# Resparsify the testdata tree tools/ci/prepare-testdata.sh just
# prepared, in whichever of the two ways that tree actually needs.
#
# A fresh clone is written out fully allocated, every image of it, so it
# gets resparsify-testdata.sh's whole-tree call, as does a cache nobody
# vouched for. A tree updated in place on the runner fleet's testdata
# dependencies disk gets the narrow one: it is a copy-on-write overlay
# of an image that was resparsified when it was built, so the only
# images in it that are not already sparse are the ones this job's own
# fetch and `git lfs pull` brought in -- which is exactly the
# changed-file list.
# Sweeping the whole tree there would write back into the overlay the
# gigabytes the disk exists to avoid, and skipping it altogether would
# leave the day's drift fully allocated.
#
# WHY THIS IS A SCRIPT RATHER THAN A CONDITIONAL IN SEVEN WORKFLOW
# STEPS. Three reasons, in increasing order of what they cost.
#
# resparsify-testdata.sh cannot make this decision itself. It is a
# cross-repository interface -- private-ci's testdata image build
# fetches it over HTTPS and runs it against its own clone, nowhere near
# GitHub Actions -- so it reads no environment variable at all,
# deliberately, with a test asserting as much. The choice between its
# two calling forms therefore belongs to its caller, and in CI the
# caller is a workflow step.
#
# Seven copies of that choice in YAML would be seven places for it to
# drift, and the drift has no symptom: a step that quietly widened back
# to the whole tree still leaves a perfectly correct tree behind, and
# the cost lands as gigabytes written into somebody's overlay. That is
# the same hazard that made the resparsify loop a shared script instead
# of a repeated workflow step in the first place.
#
# And a workflow step cannot be tested. This can be, and is, by
# tools/ci/test-resparsify-prepared-testdata.sh.
#
# Inputs (environment), all of them exported by prepare-testdata.sh:
#
#   TESTDATA_PATH          (required) the prepared tree.
#   TESTDATA_SOURCE        (required) "clone", "unverified-cache" or
#                          "cache".
#   TESTDATA_CHANGED_FILES (required when the source is "cache") a file
#                          listing the paths that update changed.
#
# An unset or unrecognised TESTDATA_SOURCE is an error rather than a
# fall back to the whole tree. The fallback is the expensive branch, and
# taking it silently would cost the most on exactly the runner where the
# saving was supposed to be.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESPARSIFY="${SCRIPT_DIR}/resparsify-testdata.sh"

if [ -z "${TESTDATA_PATH:-}" ]; then
    echo "::error::TESTDATA_PATH is not set. tools/ci/prepare-testdata.sh exports it, so" \
         "it has to have run in this job before this step." >&2
    exit 1
fi

case "${TESTDATA_SOURCE:-}" in
    clone)
        echo "testdata source is a fresh clone: resparsifying the whole tree"
        exec "${RESPARSIFY}" "${TESTDATA_PATH}"
        ;;
    unverified-cache)
        # A tree that was already there, on a job that did not assert
        # it is the fleet's disk. Nothing says what it arrived with was
        # sparse, and narrowing would leave anything that was not fully
        # allocated with no symptom but drifting disk_size results. No
        # overlay is being protected here either, so the whole tree.
        echo "testdata source is a cache this job did not vouch for: resparsifying the whole tree"
        exec "${RESPARSIFY}" "${TESTDATA_PATH}"
        ;;
    cache)
        # The assumption this branch rests on, stated where it is
        # relied upon: narrowing to the changed files is correct only
        # if everything that was already there was already sparse.
        # Nothing observes that directly. prepare-testdata.sh reports
        # "cache" only when TESTDATA_REQUIRE_CACHE=1 has asserted the
        # tree is the fleet's pre-built testdata disk, whose image is
        # resparsified when it is built; any other cache arrives as
        # "unverified-cache" above.
        if [ -z "${TESTDATA_CHANGED_FILES:-}" ]; then
            echo "::error::TESTDATA_SOURCE=cache but TESTDATA_CHANGED_FILES is not set." \
                 "prepare-testdata.sh exports both together on that branch, so one without" \
                 "the other means the two scripts have drifted apart. Resparsifying the whole" \
                 "tree instead is refused on purpose: on a copy-on-write overlay that writes" \
                 "back the gigabytes the testdata disk exists to avoid." >&2
            exit 1
        fi
        if [ ! -f "${TESTDATA_CHANGED_FILES}" ]; then
            echo "::error::TESTDATA_CHANGED_FILES is ${TESTDATA_CHANGED_FILES}, which does not" \
                 "exist. prepare-testdata.sh writes it under \$RUNNER_TEMP, which survives to" \
                 "later steps in the same job but not between jobs; a step in another job" \
                 "cannot use it." >&2
            exit 1
        fi
        echo "testdata source is an updated cache: resparsifying only the" \
             "$(wc -l < "${TESTDATA_CHANGED_FILES}") path(s) the update changed"
        exec "${RESPARSIFY}" "${TESTDATA_PATH}" --files-from "${TESTDATA_CHANGED_FILES}"
        ;;
    '')
        echo "::error::TESTDATA_SOURCE is not set. tools/ci/prepare-testdata.sh exports it" \
             "alongside TESTDATA_PATH, so it has to have run in this job before this step." \
             "Defaulting to the whole tree is refused: that is the expensive branch, and a" \
             "silent default would cost the most on a runner carrying the testdata disk." >&2
        exit 1
        ;;
    *)
        echo "::error::TESTDATA_SOURCE is '${TESTDATA_SOURCE}', which is not 'clone'," \
             "'unverified-cache' or 'cache'. Those are the only values prepare-testdata.sh exports," \
             "so either it has gained a branch without teaching this script what the tree looks like," \
             "or something else in the job overwrote the variable." >&2
        exit 1
        ;;
esac
