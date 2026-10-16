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
#   TESTDATA_REQUIRE_CACHE
#                    (optional) 1 refuses the fresh-clone fallback; 0
#                    or unset allows it. Any other value is an error,
#                    not an "off" -- see "REQUIRING THE CACHE" below.
#   TESTDATA_CONTRACT_CACHE
#                    (test seam) Relocates the contractual path that
#                    flag is checked against. See CONTRACT_CACHE below
#                    for why this does not weaken the check.
#   GITHUB_WORKSPACE (required in Actions) Fresh-clone parent dir.
#   RUNNER_TEMP      (optional) Where the changed-file list below is
#                    written; the workspace when unset.
#   GITHUB_ENV       (optional) When set, the resolved TESTDATA_PATH and
#                    the two variables below are exported to it for
#                    later steps.
#
# Output: prints, and when GITHUB_ENV is set writes to it,
#
#   TESTDATA_PATH          the resolved tree.
#   TESTDATA_SOURCE        "cache" or "clone" -- which of the two
#                          branches below ran. A later step has to know:
#                          the two leave the tree in materially
#                          different states, and nothing else can tell
#                          them apart by looking.
#   TESTDATA_CHANGED_FILES on the cache branch only, a file listing the
#                          paths the update changed, one per line.
#
# WHY THE BRANCH TAKEN IS PART OF THE OUTPUT. A fresh clone writes every
# image out fully allocated, so the whole tree needs resparsifying
# afterwards. The consumer is tools/ci/resparsify-prepared-testdata.sh,
# which reads these variables and picks one of the two calling forms of
# tools/ci/resparsify-testdata.sh. A cache does not need all of it:
# where that cache is a pre-built testdata dependencies disk, the tree
# is a copy-on-write overlay of an image that was resparsified when it was
# built, and rewriting all of it would write the gigabytes into the
# overlay that the disk exists to avoid. Only the paths this update
# brought in need it, which is why the changed-file list is produced
# here: the reset that changed them has already happened by the time any
# later step runs, so this is the only place that set can be derived.
#
# REQUIRING THE CACHE. With TESTDATA_REQUIRE_CACHE=1 a missing cache is
# an infra error rather than a 7.46 GiB fallback clone, in the same
# idiom as the LFS guard above: a job that silently did the slow thing
# merely looks slow, and looking slow is exactly the failure mode that
# is invisible for weeks. The assertion names the contractual path
# literally rather than taking it from TESTDATA_CACHE, so that a change
# to either side of that contract fails here instead of quietly
# following a defaulted path somewhere else.

set -euo pipefail

# Resolved before anything changes directory: this script cd's into the
# testdata clone, so a relative $0 would not survive to the fixture
# check below.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TESTDATA_CACHE="${TESTDATA_CACHE:-/srv/ci/cached/instar-testdata}"
REPO_HOST='gitlab.home.stillhq.com'
REPO_PATH='private/instar-testdata.git'

# Where the runner fleet's testdata dependencies disk is mounted, by
# agreement with the fleet: userdata mounts it there by filesystem label
# before the runner registers, and the conductor carries the same path.
# Written out literally, and deliberately not derived from
# TESTDATA_CACHE above, because this is the half of the contract this
# repository is responsible for asserting.
#
# TESTDATA_CONTRACT_CACHE relocates it, and exists for exactly one
# caller: tools/ci/test-prepare-testdata.sh, which otherwise cannot
# exercise either side of the guard below without the real disk being
# mounted on the machine running the tests. A case that can only be
# skipped is a case that proves nothing, and the half of the contract
# that matters most -- a required cache that is present -- is the half
# a developer machine can never reach.
#
# It is a seam, not a loophole, and the distinction is that it is a
# *different variable* from TESTDATA_CACHE. The guard asks whether the
# operational override agrees with the agreed path; letting the same
# variable supply both sides would make it tautological, which is the
# thing the literal was written out to prevent. Supplying only this one
# does not help a misconfigured job either: TESTDATA_CACHE still has to
# match it. Nothing under .github/ sets it, and
# tools/ci/test-prepare-testdata.sh asserts that nothing does.
CONTRACT_CACHE="${TESTDATA_CONTRACT_CACHE:-/srv/ci/cached/instar-testdata}"

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

# Read as a tri-state rather than compared against '1', because the
# two ways of getting this wrong are not symmetric. An unrecognised
# value read as "off" gives back the 7.46 GiB fallback clone this flag
# exists to refuse, on a job whose author believed they had turned the
# refusal on -- and the symptom is a job that merely looks slow, which
# is the failure mode the whole arrangement is built to remove. So
# "off" is spelled out exhaustively and everything else is an error
# rather than a default.
case "${TESTDATA_REQUIRE_CACHE:-}" in
    ''|'0') REQUIRE_CACHE=0 ;;
    '1') REQUIRE_CACHE=1 ;;
    *)
        echo "::error::TESTDATA_REQUIRE_CACHE is" \
             "'${TESTDATA_REQUIRE_CACHE}'; it takes 1 to require the" \
             "prepared cache and 0 or unset to allow the fresh-clone" \
             "fallback. Refusing to guess: reading an unrecognised value" \
             "as off would hand back the fallback clone the flag was set" \
             "to prevent, and that is invisible in a passing job." >&2
        exit 1
        ;;
esac

# Asserted before either branch, so that a cache at some other path
# cannot satisfy a job that asked for the contractual one.
if [ "${REQUIRE_CACHE}" = '1' ]; then
    if [ "${TESTDATA_CACHE}" != "${CONTRACT_CACHE}" ]; then
        echo "::error::TESTDATA_REQUIRE_CACHE=1 but TESTDATA_CACHE is" \
             "${TESTDATA_CACHE}, not the agreed ${CONTRACT_CACHE}. The path is" \
             "half of the contract with the runner fleet's testdata dependencies" \
             "disk; a job that requires the disk must look where the fleet" \
             "mounts it, so fix the override or the agreement rather than this" \
             "check." >&2
        exit 1
    fi
    if [ ! -d "${CONTRACT_CACHE}/.git" ]; then
        # Deliberately not blamed on a failed mount, which cannot be the
        # cause: a mount that fails stops the fleet's userdata before the
        # runner registers, so the job stays queued and never reaches
        # this script at all. What is left is a mismatch -- we are
        # looking somewhere the disk is not, or this runner advertised
        # the label without carrying the disk.
        echo "::error::TESTDATA_REQUIRE_CACHE=1 but there is no prepared" \
             "instar-testdata tree at ${CONTRACT_CACHE}. This is a path" \
             "mismatch, not a failed mount: a mount failure stops the runner" \
             "before it registers, so such a job never starts and never gets" \
             "here. Either the mount path changed on one side of the contract," \
             "or this job was assigned a runner advertising the testdata disk's" \
             "label without the disk. Do not read userdata logs for a mount" \
             "failure; compare the paths. This is an infrastructure problem, NOT" \
             "a test or instar regression, and the fresh-clone fallback is" \
             "refused on purpose: 7.46 GiB of clone would turn it into a job" \
             "that merely looks slow." >&2
        exit 1
    fi
fi

# Set on the cache branch only, and read again where the changed-file
# list is built. Declared here so that neither reference depends on
# which branch ran.
STAT_DIRTY=''

if [ -d "${TESTDATA_CACHE}/.git" ]; then
    echo "Using cached testdata at ${TESTDATA_CACHE}, updating in place..."
    cd "${TESTDATA_CACHE}"
    # Captured before the fetch: the changed-file list below is the diff
    # across the reset, and this is the only moment the pre-update
    # revision is still reachable by name.
    PREVIOUS_REV="$(git rev-parse --verify --quiet HEAD || true)"
    # Captured before the fetch as well, and for a reason the tree diff
    # below cannot cover. The disk build resparsifies after its own
    # checkout; resparsifying is a cp + mv, so the index's stored stat
    # data for every image it touched no longer matches the file. The
    # reset then rewrites those entries -- measured, not assumed: an
    # unchanged file whose index entry is stat-dirty gets a new mtime
    # across the reset, while an unchanged file with clean stat data
    # does not. Under LFS that rewrite comes back through the smudge
    # filter fully allocated, and no diff between the two trees names
    # it, so the narrow resparsify below would skip exactly the files
    # the reset had just re-expanded.
    #
    # Plumbing on purpose: `git diff` and `git status` are porcelain
    # and silently run update-index --refresh, which would clear the
    # evidence before it could be read. Nothing may run them here
    # first.
    STAT_DIRTY="$(git diff-files --name-only -z | tr '\0' '\n')"
    git remote set-url origin "${AUTHED_URL}"
    git fetch --depth 1 origin main
    git reset --hard origin/main
    TESTDATA_PATH="${TESTDATA_CACHE}"
    # "cache" is only ever observed as "a tree was already here", which
    # is strictly weaker than what the narrow resparsify downstream
    # relies on -- that the tree it was built from was already sparse.
    # Nothing here can check the stronger thing, and today the two
    # coincide because the only cache any job meets is the fleet's
    # pre-built disk, whose image is resparsified when it is built. A
    # second kind of cache, seeded any other way, would make this value
    # a lie in the expensive direction: the images it arrived with would
    # stay fully allocated because no update touched them. Such a cache
    # needs a third TESTDATA_SOURCE value, not a looser reading of this
    # one.
    TESTDATA_SOURCE='cache'
else
    echo "No cache at ${TESTDATA_CACHE}, cloning fresh..."
    TESTDATA_PATH="${GITHUB_WORKSPACE}/instar-testdata"
    TESTDATA_SOURCE='clone'
    git clone --depth 1 "${AUTHED_URL}" "${TESTDATA_PATH}"
    cd "${TESTDATA_PATH}"
fi

# Materialise LFS content explicitly rather than relying on an implicit
# smudge filter. install --local writes the filter config into this
# clone; pull fetches and checks out the actual objects. Both are
# idempotent and cheap when the objects are already present.
git lfs install --local
git lfs pull

# The paths this update brought in, for a later step that needs to treat
# them differently from the rest of the tree -- resparsifying only them,
# today. Derived here because the reset that changed them is here: by
# the time a later step runs there is nothing left to diff.
#
# The list is every changed path, not only the images: the consumer
# filters it against its own idea of what it acts on, so that this
# script does not carry a second copy of that extension list to drift
# from. Paths arrive NUL-separated from git and are rewritten one per
# line, which keeps them raw rather than quoted; a path containing a
# literal newline would split into two entries that the consumer then
# discards, and instar-testdata has none.
TESTDATA_CHANGED_FILES=''
if [ "${TESTDATA_SOURCE}" = 'cache' ]; then
    # RUNNER_TEMP rather than the workspace: it survives to the next
    # step, is cleaned between jobs, and is not inside anybody's
    # checkout -- one of the workflows checks instar out at the
    # workspace root, where this would land as an untracked file in the
    # repository. Falls back to the workspace when run outside Actions.
    TESTDATA_CHANGED_FILES="${RUNNER_TEMP:-${GITHUB_WORKSPACE}}/testdata-changed-files.txt"
    if [ -z "${PREVIOUS_REV}" ]; then
        # No HEAD before the update, so everything in the tree is new;
        # git's empty tree is the honest left-hand side for that, and
        # asking git for it keeps this correct under either hash
        # algorithm.
        PREVIOUS_REV="$(git hash-object -t tree /dev/null)"
    fi
    # Two sources, unioned: what the two trees disagree about, and what
    # was stat-dirty going in. Both are paths the reset rewrote, and
    # the second is invisible to any diff of the trees -- see the
    # capture above. Adding them costs nothing that has not already
    # been spent: the reset expanded those files into the
    # copy-on-write overlay whether or not this list names them, so
    # resparsifying them afterwards shrinks a copy-up that has already
    # happened rather than causing one. tools/ci/test-testdata-changed-files.sh
    # proves the union against a real git, including that the tree diff
    # alone would miss them.
    {
        git diff --name-only -z "${PREVIOUS_REV}" HEAD | tr '\0' '\n'
        if [ -n "${STAT_DIRTY}" ]; then
            printf '%s\n' "${STAT_DIRTY}"
        fi
    } | sort -u > "${TESTDATA_CHANGED_FILES}"
    if [ -n "${STAT_DIRTY}" ]; then
        # Worth an annotation rather than a log line: a non-zero count
        # means whatever built this cache left the index stat-dirty,
        # and every job on it then pays to rewrite and resparsify those
        # files. The fix is on the other side -- the build runs
        # `git update-index --refresh` after resparsifying -- and this
        # is the only place the cost is visible.
        echo "::warning::$(printf '%s\n' "${STAT_DIRTY}" | wc -l) path(s) in" \
             "${TESTDATA_CACHE} had stale index stat data before the update, so" \
             "the reset rewrote them and they are resparsified again here." \
             "Whatever built this cache should run 'git update-index --refresh'" \
             "after resparsifying it."
    fi
    echo "the update changed $(wc -l < "${TESTDATA_CHANGED_FILES}") path(s)," \
         "listed in ${TESTDATA_CHANGED_FILES}"
fi

# Guard: prove the fixtures the suite cannot do without are present and
# materialised. The check is a separate script because
# tools/test-package-functional.sh needs the same guarantee, and because
# a guard this load-bearing deserves tests of its own -- see
# tools/ci/test-check-testdata-fixtures.sh. It fails on a missing
# fixture, not only on an un-materialised LFS pointer: every test that
# reads these skips rather than fails when its file is absent, so a
# partial or renamed checkout would quietly shrink the suite.
"${SCRIPT_DIR}/check-testdata-fixtures.sh" "${TESTDATA_PATH}" --annotate

echo "testdata ready at ${TESTDATA_PATH} (LFS materialised, required fixtures verified)"
echo "testdata source: ${TESTDATA_SOURCE}"
if [ -n "${GITHUB_ENV:-}" ]; then
    {
        echo "TESTDATA_PATH=${TESTDATA_PATH}"
        echo "TESTDATA_SOURCE=${TESTDATA_SOURCE}"
        if [ -n "${TESTDATA_CHANGED_FILES}" ]; then
            echo "TESTDATA_CHANGED_FILES=${TESTDATA_CHANGED_FILES}"
        fi
    } >> "${GITHUB_ENV}"
fi
