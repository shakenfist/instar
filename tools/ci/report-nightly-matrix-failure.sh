#!/usr/bin/env bash
#
# File or update a GitHub issue for a failed nightly distro-matrix leg.
#
# The six heavy VHD conversion tests no longer gate a merge: they run
# once a night across all seven distros instead, because they measure a
# distro's qemu-img rather than the change under test and they were half
# the merge queue's critical path. That trade is only honest if a red
# nightly reaches a person. A nightly whose failure is visible solely as
# a red square in the Actions tab is not a safety net -- nobody opens the
# Actions tab on a morning when nothing seems wrong -- so filing the
# issue is part of the job rather than a follow-up.
#
# The issue has to name BOTH the distro and the test. That pair is the
# whole signal: the same test failing on one distro and passing on six is
# a qemu-img divergence at that distro's version, while the same test
# failing everywhere is an instar regression that the pull-request jobs
# somehow missed. An issue that says only "the nightly failed" makes a
# reader re-derive that from the log.
#
# Usage:
#   tools/ci/report-nightly-matrix-failure.sh DISTRO IMAGE LOG_FILE \
#       [--dry-run] [--no-dedup] [--kind distro|timing-refresh]
#
#   DISTRO     the matrix entry's name, e.g. "Rocky 9".
#   IMAGE      the container image it ran on, e.g. "rockylinux:9".
#   LOG_FILE   the leg's captured log (MATRIX_LOG from
#              tools/ci/run-matrix-entry.sh).
#
# --kind says what failed, because the nightly has one job that can go
# red without a test having failed. The measurement leg runs the whole
# suite and then publishes the refreshed timings, and a failure in that
# publishing step is a bug in the publisher: filing it as a distro
# failure would send a reader looking for a qemu-img divergence that is
# not there, while filing nothing at all leaves a red run visible only in
# the Actions tab, which is precisely what this script exists to prevent.
# `timing-refresh` therefore says so in the title, the body and the dedup
# key, and skips the per-test and cross-distro reasoning that does not
# apply. `distro` is the default and is the failing-leg report.
#
# --dry-run builds the report and prints it instead of touching the
# GitHub API, for local testing against a downloaded matrix log. It
# implies --no-dedup, since it talks to no API at all.
#
# --no-dedup files unconditionally, without looking for an open issue for
# the same distro.
#
# Inputs (environment):
#   GH_TOKEN          (required unless --dry-run) for `gh issue`.
#   WORKFLOW_URL      (optional) run URL recorded in the issue.
#   MAX_EXCERPT_BYTES (default 4000) byte cap on the whole log excerpt.
#   MAX_LINE_BYTES    (default 200) byte cap on each excerpt line.
#
# Deduplication is per DISTRO, not per failing test set. One open issue
# per distro collects each subsequent night as a comment naming that
# night's tests, which is deliberate: a divergence that takes a week to
# work through would otherwise file seven issues, and the failing set
# often grows or shrinks between nights for one underlying cause. The
# cost is that a genuinely unrelated second failure on the same distro
# arrives as a comment on the first issue; the comment names its tests,
# so it is visible, and that is the cheaper direction.
#
# The labels are `test-failure` and `needs-attention`, which already
# exist in this repository and are what test-drift-fix.yml files its
# unattended failures under. Reusing them keeps one queue of "CI found
# something and nobody has looked" rather than starting a second.
#
# The caller treats a failure here as a warning, not a job-ending error:
# a leg that cannot file its issue has already failed, and masking its
# verdict with the reporter's would lose the distro's result.
#
# tools/ci/test-report-nightly-matrix-failure.sh exercises this against
# synthetic logs, including a leg that died before running any test at
# all.

set -euo pipefail

usage() {
    echo "usage: $0 DISTRO IMAGE LOG_FILE [--dry-run] [--no-dedup]" \
        "[--kind distro|timing-refresh]" >&2
    exit 2
}

DRY_RUN=0
DEDUP=1
KIND=distro
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; DEDUP=0 ;;
        --no-dedup) DEDUP=0 ;;
        --kind)
            shift
            KIND="${1:-}"
            case "${KIND}" in
                distro|timing-refresh) ;;
                *)
                    echo "unknown --kind: '${KIND}' (expected distro or timing-refresh)" >&2
                    usage
                    ;;
            esac
            ;;
        -*) usage ;;
        *) POSITIONAL+=("$1") ;;
    esac
    shift
done

if [ "${#POSITIONAL[@]}" -ne 3 ]; then
    usage
fi
DISTRO="${POSITIONAL[0]}"
IMAGE="${POSITIONAL[1]}"
LOG_FILE="${POSITIONAL[2]}"

if [ -z "${DISTRO}" ] || [ -z "${IMAGE}" ] || [ -z "${LOG_FILE}" ]; then
    usage
fi

MAX_EXCERPT_BYTES="${MAX_EXCERPT_BYTES:-4000}"
MAX_LINE_BYTES="${MAX_LINE_BYTES:-200}"

# How many failing test ids the issue lists by name. A distro whose
# qemu-img diverges on a whole format fails dozens at once, and the first
# twenty are enough to recognise which; the count is always exact.
MAX_TESTS_LISTED=20

if [ ! -f "${LOG_FILE}" ]; then
    echo "::warning::${LOG_FILE} not found; reporting ${DISTRO} without a log" >&2
    LOG_FILE=/dev/null
fi

# Scrub the way tools/ci/report-fuzz-crash.sh does, and for the same
# reason: a matrix log carries test output, including the bytes of
# deliberately malformed images, and invalid UTF-8 is rejected by both jq
# and the GitHub API.
if command -v iconv > /dev/null 2>&1; then
    SCRUB=(iconv -c -f UTF-8 -t UTF-8)
else
    SCRUB=(cat)
fi

# stestr's run output names each result as, for example:
#   {2} test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd [444.8s] ... FAILED
# so the failing ids come straight off those lines. Anchored on both ends
# so a traceback quoting the word FAILED cannot add a phantom test, and
# sorted unique because a parameterised case can report more than once.
TESTS_FILE="$(mktemp)"
BODY_FILE="$(mktemp)"
EXCERPT_FILE="$(mktemp)"
trap 'rm -f "${TESTS_FILE}" "${BODY_FILE}" "${EXCERPT_FILE}"' EXIT

sed -n 's/^{[0-9][0-9]*} \([^ ][^ ]*\) \[[^]]*\] \.\.\. FAILED$/\1/p' \
    "${LOG_FILE}" 2> /dev/null | sort -u > "${TESTS_FILE}" || true
TEST_COUNT="$(grep -c . "${TESTS_FILE}" || true)"
TEST_COUNT="${TEST_COUNT:-0}"

# The totals block, for the one question a reader asks before anything
# else: did this leg fail two tests or two thousand?
TOTALS="$(sed -n 's/^\(Ran: [0-9]* tests.*\)$/\1/p' "${LOG_FILE}" 2> /dev/null | tail -n1 || true)"
QEMU="$(sed -n 's/^qemu-img version \([^ ]*\).*/\1/p' "${LOG_FILE}" 2> /dev/null | head -n1 || true)"
QEMU="${QEMU:-unknown}"

# Anchor the excerpt on stestr's failure block rather than on the end of
# the log. A matrix leg's log ends with the totals and the worker
# balance, so a plain tail shows how long the run took and nothing about
# why it failed. Each line is clipped before the byte cap, because one
# line of captured image bytes can be enormous on its own.
ANCHOR="$(grep -a -n -m1 -- '- output below:' "${LOG_FILE}" 2> /dev/null || true)"
ANCHOR_LINE="${ANCHOR%%:*}"
if [ -n "${ANCHOR_LINE}" ]; then
    sed -n "${ANCHOR_LINE},\$p" "${LOG_FILE}" 2> /dev/null \
        | cut -b "1-${MAX_LINE_BYTES}" \
        | head -c "${MAX_EXCERPT_BYTES}" \
        | tr -d '\000' \
        | "${SCRUB[@]}" 2> /dev/null > "${EXCERPT_FILE}" || true
else
    # No stestr failure block: the leg died before or outside the tests
    # -- a package that would not install, a testdata tree that was not
    # materialised, one of the truncated-run guards, a timeout. The tail
    # is then where the trouble is.
    cut -b "1-${MAX_LINE_BYTES}" "${LOG_FILE}" 2> /dev/null \
        | tail -n 40 \
        | tail -c "${MAX_EXCERPT_BYTES}" \
        | tr -d '\000' \
        | "${SCRUB[@]}" 2> /dev/null > "${EXCERPT_FILE}" || true
fi

# A machine-readable marker in an otherwise human-readable body. The
# fuzz reporter makes its whole body JSON, which suits a crash record
# nobody reads without the reproducer, but a distro divergence is read by
# a person first -- so the body is Markdown and only the dedup key is
# hidden in a comment.
#
# The timing refresh gets a key of its own rather than the measurement
# leg's distro, so a publisher bug cannot be collapsed into an open
# distro-divergence issue (or collapse one into itself); it is one leg,
# so there is no distro to key on.
if [ "${KIND}" = "timing-refresh" ]; then
    TITLE="Nightly timing refresh failure"
    DEDUP_KEY="nightly-timing-refresh"
else
    TITLE="Nightly matrix failure: ${DISTRO}"
    DEDUP_KEY="nightly-matrix:${DISTRO}"
fi

# Backticks throughout the body below are Markdown code spans, not
# command substitution, so the single quotes are deliberate.
# shellcheck disable=SC2016
{
    if [ "${KIND}" = "timing-refresh" ]; then
        printf 'The nightly timing refresh failed on **%s** (`%s`). **No test failed.**\n\n' \
            "${DISTRO}" "${IMAGE}"
        printf 'The measurement leg ran the whole suite and the suite passed. What broke is\n'
        printf 'the step after it, `tools/ci/publish-stestr-timing.sh`, which compares the\n'
        printf 'measured durations against the committed `tests/stestr-timing.txt` and opens\n'
        printf 'a pull request when they moved materially. So this is a bug in the publisher\n'
        printf 'or in its access to the repository -- not a qemu-img divergence, and not an\n'
        printf 'instar regression. Nothing in the suite is implicated by this issue.\n\n'
        printf 'What it costs: `tests/stestr-timing.txt` was not refreshed tonight. The\n'
        printf 'committed file still works, it is simply one night staler, and stestr\n'
        printf "bin-packs its workers less well as it ages. It will not fix itself, which\n"
        printf 'is why this is an issue rather than a red square in the Actions tab.\n\n'
    else
        printf 'The nightly distro matrix failed on **%s** (`%s`), running qemu-img %s.\n\n' \
            "${DISTRO}" "${IMAGE}" "${QEMU}"
        if [ "${TEST_COUNT}" -gt 0 ]; then
            printf 'Failing tests (%s):\n\n' "${TEST_COUNT}"
            awk -v limit="${MAX_TESTS_LISTED}" 'NR <= limit { printf "- `%s`\n", $0 }' \
                "${TESTS_FILE}"
            if [ "${TEST_COUNT}" -gt "${MAX_TESTS_LISTED}" ]; then
                printf -- '- ... and %s more; the full list is in the job log.\n' \
                    "$((TEST_COUNT - MAX_TESTS_LISTED))"
            fi
            printf '\n'
        else
            printf 'No failing test was identified in the log, so this leg failed before or\n'
            printf 'outside the tests themselves -- a package that would not install, testdata\n'
            printf 'that was not materialised, one of the truncated-run guards, or a timeout.\n'
            printf 'The excerpt below is the end of the log rather than a failure block.\n\n'
        fi
        if [ -n "${TOTALS}" ]; then
            printf 'Totals: %s\n\n' "${TOTALS}"
        fi
        printf 'What this means depends on the other six legs of the same run. The same\n'
        printf 'test failing here and passing elsewhere is a qemu-img divergence at this\n'
        printf "distro's version; the same test failing on every distro is an instar\n"
        printf 'regression, and one the pull-request jobs did not catch.\n\n'
    fi
    printf 'Log excerpt:\n\n'
    printf '```\n'
    cat "${EXCERPT_FILE}"
    printf '\n```\n\n'
    printf -- '---\n'
    printf 'Reported by `tools/ci/report-nightly-matrix-failure.sh` from %s.\n\n' \
        "${WORKFLOW_URL:-an unrecorded run}"
    printf '<!-- dedup_key: %s -->\n' "${DEDUP_KEY}"
} > "${BODY_FILE}"

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "--dry-run: would file an issue titled '${TITLE}'"
    echo "body is $(wc -c < "${BODY_FILE}") bytes:"
    cat "${BODY_FILE}"
    exit 0
fi

# A GitHub issue body is capped at 65536 characters. Nothing here should
# approach it -- the excerpt is capped at 4000 bytes and the test list at
# twenty ids -- but a distro that fails every test in the suite would
# make the list long, so drop the excerpt rather than have the API
# reject the whole report.
BODY_BYTES="$(wc -c < "${BODY_FILE}")"
if [ "${BODY_BYTES}" -gt 60000 ]; then
    echo "::warning::issue body for ${DISTRO} is ${BODY_BYTES} bytes; truncating" >&2
    TRUNCATED="$(mktemp)"
    head -c 59000 "${BODY_FILE}" > "${TRUNCATED}" || true
    printf '\n\n(truncated)\n<!-- dedup_key: %s -->\n' "${DEDUP_KEY}" >> "${TRUNCATED}"
    mv "${TRUNCATED}" "${BODY_FILE}"
fi

if [ "${DEDUP}" -eq 1 ]; then
    # --search narrows server-side so the page cannot fill with other
    # distros' issues; the client-side match on the hidden key is the
    # authority. A lookup that fails falls through to filing, because a
    # duplicate issue is a far smaller problem than a silent nightly.
    EXISTING="$(gh issue list \
        --label "test-failure" \
        --state open \
        --search "in:title \"${TITLE}\"" \
        --json number,title,body \
        --limit 100 2> /dev/null \
        | jq -r --arg title "${TITLE}" --arg key "<!-- dedup_key: ${DEDUP_KEY} -->" \
            'map(select(.title == $title and (.body | contains($key)))) | .[0].number // empty' \
        2> /dev/null || true)"

    if [ -n "${EXISTING}" ]; then
        echo "'${TITLE}' already has open issue #${EXISTING};" \
            "commenting instead of filing a duplicate"
        COMMENT_FILE="$(mktemp)"
        trap 'rm -f "${TESTS_FILE}" "${BODY_FILE}" "${EXCERPT_FILE}" "${COMMENT_FILE}"' EXIT
        # shellcheck disable=SC2016
        {
            if [ "${KIND}" = "timing-refresh" ]; then
                printf 'The timing refresh failed again in %s.\n\n' \
                    "${WORKFLOW_URL:-an unrecorded run}"
                printf 'Still the publisher and still not a test: the suite passed, and\n'
                printf '`tests/stestr-timing.txt` went another night without being refreshed.\n'
            else
                printf 'Failed again on %s in %s.\n\n' \
                    "${DISTRO}" "${WORKFLOW_URL:-an unrecorded run}"
                if [ "${TEST_COUNT}" -gt 0 ]; then
                    printf 'Failing tests this run (%s):\n\n' "${TEST_COUNT}"
                    awk -v limit="${MAX_TESTS_LISTED}" 'NR <= limit { printf "- `%s`\n", $0 }' \
                        "${TESTS_FILE}"
                    if [ "${TEST_COUNT}" -gt "${MAX_TESTS_LISTED}" ]; then
                        printf -- '- ... and %s more.\n' "$((TEST_COUNT - MAX_TESTS_LISTED))"
                    fi
                else
                    printf 'No failing test was identified in the log this time either.\n'
                fi
                printf '\nqemu-img %s' "${QEMU}"
                if [ -n "${TOTALS}" ]; then
                    printf ' -- %s' "${TOTALS}"
                fi
                printf '\n'
            fi
        } > "${COMMENT_FILE}"
        gh issue comment "${EXISTING}" --body-file "${COMMENT_FILE}"
        exit 0
    fi
fi

gh issue create \
    --label "test-failure" \
    --label "needs-attention" \
    --title "${TITLE}" \
    --body-file "${BODY_FILE}"
