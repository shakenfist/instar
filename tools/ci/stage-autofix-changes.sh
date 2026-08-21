#!/usr/bin/env bash
#
# Stage what a Claude Code autofix run left in the working tree, and
# refuse the attempt if it left anything that cannot be staged safely.
#
# .github/workflows/fuzz-autofix.yml judges an attempt by inspecting the
# index (`git diff --cached --name-only`), and an empty index means "no
# fix". Claude Code edits the working tree and does not reliably stage.
# The compensating `git add -u` used to live in the Create PR step,
# downstream of the gate that needed it, so for months every attempt
# reported "No changes staged by Claude" and the issue was labelled
# autofix-failed with a real edit sitting unstaged in the working tree
# (issues #492, #485 and #426 each show a modified source file above an
# empty "=== Staged Changes ===" block). Move or delete the call to this
# script and that failure comes straight back.
#
# It stages tracked modifications and deletions, and NOTHING ELSE. A
# file the fix created is refused, not guessed at:
#
#   * staging new files means classifying them -- source file or editor
#     leftover, fixture or build output -- and a wrong guess ships a
#     branch that does not compile behind a PR that says "Build
#     succeeded", because the verify build runs against the working
#     tree where the file is present;
#   * refusing means the run stops, the file is named, and the issue
#     keeps its autofix-failed label for a human. A wrong guess costs a
#     look at an issue that was already going to get one.
#
# The second failure is the cheap one, so the classification is not
# worth having. An earlier revision of this script tried it and grew a
# source-root allowlist, an artifact denylist, gitignored-file
# reporting and a workflow-path exclusion; each refinement introduced
# the next defect. If you are about to add a rule for which new files
# are safe to stage, that is the history you are repeating.
#
# Refusal cases, all reported by path:
#
#   * an untracked file, excluding editor and merge leftovers (`*~`,
#     `*.orig`, ...) which pre-commit and editors produce routinely;
#   * a file matching a .gitignore rule that was not there before the
#     attempt. git hides ignored paths from the untracked listing
#     entirely, so without the --baseline comparison these vanish
#     without a trace -- and `**/*.bin` is in .gitignore, which is
#     exactly what a fuzz-crash regression fixture would be called.
#     Known limit: the listing collapses a wholly-ignored directory to
#     one entry, so a file created inside a directory that was ALREADY
#     ignored when the baseline was taken produces no new entry and no
#     refusal. What qualifies is build output nobody would put a
#     fixture in, and closing it would mean an mtime pass over every
#     ignored tree on every run;
#   * a change under .github/workflows/. `git push` with the
#     GITHUB_TOKEN actions/checkout persists is refused for any commit
#     touching one, and the `workflows` scope it needs cannot be
#     granted through the workflow's `permissions:` key -- so a staged
#     workflow edit does not fail here, it fails two hours later at the
#     push. Actively unstaged, because Claude may have staged it
#     itself, in which case declining to add it is not enough.
#
# This is a script rather than inline YAML for the same reason
# pick-fuzz-artifact.sh is: logic that only runs inside a live daily
# workflow run cannot be tested there, and the bugs in this area all
# hid in inline YAML. Covered by tools/ci/test-stage-autofix-changes.sh.
#
# Usage:
#   tools/ci/stage-autofix-changes.sh --snapshot FILE [REPO_DIR]
#       Record the ignored paths that exist now, before the attempt
#       starts. Stages nothing.
#
#   tools/ci/stage-autofix-changes.sh [--baseline FILE]
#                                     [--refused-file FILE] [REPO_DIR]
#       Stage tracked modifications; refuse on anything above. Without
#       --baseline no ignored-file comparison is made, so a new ignored
#       file is not detected -- pass it. --refused-file records the
#       ignored paths that caused a refusal, for a caller that wants to
#       delete them before retrying.
#
#   tools/ci/stage-autofix-changes.sh --tracked-only [REPO_DIR]
#       Stage tracked modifications and check nothing. For call sites
#       downstream of the gates, where the checks have already run and
#       the verify build has since written to the tree.
#
# REPO_DIR defaults to the current directory; the script works from the
# top level of whatever work tree it names. The FILE arguments are
# resolved after that chdir, so pass absolute paths.
#
# Exit codes: 0 staged (or nothing to stage), 2 usage error, 3 refused.

set -euo pipefail

# What counts as a leftover rather than part of the fix. Shared with
# address-comments-with-claude.sh, which stages new files onto a
# review-comment commit and needs to skip exactly the same paths.
#
# Resolved here rather than at the point of use: this script cd's to
# REPO_DIR and then to its top level, and fuzz-autofix.yml invokes it
# by the relative path tools/ci/stage-autofix-changes.sh, so a dirname
# taken after those cd's points somewhere else.
# shellcheck source=tools/ci/autofix-artifact-patterns.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/autofix-artifact-patterns.sh"

REFUSED=3

usage() {
    echo "usage: $0 [--snapshot FILE | --baseline FILE [--refused-file FILE] | --tracked-only] [REPO_DIR]"
}

MODE=check
BASELINE=
REFUSED_FILE=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --snapshot)
            MODE=snapshot
            BASELINE="${2:-}"
            [ -n "${BASELINE}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        --baseline)
            BASELINE="${2:-}"
            [ -n "${BASELINE}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        --refused-file)
            REFUSED_FILE="${2:-}"
            [ -n "${REFUSED_FILE}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        --tracked-only) MODE=tracked-only; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) usage >&2; exit 2 ;;
        *) break ;;
    esac
done

REPO_DIR="${1:-.}"

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

if [ ! -d "${REPO_DIR}" ]; then
    echo "stage-autofix-changes: ${REPO_DIR} does not exist" >&2
    exit 2
fi

cd "${REPO_DIR}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "stage-autofix-changes: ${REPO_DIR} is not a git work tree" >&2
    exit 2
fi

# `git add -u` is repo-wide but `git ls-files --others` prints paths
# relative to the cwd, so without this the two would disagree about
# what "the repo" means.
cd "$(git rev-parse --show-toplevel)"

# One collapsed entry per wholly-ignored directory, so src/target/ is
# one line rather than thousands. Used for both the snapshot and the
# comparison, so the two are always in the same shape.
list_ignored() {
    # -c core.quotePath=false: the listing has to be newline
    # separated so `comm` can diff it against the baseline, which means
    # git would otherwise octal-escape and quote any path with
    # non-ASCII bytes. That quoted string ends up in --refused-file,
    # and the retry's `rm -rf` then matches nothing, so the file
    # survives and refuses attempt 2 unconditionally -- the failure the
    # deletion exists to prevent. It fixes the non-ASCII case only:
    # git still C-quotes a path containing a newline, tab or double
    # quote, and one of those would round-trip the same broken way.
    # Making that safe means a NUL-separated comparison rather than
    # `comm`, which is more than the case is worth here.
    git -c core.quotePath=false \
        ls-files --others --ignored --exclude-standard --directory \
        | LC_ALL=C sort
}

if [ "${MODE}" = snapshot ]; then
    list_ignored > "${BASELINE}"
    echo "Recorded $(grep -c . < "${BASELINE}" || true) ignored path(s) as the pre-attempt baseline."
    exit 0
fi


declare -A REPORTED_WORKFLOW=()

# Read before `git add -u` so this reflects what Claude staged, not
# what this script is about to stage. `git ls-files --others` does not
# list a path that is already in the index, so without this a new file
# Claude ran `git add` on would reach a pull request without the human
# look the refusal exists to force -- and the whole point of this
# script is not to depend on Claude following the prompt.
CLAUDE_ADDED=()
while IFS= read -r -d '' FILE; do
    case "${FILE}" in
        .github/workflows/*) continue ;;
    esac
    CLAUDE_ADDED+=("${FILE}")
done < <(git diff --cached --name-only -z --diff-filter=A)

WORKFLOW_CHANGES=()
while IFS= read -r -d '' FILE; do
    WORKFLOW_CHANGES+=("${FILE}")
done < <(git diff HEAD --name-only -z -- '.github/workflows/')

# Declining to add it is not enough: Claude may have staged it already,
# and an exclude pathspec does not remove what is in the index.
if [ ${#WORKFLOW_CHANGES[@]} -gt 0 ]; then
    git reset -q HEAD -- '.github/workflows/' 2>/dev/null || true
    for WF in "${WORKFLOW_CHANGES[@]}"; do
        REPORTED_WORKFLOW["${WF}"]=1
    done
fi

git add -u -- . ':(exclude).github/workflows/'

if [ "${MODE}" = tracked-only ]; then
    if [ ${#WORKFLOW_CHANGES[@]} -gt 0 ]; then
        echo "Unstaged ${#WORKFLOW_CHANGES[@]} workflow change(s); a commit touching these cannot be pushed:"
        printf '    %s\n' "${WORKFLOW_CHANGES[@]}"
    fi
    exit 0
fi

UNTRACKED=("${CLAUDE_ADDED[@]}")
ARTIFACTS=()
while IFS= read -r -d '' FILE; do
    # Skip only what the workflow heading actually named. The reset
    # above turns a staged new workflow file untracked, so a blanket
    # skip would stop it being named twice -- but it would also hide a
    # workflow file the attempt created and never staged, which
    # `git diff HEAD` cannot see either. That one exits 0 and is
    # dropped from the commit, which is the outcome this whole script
    # exists to prevent.
    if [ -n "${REPORTED_WORKFLOW["${FILE}"]:-}" ]; then
        continue
    fi
    if [[ "${FILE}" =~ ${ARTIFACT_NAMES} ]]; then
        ARTIFACTS+=("${FILE}")
    else
        UNTRACKED+=("${FILE}")
    fi
done < <(git ls-files --others --exclude-standard -z)

NEW_IGNORED=()
if [ -n "${BASELINE}" ] && [ -f "${BASELINE}" ]; then
    while IFS= read -r FILE; do
        [ -n "${FILE}" ] || continue
        if [[ "${FILE}" =~ ${ARTIFACT_NAMES} ]] \
            || [[ "${FILE}" =~ ${CI_OUTPUT_DIRS} ]] \
            || [[ "${FILE}" =~ ${CI_OUTPUT_NAMES} ]]; then
            ARTIFACTS+=("${FILE}")
        else
            NEW_IGNORED+=("${FILE}")
        fi
    done < <(LC_ALL=C comm -13 "${BASELINE}" <(list_ignored))
fi

if [ ${#ARTIFACTS[@]} -gt 0 ]; then
    echo "Ignoring ${#ARTIFACTS[@]} artifact(s) and build or test output:"
    printf '    %s\n' "${ARTIFACTS[@]}"
fi

REFUSE=false

if [ ${#WORKFLOW_CHANGES[@]} -gt 0 ]; then
    REFUSE=true
    echo "REFUSED: a commit touching these cannot be pushed with the token CI holds:"
    printf '    %s\n' "${WORKFLOW_CHANGES[@]}"
fi

if [ ${#UNTRACKED[@]} -gt 0 ]; then
    REFUSE=true
    echo "REFUSED: the attempt created these files, which are not staged and would not reach the pull request:"
    printf '    %s\n' "${UNTRACKED[@]}"
fi

if [ ${#NEW_IGNORED[@]} -gt 0 ]; then
    REFUSE=true
    echo "REFUSED: the attempt created these, which .gitignore hides and which would not reach the pull request:"
    printf '    %s\n' "${NEW_IGNORED[@]}"
    # `git clean -fd` has no -x, so these survive a retry reset and
    # would refuse the next attempt whatever it did. The caller deletes
    # what is named here before retrying.
    if [ -n "${REFUSED_FILE}" ]; then
        printf '%s\n' "${NEW_IGNORED[@]}" > "${REFUSED_FILE}"
    fi
fi

if [ "${REFUSE}" = true ]; then
    echo "A fix that needs a new file needs a human. The tracked edits above are"
    echo "staged so the failure report and the retry prompt can show them, but this"
    echo "attempt will not become a pull request."
    exit "${REFUSED}"
fi

if [ -z "$(git diff --cached --name-only)" ]; then
    echo "Nothing staged: the attempt modified no tracked file."
fi
