#!/usr/bin/env bash
#
# Stage what a Claude Code autofix run left in the working tree, so the
# steps that decide whether a fix exists can actually see it.
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
# This is a script rather than inline YAML for the same reason
# pick-fuzz-artifact.sh is: logic that only runs inside a live daily
# workflow run cannot be tested there, and the previous three bugs in
# this area all hid in inline YAML. Covered by
# tools/ci/test-stage-autofix-changes.sh.
#
# What gets staged:
#
#   * every tracked modification and deletion (`git add -u`);
#   * newly created files under a source root, because a fix that adds
#     a regression test or a new module is otherwise invisible to the
#     index while still being present for `make instar` and
#     `make test-container-core` -- which would verify green and then
#     commit a branch that does not compile.
#
# What does not, and why it is not `git add -A`: untracked files outside
# the source roots, and editor/merge artifacts (`*~`, `*.orig`, `*.rej`,
# ...) anywhere. Those are the temp files the original comment was
# guarding against, plus edits under .github/workflows/, which cannot be
# pushed with the token the workflow has. They are reported rather than
# silently dropped, so a
# failure report shows what was left behind, and separately so a reader
# can tell why a path was left. New files matching a .gitignore rule are
# reported too, loudly: git hides them from the untracked listing
# entirely, so before that pass they were dropped without a trace.
#
# Usage:
#   tools/ci/stage-autofix-changes.sh [--tracked-only] [REPO_DIR]
#
# --tracked-only stages tracked modifications and nothing else. It is
# for call sites downstream of the complexity guardrail: staging a new
# file there would commit it into the PR without it ever having been
# counted against the 3-file limit or the cross-crate check. The
# per-attempt call sites run upstream of those gates and take the full
# behaviour.
#
# REPO_DIR defaults to the current directory; the script then works from
# the top level of whatever work tree it names, so the source roots mean
# the same thing whichever subdirectory a caller happens to be in.
#
# Always exits 0 on a well-formed tree, including a tree with nothing to
# stage: "Claude changed nothing" is a state the caller decides about,
# not an error here.

set -euo pipefail

usage() { echo "usage: $0 [--tracked-only] [REPO_DIR]"; }

TRACKED_ONLY=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --tracked-only) TRACKED_ONLY=true; shift ;;
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
# relative to the cwd, so without this the source roots would anchor at
# REPO_DIR while the staging did not -- two different notions of "root"
# in one run, and `REPO_DIR=src` would match src/tests/ as `^tests/`.
cd "$(git rev-parse --show-toplevel)"

# Directories a fix is allowed to create files in. Anchored at the repo
# root, so a stray `report.md` at the top level is not swept up.
SOURCE_ROOTS='^(src|tests|docs|crates|tools|scripts)/'

# Editor backups, merge leftovers and scratch files. .gitignore already
# covers *.swp/*.swo and build output; this catches the rest, including
# inside the source roots where the path filter alone would let them
# through.
ARTIFACT_NAMES='(^|/)(\.#[^/]*|[^/]*~|[^/]*\.(orig|rej|bak|tmp|swp|swo))$'

# `git push` with the GITHUB_TOKEN actions/checkout persists is refused
# for any commit touching .github/workflows/; the `workflows` scope it
# needs cannot be granted through the workflow's `permissions:` key. So
# a staged workflow edit does not fail here, it fails two hours later
# at the push, after the build and the test run. Excluded and reported
# rather than staged. Moot before this script existed, because nothing
# was ever staged at all.
WORKFLOW_EDITS=()
while IFS= read -r -d '' FILE; do
    WORKFLOW_EDITS+=("${FILE}")
done < <(git diff --name-only -z -- '.github/workflows/')

# Tracked modifications and deletions.
git add -u -- . ':(exclude).github/workflows/'

STAGED_NEW=()
SKIPPED_ARTIFACT=()
SKIPPED_OUTSIDE=()
IGNORED=()

if [ "${TRACKED_ONLY}" = false ]; then
    while IFS= read -r -d '' FILE; do
        if [[ "${FILE}" =~ ${ARTIFACT_NAMES} ]]; then
            SKIPPED_ARTIFACT+=("${FILE}")
        elif [[ "${FILE}" =~ ${SOURCE_ROOTS} ]]; then
            STAGED_NEW+=("${FILE}")
        else
            SKIPPED_OUTSIDE+=("${FILE}")
        fi
    done < <(git ls-files --others --exclude-standard -z)

    # `--exclude-standard` hides gitignored paths completely, so
    # without this pass a new file matching an ignore rule is neither
    # staged nor mentioned. `**/*.bin` is in .gitignore and is exactly
    # what a fuzz-crash regression fixture would be called, so the
    # build would go green against a working tree holding the fixture
    # and then commit a branch without it -- the failure this script
    # exists to prevent, arrived at silently. Not staged (that would
    # sweep in build output); reported, so it is visible in the log and
    # in claude-changes-N.txt.
    #
    # `--directory` collapses a wholly-ignored directory to one entry,
    # which is what keeps src/target/ from flooding the report. Those
    # entries are reported, NOT skipped: src/fuzz/.gitignore ignores
    # `corpus/` and `artifacts/` as whole directories, and a fuzz-crash
    # input is more likely to land there than anywhere else. An earlier
    # version dropped every collapsed directory to keep the output
    # tidy and reopened the exact hole this pass exists to close. A
    # couple of dozen predictable lines per run -- the guest operation
    # `*.bin` files and the collapsed target/ trees, if Claude has run
    # `make instar` -- is the price of never silently dropping one. Do
    # not add a denylist to tidy that up without a way to tell build
    # output from a file Claude created; the last attempt to make this
    # block tidier is what reopened the hole.
    while IFS= read -r -d '' FILE; do
        if [[ "${FILE}" =~ ${ARTIFACT_NAMES} ]]; then
            # An editor leftover that also matches an ignore rule is
            # routine junk, not a lost fix. Keeping it out of the loud
            # heading is what stops a reader skimming past the line
            # that matters.
            SKIPPED_ARTIFACT+=("${FILE}")
        elif [[ "${FILE}" =~ ${SOURCE_ROOTS} ]]; then
            IGNORED+=("${FILE}")
        fi
    done < <(git ls-files --others --ignored --exclude-standard --directory -z)
fi

if [ ${#STAGED_NEW[@]} -gt 0 ]; then
    git add -- "${STAGED_NEW[@]}"
    echo "Staged ${#STAGED_NEW[@]} newly created file(s):"
    printf '    %s\n' "${STAGED_NEW[@]}"
fi

if [ ${#SKIPPED_ARTIFACT[@]} -gt 0 ]; then
    echo "Left ${#SKIPPED_ARTIFACT[@]} editor or merge artifact(s) unstaged:"
    printf '    %s\n' "${SKIPPED_ARTIFACT[@]}"
fi

if [ ${#SKIPPED_OUTSIDE[@]} -gt 0 ]; then
    echo "Left ${#SKIPPED_OUTSIDE[@]} untracked file(s) outside a source root unstaged:"
    printf '    %s\n' "${SKIPPED_OUTSIDE[@]}"
fi

if [ ${#WORKFLOW_EDITS[@]} -gt 0 ]; then
    echo "NOT staged, a commit touching these cannot be pushed with GITHUB_TOKEN:"
    printf '    %s\n' "${WORKFLOW_EDITS[@]}"
fi

if [ ${#IGNORED[@]} -gt 0 ]; then
    echo "Ignored by .gitignore, NOT staged, will NOT reach the pull request:"
    printf '    %s\n' "${IGNORED[@]}"
fi

if [ -z "$(git diff --cached --name-only)" ]; then
    echo "Nothing staged: no tracked file was modified and no new source file was created."
fi
