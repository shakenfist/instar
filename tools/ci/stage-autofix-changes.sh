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
# guarding against. They are reported rather than silently dropped, so a
# failure report shows what was left behind.
#
# Usage:
#   tools/ci/stage-autofix-changes.sh [REPO_DIR]
#
# REPO_DIR defaults to the current directory. Always exits 0 on a
# well-formed tree, including a tree with nothing to stage: "Claude
# changed nothing" is a state the caller decides about, not an error
# here.

set -euo pipefail

REPO_DIR="${1:-.}"

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [REPO_DIR]" >&2
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

# Directories a fix is allowed to create files in. Anchored at the repo
# root, so a stray `report.md` at the top level is not swept up.
SOURCE_ROOTS='^(src|tests|docs|crates|tools|scripts)/'

# Editor backups, merge leftovers and scratch files. .gitignore already
# covers *.swp/*.swo and build output; this catches the rest, including
# inside the source roots where the path filter alone would let them
# through.
ARTIFACT_NAMES='(^|/)(\.#[^/]*|[^/]*~|[^/]*\.(orig|rej|bak|tmp|swp|swo))$'

# Tracked modifications and deletions.
git add -u

STAGED_NEW=()
SKIPPED=()

while IFS= read -r -d '' FILE; do
    if [[ "${FILE}" =~ ${ARTIFACT_NAMES} ]]; then
        SKIPPED+=("${FILE}")
    elif [[ "${FILE}" =~ ${SOURCE_ROOTS} ]]; then
        git add -- "${FILE}"
        STAGED_NEW+=("${FILE}")
    else
        SKIPPED+=("${FILE}")
    fi
done < <(git ls-files --others --exclude-standard -z)

if [ ${#STAGED_NEW[@]} -gt 0 ]; then
    echo "Staged ${#STAGED_NEW[@]} newly created file(s):"
    printf '    %s\n' "${STAGED_NEW[@]}"
fi

if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo "Left ${#SKIPPED[@]} untracked file(s) unstaged:"
    printf '    %s\n' "${SKIPPED[@]}"
fi

if [ -z "$(git diff --cached --name-only)" ]; then
    echo "Nothing staged: no tracked file was modified and no new source file was created."
fi
