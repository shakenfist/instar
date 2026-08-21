#!/usr/bin/env bash
#
# Abandon whatever a Claude Code autofix attempt left behind, so the
# next attempt's commit contains only its own work.
#
# tools/address-comments-with-claude.sh walks a review item at a time
# and commits each one separately. Every path that gives up on an item
# has to call this: without it, edits from an item Claude failed on or
# disagreed with survive into the next item, are staged on that item's
# behalf, and get committed under that item's review id and rationale.
#
# That leak only became reachable when CI started staging for Claude
# (issue #510). The old reset was a bare `git checkout -- .`, which
# restores tracked files but leaves the index alone -- harmless while
# nothing but Claude ever staged anything, and wrong the moment
# something did.
#
# Three things have to go, and each needs its own command:
#
#   * staged edits -- `git reset HEAD`, which also turns a new file
#     Claude staged back into an untracked one so the clean below can
#     remove it;
#   * unstaged edits to tracked files -- `git checkout`;
#   * files the attempt created -- `git clean -fd`.
#
# `git clean` deliberately has no -x. Ignored build output is expensive
# to recreate -- src/target/ is the whole Rust build -- and it is not
# what leaks between items, because nothing stages an ignored path.
#
# This is a script rather than a function inside the caller for the
# same reason stage-autofix-changes.sh is a script: it only ever runs
# inside a privileged issue_comment workflow that a maintainer triggers
# by hand, so nothing exercises it unless a test does. #510 was a bug
# of exactly that shape, unobserved for months.

set -euo pipefail

usage() {
    cat <<'EOF'
usage: reset-autofix-worktree.sh [REPO_DIR]

Discard staged edits, unstaged edits and newly created files in
REPO_DIR (default: the current directory), leaving ignored build
output alone.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
esac

REPO_DIR="${1:-.}"

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

if [ ! -d "${REPO_DIR}" ]; then
    echo "reset-autofix-worktree: ${REPO_DIR} does not exist" >&2
    exit 2
fi

cd "${REPO_DIR}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "reset-autofix-worktree: ${REPO_DIR} is not a git work tree" >&2
    exit 2
fi

# All three commands below are scoped to the cwd. The stager anchors
# itself at the top level before `git add -u`, and the caller's index
# check (`git diff --cached --name-only`) is repo-wide whatever the
# cwd, so a REPO_DIR pointing at a subdirectory would leave the three
# disagreeing: an edit outside the subdirectory gets staged, is seen as
# a change, and is not cleaned up -- the leak this script exists to
# prevent.
cd "$(git rev-parse --show-toplevel)"

git reset -q HEAD -- . 2>/dev/null || true
git checkout -- . 2>/dev/null || true
git clean -qfd 2>/dev/null || true
