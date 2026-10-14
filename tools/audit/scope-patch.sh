#!/usr/bin/env bash
#
# Write the resolved audit scope to stdout as one patch.
#
# PUSH-AUDIT.md tells the management session to materialise the scope
# once and hand the same patch to all four judgment agents, rather than
# having each of them recompute it. This is that command. It exists as a
# script because the recipe the runbook carried in prose was wrong in a
# way that is easy to get wrong again: `git diff <merge>^1 <merge> >
# scope.patch` covers one merge, and run once per merge the `>`
# truncates, so only the last one survives -- an audit reading a subset
# of the work and reporting cleanly on it, which is the exact defect the
# scope library was written to stop.
#
# Usage: tools/audit/scope-patch.sh [--range REV..REV | --commits-file PATH] \
#            [-- PATHSPEC...] > scope.patch
#
# Options are the audit scope options; see audit-scope.sh, which is the
# authority on them. A `--` separator passes pathspecs through to the
# underlying git diff.
#
# In commits mode each audited commit's first-parent diff is emitted in
# the order the commits file lists them, each preceded by a comment line
# naming the commit, so a reader of the patch can tell which phase a
# hunk came from. Those lines begin with "#", which `git apply` rejects
# -- this is an artefact for reading, not for applying.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 6

# Split our own options from any trailing pathspecs.
SCOPE_ARGS=()
PATHSPECS=()
seen_sep=0
for arg in "$@"; do
    if [[ "$seen_sep" -eq 1 ]]; then
        PATHSPECS+=("$arg")
    elif [[ "$arg" == "--" ]]; then
        seen_sep=1
    else
        SCOPE_ARGS+=("$arg")
    fi
done

# shellcheck source=tools/audit/audit-scope.sh
source "$SCRIPT_DIR/audit-scope.sh"
audit_scope_init "${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"}"

# The banner goes to stderr: stdout is the patch, and a caller
# redirecting it must not find a human-readable line inside the diff.
audit_scope_report >&2

if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 1 ]]; then
    echo "refusing to write a patch for an unresolved or empty scope" >&2
    exit "$AUDIT_SCOPE_EXIT_CODE"
fi

if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
    for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
        git log -1 --format='# commit %H %s' "$sha"
        # The library's wrapper, not a bare `git diff`: a user's
        # color.diff, diff.external or diff.noprefix setting would
        # otherwise change the shape of the patch every judgment agent
        # reads. See _audit_scope_git_diff in audit-scope.sh.
        _audit_scope_git_diff "${sha}^1" "$sha" -- "${PATHSPECS[@]+"${PATHSPECS[@]}"}"
    done
else
    audit_scope_diff "${PATHSPECS[@]+"${PATHSPECS[@]}"}"
fi
