#!/usr/bin/env bash
#
# source-size.sh -- the push auditor's by-hand stand-in for the
# source-size ratchet.
#
# PUSH-AUDIT.md's source-file-size block says a file over 1,500 lines
# may stay that long but may not grow, that no file may cross 1,500,
# and that growth of a file already over 800 lines is raised too. A
# repository that has adopted shakenfist/development's
# source-size-ratchet checks that on every commit against a baseline
# file; instar has not, so the auditor applies the rule by hand and
# this script does the counting.
#
# The scope is audit-scope.sh's, so --commits-file means here what it
# means everywhere else in the audit: on a push-audit branch the phases
# under review have already merged, and a range computed from the
# branch alone would see none of them. Every way this script can fail
# to measure -- an unresolved scope, a diff or count that errors -- is
# printed as such. None of them may come out as "(none)", because that
# is what a clean result looks like.
#
# Usage:
#   tools/audit/source-size.sh --baseline [LINES]
#       Every tracked source file over LINES lines (default 1500),
#       longest first. Whole tree, not scoped: this is the baseline the
#       ratchet would otherwise keep in a file.
#   tools/audit/source-size.sh [--range REV..REV | --commits-file PATH]
#       The findings: every source file the audit scope grows that is
#       over 800 lines now, with its length and its net growth across
#       the scope. wave2-mechanical.sh runs this for you.
#
# When sourced, defines source_size_growth for wave2-mechanical.sh,
# which has already resolved the scope.

# What counts as source is every tracked file except the formats that
# are not, rather than a list of languages: a new language is then in
# scope the day it is committed, and a new data format shows up as
# noise in the output rather than going missing from it. That is also
# why this list is the thing to revisit when a new tracked format
# lands: a generated artefact or a binary fixture belongs here, under
# the block's exemption for generated files and data tables. Workflow
# YAML stays in: it carries real logic and is reviewed as such.
# prototypes/ is out because AGENTS.md calls it reference material
# rather than shipped code. Build output under target/, the vendored crates under
# .cargo-cache/ and Cargo.lock are gitignored, so they are never
# tracked and need no entry.
SOURCE_SIZE_PATHSPECS=(
    ':(top,exclude)prototypes/'
    ':(top,exclude)*.md'
    ':(top,exclude)*.toml'
    ':(top,exclude)*.json'
    ':(top,exclude)*.txt'
)

SOURCE_SIZE_SPLIT=800
SOURCE_SIZE_RATCHET=1500

# _source_size_diff -- the scope's diff, restricted to source, with
# rename detection forced on. A pure move of an oversize file is not
# growth, and without -M a user's diff.renames=false would make it read
# as a new file the length of the old one. Same loop as scope-patch.sh,
# through the library's wrapper so colour, external diff drivers and
# prefix settings cannot change the patch's shape. Fails if any one
# diff fails, not only the last.
_source_size_diff() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            _audit_scope_git_diff -M "${sha}^1" "$sha" -- "${SOURCE_SIZE_PATHSPECS[@]}" || return 1
        done
    else
        _audit_scope_git_diff -M "$AUDIT_SCOPE_RANGE" -- "${SOURCE_SIZE_PATHSPECS[@]}"
    fi
}

# _source_size_count PATH -- PATH's line count, or an error line and a
# non-zero status. Called inside a pipeline stage, so the caller's
# pipefail is what carries the failure out.
_source_size_count() {
    local n
    if ! n=$(wc -l < "$1"); then
        echo "error: could not count the lines in $1"
        return 1
    fi
    printf '%s' "$n"
}

# source_size_growth -- print one line per finding, longest first;
# "(none)" with the reason when there is genuinely nothing; or a
# "skipped" or "error" line, and a non-zero status for an error.
# Requires audit_scope_init to have run.
#
# Growth is the net of lines added and removed across the whole scope,
# summed per path. `git apply --numstat` does the counting because it
# parses the patch's structure rather than its line prefixes, so an
# added line whose content begins "++" is not mistaken for a header.
# It refuses an empty patch, which is why a scope that touches no
# source is answered before it is called. In commits mode the sum is
# over the audited commits only, so a file that unrelated work grew
# between two phases is not charged to this one. A binary file's
# numstat is "-" for both counts, which nets to zero and so never
# reaches the findings. A path the scope grew but that is gone from
# the worktree has nothing left to review.
source_size_growth() {
    # Scoped to this function: wave2-mechanical.sh sources it and runs
    # without pipefail, and a failed stage must not read as no output.
    local -
    set -o pipefail

    if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 1 ]]; then
        echo "skipped: no scope to measure growth against -- this is not a clean result"
        return 0
    fi

    local patch findings
    if ! patch=$(_source_size_diff); then
        echo "error: could not compute the scope's diff -- this is not a clean result"
        return 2
    fi
    if [[ -z "$patch" ]]; then
        echo "(none): the scope changes no file that counts as source"
        return 0
    fi

    if ! findings=$(
        printf '%s\n' "$patch" \
            | git apply --numstat -z \
            | awk -v RS='\0' -F'\t' '
                {
                    path = $3
                    for (i = 4; i <= NF; i++) path = path "\t" $i
                    net[path] += $1 - $2
                }
                # %c of 0 rather than "\0" in the format: mawk ends the
                # format string at an embedded NUL and drops it.
                END { for (p in net) if (net[p] > 0) printf "%d\t%s%c", net[p], p, 0 }
            ' \
            | while IFS=$'\t' read -r -d '' net path; do
                [[ -f "$path" ]] || continue
                now=$(_source_size_count "$path") || { echo "$now"; exit 1; }
                [[ "$now" -gt "$SOURCE_SIZE_SPLIT" ]] || continue
                verdict="over ${SOURCE_SIZE_SPLIT}: a question"
                if [[ "$now" -gt "$SOURCE_SIZE_RATCHET" ]]; then
                    verdict="over ${SOURCE_SIZE_RATCHET}: needs its reason in the pull request description"
                fi
                printf '%7d lines  +%d in scope  %s  (%s)\n' "$now" "$net" "$path" "$verdict"
            done \
            | sort -rn
    ); then
        printf '%s\n' "$findings" | grep '^error: '
        echo "error: could not measure growth across the scope -- this is not a clean result"
        return 2
    fi
    if [[ -n "$findings" ]]; then
        printf '%s\n' "$findings"
    else
        echo "(none)"
    fi
}

# source_size_baseline LINES -- every tracked source file over LINES,
# counted one file at a time so that no path is mistaken for wc's own
# "total" line. A tracked path that is not a regular file in the
# worktree (deleted, or a submodule) has no length to report.
source_size_baseline() {
    local -
    set -o pipefail
    local lines="$1"
    git ls-files -z -- "${SOURCE_SIZE_PATHSPECS[@]}" \
        | while IFS= read -r -d '' f; do
            [[ -f "$f" ]] || continue
            n=$(_source_size_count "$f") || { echo "$n" >&2; exit 1; }
            if [[ "$n" -gt "$lines" ]]; then
                printf '%7d %s\n' "$n" "$f"
            fi
        done \
        | sort -rn
}

_source_size_main() {
    set -u
    local script_dir repo_root
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd "$script_dir/../.." && pwd)"
    cd "$repo_root" || exit 6

    if [[ "${1:-}" == "--baseline" ]]; then
        local lines="${2:-$SOURCE_SIZE_RATCHET}"
        [[ "$lines" =~ ^[0-9]+$ ]] || { echo "--baseline takes a line count, not '$lines'" >&2; exit 9; }
        source_size_baseline "$lines" || exit 2
        exit 0
    fi

    # shellcheck source=tools/audit/audit-scope.sh
    source "$script_dir/audit-scope.sh"
    audit_scope_init "$@"
    audit_scope_report
    source_size_growth
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    _source_size_main "$@"
fi
