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
# It used to be two commands in a fence in PUSH-AUDIT.md. Shell in a
# runbook is not shellchecked, not tested and not shared with the wave
# scripts, and that copy computed its scope as
# `git merge-base origin/develop HEAD` -- which on a push-audit branch
# covers only the audit branch's own commits, and with no origin/develop
# printed nothing at all, both of which read as "no findings". The scope
# here is audit-scope.sh's, so --commits-file means what it means
# everywhere else in the audit, and an unresolved scope says so.
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
# noise rather than going missing. A list of languages has already gone
# stale once here (*.rs, *.py and *.sh left out the top-level Makefile),
# and a `find` rooted at src/ before it left out crates/ and scripts/.
# Workflow YAML stays in: it carries real logic and is reviewed as
# such. prototypes/ is out because AGENTS.md calls it reference
# material rather than shipped code. Build output under target/ and the
# vendored crates under .cargo-cache/ are gitignored, so they are never
# tracked and need no entry -- which is the block's exemption for
# generated and vendored trees.
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
# prefix settings cannot change the patch's shape.
_source_size_diff() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            _audit_scope_git_diff -M "${sha}^1" "$sha" -- "${SOURCE_SIZE_PATHSPECS[@]}"
        done
    else
        _audit_scope_git_diff -M "$AUDIT_SCOPE_RANGE" -- "${SOURCE_SIZE_PATHSPECS[@]}"
    fi
}

# source_size_growth -- print one line per finding, longest first, or
# "(none)". Requires audit_scope_init to have run.
#
# Growth is the net of lines added and removed across the whole scope,
# summed per path. `git apply --numstat` does the counting because it
# parses the patch's structure rather than its line prefixes, so an
# added line whose content begins "++" is not mistaken for a header.
# In commits mode the sum is over the audited commits only, so a file
# that unrelated work grew between two phases is not charged to this
# one. A binary file's numstat is "-" for both counts, which nets to
# zero and so never reaches the findings. A path the scope grew but
# that is gone from the worktree has nothing left to review.
source_size_growth() {
    local findings
    findings=$(
        _source_size_diff \
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
                local now
                now=$(wc -l < "$path")
                [[ "$now" -gt "$SOURCE_SIZE_SPLIT" ]] || continue
                local verdict="over ${SOURCE_SIZE_SPLIT}: a question"
                if [[ "$now" -gt "$SOURCE_SIZE_RATCHET" ]]; then
                    verdict="over ${SOURCE_SIZE_RATCHET}: needs its reason in the pull request description"
                fi
                printf '%7d lines  +%d in scope  %s  (%s)\n' "$now" "$net" "$path" "$verdict"
            done \
            | sort -rn
    )
    if [[ -n "$findings" ]]; then
        printf '%s\n' "$findings"
    else
        echo "(none)"
    fi
}

# source_size_baseline LINES -- every tracked source file over LINES.
source_size_baseline() {
    local lines="$1"
    git ls-files -z -- "${SOURCE_SIZE_PATHSPECS[@]}" \
        | xargs -0r wc -l \
        | awk -v n="$lines" '$1 > n && $2 != "total"' \
        | sort -rn
}

_source_size_main() {
    set -uo pipefail
    local script_dir repo_root
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd "$script_dir/../.." && pwd)"
    cd "$repo_root" || exit 6

    if [[ "${1:-}" == "--baseline" ]]; then
        local lines="${2:-$SOURCE_SIZE_RATCHET}"
        [[ "$lines" =~ ^[0-9]+$ ]] || { echo "--baseline takes a line count, not '$lines'" >&2; exit 9; }
        source_size_baseline "$lines"
        exit 0
    fi

    # shellcheck source=tools/audit/audit-scope.sh
    source "$script_dir/audit-scope.sh"
    audit_scope_init "$@"
    audit_scope_report
    if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 1 ]]; then
        echo "skipped: no scope to measure growth against -- this is not a clean result"
        exit 0
    fi
    source_size_growth
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    _source_size_main "$@"
fi
