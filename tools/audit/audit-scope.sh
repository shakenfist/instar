#!/usr/bin/env bash
# audit-scope.sh -- shared file-scope resolution for the push-audit
# mechanical scripts (wave1.sh, wave2-mechanical.sh).
#
# Every diff-scoped check in both scripts used to compute its file
# set directly from `git diff develop...HEAD`. That is correct for
# ordinary pre-push use, where HEAD is the tip of a branch about to
# be pushed. It is wrong on a push-audit branch, where the phases
# under audit have already merged into develop and the branch being
# audited carries little or none of the work itself -- the range is
# then small or empty, and an empty range reads exactly like a clean
# audit. See docs/plans/PLAN-differencing-phase-18-push-audit.md,
# "The audit scripts would have audited nothing".
#
# This file is meant to be sourced, not executed. Usage, from either
# script, immediately after `cd` to the repo root:
#
#   # shellcheck source=tools/audit/audit-scope.sh
#   source "$SCRIPT_DIR/audit-scope.sh"
#   audit_scope_init "$@"
#   audit_scope_report
#
# audit_scope_init consumes two mutually exclusive options from the
# calling script's own argv:
#
#   --range REV..REV / REV...REV   -- use `git diff <range>` as the
#                                      scope.
#   --commits-file PATH            -- PATH holds one commit per line
#                                      (blank lines and `#` comments
#                                      ignored); the scope is the
#                                      UNION over those commits of
#                                      each commit's diff against its
#                                      first parent (`git diff
#                                      <sha>^1 <sha>`). This is not
#                                      only for merge commits -- a
#                                      phase that landed as a direct
#                                      push records an ordinary
#                                      single-parent commit (or a
#                                      first..last range of them) the
#                                      same way, and `^1` is exactly
#                                      the right diff for one of
#                                      those too. It matters most for
#                                      a merge commit specifically
#                                      because a plain `git show` of
#                                      one shows nothing useful.
#
# With neither option, the scope is literally `develop...HEAD`,
# unchanged from before this file existed -- this is the one
# constraint every change here is built around.
#
# A bad invocation (both options given, a --range that does not
# parse or resolve, a --commits-file that does not exist, or a
# commit in it that does not resolve or is a root commit with no
# parent to diff against) exits the whole process with exit code 9
# and a message naming the problem -- there is no sane way to keep
# running with an ambiguous scope.
#
# An empty or unresolvable scope has two outcomes, and which one
# applies turns on who asserted the scope. Both are implemented and
# argued for above audit_scope_init and audit_scope_report rather than
# restated here: in summary, an empty EXPLICIT scope exits 9, while an
# empty or unresolvable implicit default warns, sets
# AUDIT_SCOPE_SKIP_SCOPED and lets the unscoped checks run.
#
# After a successful audit_scope_init, six functions read the
# resolved scope. Each takes zero or more PATHSPEC arguments; an
# empty pathspec list means "no path restriction". In default/range
# mode every one of these is a single `git diff` call with the same
# arguments the original inline checks used, so the default path is
# byte-for-byte the same command as before. In --commits-file mode
# each loops over the commit list and concatenates (de-duplicating
# names, where de-duplication is meaningful):
#
#   audit_scope_names_null PATHSPEC...
#       NUL-delimited file names (any status), for a check piping
#       into `xargs -0`.
#   audit_scope_names_all [PATHSPEC...]
#       Newline-delimited file names (any status).
#   audit_scope_names_added [PATHSPEC...]
#       Newline-delimited file names added (--diff-filter=A). A file
#       added in one commit of a --commits-file union counts as
#       added even if a later commit in the union modified it.
#   audit_scope_diff [PATHSPEC...]
#       Concatenated `git diff` content (unified diff, additions and
#       removals), for checks that grep added lines rather than file
#       names.
#   audit_scope_names_existing [PATHSPEC...]
#       As audit_scope_names_all, less the paths that are not regular
#       files in the worktree now.
#   audit_scope_names_existing_null [PATHSPEC...]
#       The same, NUL-delimited.
#
# **A check that opens the files must use one of the two `_existing`
# readers.** The scope legitimately names paths that are not there --
# a file deleted by an audited commit, or by a later commit outside
# the scope -- and handing those to grep or awk produces an error per
# path. The two checks that did that silenced it with 2>/dev/null,
# which silenced every other error those tools could raise along with
# it. The plain `names_*` readers are for counting and for filtering
# names, not for reading content.
#
# audit_scope_report prints the "audit scope: N files (...)" banner,
# naming how many of those files are not on disk, and enforces the
# non-empty rule above.

AUDIT_SCOPE_EXIT_CODE=9

# _audit_scope_git_diff -- git diff, with every setting that would change the
# shape of what the readers below parse pinned to its default.
#
# A user's or system's git config is not under this library's control,
# and several settings silently change diff output rather than failing:
# `color.diff = always` wraps every line in ANSI escapes, so a `^+`
# grep matches nothing and the awk sees no markers; `diff.external` or
# a textconv driver replaces the patch with something else entirely;
# `diff.noprefix` or `diff.mnemonicPrefix` changes the `a/` and `b/`
# the awk strips, so paths come out mangled. Each of those makes the
# audit report less than it examined without raising an error --
# the failure mode this whole library exists to remove -- and each is
# a one-flag fix, so they are all pinned here rather than trusted.
#
# core.quotePath=false keeps a non-ASCII path readable instead of
# C-quoted; a path with an embedded tab or newline stays quoted, which
# diff-added-lines.awk reports as-is.
# The flags go immediately after the subcommand, never at the end: a
# caller's last arguments are pathspecs behind a `--`, and anything
# after that separator is a path, not an option.
_audit_scope_git_diff() {
    git \
        -c color.ui=never \
        -c color.diff=never \
        -c diff.external= \
        -c diff.noprefix=false \
        -c diff.mnemonicPrefix=false \
        -c core.quotePath=false \
        diff --no-color --no-ext-diff --no-textconv "$@"
}

_audit_scope_die() {
    echo "audit scope error: $*" >&2
    exit "${AUDIT_SCOPE_EXIT_CODE}"
}

_audit_scope_trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# audit_scope_init "$@" -- parse options, validate, and set:
#   AUDIT_SCOPE_MODE          "range" or "commits"
#   AUDIT_SCOPE_RANGE         the range string, when MODE=range
#   AUDIT_SCOPE_COMMITS       array of commit SHAs, when MODE=commits
#   AUDIT_SCOPE_DESC          human-readable description for the banner
#   AUDIT_SCOPE_EXPLICIT      1 if --range or --commits-file was given,
#                             0 for the implicit develop...HEAD default
#   AUDIT_SCOPE_SKIP_SCOPED   1 only for the implicit default when
#                             `develop` does not resolve; 0 otherwise.
#                             audit_scope_report may also set this to
#                             1 (never init) when the implicit default
#                             resolves to zero files.
audit_scope_init() {
    AUDIT_SCOPE_MODE="range"
    AUDIT_SCOPE_RANGE="develop...HEAD"
    AUDIT_SCOPE_COMMITS=()
    AUDIT_SCOPE_EXPLICIT=0
    AUDIT_SCOPE_SKIP_SCOPED=0
    local range_given="" commits_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --range)
                [[ $# -ge 2 ]] || _audit_scope_die "--range needs an argument"
                range_given="$2"
                shift 2
                ;;
            --range=*)
                range_given="${1#--range=}"
                shift
                ;;
            --commits-file)
                [[ $# -ge 2 ]] || _audit_scope_die "--commits-file needs an argument"
                commits_file="$2"
                shift 2
                ;;
            --commits-file=*)
                commits_file="${1#--commits-file=}"
                shift
                ;;
            *)
                _audit_scope_die "unknown option: $1"
                ;;
        esac
    done

    if [[ -n "$range_given" && -n "$commits_file" ]]; then
        _audit_scope_die "--range and --commits-file are mutually exclusive"
    fi

    if [[ -n "$range_given" ]]; then
        # A value beginning with "-" is parsed by git as an option, not
        # a revision, so `--range --output=/tmp/x..y` would reach
        # `git diff` as a real option and write a file. Nothing
        # legitimate starts with "-", so refuse rather than try to
        # escape it; `git diff -- <path>` separators do not help, since
        # the problem value sits where git expects a revision.
        case "$range_given" in
            -*) _audit_scope_die "--range must not start with '-' (it would be read as a git option): $range_given" ;;
        esac
        case "$range_given" in
            *..*) ;;
            *) _audit_scope_die "--range must look like REV..REV or REV...REV, got: $range_given" ;;
        esac
        local range_err
        if ! range_err="$(_audit_scope_git_diff --name-only "$range_given" 2>&1 >/dev/null)"; then
            _audit_scope_die "--range does not resolve ($range_given): ${range_err}"
        fi
        AUDIT_SCOPE_MODE="range"
        AUDIT_SCOPE_RANGE="$range_given"
        AUDIT_SCOPE_DESC="--range $range_given"
        AUDIT_SCOPE_EXPLICIT=1
        return 0
    fi

    if [[ -n "$commits_file" ]]; then
        [[ -f "$commits_file" ]] || _audit_scope_die "--commits-file not found: $commits_file"
        AUDIT_SCOPE_MODE="commits"
        local line sha
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="$(_audit_scope_trim "$line")"
            [[ -z "$line" ]] && continue
            sha="$line"
            # Same reasoning as --range above: a commit named in the
            # file is interpolated into `git diff` where a revision is
            # expected, so an option-shaped entry must not get there.
            case "$sha" in
                -*) _audit_scope_die "commit must not start with '-' (it would be read as a git option): $sha (from $commits_file)" ;;
            esac
            git rev-parse --verify "${sha}^{commit}" >/dev/null 2>&1 \
                || _audit_scope_die "commit does not resolve: $sha (from $commits_file)"
            git rev-parse --verify "${sha}^1" >/dev/null 2>&1 \
                || _audit_scope_die "commit has no parent to diff against (it is the root commit): $sha (from $commits_file)"
            AUDIT_SCOPE_COMMITS+=("$sha")
        done < "$commits_file"
        if [[ ${#AUDIT_SCOPE_COMMITS[@]} -eq 0 ]]; then
            _audit_scope_die "no commits found in $commits_file"
        fi
        AUDIT_SCOPE_DESC="--commits-file $commits_file"
        AUDIT_SCOPE_EXPLICIT=1
        return 0
    fi

    # Implicit default: develop...HEAD. Preserve the original, lenient
    # behaviour for an unresolvable `develop` (e.g. a shallow CI
    # clone) -- every scoped check used to skip itself silently in
    # that case, and nothing here is allowed to turn that into a hard
    # failure for ordinary pre-push use.
    #
    # The ref resolving is not enough on its own. In a shallow clone
    # the `develop` ref can exist while its history does not, and then
    # `git diff develop...HEAD` fails ("fatal: develop...HEAD: no
    # merge base", exit 128) rather than returning an empty set. The
    # readers below would report zero files for that, and
    # audit_scope_report would print "nothing to audit" -- a git
    # failure rendered as a clean result, which is the exact defect
    # this library exists to stop. So require the merge-base too, and
    # treat its absence as "unresolved" rather than as "empty".
    if ! git rev-parse --verify develop >/dev/null 2>&1 \
        || ! git merge-base develop HEAD >/dev/null 2>&1; then
        AUDIT_SCOPE_SKIP_SCOPED=1
    fi
    AUDIT_SCOPE_DESC="develop...HEAD"
}

# audit_scope_report -- print the scope banner; call once, before any
# check runs.
#
# An empty EXPLICIT scope (--range/--commits-file) exits 9: the
# caller asserted a scope and got it wrong. An empty IMPLICIT scope
# (the develop...HEAD default) is not an error -- it is what "no
# changes against develop" looks like -- so it prints a warning and
# sets AUDIT_SCOPE_SKIP_SCOPED instead, same as the develop-unresolved
# case, so the caller's unscoped checks (build, lint, test suite)
# still run.
audit_scope_report() {
    if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 1 ]]; then
        echo "audit scope: unresolved (develop ref not found; diff-scoped checks will be skipped)"
        return 0
    fi
    # One listing, two numbers. In commits mode each listing is a
    # git diff per audited commit, so asking twice doubled that for no
    # reason -- and, more to the point, left the total and the deleted
    # tally free to disagree if the worktree changed between them.
    local names count deleted name
    names="$(audit_scope_names_all)"
    count="$(printf '%s' "$names" | grep -c . || true)"
    # -e for "gone", then -f for "readable as a file": a path that
    # exists but is not a regular file (a submodule gitlink, a symlink
    # to a directory) is excluded from the content checks just as a
    # deleted one is, but it has not been deleted, and reporting it as
    # such would be the banner telling a small lie about the tree.
    deleted=0
    local nonregular=0
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        if [[ ! -e "$name" ]]; then
            deleted=$((deleted + 1))
        elif [[ ! -f "$name" ]]; then
            nonregular=$((nonregular + 1))
        fi
    done <<< "$names"
    local note="" unreadable=$((deleted + nonregular))
    if [[ "$deleted" -gt 0 ]]; then
        note="; ${deleted} no longer on disk"
    fi
    if [[ "$nonregular" -gt 0 ]]; then
        note="${note:+${note},}${note:-;} ${nonregular} not a regular file"
    fi
    if [[ -n "$note" ]]; then
        note="${note}, so content checks read ${count} minus ${unreadable}"
    fi
    echo "audit scope: ${count} files (${AUDIT_SCOPE_DESC})${note}"
    if [[ "$count" -eq 0 ]]; then
        if [[ "$AUDIT_SCOPE_EXPLICIT" -eq 1 ]]; then
            _audit_scope_die "resolved file set is empty for ${AUDIT_SCOPE_DESC} -- nothing to audit"
        fi
        echo "WARNING: nothing to audit; the diff-scoped checks below will report nothing (no diff against ${AUDIT_SCOPE_DESC})"
        AUDIT_SCOPE_SKIP_SCOPED=1
    fi
}

audit_scope_names_null() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            _audit_scope_git_diff -z --name-only "${sha}^1" "$sha" -- "$@"
        done | sort -z -u
    else
        _audit_scope_git_diff -z --name-only "$AUDIT_SCOPE_RANGE" -- "$@"
    fi
}

# The optional-PATHSPEC signature documented in the header is
# deliberate, but a single-file lint cannot see it: the only in-file
# call is audit_scope_report's zero-arg one, from which shellcheck
# concludes this function never needs arguments (SC2120) and that the
# call should pass "$@" (SC2119). The callers that pass pathspecs are
# wave1.sh, wave2-mechanical.sh and test-audit-scope.sh, which it has
# no visibility into. The other readers have no in-file caller at all,
# so there is no zero-arg call site for the lint to reason from and it
# raises nothing for them -- the asymmetry is the one caller, not a
# difference in the functions' shapes.
# shellcheck disable=SC2120  # see above; pathspec callers are in the wave scripts
audit_scope_names_all() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                _audit_scope_git_diff --name-only "${sha}^1" "$sha" -- "$@"
            else
                _audit_scope_git_diff --name-only "${sha}^1" "$sha"
            fi
        done | sort -u
    else
        if [[ $# -gt 0 ]]; then
            _audit_scope_git_diff --name-only "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            _audit_scope_git_diff --name-only "$AUDIT_SCOPE_RANGE"
        fi
    fi
}

# The scope is "every file the audited commits touched", which
# deliberately includes files they deleted -- that is the honest count
# of what was changed, and audit_scope_report keeps reporting it. A
# check that opens files cannot use that list directly, though: in
# commits mode a path deleted by one of the audited commits, or by a
# later commit outside the scope, no longer exists in the worktree.
# Feeding it to grep or awk produced a "No such file or directory" that
# the callers then silenced with 2>/dev/null -- which also silenced
# every other error those tools could raise. These two readers filter
# to what is actually on disk so the silencing is unnecessary, and the
# errors that remain are real.
audit_scope_names_existing() {
    local name
    while IFS= read -r name; do
        [[ -f "$name" ]] && printf '%s\n' "$name"
    done < <(audit_scope_names_all "$@")
}

audit_scope_names_existing_null() {
    local name
    while IFS= read -r -d '' name; do
        [[ -f "$name" ]] && printf '%s\0' "$name"
    done < <(audit_scope_names_null "$@")
}

audit_scope_names_added() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                _audit_scope_git_diff --name-only --diff-filter=A "${sha}^1" "$sha" -- "$@"
            else
                _audit_scope_git_diff --name-only --diff-filter=A "${sha}^1" "$sha"
            fi
        done | sort -u
    else
        if [[ $# -gt 0 ]]; then
            _audit_scope_git_diff --name-only --diff-filter=A "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            _audit_scope_git_diff --name-only --diff-filter=A "$AUDIT_SCOPE_RANGE"
        fi
    fi
}

audit_scope_diff() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                _audit_scope_git_diff "${sha}^1" "$sha" -- "$@"
            else
                _audit_scope_git_diff "${sha}^1" "$sha"
            fi
        done
    else
        if [[ $# -gt 0 ]]; then
            _audit_scope_git_diff "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            _audit_scope_git_diff "$AUDIT_SCOPE_RANGE"
        fi
    fi
}
