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
# An EXPLICIT scope (--range or --commits-file) that resolves to zero
# files is treated the same way: the caller asserted a scope and got
# it wrong, so audit_scope_report exits 9 for that too -- that is not
# a finding, it is a broken invocation. The IMPLICIT default
# (develop...HEAD, no option given) is different: an empty result
# there legitimately means "no changes against develop" -- the
# ordinary state right after a push, or on a branch whose own work
# has already merged -- and failing the whole pre-push gate over that
# would block the unscoped checks (pre-commit, the build, the test
# suite) that do not care about the diff at all. So in that one case
# audit_scope_report prints a warning instead of exiting, and the
# diff-scoped checks skip themselves exactly as they do when `develop`
# itself does not resolve (next paragraph) -- both are surfaced to
# callers via AUDIT_SCOPE_SKIP_SCOPED.
#
# The other case that does NOT exit is the one this script inherits
# from both callers' original guards: if no option is given and
# `develop` does not resolve (e.g. a shallow clone in CI), the
# default scope is left unresolved and audit_scope_report says so
# without erroring. Checks that need the scope skip themselves via
# AUDIT_SCOPE_SKIP_SCOPED, exactly as they skipped themselves before
# this file existed.
#
# After a successful audit_scope_init, four functions read the
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
#
# audit_scope_count prints the number of distinct files in the whole
# scope (no path restriction); audit_scope_report prints the
# "audit scope: N files (...)" banner from it and enforces the
# non-empty rule above.

AUDIT_SCOPE_EXIT_CODE=9

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
        case "$range_given" in
            *..*) ;;
            *) _audit_scope_die "--range must look like REV..REV or REV...REV, got: $range_given" ;;
        esac
        local range_err
        if ! range_err="$(git diff --name-only "$range_given" 2>&1 >/dev/null)"; then
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
    if ! git rev-parse --verify develop >/dev/null 2>&1; then
        AUDIT_SCOPE_SKIP_SCOPED=1
    fi
    AUDIT_SCOPE_DESC="develop...HEAD"
}

# audit_scope_count -- number of distinct files in the whole scope.
#
# This is the only call, anywhere in this file, to one of the four
# scope-reading functions with no pathspec. A single-file lint sees
# that call and concludes (SC2119/SC2120) that audit_scope_names_all
# never needs arguments at all -- it has no visibility into
# wave1.sh, wave2-mechanical.sh or test-audit-scope.sh, which are the
# files that actually call it (and the other three functions below)
# with pathspecs. That is a false positive: the optional-PATHSPEC
# signature documented above is deliberate, so both findings are
# disabled with a reason rather than restructured.
# audit_scope_names_null, audit_scope_names_added and audit_scope_diff
# have no internal caller in this file at all, so the lint has no
# zero-arg call site to reason from here and raises nothing for them
# -- the asymmetry is this one caller, not a difference in the
# functions' shapes.
# shellcheck disable=SC2119  # no pathspec: whole-scope, by design
audit_scope_count() {
    audit_scope_names_all | grep -c .
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
    local count
    count="$(audit_scope_count)"
    echo "audit scope: ${count} files (${AUDIT_SCOPE_DESC})"
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
            git diff -z --name-only "${sha}^1" "$sha" -- "$@"
        done | sort -z -u
    else
        git diff -z --name-only "$AUDIT_SCOPE_RANGE" -- "$@"
    fi
}

# shellcheck disable=SC2120  # called with pathspecs from wave1.sh/wave2-mechanical.sh/test-audit-scope.sh; audit_scope_count's zero-arg call above is this file's only caller
audit_scope_names_all() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                git diff --name-only "${sha}^1" "$sha" -- "$@"
            else
                git diff --name-only "${sha}^1" "$sha"
            fi
        done | sort -u
    else
        if [[ $# -gt 0 ]]; then
            git diff --name-only "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            git diff --name-only "$AUDIT_SCOPE_RANGE"
        fi
    fi
}

audit_scope_names_added() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                git diff --name-only --diff-filter=A "${sha}^1" "$sha" -- "$@"
            else
                git diff --name-only --diff-filter=A "${sha}^1" "$sha"
            fi
        done | sort -u
    else
        if [[ $# -gt 0 ]]; then
            git diff --name-only --diff-filter=A "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            git diff --name-only --diff-filter=A "$AUDIT_SCOPE_RANGE"
        fi
    fi
}

audit_scope_diff() {
    if [[ "$AUDIT_SCOPE_MODE" == "commits" ]]; then
        local sha
        for sha in "${AUDIT_SCOPE_COMMITS[@]}"; do
            if [[ $# -gt 0 ]]; then
                git diff "${sha}^1" "$sha" -- "$@"
            else
                git diff "${sha}^1" "$sha"
            fi
        done
    else
        if [[ $# -gt 0 ]]; then
            git diff "$AUDIT_SCOPE_RANGE" -- "$@"
        else
            git diff "$AUDIT_SCOPE_RANGE"
        fi
    fi
}
