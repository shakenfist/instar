#!/usr/bin/env bash
#
# Tests for tools/audit/source-size.sh, the push auditor's by-hand
# stand-in for the source-size ratchet.
#
# Every case runs against a throwaway fixture repository with its own
# copy of the audit tooling, so the script resolves the fixture as its
# repository root -- the same arrangement test-audit-scope.sh uses, and
# for the same reason: the ci-tooling job checks out at depth 1, and a
# case that needed this repository's history would skip there, which
# reads as a pass. Oracles are line counts the fixture writes, never a
# number copied from the real tree.
#
# The shapes the fixture holds, each of which the old in-runbook
# command got wrong or never saw:
#   * work that has already merged, audited with --commits-file -- the
#     old command diffed merge-base(origin/develop, HEAD)..HEAD and saw
#     only the audit branch's own commits;
#   * no develop branch at all -- the old command printed nothing,
#     which read as "no findings";
#   * a pure rename of an oversize file, which is not growth;
#   * an oversize file that shrank, which is not a finding, and one
#     whose lines were rewritten into fewer -- lines added, but a net
#     loss;
#   * a grown file under 800 lines, which is not a finding;
#   * excluded trees and formats (prototypes/, *.md) that grew;
#   * workflow YAML, which is source here and must be counted;
#   * a path with a space, a path with a tab, and an added line whose
#     content is "++";
#   * a file the scope grew that a later commit deleted;
#   * a commit on develop between the two phases that grows a file the
#     phases also grow, and is not in the commits file -- it must not be
#     charged to them, though a --range spanning it must;
#   * a scope that touches no source at all, where git apply refuses
#     the empty patch;
#   * a file whose name starts with "total", which wc's summary line
#     must not be confused with;
#   * wc, git apply and git diff each failing, through PATH shims, which
#     must come out as an error and never as "(none)";
#   * diff.renames=false in the repository's config, so the rename case
#     proves the script asks for rename detection rather than
#     inheriting it.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0
start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# show OUTPUT -- OUTPUT indented, on stderr, for a failure message.
# shellcheck disable=SC2001  # sed anchors per line; bash patterns cannot
show() { sed 's/^/        /' <<< "$1" >&2; }

# expect_line NAME PATTERN OUTPUT -- OUTPUT has a line matching the
# extended regex PATTERN.
expect_line() {
    if grep -qE -- "$2" <<< "$3"; then
        ok "$1"
    else
        fail "$1"; echo "      wanted /$2/ in:" >&2; show "$3"
    fi
}

# expect_no_line NAME PATTERN OUTPUT -- OUTPUT has no such line.
expect_no_line() {
    if grep -qE -- "$2" <<< "$3"; then
        fail "$1"; echo "      did not want /$2/ in:" >&2; show "$3"
    else
        ok "$1"
    fi
}

lines() { seq "$2" > "$1"; }

TABBED=$'tab\there.rs'

# build_fixture DIR -- develop with two merged features, and a work
# branch with commits of its own. Sets M1 and M2 to the merge SHAs.
build_fixture() {
    local dir="$1"
    mkdir -p "${dir}/tools/audit"
    cp "${SCRIPT_DIR}/audit-scope.sh" "${SCRIPT_DIR}/source-size.sh" "${dir}/tools/audit/"
    (
        cd "${dir}" || exit 1
        git init -q -b develop .
        git config user.email 'test@example.com'
        git config user.name 'Source Size Test'
        git config commit.gpgsign false
        git config diff.renames false
        mkdir -p prototypes docs .github/workflows
        lines big.rs 1600
        lines mid.rs 900
        lines small.rs 100
        lines shrinks.rs 2000
        lines moves.rs 3000
        lines prototypes/huge.rs 2000
        lines docs/huge.md 2000
        lines .github/workflows/ci.yml 1000
        lines gone.rs 900
        lines churn.rs 2000
        lines "${TABBED}" 900
        lines 'total counts.rs' 1600
        git add -A
        git commit -q -m 'base'

        # Merge 1: grows a file over 1,500, one over 800, one under 800.
        git checkout -q -b feat-a
        printf 'x\n' >> big.rs
        printf 'x\n' >> mid.rs
        printf 'x\n' >> small.rs
        printf 'x\n' >> gone.rs
        printf 'x\n' >> "${TABBED}"
        git commit -q -am 'feat a'
        git checkout -q develop
        git merge -q --no-ff -m 'merge feat a' feat-a

        # Unrelated work on develop between the phases, not audited.
        seq 5 >> big.rs
        git commit -q -am 'unrelated'

        # Merge 2: a rename, a shrink, excluded growth, workflow growth,
        # a new spaced path, and an added line that looks like a header.
        git checkout -q -b feat-b
        git mv moves.rs moved.rs
        head -n 1000 shrinks.rs > t && mv t shrinks.rs
        { printf 'a\nb\nc\n'; tail -n +11 churn.rs; } > t && mv t churn.rs
        printf 'x\n' >> prototypes/huge.rs
        printf 'x\n' >> docs/huge.md
        printf 'x\n' >> .github/workflows/ci.yml
        lines 'new spaced.rs' 1700
        printf '++ looks like a header\n' >> mid.rs
        git add -A
        git commit -q -m 'feat b'
        git checkout -q develop
        git merge -q --no-ff -m 'merge feat b' feat-b

        # A documentation-only commit: no source in it at all.
        printf 'x\n' >> docs/huge.md
        git commit -q -am 'docs only'

        # The audit branch: one commit of its own, under 800 lines.
        git checkout -q -b audit
        printf 'x\n' >> small.rs
        git rm -q gone.rs
        git commit -q -am 'audit branch'
    ) || return 1
    M1="$(git -C "${dir}" log --format=%H --merges --first-parent develop | tail -1)"
    M2="$(git -C "${dir}" log --format=%H --merges --first-parent develop | head -1)"
    [ -n "${M1}" ] && [ -n "${M2}" ] && [ "${M1}" != "${M2}" ]
}

FIX="${WORK}/fixture"
build_fixture "${FIX}" || { echo "could not build the fixture" >&2; exit 1; }
TOOL="${FIX}/tools/audit/source-size.sh"
CFILE="${WORK}/commits.txt"
printf '%s\n%s\n' "$M1" "$M2" > "$CFILE"

start "--commits-file sees growth the phases merged"
out="$("$TOOL" --commits-file "$CFILE" 2>&1)"
expect_line "file over 1,500 that grew, charged only its audited growth" \
    '^ *1606 lines +\+1 in scope +big\.rs +\(over 1500' "$out"
expect_line "file over 800 that grew, a header-shaped line counted" \
    '^ *902 lines +\+2 in scope +mid\.rs +\(over 800: a question\)' "$out"
expect_line "new file over 1,500, path with a space" '^ *1700 lines +\+1700 in scope +new spaced\.rs ' "$out"
expect_line "workflow YAML is source" '^ *1001 lines +\+1 in scope +\.github/workflows/ci\.yml ' "$out"
expect_line "path with a tab" $'^ *901 lines +\\+1 in scope +tab\there\\.rs ' "$out"
expect_no_line "grown file under 800" 'small\.rs' "$out"
expect_no_line "grown file deleted since is not opened" 'gone\.rs|No such file' "$out"
expect_no_line "oversize file that shrank" 'shrinks\.rs' "$out"
expect_no_line "rewritten into fewer lines is a net loss" 'churn\.rs' "$out"
expect_no_line "pure rename is not growth" 'move[sd]\.rs' "$out"
expect_no_line "prototypes/ is excluded" 'prototypes/' "$out"
expect_no_line "markdown is excluded" '\.md' "$out"

start "--range measures everything in the range"
out="$("$TOOL" --range "${M1}^1..develop" 2>&1)"
expect_line "unrelated commit inside the range is counted" '^ *1606 lines +\+6 in scope +big\.rs ' "$out"
expect_line "range finds a file over 800" '^ *902 lines +\+2 in scope +mid\.rs ' "$out"
expect_no_line "rename is not growth in range mode either" 'move[sd]\.rs' "$out"
expect_no_line "no (none) beside findings" '^\(none\)' "$out"

start "a scope with no source in it says so, without an error"
DOCS_ONLY="$(git -C "${FIX}" log --format=%H -1 --grep='^docs only$' develop)"
out="$("$TOOL" --range "${DOCS_ONLY}^..${DOCS_ONLY}" 2>&1)"
expect_line "the reason is given" '^\(none\): the scope changes no file that counts as source$' "$out"
expect_no_line "git apply is not handed an empty patch" 'error|No valid patches' "$out"

start "a failure to measure is an error, never (none)"
SHIM="${WORK}/shim"
mkdir -p "${SHIM}/wc" "${SHIM}/apply" "${SHIM}/diff"
REAL_GIT="$(command -v git)"
REAL_WC="$(command -v wc)"
# Each shim breaks one thing as narrowly as it can, so that a failure
# the script handles only partly -- the last commit's diff but not the
# first's, the count of every file but not one -- still shows. wc reads
# the file on stdin, so the shim finds out which file through /proc.
# shellcheck disable=SC2016  # the shim expands these, not this script
printf '#!/bin/sh\ncase "$(readlink /proc/$$/fd/0)" in */big.rs) exit 1;; esac\nexec "%s" "$@"\n' \
    "${REAL_WC}" > "${SHIM}/wc/wc"
# shellcheck disable=SC2016  # the shim expands these, not this script
printf '#!/bin/sh\n[ "$1" = apply ] && exit 1\nexec "%s" "$@"\n' "${REAL_GIT}" > "${SHIM}/apply/git"
# shellcheck disable=SC2016  # the shim expands these, not this script
printf '#!/bin/sh\nfor a; do [ "$a" = "%s" ] && exit 1; done\nexec "%s" "$@"\n' \
    "${M1}" "${REAL_GIT}" > "${SHIM}/diff/git"
chmod +x "${SHIM}"/*/*
for broken in wc apply diff; do
    out="$(PATH="${SHIM}/${broken}:${PATH}" "$TOOL" --commits-file "$CFILE" 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then ok "${broken} failing exits non-zero"; else fail "${broken} failing exited 0"; fi
    expect_line "${broken} failing is reported" '^error: .*not a clean result$' "$out"
    if [ "$broken" = wc ]; then
        expect_line "the file that could not be counted is named" '^error: could not count the lines in big\.rs$' "$out"
    fi
    expect_no_line "${broken} failing is not (none)" '^\(none\)' "$out"
done
out="$(PATH="${SHIM}/wc:${PATH}" "$TOOL" --baseline 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then ok "--baseline exits non-zero with wc failing"; else fail "--baseline exited 0 with wc failing"; fi
expect_line "--baseline names the file it could not count" '^error: could not count the lines in big\.rs$' "$out"

start "the default scope on an audit branch sees only the branch"
out="$(cd "${FIX}/docs" && "$TOOL" 2>&1)"
expect_line "banner names the default range" '^audit scope: 2 files \(develop\.\.\.HEAD\)' "$out"
expect_line "nothing over 800 grew on the branch itself" '^\(none\)$' "$out"

start "an unresolvable scope says so rather than reporting none"
NODEV="${WORK}/nodev"
build_fixture "${NODEV}" || { echo "could not build the second fixture" >&2; exit 1; }
git -C "${NODEV}" branch -q -m develop elsewhere
out="$("${NODEV}/tools/audit/source-size.sh" 2>&1)"
expect_line "skip is stated" '^skipped: no scope' "$out"
expect_no_line "no (none) standing in for a result" '^\(none\)$' "$out"

start "an explicit scope that does not resolve is an error"
if "$TOOL" --range 'nosuch..HEAD' > /dev/null 2>&1; then
    fail "an unresolvable --range exited 0"
else
    ok "an unresolvable --range exits non-zero"
fi

start "--baseline lists the tracked tree, from any directory"
out="$(cd "${FIX}/docs" && "$TOOL" --baseline 2>&1)"
expect_line "file over 1,500 listed" '^ *1700 new spaced\.rs$' "$out"
expect_line "renamed file listed under its new name" '^ *3000 moved\.rs$' "$out"
expect_line "a name starting with total is listed" '^ *1600 total counts\.rs$' "$out"
expect_no_line "file under 1,500 not listed" 'mid\.rs' "$out"
expect_no_line "prototypes/ excluded from a subdirectory" 'prototypes/' "$out"
expect_no_line "markdown excluded from a subdirectory" '\.md' "$out"
expect_no_line "no wc total line" ' total$' "$out"
out="$("$TOOL" --baseline 800 2>&1)"
expect_line "a threshold argument is honoured" '^ *902 mid\.rs$' "$out"
expect_line "workflow YAML in the baseline" '^ *1001 \.github/workflows/ci\.yml$' "$out"
out="$("$TOOL" --baseline lots 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then ok "a non-numeric threshold exits non-zero"; else fail "a non-numeric threshold exited 0"; fi
expect_line "a non-numeric threshold is refused by name" "^--baseline takes a line count, not 'lots'$" "$out"

if [ "$FAILURES" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all source-size tests passed"
