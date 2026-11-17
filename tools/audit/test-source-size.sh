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
expect_line "file over 1,500 that grew" '^ *1601 lines +\+1 in scope +big\.rs +\(over 1500' "$out"
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
expect_no_line "file under 1,500 not listed" 'mid\.rs' "$out"
expect_no_line "prototypes/ excluded from a subdirectory" 'prototypes/' "$out"
expect_no_line "markdown excluded from a subdirectory" '\.md' "$out"
expect_no_line "no wc total line" ' total$' "$out"
out="$("$TOOL" --baseline 800 2>&1)"
expect_line "a threshold argument is honoured" '^ *902 mid\.rs$' "$out"
expect_line "workflow YAML in the baseline" '^ *1001 \.github/workflows/ci\.yml$' "$out"
if "$TOOL" --baseline lots > /dev/null 2>&1; then
    fail "a non-numeric threshold exited 0"
else
    ok "a non-numeric threshold is refused"
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all source-size tests passed"
