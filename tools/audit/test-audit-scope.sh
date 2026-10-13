#!/usr/bin/env bash
#
# Tests for tools/audit/audit-scope.sh, the shared file-scope
# resolution used by wave1.sh and wave2-mechanical.sh.
#
# The defect this guards against: every diff-scoped check in both
# scripts used to compute its file set from `git diff
# develop...HEAD`, which is silently wrong on a push-audit branch
# (every audited phase has already merged, so the range covers only
# what the branch itself adds -- small, or empty, either of which
# reads as a clean audit). See
# docs/plans/PLAN-differencing-phase-18-push-audit.md, "The audit
# scripts would have audited nothing".
#
# These tests run against this repository's own real history rather
# than a synthetic fixture repo, because the --commits-file mode's
# whole point is resolving a merge commit's first-parent diff, and a
# fixture history built just for the test would not exercise that in
# a way a reader could independently sanity-check. 60e4381c and
# d7a4973f are two real phase-merge commits already on develop; their
# file counts (10 and 20) are asserted against `git diff --name-only
# <sha>^1 <sha>` as the oracle, not hand-counted, so they do not need
# to be re-verified by hand if history is rewritten upstream of them.
# Nothing here depends on network access, and the "default" case
# depends on `develop` resolving to *something* in this repo (true by
# construction, since it is the base branch), not on its content.
#
# Library-level cases run the resolver in a command-substitution
# subshell so a deliberate `exit 9` inside it (an invalid invocation)
# only ends that subshell, not this test script. Script-level cases
# invoke wave2-mechanical.sh itself as a child process, which isolates
# the same way for free; they never reach wave1.sh's build steps,
# because every case here is designed to be refused, or to resolve,
# before any check runs -- this script must not trigger a build.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIB="${SCRIPT_DIR}/audit-scope.sh"
WAVE2="${SCRIPT_DIR}/wave2-mechanical.sh"

cd "$REPO_ROOT" || exit 1

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# expect_names NAME EXPECTED ACTUAL -- compare two newline-delimited
# (already sorted) name lists in full, so a spurious extra or missing
# file fails as loudly as a wrong count.
expect_names() {
    local name="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        ok "$name"
    else
        fail "$name"
        echo "      expected:" >&2
        echo "${expected:-<nothing>}" | sed 's/^/        /' >&2
        echo "      actual:" >&2
        echo "${actual:-<nothing>}" | sed 's/^/        /' >&2
    fi
}

# expect_refused NAME EXPECTED_EXIT -- run wave2-mechanical.sh with
# the given args, which must exit non-zero with EXPECTED_EXIT and
# print something on stderr naming the problem.
expect_refused() {
    local name="$1" expected_rc="$2"
    shift 2
    local out err rc
    out="$("$WAVE2" "$@" 2>/tmp/audit-scope-test-err.$$)"
    rc=$?
    err="$(cat /tmp/audit-scope-test-err.$$)"
    rm -f /tmp/audit-scope-test-err.$$
    if [ "$rc" -ne "$expected_rc" ]; then
        fail "$name (exit $rc, want $expected_rc)"
        return
    fi
    if [ -z "$err" ]; then
        fail "$name (exit code matched but nothing was printed naming the problem)"
        return
    fi
    ok "$name"
}

start "default (no option) matches git diff --name-only develop...HEAD"
expected="$(git diff --name-only develop...HEAD | sort -u)"
actual="$(
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init
    audit_scope_names_all | sort -u
)"
expect_names "default scope == develop...HEAD" "$expected" "$actual"

start "explicit --range selects the right files"
expected="$(git diff --name-only '60e4381c^1..60e4381c' | sort -u)"
actual="$(
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init --range '60e4381c^1..60e4381c'
    audit_scope_names_all | sort -u
)"
expect_names "--range 60e4381c^1..60e4381c" "$expected" "$actual"
count="$(echo "$expected" | grep -c .)"
if [ "$count" -eq 10 ]; then
    ok "60e4381c first-parent diff is 10 files, as the plan records"
else
    fail "60e4381c first-parent diff is $count files, expected 10"
fi

start "--commits-file of one merge resolves to its first-parent diff"
cfile="$(mktemp)"
printf '# one phase merge\n60e4381c\n' > "$cfile"
expected="$(git diff --name-only '60e4381c^1' '60e4381c' | sort -u)"
actual="$(
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init --commits-file "$cfile"
    audit_scope_names_all | sort -u
)"
rm -f "$cfile"
expect_names "--commits-file (single merge)" "$expected" "$actual"

start "--commits-file of two merges resolves to the union of their first-parent diffs"
cfile="$(mktemp)"
cat > "$cfile" <<'EOF'
# two phase merges; blank lines and comments are ignored

60e4381c

d7a4973f
EOF
expected="$( { git diff --name-only '60e4381c^1' '60e4381c'; git diff --name-only 'd7a4973f^1' 'd7a4973f'; } | sort -u)"
actual="$(
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init --commits-file "$cfile"
    audit_scope_names_all | sort -u
)"
rm -f "$cfile"
expect_names "--commits-file (union of two merges)" "$expected" "$actual"
count="$(echo "$expected" | grep -c .)"
if [ "$count" -eq 26 ]; then
    ok "union of 60e4381c (10) and d7a4973f (20) is 26 distinct files"
else
    fail "union is $count files, expected 26"
fi

start "an empty EXPLICIT resolved set is refused"
expect_refused "empty --range is refused with exit 9" 9 --range 'HEAD..HEAD'

start "an empty IMPLICIT (default) scope warns and continues, exit 0"
# Force the resolved range empty (HEAD...HEAD) after an ordinary
# no-option init, the way the reviewer's own repro did, since this
# repo's real develop...HEAD is not guaranteed to be empty and must
# not be made to be for a test. An implicit empty scope must NOT
# refuse -- unlike the explicit case above, nothing here asserted a
# scope and got it wrong; it legitimately means "no changes against
# develop", and wave1.sh's unscoped checks (pre-commit, the build,
# the test suite) must still run.
output="$(
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init
    AUDIT_SCOPE_RANGE='HEAD...HEAD'
    audit_scope_report
    echo "exit_code_was:$?"
    echo "skip_scoped_was:${AUDIT_SCOPE_SKIP_SCOPED}"
)"
rc=$?
if [ "$rc" -eq 0 ] \
    && [[ "$output" == *"audit scope: 0 files"* ]] \
    && [[ "$output" == *"WARNING: nothing to audit"* ]] \
    && [[ "$output" == *"exit_code_was:0"* ]] \
    && [[ "$output" == *"skip_scoped_was:1"* ]]; then
    ok "implicit empty scope warns, sets skip, and does not exit"
else
    fail "implicit empty scope was not handled as expected (subshell rc=$rc)"
    echo "$output" | sed 's/^/      /' >&2
fi

start "both options together are refused"
cfile="$(mktemp)"
printf '60e4381c\n' > "$cfile"
expect_refused "--range + --commits-file together are refused with exit 9" 9 \
    --range 'HEAD..HEAD' --commits-file "$cfile"
rm -f "$cfile"

start "a missing --commits-file is refused"
expect_refused "nonexistent --commits-file is refused with exit 9" 9 \
    --commits-file "/nonexistent/$$-audit-scope-test.txt"

start "an unparseable --range is refused"
expect_refused "--range with no '..' is refused with exit 9" 9 --range 'notarange'

echo
if [ "$FAILURES" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all audit-scope tests passed"
