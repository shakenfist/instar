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
# Every case builds its own throwaway repository under $WORK and runs
# the resolver there. An earlier version asserted against this
# repository's real history and two hard-coded merge SHAs, which
# cannot work in CI: the ci-tooling job checks out at depth 1, so the
# merges are not present and neither is a merge-base for
# `develop...HEAD`. A fixture repository makes the test hermetic
# (runnable in a shallow clone, a fork, or a rewritten history),
# removes the hand-maintained file counts, and still exercises the
# real thing -- `git merge --no-ff` produces a genuine merge commit,
# so first-parent resolution is tested against git rather than against
# a simulation of it. Oracles are computed by running git in the
# fixture repository, never written down.
#
# Three fixture details are load-bearing:
#   * one path contains a space, so a reader that splits on whitespace
#     fails instead of silently reading two nonexistent files;
#   * one merge deletes a file, so the scope legitimately names a path
#     that is not on disk -- the case that used to reach grep and awk
#     as an error and get discarded with 2>/dev/null;
#   * `develop` is a real branch, so the default (no-option) scope is
#     the same `develop...HEAD` expression the scripts use in anger.
#
# Library-level cases run the resolver in a command-substitution
# subshell so a deliberate `exit 9` inside it (an invalid invocation)
# only ends that subshell, not this test script. The script-level
# cases at the end invoke wave2-mechanical.sh itself, which resolves
# its own repository root and so runs against this checkout rather
# than the fixture; they prove the *script* refuses a bad scope before
# running any check, and every one of them is refused during argument
# parsing or on an empty explicit range, so none needs history and
# none triggers a build.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/audit-scope.sh"
WAVE1="${SCRIPT_DIR}/wave1.sh"
WAVE2="${SCRIPT_DIR}/wave2-mechanical.sh"

# Same idiom as test-inline-script-check.sh: one work directory, removed
# on any exit, so nothing is left in /tmp and no path is predictable.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

SPACED='f2 with space.rs'

# build_fixture DIR -- a repository with a develop branch, two real
# merge commits and a working branch. Sets M1 and M2 to the merge SHAs.
build_fixture() {
    local dir="$1"
    mkdir -p "${dir}"
    (
        cd "${dir}" || exit 1
        git init -q -b develop .
        git config user.email 'test@example.com'
        git config user.name 'Audit Scope Test'
        git config commit.gpgsign false
        printf 'base\n' > a.rs
        printf 'base\n' > b.rs
        printf 'keep\n' > keep.txt
        printf 'doc\n' > doc.md
        git add -A
        git commit -q -m 'base'

        # Merge 1: two added Rust files (one with a space in its name)
        # and one modified.
        git checkout -q -b feat-a
        printf 'one\n' > f1.rs
        printf 'two\n' > "${SPACED}"
        printf 'changed\n' >> a.rs
        git add -A
        git commit -q -m 'feat a'
        git checkout -q develop
        git merge -q --no-ff -m 'merge feat a' feat-a

        # Merge 2: one added, one modified, one DELETED -- the deleted
        # path is why the scope can name a file that is not on disk.
        git checkout -q -b feat-b
        printf 'three\n' > f3.rs
        printf 'changed\n' >> b.rs
        git rm -q keep.txt
        git add -A
        git commit -q -m 'feat b'
        git checkout -q develop
        git merge -q --no-ff -m 'merge feat b' feat-b

        # A working branch, so the default develop...HEAD scope is
        # non-empty and has a real merge-base.
        git checkout -q -b work
        printf 'work\n' > w1.rs
        git add -A
        git commit -q -m 'work in progress'
    ) || return 1
    M1="$(git -C "${dir}" log --format=%H --merges --first-parent develop | tail -1)"
    M2="$(git -C "${dir}" log --format=%H --merges --first-parent develop | head -1)"
    [ -n "${M1}" ] && [ -n "${M2}" ] && [ "${M1}" != "${M2}" ]
}

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
        # ${var//pat/repl} cannot anchor "start of each line" the way
        # sed's ^ does -- bash pattern matching has no multiline mode,
        # so it would only ever touch the first line. sed is correct
        # here, not just familiar.
        # shellcheck disable=SC2001
        sed 's/^/        /' <<< "${expected:-<nothing>}" >&2
        echo "      actual:" >&2
        # shellcheck disable=SC2001  # see the multi-line note above
        sed 's/^/        /' <<< "${actual:-<nothing>}" >&2
    fi
}

# in_fixture CODE... -- run CODE with the library sourced, inside the
# fixture repository, in a subshell. Echoes its stdout; the caller sees
# the subshell's exit status in $?.
in_fixture() {
    (
        cd "${FIX}" || exit 1
        # shellcheck source=tools/audit/audit-scope.sh
        source "$LIB"
        eval "$*"
    )
}

# expect_lib_refused NAME EXPECTED_EXIT WANT_ERR INIT_ARGS... --
# audit_scope_init (or audit_scope_report) must end the subshell with
# EXPECTED_EXIT and print WANT_ERR on stderr.
#
# WANT_ERR is required rather than optional because several of these
# invocations are refused by more than one rule: with the mutual
# exclusion of --range and --commits-file removed, for instance,
# `--range HEAD..HEAD --commits-file f` still exits 9, because the
# range branch resolves to an empty explicit scope. An exit-code-only
# assertion cannot tell those apart, and a mutation run proved it does
# not: deleting the mutual-exclusion check left this test passing.
expect_lib_refused() {
    local case_name="$1" want_rc="$2" want_err="$3"
    shift 3
    local rc err
    (
        cd "${FIX}" || exit 1
        # shellcheck source=tools/audit/audit-scope.sh
        source "$LIB"
        audit_scope_init "$@"
        audit_scope_report
    ) >/dev/null 2>"${WORK}/stderr"
    rc=$?
    err="$(cat "${WORK}/stderr")"
    if [ "$rc" -ne "$want_rc" ]; then
        fail "$case_name (exit $rc, want $want_rc)"
        # shellcheck disable=SC2001  # see the multi-line note in expect_names
        sed 's/^/      /' <<< "$err" >&2
        return
    fi
    if [[ "$err" != *"$want_err"* ]]; then
        fail "$case_name (exit code matched but stderr did not mention '${want_err}')"
        # shellcheck disable=SC2001  # see the multi-line note in expect_names
        sed 's/^/      /' <<< "$err" >&2
        return
    fi
    ok "$case_name"
}

# expect_refused SCRIPT NAME EXPECTED_EXIT -- run SCRIPT with the given
# args, which must exit non-zero with EXPECTED_EXIT and print something
# on stderr naming the problem.
#
# Both wave scripts are driven, not just one: they parse their options
# through the same library but call it from their own preamble, and the
# point of a script-level case is to catch those two preambles drifting
# apart. Every case here is refused during argument parsing or on an
# empty explicit range -- before wave1.sh reaches pre-commit or
# wave2-mechanical.sh reaches its first grep -- so neither starts any
# work.
expect_refused() {
    local script="$1" name="$2" expected_rc="$3"
    shift 3
    local err rc
    # stdout is discarded, not inspected -- only the exit code and
    # stderr (the "naming the problem" message) matter here.
    "$script" "$@" >/dev/null 2>"${WORK}/stderr"
    rc=$?
    err="$(cat "${WORK}/stderr")"
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

FIX="${WORK}/fixture"
M1=""
M2=""
start "fixture repository builds, with two real merge commits"
if build_fixture "${FIX}"; then
    ok "fixture built (merges ${M1:0:8} and ${M2:0:8})"
else
    fail "could not build the fixture repository -- nothing below can run"
    echo "1 failure(s)" >&2
    exit 1
fi

start "default (no option) matches git diff --name-only develop...HEAD"
expected="$(git -C "${FIX}" diff --name-only develop...HEAD | sort -u)"
actual="$(in_fixture 'audit_scope_init; audit_scope_names_all | sort -u')"
expect_names "default scope == develop...HEAD" "$expected" "$actual"

start "explicit --range selects the right files"
expected="$(git -C "${FIX}" diff --name-only "${M1}^1..${M1}" | sort -u)"
actual="$(in_fixture "audit_scope_init --range '${M1}^1..${M1}'; audit_scope_names_all | sort -u")"
expect_names "--range <merge>^1..<merge>" "$expected" "$actual"

start "--commits-file of one merge resolves to its first-parent diff"
cfile="${WORK}/one.txt"
printf '# one phase merge\n%s\n' "${M1}" > "$cfile"
expected="$(git -C "${FIX}" diff --name-only "${M1}^1" "${M1}" | sort -u)"
actual="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_all | sort -u")"
expect_names "--commits-file (single merge)" "$expected" "$actual"

start "--commits-file of two merges resolves to the union of their first-parent diffs"
cfile="${WORK}/two.txt"
cat > "$cfile" <<EOF
# two phase merges; blank lines and comments are ignored

${M1}

${M2}
EOF
expected="$( {
    git -C "${FIX}" diff --name-only "${M1}^1" "${M1}"
    git -C "${FIX}" diff --name-only "${M2}^1" "${M2}"
} | sort -u)"
actual="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_all | sort -u")"
expect_names "--commits-file (union of two merges)" "$expected" "$actual"
# The union must be strictly larger than either side, or the test would
# pass just as well against a resolver that ignored the second commit.
one="$(git -C "${FIX}" diff --name-only "${M1}^1" "${M1}" | grep -c .)"
both="$(echo "$expected" | grep -c .)"
if [ "$both" -gt "$one" ]; then
    ok "the union (${both}) is larger than the first merge alone (${one})"
else
    fail "the union is ${both} files and the first merge alone is ${one}; the second commit cannot be contributing"
fi

start "a pathspec filters the union (commits mode)"
expected="$( {
    git -C "${FIX}" diff --name-only "${M1}^1" "${M1}" -- '*.rs'
    git -C "${FIX}" diff --name-only "${M2}^1" "${M2}" -- '*.rs'
} | sort -u)"
actual="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_all '*.rs' | sort -u")"
expect_names "names_all '*.rs' in commits mode" "$expected" "$actual"
if ! grep -q 'doc.md' <<< "$actual" && grep -q 'f1.rs' <<< "$actual"; then
    ok "the pathspec excluded doc.md and kept f1.rs"
else
    fail "the pathspec did not filter: ${actual//$'\n'/, }"
fi

start "names_added reports only added files (commits mode)"
expected="$( {
    git -C "${FIX}" diff --name-only --diff-filter=A "${M1}^1" "${M1}"
    git -C "${FIX}" diff --name-only --diff-filter=A "${M2}^1" "${M2}"
} | sort -u)"
actual="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_added | sort -u")"
expect_names "names_added in commits mode" "$expected" "$actual"
if ! grep -qx 'a.rs' <<< "$actual"; then
    ok "a modified file (a.rs) is not reported as added"
else
    fail "names_added included the merely-modified a.rs"
fi

start "audit_scope_diff produces a patch for the whole union"
patch="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_diff")"
if grep -q 'f1.rs' <<< "$patch" && grep -q 'f3.rs' <<< "$patch"; then
    ok "the patch covers files from both merges"
else
    fail "the patch did not cover both merges ($(wc -l <<< "$patch") lines)"
fi

start "a path deleted by an audited commit is in the scope but not fed to content checks"
all="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_all | sort -u")"
existing="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_existing | sort -u")"
if grep -qx 'keep.txt' <<< "$all"; then
    ok "names_all keeps the deleted keep.txt, so the reported scope is the true one"
else
    fail "names_all dropped the deleted keep.txt; the scope count would understate what changed"
fi
if ! grep -qx 'keep.txt' <<< "$existing"; then
    ok "names_existing drops keep.txt, so no check is handed a path that is not there"
else
    fail "names_existing returned the deleted keep.txt"
fi
if [ -n "$existing" ] && [ "$(grep -c . <<< "$existing")" -eq "$(( $(grep -c . <<< "$all") - 1 ))" ]; then
    ok "names_existing drops exactly the one deleted path"
else
    fail "names_existing dropped the wrong number of paths"
fi

start "the report names how many scoped files are no longer on disk"
output="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_report")"
if [[ "$output" == *"1 no longer on disk"* ]]; then
    ok "the banner says one file is gone, so a smaller content-check count is explained"
else
    fail "the banner did not mention the deleted file: ${output}"
fi

start "a filename containing a space survives the NUL-delimited reader"
names="$(in_fixture "audit_scope_init --commits-file '${cfile}'; audit_scope_names_existing_null '*.rs' | tr '\\0' '\\n' | sort -u")"
if grep -qxF "${SPACED}" <<< "$names"; then
    ok "'${SPACED}' came back as one path"
else
    fail "'${SPACED}' was lost or split: ${names//$'\n'/, }"
fi

start "an empty EXPLICIT resolved set is refused"
expect_lib_refused "empty --range is refused with exit 9" 9 'nothing to audit' \
    --range 'HEAD..HEAD'

start "an empty IMPLICIT (default) scope warns and continues, exit 0"
# An implicit empty scope must NOT refuse -- unlike the explicit case
# above, nothing here asserted a scope and got it wrong; it
# legitimately means "no changes against develop", and wave1.sh's
# unscoped checks (pre-commit, the build, the test suite) must still
# run. Checked out on develop itself, develop...HEAD is empty for real.
output="$(
    cd "${FIX}" && git checkout -q develop || exit 1
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init
    audit_scope_report
    echo "exit_code_was:$?"
    echo "skip_scoped_was:${AUDIT_SCOPE_SKIP_SCOPED}"
)"
rc=$?
git -C "${FIX}" checkout -q work
if [ "$rc" -eq 0 ] \
    && [[ "$output" == *"audit scope: 0 files"* ]] \
    && [[ "$output" == *"WARNING: nothing to audit"* ]] \
    && [[ "$output" == *"exit_code_was:0"* ]] \
    && [[ "$output" == *"skip_scoped_was:1"* ]]; then
    ok "implicit empty scope warns, sets skip, and does not exit"
else
    fail "implicit empty scope was not handled as expected (subshell rc=$rc)"
    # shellcheck disable=SC2001  # see the multi-line note in expect_names above
    sed 's/^/      /' <<< "$output" >&2
fi

start "an option-shaped revision is refused rather than handed to git"
# --output=PATH is a real `git diff` option, so an unchecked value
# reaching git writes the diff to PATH. Pointing it at a path that does
# not exist turns "was it refused?" into something observable: the file
# must still not exist afterwards.
PWNED="${WORK}/written-by-git"
expect_lib_refused "--range starting with '-' is refused with exit 9" 9 \
    "must not start with" --range "--output=${PWNED}..HEAD"
cfile="${WORK}/dash.txt"
printf -- '--output=%s\n' "${PWNED}" > "$cfile"
expect_lib_refused "a commits-file entry starting with '-' is refused with exit 9" 9 \
    "must not start with" --commits-file "$cfile"
# Glob, not an exact path: git treats the whole --output=VALUE as the
# file name, so `--output=P..HEAD` writes "P..HEAD" rather than "P" --
# which is how an earlier version of this assertion managed to pass
# against a build with the guard removed.
written=("${PWNED}"*)
if [ ! -e "${written[0]}" ]; then
    ok "git wrote no file, so the value never reached it as an option"
else
    fail "git wrote ${written[0]}: the option-shaped value reached git after all"
fi

start "both options together are refused"
cfile="${WORK}/both.txt"
printf '%s\n' "${M1}" > "$cfile"
expect_lib_refused "--range + --commits-file together are refused with exit 9" 9 \
    "mutually exclusive" --range 'HEAD..HEAD' --commits-file "$cfile"

start "a missing --commits-file is refused"
expect_lib_refused "nonexistent --commits-file is refused with exit 9" 9 \
    "not found" --commits-file "${WORK}/no-such-file.txt"

start "an unparseable --range is refused"
expect_lib_refused "--range with no '..' is refused with exit 9" 9 \
    "must look like REV..REV" --range 'notarange'

start "an unresolvable commit in --commits-file is refused"
cfile="${WORK}/bogus.txt"
printf '%s\n' 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' > "$cfile"
expect_lib_refused "a commit that does not resolve is refused with exit 9" 9 \
    "does not resolve" --commits-file "$cfile"

start "a root commit in --commits-file is refused (it has no parent to diff)"
cfile="${WORK}/root.txt"
git -C "${FIX}" rev-list --max-parents=0 develop > "$cfile"
expect_lib_refused "a root commit is refused with exit 9" 9 \
    "no parent to diff against" --commits-file "$cfile"

start "develop resolving without a merge-base is 'unresolved', not 'nothing to audit'"
# A shallow clone can have the develop ref without its history, and
# then `git diff develop...HEAD` fails ("no merge base", exit 128)
# rather than returning an empty set. Reported as zero files that would
# read as a clean audit. An orphan branch reproduces it exactly: the
# ref resolves, the merge-base does not.
ORPHAN="${WORK}/orphan"
(
    cp -a "${FIX}" "${ORPHAN}"
    cd "${ORPHAN}" || exit 1
    git checkout -q --orphan unrelated
    git rm -q -rf . >/dev/null 2>&1
    printf 'unrelated\n' > u.rs
    git add -A
    git commit -q -m 'unrelated root'
) || fail "could not build the orphan fixture"
if git -C "${ORPHAN}" rev-parse --verify develop >/dev/null 2>&1 \
    && ! git -C "${ORPHAN}" merge-base develop HEAD >/dev/null 2>&1; then
    ok "the fixture has the shape: develop resolves, merge-base does not"
else
    fail "the orphan fixture does not reproduce the no-merge-base case"
fi
output="$(
    cd "${ORPHAN}" || exit 1
    # shellcheck source=tools/audit/audit-scope.sh
    source "$LIB"
    audit_scope_init
    audit_scope_report
    echo "skip_scoped_was:${AUDIT_SCOPE_SKIP_SCOPED}"
)"
rc=$?
if [ "$rc" -eq 0 ] \
    && [[ "$output" == *"unresolved"* ]] \
    && [[ "$output" != *"nothing to audit"* ]] \
    && [[ "$output" == *"skip_scoped_was:1"* ]]; then
    ok "the banner says unresolved rather than reporting an empty audit"
else
    fail "a failing develop...HEAD was not reported as unresolved (rc=$rc)"
    # shellcheck disable=SC2001  # see the multi-line note in expect_names above
    sed 's/^/      /' <<< "$output" >&2
fi

# Script level: the same refusals must stop each wave script itself
# before it runs a single check.
for script_path in "$WAVE1" "$WAVE2"; do
    script_name="$(basename "$script_path")"
    start "${script_name} refuses a bad scope before running any check"
    expect_refused "$script_path" \
        "${script_name}: empty --range is refused with exit 9" 9 --range 'HEAD..HEAD'
    expect_refused "$script_path" \
        "${script_name}: --range with no '..' is refused with exit 9" 9 --range 'notarange'
    expect_refused "$script_path" \
        "${script_name}: nonexistent --commits-file is refused with exit 9" 9 \
        --commits-file "${WORK}/no-such-file.txt"
    expect_refused "$script_path" \
        "${script_name}: both options together are refused with exit 9" 9 \
        --range 'HEAD..HEAD' --commits-file "${WORK}/both.txt"
    expect_refused "$script_path" \
        "${script_name}: an unknown option is refused with exit 9" 9 --nonsense
done

echo
if [ "$FAILURES" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all audit-scope tests passed"
