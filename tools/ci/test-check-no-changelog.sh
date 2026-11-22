#!/usr/bin/env bash
#
# Tests for tools/ci/check-no-changelog.sh.
#
# Once CHANGELOG.md is gone nothing in the tree matches the guard, so a
# pattern that matched nothing at all would look exactly like a clean
# tree. These cases are what show it can fail: the top-level file, the
# near misses an agent might create instead (a nested path, no
# extension, another case), and names that merely contain the word,
# which must not match.
#
# The guard uses `git ls-files`, so each fixture is a real git
# repository with the guard copied in: it resolves its repository root
# from BASH_SOURCE.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-no-changelog.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# tree FILE... -- a fresh git repository with the guard installed and
# each FILE added to the index (staged, not committed: pre-commit runs
# before the commit exists). Prints the repository's path.
tree() {
    local dir f
    dir="$(mktemp -d "${WORK}/t.XXXXXX")"
    mkdir -p "${dir}/tools/ci"
    cp "${CHECK}" "${dir}/tools/ci/check-no-changelog.sh"
    for f in "$@"; do
        mkdir -p "${dir}/$(dirname "${f}")"
        echo 'content' > "${dir}/${f}"
    done
    git -C "${dir}" init -q
    git -C "${dir}" add -A
    echo "${dir}"
}

run_check() {
    "$1/tools/ci/check-no-changelog.sh" > "${WORK}/out" 2> "${WORK}/err"
}

# expect_pass NAME DIR
expect_pass() {
    if run_check "$2"; then
        ok "$1"
    else
        fail "$1: expected exit 0, got $?; stderr: $(cat "${WORK}/err")"
    fi
}

# expect_fail NAME DIR NEEDLE... -- exit 1, with every NEEDLE on stderr.
expect_fail() {
    local name="$1" dir="$2" status=0 needle; shift 2
    run_check "${dir}" || status=$?
    if [ "${status}" -ne 1 ]; then
        fail "${name}: expected exit 1, got ${status}; stderr: $(cat "${WORK}/err")"
        return
    fi
    for needle in "$@"; do
        if ! grep -qF -- "${needle}" "${WORK}/err"; then
            fail "${name}: stderr does not mention '${needle}': $(cat "${WORK}/err")"
            return
        fi
    done
    ok "${name}"
}

start 'a clean tree passes'
T="$(tree README.md docs/development.md docs/changelog-policy.md \
    docs/plans/PLAN-add-a-CHANGELOG-entry.md CHANGELOG.txt)"
expect_pass 'names that only contain the word' "${T}"
if grep -q 'carries no changelog file' "${WORK}/out"; then
    ok 'the summary states the tree is clean'
else
    fail "the summary is missing: $(cat "${WORK}/out")"
fi

start 'a changelog file fails'
expect_fail 'the top-level CHANGELOG.md' "$(tree CHANGELOG.md)" \
    'CHANGELOG.md' 'Releases'
expect_fail 'a nested docs/CHANGELOG.md' "$(tree docs/CHANGELOG.md)" \
    'docs/CHANGELOG.md'
expect_fail 'CHANGELOG with no extension' "$(tree CHANGELOG)" \
    'in the tree: CHANGELOG'
expect_fail 'another case, Changelog.md' "$(tree Changelog.md)" \
    'Changelog.md'
expect_fail 'every offender is named' \
    "$(tree CHANGELOG.md src/crates/x/changelog.md)" \
    'in the tree: CHANGELOG.md' 'src/crates/x/changelog.md'

start 'outside a git checkout is an error, not a clean tree'
D="$(mktemp -d "${WORK}/nogit.XXXXXX")"
mkdir -p "${D}/tools/ci"
cp "${CHECK}" "${D}/tools/ci/check-no-changelog.sh"
STATUS=0
GIT_CEILING_DIRECTORIES="${WORK}" run_check "${D}" || STATUS=$?
if [ "${STATUS}" -eq 2 ]; then
    ok 'exit 2 outside a checkout'
else
    fail "expected exit 2 outside a checkout, got ${STATUS}"
fi

if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-no-changelog: ${FAILURES} failure(s)." >&2
    exit 1
fi
echo 'test-check-no-changelog: all cases passed.'
