#!/usr/bin/env bash
#
# Tests for tools/ci/stage-autofix-changes.sh.
#
# The staging this covers used to be a bare `git add -u` in inline
# workflow YAML that only ever ran during a live daily autofix run, and
# it was in the wrong step for months without anything noticing. These
# cases pin the states the working tree can be in when Claude Code hands
# back control: nothing changed, a tracked file edited or deleted, a new
# source file created, and the untracked junk the `-A` alternative was
# rejected for picking up.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="${REPO_ROOT}/tools/ci/stage-autofix-changes.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

check() {
    # check DESCRIPTION ACTUAL EXPECTED
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        fail "$1: expected '$3', got '$2'"
    fi
}

# A scratch repo with one commit, the source roots the real repo has,
# and the ignore rules that matter to staging.
setup() {
    D="${WORK}/repo"
    rm -rf "${D}"
    mkdir -p "${D}"
    git -C "${D}" init -q
    git -C "${D}" config user.email bot@example.com
    git -C "${D}" config user.name bot
    mkdir -p "${D}/src/crates/qcow2" "${D}/tests" "${D}/docs" \
        "${D}/tools/ci" "${D}/scripts" "${D}/crates" "${D}/prototypes"
    echo 'fn main() {}' > "${D}/src/main.rs"
    echo 'fn parse() {}' > "${D}/src/crates/qcow2/lib.rs"
    echo '# notes' > "${D}/docs/testing.md"
    printf '**/target/\n**/*.bin\n*.swp\n' > "${D}/.gitignore"
    git -C "${D}" add -A
    git -C "${D}" commit -qm 'base'
}

stage() { "${STAGE}" "${D}"; }

# Newline-separated sorted list of staged paths, so a check can compare
# against a literal.
staged() { git -C "${D}" diff --cached --name-only | sort | tr '\n' ' ' | sed 's/ $//'; }

start "a clean tree stages nothing and says so"
setup
OUT="$(stage)"
check "nothing staged" "$(staged)" ""
case "${OUT}" in
    *"Nothing staged"*) ok "reports the empty case" ;;
    *) fail "reports the empty case: got '${OUT}'" ;;
esac

start "a tracked modification is staged"
setup
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
stage > /dev/null
check "modified file staged" "$(staged)" "src/main.rs"

start "a tracked deletion is staged"
setup
rm "${D}/src/crates/qcow2/lib.rs"
stage > /dev/null
check "deletion staged" "$(staged)" "src/crates/qcow2/lib.rs"

start "a file already staged by Claude stays staged"
setup
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
git -C "${D}" add src/main.rs
stage > /dev/null
check "still staged, once" "$(staged)" "src/main.rs"

# The case the review flagged: `git add -u` alone leaves a new file
# untracked, so `make instar` and `make test-container-core` verify a
# working tree the commit then does not contain -- a PR that reports
# "Build succeeded" and does not compile.
start "a newly created file under a source root is staged"
setup
echo 'fn t() {}' > "${D}/tests/regression_qcow2.rs"
OUT="$(stage)"
check "new test file staged" "$(staged)" "tests/regression_qcow2.rs"
case "${OUT}" in
    *"Staged 1 newly created file"*) ok "reports what it staged" ;;
    *) fail "reports what it staged: got '${OUT}'" ;;
esac

start "every source root is covered"
setup
for P in src/new.rs tests/new.rs docs/new.md crates/new.rs \
         tools/ci/new.sh scripts/new.sh; do
    echo x > "${D}/${P}"
done
stage > /dev/null
check "all six staged" "$(staged)" \
    "crates/new.rs docs/new.md scripts/new.sh src/new.rs tests/new.rs tools/ci/new.sh"

start "an untracked file outside the source roots is not staged"
setup
echo 'scratch' > "${D}/notes.txt"
mkdir -p "${D}/prototypes/src"
echo 'x' > "${D}/prototypes/spike.rs"
# The roots are anchored at the repo root, so a directory that merely
# contains one of their names further down does not qualify.
echo 'x' > "${D}/prototypes/src/spike.rs"
OUT="$(stage)"
check "nothing staged" "$(staged)" ""
case "${OUT}" in
    *"Left 3 untracked file(s) unstaged"*) ok "reports what it skipped" ;;
    *) fail "reports what it skipped: got '${OUT}'" ;;
esac

# Editor and merge leftovers land inside src/ as readily as anywhere
# else, so the path filter alone is not enough -- this is the temp-file
# protection that ruled out `git add -A`.
start "editor and merge artifacts inside a source root are not staged"
setup
echo x > "${D}/src/main.rs~"
echo x > "${D}/src/main.rs.orig"
echo x > "${D}/src/main.rs.rej"
echo x > "${D}/src/main.rs.bak"
echo x > "${D}/src/.#main.rs"
stage > /dev/null
check "no artifact staged" "$(staged)" ""

start "gitignored build output is not staged"
setup
mkdir -p "${D}/src/target/debug"
echo x > "${D}/src/target/debug/instar"
echo x > "${D}/src/core.bin"
echo x > "${D}/src/main.rs.swp"
OUT="$(stage)"
check "nothing staged" "$(staged)" ""
case "${OUT}" in
    *"untracked file(s) unstaged"*) fail "ignored files should not even be reported" ;;
    *) ok "ignored files are invisible, not skipped" ;;
esac

start "a new source file with a space in its name is staged"
setup
echo x > "${D}/docs/image notes.md"
stage > /dev/null
check "space-bearing path staged" "$(staged)" "docs/image notes.md"

start "a mixed tree stages the fix and leaves the junk"
setup
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
echo 'fn t() {}' > "${D}/tests/regression.rs"
echo x > "${D}/src/main.rs.orig"
echo x > "${D}/scratch.log"
stage > /dev/null
check "fix staged, junk left" "$(staged)" "src/main.rs tests/regression.rs"

start "argument errors are rejected"
setup
set +e
"${STAGE}" "${D}" extra > /dev/null 2>&1
check "too many arguments" "$?" "2"
"${STAGE}" "${WORK}/not-a-repo" > /dev/null 2>&1
check "missing directory" "$?" "2"
mkdir -p "${WORK}/plain-dir"
"${STAGE}" "${WORK}/plain-dir" > /dev/null 2>&1
check "not a work tree" "$?" "2"
set -e

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi

echo "all stage-autofix-changes tests passed"
