#!/usr/bin/env bash
#
# Tests for tools/ci/check-tests-relocatable.sh.
#
# Once the one offending line was moved to tools/ci, nothing in the tree
# matches the guard, so a pattern that matched nothing at all would look
# exactly like a clean tree. These cases are what show it can fail. The
# positive ones include the shape #968 was ejected for: a test reading
# src/crates/vmdk/src/lib.rs through a pathlib join.
#
# The guard uses `git grep` and `git ls-tree`, so each fixture is a real git
# repository with the guard copied in: it resolves its repository root from
# BASH_SOURCE, and reads its own top-level directories.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-tests-relocatable.sh"
GUARD='tools/ci/check-tests-relocatable.sh'

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# tree FILE [EXTRA_DIR...] -- a fresh git repository with the guard installed,
# the heredoc on stdin committed at FILE, and a file inside each of src/,
# tools/ and docs/ so that `git ls-tree -d` sees them. EXTRA_DIR adds another
# top-level directory. Prints the repository's path.
# It runs in a command substitution, so the directory comes from mktemp: a
# counter incremented here would never leave the subshell, and every case
# would share, and accumulate into, one repository.
tree() {
    local file="$1"; shift
    local dir extra
    dir="$(mktemp -d "${WORK}/t.XXXXXX")"
    mkdir -p "${dir}/tools/ci" "${dir}/$(dirname "${file}")" "${dir}/src" "${dir}/docs"
    cp "${CHECK}" "${dir}/${GUARD}"
    echo 'fn main() {}' > "${dir}/src/main.rs"
    echo 'docs' > "${dir}/docs/index.md"
    for extra in "$@"; do
        mkdir -p "${dir}/${extra}"
        echo x > "${dir}/${extra}/file.txt"
    done
    cat > "${dir}/${file}"
    git -C "${dir}" init -q
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test add -A
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test commit -q -m fixture
    echo "${dir}"
}

run_check() {
    "$1/${GUARD}" > "${WORK}/out" 2> "${WORK}/err"
}

# expect_pass NAME DIR
expect_pass() {
    if run_check "$2"; then
        ok "$1"
    else
        fail "$1: expected exit 0, got $?; stderr: $(cat "${WORK}/err")"
    fi
}

# expect_fail NAME DIR [NEEDLE]
expect_fail() {
    local rc=0
    run_check "$2" || rc=$?
    if [ "${rc}" -ne 1 ]; then
        fail "$1: expected exit 1, got ${rc}"
        return
    fi
    if [ -n "${3:-}" ] && ! grep -q "$3" "${WORK}/err"; then
        fail "$1: stderr does not mention '$3': $(cat "${WORK}/err")"
        return
    fi
    ok "$1"
}

start 'a test that stays inside tests/ passes'
expect_pass 'self-contained' "$(tree tests/test_x.py <<'PY'
from pathlib import Path
GOLDEN = Path(__file__).resolve().parent / 'golden' / 'pins.json'
PY
)"

start 'the #968 shape is caught'
expect_fail 'reads the rust source' "$(tree tests/test_x.py <<'PY'
from pathlib import Path
RUST_SOURCE = Path(__file__).resolve().parent.parent / 'src' / 'crates' / 'vmdk' / 'src' / 'lib.rs'
PY
)" 'builds a path outside tests/'

start 'the instar-testdata sibling is not matched'
expect_pass 'testdata sibling' "$(tree tests/test_x.py <<'PY'
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent.parent / 'instar-testdata'
PY
)"

start 'a helper addressing tests/golden passes'
expect_pass 'helper inside tests' "$(tree tests/helpers/pins.py <<'PY'
from pathlib import Path
PIN_PATH = Path(__file__).resolve().parent.parent / 'golden' / 'qemu-create-pins.json'
PY
)"

start 'tests/base.py is exempt'
expect_pass 'exempt base.py' "$(tree tests/base.py <<'PY'
from pathlib import Path
binary = Path(__file__).parent.parent / 'src' / 'target' / 'release' / 'instar'
PY
)"

start 'double quotes are caught too'
expect_fail 'double quoted' "$(tree tests/test_x.py <<'PY'
from pathlib import Path
DOCS = Path(__file__).resolve().parent.parent / "docs" / "testing.md"
PY
)" 'builds a path outside tests/'

start 'a top-level directory added later is covered'
expect_fail 'dynamic dir list' "$(tree tests/test_x.py packaging <<'PY'
from pathlib import Path
SPEC = Path(__file__).resolve().parent.parent / 'packaging' / 'instar.spec'
PY
)" 'builds a path outside tests/'

start 'a bare string that is not a path join is not matched'
expect_pass 'bitmap named src' "$(tree tests/test_x.py <<'PY'
CASES = [('empty_merge', [('--add', 'src'), ('--merge', 'src', 'dst')])]
PY
)"

start 'outside a git checkout it exits 2'
NON_GIT="$(mktemp -d "${WORK}/n.XXXXXX")"
mkdir -p "${NON_GIT}/tools/ci"
cp "${CHECK}" "${NON_GIT}/${GUARD}"
RC=0
run_check "${NON_GIT}" || RC=$?
if [ "${RC}" -eq 2 ]; then
    ok 'exit 2 outside a checkout'
else
    fail "expected exit 2 outside a checkout, got ${RC}"
fi

echo ""
if [ "${FAILURES}" -eq 0 ]; then
    echo 'test-check-tests-relocatable: all cases passed.'
else
    echo "test-check-tests-relocatable: ${FAILURES} case(s) failed." >&2
    exit 1
fi
