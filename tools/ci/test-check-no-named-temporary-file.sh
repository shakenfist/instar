#!/usr/bin/env bash
#
# Tests for tools/ci/check-no-named-temporary-file.sh.
#
# Since every test was converted to ScratchFile, nothing in the tree
# matches the guard, so a pattern that matched nothing at all would look
# exactly like a clean tree. These cases are what show it can fail. The
# positive ones include the shape #959 was about: a refused convert
# inside a `with tempfile.NamedTemporaryFile(...)`.
#
# The guard uses `git grep`, so each fixture is a real git repository
# with the guard copied in: it resolves its repository root from
# BASH_SOURCE.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-no-named-temporary-file.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# tree FILE -- a fresh git repository with the guard installed and the
# heredoc on stdin committed at FILE. Prints the repository's path.
# It runs in a command substitution, so the directory comes from
# mktemp: a counter incremented here would never leave the subshell,
# and every case would share, and accumulate into, one repository.
tree() {
    local dir
    dir="$(mktemp -d "${WORK}/t.XXXXXX")"
    mkdir -p "${dir}/tools/ci" "${dir}/$(dirname "$1")"
    cp "${CHECK}" "${dir}/tools/ci/check-no-named-temporary-file.sh"
    cat > "${dir}/$1"
    git -C "${dir}" init -q
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test \
        add -A
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test \
        commit -q -m fixture
    echo "${dir}"
}

run_check() {
    "$1/tools/ci/check-no-named-temporary-file.sh" > "${WORK}/out" 2> "${WORK}/err"
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
T="$(tree tests/test_plain.py <<'EOF'
from helpers.scratch import ScratchFile

with ScratchFile(suffix='.raw') as out:
    self.run_instar_convert(image.path, Path(out.name))
with tempfile.TemporaryDirectory() as td:
    pass
EOF
)"
expect_pass 'ScratchFile and a TemporaryDirectory' "${T}"
if grep -q 'no test uses NamedTemporaryFile' "${WORK}/out"; then
    ok 'the summary states the tree is clean'
else
    fail "the summary is missing: $(cat "${WORK}/out")"
fi

start 'the shape #959 was about, naming file and line'
T="$(tree tests/test_adversarial.py <<'EOF'
import tempfile


def test_convert_truncated_qcow2(self):
    image = self.get_adversarial_image('qcow2-truncated-header-v2')
    with tempfile.NamedTemporaryFile(suffix='.raw') as out:
        self.run_adversarial(['instar', 'convert', str(image.path), out.name])
EOF
)"
expect_fail 'a refused convert into a NamedTemporaryFile' "${T}" 'tests/test_adversarial.py:6:'

start 'an import by name is caught'
T="$(tree tests/test_import.py <<'EOF'
from tempfile import NamedTemporaryFile
EOF
)"
expect_fail 'from tempfile import NamedTemporaryFile' "${T}" 'tests/test_import.py:1:'

start 'a helper under tests/ is read as well as a test'
T="$(tree tests/helpers/fixtures.py <<'EOF'
f = tempfile.NamedTemporaryFile(suffix='.qcow2')
EOF
)"
expect_fail 'a helper module' "${T}" 'tests/helpers/fixtures.py:1:'

start 'every hit is reported, with a count'
T="$(tree tests/test_two.py <<'EOF'
a = tempfile.NamedTemporaryFile(suffix='.raw')
b = tempfile.NamedTemporaryFile(suffix='.qcow2')
EOF
)"
expect_fail 'both hits named' "${T}" 'tests/test_two.py:1:' \
    'tests/test_two.py:2:' '2 problem(s) found'

start 'tests/helpers/scratch.py is exempt by name, and only it'
SCRATCH="$(cat <<'EOF'
self._file = tempfile.NamedTemporaryFile(*args, delete=False, **kwargs)
EOF
)"
T="$(tree tests/helpers/scratch.py <<< "${SCRATCH}")"
expect_pass 'ScratchFile itself' "${T}"
T="$(tree tests/helpers/other.py <<< "${SCRATCH}")"
expect_fail 'the same line in another file' "${T}" 'tests/helpers/other.py:1:'

start 'code outside tests/ is not read'
T="$(tree tools/ci/thing.py <<'EOF'
with tempfile.NamedTemporaryFile() as f:
    pass
EOF
)"
expect_pass 'a tool' "${T}"

start 'a git failure is an error, not a clean tree'
T="${WORK}/not-a-repo"
mkdir -p "${T}/tools/ci"
cp "${CHECK}" "${T}/tools/ci/check-no-named-temporary-file.sh"
STATUS=0
GIT_CEILING_DIRECTORIES="${WORK}" run_check "${T}" || STATUS=$?
if [ "${STATUS}" -eq 2 ] && grep -q 'git grep failed' "${WORK}/err"; then
    ok 'running outside a git checkout exits 2, naming git'
else
    fail "outside a checkout: exit ${STATUS}, stderr: $(cat "${WORK}/err")"
fi

if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-no-named-temporary-file: ${FAILURES} test(s) failed" >&2
    exit 1
fi
echo 'test-check-no-named-temporary-file: all tests passed'
