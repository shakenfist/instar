#!/usr/bin/env bash
#
# Tests for tools/ci/check-no-runtime-luks-create.sh.
#
# Since the tests that made LUKS images were converted to the fixture,
# nothing in the tree matches the guard, so a pattern that matched
# nothing at all would look exactly like a clean tree. These cases are
# what show it can fail. The positive ones include the two argv lists
# the conversion deleted from test_bench.py and test_compare.py, and
# the `]`-inside-the-list shape that defeated the guard's first,
# argv-shaped pattern.
#
# The guard uses `git grep`, so each fixture is a real git repository
# with the guard copied in: it resolves its repository root from
# BASH_SOURCE.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-no-runtime-luks-create.sh"

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
    cp "${CHECK}" "${dir}/tools/ci/check-no-runtime-luks-create.sh"
    cat > "${dir}/$1"
    git -C "${dir}" init -q
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test \
        add -A
    git -C "${dir}" -c user.email=test@example.com -c user.name=Test \
        commit -q -m fixture
    echo "${dir}"
}

run_check() {
    "$1/tools/ci/check-no-runtime-luks-create.sh" > "${WORK}/out" 2> "${WORK}/err"
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
r = subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(img), '16M'])
image = self.get_image('qcow2-luks')
EOF
)"
expect_pass 'a non-LUKS create and a fixture read' "${T}"
if grep -q 'no test makes a LUKS image' "${WORK}/out"; then
    ok 'the summary states the tree is clean'
else
    fail "the summary is missing: $(cat "${WORK}/out")"
fi

start 'the argv test_bench.py used to build, naming file and line'
T="$(tree tests/test_bench.py <<'EOF'
import subprocess


def test_refuse_luks(self):
    r = subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2',
         '--object', 'secret,id=sec0,data=test-passphrase',
         '-o', 'encrypt.format=luks,encrypt.key-secret=sec0,encrypt.iter-time=10',
         str(img), '16M'],
        capture_output=True, text=True, timeout=30)
EOF
)"
expect_fail 'the bench argv' "${T}" 'tests/test_bench.py:8:'

start 'the argv test_compare.py used to build'
T="$(tree tests/test_compare.py <<'EOF'
self._run_tool(
    ['qemu-img', 'create',
     '--object', 'secret,id=sec0,data=correct-horse',
     '-f', 'qcow2',
     '-o', 'encrypt.format=luks,encrypt.key-secret=sec0',
     'luks.qcow2', '1M'],
    td)
EOF
)"
expect_fail 'the compare argv' "${T}" 'tests/test_compare.py:5:'

# The backticks below are literal text in a test name, not a command
# substitution to expand.
# shellcheck disable=SC2016
start 'a `]` inside the list does not hide it'
# The argv-shaped pattern this guard replaced stopped at the first `]`,
# so a subscript in an f-string before the option let it through.
T="$(tree tests/test_subscript.py <<'EOF'
subprocess.run(['qemu-img', 'convert', '-O', 'qcow2',
                '--object', f'secret,id=sec0,data={self.PASSPHRASES[0]}',
                '-o', 'encrypt.format=luks,encrypt.key-secret=sec0',
                src, dst])
EOF
)"
expect_fail 'a subscript before the option' "${T}" 'tests/test_subscript.py:3:'

start 'cryptsetup luksFormat is caught too'
T="$(tree tests/test_raw_luks.py <<'EOF'
subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', str(img)],
               input=b'passphrase')
EOF
)"
expect_fail 'a cryptsetup luksFormat' "${T}" 'tests/test_raw_luks.py:1:'

start 'shell under tests/ is read as well as Python'
T="$(tree tests/helpers/make.sh <<'EOF'
qemu-img create -f qcow2 -o encrypt.format=luks,encrypt.key-secret=s x 1M
EOF
)"
expect_fail 'a shell helper' "${T}" 'tests/helpers/make.sh:1:'

start 'every hit is reported, with a count'
T="$(tree tests/test_two.py <<'EOF'
a = ['qemu-img', 'create', '-o', 'encrypt.format=luks', 'a', '1M']
b = ['cryptsetup', 'luksFormat', 'b']
EOF
)"
expect_fail 'both hits named' "${T}" 'tests/test_two.py:1:' \
    'tests/test_two.py:2:' '2 problem(s) found'

start 'test_measure.py is exempt by name, and only it'
MEASURE="$(cat <<'EOF'
def test_o_encrypt_format_rejected(self):
    """``-o encrypt.format=luks`` exits non-zero; LUKS is not yet supported."""
    stdout, stderr, rc = self.run_instar_measure(
        '--size', '1M', '-O', 'qcow2', '-o', 'encrypt.format=luks'
    )
EOF
)"
T="$(tree tests/test_measure.py <<< "${MEASURE}")"
expect_pass 'instar measure refusing the option' "${T}"
# The exemption is a file name, not a shape: the same lines anywhere
# else are flagged, so a new mention needs a reviewed entry.
T="$(tree tests/test_other.py <<< "${MEASURE}")"
expect_fail 'the same lines in another file' "${T}" 'tests/test_other.py:2:'

start 'the generators under scripts/ are not read'
T="$(tree scripts/create-qcow2-luks-testdata.sh <<'EOF'
qemu-img create -f qcow2 -o encrypt.format=luks,encrypt.key-secret=sec0 x 10M
EOF
)"
expect_pass 'a fixture generator' "${T}"

start 'a git failure is an error, not a clean tree'
T="${WORK}/not-a-repo"
mkdir -p "${T}/tools/ci"
cp "${CHECK}" "${T}/tools/ci/check-no-runtime-luks-create.sh"
STATUS=0
GIT_CEILING_DIRECTORIES="${WORK}" run_check "${T}" || STATUS=$?
if [ "${STATUS}" -eq 2 ] && grep -q 'git grep failed' "${WORK}/err"; then
    ok 'running outside a git checkout exits 2, naming git'
else
    fail "outside a checkout: exit ${STATUS}, stderr: $(cat "${WORK}/err")"
fi

if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-no-runtime-luks-create: ${FAILURES} test(s) failed" >&2
    exit 1
fi
echo 'test-check-no-runtime-luks-create: all tests passed'
