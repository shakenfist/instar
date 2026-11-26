#!/usr/bin/env bash
#
# Tests for tools/ci/check-vmdk-split-pins.py.
#
# The guard passes on the tree as committed, so a guard that checked nothing
# would look exactly like agreeing literals. These cases are what show it can
# fail: each points --source at a copy of the Rust file with one deliberate
# change, and at an empty directory in place of the testdata clone.
#
# The absent-fixture case is the one worth keeping honest. That check is the
# only witness for the 33 GiB descriptor -- past sixteen extents and past
# 65535 cylinders -- so its absence has to be a failure rather than a quiet
# pass, and --no-fixture is the only way to say otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-vmdk-split-pins.py"
SOURCE="${REPO_ROOT}/src/crates/vmdk/src/lib.rs"

if [ -n "${INSTAR_TESTDATA_PATH:-}" ]; then
    TESTDATA="${INSTAR_TESTDATA_PATH}"
else
    TESTDATA="$(cd "${REPO_ROOT}/.." && pwd)/instar-testdata"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

EMPTY="${WORK}/no-testdata"
mkdir -p "${EMPTY}"

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# mutate NAME SED_EXPR -- a copy of the Rust file with SED_EXPR applied.
# Fails loudly when the expression changed nothing, which would otherwise
# make the case below pass against an unmutated file.
mutate() {
    local out="${WORK}/$1.rs"
    sed "$2" "${SOURCE}" > "${out}"
    if cmp -s "${SOURCE}" "${out}"; then
        fail "$1: the mutation changed nothing; the pattern no longer matches the source"
        return 1
    fi
    echo "${out}"
}

# expect NAME WANTED_RC NEEDLE -- runs the guard with the remaining arguments.
expect() {
    local name="$1" wanted="$2" needle="$3"; shift 3
    local rc=0
    python3 "${CHECK}" "$@" > "${WORK}/out" 2> "${WORK}/err" || rc=$?
    if [ "${rc}" -ne "${wanted}" ]; then
        fail "${name}: expected exit ${wanted}, got ${rc}; stderr: $(head -c 300 "${WORK}/err")"
        return
    fi
    if [ -n "${needle}" ] && ! grep -q -- "${needle}" "${WORK}/out" "${WORK}/err"; then
        fail "${name}: output does not mention '${needle}'"
        return
    fi
    ok "${name}"
}

start 'the tree as committed passes'
expect 'clean, no fixture' 0 'not checked' --no-fixture
if [ -d "${TESTDATA}" ]; then
    expect 'clean, with fixture' 0 'checked against the fixture' --testdata "${TESTDATA}"
else
    echo "    skip: no testdata clone at ${TESTDATA}"
fi

start 'a changed descriptor literal is caught'
if MUT="$(mutate createtype 's/createType=\\"twoGbMaxExtentSparse\\"/createType=\\"twoGbMaxExtentSparsX\\"/')"; then
    expect 'createType drift' 1 'is not in the Rust source' --no-fixture --source "${MUT}"
fi

start 'a renamed fixture constant is caught'
if [ -d "${TESTDATA}" ]; then
    if MUT="$(mutate renamed 's/const QEMU_SPLIT_SPARSE_33G:/const QEMU_SPLIT_SPARSE_33G_OLD:/')"; then
        expect 'fixture constant absent' 1 'absent from the Rust source entirely' \
            --testdata "${TESTDATA}" --source "${MUT}"
    fi
else
    echo "    skip: no testdata clone at ${TESTDATA}"
fi

start 'an absent testdata clone is a failure, not a pass'
expect 'absent testdata fails' 1 'is unchecked' --testdata "${EMPTY}"

start 'and --no-fixture is the only way to say so deliberately'
expect 'absent testdata waived' 0 'not checked' --testdata "${EMPTY}" --no-fixture

start 'an absent Rust source exits 2'
expect 'missing source' 2 'the Rust source is absent' --no-fixture --source "${WORK}/nope.rs"

echo ""
if [ "${FAILURES}" -eq 0 ]; then
    echo 'test-check-vmdk-split-pins: all cases passed.'
else
    echo "test-check-vmdk-split-pins: ${FAILURES} case(s) failed." >&2
    exit 1
fi
