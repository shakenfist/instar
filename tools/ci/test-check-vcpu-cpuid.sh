#!/usr/bin/env bash
#
# Tests for tools/ci/check-vcpu-cpuid.py.
#
# The guard's whole value is that it fails, so each property it claims to
# enforce is broken here on a copy of the real VMM source and the guard is
# required to notice. Reading the guard cannot distinguish "this holds"
# from "this cannot fail": only mutation can.
#
# Four cases: the tree as it stands must pass, and the three ways the
# property can be lost -- one call site forgetting the helper, the helper
# keeping its name while setting nothing, and the helper disappearing
# altogether -- must each be caught.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-vcpu-cpuid.py"
SOURCE="${REPO_ROOT}/src/vmm/src/main.rs"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# The tree as it stands.
start 'the current source passes'
if python3 "${CHECK}" --source "${SOURCE}" >/dev/null; then
    ok 'guard accepts the tree'
else
    fail 'guard rejects the tree it is supposed to describe'
fi

# One call site forgets the helper. Drop the first setup_cpuid call only,
# so sixteen of the seventeen sites remain correct -- the guard has to
# report the one, not merely notice that the helper is used somewhere.
start 'one vCPU without a setup_cpuid call is caught'
python3 - "${SOURCE}" "${WORK}/one-site-missing.rs" <<'PYEOF'
import sys
src = open(sys.argv[1], encoding='utf-8').read()
needle = '    setup_cpuid(&kvm, &vcpu)?;\n'
assert needle in src, 'the fix no longer spells the call this way'
open(sys.argv[2], 'w', encoding='utf-8').write(src.replace(needle, '', 1))
PYEOF
if python3 "${CHECK}" --source "${WORK}/one-site-missing.rs" >/dev/null 2>&1; then
    fail 'guard passed a vCPU with no CPUID setup'
else
    ok 'guard caught the unprepared vCPU'
fi

# The helper keeps its name and stops setting anything. This is the
# mutation that defeats a guard which only counts call sites.
start 'a hollowed-out setup_cpuid is caught'
python3 - "${SOURCE}" "${WORK}/helper-hollow.rs" <<'PYEOF'
import re
import sys
src = open(sys.argv[1], encoding='utf-8').read()
body = re.search(r'fn setup_cpuid\b.*?\n}\n', src, re.S)
assert body, 'setup_cpuid is not defined as expected'
hollow = 'fn setup_cpuid(kvm: &Kvm, vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {\n    Ok(())\n}\n'
open(sys.argv[2], 'w', encoding='utf-8').write(src.replace(body.group(0), hollow))
PYEOF
if python3 "${CHECK}" --source "${WORK}/helper-hollow.rs" >/dev/null 2>&1; then
    fail 'guard passed a setup_cpuid that sets no CPUID'
else
    ok 'guard caught the hollowed-out helper'
fi

# The helper is gone entirely.
start 'a missing setup_cpuid definition is caught'
grep -v '^fn setup_cpuid\b' "${SOURCE}" > "${WORK}/helper-absent.rs"
if python3 "${CHECK}" --source "${WORK}/helper-absent.rs" >/dev/null 2>&1; then
    fail 'guard passed a source with no setup_cpuid at all'
else
    ok 'guard caught the missing helper'
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} test(s) failed" >&2
    exit 1
fi
echo 'all tests passed'
