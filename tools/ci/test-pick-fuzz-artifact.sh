#!/usr/bin/env bash
#
# Tests for tools/ci/pick-fuzz-artifact.sh.
#
# The selector used to be inline YAML in coverage-fuzz.yml and only ever
# ran when a target actually crashed, which is how it shipped a bug that
# could report a 0-byte file as a crash reproducer. These cases cover
# the states an artifacts directory can be in after a fuzz run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PICK="${REPO_ROOT}/tools/ci/pick-fuzz-artifact.sh"

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

# Each case gets a fresh directory built from a list of "name:bytes"
# specs; bytes of 0 makes an empty file.
setup() {
    D="${WORK}/case"
    rm -rf "${D}"
    mkdir -p "${D}"
    for SPEC in "$@"; do
        NAME="${SPEC%%:*}"
        SIZE="${SPEC##*:}"
        if [ "${SIZE}" = "0" ]; then
            : > "${D}/${NAME}"
        else
            head -c "${SIZE}" < /dev/zero | tr '\0' 'x' > "${D}/${NAME}"
        fi
    done
}

pick() { "${PICK}" "$1" "${D}"; }

start "a single crash artifact is chosen"
setup "crash-aaa:100"
check "crash picked" "$(pick crash)" "${D}/crash-aaa"
check "no minimized file yet" "$(pick minimized)" ""

start "an empty crash artifact is still reported"
# libFuzzer writes a 0-byte crash-* when a target panics on the empty
# input. Rejecting it would send the workflow down its no-artifact
# branch, which files nothing and tells the reader to check the build
# -- pointing away from a real crash. Only minimized-from-* needs the
# empty-file filter, where empty means tmin failed.
setup "crash-aaa:0"
check "empty crash reported" "$(pick crash)" "${D}/crash-aaa"

# With only the 0-byte crash present the catch-all branch would return
# it either way, so pair it with a lower-ranked artifact: the crash has
# to win on rank, not fall through on size.
setup "crash-aaa:0" "timeout-zzz:100"
check "empty crash still outranks a timeout" \
    "$(pick crash)" "${D}/crash-aaa"

start "a failed minimization does not become the reproducer"
setup "crash-aaa:100" "minimized-from-aaa:0"
check "crash still picked" "$(pick crash)" "${D}/crash-aaa"
check "empty minimized rejected" "$(pick minimized)" ""

start "a successful minimization is offered"
setup "crash-aaa:100" "minimized-from-aaa:10"
check "crash unaffected" "$(pick crash)" "${D}/crash-aaa"
check "minimized offered" "$(pick minimized)" "${D}/minimized-from-aaa"

start "a minimized file is never picked as the crash input"
# Otherwise tmin would be pointed at its own previous output.
setup "minimized-from-aaa:10"
check "minimized not picked as crash" "$(pick crash)" ""

start "selection is deterministic across several crashes"
setup "crash-ccc:100" "crash-aaa:100" "crash-bbb:100"
check "lowest name picked" "$(pick crash)" "${D}/crash-aaa"
check "stable on a second call" "$(pick crash)" "${D}/crash-aaa"

start "a real crash outranks a slow unit"
# The inversion that made lexicographic ordering wrong: a slow unit is
# any input over 10s, so one can be sitting in the directory when a
# genuine crash arrives.
setup "slow-unit-aaa:100" "crash-zzz:100"
check "crash preferred over slow unit" "$(pick crash)" "${D}/crash-zzz"

start "a timeout outranks a slow unit"
# lexicographically slow-unit- sorts BEFORE timeout-, so a plain sort
# reports the slow unit as the reproducer for the timeout.
setup "slow-unit-aaa:100" "timeout-zzz:100"
check "timeout preferred over slow unit" "$(pick crash)" "${D}/timeout-zzz"

start "oom and leak artifacts are reported when they are all there is"
setup "oom-aaa:100"
check "oom picked" "$(pick crash)" "${D}/oom-aaa"
setup "leak-aaa:100"
check "leak picked" "$(pick crash)" "${D}/leak-aaa"

start "an unrecognised prefix is still reported"
# Better a reproducer we did not anticipate than no reproducer at all.
setup "something-new-aaa:100"
check "unknown prefix picked" "$(pick crash)" "${D}/something-new-aaa"

start "an empty artifacts directory yields nothing"
setup
check "no crash" "$(pick crash)" ""
check "no minimized" "$(pick minimized)" ""

start "a missing artifacts directory yields nothing, not an error"
D="${WORK}/does-not-exist"
STATUS=0
OUT="$(pick crash)" || STATUS=$?
check "exited 0" "${STATUS}" "0"
check "printed nothing" "${OUT}" ""

start "subdirectories are not descended into"
# src/fuzz/artifacts/ is per-target, but a stray directory must not
# turn into a reproducer path.
setup "crash-aaa:100"
mkdir -p "${D}/nested"
head -c 100 < /dev/zero | tr '\0' 'x' > "${D}/nested/crash-000"
check "nested file ignored" "$(pick crash)" "${D}/crash-aaa"

start "a large artifacts directory does not make the picker fail"
# `find | sort | head -1` exits 141 once sort's output outgrows the
# 64KB pipe buffer and it takes EPIPE. Under this script's
# `set -euo pipefail` that beats its own `exit 0`, and the workflow
# call site is a bare `CRASH_FILE=$(...)` under `bash -e` -- so the
# fuzz step would abort at the first crash, which is the entire failure
# this script was extracted to prevent. Every other case here uses one
# to three files and so cannot see it.
D="${WORK}/many"
mkdir -p "${D}"
python3 - "${D}" <<'PY'
import sys
d = sys.argv[1]
for i in range(3000):
    with open(f'{d}/crash-{i:06d}', 'w') as f:
        f.write('x' * 40)
PY
STATUS=0
OUT="$(pick crash)" || STATUS=$?
check "exited 0 with 3000 artifacts" "${STATUS}" "0"
check "still returned the first artifact" "${OUT}" "${D}/crash-000000"

STATUS=0
OUT="$(pick minimized)" || STATUS=$?
check "minimized mode exited 0 too" "${STATUS}" "0"

# The shape the workflow actually uses.
STATUS=0
bash -e -c "CRASH_FILE=\$('${PICK}' crash '${D}'); [ -n \"\${CRASH_FILE}\" ]" \
    || STATUS=$?
check "survives a bare assignment under bash -e" "${STATUS}" "0"

start "bad arguments are rejected"
if "${PICK}" crash > /dev/null 2>&1; then
    fail "missing directory accepted"
else
    ok "missing directory rejected"
fi
if "${PICK}" nonsense "${WORK}" > /dev/null 2>&1; then
    fail "unknown mode accepted"
else
    ok "unknown mode rejected"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
