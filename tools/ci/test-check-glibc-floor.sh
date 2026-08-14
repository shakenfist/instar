#!/usr/bin/env bash
#
# Tests for tools/ci/check-glibc-floor.sh.
#
# The check guards a promise (glibc 2.31+, Debian 11+) that nothing else
# on the pull request path looks at, so a silent inversion of its
# comparison would restore exactly the hole it was written to close. The
# equality boundary is the interesting one: floor == ceiling must pass,
# and it is the case a later simplification of the sort -V comparison is
# most likely to get wrong.
#
# Fixtures are plain files containing literal GLIBC_x.y strings rather
# than real ELF binaries. That exercises the grep fallback directly; the
# objdump path is covered against a real binary when one is available.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-glibc-floor.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# Fixtures are read by the fallback, so keep objdump off the PATH for
# them: objdump on a non-ELF file produces no symbols at all, which
# would exercise the wrong branch. Emptying PATH is not an option --
# the script needs grep, sed, sort and tail — so build a PATH that has
# those and nothing else.
SHIM="${WORK}/bin"
mkdir -p "${SHIM}"
for tool in grep sed sort tail; do
    ln -s "$(command -v "${tool}")" "${SHIM}/${tool}"
done
if [ -e "${SHIM}/objdump" ]; then
    echo "the shim PATH must not provide objdump" >&2
    exit 1
fi

# Resolved now, and invoked by absolute path below: env looks the
# interpreter up on the PATH it is handing over, and the shim does not
# carry one.
BASH_BIN="$(command -v bash)"

run_fallback() {
    # run_fallback CEILING FIXTURE -> exit status, output on stdout
    env PATH="${SHIM}" MAX_GLIBC="$1" "${BASH_BIN}" "${CHECK}" "$2" 2>&1
}

fixture() {
    # fixture NAME VERSION... -> path
    local name="$1"
    shift
    local path="${WORK}/${name}"
    : > "${path}"
    for version in "$@"; do
        printf 'GLIBC_%s\n' "${version}" >> "${path}"
    done
    echo "${path}"
}

expect_status() {
    # expect_status DESCRIPTION EXPECTED CEILING FIXTURE
    local status=0
    run_fallback "$3" "$4" > /dev/null 2>&1 || status=$?
    if [ "${status}" = "$2" ]; then
        ok "$1"
    else
        fail "$1: expected exit ${2}, got ${status}"
    fi
}

BELOW="$(fixture below 2.2.5 2.14 2.30)"
EQUAL="$(fixture equal 2.14 2.31)"
ABOVE="$(fixture above 2.14 2.39)"

start "the ceiling comparison"
expect_status "a floor below the ceiling passes" 0 2.31 "${BELOW}"
expect_status "a floor equal to the ceiling passes" 0 2.31 "${EQUAL}"
expect_status "a floor above the ceiling fails" 1 2.31 "${ABOVE}"
expect_status "the default ceiling is not looser than 2.31" 1 "" "${ABOVE}"

start "version ordering is numeric, not lexical"
# 2.9 < 2.10 numerically but sorts after it as text, so a lexical
# comparison would wrongly fail this fixture against a 2.31 ceiling.
LEXICAL="$(fixture lexical 2.9 2.10)"
expect_status "2.10 outranks 2.9" 0 2.31 "${LEXICAL}"

start "the reported floor is the highest version present"
OUTPUT="$(run_fallback 2.39 "${ABOVE}")"
case "${OUTPUT}" in
    *"at most GLIBC_2.39"*) ok "reports the maximum, not the last seen" ;;
    *) fail "expected the maximum in '${OUTPUT}'" ;;
esac

start "failure output explains where to look"
OUTPUT="$(run_fallback 2.31 "${ABOVE}" || true)"
case "${OUTPUT}" in
    *"src/.devcontainer/build/Dockerfile"*)
        ok "names the Dockerfile that sets the floor" ;;
    *) fail "expected the Dockerfile path in '${OUTPUT}'" ;;
esac

start "error paths"
expect_status "a missing binary fails" 1 2.31 "${WORK}/does-not-exist"
NO_SYMBOLS="$(fixture no-symbols)"
printf 'no version strings here\n' > "${NO_SYMBOLS}"
expect_status "a file with no GLIBC symbols fails" 1 2.31 "${NO_SYMBOLS}"

start "objdump and the fallback agree"
# Only meaningful against a real dynamically linked binary. The point is
# that the two extraction paths return the same set, which is the
# assumption the fallback rests on.
REAL_BINARY=""
for candidate in "${REPO_ROOT}/src/target/release/instar" /bin/ls; do
    if [ -f "${candidate}" ]; then
        REAL_BINARY="${candidate}"
        break
    fi
done
if [ -z "${REAL_BINARY}" ] || ! command -v objdump > /dev/null 2>&1; then
    ok "skipped: needs objdump and a dynamically linked binary"
else
    VIA_OBJDUMP="$(objdump -T "${REAL_BINARY}" \
        | grep -o 'GLIBC_[0-9]\+\.[0-9]\+' | sort -uV)"
    VIA_GREP="$(grep -ao 'GLIBC_[0-9]\+\.[0-9]\+' "${REAL_BINARY}" | sort -uV)"
    if [ "${VIA_OBJDUMP}" = "${VIA_GREP}" ]; then
        ok "both paths extract the same versions from ${REAL_BINARY}"
    else
        fail "objdump and grep disagree on ${REAL_BINARY}"
    fi
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
