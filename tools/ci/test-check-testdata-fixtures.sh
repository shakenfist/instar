#!/usr/bin/env bash
#
# Tests for tools/ci/check-testdata-fixtures.sh.
#
# The case that matters is a *missing* fixture. Before this check
# existed, the canary loops in prepare-testdata.sh and
# test-package-functional.sh skipped past an absent fixture and failed
# only when every canary was gone, so a partial checkout removed the
# tests that depend on it and CI stayed green -- the same shape of
# defect as a gate that passes because it examined nothing. The missing
# and pointer cases below are the two that must fail, and the
# all-present case is what proves they are not failing for an unrelated
# reason.
#
# Fixtures here are plain files, not real images: the check reads only
# the first 64 bytes looking for an LFS pointer header, so a text file
# containing that header exercises the pointer branch exactly, and any
# other content exercises the healthy branch.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-testdata-fixtures.sh"
MANIFEST="${REPO_ROOT}/tests/manifest.json"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

LFS_HEADER='version https://git-lfs.github.com/spec/v1'

# The list the check enforces, asked of the check itself so the two
# cannot drift. An earlier version parsed the array out of the source
# with a sed range, which depended on each entry being double-quoted on
# its own line: reformatting the array would have returned fewer
# entries and quietly shrunk every generated case below. --list cannot
# be wrong about its own array.
required() {
    "${CHECK}" --list
}

# populate DIR [--omit REL] [--pointer REL] -- build a testdata tree
# holding every required fixture, optionally omitting one or writing one
# as an LFS pointer instead of content.
populate() {
    local dir="$1" omit="" pointer="" rel
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --omit) omit="$2"; shift 2 ;;
            --pointer) pointer="$2"; shift 2 ;;
            *) echo "populate: bad arg $1" >&2; return 1 ;;
        esac
    done
    while IFS= read -r rel; do
        [ "${rel}" = "${omit}" ] && continue
        mkdir -p "${dir}/$(dirname "${rel}")"
        if [ "${rel}" = "${pointer}" ]; then
            printf '%s\noid sha256:0\nsize 1\n' "${LFS_HEADER}" > "${dir}/${rel}"
        else
            printf 'not-an-lfs-pointer\n' > "${dir}/${rel}"
        fi
    done < <(required)
}

# expect NAME EXPECTED_RC WANT_IN_STDERR -- run the check over DIR and
# compare the exit code, and (when non-empty) require a stderr mention.
expect() {
    local name="$1" want_rc="$2" want_err="$3" dir="$4"
    shift 4
    local rc err
    "${CHECK}" "${dir}" "$@" >"${WORK}/out" 2>"${WORK}/err"
    rc=$?
    err="$(cat "${WORK}/err")"
    if [ "${rc}" -ne "${want_rc}" ]; then
        fail "${name} (exit ${rc}, want ${want_rc})"
        sed 's/^/      /' "${WORK}/err" >&2
        return
    fi
    if [ -n "${want_err}" ] && [[ "${err}" != *"${want_err}"* ]]; then
        fail "${name} (exit code matched but stderr did not mention '${want_err}')"
        sed 's/^/      /' "${WORK}/err" >&2
        return
    fi
    ok "${name}"
}

# The expected total is written down rather than derived, because every
# other case here reads the list out of the check: dropping an entry
# would shrink the check and the generated cases together, and nothing
# would notice. This is the one assertion that must be updated by hand
# when a fixture is deliberately added or removed.
EXPECTED_REQUIRED=3

count="$(required | grep -c .)"
start "the required-fixture list is non-empty and parseable"
if [ "${count}" -lt 1 ]; then
    fail "could not parse REQUIRED_FIXTURES out of ${CHECK}"
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
if [ "${count}" -eq "${EXPECTED_REQUIRED}" ]; then
    ok "${count} required fixture(s) declared"
else
    fail "REQUIRED_FIXTURES declares ${count} fixture(s), expected ${EXPECTED_REQUIRED}" \
         "-- if this change is deliberate, update EXPECTED_REQUIRED here"
fi

start "every required fixture has a tests/manifest.json entry"
missing_manifest=0
while IFS= read -r rel; do
    if ! grep -qF "\"${rel}\"" "${MANIFEST}"; then
        fail "no manifest.json entry for ${rel}"
        missing_manifest=1
    fi
done < <(required)
if [ "${missing_manifest}" -eq 0 ]; then
    ok "all ${count} paths appear in tests/manifest.json"
fi

start "a complete, materialised checkout passes"
GOOD="${WORK}/good"
populate "${GOOD}"
expect "complete checkout exits 0" 0 "" "${GOOD}"

start "a missing fixture fails, naming it"
while IFS= read -r rel; do
    dir="${WORK}/omit-$(echo "${rel}" | tr '/.' '__')"
    populate "${dir}" --omit "${rel}"
    expect "missing ${rel} is refused" 1 "${rel}" "${dir}"
done < <(required)

start "an un-materialised LFS pointer fails, naming it"
while IFS= read -r rel; do
    dir="${WORK}/ptr-$(echo "${rel}" | tr '/.' '__')"
    populate "${dir}" --pointer "${rel}"
    expect "pointer ${rel} is refused" 1 "${rel}" "${dir}"
done < <(required)

start "an empty checkout fails"
EMPTY="${WORK}/empty"
mkdir -p "${EMPTY}"
expect "empty checkout is refused" 1 "missing required fixture" "${EMPTY}"

start "a nonexistent path fails"
expect "nonexistent path is refused" 1 "does not exist" "${WORK}/no-such-dir"

start "--annotate emits a GitHub Actions error annotation"
expect "annotated failure is refused" 1 "::error::" "${EMPTY}" --annotate

start "no argument fails rather than passing vacuously"
if "${CHECK}" >/dev/null 2>"${WORK}/err"; then
    fail "no argument exited 0"
else
    if grep -q 'usage:' "${WORK}/err"; then
        ok "no argument is refused with a usage message"
    else
        fail "no argument was refused but printed no usage message"
    fi
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all check-testdata-fixtures tests passed"
