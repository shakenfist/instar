#!/usr/bin/env bash
#
# Tests for tools/ci/dnf.sh, run against a fake dnf.
#
# The wrapper only does anything while a distro's repository metadata is
# inconsistent, which no CI run arranges on purpose. A retry loop that
# had stopped retrying, or that retried every failure, would pass every
# ordinary run and be discovered on the next unlucky mirror rotation --
# in a matrix leg, hours into a merge-queue run.
#
# Contract (see the script's header): the arguments reach dnf unchanged
# and in order, with nothing added; a metadata failure is retried, with
# `clean metadata` between attempts, until one deadline expires; any
# other failure is returned at once with its own status.
#
# Pure bash: no sudo, no dnf, no network.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/dnf.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

# The fake fails with FAKE_MESSAGE for its first FAKE_FAILS resolving
# calls (forever if negative), then behaves as FAKE_RESULT says. A
# `clean` always succeeds and is not counted as an attempt, so the
# assertions below can tell the two apart. Each call appends its
# arguments to calls.txt.
FAKE="${WORK}/fake-dnf"
cat >"${FAKE}" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_DIR}/calls.txt"
if [ "${1:-}" = clean ]; then
    exit 0
fi
attempts=$(grep -cv '^clean' "${FAKE_DIR}/calls.txt")
if [ "${FAKE_FAILS}" -lt 0 ] || [ "${attempts}" -le "${FAKE_FAILS}" ]; then
    echo "${FAKE_MESSAGE}" >&2
    exit 1
fi
case "${FAKE_RESULT}" in
    ok) echo 'fake dnf: done'; exit 0 ;;
    *) echo 'Error: Unable to find a match: nonesuch' >&2; exit "${FAKE_RESULT}" ;;
esac
EOF
chmod +x "${FAKE}"

# The three wordings a metadata failure arrives in: dnf4, dnf5, and the
# mirror line, which comes from librepo rather than from dnf at all.
DNF4_MESSAGE="Error: Failed to download metadata for repo 'appstream':"
DNF4_MESSAGE="${DNF4_MESSAGE} Yum repo downloading error"
DNF5_MESSAGE="Failed to synchronize cache for repo 'appstream'"
MIRROR_MESSAGE='repodata/8dad4ae7-primary.xml.gz - Cannot download,'
MIRROR_MESSAGE="${MIRROR_MESSAGE} all mirrors were already tried without success"

FAILURES=0

fail() {
    printf 'FAIL %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

run() {
    # run FAILS RESULT TIMEOUT MESSAGE ARGS...
    #   -- sets STATUS, ATTEMPTS, CLEANS, OUTPUT
    # The outer timeout turns a wrapper that never gives up into a
    # failed assertion (exit 124) rather than a hung CI step.
    local fails="$1" result="$2" timeout="$3" message="$4"
    shift 4
    rm -f "${WORK}/calls.txt"
    touch "${WORK}/calls.txt"
    OUTPUT="$(FAKE_DIR="${WORK}" FAKE_FAILS="${fails}" \
        FAKE_RESULT="${result}" FAKE_MESSAGE="${message}" DNF="${FAKE}" \
        DNF_RETRY_TIMEOUT="${timeout}" DNF_RETRY_INTERVAL=1 \
        timeout 20 "${SCRIPT}" "$@" 2>&1)"
    STATUS=$?
    ATTEMPTS=$(grep -cv '^clean' "${WORK}/calls.txt")
    CLEANS=$(grep -c '^clean' "${WORK}/calls.txt")
}

# Success first time: one call, the arguments in order and nothing
# added. The wrapper is a pass-through on the happy path, which is
# every run but the unlucky one.
run 0 ok 300 "${DNF4_MESSAGE}" install -y --setopt=install_weak_deps=False /pkg/instar.rpm
[ "${STATUS}" -eq 0 ] || fail "success: exit ${STATUS}, wanted 0"
[ "${ATTEMPTS}" -eq 1 ] || fail "success: ${ATTEMPTS} attempts, wanted 1"
[ "${CLEANS}" -eq 0 ] || fail "success: cleaned metadata without a failure"
WANTED='install -y --setopt=install_weak_deps=False /pkg/instar.rpm'
[ "$(cat "${WORK}/calls.txt")" = "${WANTED}" ] \
    || fail "success: dnf got '$(cat "${WORK}/calls.txt")'"
[[ "${OUTPUT}" == *'fake dnf: done'* ]] \
    || fail "success: dnf's output did not reach the caller"

# A metadata failure is retried until the mirrors agree again, and the
# stale copy is discarded before each retry rather than being asked
# the same question twice.
for message in "${DNF4_MESSAGE}" "${DNF5_MESSAGE}" "${MIRROR_MESSAGE}"; do
    run 2 ok 300 "${message}" install -y qemu-img
    [ "${STATUS}" -eq 0 ] || fail "retried (${message:0:40}): exit ${STATUS}, wanted 0"
    [ "${ATTEMPTS}" -eq 3 ] \
        || fail "retried (${message:0:40}): ${ATTEMPTS} attempts, wanted 3"
    [ "${CLEANS}" -eq 2 ] \
        || fail "retried (${message:0:40}): ${CLEANS} cleans, wanted 2"
    [ "$(sed -n 2p "${WORK}/calls.txt")" = 'clean metadata' ] \
        || fail "retried (${message:0:40}): the retry reused the metadata that failed"
done

# Any other failure is returned at once, with its own status: an
# unknown package is an answer, not weather.
run 0 42 300 "${DNF4_MESSAGE}" install -y nonesuch
[ "${STATUS}" -eq 42 ] || fail "other failure: exit ${STATUS}, wanted 42"
[ "${ATTEMPTS}" -eq 1 ] \
    || fail "other failure: ${ATTEMPTS} attempts, wanted 1 (it was retried)"
[ "${CLEANS}" -eq 0 ] \
    || fail 'other failure: metadata was cleaned for an unrelated failure'

# Metadata that never recovers fails the step once the deadline passes,
# with dnf's own status and a message saying why.
run -1 ok 3 "${MIRROR_MESSAGE}" install -y qemu-img
[ "${STATUS}" -eq 1 ] || fail "wedged mirrors: exit ${STATUS}, wanted 1"
[ "${ATTEMPTS}" -ge 2 ] || fail "wedged mirrors: ${ATTEMPTS} attempts, wanted at least 2"
[[ "${OUTPUT}" == *'still unusable after 3s'* ]] \
    || fail 'wedged mirrors: no message naming the deadline'

if [ "${FAILURES}" -ne 0 ]; then
    echo "dnf: ${FAILURES} assertion(s) failed" >&2
    exit 1
fi
echo 'dnf: contract holds'
