#!/usr/bin/env bash
#
# Tests for tools/ci/apt-get.sh, run against a fake apt-get.
#
# The wrapper only does anything when a runner's own apt job holds a
# lock, which no CI run arranges on purpose. A retry loop that had
# stopped retrying, or that retried every failure, would pass every
# ordinary run and be discovered on the next unlucky boot.
#
# Contract (see the script's header): the arguments reach apt-get in
# order behind `-o DPkg::Lock::Timeout`; a "Could not get lock" failure
# is retried until one deadline expires; any other failure is returned
# at once with its own status.
#
# Pure bash: no sudo, no apt, no network.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/apt-get.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

# The fake fails on a held lock for its first FAKE_LOCK_FAILS calls
# (forever if negative), then behaves as FAKE_RESULT says. Each call
# appends its arguments to calls.txt.
FAKE="${WORK}/fake-apt-get"
cat >"${FAKE}" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_DIR}/calls.txt"
calls=$(wc -l <"${FAKE_DIR}/calls.txt")
if [ "${FAKE_LOCK_FAILS}" -lt 0 ] || [ "${calls}" -le "${FAKE_LOCK_FAILS}" ]; then
    echo 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 1 (apt-get)' >&2
    exit 100
fi
case "${FAKE_RESULT}" in
    ok) echo 'fake apt-get: done'; exit 0 ;;
    *) echo 'E: Unable to locate package nonesuch' >&2; exit "${FAKE_RESULT}" ;;
esac
EOF
chmod +x "${FAKE}"

FAILURES=0

fail() {
    printf 'FAIL %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

run() {
    # run LOCK_FAILS RESULT TIMEOUT ARGS... -- sets STATUS, CALLS, OUTPUT
    # The outer timeout turns a wrapper that never gives up into a
    # failed assertion (exit 124) rather than a hung CI step.
    local lock_fails="$1" result="$2" timeout="$3"
    shift 3
    rm -f "${WORK}/calls.txt"
    touch "${WORK}/calls.txt"
    OUTPUT="$(FAKE_DIR="${WORK}" FAKE_LOCK_FAILS="${lock_fails}" \
        FAKE_RESULT="${result}" APT_GET="${FAKE}" \
        APT_LOCK_TIMEOUT="${timeout}" APT_LOCK_RETRY_INTERVAL=1 \
        timeout 20 "${SCRIPT}" "$@" 2>&1)"
    STATUS=$?
    CALLS=$(wc -l <"${WORK}/calls.txt")
}

# Success first time: one call, the option first, the arguments in order.
run 0 ok 300 install -y jq
[ "${STATUS}" -eq 0 ] || fail "success: exit ${STATUS}, wanted 0"
[ "${CALLS}" -eq 1 ] || fail "success: ${CALLS} calls, wanted 1"
[ "$(cat "${WORK}/calls.txt")" = '-o DPkg::Lock::Timeout=300 install -y jq' ] \
    || fail "success: apt-get got '$(cat "${WORK}/calls.txt")'"
[[ "${OUTPUT}" == *'fake apt-get: done'* ]] \
    || fail "success: apt-get's output did not reach the caller"

# A held lock is retried until it is released.
run 2 ok 300 update
[ "${STATUS}" -eq 0 ] || fail "lock released: exit ${STATUS}, wanted 0"
[ "${CALLS}" -eq 3 ] || fail "lock released: ${CALLS} calls, wanted 3"

# Any other failure is returned at once, with its own status.
run 0 42 3 install -y nonesuch
[ "${STATUS}" -eq 42 ] || fail "other failure: exit ${STATUS}, wanted 42"
[ "${CALLS}" -eq 1 ] || fail "other failure: ${CALLS} calls, wanted 1 (it was retried)"

# A lock that is never released fails the step once the deadline passes,
# with apt-get's status and a message saying why.
run -1 ok 2 update
[ "${STATUS}" -eq 100 ] || fail "wedged lock: exit ${STATUS}, wanted 100"
[ "${CALLS}" -ge 2 ] && [ "${CALLS}" -le 4 ] \
    || fail "wedged lock: ${CALLS} calls, wanted 2-4 inside a 2s deadline"
[[ "${OUTPUT}" == *'still held after 2s'* ]] \
    || fail 'wedged lock: no message naming the deadline'

# The frontend wait shares that one deadline: a retry is offered only
# what is left of it, never the whole timeout again.
first="$(sed -n 1p "${WORK}/calls.txt")"
last="$(sed -n '$p' "${WORK}/calls.txt")"
[ "${first}" = '-o DPkg::Lock::Timeout=2 update' ] \
    || fail "wedged lock: first call got '${first}'"
[ "${last}" != "${first}" ] \
    || fail "wedged lock: the last retry was offered the full timeout again"

if [ "${FAILURES}" -ne 0 ]; then
    echo "apt-get: ${FAILURES} assertion(s) failed" >&2
    exit 1
fi
echo 'apt-get: contract holds'
