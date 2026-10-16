#!/usr/bin/env bash
#
# Tests for tools/ci/prepare-testdata.sh.
#
# Every job that touches testdata runs that script first, and two of the
# things it now decides cannot be seen from its output in a passing job:
# which of its two branches ran, and whether it is allowed to fall back
# to a fresh clone at all. Both only show up when they are wrong, and
# both show up as a job that merely looks slow -- the failure mode the
# whole testdata-disk arrangement exists to remove. So they are measured
# here rather than read.
#
# git is stubbed. The real script talks to a private GitLab host over an
# authenticated remote and moves 7.46 GiB, none of which belongs in a
# unit test; the stub records what it was asked to do and fabricates
# just enough of a checkout to satisfy the fixture guard. That makes the
# interesting assertion possible: not only that the script failed, but
# that it failed *without* having started a clone.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/prepare-testdata.sh"
RESPARSIFY="${REPO_ROOT}/tools/ci/resparsify-testdata.sh"
FIXTURE_CHECK="${REPO_ROOT}/tools/ci/check-testdata-fixtures.sh"

# The path the runner fleet mounts the testdata dependencies disk on,
# asserted literally by the script under test. Stated again here rather
# than scraped out of it, so that a change to one has to be a change to
# both.
CONTRACT_CACHE='/srv/ci/cached/instar-testdata'

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# A git that does nothing but record, plus the minimum fabrication the
# script's own guards need: a clone has to leave a checkout containing
# the required fixtures, and a cache update has to answer rev-parse and
# diff. The token never reaches the log.
STUB_BIN="${WORK}/bin"
mkdir -p "${STUB_BIN}"

cat > "${STUB_BIN}/git" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

# Credentials travel in the clone/remote URL, so the log records the
# subcommand and strips anything carrying one.
{
    printf '%s' "$1"
    for arg in "${@:2}"; do
        case "${arg}" in
            https://*) printf ' <url>' ;;
            *) printf ' %s' "${arg}" ;;
        esac
    done
    printf '\n'
} >> "${GIT_STUB_LOG}"

case "$1" in
    clone)
        target="${*: -1}"
        mkdir -p "${target}/.git" "${target}/downloaded"
        "${GIT_STUB_FIXTURES}" "${target}"
        ;;
    rev-parse)
        if [ -n "${GIT_STUB_PREVIOUS_REV:-}" ]; then
            echo "${GIT_STUB_PREVIOUS_REV}"
        else
            exit 1
        fi
        ;;
    hash-object)
        echo '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
        ;;
    diff)
        if [ -n "${GIT_STUB_CHANGED:-}" ]; then
            tr '\n' '\0' < "${GIT_STUB_CHANGED}"
        fi
        ;;
esac
exit 0
STUB
chmod +x "${STUB_BIN}/git"

# Only its presence on PATH is checked.
printf '#!/bin/sh\nexit 0\n' > "${STUB_BIN}/git-lfs"
chmod +x "${STUB_BIN}/git-lfs"

# The fixtures the script's own guard requires, read from that guard
# rather than copied, so a change to its list cannot leave this test
# fabricating the wrong tree.
cat > "${WORK}/make-fixtures" <<STUB
#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r rel; do
    mkdir -p "\$1/\$(dirname "\${rel}")"
    printf 'QFI\\xfb not a pointer' > "\$1/\${rel}"
done < <("${FIXTURE_CHECK}" --list)
STUB
chmod +x "${WORK}/make-fixtures"

# run_prepare NAME [VAR=VALUE...] -- runs the script under the stubs in
# a fresh workspace, leaving ${WORK}/NAME/{env,log,out,status} behind.
run_prepare() {
    local name="$1"
    shift
    local case_dir="${WORK}/${name}"
    mkdir -p "${case_dir}/workspace"
    : > "${case_dir}/env"
    : > "${case_dir}/log"
    local status=0
    env -i \
        PATH="${STUB_BIN}:/usr/bin:/bin" \
        HOME="${case_dir}" \
        GIT_STUB_LOG="${case_dir}/log" \
        GIT_STUB_FIXTURES="${WORK}/make-fixtures" \
        TESTDATA_TOKEN='not-a-real-token' \
        GITHUB_WORKSPACE="${case_dir}/workspace" \
        GITHUB_ENV="${case_dir}/env" \
        "$@" \
        bash "${SCRIPT}" > "${case_dir}/out" 2>&1 || status=$?
    echo "${status}" > "${case_dir}/status"
}

# env_value CASE VAR -- what the script exported to $GITHUB_ENV
env_value() {
    sed -n "s/^$2=//p" "${WORK}/$1/env" | tail -1
}

# a cache the script will take the update-in-place branch on
make_cache() {
    local cache="${WORK}/$1"
    mkdir -p "${cache}/.git" "${cache}/downloaded"
    "${WORK}/make-fixtures" "${cache}"
    echo "${cache}"
}

start "the branch taken is reported"
CACHE="$(make_cache cache-tree)"
printf '%s\n' 'downloaded/qemu-iotests/updated.qcow2' 'README.md' > "${WORK}/changed.txt"
run_prepare cache \
    TESTDATA_CACHE="${CACHE}" \
    GIT_STUB_PREVIOUS_REV='1111111111111111111111111111111111111111' \
    GIT_STUB_CHANGED="${WORK}/changed.txt"
if [ "$(cat "${WORK}/cache/status")" -eq 0 ]; then
    ok "the cache branch exits 0"
else
    fail "expected exit 0, got $(cat "${WORK}/cache/status"): $(cat "${WORK}/cache/out")"
fi
if [ "$(env_value cache TESTDATA_SOURCE)" = 'cache' ]; then
    ok "exports TESTDATA_SOURCE=cache beside TESTDATA_PATH"
else
    fail "TESTDATA_SOURCE was '$(env_value cache TESTDATA_SOURCE)': $(cat "${WORK}/cache/env")"
fi
if [ "$(env_value cache TESTDATA_PATH)" = "${CACHE}" ]; then
    ok "TESTDATA_PATH is the cache"
else
    fail "TESTDATA_PATH was '$(env_value cache TESTDATA_PATH)'"
fi
if grep -q 'reset --hard' "${WORK}/cache/log" && ! grep -q '^clone' "${WORK}/cache/log"; then
    ok "updated in place without cloning"
else
    fail "unexpected git calls: $(cat "${WORK}/cache/log")"
fi
case "$(cat "${WORK}/cache/out")" in
    *"testdata source: cache"*) ok "prints the branch it took" ;;
    *) fail "expected the branch in the output: $(cat "${WORK}/cache/out")" ;;
esac

run_prepare clone TESTDATA_CACHE="${WORK}/no-such-cache"
if [ "$(cat "${WORK}/clone/status")" -eq 0 ] \
    && [ "$(env_value clone TESTDATA_SOURCE)" = 'clone' ]; then
    ok "the fresh-clone branch exports TESTDATA_SOURCE=clone"
else
    fail "exit $(cat "${WORK}/clone/status"), source '$(env_value clone TESTDATA_SOURCE)'"
fi
if grep -q '^clone' "${WORK}/clone/log"; then
    ok "it really did clone"
else
    fail "no clone in: $(cat "${WORK}/clone/log")"
fi

start "the changed-file list, and that the resparsifier accepts it"
# The two halves have to fit: this list is produced for one consumer,
# which refuses paths it will not act on. A list it cannot take is as
# useless as no list at all, and nothing else would notice until a job
# started failing on the cache path.
CHANGED="$(env_value cache TESTDATA_CHANGED_FILES)"
if [ -n "${CHANGED}" ] && [ -f "${CHANGED}" ]; then
    ok "TESTDATA_CHANGED_FILES points at a file that exists"
else
    fail "TESTDATA_CHANGED_FILES was '${CHANGED}'"
fi
if [ "$(cat "${CHANGED}")" = "$(cat "${WORK}/changed.txt")" ]; then
    ok "it holds every changed path, images and otherwise"
else
    fail "list was '$(cat "${CHANGED}")'"
fi
if [ -z "$(env_value clone TESTDATA_CHANGED_FILES)" ]; then
    ok "the fresh-clone branch exports no list, because the whole tree is new"
else
    fail "the clone branch exported '$(env_value clone TESTDATA_CHANGED_FILES)'"
fi

# One of the workflows checks instar out at the workspace root, so the
# list must not default into a checkout when the runner offers a temp
# directory for exactly this.
CACHE_RT="$(make_cache runnertemp-cache)"
mkdir -p "${WORK}/runnertemp-dir"
run_prepare runnertemp \
    TESTDATA_CACHE="${CACHE_RT}" \
    RUNNER_TEMP="${WORK}/runnertemp-dir" \
    GIT_STUB_PREVIOUS_REV='3333333333333333333333333333333333333333' \
    GIT_STUB_CHANGED="${WORK}/changed.txt"
case "$(env_value runnertemp TESTDATA_CHANGED_FILES)" in
    "${WORK}/runnertemp-dir"/*) ok "the list is written under \$RUNNER_TEMP when set" ;;
    *) fail "list went to '$(env_value runnertemp TESTDATA_CHANGED_FILES)'" ;;
esac

blocks() { stat -c %b "$1"; }
NARROW_TREE="${CACHE}"
mkdir -p "${NARROW_TREE}/downloaded/qemu-iotests"
dd if=/dev/zero of="${NARROW_TREE}/downloaded/qemu-iotests/updated.qcow2" bs=1M count=8 status=none
dd if=/dev/zero of="${NARROW_TREE}/downloaded/qemu-iotests/untouched.qcow2" bs=1M count=8 status=none
UPDATED_BEFORE="$(blocks "${NARROW_TREE}/downloaded/qemu-iotests/updated.qcow2")"
UNTOUCHED_BEFORE="$(blocks "${NARROW_TREE}/downloaded/qemu-iotests/untouched.qcow2")"
STATUS=0
OUTPUT="$(bash "${RESPARSIFY}" "${NARROW_TREE}" --files-from "${CHANGED}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "the resparsifier accepts the list as-is"
else
    fail "resparsifier exit ${STATUS}: ${OUTPUT}"
fi
if [ "$(blocks "${NARROW_TREE}/downloaded/qemu-iotests/updated.qcow2")" -lt "${UPDATED_BEFORE}" ] \
    && [ "$(blocks "${NARROW_TREE}/downloaded/qemu-iotests/untouched.qcow2")" = "${UNTOUCHED_BEFORE}" ]; then
    ok "only the changed image was rewritten"
else
    fail "wrong images rewritten: ${OUTPUT}"
fi

start "running by hand, with no \$GITHUB_ENV"
# Developers and anyone debugging a runner run this directly. An
# unwritable or unset $GITHUB_ENV must not be the thing that fails.
CACHE="$(make_cache byhand)"
mkdir -p "${WORK}/byhand-run/workspace"
STATUS=0
OUTPUT="$(env -i \
    PATH="${STUB_BIN}:/usr/bin:/bin" \
    HOME="${WORK}/byhand-run" \
    GIT_STUB_LOG="${WORK}/byhand-run/log" \
    GIT_STUB_FIXTURES="${WORK}/make-fixtures" \
    GIT_STUB_PREVIOUS_REV='2222222222222222222222222222222222222222' \
    TESTDATA_TOKEN='not-a-real-token' \
    TESTDATA_CACHE="${CACHE}" \
    GITHUB_WORKSPACE="${WORK}/byhand-run/workspace" \
    bash "${SCRIPT}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0 with GITHUB_ENV unset"
else
    fail "expected exit 0, got ${STATUS}: ${OUTPUT}"
fi
case "${OUTPUT}" in
    *"testdata source: cache"*) ok "still says which branch it took" ;;
    *) fail "expected the branch in '${OUTPUT}'" ;;
esac

start "TESTDATA_REQUIRE_CACHE refuses the fallback with the cache absent"
# Proved with the cache absent rather than by reading the branch: this
# is the assertion that stops a mounted-nowhere disk from degrading into
# a 7.46 GiB clone that merely looks slow.
if [ -d "${CONTRACT_CACHE}/.git" ]; then
    # On a runner that really has the disk the default path exists, and
    # the case below would be measuring the wrong thing.
    ok "skipped: ${CONTRACT_CACHE} exists here, so this case cannot be set up"
else
    run_prepare require TESTDATA_REQUIRE_CACHE=1
    REQUIRE_STATUS="$(cat "${WORK}/require/status")"
    REQUIRE_OUT="$(cat "${WORK}/require/out")"
    if [ "${REQUIRE_STATUS}" -ne 0 ]; then
        ok "exits non-zero (${REQUIRE_STATUS}) instead of cloning"
    else
        fail "expected a non-zero exit: ${REQUIRE_OUT}"
    fi
    if [ ! -s "${WORK}/require/log" ]; then
        ok "ran no git at all, so nothing was cloned"
    else
        fail "git was called: $(cat "${WORK}/require/log")"
    fi
    if [ -z "$(ls -A "${WORK}/require/workspace")" ]; then
        ok "left no checkout in the workspace"
    else
        fail "workspace holds $(ls -A "${WORK}/require/workspace")"
    fi
    case "${REQUIRE_OUT}" in
        *"::error::"*) ok "reports it as an infra error, in the annotated idiom" ;;
        *) fail "expected an ::error:: annotation in '${REQUIRE_OUT}'" ;;
    esac
    case "${REQUIRE_OUT}" in
        *"${CONTRACT_CACHE}"*) ok "names the contractual path" ;;
        *) fail "expected ${CONTRACT_CACHE} in '${REQUIRE_OUT}'" ;;
    esac
    # The diagnosis is load bearing and easy to get wrong in the
    # reassuring direction: a mount that failed cannot produce this
    # message, because it stops the runner before it registers, so the
    # job never starts. Blaming one would send the reader to userdata
    # logs for an event that cannot have happened.
    case "${REQUIRE_OUT}" in
        *"path mismatch, not a failed mount"*) ok "diagnoses a path mismatch, not a mount failure" ;;
        *) fail "expected the path-mismatch diagnosis in '${REQUIRE_OUT}'" ;;
    esac
    if ! grep -q 'TESTDATA_REQUIRE_CACHE' "${WORK}/require/env"; then
        ok "exported nothing to \$GITHUB_ENV"
    else
        fail "wrote to GITHUB_ENV: $(cat "${WORK}/require/env")"
    fi
fi

start "TESTDATA_REQUIRE_CACHE also refuses a cache somewhere else"
# Hermetic counterpart to the case above, and the other half of the
# contract: a cache that exists at some other path does not satisfy a
# job that required the agreed one, because the agreed path is what the
# fleet mounts and what the conductor carries.
CACHE="$(make_cache elsewhere)"
run_prepare elsewhere TESTDATA_REQUIRE_CACHE=1 TESTDATA_CACHE="${CACHE}"
ELSEWHERE_OUT="$(cat "${WORK}/elsewhere/out")"
if [ "$(cat "${WORK}/elsewhere/status")" -ne 0 ] && [ ! -s "${WORK}/elsewhere/log" ]; then
    ok "exits non-zero without running git, even though that cache exists"
else
    fail "exit $(cat "${WORK}/elsewhere/status"), git log: $(cat "${WORK}/elsewhere/log")"
fi
case "${ELSEWHERE_OUT}" in
    *"not the agreed ${CONTRACT_CACHE}"*) ok "names both paths" ;;
    *) fail "expected both paths in '${ELSEWHERE_OUT}'" ;;
esac

start "TESTDATA_REQUIRE_CACHE unset keeps the fallback"
# The flag is implemented but switched on nowhere, so the default has to
# stay exactly what it was.
if [ "$(cat "${WORK}/clone/status")" -eq 0 ] && grep -q '^clone' "${WORK}/clone/log"; then
    ok "a missing cache still clones when the flag is not set"
else
    fail "exit $(cat "${WORK}/clone/status"): $(cat "${WORK}/clone/out")"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
