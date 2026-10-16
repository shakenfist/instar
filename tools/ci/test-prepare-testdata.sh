#!/usr/bin/env bash
#
# Tests for tools/ci/prepare-testdata.sh.
#
# Every job that touches testdata runs that script first, and two of the
# things it now decides cannot be seen from its output in a passing job:
# which branch ran, and whether it is allowed to fall back
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
#
# Every case here runs everywhere, deliberately: there is no skip and
# nothing conditional on what this machine happens to have mounted.
# The require-cache cases used to stand down when the contractual path
# existed -- which is the runner they exist for -- and a stood-down
# case printed "ok", so "we tested the refusal" and "we could not test
# it" read identically. They now relocate the contract through
# TESTDATA_CONTRACT_CACHE instead; if a case ever has to become
# conditional again, make it say so loudly rather than reporting a
# pass.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/prepare-testdata.sh"
WRAPPER="${REPO_ROOT}/tools/ci/resparsify-prepared-testdata.sh"
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
    diff-files)
        # The paths whose index stat data was stale before the update.
        # A separate subcommand from "diff" above and a separate stub
        # input, because the script unions two lists that come from
        # different places and a stub that conflated them could not
        # show the union happening.
        if [ -n "${GIT_STUB_STAT_DIRTY:-}" ]; then
            tr '\n' '\0' < "${GIT_STUB_STAT_DIRTY}"
        fi
        ;;
    lfs)
        # `git lfs ls-files`, replayed verbatim from a file holding
        # lines in the shape git-lfs 3.6.1 was measured to print:
        # "<short oid> - <path>" for a working-tree pointer and
        # "<short oid> * <path>" for a materialised file.
        if [ "$2" = 'ls-files' ] && [ -n "${GIT_STUB_LFS_LS_FILES:-}" ]; then
            cat "${GIT_STUB_LFS_LS_FILES}"
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

# env_is_empty CASE -- the script exported nothing at all.
#
# Emptiness rather than the absence of a particular name: the first
# version of this grepped for TESTDATA_REQUIRE_CACHE, which the script
# never writes to $GITHUB_ENV on any path, so it passed whatever the
# script did. What a refusal must not do is export TESTDATA_PATH or
# TESTDATA_SOURCE -- a later step reading either of those would act on
# a tree the script just refused to prepare -- and only an empty file
# says that.
env_is_empty() {
    [ ! -s "${WORK}/$1/env" ]
}

# a cache the script will take the update-in-place branch on
make_cache() {
    local cache="${WORK}/$1"
    mkdir -p "${cache}/.git" "${cache}/downloaded"
    "${WORK}/make-fixtures" "${cache}"
    echo "${cache}"
}

start "the branch taken is reported"
# The cache cases from here to the narrow-resparsify check all vouch
# for the cache, because the narrow treatment they exercise is only
# ever given to a cache the job asserted is the fleet's disk.
CACHE="$(make_cache cache-tree)"
printf '%s\n' 'downloaded/qemu-iotests/updated.qcow2' 'README.md' > "${WORK}/changed.txt"
run_prepare cache \
    TESTDATA_REQUIRE_CACHE=1 TESTDATA_CONTRACT_CACHE="${CACHE}" TESTDATA_CACHE="${CACHE}" \
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

# A tree at the cache path on a job that did not require it -- a
# long-lived cache on a static runner, say -- is not known to be
# sparse, so it must not be handed to the narrow resparsify.
CACHE_UV="$(make_cache unverified-cache)"
run_prepare unverified \
    TESTDATA_CACHE="${CACHE_UV}" \
    GIT_STUB_PREVIOUS_REV='6666666666666666666666666666666666666666' \
    GIT_STUB_CHANGED="${WORK}/changed.txt"
if [ "$(cat "${WORK}/unverified/status")" -eq 0 ] \
    && [ "$(env_value unverified TESTDATA_SOURCE)" = 'unverified-cache' ]; then
    ok "a cache the job did not require exports TESTDATA_SOURCE=unverified-cache"
else
    fail "exit $(cat "${WORK}/unverified/status"), source '$(env_value unverified TESTDATA_SOURCE)'"
fi
if grep -q 'reset --hard' "${WORK}/unverified/log" && ! grep -q '^clone' "${WORK}/unverified/log"; then
    ok "and still updates it in place rather than cloning"
else
    fail "unexpected git calls: $(cat "${WORK}/unverified/log")"
fi
if [ -z "$(env_value unverified TESTDATA_CHANGED_FILES)" ]; then
    ok "and exports no changed-file list, because the whole tree is resparsified"
else
    fail "exported '$(env_value unverified TESTDATA_CHANGED_FILES)'"
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
if [ "$(sort -u "${CHANGED}")" = "$(sort -u "${WORK}/changed.txt")" ]; then
    ok "it holds every changed path, images and otherwise"
else
    fail "list was '$(cat "${CHANGED}")'"
fi

# The other half of the list, which no diff of the two trees produces:
# paths whose index stat data was stale before the update, which the
# reset rewrites and the tree diff does not name. The case overlaps
# them deliberately -- one path in both lists, one in each -- because
# the union is a union and not a concatenation.
printf '%s\n' 'downloaded/qemu-iotests/updated.qcow2' \
    'downloaded/qemu-iotests/stale-stat.qcow2' \
    'downloaded/qemu-iotests/stale-stat.txt' > "${WORK}/stat-dirty.txt"
CACHE_SD="$(make_cache stat-dirty-cache)"
run_prepare statdirty \
    TESTDATA_REQUIRE_CACHE=1 TESTDATA_CONTRACT_CACHE="${CACHE_SD}" TESTDATA_CACHE="${CACHE_SD}" \
    GIT_STUB_PREVIOUS_REV='5555555555555555555555555555555555555555' \
    GIT_STUB_CHANGED="${WORK}/changed.txt" \
    GIT_STUB_STAT_DIRTY="${WORK}/stat-dirty.txt"
SD_LIST="$(env_value statdirty TESTDATA_CHANGED_FILES)"
EXPECTED_UNION="$(cat "${WORK}/changed.txt" "${WORK}/stat-dirty.txt" | sort -u)"
if [ "$(sort -u "${SD_LIST}")" = "${EXPECTED_UNION}" ]; then
    ok "a stat-dirty path the tree diff does not name is in the list"
else
    fail "union was '$(cat "${SD_LIST}")', wanted '${EXPECTED_UNION}'"
fi
if [ "$(wc -l < "${SD_LIST}")" -eq "$(printf '%s\n' "${EXPECTED_UNION}" | wc -l)" ]; then
    ok "and a path in both lists appears once"
else
    fail "list has $(wc -l < "${SD_LIST}") entries: $(cat "${SD_LIST}")"
fi
case "$(cat "${WORK}/statdirty/out")" in
    *"::warning::"*"update-index --refresh"*)
        ok "and says so, because the cache's builder is what should fix it" ;;
    *) fail "expected a warning naming the fix: $(cat "${WORK}/statdirty/out")" ;;
esac
# Two counts, because the total answers "which failure is this" and
# only the second answers "what does it cost". git reports every
# tracked path whose stat data differs, images or not, so a reader
# given one number would compare it against the wrong denominator --
# the fixture here is deliberately two images and one file that is
# neither an image nor under downloaded/'s image extensions.
case "$(cat "${WORK}/statdirty/out")" in
    *"3 tracked path(s)"*"2 of them in-scope images"*)
        ok "and separates the tracked-path count from the image count" ;;
    *) fail "expected both counts: $(cat "${WORK}/statdirty/out")" ;;
esac
case "$(cat "${WORK}/statdirty/out")" in
    *"number of tracked files in the tree"*)
        ok "and says what a large total means, against the right denominator" ;;
    *) fail "expected the tracked-files reading: $(cat "${WORK}/statdirty/out")" ;;
esac
if ! grep -q '::warning::' "${WORK}/cache/out"; then
    ok "no warning when nothing was stat-dirty"
else
    fail "warned with a clean index: $(cat "${WORK}/cache/out")"
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
    TESTDATA_REQUIRE_CACHE=1 TESTDATA_CONTRACT_CACHE="${CACHE_RT}" TESTDATA_CACHE="${CACHE_RT}" \
    RUNNER_TEMP="${WORK}/runnertemp-dir" \
    GIT_STUB_PREVIOUS_REV='3333333333333333333333333333333333333333' \
    GIT_STUB_CHANGED="${WORK}/changed.txt"
case "$(env_value runnertemp TESTDATA_CHANGED_FILES)" in
    "${WORK}/runnertemp-dir"/*) ok "the list is written under \$RUNNER_TEMP when set" ;;
    *) fail "list went to '$(env_value runnertemp TESTDATA_CHANGED_FILES)'" ;;
esac

# The third source: files still LFS pointers before the pull, which the
# pull writes out fully allocated and leaves no trace of -- it refreshes
# the index as it goes, so no diff-files afterwards names them. One
# pointer overlaps the tree diff, one is new to the list, and one line
# is a materialised file, which must not be listed.
printf '%s\n' \
    '495f0e0c5c - downloaded/qemu-iotests/updated.qcow2' \
    '480099afeb - downloaded/qemu-iotests/still-a-pointer.qcow2' \
    '7c1a2b3d4e * downloaded/qemu-iotests/materialised.qcow2' \
    > "${WORK}/lfs-ls-files.txt"
CACHE_PTR="$(make_cache pointer-cache)"
run_prepare pointers \
    TESTDATA_REQUIRE_CACHE=1 TESTDATA_CONTRACT_CACHE="${CACHE_PTR}" TESTDATA_CACHE="${CACHE_PTR}" \
    GIT_STUB_PREVIOUS_REV='7777777777777777777777777777777777777777' \
    GIT_STUB_CHANGED="${WORK}/changed.txt" \
    GIT_STUB_LFS_LS_FILES="${WORK}/lfs-ls-files.txt"
PTR_LIST="$(env_value pointers TESTDATA_CHANGED_FILES)"
EXPECTED_PTR="$(printf '%s\n' 'downloaded/qemu-iotests/still-a-pointer.qcow2' \
    | cat - "${WORK}/changed.txt" | sort -u)"
if [ "$(sort -u "${PTR_LIST}")" = "${EXPECTED_PTR}" ]; then
    ok "a pointer the update did not touch is in the list, a materialised file is not"
else
    fail "list was '$(cat "${PTR_LIST}")', wanted '${EXPECTED_PTR}'"
fi
if [ "$(grep -n 'lfs ls-files' "${WORK}/pointers/log" | cut -d: -f1)" \
    -lt "$(grep -n 'lfs pull' "${WORK}/pointers/log" | cut -d: -f1)" ]; then
    ok "the pointers are listed before the pull, not after it"
else
    fail "wrong order: $(cat "${WORK}/pointers/log")"
fi
case "$(cat "${WORK}/pointers/out")" in
    *"::warning::"*"were still LFS pointers"*)
        ok "and warns, because the cache's builder should have pulled them" ;;
    *) fail "expected a pointer warning: $(cat "${WORK}/pointers/out")" ;;
esac
if ! grep -q 'lfs ls-files' "${WORK}/unverified/log" "${WORK}/clone/log"; then
    ok "the whole-tree branches do not pay for the listing"
else
    fail "lfs ls-files ran on a branch that resparsifies the whole tree"
fi

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
    *"testdata source: unverified-cache"*) ok "still says which branch it took" ;;
    *) fail "expected the branch in '${OUTPUT}'" ;;
esac

start "the contractual path is a constant, relocatable only by the test seam"
# Everything below moves the contract to a temporary directory, because
# the real one is a disk this machine does not have. Two things make
# that honest rather than a way of testing something else.
#
# The default is still the literal path: asserted here by running with
# the seam unset, which is also the one case in this file that pins the
# constant the fleet agreed to.
run_prepare default-contract TESTDATA_REQUIRE_CACHE=1 TESTDATA_CACHE="${WORK}/somewhere-else"
DEFAULT_OUT="$(cat "${WORK}/default-contract/out")"
case "${DEFAULT_OUT}" in
    *"not the agreed ${CONTRACT_CACHE}"*) ok "unset, the contract is ${CONTRACT_CACHE}" ;;
    *) fail "expected ${CONTRACT_CACHE} in '${DEFAULT_OUT}'" ;;
esac
if env_is_empty default-contract; then
    ok "and exported nothing"
else
    fail "wrote to GITHUB_ENV: $(cat "${WORK}/default-contract/env")"
fi
# And the seam is a different variable from TESTDATA_CACHE, so a job
# cannot satisfy the guard by pointing both halves of it at the same
# wrong place. That only holds while nothing in CI sets it.
if ! grep -rq 'TESTDATA_CONTRACT_CACHE' "${REPO_ROOT}/.github"; then
    ok "nothing under .github/ sets the seam"
else
    fail "a workflow sets it: $(grep -rn 'TESTDATA_CONTRACT_CACHE' "${REPO_ROOT}/.github")"
fi
run_prepare seam-alone TESTDATA_REQUIRE_CACHE=1 \
    TESTDATA_CONTRACT_CACHE="${WORK}/relocated-contract"
case "$(cat "${WORK}/seam-alone/out")" in
    *"not the agreed ${WORK}/relocated-contract"*)
        ok "relocating the contract alone still refuses a TESTDATA_CACHE that does not match" ;;
    *) fail "expected a mismatch against the relocated path: $(cat "${WORK}/seam-alone/out")" ;;
esac

start "TESTDATA_REQUIRE_CACHE refuses the fallback with the cache absent"
# Proved with the cache absent rather than by reading the branch: this
# is the assertion that stops a mounted-nowhere disk from degrading into
# a 7.46 GiB clone that merely looks slow. Hermetic through the seam
# above: the previous shape of this case stood down whenever the real
# path happened to exist, which is precisely the runner the guard is
# for, and a stood-down case printed "ok".
ABSENT_CONTRACT="${WORK}/absent-contract"
run_prepare require TESTDATA_REQUIRE_CACHE=1 \
    TESTDATA_CONTRACT_CACHE="${ABSENT_CONTRACT}" TESTDATA_CACHE="${ABSENT_CONTRACT}"
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
    *"${ABSENT_CONTRACT}"*) ok "names the contractual path" ;;
    *) fail "expected ${ABSENT_CONTRACT} in '${REQUIRE_OUT}'" ;;
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
if env_is_empty require; then
    ok "exported nothing to \$GITHUB_ENV"
else
    fail "wrote to GITHUB_ENV: $(cat "${WORK}/require/env")"
fi

start "TESTDATA_REQUIRE_CACHE is satisfied by a cache at the contractual path"
# The load-bearing half, and until the seam above it was covered by
# nothing: every other case here proves the guard refuses, none proved
# it lets the ordinary job through. A guard that refused everything
# would pass all of them and fail every labelled job in CI.
PRESENT_CONTRACT="$(make_cache present-contract)"
run_prepare satisfied TESTDATA_REQUIRE_CACHE=1 \
    TESTDATA_CONTRACT_CACHE="${PRESENT_CONTRACT}" TESTDATA_CACHE="${PRESENT_CONTRACT}" \
    GIT_STUB_PREVIOUS_REV='4444444444444444444444444444444444444444' \
    GIT_STUB_CHANGED="${WORK}/changed.txt"
SATISFIED_OUT="$(cat "${WORK}/satisfied/out")"
if [ "$(cat "${WORK}/satisfied/status")" -eq 0 ]; then
    ok "exits 0"
else
    fail "expected exit 0, got $(cat "${WORK}/satisfied/status"): ${SATISFIED_OUT}"
fi
if [ "$(env_value satisfied TESTDATA_SOURCE)" = 'cache' ] \
    && [ "$(env_value satisfied TESTDATA_PATH)" = "${PRESENT_CONTRACT}" ]; then
    ok "takes the cache branch and exports the contractual path"
else
    fail "source '$(env_value satisfied TESTDATA_SOURCE)', path '$(env_value satisfied TESTDATA_PATH)'"
fi
if grep -q 'reset --hard' "${WORK}/satisfied/log" && ! grep -q '^clone' "${WORK}/satisfied/log"; then
    ok "updated in place without cloning"
else
    fail "unexpected git calls: $(cat "${WORK}/satisfied/log")"
fi
if [ -n "$(env_value satisfied TESTDATA_CHANGED_FILES)" ]; then
    ok "still produces the changed-file list the narrow resparsify needs"
else
    fail "no TESTDATA_CHANGED_FILES: $(cat "${WORK}/satisfied/env")"
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
if env_is_empty elsewhere; then
    ok "and exported nothing, so no later step can act on that tree"
else
    fail "wrote to GITHUB_ENV: $(cat "${WORK}/elsewhere/env")"
fi

start "TESTDATA_REQUIRE_CACHE takes 1, 0 or unset and nothing else"
# The asymmetry worth testing: an unrecognised value read as "off"
# hands back the 7.46 GiB fallback on a job whose author believed the
# refusal was on, and the only symptom is a slow job. '0' is the one
# value that may legitimately mean off, so it has to keep working.
run_prepare require-zero TESTDATA_REQUIRE_CACHE=0 TESTDATA_CACHE="${WORK}/no-such-cache-0"
if [ "$(cat "${WORK}/require-zero/status")" -eq 0 ] \
    && [ "$(env_value require-zero TESTDATA_SOURCE)" = 'clone' ]; then
    ok "0 allows the fallback, like unset"
else
    fail "exit $(cat "${WORK}/require-zero/status")': $(cat "${WORK}/require-zero/out")"
fi
for bad in true yes TRUE 2 ' 1'; do
    run_prepare require-bad TESTDATA_REQUIRE_CACHE="${bad}" \
        TESTDATA_CACHE="${WORK}/no-such-cache-bad"
    BAD_OUT="$(cat "${WORK}/require-bad/out")"
    if [ "$(cat "${WORK}/require-bad/status")" -ne 0 ] \
        && [ ! -s "${WORK}/require-bad/log" ] \
        && env_is_empty require-bad; then
        case "${BAD_OUT}" in
            *"::error::"*) ok "'${bad}' is an error, and nothing was cloned" ;;
            *) fail "'${bad}' failed without an annotation: ${BAD_OUT}" ;;
        esac
    else
        fail "'${bad}' gave exit $(cat "${WORK}/require-bad/status"), git: $(cat "${WORK}/require-bad/log")"
    fi
done

start "what each branch exports is what the resparsify step reads"
# The two scripts are joined by three variable names and three source
# values, and the workflow steps between them pass no arguments, so a
# rename on either side just means a branch is never taken -- or, for a
# new source value, that every job fails at the resparsify step. Fed
# straight from the $GITHUB_ENV each branch above wrote, rather than by
# matching either script's text, so that any spelling of the export
# that works passes and any that does not fails.
for case_name in clone:'resparsifying the whole tree' \
    unverified:'did not vouch for' \
    cache:'resparsifying only the'; do
    name="${case_name%%:*}"
    want="${case_name#*:}"
    mapfile -t EXPORTED < "${WORK}/${name}/env"
    STATUS=0
    OUTPUT="$(env -i PATH="/usr/bin:/bin" "${EXPORTED[@]}" bash "${WRAPPER}" 2>&1)" || STATUS=$?
    if [ "${STATUS}" -eq 0 ]; then
        case "${OUTPUT}" in
            *"${want}"*) ok "the ${name} branch's exports take the resparsify step's ${name} path" ;;
            *) fail "the ${name} branch's exports took the wrong path: ${OUTPUT}" ;;
        esac
    else
        fail "the resparsify step rejected the ${name} branch's exports (${STATUS}): ${OUTPUT}"
    fi
done

start "TESTDATA_REQUIRE_CACHE unset keeps the fallback"
# The flag is on in CI, but only on the jobs that ask the fleet for the
# disk. Everything else -- the static-fleet drift fixer, a developer
# running this by hand, a future job that has no reason to want the
# disk -- still has to get the clone it always got.
#
# The exact complement of the refusal case above, and not the earlier
# clone case re-read: this one looks for the cache at the *contractual*
# path and finds it missing, which is the configuration the guard
# refuses, with only the flag changed. Re-asserting the earlier run
# would have proved that a missing cache somewhere else still clones,
# which nothing threatened.
ABSENT_CONTRACT_UNSET="${WORK}/absent-contract-unset"
run_prepare fallback \
    TESTDATA_CONTRACT_CACHE="${ABSENT_CONTRACT_UNSET}" \
    TESTDATA_CACHE="${ABSENT_CONTRACT_UNSET}"
if [ "$(cat "${WORK}/fallback/status")" -eq 0 ] \
    && grep -q '^clone' "${WORK}/fallback/log"; then
    ok "the contractual path missing still clones when the flag is not set"
else
    fail "exit $(cat "${WORK}/fallback/status"): $(cat "${WORK}/fallback/out")"
fi
if [ "$(env_value fallback TESTDATA_SOURCE)" = 'clone' ]; then
    ok "and calls it a clone, so the whole tree is resparsified"
else
    fail "source was '$(env_value fallback TESTDATA_SOURCE)'"
fi

start "the workspace is required up front, not discovered halfway"
# A developer debugging a runner runs this by hand. $GITHUB_ENV being
# unset is fine and is asserted above; $GITHUB_WORKSPACE is not
# optional, because the fresh clone has nowhere to go without it, and
# the point of checking it at the top is that the refusal arrives
# before the update rather than as a bare "unbound variable" after it.
mkdir -p "${WORK}/no-workspace"
NOWS_STATUS=0
NOWS_OUT="$(env -i \
    PATH="${STUB_BIN}:/usr/bin:/bin" \
    HOME="${WORK}/no-workspace" \
    GIT_STUB_LOG="${WORK}/no-workspace/log" \
    GIT_STUB_FIXTURES="${WORK}/make-fixtures" \
    TESTDATA_TOKEN='not-a-real-token' \
    TESTDATA_REQUIRE_CACHE=1 \
    TESTDATA_CACHE="${WORK}/no-workspace/cache" \
    bash "${SCRIPT}" 2>&1)" || NOWS_STATUS=$?
case "${NOWS_OUT}" in
    *"::error::GITHUB_WORKSPACE is not set"*)
        ok "names GITHUB_WORKSPACE rather than dying on an expansion" ;;
    *) fail "expected the up-front refusal, got (${NOWS_STATUS}): ${NOWS_OUT}" ;;
esac
if [ "${NOWS_STATUS}" -ne 0 ] && [ ! -s "${WORK}/no-workspace/log" ]; then
    ok "and refuses before running any git at all"
else
    fail "exit ${NOWS_STATUS}, git log: $(cat "${WORK}/no-workspace/log" 2>/dev/null)"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
