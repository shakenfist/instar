#!/usr/bin/env bash
#
# Tests for tools/ci/resparsify-prepared-testdata.sh.
#
# That script picks between resparsifying a whole testdata tree and
# resparsifying only the files an update changed, and both of its
# mistakes are invisible from the outside. Narrowing a fresh clone
# leaves most of a 7.5 GiB tree fully allocated, which shows up much
# later as a slow job and as disk_size comparisons measuring git's
# allocation rather than the fixture's. Widening a cached tree leaves a
# perfectly correct tree behind and writes gigabytes into a
# copy-on-write overlay, which shows up as nothing at all -- it just
# gives back the saving the testdata dependencies disk exists to
# provide.
#
# So the cases below measure allocated blocks, on the files a run was
# not supposed to touch as well as on the ones it was. An exit status
# and a summary line would be identical either way.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/resparsify-prepared-testdata.sh"
PREPARE="${REPO_ROOT}/tools/ci/prepare-testdata.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

BASH_BIN="$(command -v bash)"

# allocated blocks, in 512-byte units
blocks() { stat -c %b "$1"; }

# A file of real allocated zeros: dd writes every block, so there is
# something for cp --sparse=always to take back. Written through dd
# rather than truncate, which would create the hole being measured.
allocated() {
    mkdir -p "$(dirname "$1")"
    dd if=/dev/zero of="$1" bs=1M count="${2:-8}" status=none
}

make_tree() {
    # make_tree NAME -> path to a fresh testdata-shaped tree holding two
    # fully allocated images, so that "only one of them was rewritten"
    # is a thing a case can actually assert.
    local tree="${WORK}/$1"
    mkdir -p "${tree}/downloaded" "${tree}/custom"
    allocated "${tree}/downloaded/changed.qcow2"
    allocated "${tree}/downloaded/untouched.qcow2"
    echo "${tree}"
}

# run_step NAME [VAR=VALUE...] -- the script under an environment
# holding nothing but what a workflow step would have, leaving
# ${WORK}/NAME.{out,status} behind. env -i so that a variable this
# script should not be reading cannot reach it from the developer's
# shell.
run_step() {
    local name="$1"
    shift
    local status=0
    env -i PATH="/usr/bin:/bin" "$@" "${BASH_BIN}" "${SCRIPT}" \
        > "${WORK}/${name}.out" 2>&1 || status=$?
    echo "${status}" > "${WORK}/${name}.status"
}

status_of() { cat "${WORK}/$1.status"; }
output_of() { cat "${WORK}/$1.out"; }

# Sanity: the filesystem under $TMPDIR has to support holes at all, or
# every measurement below is meaningless. Checked explicitly so that an
# unsupported filesystem reports itself instead of looking like a
# regression in the script.
PROBE="${WORK}/probe"
allocated "${PROBE}" 4
PROBE_FULL="$(blocks "${PROBE}")"
cp --sparse=always "${PROBE}" "${PROBE}.sparse"
PROBE_SPARSE="$(blocks "${PROBE}.sparse")"
if [ "${PROBE_SPARSE}" -ge "${PROBE_FULL}" ]; then
    echo "this filesystem does not support sparse files (${PROBE_FULL} ->" \
        "${PROBE_SPARSE} blocks); cannot test resparsification here" >&2
    exit 1
fi
rm -f "${PROBE}" "${PROBE}.sparse"

start "a fresh clone gets the whole tree"
TREE="$(make_tree clone-tree)"
CHANGED_BEFORE="$(blocks "${TREE}/downloaded/changed.qcow2")"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
run_step clone TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=clone
if [ "$(status_of clone)" -eq 0 ]; then
    ok "exits 0"
else
    fail "expected exit 0, got $(status_of clone): $(output_of clone)"
fi
if [ "$(blocks "${TREE}/downloaded/changed.qcow2")" -lt "${CHANGED_BEFORE}" ] \
    && [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -lt "${UNTOUCHED_BEFORE}" ]; then
    ok "every image in the tree shrank, including the one no list named"
else
    fail "expected both images to shrink: $(output_of clone)"
fi

start "an updated cache gets only what the update changed"
TREE="$(make_tree cache-tree)"
CHANGED_BEFORE="$(blocks "${TREE}/downloaded/changed.qcow2")"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
# Shaped like a real changed-file list rather than a tidy one: it is a
# `git diff --name-only` across the reset, so it legitimately carries
# non-images, fixtures outside downloaded/ and paths the update deleted.
# Those have to be dropped rather than refused, or the first day
# instar-testdata touches its README the whole fleet's jobs fail.
CHANGED_LIST="${WORK}/cache-changed.txt"
printf '%s\n' \
    'downloaded/changed.qcow2' \
    'README.md' \
    'custom/fixture.qcow2' \
    'downloaded/deleted-by-this-update.qcow2' \
    > "${CHANGED_LIST}"
run_step cache TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=cache \
    TESTDATA_CHANGED_FILES="${CHANGED_LIST}"
if [ "$(status_of cache)" -eq 0 ]; then
    ok "exits 0 over a list holding non-images, custom/ paths and a deleted file"
else
    fail "expected exit 0, got $(status_of cache): $(output_of cache)"
fi
if [ "$(blocks "${TREE}/downloaded/changed.qcow2")" -lt "${CHANGED_BEFORE}" ]; then
    ok "the changed image shrank: ${CHANGED_BEFORE} -> $(blocks "${TREE}/downloaded/changed.qcow2")"
else
    fail "the changed image was not resparsified: $(output_of cache)"
fi
if [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -eq "${UNTOUCHED_BEFORE}" ]; then
    ok "the image the update did not change was not rewritten"
else
    fail "an unchanged image was rewritten, which is the whole cost this avoids"
fi

start "a cached tree whose update changed nothing is not an error"
TREE="$(make_tree cache-empty)"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
: > "${WORK}/empty-changed.txt"
run_step empty TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=cache \
    TESTDATA_CHANGED_FILES="${WORK}/empty-changed.txt"
if [ "$(status_of empty)" -eq 0 ]; then
    ok "exits 0 on an empty changed-file list, which is the normal case"
else
    fail "expected exit 0, got $(status_of empty): $(output_of empty)"
fi
if [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -eq "${UNTOUCHED_BEFORE}" ]; then
    ok "nothing was rewritten"
else
    fail "an empty list still rewrote the tree"
fi

start "the expensive branch is never a silent default"
TREE="$(make_tree no-source)"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
run_step no-source TESTDATA_PATH="${TREE}"
if [ "$(status_of no-source)" -ne 0 ]; then
    ok "an unset TESTDATA_SOURCE exits non-zero"
else
    fail "expected a non-zero exit with no TESTDATA_SOURCE"
fi
if [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -eq "${UNTOUCHED_BEFORE}" ]; then
    ok "and resparsifies nothing on the way out"
else
    fail "it swept the tree before failing"
fi
case "$(output_of no-source)" in
    *prepare-testdata.sh*) ok "names the script that was supposed to set it" ;;
    *) fail "expected prepare-testdata.sh in '$(output_of no-source)'" ;;
esac

TREE="$(make_tree bad-source)"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
run_step bad-source TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=disk
if [ "$(status_of bad-source)" -ne 0 ] \
    && [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -eq "${UNTOUCHED_BEFORE}" ]; then
    ok "an unrecognised TESTDATA_SOURCE exits non-zero and rewrites nothing"
else
    fail "expected a non-zero exit and an untouched tree: $(output_of bad-source)"
fi
case "$(output_of bad-source)" in
    *disk*) ok "quotes the value it did not understand" ;;
    *) fail "expected the offending value in '$(output_of bad-source)'" ;;
esac

run_step no-path TESTDATA_SOURCE=clone
if [ "$(status_of no-path)" -ne 0 ]; then
    ok "an unset TESTDATA_PATH exits non-zero"
else
    fail "expected a non-zero exit with no TESTDATA_PATH"
fi

start "a cache branch missing its changed-file list fails loudly"
TREE="$(make_tree cache-no-list)"
run_step cache-no-list TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=cache
if [ "$(status_of cache-no-list)" -ne 0 ]; then
    ok "TESTDATA_CHANGED_FILES unset exits non-zero rather than sweeping the tree"
else
    fail "expected a non-zero exit: $(output_of cache-no-list)"
fi

TREE="$(make_tree cache-stale-list)"
UNTOUCHED_BEFORE="$(blocks "${TREE}/downloaded/untouched.qcow2")"
run_step cache-stale-list TESTDATA_PATH="${TREE}" TESTDATA_SOURCE=cache \
    TESTDATA_CHANGED_FILES="${WORK}/no-such-list.txt"
if [ "$(status_of cache-stale-list)" -ne 0 ] \
    && [ "$(blocks "${TREE}/downloaded/untouched.qcow2")" -eq "${UNTOUCHED_BEFORE}" ]; then
    ok "a changed-file list that does not exist exits non-zero and rewrites nothing"
else
    fail "expected a non-zero exit and an untouched tree: $(output_of cache-stale-list)"
fi

start "the variable names still match what prepare-testdata.sh exports"
# This script and prepare-testdata.sh are joined by three variable names
# and two source values, and nothing else in the repository would notice
# a rename on one side of that: the workflow steps pass no arguments, so
# a renamed variable just means the branch is never taken, and the
# expensive branch is the one that still works.
for name in TESTDATA_PATH TESTDATA_SOURCE TESTDATA_CHANGED_FILES; do
    if grep -q "echo \"${name}=" "${PREPARE}"; then
        ok "${name} is still exported by prepare-testdata.sh"
    else
        fail "${name} is read here but prepare-testdata.sh no longer exports it"
    fi
done
for value in clone cache; do
    if grep -q "TESTDATA_SOURCE='${value}'" "${PREPARE}"; then
        ok "prepare-testdata.sh still reports the '${value}' source"
    else
        fail "this script branches on TESTDATA_SOURCE=${value}, which prepare-testdata.sh no longer sets"
    fi
done

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
