#!/usr/bin/env bash
#
# Tests for tools/ci/resparsify-testdata.sh.
#
# Two reasons this one is worth a test rather than a read-through.
#
# It is a cross-repository interface: private-ci's testdata image build
# fetches it over HTTPS and runs it as a plain user against a clone, with
# one positional argument and no Actions environment. Nothing in instar's
# own CI exercises that calling convention, so the first case below is
# literally it -- one argument, a scrubbed environment, and a non-zero
# exit demanded on failure. An instar-side change that made the script
# depend on the workflow it happens to be called from would otherwise
# surface as somebody else's broken nightly.
#
# And its only symptom when it silently does nothing is a slow job. So
# sparseness is measured here in allocated blocks before and after, not
# asserted by reading the script: a change that stopped shrinking files
# would still exit 0 and still print its summary.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/resparsify-testdata.sh"

WORK="$(mktemp -d)"
trap 'chmod -R u+w "${WORK}" 2>/dev/null; rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

BASH_BIN="$(command -v bash)"

# allocated blocks, in 512-byte units
blocks() { stat -c %b "$1"; }

# A file of real allocated zeros: dd writes every block, so there is
# something for cp --sparse=always to take back. Written through dd
# rather than truncate, which would create the hole this is measuring.
allocated() {
    # allocated PATH [MEGABYTES]
    mkdir -p "$(dirname "$1")"
    dd if=/dev/zero of="$1" bs=1M count="${2:-8}" status=none
}

make_tree() {
    # make_tree NAME -> path to a fresh testdata-shaped tree
    local tree="${WORK}/$1"
    mkdir -p "${tree}/downloaded" "${tree}/custom"
    echo "${tree}"
}

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

start "private-ci's calling convention"
# Exactly their call: one positional argument, nothing in the
# environment. `env -i` keeps PATH and HOME out too, which is stronger
# than their build needs and proves no environment dependence at all;
# the interpreter is therefore invoked by absolute path, because `env`
# would have no PATH to look one up on.
TREE="$(make_tree convention)"
allocated "${TREE}/downloaded/disk.qcow2"
BEFORE="$(blocks "${TREE}/downloaded/disk.qcow2")"
SUM_BEFORE="$(md5sum < "${TREE}/downloaded/disk.qcow2")"
STATUS=0
OUTPUT="$(env -i "${BASH_BIN}" "${SCRIPT}" "${TREE}" 2>&1)" || STATUS=$?
AFTER="$(blocks "${TREE}/downloaded/disk.qcow2")"
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0 with one positional argument and an empty environment"
else
    fail "expected exit 0, got ${STATUS}: ${OUTPUT}"
fi
if [ "${AFTER}" -lt "${BEFORE}" ]; then
    ok "the image shrank: ${BEFORE} -> ${AFTER} allocated blocks"
else
    fail "expected fewer than ${BEFORE} allocated blocks, got ${AFTER}"
fi
if [ "$(md5sum < "${TREE}/downloaded/disk.qcow2")" = "${SUM_BEFORE}" ]; then
    ok "the image's contents are unchanged"
else
    fail "resparsifying altered the image's contents"
fi

start "GITHUB_* variables are not consulted"
# The counterpart to the case above: garbage in every GITHUB_* variable
# the workflows set must make no difference, so that a future reader of
# $GITHUB_ENV or $GITHUB_WORKSPACE has to be added deliberately and
# fails here.
TREE="$(make_tree no-github-env)"
allocated "${TREE}/downloaded/disk.vmdk"
BEFORE="$(blocks "${TREE}/downloaded/disk.vmdk")"
STATUS=0
OUTPUT="$(env \
    GITHUB_ACTIONS=true \
    GITHUB_WORKSPACE=/nonexistent \
    GITHUB_ENV=/nonexistent/env \
    GITHUB_OUTPUT=/nonexistent/output \
    GITHUB_STEP_SUMMARY=/nonexistent/summary \
    "${BASH_BIN}" "${SCRIPT}" "${TREE}" 2>&1)" || STATUS=$?
AFTER="$(blocks "${TREE}/downloaded/disk.vmdk")"
if [ "${STATUS}" -eq 0 ] && [ "${AFTER}" -lt "${BEFORE}" ]; then
    ok "unaffected by GITHUB_* pointing at paths that do not exist"
else
    fail "exit ${STATUS}, ${BEFORE} -> ${AFTER} blocks: ${OUTPUT}"
fi

start "scope"
TREE="$(make_tree scope)"
allocated "${TREE}/downloaded/in-scope.vhd"
allocated "${TREE}/downloaded/nested/deeper/in-scope.vhdx"
allocated "${TREE}/downloaded/has a space in it.img"
allocated "${TREE}/downloaded/backing.raw"
allocated "${TREE}/downloaded/notes.txt"
allocated "${TREE}/custom/fixture.qcow2"
allocated "${TREE}/custom/nested/fixture.img"
allocated "${TREE}/top-level.qcow2"
declare -A WAS
while IFS= read -r file; do
    WAS["${file}"]="$(blocks "${TREE}/${file}")"
done < <(cd "${TREE}" && find . -type f -printf '%P\n' | sed 's|^\./||')
"${BASH_BIN}" "${SCRIPT}" "${TREE}" > /dev/null

check_shrank() {
    local rel="$1"
    local now
    now="$(blocks "${TREE}/${rel}")"
    if [ "${now}" -lt "${WAS[${rel}]}" ]; then
        ok "${rel} shrank: ${WAS[${rel}]} -> ${now}"
    else
        fail "${rel} should have shrunk from ${WAS[${rel}]}, still ${now}"
    fi
}

check_untouched() {
    local rel="$1"
    local now
    now="$(blocks "${TREE}/${rel}")"
    if [ "${now}" = "${WAS[${rel}]}" ]; then
        ok "${rel} left at ${now} blocks"
    else
        fail "${rel} should have been left at ${WAS[${rel}]}, now ${now}"
    fi
}

check_shrank "downloaded/in-scope.vhd"
check_shrank "downloaded/nested/deeper/in-scope.vhdx"
check_shrank "downloaded/has a space in it.img"
check_untouched "downloaded/backing.raw"
check_untouched "downloaded/notes.txt"
check_untouched "custom/fixture.qcow2"
check_untouched "custom/nested/fixture.img"
check_untouched "top-level.qcow2"

start "re-running over a sparse tree"
# The cached-tree case: already sparse, so it must neither fail nor
# re-inflate anything.
SPARSE_WAS="$(blocks "${TREE}/downloaded/in-scope.vhd")"
STATUS=0
"${BASH_BIN}" "${SCRIPT}" "${TREE}" > /dev/null 2>&1 || STATUS=$?
SPARSE_NOW="$(blocks "${TREE}/downloaded/in-scope.vhd")"
if [ "${STATUS}" -eq 0 ] && [ "${SPARSE_NOW}" -le "${SPARSE_WAS}" ]; then
    ok "idempotent: exit 0, ${SPARSE_WAS} -> ${SPARSE_NOW} blocks"
else
    fail "exit ${STATUS}, ${SPARSE_WAS} -> ${SPARSE_NOW} blocks"
fi
if [ -z "$(find "${TREE}" -name '*.resparsify' -print -quit)" ]; then
    ok "leaves no .resparsify temporary files behind"
else
    fail "left a .resparsify temporary file behind"
fi

start "argument handling"
expect_status() {
    # expect_status DESCRIPTION EXPECTED_EXIT [ARG...]
    local description="$1"
    local expected="$2"
    shift 2
    local status=0
    "${BASH_BIN}" "${SCRIPT}" "$@" > /dev/null 2>&1 || status=$?
    if [ "${status}" = "${expected}" ]; then
        ok "${description}"
    else
        fail "${description}: expected exit ${expected}, got ${status}"
    fi
}

expect_status "no arguments fails" 1
# Rejected rather than ignored: the changed-files-only mode this script
# is expected to grow takes further arguments, and a caller asking for
# it against a version that does not have it must not quietly get a
# whole-tree run instead.
expect_status "two arguments fails" 1 "${TREE}" "${TREE}/downloaded/in-scope.vhd"
expect_status "a missing tree path fails" 1 "${WORK}/no-such-tree"
expect_status "a file given as the tree path fails" 1 "${TREE}/downloaded/in-scope.vhd"
expect_status "a tree with no downloaded/ fails" 1 "${WORK}"

start "a failing copy is a failing run"
# The loud-failure half of the contract. An unwritable directory is the
# cheapest way to make cp fail; root ignores the mode bits, so there is
# nothing to test as root.
if [ "$(id -u)" -eq 0 ]; then
    ok "skipped: running as root, which is not refused write access"
else
    TREE="$(make_tree unwritable)"
    allocated "${TREE}/downloaded/disk.qcow2" 4
    SUM_BEFORE="$(md5sum < "${TREE}/downloaded/disk.qcow2")"
    chmod a-w "${TREE}/downloaded"
    STATUS=0
    OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" 2>&1)" || STATUS=$?
    chmod u+w "${TREE}/downloaded"
    if [ "${STATUS}" -ne 0 ]; then
        ok "exits non-zero when an image cannot be rewritten"
    else
        fail "expected a non-zero exit, got 0: ${OUTPUT}"
    fi
    case "${OUTPUT}" in
        *"disk.qcow2"*) ok "names the image it could not resparsify" ;;
        *) fail "expected the failing image's name in '${OUTPUT}'" ;;
    esac
    if [ "$(md5sum < "${TREE}/downloaded/disk.qcow2")" = "${SUM_BEFORE}" ]; then
        ok "the image survives a failed copy intact"
    else
        fail "a failed copy damaged the image"
    fi
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
