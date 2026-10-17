#!/usr/bin/env bash
#
# Tests for tools/ci/resparsify-testdata.sh.
#
# Three reasons this one is worth a test rather than a read-through.
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
#
# The narrow mode inverts that last point and needs both halves measured.
# It exists to not write bytes -- the tree it runs against on a runner
# with a testdata dependencies disk is a copy-on-write overlay, so every
# image it rewrites unnecessarily lands in the overlay. A narrow run that
# had quietly widened to the whole tree would exit 0, print a count, and
# leave a perfectly correct tree behind, so the cases below measure the
# files that were *not* named as well as the ones that were.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/resparsify-testdata.sh"

WORK="$(mktemp -d)"
trap 'chmod -R u+w "${WORK}" 2>/dev/null; rm -rf "${WORK}"' EXIT

FAILURES=0
SKIPS=0
SKIPPED_CASES=''

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# A case this environment cannot set up. Counted and named in the
# summary rather than reported as an ok, because "we checked it" and
# "we could not check it" reading identically is how a guard loses its
# only coverage without anybody noticing.
skip() {
    echo "    SKIP: $1"
    SKIPS=$((SKIPS + 1))
    SKIPPED_CASES="${SKIPPED_CASES}
  - $1"
}

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
expect_status "a missing tree path fails" 1 "${WORK}/no-such-tree"
expect_status "a file given as the tree path fails" 1 "${TREE}/downloaded/in-scope.vhd"
expect_status "a tree with no downloaded/ fails" 1 "${WORK}"
expect_status "an unknown option fails" 1 "${TREE}" --narrow
expect_status "--files-from with no file fails" 1 "${TREE}" --files-from
expect_status "--files-from naming a missing list fails" 1 "${TREE}" --files-from "${WORK}/no-such-list"

start "a downloaded/ with no images fails rather than succeeding quietly"
# The directory exists, so the path is right and the caller gets no hint
# that nothing happened: an extension-list typo or a layout change in
# instar-testdata lands here, and a warning plus exit 0 would surface
# only as a slow job and as disk_size comparisons measuring git's
# allocation. The message has to say what was expected, because the
# caller that sees it may well be private-ci's image build rather than
# anyone in this repository.
EMPTY_TREE="$(make_tree no-images)"
allocated "${EMPTY_TREE}/downloaded/notes.txt"
allocated "${EMPTY_TREE}/downloaded/backing.raw"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${EMPTY_TREE}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    ok "exits non-zero when nothing matched"
else
    fail "expected a non-zero exit, got 0: ${OUTPUT}"
fi
case "${OUTPUT}" in
    *"no images matched"*"*.qcow2"*) ok "says what it expected to find" ;;
    *) fail "expected the extension list in '${OUTPUT}'" ;;
esac

# ---------------------------------------------------------------------
# The narrow mode. Its whole reason for existing is to not write bytes,
# so every case here measures allocated blocks on the files it did not
# name as well as on the ones it did: a narrow run that quietly fell
# back to the whole tree would still exit 0, still print a count, and
# still leave a correct-looking tree -- while writing the gigabytes into
# a copy-on-write overlay that the narrowing exists to avoid.

narrow_tree() {
    # narrow_tree NAME -> a tree with one in-scope image per interesting
    # category, all fully allocated
    local tree
    tree="$(make_tree "$1")"
    allocated "${tree}/downloaded/named.qcow2"
    allocated "${tree}/downloaded/unnamed.qcow2"
    allocated "${tree}/downloaded/nested/also-unnamed.vhd"
    allocated "${tree}/downloaded/notes.txt"
    allocated "${tree}/custom/fixture.qcow2"
    echo "${tree}"
}

start "naming one file resparsifies only that file"
TREE="$(narrow_tree narrow-named)"
NAMED_BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
UNNAMED_BEFORE="$(blocks "${TREE}/downloaded/unnamed.qcow2")"
NESTED_BEFORE="$(blocks "${TREE}/downloaded/nested/also-unnamed.vhd")"
SUM_BEFORE="$(md5sum < "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" downloaded/named.qcow2 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0"
else
    fail "expected exit 0, got ${STATUS}: ${OUTPUT}"
fi
if [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${NAMED_BEFORE}" ]; then
    ok "the named image shrank: ${NAMED_BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2")"
else
    fail "the named image did not shrink from ${NAMED_BEFORE}"
fi
if [ "$(blocks "${TREE}/downloaded/unnamed.qcow2")" = "${UNNAMED_BEFORE}" ] \
    && [ "$(blocks "${TREE}/downloaded/nested/also-unnamed.vhd")" = "${NESTED_BEFORE}" ]; then
    ok "the images it was not given are left fully allocated"
else
    UNNAMED_NOW="$(blocks "${TREE}/downloaded/unnamed.qcow2")"
    NESTED_NOW="$(blocks "${TREE}/downloaded/nested/also-unnamed.vhd")"
    fail "an unnamed image was resparsified: ${UNNAMED_NOW} and ${NESTED_NOW} blocks"
fi
if [ "$(md5sum < "${TREE}/downloaded/named.qcow2")" = "${SUM_BEFORE}" ]; then
    ok "the named image's contents are unchanged"
else
    fail "resparsifying altered the named image's contents"
fi

start "an absolute path inside the tree is accepted"
TREE="$(narrow_tree narrow-absolute)"
BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" "${TREE}/downloaded/named.qcow2" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${BEFORE}" ]; then
    ok "exit 0 and the image shrank: ${BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2")"
else
    fail "exit ${STATUS}, ${BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2") blocks: ${OUTPUT}"
fi

start "a changed-file list is filtered rather than refused"
# What the caller actually has is a reset's "git diff --name-only":
# in-scope images mixed with text files, custom/ fixtures and paths the
# update deleted. Filtering those here is deliberate, so that the caller
# does not need its own copy of the extension list to drift from.
TREE="$(narrow_tree narrow-list)"
LIST_FILE="${WORK}/changed.txt"
cat > "${LIST_FILE}" <<EOF
downloaded/named.qcow2
downloaded/notes.txt
custom/fixture.qcow2
downloaded/deleted-by-the-update.qcow2
EOF
NAMED_BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
UNNAMED_BEFORE="$(blocks "${TREE}/downloaded/unnamed.qcow2")"
TEXT_BEFORE="$(blocks "${TREE}/downloaded/notes.txt")"
CUSTOM_BEFORE="$(blocks "${TREE}/custom/fixture.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" --files-from "${LIST_FILE}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0 with a list holding non-images, custom/ files and a deleted path"
else
    fail "expected exit 0, got ${STATUS}: ${OUTPUT}"
fi
if [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${NAMED_BEFORE}" ]; then
    ok "the in-scope image from the list shrank: ${NAMED_BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2")"
else
    fail "the listed image did not shrink from ${NAMED_BEFORE}"
fi
if [ "$(blocks "${TREE}/downloaded/notes.txt")" = "${TEXT_BEFORE}" ] \
    && [ "$(blocks "${TREE}/custom/fixture.qcow2")" = "${CUSTOM_BEFORE}" ] \
    && [ "$(blocks "${TREE}/downloaded/unnamed.qcow2")" = "${UNNAMED_BEFORE}" ]; then
    ok "the out-of-scope entries and the rest of the tree are untouched"
else
    fail "something out of scope was rewritten"
fi
case "${OUTPUT}" in
    *"3 candidate(s) not in scope"*) ok "counts what it dropped" ;;
    *) fail "expected a dropped-candidate count in '${OUTPUT}'" ;;
esac
if [ -z "$(find "${TREE}" -name '*.resparsify' -print -quit)" ]; then
    ok "leaves no .resparsify temporary files behind"
else
    fail "left a .resparsify temporary file behind"
fi

start "an empty narrow set is success, unlike an empty whole tree"
# The normal case on a cached tree: the update changed no image. The
# whole-tree form treats zero matches as a misconfiguration, and this
# must not inherit that -- a nightly-fresh dependencies disk would fail
# every job on the day nothing changed.
TREE="$(narrow_tree narrow-empty)"
: > "${WORK}/empty.txt"
BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" --files-from "${WORK}/empty.txt" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ "$(blocks "${TREE}/downloaded/named.qcow2")" = "${BEFORE}" ]; then
    ok "exit 0 and nothing was rewritten"
else
    fail "exit ${STATUS}, ${BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2") blocks: ${OUTPUT}"
fi

start "a named path this script will not act on is refused"
TREE="$(narrow_tree narrow-refusals)"
# Three symlinks, all with an in-scope extension, differing only in what
# they point at -- which is the only thing the script judges them by. A
# fourth, pointing at an in-scope image, is the case that is *not* a
# refusal and has a section of its own below.
ln -s /etc/hostname "${TREE}/downloaded/out-of-tree-link.qcow2"
ln -s ../custom/fixture.qcow2 "${TREE}/downloaded/out-of-scope-link.qcow2"
ln -s no-such-image.qcow2 "${TREE}/downloaded/dangling-link.qcow2"
refuses() {
    # refuses DESCRIPTION [ARG...] -- non-zero exit, and the refused
    # path named in the message
    local description="$1"
    shift
    local status=0 output
    output="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" "$@" 2>&1)" || status=$?
    if [ "${status}" -ne 0 ]; then
        ok "${description}"
    else
        fail "${description}: expected a non-zero exit, got 0: ${output}"
    fi
    case "${output}" in
        *refusing*) ;;
        *) fail "${description}: expected a refusal message in '${output}'" ;;
    esac
}

refuses "an absolute path outside the tree" /etc/hostname
refuses "a relative path climbing out of the tree" ../../etc/hostname
refuses "a path outside the tree reached through downloaded/" "downloaded/../../etc/hostname"
refuses "a non-image inside downloaded/" downloaded/notes.txt
refuses "an image outside downloaded/" custom/fixture.qcow2
refuses "an image that does not exist" downloaded/no-such-image.qcow2
refuses "a symlink whose target is outside the tree" downloaded/out-of-tree-link.qcow2
refuses "a symlink whose target is outside downloaded/" downloaded/out-of-scope-link.qcow2
refuses "a symlink whose target does not exist" downloaded/dangling-link.qcow2

start "a refused entry resparsifies nothing at all"
# The refusal has to be a precondition, not a partial run: a job that
# fails after rewriting half the tree has still written the bytes into
# the overlay, and the next job inherits whatever state it left.
BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" downloaded/named.qcow2 /etc/hostname 2>&1)" || STATUS=$?
if [ "${STATUS}" -ne 0 ] && [ "$(blocks "${TREE}/downloaded/named.qcow2")" = "${BEFORE}" ]; then
    ok "exit ${STATUS} and the valid image alongside it is still at ${BEFORE} blocks"
else
    fail "exit ${STATUS}, ${BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2") blocks: ${OUTPUT}"
fi

start "a list naming a path outside the tree is refused, not filtered"
# The filtering above is a convenience for the caller's own tree; it is
# not permission to follow a path somewhere else. Only entries that
# resolve inside the tree are candidates at all.
LIST_FILE="${WORK}/escaping.txt"
printf '%s\n' downloaded/named.qcow2 /etc/hostname > "${LIST_FILE}"
BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" --files-from "${LIST_FILE}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -ne 0 ] && [ "$(blocks "${TREE}/downloaded/named.qcow2")" = "${BEFORE}" ]; then
    ok "exit ${STATUS}, nothing rewritten"
else
    fail "exit ${STATUS}, ${BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2") blocks: ${OUTPUT}"
fi

start "a symlink to an in-scope image inside the tree is followed"
# The counterpart to the three refusals above, and the reason there is
# no symlink check in the script: every rule is applied to the resolved
# target, so a link to an image this script would have rewritten anyway
# is simply a second name for it. Fixtures with an out-of-tree target
# cannot assert this -- they are refused for being out of the tree and
# would pass whatever the script did about symlinks.
TREE="$(narrow_tree narrow-symlink)"
ln -s named.qcow2 "${TREE}/downloaded/link.qcow2"
NAMED_BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
UNNAMED_BEFORE="$(blocks "${TREE}/downloaded/unnamed.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" downloaded/link.qcow2 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0"
else
    fail "exit ${STATUS}: ${OUTPUT}"
fi
if [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${NAMED_BEFORE}" ]; then
    ok "the target shrank: ${NAMED_BEFORE} -> $(blocks "${TREE}/downloaded/named.qcow2")"
else
    fail "the target did not shrink from ${NAMED_BEFORE}: ${OUTPUT}"
fi
if [ -L "${TREE}/downloaded/link.qcow2" ]; then
    ok "the link itself is still a link, not replaced by a copy"
else
    fail "the link was replaced: $(ls -l "${TREE}/downloaded/link.qcow2")"
fi
if [ "$(blocks "${TREE}/downloaded/unnamed.qcow2")" = "${UNNAMED_BEFORE}" ]; then
    ok "nothing else in the tree was rewritten"
else
    fail "an unnamed image was rewritten: ${OUTPUT}"
fi
# Naming both names one file: the resolution that makes the link
# followable is also what collapses the pair, so a caller whose
# changed-file list holds both does not pay for the copy twice.
TREE="$(narrow_tree narrow-symlink-dedup)"
ln -s named.qcow2 "${TREE}/downloaded/link.qcow2"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" downloaded/link.qcow2 downloaded/named.qcow2 2>&1)" \
    || STATUS=$?
case "${OUTPUT}" in
    *"resparsified 1 named image(s)"*) ok "a link and its target count as one image" ;;
    *) fail "exit ${STATUS}, expected one image in '${OUTPUT}'" ;;
esac

start "a large list is filtered without a process per entry"
# The changed-file list this mode reads is not bounded by the number of
# images. Its stat-dirty half covers every tracked path, so a cache
# whose index did not survive the trip from the disk build names all
# ~770,000 files in instar-testdata. A classifier that resolved each one
# would spend a process per entry and the step would hit the job
# timeout -- which would hide the ::warning:: that diagnoses exactly
# that situation behind a failure that explains nothing.
#
# Counted rather than timed: a wall-clock bound would be a flake on a
# loaded runner, and the property is not "fast" but "one resolution per
# candidate worth resolving". The stub counts and then execs the real
# thing, so the script under test still gets real answers.
TREE="$(narrow_tree narrow-bulk)"
COUNT_BIN="${WORK}/count-bin"
mkdir -p "${COUNT_BIN}"
REAL_REALPATH="$(command -v realpath)"
cat > "${COUNT_BIN}/realpath" <<STUB
#!/usr/bin/env bash
echo x >> "${WORK}/realpath-calls"
exec "${REAL_REALPATH}" "\$@"
STUB
chmod +x "${COUNT_BIN}/realpath"
BULK_LIST="${WORK}/bulk-list.txt"
: > "${BULK_LIST}"
# Weighted towards the shape that is both the most common in a real
# list and the most expensive to get wrong: a path under downloaded/
# that is not an image, which is the one the extension rejection
# builds a message for.
for i in $(seq 1 4000); do
    printf 'downloaded/notes-%s.txt\n' "${i}" >> "${BULK_LIST}"
done
for i in $(seq 1 1000); do
    printf 'docs/page-%s.md\ncustom/fixture-%s.qcow2\n' "${i}" "${i}" >> "${BULK_LIST}"
done
printf 'downloaded/named.qcow2\n' >> "${BULK_LIST}"
: > "${WORK}/realpath-calls"
NAMED_BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
STATUS=0
OUTPUT="$(PATH="${COUNT_BIN}:${PATH}" "${BASH_BIN}" "${SCRIPT}" "${TREE}" \
    --files-from "${BULK_LIST}" 2>&1)" || STATUS=$?
CALLS="$(wc -l < "${WORK}/realpath-calls")"
if [ "${STATUS}" -eq 0 ] \
    && [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${NAMED_BEFORE}" ]; then
    ok "6001 entries, and the one in-scope image still shrank"
else
    fail "exit ${STATUS}: ${OUTPUT}"
fi
# One for the tree itself, one for the single in-scope candidate. The
# bound is deliberately loose -- what must not happen is a count that
# grows with the list.
if [ "${CALLS}" -le 10 ]; then
    ok "resolved ${CALLS} path(s), not one per entry"
else
    fail "resolved ${CALLS} path(s) for a 6001-entry list"
fi

# Counting realpath alone is not enough, and the gap was not
# hypothetical: the first version of this check passed while the
# classifier still forked a subshell per rejected candidate, to build
# the phrase for a rejection message that is only ever printed for a
# path the caller named. A counter that names one kind of process
# reports on less than it examined.
#
# CPU time rather than wall time, and rather than a count: a command
# substitution is a fork of the shell itself, so there is no binary to
# wrap, and CPU barely moves when the runner is loaded while wall
# clock does. The separation is wide enough that the bound does not
# have to be tight -- measured here, 2000 rejected entries under
# downloaded/ cost 0.17s of CPU filtered on the string and 3.06s with
# a subshell each, and the real list is 770,000 entries rather than
# 6001.
: > "${WORK}/realpath-calls"
dd if=/dev/zero of="${TREE}/downloaded/named.qcow2" bs=1M count=4 status=none
TIMEFORMAT='%3U %3S'
CPU_LINE="$( { time PATH="${COUNT_BIN}:${PATH}" "${BASH_BIN}" "${SCRIPT}" "${TREE}" \
    --files-from "${BULK_LIST}" > /dev/null 2>&1; } 2>&1 )"
unset TIMEFORMAT
CPU_HUNDREDTHS="$(echo "${CPU_LINE}" | awk '{printf "%d", ($1 + $2) * 100}')"
if [ "${CPU_HUNDREDTHS}" -lt 150 ]; then
    ok "and spent ${CPU_HUNDREDTHS} hundredths of a second of CPU on it, not a fork per entry"
else
    fail "6001 entries cost ${CPU_HUNDREDTHS} hundredths of a second of CPU (${CPU_LINE})"
fi

start "the narrow argument forms the parser accepts are all exercised"
# Each of these is a branch of the argument parser with no other
# coverage: the attached spelling, a second list, the end-of-options
# separator, and a list whose last line has no newline -- which is what
# a generator that forgot the final write produces, and which the read
# loop handles on purpose.
TREE="$(narrow_tree narrow-forms)"
printf 'downloaded/unnamed.qcow2\n' > "${WORK}/forms-a.txt"
printf 'downloaded/nested/also-unnamed.vhd' > "${WORK}/forms-b.txt"
NAMED_BEFORE="$(blocks "${TREE}/downloaded/named.qcow2")"
UNNAMED_BEFORE="$(blocks "${TREE}/downloaded/unnamed.qcow2")"
NESTED_BEFORE="$(blocks "${TREE}/downloaded/nested/also-unnamed.vhd")"
CUSTOM_BEFORE="$(blocks "${TREE}/custom/fixture.qcow2")"
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" "${TREE}" \
    --files-from="${WORK}/forms-a.txt" \
    --files-from "${WORK}/forms-b.txt" \
    -- downloaded/named.qcow2 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0"
else
    fail "exit ${STATUS}: ${OUTPUT}"
fi
if [ "$(blocks "${TREE}/downloaded/named.qcow2")" -lt "${NAMED_BEFORE}" ] \
    && [ "$(blocks "${TREE}/downloaded/unnamed.qcow2")" -lt "${UNNAMED_BEFORE}" ] \
    && [ "$(blocks "${TREE}/downloaded/nested/also-unnamed.vhd")" -lt "${NESTED_BEFORE}" ]; then
    ok "all three forms contributed: attached list, separate list, path after --"
else
    fail "not every form was acted on: ${OUTPUT}"
fi
if [ "$(blocks "${TREE}/custom/fixture.qcow2")" = "${CUSTOM_BEFORE}" ]; then
    ok "and nothing outside the three was touched"
else
    fail "custom/fixture.qcow2 was rewritten: ${OUTPUT}"
fi

start "the extension list is published rather than copied"
# tools/ci/prepare-testdata.sh builds the changed-file list this mode
# consumes, and nothing else in the repository may hold a second copy of
# the extensions: a mirrored copy's only symptom when it drifts is a
# slower job.
STATUS=0
OUTPUT="$("${BASH_BIN}" "${SCRIPT}" --list-extensions 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ] && [ "$(echo "${OUTPUT}" | wc -l)" -ge 5 ]; then
    ok "--list-extensions prints $(echo "${OUTPUT}" | wc -l) extensions"
else
    fail "exit ${STATUS}: ${OUTPUT}"
fi
case "${OUTPUT}" in
    *qcow2*vmdk*vhd*vhdx*img*) ok "lists the five whole-disk image extensions" ;;
    *) fail "expected the five extensions in '${OUTPUT}'" ;;
esac

start "a failing copy is a failing run"
# The loud-failure half of the contract. An unwritable directory is the
# cheapest way to make cp fail; root ignores the mode bits, so there is
# nothing to test as root.
if [ "$(id -u)" -eq 0 ]; then
    skip "a failing copy is a failing run: running as root, which is not refused write access"
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
if [ "${SKIPS}" -ne 0 ]; then
    echo "${SKIPS} check(s) skipped:${SKIPPED_CASES}"
fi
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
if [ "${SKIPS}" -ne 0 ]; then
    echo "All checks passed, but ${SKIPS} were skipped and proved nothing"
    exit 0
fi
echo "All checks passed"
