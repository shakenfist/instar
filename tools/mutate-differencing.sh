#!/usr/bin/env bash
# Falsification harness for the differencing output path.
#
# This is not a coverage tool and it does not measure anything. It
# answers one question: can the tests that guard `instar create -f
# {vpc,vhdx} -b PARENT` actually fail? Each case breaks one specific
# behaviour in `src/` and demands that one named test notices. A test
# that still passes against a deliberately broken emitter is not
# guarding what its name says it guards.
#
# See docs/testing.md and docs/plans/PLAN-differencing.md.
#
# Vocabulary, which is the whole point of the script:
#
#   PASS   -- the mutation applied and the named test FAILED. The test
#             guards the property.
#   FAIL   -- the mutation applied and the named test still passed.
#             The test does not guard the property.
#   BROKEN -- the mutation could not be applied (the search string is
#             absent, or present more than once), or the test command
#             did not run (wrong package name, build error, zero tests
#             matched, test skipped). A mutation that cannot be applied
#             is NEVER scored as a PASS; earlier hand-rolled harnesses
#             did exactly that and reported success for code they had
#             never changed.
#
# Every edit goes through tools/replace-once.py, which is a literal
# find-and-replace that exits non-zero unless the search string occurs
# exactly once. No regex, no sed, no escaping rules to get wrong.
#
# The original file is copied to a scratch directory OUTSIDE the
# repository before each edit and copied back afterwards, including on
# interrupt. Restoring with `git checkout <path>` is deliberately
# avoided: it silently discards uncommitted work.
#
# Cases that mutate a guest operation (src/operations/) need `make
# instar` to rebuild and re-embed the operation binary before an
# integration test can see the change. The trap restores source, not
# build artefacts, so those cases rebuild again after restoring and the
# script rebuilds once more on exit.
#
# Usage:
#   tools/mutate-differencing.sh              # every case
#   tools/mutate-differencing.sh --list       # names only, run nothing
#   tools/mutate-differencing.sh NAME...      # only the named cases
#
# Exits non-zero if any case is FAIL or BROKEN.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="${REPO_ROOT}/tools/replace-once.py"
SCRATCH="$(mktemp -d)"

PASS_COUNT=0
FAIL_COUNT=0
BROKEN_COUNT=0
TOTAL_COUNT=0

# The file currently mutated, and the copy to put back. Empty when no
# mutation is outstanding, which is what makes the trap idempotent.
RESTORE_TO=''
RESTORE_FROM=''
# Whether any case has rebuilt the instar binary from mutated source.
BINARY_DIRTY='no'

LIST_ONLY='no'
SELECTED=()

rebuild_instar() {
    make -C "${REPO_ROOT}" instar >"${SCRATCH}/build.log" 2>&1
}

# shellcheck disable=SC2329  # invoked by the EXIT trap below.
cleanup() {
    local status=$?
    if [ -n "${RESTORE_TO}" ] && [ -f "${RESTORE_FROM}" ]; then
        echo "restoring ${RESTORE_TO}"
        cp -- "${RESTORE_FROM}" "${RESTORE_TO}"
        RESTORE_TO=''
    fi
    if [ "${BINARY_DIRTY}" = 'yes' ]; then
        echo 'rebuilding instar from restored source'
        rebuild_instar || echo 'WARNING: the final rebuild failed; run make instar by hand'
        BINARY_DIRTY='no'
    fi
    rm -rf -- "${SCRATCH}"
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

usage() {
    echo 'usage: tools/mutate-differencing.sh [--list] [CASE-NAME...]'
    echo
    echo '  --list   print the case names and what each runs, then stop'
    echo '  NAME...  run only the named cases (default: all of them)'
    echo
    echo 'Each case breaks one behaviour in src/ and requires one named'
    echo 'test to fail. PASS means the test caught it; FAIL means it did'
    echo 'not; BROKEN means the mutation or the test never ran at all.'
}

record() {
    # record VERDICT NAME DETAIL
    local verdict="$1" name="$2" detail="$3"
    case "${verdict}" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        *) BROKEN_COUNT=$((BROKEN_COUNT + 1)) ;;
    esac
    printf '%-6s %-38s %s\n' "${verdict}" "${name}" "${detail}"
}

wanted() {
    # wanted NAME -- is this case selected on the command line?
    local name="$1" candidate
    if [ "${#SELECTED[@]}" -eq 0 ]; then
        return 0
    fi
    for candidate in "${SELECTED[@]}"; do
        if [ "${candidate}" = "${name}" ]; then
            return 0
        fi
    done
    return 1
}

apply_mutation() {
    # apply_mutation NAME RELATIVE_FILE SEARCH REPLACE
    #
    # Copies the file aside, then applies exactly one literal
    # substitution. Returns 0 when the mutation landed, 1 otherwise
    # (having already recorded BROKEN and restored the file).
    local name="$1" relative="$2" search="$3" replace="$4"
    local target="${REPO_ROOT}/${relative}"

    if [ ! -f "${target}" ]; then
        record BROKEN "${name}" "target file is missing: ${relative}"
        return 1
    fi

    RESTORE_FROM="${SCRATCH}/${name}.orig"
    if ! cp -- "${target}" "${RESTORE_FROM}"; then
        record BROKEN "${name}" "could not copy ${relative} aside"
        return 1
    fi
    RESTORE_TO="${target}"

    if ! python3 "${HELPER}" "${target}" "${search}" "${replace}" \
            >"${SCRATCH}/${name}.mutate.log" 2>&1; then
        record BROKEN "${name}" "$(tail -n 2 "${SCRATCH}/${name}.mutate.log" | tr '\n' ' ')"
        restore_mutation
        return 1
    fi
    return 0
}

restore_mutation() {
    if [ -n "${RESTORE_TO}" ]; then
        cp -- "${RESTORE_FROM}" "${RESTORE_TO}"
        RESTORE_TO=''
    fi
}

rust_verdict() {
    # rust_verdict LOGFILE -- classify a `cargo test` run.
    local log="$1"
    if grep -q 'did not match any packages' "${log}"; then
        echo 'BROKEN did not match any packages'
        return
    fi
    if grep -qE '^test result: FAILED' "${log}"; then
        echo 'PASS the test failed, as required'
        return
    fi
    if grep -qE '^test result: ok\. [1-9][0-9]* passed' "${log}"; then
        echo 'FAIL the test still passed against mutated code'
        return
    fi
    if ! grep -qE '^test result:' "${log}"; then
        echo 'BROKEN the test command did not run (build error?)'
        return
    fi
    echo 'BROKEN no test matched the filter'
}

python_verdict() {
    # python_verdict LOGFILE -- classify a `python -m unittest` run.
    local log="$1"
    if ! grep -qE '^Ran [0-9]+ test' "${log}"; then
        echo 'BROKEN the test command did not run'
        return
    fi
    if grep -qE '^Ran 0 tests' "${log}"; then
        echo 'BROKEN no test matched the name'
        return
    fi
    if grep -qE 'skipped=' "${log}"; then
        echo 'BROKEN the test skipped'
        return
    fi
    if grep -qE '^FAILED \(' "${log}"; then
        echo 'PASS the test failed, as required'
        return
    fi
    if grep -qE '^OK' "${log}"; then
        echo 'FAIL the test still passed against mutated code'
        return
    fi
    echo 'BROKEN the outcome could not be read from the test output'
}

rust_case() {
    # rust_case NAME FILE SEARCH REPLACE PACKAGE TEST [CARGO_ARGS...]
    #
    # The package name is the Cargo package, not the directory. The vmm
    # crate's package is `instar`, not `vmm`; `cargo test -p vmm` says
    # "did not match any packages", which this harness reports as
    # BROKEN rather than as a test that failed.
    local name="$1" relative="$2" search="$3" replace="$4" package="$5" test_name="$6"
    shift 6
    wanted "${name}" || return 0
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if [ "${LIST_ONLY}" = 'yes' ]; then
        printf '%-38s rust %s :: %s\n' "${name}" "${package}" "${test_name}"
        return 0
    fi

    apply_mutation "${name}" "${relative}" "${search}" "${replace}" || return 0

    local log="${SCRATCH}/${name}.log"
    "${REPO_ROOT}/tools/cargo-in-container.sh" test --release \
        -p "${package}" "$@" -- "${test_name}" >"${log}" 2>&1

    restore_mutation
    local verdict
    verdict="$(rust_verdict "${log}")"
    record "${verdict%% *}" "${name}" "${test_name}: ${verdict#* }"
}

integration_case() {
    # integration_case NAME FILE SEARCH REPLACE UNITTEST_TARGET
    #
    # For mutations inside a guest operation. `src/operations/create`
    # is excluded from `cargo test --workspace` (see the Makefile), so
    # a unit test written beside that code would never run -- these
    # have to be caught through the real binary. That means a rebuild
    # before the test and another after the restore, because the trap
    # puts source back and not build artefacts.
    local name="$1" relative="$2" search="$3" replace="$4" target="$5"
    wanted "${name}" || return 0
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if [ "${LIST_ONLY}" = 'yes' ]; then
        printf '%-38s integration %s\n' "${name}" "${target}"
        return 0
    fi

    apply_mutation "${name}" "${relative}" "${search}" "${replace}" || return 0

    BINARY_DIRTY='yes'
    if ! rebuild_instar; then
        record BROKEN "${name}" "make instar failed against the mutated source"
        restore_mutation
        rebuild_instar || true
        BINARY_DIRTY='no'
        return 0
    fi

    local log="${SCRATCH}/${name}.log"
    (cd "${REPO_ROOT}/tests" && .venv/bin/python -m unittest "${target}") \
        >"${log}" 2>&1

    restore_mutation
    rebuild_instar || true
    BINARY_DIRTY='no'

    local verdict
    verdict="$(python_verdict "${log}")"
    record "${verdict%% *}" "${name}" "${target##*.}: ${verdict#* }"
}

# ---------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------

while [ "$#" -gt 0 ]; do
    case "$1" in
        --list) LIST_ONLY='yes' ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) SELECTED+=("$1") ;;
    esac
    shift
done

if [ ! -x "${REPO_ROOT}/tools/cargo-in-container.sh" ]; then
    echo 'tools/cargo-in-container.sh is missing or not executable' >&2
    exit 2
fi
if [ "${LIST_ONLY}" = 'no' ] && [ ! -x "${REPO_ROOT}/tests/.venv/bin/python" ]; then
    echo 'tests/.venv is missing; run make test-venv first' >&2
    exit 2
fi

# ---------------------------------------------------------------------
# The cases
#
# Emitter, in the `create` crate: what a differencing child records
# about its parent and how the parent's path is rendered.
# ---------------------------------------------------------------------

CREATE_LIB='src/crates/create/src/lib.rs'

rust_case 'vhd-locator-platform-code' "${CREATE_LIB}" \
    '                        (b"W2ku", path)' \
    '                        (b"W2ru", path)' \
    create 'vhd_differencing_platform_code_follows_the_path'

rust_case 'vhdx-locator-path-key' "${CREATE_LIB}" \
    '            (vhdx::KEY_ABSOLUTE_WIN32_PATH, path)' \
    '            (vhdx::KEY_RELATIVE_PATH, path)' \
    create 'vhdx_differencing_path_key_follows_the_path'

rust_case 'windows-relative-prefix' "${CREATE_LIB}" \
    'const WINDOWS_RELATIVE_PREFIX: &[u8] = br".\";' \
    'const WINDOWS_RELATIVE_PREFIX: &[u8] = br"_\";' \
    create 'a_bare_name_gains_the_prefix'

rust_case 'separator-collapsing' "${CREATE_LIB}" \
    '        previous_was_separator = is_separator;' \
    '        previous_was_separator = false;' \
    create 'repeated_separators_and_dot_components_collapse'

rust_case 'separator-translation' "${CREATE_LIB}" \
    "        *slot = if is_separator { b'\\\\' } else { *byte };" \
    '        *slot = *byte;' \
    create 'every_separator_is_translated'

rust_case 'dot-slash-consumption' "${CREATE_LIB}" \
    '        if let Some(tail) = rest.strip_prefix(b"./") {' \
    '        if let Some(tail) = rest.strip_prefix(b"../") {' \
    create 'a_leading_dot_slash_is_replaced_not_doubled'

rust_case 'empty-relative-path-refusal' "${CREATE_LIB}" \
    '    if rest.is_empty() {' \
    '    if rest.len() > 4096 {' \
    create 'a_relative_path_that_is_only_dots_is_refused'

rust_case 'backslash-refusal' "${CREATE_LIB}" \
    "    if bytes.contains(&b'\\\\') {" \
    "    if bytes.contains(&b'\\0') {" \
    create 'a_literal_backslash_is_refused_not_rendered'

rust_case 'parent-format-required' "${CREATE_LIB}" \
    '        ImageFormat::Vhd => ImageFormat::Vhd,' \
    '        ImageFormat::Vhd => return true,' \
    create 'a_vpc_child_takes_a_vhd_parent_and_nothing_else'

rust_case 'parent-format-hint-agreement' "${CREATE_LIB}" \
    '    matches!(hint, ImageFormat::Unknown) || hint == detected' \
    '    true' \
    create 'a_hint_the_bytes_disprove_is_refused'

rust_case 'footer-fallback-hint' "${CREATE_LIB}" \
    '        ImageFormat::Raw => matches!(hint, ImageFormat::Unknown | ImageFormat::Vhd),' \
    '        ImageFormat::Raw => true,' \
    create 'a_hint_that_contradicts_vhd_suppresses_the_fallback'

# The backward footer scan, added so a fixed VHD parent is found in the
# last sector rather than only at its offset zero.
rust_case 'vhd-footer-backward-scan' 'src/crates/vhd/src/lib.rs' \
    '    let mut slot = last_sector.len() / FOOTER_SIZE;' \
    '    let mut slot = 1;' \
    vhd 'footer_offset_fixed_4096_sector'

# Read side: how `info` renders a VHDX parent locator back to the user.
VHDX_LIB='src/crates/vhdx/src/lib.rs'

rust_case 'vhdx-posix-relative-rendering' "${VHDX_LIB}" \
    '    let body = match value.strip_prefix(br".\") {' \
    '    let body = match value.strip_prefix(br"._") {' \
    vhdx 'posix_relative_path_undoes_the_windows_rendering'

rust_case 'vhdx-relative-key-convention' "${VHDX_LIB}" \
    '            return Some((relative, true));' \
    '            return Some((relative, false));' \
    vhdx 'only_the_relative_key_is_flagged_as_windows_convention'

# ---------------------------------------------------------------------
# The create guest operation. Caught through the real binary only.
# ---------------------------------------------------------------------

CREATE_OP='src/operations/create/src/main.rs'
ROUND_TRIP='test_create.TestCreateSmoke.test_create_vhd_and_vhdx_differencing_round_trip'
MISMATCH='test_create.TestCreateSmoke.test_create_vhd_and_vhdx_reject_mismatched_parent_format'
FIXED_PARENT='test_create.TestCreateSmoke.test_create_vhd_differencing_from_a_fixed_parent'
DIFF_BACKING='test_differencing.TestDifferencingCreateRefusesAsBacking'
DIFF_BACKING="${DIFF_BACKING}.test_create_refuses_a_differencing_backing_file"

integration_case 'create-op-vhd-parent-identity' "${CREATE_OP}" \
    '        (ParentIdentity::Vhd { uuid, timestamp }, true) => (uuid, timestamp),' \
    '        (ParentIdentity::Vhd { .. }, true) => ([0u8; 16], 0),' \
    "${ROUND_TRIP}"

integration_case 'create-op-vhdx-parent-identity' "${CREATE_OP}" \
    '        (ParentIdentity::Vhdx { data_write_guid }, true) => data_write_guid,' \
    '        (ParentIdentity::Vhdx { .. }, true) => [0u8; 16],' \
    "${ROUND_TRIP}"

# The `-F` hint is part of the parent-format check, not just detection:
# a hint the parent's bytes disprove is refused. Dropping the hint from
# the call leaves the bytes to decide alone.
#
# Note what is NOT mutated here: the `(_, true) => Err(
# ERROR_PARENT_FORMAT_MISMATCH)` arms of `vhd_opts_from` and
# `vhdx_opts_from`. The operation refuses a wrong-format parent at the
# `parent_format_matches` call site above them and a format-right but
# identity-less parent immediately after, which the code comment there
# says makes those arms unreachable. A single substitution in an
# unreachable arm cannot change any observable behaviour, so there is
# no honest case to write for them.
integration_case 'create-op-parent-format-mismatch' "${CREATE_OP}" \
    $'        if !parent_format_matches(\n            target,\n            probe.format,\n            ImageFormat::from_u32(config.backing_format),\n        ) {' \
    $'        if !parent_format_matches(\n            target,\n            probe.format,\n            ImageFormat::Unknown,\n        ) {' \
    "${MISMATCH}"

integration_case 'create-op-vhd-differencing-refusal' "${CREATE_OP}" \
    '            if footer.disk_type == vhd::DISK_TYPE_DIFFERENCING {' \
    '            if footer.disk_type == vhd::DISK_TYPE_FIXED {' \
    "${DIFF_BACKING}"

integration_case 'create-op-vhdx-differencing-refusal' "${CREATE_OP}" \
    '            if state.has_parent {' \
    '            if state.has_parent && capacity == 0 {' \
    "${DIFF_BACKING}"

# The backing probe reads the parent's LAST sector, which is the only
# place a fixed VHD keeps its footer.
integration_case 'create-op-footer-reads-the-last-sector' "${CREATE_OP}" \
    '        && (call_table.read_input_sector)(0, capacity - 1, header_ptr, sector_size)' \
    '        && (call_table.read_input_sector)(0, 0, header_ptr, sector_size)' \
    "${FIXED_PARENT}"

# ---------------------------------------------------------------------
# Totals
# ---------------------------------------------------------------------

if [ "${LIST_ONLY}" = 'yes' ]; then
    echo "${TOTAL_COUNT} cases"
    exit 0
fi

echo
echo "${TOTAL_COUNT} cases: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${BROKEN_COUNT} BROKEN"

if [ "${FAIL_COUNT}" -ne 0 ] || [ "${BROKEN_COUNT}" -ne 0 ]; then
    echo 'logs from this run are deleted on exit; re-run a single case by name to keep looking'
    exit 1
fi
exit 0
