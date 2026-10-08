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
#   BROKEN -- the case proved nothing, for one of four reasons: the
#             mutation could not be applied (the search string is absent,
#             or present more than once); the test command did not run
#             (wrong package name, build error, zero tests matched); the
#             test skipped; or the test does not pass against unmutated
#             source in the first place, so its failure cannot be
#             attributed to the mutation.
#
#             A case that proved nothing is NEVER scored as a PASS.
#             Earlier hand-rolled harnesses did exactly that and
#             reported success for code they had never changed, and this
#             script shipped with a narrower version of the same bug: it
#             read unittest's `FAILED (errors=1)` -- setUpClass raising
#             because the testdata checkout was missing -- as a caught
#             mutation, so a run with no testdata scored PASS for every
#             integration case without evaluating one assertion.
#
# Every edit goes through tools/replace-once.py, which is a literal
# find-and-replace that exits non-zero unless the search string occurs
# exactly once. No regex, no sed, no escaping rules to get wrong.
#
# The original file is copied into .mutation-backups/ (gitignored)
# before each edit and copied back afterwards, including on interrupt.
# Restoring with `git checkout <path>` is deliberately avoided: it
# silently discards uncommitted work.
#
# That backup deliberately lives inside the repository rather than in a
# `mktemp -d`, because a `mktemp -d` dies with the process: a `kill -9`
# mid-case used to leave mutated source in the tree with the only copy
# of the original already gone. A mutation is a small, deliberate,
# COMPILING change -- pre-commit passes on it, `cargo build` passes on
# it -- so nothing downstream would stop someone committing it. Hence
# the second line of defence: this script refuses to start when `src/`
# has uncommitted modifications, so an interrupted run is caught at the
# next invocation instead of at some later commit. Pass
# --allow-dirty-src when you are deliberately working on `src/` and
# know what the modifications are.
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
#   tools/mutate-differencing.sh --self-test  # check the verdict classifier
#   tools/mutate-differencing.sh --check-patterns  # do the mutations still land?
#   tools/mutate-differencing.sh --allow-dirty-src   # run over a dirty src/
#
# The four oracle-* cases need `vhdiinfo` on PATH (Debian:
# libvhdi-utils); the tests they name skip without it, which the
# harness scores as BROKEN.
#
# Exits non-zero if any case is FAIL or BROKEN.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="${REPO_ROOT}/tools/replace-once.py"
SCRATCH="$(mktemp -d)"

# The repository root as git sees it. This may be a worktree, so ask
# git rather than assuming REPO_ROOT is a clone.
GIT_ROOT="$(git -C "${REPO_ROOT}" rev-parse --show-toplevel 2>/dev/null || echo "${REPO_ROOT}")"

# Per-case backups of the mutated file. Inside the repository and
# gitignored, so that they outlive a `kill -9` and can be found again.
BACKUP_DIR="${GIT_ROOT}/.mutation-backups"

# Logs of cases that did not pass. SCRATCH dies with the process, and
# the one moment the cargo or unittest output is actually wanted is
# when something went wrong, so those are copied somewhere that
# survives. Cleared at the start of each run: a stale log read as a
# current one is worse than no log.
LOG_DIR="${BACKUP_DIR}/logs"

# Where the integration tests look for their images. Resolved exactly as
# tests/base.py:_load_manifest resolves it, so the preflight below fails
# for the same reason the tests would.
TESTDATA_PATH="${INSTAR_TESTDATA_PATH:-$(dirname "${REPO_ROOT}")/instar-testdata}"

PASS_COUNT=0
FAIL_COUNT=0
BROKEN_COUNT=0
TOTAL_COUNT=0

# The file currently mutated, and the copy to put back. Empty when no
# mutation is outstanding, which is what makes the trap idempotent.
RESTORE_TO=''
RESTORE_FROM=''
RESTORE_RELATIVE=''
# Set when a copy back failed, so the run cannot exit 0 over a mutated tree.
RESTORE_FAILED='no'
# Whether any case has rebuilt the instar binary from mutated source.
BINARY_DIRTY='no'

LIST_ONLY='no'
ALLOW_DIRTY_SRC='no'
SELF_TEST='no'
CHECK_PATTERNS='no'
SELECTED=()
# Names from SELECTED that matched a real case; see check_selection_matched.
declare -A MATCHED

rebuild_instar() {
    make -C "${REPO_ROOT}" instar >"${SCRATCH}/build.log" 2>&1
}

backup_path_for() {
    # backup_path_for RELATIVE -- where the pristine copy of a source
    # file is kept. The relative path is encoded into the file name (`/`
    # becomes `%`) so that one leftover file names both the backup and
    # the thing it restores, with no sidecar to get out of step with it.
    printf '%s/%s.orig\n' "${BACKUP_DIR}" "${1//\//%}"
}

leftover_backups() {
    # Print "RELATIVE<tab>BACKUP" for each backup an earlier run left
    # behind. Silent when there are none.
    local backup base
    [ -d "${BACKUP_DIR}" ] || return 0
    for backup in "${BACKUP_DIR}"/*.orig; do
        [ -f "${backup}" ] || continue
        base="$(basename -- "${backup}" .orig)"
        printf '%s\t%s\n' "${base//%//}" "${backup}"
    done
}

discard_backup() {
    # discard_backup RELATIVE -- the file is back to its original
    # contents, so the copy has no further job to do.
    local backup
    backup="$(backup_path_for "$1")"
    rm -f -- "${backup}"
    rmdir -- "${BACKUP_DIR}" 2>/dev/null || true
}

# shellcheck disable=SC2329  # invoked by the EXIT trap below.
cleanup() {
    local status=$?
    if [ -n "${RESTORE_TO}" ] && [ -f "${RESTORE_FROM}" ]; then
        echo "restoring ${RESTORE_TO}"
        restore_mutation
    fi
    if [ "${BINARY_DIRTY}" = 'yes' ]; then
        echo 'rebuilding instar from restored source'
        rebuild_instar || echo 'WARNING: the final rebuild failed; run make instar by hand'
        BINARY_DIRTY='no'
    fi
    rm -rf -- "${SCRATCH}"
    # A run that left mutated source behind cannot report success, even
    # if every case passed before the restore failed.
    if [ "${RESTORE_FAILED}" = 'yes' ] && [ "${status}" -eq 0 ]; then
        status=1
    fi
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

usage() {
    echo 'usage: tools/mutate-differencing.sh [--list] [--self-test] [--check-patterns] [--allow-dirty-src] [CASE-NAME...]'
    echo
    echo '  --list              print the case names and what each runs, then stop'
    echo '  --self-test         check the verdict classifier against synthetic'
    echo '                      logs and stop; needs no docker, venv or testdata'
    echo '  --check-patterns    check every mutation still has exactly one place'
    echo '                      to land, and stop; mutates and builds nothing'
    echo '  --allow-dirty-src   run even though src/ has uncommitted modifications'
    echo '  NAME...             run only the named cases (default: all of them)'
    echo
    echo 'Each case breaks one behaviour in src/ and requires one named'
    echo 'test to fail. PASS means the test caught it; FAIL means it did'
    echo 'not; BROKEN means the case proved nothing.'
}

keep_log() {
    # keep_log SOURCE NAME -- preserve a log for a case that did not pass.
    local source="$1" name="$2"
    [ -f "${source}" ] || return 0
    mkdir -p "${LOG_DIR}" 2>/dev/null || return 0
    cp -- "${source}" "${LOG_DIR}/${name}.log" 2>/dev/null || return 0
    printf '       log: %s\n' "${LOG_DIR}/${name}.log"
}

record() {
    # record VERDICT NAME DETAIL
    local verdict="$1" name="$2" detail="$3"
    case "${verdict}" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        SURVIVOR) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        *) BROKEN_COUNT=$((BROKEN_COUNT + 1)) ;;
    esac
    printf '%-8s %-48s %s\n' "${verdict}" "${name}" "${detail}"
    if [ "${verdict}" != 'PASS' ] && [ "${verdict}" != 'SURVIVOR' ]; then
        keep_log "${SCRATCH}/${name}.log" "${name}"
    fi
}

wanted() {
    # wanted NAME -- is this case selected on the command line?
    #
    # Matches are recorded so the totals block can refuse a selection
    # that named nothing. Without that, a mistyped or renamed case ran
    # no cases and the script printed `0 cases: 0 PASS, 0 FAIL, 0
    # BROKEN` and exited 0 -- a clean bill of health for work never
    # done, which is the failure this script exists to refuse.
    local name="$1" candidate
    if [ "${#SELECTED[@]}" -eq 0 ]; then
        return 0
    fi
    for candidate in "${SELECTED[@]}"; do
        if [ "${candidate}" = "${name}" ]; then
            MATCHED["${name}"]=1
            return 0
        fi
    done
    return 1
}

check_selection_matched() {
    # Every name given on the command line has to correspond to a case.
    local candidate missing=()
    [ "${#SELECTED[@]}" -eq 0 ] && return 0
    for candidate in "${SELECTED[@]}"; do
        [ -n "${MATCHED[${candidate}]+set}" ] || missing+=("${candidate}")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    echo >&2
    echo "no such case: ${missing[*]}" >&2
    echo 'Run --list for the case names. Nothing was run for those arguments,' >&2
    echo 'so this is a failure rather than an empty pass.' >&2
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

    RESTORE_FROM="$(backup_path_for "${relative}")"
    if ! mkdir -p -- "${BACKUP_DIR}" || ! cp -- "${target}" "${RESTORE_FROM}"; then
        record BROKEN "${name}" "could not copy ${relative} aside"
        return 1
    fi
    RESTORE_TO="${target}"
    RESTORE_RELATIVE="${relative}"

    if ! python3 "${HELPER}" "${target}" "${search}" "${replace}" \
            >"${SCRATCH}/${name}.mutate.log" 2>&1; then
        record BROKEN "${name}" "$(tail -n 2 "${SCRATCH}/${name}.mutate.log" | tr '\n' ' ')"
        keep_log "${SCRATCH}/${name}.mutate.log" "${name}-mutate"
        restore_mutation
        return 1
    fi
    return 0
}

restore_mutation() {
    # The backup is discarded only if the copy back actually worked.
    # Discarding it unconditionally threw away the one pristine copy at
    # the exact moment it was needed -- a full disk or a read-only
    # mount would leave the tree mutated with nothing to restore from,
    # which is the scenario this directory exists to survive.
    if [ -n "${RESTORE_TO}" ]; then
        if cp -- "${RESTORE_FROM}" "${RESTORE_TO}"; then
            discard_backup "${RESTORE_RELATIVE}"
            RESTORE_TO=''
        else
            RESTORE_FAILED='yes'
            echo >&2
            echo "RESTORE FAILED: ${RESTORE_TO} still holds a mutation." >&2
            echo "  the pristine copy is kept at ${RESTORE_FROM}" >&2
            echo "  restore it with: cp -- ${RESTORE_FROM} ${RESTORE_TO}" >&2
        fi
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
    #
    # The order here is load-bearing, and one ordering used to be wrong.
    # unittest reports an exception raised outside an assertion as
    # `FAILED (errors=1)` -- setUpClass blowing up, an import error,
    # InstarTestBase._load_manifest raising because the testdata
    # checkout is absent (tests/base.py). That is the same `^FAILED (`
    # line a caught mutation produces, so matching on the word FAILED
    # alone scored PASS for a run in which no assertion was ever
    # evaluated: precisely the unearned pass this script exists to
    # refuse. A genuine catch always surfaces as `failures=`.
    #
    # `skipped=` is tested after `failures=` so that a run which caught
    # the mutation and skipped something else -- `FAILED (failures=1,
    # skipped=1)` -- is scored on the catch rather than on the skip.
    local log="$1" summary
    if ! grep -qE '^Ran [0-9]+ test' "${log}"; then
        echo 'BROKEN the test command did not run'
        return
    fi
    if grep -qE '^Ran 0 tests' "${log}"; then
        echo 'BROKEN no test matched the name'
        return
    fi
    summary="$(grep -E '^(OK|FAILED)\b' "${log}" | tail -1)"
    case "${summary}" in
        '')
            echo 'BROKEN the outcome could not be read from the test output' ;;
        *errors=*)
            echo 'BROKEN the test errored instead of failing; no assertion ran' ;;
        FAILED*failures=*)
            echo 'PASS the test failed, as required' ;;
        *skipped=*)
            echo 'BROKEN the test skipped' ;;
        OK*)
            echo 'FAIL the test still passed against mutated code' ;;
        *)
            echo 'BROKEN the outcome could not be read from the test output' ;;
    esac
}

# A mutation case proves something only if the test it names passes
# against unmutated source. A test that is already red -- broken on
# develop, or red for an environmental reason that fails rather than
# skips -- fails again with the mutation applied and scores PASS
# without the mutation having anything to do with it. That is the same
# false confidence as a mutation that never applied, which
# replace-once.py closes; this closes the other half.
#
# Baselines are run lazily and cached per target, so a run selecting
# one case pays for one baseline, and the 21 distinct targets behind
# the 26 cases are each measured once.
declare -A BASELINE_VERDICT

# 'yes' once the instar binary is known to be built from unmutated
# source, so the integration baselines do not each force a rebuild.
CLEAN_BINARY='no'

ensure_clean_binary() {
    # The integration cases exercise the real binary, so a baseline has
    # to run against one built from clean source.
    [ "${CLEAN_BINARY}" = 'yes' ] && return 0
    rebuild_instar || return 1
    CLEAN_BINARY='yes'
}

rust_baseline_ok() {
    # rust_baseline_ok PACKAGE TEST [CARGO_ARGS...] -- does this test
    # pass against unmutated source? Cached; call only while the tree is
    # clean.
    local package="$1" test_name="$2"
    shift 2
    local key="rust|${package}|${test_name}|$*"
    if [ -z "${BASELINE_VERDICT[${key}]+set}" ]; then
        local log="${SCRATCH}/baseline-${package}-${test_name}.log"
        "${REPO_ROOT}/tools/cargo-in-container.sh" test --release \
            -p "${package}" "$@" -- "${test_name}" >"${log}" 2>&1
        # cargo treats the filter as a substring, so a name that is a
        # prefix of another test would run both and the case could then
        # be scored on the wrong test's failure. Requiring the baseline
        # to have run exactly ONE test -- summed across every test
        # binary in the package, since a filter can match in more than
        # one -- closes that without depending on --exact, which needs
        # the full module path and so matches nothing at all for the
        # unit tests nested in `mod tests`.
        local passed failed
        passed="$(awk '/^test result: ok\. [0-9]+ passed/ {sum += $4} END {print sum + 0}' "${log}")"
        failed="$(grep -cE '^test result: FAILED' "${log}")"
        if [ "${passed}" = '1' ] && [ "${failed}" = '0' ]; then
            BASELINE_VERDICT["${key}"]='ok'
        else
            BASELINE_VERDICT["${key}"]='bad'
        fi
    fi
    [ "${BASELINE_VERDICT[${key}]}" = 'ok' ]
}

python_baseline_ok() {
    # python_baseline_ok TARGET -- does this test pass against
    # unmutated source, without skipping? Cached; call only while the
    # tree is clean.
    local target="$1"
    local key="py|${target}"
    if [ -z "${BASELINE_VERDICT[${key}]+set}" ]; then
        local log="${SCRATCH}/baseline-${target}.log"
        if ! ensure_clean_binary; then
            BASELINE_VERDICT["${key}"]='bad'
        else
            (cd "${REPO_ROOT}/tests" && .venv/bin/python -m unittest "${target}") \
                >"${log}" 2>&1
            # `OK` and nothing else: a baseline that skipped measures
            # nothing, and is the state the oracle cases land in when
            # vhdiinfo is missing.
            if grep -qE '^OK$' "${log}"; then
                BASELINE_VERDICT["${key}"]='ok'
            else
                BASELINE_VERDICT["${key}"]='bad'
            fi
        fi
    fi
    [ "${BASELINE_VERDICT[${key}]}" = 'ok' ]
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
        printf '%-48s rust %s :: %s\n' "${name}" "${package}" "${test_name}"
        return 0
    fi
    if [ "${CHECK_PATTERNS}" = 'yes' ]; then
        check_pattern "${name}" "${relative}" "${search}"
        return 0
    fi

    if ! rust_baseline_ok "${package}" "${test_name}" "$@"; then
        record BROKEN "${name}" "${test_name}: does not pass against unmutated source"
        keep_log "${SCRATCH}/baseline-${package}-${test_name}.log" "${name}-baseline"
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

rust_survivor_case() {
    # rust_survivor_case NAME FILE SEARCH REPLACE PACKAGE TEST [CARGO_ARGS...]
    #
    # A mutation that is EXPECTED to survive, with the reason recorded
    # at the case. These are here rather than deleted because a
    # surviving mutation is a real result about the tests, and the next
    # person to find it should read the reason instead of concluding
    # the test is weak. check_case_count asserts how many there are
    # against docs/testing.md, so the prose cannot drift from the
    # script.
    #
    # The verdict is therefore inverted: surviving is SURVIVOR and
    # scores as a pass, and being killed is FAIL -- not because
    # catching a bug is bad, but because it means the documented reason
    # no longer holds and the comment is now lying. Either the test set
    # grew a check the comment does not know about, or the code moved.
    # Read the case, confirm which, and then either promote it to a
    # rust_case or rewrite the reason.
    local name="$1" relative="$2" search="$3" replace="$4" package="$5" test_name="$6"
    shift 6
    wanted "${name}" || return 0
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if [ "${LIST_ONLY}" = 'yes' ]; then
        printf '%-48s rust %s :: %s (survivor)\n' "${name}" "${package}" "${test_name}"
        return 0
    fi
    if [ "${CHECK_PATTERNS}" = 'yes' ]; then
        check_pattern "${name}" "${relative}" "${search}"
        return 0
    fi

    if ! rust_baseline_ok "${package}" "${test_name}" "$@"; then
        record BROKEN "${name}" "${test_name}: does not pass against unmutated source"
        keep_log "${SCRATCH}/baseline-${package}-${test_name}.log" "${name}-baseline"
        return 0
    fi

    apply_mutation "${name}" "${relative}" "${search}" "${replace}" || return 0

    local log="${SCRATCH}/${name}.log"
    "${REPO_ROOT}/tools/cargo-in-container.sh" test --release \
        -p "${package}" "$@" -- "${test_name}" >"${log}" 2>&1

    restore_mutation
    local verdict
    verdict="$(rust_verdict "${log}")"
    case "${verdict%% *}" in
        FAIL)
            # The mutation survived, which is what this case asserts.
            record SURVIVOR "${name}" "${test_name}: survived, as documented"
            ;;
        PASS)
            record FAIL "${name}" \
                "${test_name}: killed a mutation documented as surviving; the reason at this case is stale"
            ;;
        *)
            record "${verdict%% *}" "${name}" "${test_name}: ${verdict#* }"
            ;;
    esac
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
        printf '%-48s integration %s\n' "${name}" "${target}"
        return 0
    fi
    if [ "${CHECK_PATTERNS}" = 'yes' ]; then
        check_pattern "${name}" "${relative}" "${search}"
        return 0
    fi

    if ! python_baseline_ok "${target}"; then
        record BROKEN "${name}" "${target##*.}: does not pass against unmutated source"
        keep_log "${SCRATCH}/baseline-${target}.log" "${name}-baseline"
        return 0
    fi

    apply_mutation "${name}" "${relative}" "${search}" "${replace}" || return 0

    BINARY_DIRTY='yes'
    CLEAN_BINARY='no'
    if ! rebuild_instar; then
        record BROKEN "${name}" "make instar failed against the mutated source"
        restore_mutation
        if rebuild_instar; then
            CLEAN_BINARY='yes'
        fi
        BINARY_DIRTY='no'
        return 0
    fi

    local log="${SCRATCH}/${name}.log"
    (cd "${REPO_ROOT}/tests" && .venv/bin/python -m unittest "${target}") \
        >"${log}" 2>&1

    restore_mutation
    if rebuild_instar; then
        CLEAN_BINARY='yes'
    fi
    BINARY_DIRTY='no'

    local verdict
    verdict="$(python_verdict "${log}")"
    record "${verdict%% *}" "${name}" "${target##*.}: ${verdict#* }"
}

self_test() {
    # The verdict functions are the harness's own logic, and they are
    # the part with no test above them: every other check here is
    # performed BY them. One of them shipped a bug -- `FAILED (errors=1)`
    # read as a caught mutation -- that no amount of running the harness
    # would have surfaced, because the environment it misreads is the
    # one nobody runs it in. So they are checked against synthetic logs,
    # in milliseconds, with no docker, no venv and no testdata.
    local failures=0
    local log="${SCRATCH}/self-test.log"

    assert_verdict() {
        # assert_verdict VERDICT_FN EXPECTED DESCRIPTION -- the log is already
        # written to ${log}.
        local fn="$1" expected="$2" description="$3" got
        got="$("${fn}" "${log}")"
        if [ "${got%% *}" != "${expected}" ]; then
            printf 'self-test FAIL: %s\n  wanted %s, got %s\n' \
                "${description}" "${expected}" "${got}" >&2
            failures=$((failures + 1))
        fi
    }

    printf 'Ran 1 test in 0.1s\n\nFAILED (failures=1)\n' >"${log}"
    assert_verdict python_verdict PASS 'python: a caught mutation'

    printf 'Ran 2 tests in 0.1s\n\nFAILED (failures=1, skipped=1)\n' >"${log}"
    assert_verdict python_verdict PASS 'python: caught, with an unrelated skip'

    printf 'Ran 1 test in 0.1s\n\nFAILED (errors=1)\n' >"${log}"
    assert_verdict python_verdict BROKEN 'python: setUpClass raised; no assertion ran'

    printf 'Ran 1 test in 0.1s\n\nFAILED (errors=1, failures=1)\n' >"${log}"
    assert_verdict python_verdict BROKEN 'python: an error alongside a failure is not trusted'

    printf 'Ran 1 test in 0.1s\n\nOK\n' >"${log}"
    assert_verdict python_verdict FAIL 'python: the test did not notice the mutation'

    printf 'Ran 1 test in 0.1s\n\nOK (skipped=1)\n' >"${log}"
    assert_verdict python_verdict BROKEN 'python: the test skipped'

    printf 'Ran 0 tests in 0.0s\n\nOK\n' >"${log}"
    assert_verdict python_verdict BROKEN 'python: the name matched nothing'

    : >"${log}"
    assert_verdict python_verdict BROKEN 'python: the command did not run'

    printf 'test result: FAILED. 0 passed; 1 failed\n' >"${log}"
    assert_verdict rust_verdict PASS 'rust: a caught mutation'

    printf 'test result: ok. 1 passed; 0 failed\n' >"${log}"
    assert_verdict rust_verdict FAIL 'rust: the test did not notice the mutation'

    printf 'test result: ok. 0 passed; 0 failed\n' >"${log}"
    assert_verdict rust_verdict BROKEN 'rust: the filter matched nothing'

    printf 'error: package ID specification vmm did not match any packages\n' >"${log}"
    assert_verdict rust_verdict BROKEN 'rust: wrong package name'

    : >"${log}"
    assert_verdict rust_verdict BROKEN 'rust: the build failed'

    if [ "${failures}" -ne 0 ]; then
        echo "self-test: ${failures} verdict(s) misclassified" >&2
        return 1
    fi
    echo 'self-test: verdict classification is correct'
    return 0
}

# The number of cases. docs/testing.md quotes this figure and the
# phase's definition of done asks the two to stay in step, which until
# now was a promise kept by hand. Asserting it makes the drift a
# failure instead of a documentation bug nobody reads.
EXPECTED_CASES=95

check_case_count() {
    # Only meaningful for a whole run; a selection is expected to be short.
    [ "${#SELECTED[@]}" -eq 0 ] || return 0

    # The figure is read out of the document rather than promised to
    # match it by a comment. A branch whose argument is that a claim
    # should be derivable cannot leave its own claim hand-maintained.
    local documented bad='no'
    documented="$(grep -oE 'There are \*\*[0-9]+ cases\*\*' \
        "${REPO_ROOT}/docs/testing.md" 2>/dev/null | grep -oE '[0-9]+' | head -1)"

    # The reader and survivor counts are quoted in prose too, and three
    # review items in one round were that prose going stale against the
    # script. Derive both from the source of truth -- the case list in
    # this file -- and make docs/testing.md state them in a form that
    # can be checked, rather than trusting anyone to update two places.
    local reader_actual survivor_actual reader_doc survivor_doc
    reader_actual="$(grep -cE "^rust_(survivor_)?case '(vhd|vhdx)-read-" "${BASH_SOURCE[0]}")"
    survivor_actual="$(grep -cE '^rust_survivor_case ' "${BASH_SOURCE[0]}")"
    reader_doc="$(grep -oE '\*\*[0-9]+ reader cases\*\*' \
        "${REPO_ROOT}/docs/testing.md" 2>/dev/null | grep -oE '[0-9]+' | head -1)"
    survivor_doc="$(grep -oE '\*\*[0-9]+ survivor cases?\*\*' \
        "${REPO_ROOT}/docs/testing.md" 2>/dev/null | grep -oE '[0-9]+' | head -1)"
    if [ "${reader_doc:-x}" != "${reader_actual}" ]; then
        echo >&2
        echo "docs/testing.md says '${reader_doc:-no}' reader cases;" >&2
        echo "this script defines ${reader_actual}." >&2
        bad='yes'
    fi
    if [ "${survivor_doc:-x}" != "${survivor_actual}" ]; then
        echo >&2
        echo "docs/testing.md says '${survivor_doc:-no}' survivor cases;" >&2
        echo "this script defines ${survivor_actual}." >&2
        bad='yes'
    fi

    if [ "${TOTAL_COUNT}" -ne "${EXPECTED_CASES}" ]; then
        echo >&2
        echo "case count is ${TOTAL_COUNT}, but EXPECTED_CASES says ${EXPECTED_CASES}." >&2
        bad='yes'
    fi
    if [ -z "${documented}" ]; then
        echo >&2
        echo 'docs/testing.md no longer states the case count in the form' >&2
        echo '"There are **N cases**", so it cannot be checked against.' >&2
        bad='yes'
    elif [ "${documented}" -ne "${EXPECTED_CASES}" ]; then
        echo >&2
        echo "docs/testing.md says ${documented} cases, EXPECTED_CASES says ${EXPECTED_CASES}." >&2
        bad='yes'
    fi
    [ "${bad}" = 'no' ] && return 0
    echo 'Update EXPECTED_CASES and docs/testing.md together.' >&2
    return 1
}

check_pattern() {
    # check_pattern NAME RELATIVE SEARCH -- does this mutation still have
    # exactly one place to land?
    #
    # The search strings are pinned to src/ byte for byte, indentation
    # included, so a reformat or a refactor of the emitter turns cases
    # BROKEN. Without this, nothing would notice until someone spent the
    # full docker-and-testdata run -- and a harness that has rotted
    # quietly is worse than no harness, because its green is trusted.
    local name="$1" relative="$2" search="$3" count
    count="$(SEARCH="${search}" python3 -c '
import os, sys
try:
    text = open(sys.argv[1], encoding="utf-8").read()
except OSError as exc:
    print("unreadable (%s)" % exc)
else:
    print(text.count(os.environ["SEARCH"]))
' "${REPO_ROOT}/${relative}")"
    # PASS and BROKEN are defined as facts about a mutation that was
    # applied and a test that ran, and neither happens here. A script
    # whose central argument is that a verdict word means exactly one
    # thing should not overload its own vocabulary.
    if [ "${count}" = '1' ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf '%-6s %-48s %s\n' 'LANDS' "${name}" "${relative}"
    else
        BROKEN_COUNT=$((BROKEN_COUNT + 1))
        printf '%-6s %-48s %s\n' 'DRIFT' "${name}" \
            "${relative}: ${count} places to land, expected 1"
    fi
}

# ---------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------

while [ "$#" -gt 0 ]; do
    case "$1" in
        --list) LIST_ONLY='yes' ;;
        --self-test) SELF_TEST='yes' ;;
        --check-patterns) CHECK_PATTERNS='yes' ;;
        --allow-dirty-src) ALLOW_DIRTY_SRC='yes' ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) SELECTED+=("$1") ;;
    esac
    shift
done

if [ "${SELF_TEST}" = 'yes' ]; then
    self_test
    exit $?
fi
if [ "${CHECK_PATTERNS}" = 'no' ] && [ ! -x "${REPO_ROOT}/tools/cargo-in-container.sh" ]; then
    echo 'tools/cargo-in-container.sh is missing or not executable' >&2
    exit 2
fi
# REPO_ROOT is derived from this script's own location; GIT_ROOT is what
# git says. They are the same directory for a clone and for a worktree,
# and everything here assumes it: mutations are written under REPO_ROOT
# while the dirty-source check, the backups and the printed restore
# command all use GIT_ROOT. If they ever diverge -- a symlinked tools/,
# a submodule, a stray .git -- the safety check would be inspecting one
# tree while the script mutated another, so refuse rather than guess.
if [ "${REPO_ROOT}" != "${GIT_ROOT}" ]; then
    echo 'refusing to start: the script'"'"'s root and git'"'"'s root disagree.' >&2
    echo "    script: ${REPO_ROOT}" >&2
    echo "    git:    ${GIT_ROOT}" >&2
    echo 'The dirty-source check and the backups follow git; the mutations follow the' >&2
    echo 'script. They have to be the same tree.' >&2
    exit 2
fi
if [ "${LIST_ONLY}" = 'no' ] && [ "${CHECK_PATTERNS}" = 'no' ] \
   && [ ! -d "${TESTDATA_PATH}" ]; then
    echo "testdata not found at ${TESTDATA_PATH}" >&2
    echo 'The integration cases load tests/manifest.json against a testdata checkout;' >&2
    echo 'without it setUpClass raises and unittest reports FAILED (errors=1), which' >&2
    echo 'looks like a caught mutation but is not. Set INSTAR_TESTDATA_PATH or put' >&2
    echo 'instar-testdata beside this checkout.' >&2
    exit 2
fi
if [ "${LIST_ONLY}" = 'no' ] && [ "${CHECK_PATTERNS}" = 'no' ] \
   && [ ! -x "${REPO_ROOT}/tests/.venv/bin/python" ]; then
    echo 'tests/.venv is missing; run make test-venv first' >&2
    exit 2
fi
# Not fatal, but worth saying once rather than four times: the oracle
# cases name tests that skip without libvhdi, and a skipped test scores
# BROKEN here, which reads like a harness fault rather than a missing
# package.
if [ "${LIST_ONLY}" = 'no' ] && [ "${CHECK_PATTERNS}" = 'no' ] \
   && ! command -v vhdiinfo >/dev/null 2>&1; then
    echo 'warning: vhdiinfo is not on PATH (Debian: libvhdi-utils).' >&2
    echo '         The oracle-* cases will report BROKEN: the tests they name' >&2
    echo '         skip without it rather than running.' >&2
    echo >&2
fi

report_leftover_backups() {
    # Print the restore command for every backup an earlier run left
    # behind. Returns 0 if it printed anything.
    local relative backup printed='no'
    while IFS=$'\t' read -r relative backup; do
        [ -n "${relative}" ] || continue
        printed='yes'
        echo "  a pristine copy of ${relative} was kept by an earlier run; restore it with:" >&2
        echo "    cp -- ${backup} ${GIT_ROOT}/${relative}" >&2
    done < <(leftover_backups)
    [ "${printed}" = 'yes' ]
}

check_src_is_clean() {
    # A mutation is a small, deliberate, COMPILING change: pre-commit
    # and cargo build both pass on mutated source, so a run that was
    # killed before its trap could fire leaves a tree that nothing else
    # in the workflow would object to. Refuse to start on top of that,
    # so the damage is visible here rather than in a later commit.
    local dirty
    dirty="$(git -C "${GIT_ROOT}" status --porcelain -- src/)"
    if [ -z "${dirty}" ]; then
        if report_leftover_backups; then
            echo '  src/ is clean, so those copies are stale; they will be reused or replaced.' >&2
            echo >&2
        fi
        return 0
    fi

    if [ "${ALLOW_DIRTY_SRC}" = 'yes' ]; then
        echo 'warning: src/ has uncommitted modifications and --allow-dirty-src was given.' >&2
        echo "${dirty}" >&2
        echo >&2
        return 0
    fi

    echo 'refusing to start: src/ has uncommitted modifications.' >&2
    echo >&2
    echo "${dirty}" >&2
    echo >&2
    echo 'This harness mutates src/ and restores it afterwards. If an earlier run was' >&2
    echo 'killed (rather than interrupted with Ctrl-C) it can leave its mutation applied,' >&2
    echo 'and a mutation still compiles, so nothing else in the workflow would catch it.' >&2
    echo 'Running now would back up the mutated file as if it were the original.' >&2
    echo >&2
    echo 'Inspect what changed with:' >&2
    echo "    git -C ${GIT_ROOT} diff -- src/" >&2
    echo 'Then restore it:' >&2
    if ! report_leftover_backups; then
        echo "  no backup was kept; discard the modifications with:" >&2
        echo "    git -C ${GIT_ROOT} checkout -- src/" >&2
    fi
    echo >&2
    echo 'If the modifications are your own work in progress and you want them mutated' >&2
    echo 'on top of, re-run with --allow-dirty-src.' >&2
    exit 2
}

if [ "${CHECK_PATTERNS}" = 'yes' ]; then
    echo 'pattern check: no mutation is applied and no test is run.'
    echo
fi
if [ "${LIST_ONLY}" = 'no' ] && [ "${CHECK_PATTERNS}" = 'no' ]; then
    check_src_is_clean
    # Stale logs from an earlier run must not be mistaken for this one's.
    rm -rf -- "${LOG_DIR}"
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

# How large a BAT the emitter declares for a differencing child. The
# mutation sizes it by the no-parent rule, which is what instar did
# before: one entry per payload block plus one per chunk group, rather
# than whole groups of chunk_ratio + 1 entries. At most geometries the
# shortfall vanishes into the 1 MiB region rounding, which is why the
# named test is the one that picks a geometry where it does not.
rust_case 'vhdx-write-differencing-bat-sized-as-dynamic' "${VHDX_LIB}" \
    '    let total_bat_entries = if has_parent {' \
    '    let total_bat_entries = if false {  // MUTATED' \
    create 'vhdx_differencing_bat_region_covers_the_last_group_bitmap'

# ---------------------------------------------------------------------
# The guest chain walker: composing a differencing VHD or VHDX against
# the device behind it. Everything above this point mutates the code
# that *writes* a differencing image; these mutate the code that reads
# one back.
#
# All of them name a test in the qcow2 crate, because that is where the
# chain walker lives, and all of them need the full input-format feature
# set -- the arms are behind `vhd-input` and `vhdx-input`, so a run
# without them compiles the mutation away and reports a pass nobody
# earned. QCOW2_FEATURES carries that list; it is the same one the
# Makefile and scripts/check-rust.sh use.
#
# Several of these mutations also break a unit test in the `vhd` or
# `vhdx` crate, which is deliberate duplication: the crate test pins the
# helper and the case here pins the arm that calls it, and the two fail
# independently. Running one named test in one package is what keeps
# them separate, since `make test-rust` stops at the first failing crate
# and would never reach the arm.
# ---------------------------------------------------------------------

QCOW2_LIB='src/crates/qcow2/src/lib.rs'
VHD_LIB='src/crates/vhd/src/lib.rs'
VHDX_READ_LIB='src/crates/vhdx/src/lib.rs'
QCOW2_FEATURES='create,vdi-input,parallels-input,qcow1-input,dmg-input,vhd-input,vhdx-input'

# --- VHD: the sector bitmap and its polarity -------------------------

rust_case 'vhd-read-classify-all-child-as-all-parent' "${QCOW2_LIB}" \
    '        VhdChunkOwnership::AllChild
    })' \
    '        VhdChunkOwnership::AllParent // MUTATED
    })' \
    qcow2 'vhd_arm_allocated_block_all_ones_bitmap_reads_wholly_from_child' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-bitmap-polarity' "${VHD_LIB}" \
    '    (bitmap_byte >> bit) & 1 == 1
}' \
    '    (bitmap_byte >> bit) & 1 == 0 // MUTATED
}' \
    qcow2 'vhd_arm_mixed_bitmap_reads_each_sector_from_the_right_device' \
    --features "${QCOW2_FEATURES}"

# Named against the vhd crate rather than the arm, deliberately. The
# arm calls the coalescer once per ownership run, each time with a
# correct starting byte, so a coalescer that stops at a byte boundary
# serves the same bytes in two runs instead of one and no arm test can
# see it. The run length is the crate's property, so the crate's test
# is the one that guards it. Established by this case failing when it
# named vhd_arm_ownership_run_crossing_a_bitmap_byte.
rust_case 'vhd-read-bitmap-byte-never-advances' "${VHD_LIB}" \
    '        let sector_byte_index = sector / 8;' \
    '        let sector_byte_index = byte_index; // MUTATED' \
    vhd 'ownership_run_crosses_a_bitmap_byte_boundary'

# Also the crate's property rather than the arm's: the arm refuses a
# chunk reaching past its block by a second route, so admitting
# first_sector == sectors_per_block here does not change what the arm
# returns. Established the same way.
rust_case 'vhd-read-block-end-guard-off-by-one' "${VHD_LIB}" \
    '    if sector_count == 0 || bitmap_bytes == 0 || first_sector >= sectors_per_block {' \
    '    if sector_count == 0 || bitmap_bytes == 0 || first_sector > sectors_per_block { // MUTATED' \
    vhd 'ownership_run_refuses_a_request_outside_the_block'

rust_case 'vhd-read-bat-entry-always-block-zero' "${VHD_LIB}" \
    '            return Some(DifferencingBlockLookup::Unallocated);
        }

        // Read BAT entry (u32 BE at table_offset + block_idx * 4)
        let bat_byte_offset = self.table_offset.checked_add(block_idx.checked_mul(4)?)?;' \
    '            return Some(DifferencingBlockLookup::Unallocated);
        }

        // MUTATED
        let bat_byte_offset = self.table_offset;' \
    qcow2 'vhd_arm_second_block_resolves_its_own_bat_entry_and_bitmap' \
    --features "${QCOW2_FEATURES}"

# --- VHD: failing closed at the bottom of a chain --------------------

rust_case 'vhd-read-unallocated-drops-the-guard' "${QCOW2_LIB}" \
    '                        if is_differencing && dev_offset + 1 >= chain_len {
                            return false;
                        }
                        continue;' \
    '                        // MUTATED
                        continue;' \
    qcow2 'vhd_arm_unallocated_block_fails_without_a_following_device' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-unallocated-guard-ignores-disk-type' "${QCOW2_LIB}" \
    '                        if is_differencing && dev_offset + 1 >= chain_len {' \
    '                        if dev_offset + 1 >= chain_len { // MUTATED' \
    qcow2 'vhd_arm_dynamic_reads_as_a_plain_dynamic_vhd' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-all-parent-chunk-zero-fills' "${QCOW2_LIB}" \
    '                                    // is a broken image, not the implied
                                    // zero layer a qcow2 chain ends in.
                                    return false;' \
    '                                    // MUTATED
                                    core::ptr::write_bytes(buf, 0, chunk_size as usize);
                                    return true;' \
    qcow2 'vhd_arm_all_parent_owned_chunk_fails_without_a_following_device' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-classify-swallows-an-undescribed-run' "${QCOW2_LIB}" \
    '        let run = next_vhd_ownership_run(
            call_table,
            state,
            bitmap_host_offset,
            sector,
            sector_byte,
            chunk_size.checked_sub(served)?,
            sector_size,
            input_capacity,
            bytes_read,
        )?;' \
    '        let run = match next_vhd_ownership_run(
            call_table,
            state,
            bitmap_host_offset,
            sector,
            sector_byte,
            chunk_size.checked_sub(served)?,
            sector_size,
            input_capacity,
            bytes_read,
        ) {
            Some(r) => r,
            None => break, // MUTATED
        };' \
    qcow2 'vhd_arm_chunk_crossing_a_block_boundary_is_refused' \
    --features "${QCOW2_FEATURES}"

# --- VHD: the device a run is read from, and in what unit ------------

rust_case 'vhd-read-mixed-arm-pins-device-zero' "${QCOW2_LIB}" \
    '                                    let state = match &mut chain_states.vhd_states[dev_idx] {' \
    '                                    let state = match &mut chain_states.vhd_states[0] { // MUTATED' \
    qcow2 'vhd_arm_composes_a_differencing_child_over_a_differencing_parent' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-runs-addressed-in-512-byte-sectors' "${QCOW2_LIB}" \
    '            // here rather than left to a reader to rediscover.
            if !read_offset_sectors(
                call_table,
                device_idx,
                run_host,
                buf.add(served as usize),
                run.bytes,
                sector_size,
                scratch,
                bytes_read,
            ) {' \
    '            // here rather than left to a reader to rediscover.
            if !read_offset_sectors(
                call_table,
                device_idx,
                run_host,
                buf.add(served as usize),
                run.bytes,
                512, // MUTATED
                scratch,
                bytes_read,
            ) {' \
    qcow2 'vhd_arm_mixed_bitmap_on_a_large_sector_device' \
    --features "${QCOW2_FEATURES}"

# --- VHD: the narrowed refusal in init_chain_states ------------------
#
# The refusal is no longer unconditional: a differencing child with a
# device behind it in its own chain composes, and only one with nothing
# behind it is refused. Three ways to get that condition wrong, each
# mutating the same clause and each killed by a different case of the
# one named test -- widening it back refuses a chain that should
# compose, removing it admits a child with nothing to compose against,
# and deriving it from the array bound admits a child whose chain is
# one device long inside an array of two.

rust_case 'vhd-read-refusal-widened-to-unconditional' "${QCOW2_LIB}" \
    '                    && !parent_in_chain(chain_config, dev_idx)' \
    '                    && true // MUTATED' \
    qcow2 'vhd_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-refusal-removed' "${QCOW2_LIB}" \
    '                    && !parent_in_chain(chain_config, dev_idx)' \
    '                    && false // MUTATED' \
    qcow2 'vhd_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhd-read-refusal-names-vhdx' "${QCOW2_LIB}" \
    'send_differencing_refusal(call_table, shared::DifferencingRefusal::STATUS_VHD);' \
    'send_differencing_refusal(call_table, shared::DifferencingRefusal::STATUS_VHDX); // MUTATED' \
    qcow2 'vhd_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

# Reverts the per-chain judgement to the array-bound form the
# segmentation replaced. The test's two-chain case declares device 1 as
# its own chain, so the segmentation says no parent is behind device 0
# while `dev_idx + 1 >= device_count` says one is -- and a reader that
# believed the latter would compose the child against an unrelated
# image rather than refusing it.
rust_case 'vhd-read-segmentation-reverted-to-device-count' "${QCOW2_LIB}" \
    '                    && !parent_in_chain(chain_config, dev_idx)' \
    '                    && dev_idx + 1 >= device_count // MUTATED' \
    qcow2 'vhd_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

# --- VHD: the documented survivor ------------------------------------

rust_survivor_case 'vhd-read-classify-stops-at-the-first-mixed-verdict' "${QCOW2_LIB}" \
    '        let run = next_vhd_ownership_run(
            call_table,
            state,
            bitmap_host_offset,
            sector,
            sector_byte,
            chunk_size.checked_sub(served)?,
            sector_size,
            input_capacity,
            bytes_read,
        )?;
        if run.child_owned {
            any_child = true;
        } else {
            any_parent = true;
        }
        served = served.checked_add(run.bytes)?;' \
    '        let run = next_vhd_ownership_run(
            call_table,
            state,
            bitmap_host_offset,
            sector,
            sector_byte,
            chunk_size.checked_sub(served)?,
            sector_size,
            input_capacity,
            bytes_read,
        )?;
        if run.child_owned {
            any_child = true;
        } else {
            any_parent = true;
        }
        if any_child && any_parent {
            break; // MUTATED
        }
        served = served.checked_add(run.bytes)?;' \
    qcow2 'vhd_arm_chunk_crossing_a_block_boundary_is_refused' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: the sector bitmap, which is where it differs from VHD -----

rust_case 'vhdx-read-bitmap-is-most-significant-bit-first' "${VHDX_READ_LIB}" \
    '    let bit = sector_in_group % 8;' \
    '    let bit = 7 - (sector_in_group % 8); // MUTATED' \
    qcow2 'vhdx_arm_mixed_block_reads_each_sector_from_the_right_device' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-bitmap-granule-is-512' "${QCOW2_LIB}" \
    '    let logical_sector_size = u64::from(state.logical_sector_size);
    // Round the span up to whole sectors.' \
    '    let logical_sector_size = 512u64; // MUTATED
    let _ = state.logical_sector_size;
    // Round the span up to whole sectors.' \
    qcow2 'vhdx_arm_mixed_block_at_a_four_kilobyte_logical_sector_size' \
    --features "${QCOW2_FEATURES}"

# The VHDX coalescer has the same shape and the same answer: the arm
# re-enters it per run, so the within-call byte advance is the crate's
# property.
rust_case 'vhdx-read-bitmap-byte-never-advances' "${VHDX_READ_LIB}" \
    '        let sector_byte_index = sector / 8;' \
    '        let sector_byte_index = byte_index; // MUTATED' \
    vhdx 'ownership_run_crosses_a_bitmap_byte_boundary'

rust_case 'vhdx-read-bits-numbered-from-the-block' "${VHDX_READ_LIB}" \
    '    let group_first_byte = group.checked_mul(chunk_ratio)?.checked_mul(block_size)?;' \
    '    let group_first_byte = virtual_offset.checked_div(block_size)?.checked_mul(block_size)?; // MUTATED' \
    qcow2 'vhdx_arm_block_later_in_a_chunk_group_uses_its_own_bitmap_bits' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: finding the sector bitmap entry in an interleaved BAT -----

rust_case 'vhdx-read-sb-index-drops-the-chunk-ratio-term' "${VHDX_READ_LIB}" \
    '    group
        .checked_mul(chunk_ratio.checked_add(1)?)?
        .checked_add(chunk_ratio)' \
    '    // MUTATED
    group.checked_mul(chunk_ratio.checked_add(1)?)' \
    qcow2 'vhdx_arm_mixed_block_reads_each_sector_from_the_right_device' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-sb-index-drops-the-group-stride' "${VHDX_READ_LIB}" \
    '        .checked_mul(chunk_ratio.checked_add(1)?)?' \
    '        .checked_mul(1)? // MUTATED' \
    qcow2 'vhdx_arm_block_in_the_second_chunk_group_finds_its_own_bitmap' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-differencing-bat-sized-as-dynamic' "${VHDX_READ_LIB}" \
    '        let sb_bat_entry_bound = if metadata.has_parent {' \
    '        let sb_bat_entry_bound = if false {  // MUTATED' \
    qcow2 'vhdx_arm_mixed_block_in_a_partial_chunk_group' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: which sector bitmap states may be used --------------------

rust_case 'vhdx-read-sb-accepts-any-state-at-all' "${VHDX_READ_LIB}" \
    '        if state != SB_BLOCK_PRESENT {
            return None;
        }' \
    '        if false { // MUTATED
            return None;
        }' \
    qcow2 'vhdx_arm_sector_bitmap_in_an_undefined_state_fails_the_read' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: absent, zero, and the block boundary ----------------------

rust_case 'vhdx-read-zero-merged-into-not-present' "${QCOW2_LIB}" \
    '                        core::ptr::write_bytes(buf, 0, chunk_size as usize);
                        return true;
                    }
                    Some(VhdxBlockLookup::Present { host_byte_offset }) => (host_byte_offset, None),' \
    '                        continue; // MUTATED
                    }
                    Some(VhdxBlockLookup::Present { host_byte_offset }) => (host_byte_offset, None),' \
    qcow2 'vhdx_arm_zero_and_absent_blocks_differ_for_a_differencing_child' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-block-boundary-cap-removed' "${QCOW2_LIB}" \
    '                    if chunk_size > block_bytes_remaining {
                        return false;
                    }' \
    '                    let _ = block_bytes_remaining; // MUTATED' \
    qcow2 'vhdx_arm_chunk_reaching_past_its_payload_block_is_refused' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-partially-present-without-a-parent' "${VHDX_READ_LIB}" \
    '                if !self.has_parent {
                    return None;
                }' \
    '                if false { // MUTATED
                    return None;
                }' \
    qcow2 'vhdx_arm_partially_present_without_a_parent_is_refused' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: failing closed at the bottom of a chain -------------------

rust_case 'vhdx-read-absent-block-drops-the-guard' "${QCOW2_LIB}" \
    '                        if has_parent {
                            let remaining = match devices_behind(chain_len, dev_offset) {
                                Some(r) => r,
                                None => return false,
                            };
                            if remaining == 0 {
                                return false;
                            }
                        }
                        continue;' \
    '                        // MUTATED
                        continue;' \
    qcow2 'vhdx_arm_absent_block_fails_without_a_following_device' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-all-parent-chunk-zero-fills' "${QCOW2_LIB}" \
    '                            // not the implied zero layer a qcow2 chain
                            // ends in.
                            return false;' \
    '                            // MUTATED
                            core::ptr::write_bytes(buf, 0, chunk_size as usize);
                            return true;' \
    qcow2 'vhdx_arm_all_parent_owned_chunk_fails_without_a_following_device' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: reading from part way into a sector -----------------------

rust_case 'vhdx-read-run-ignores-the-leading-sector-byte' "${QCOW2_LIB}" \
    '    let run_bytes = u64::from(run.sectors)
        .checked_mul(logical_sector_size)?
        .checked_sub(sector_byte)?;' \
    '    let run_bytes = u64::from(run.sectors).checked_mul(logical_sector_size)?; // MUTATED' \
    qcow2 'vhdx_arm_mixed_chunk_at_an_unaligned_virtual_offset' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: the narrowed refusal in init_chain_states -----------------
#
# The VHDX twins of the four VHD cases above; see the reasoning there.

rust_case 'vhdx-read-refusal-names-vhd' "${QCOW2_LIB}" \
    'send_differencing_refusal(call_table, shared::DifferencingRefusal::STATUS_VHDX);' \
    'send_differencing_refusal(call_table, shared::DifferencingRefusal::STATUS_VHD); // MUTATED' \
    qcow2 'vhdx_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-refusal-widened-to-unconditional' "${QCOW2_LIB}" \
    '                if state.has_parent && !parent_in_chain(chain_config, dev_idx) {' \
    '                if state.has_parent && true { // MUTATED' \
    qcow2 'vhdx_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-refusal-removed' "${QCOW2_LIB}" \
    '                if state.has_parent && !parent_in_chain(chain_config, dev_idx) {' \
    '                if state.has_parent && false { // MUTATED' \
    qcow2 'vhdx_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-segmentation-reverted-to-device-count' "${QCOW2_LIB}" \
    '                if state.has_parent && !parent_in_chain(chain_config, dev_idx) {' \
    '                if state.has_parent && dev_idx + 1 >= device_count { // MUTATED' \
    qcow2 'vhdx_init_refuses_a_differencing_child_with_no_parent_in_its_own_chain' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-mixed-chunk-zero-fills-the-parent-share' "${QCOW2_LIB}" \
    '                                // chunk cannot be served, and zeros
                                // would be wrong data reported as
                                // success.
                                return false;' \
    '                                // MUTATED
                                core::ptr::write_bytes(buf, 0, chunk_size as usize);' \
    qcow2 'vhdx_arm_mixed_chunk_fails_without_a_following_device' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: no block begins inside the headers ------------------------
#
# Offset zero is its own guard, independent of the overlap test below:
# the file identifier and headers are fixed structure, not region
# table entries, so a region table a writer never touches would leave
# nothing for the overlap test to catch there. Each case mutates only
# the zero check, leaving the overlap check beside it intact, so a
# mutation that silently relied on the other guard to cover for it
# would still be caught.

rust_case 'vhdx-read-sb-offset-zero-accepted' "${VHDX_READ_LIB}" \
    '        if file_offset == 0 {
            return None;
        }' \
    '        if false { // MUTATED
            return None;
        }' \
    qcow2 'vhdx_arm_block_at_file_offset_zero_is_refused' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-full-payload-offset-zero-accepted' "${VHDX_READ_LIB}" \
    '                if file_offset == 0 {
                    return None;
                }
                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    '                if false { // MUTATED
                    return None;
                }
                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    qcow2 'vhdx_arm_block_at_file_offset_zero_is_refused' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-partial-payload-offset-zero-accepted' "${VHDX_READ_LIB}" \
    '                if file_offset == 0 {
                    return None;
                }
                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::PartiallyPresent {' \
    '                if false { // MUTATED
                    return None;
                }
                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::PartiallyPresent {' \
    qcow2 'vhdx_arm_block_at_file_offset_zero_is_refused' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: no block begins inside the BAT or metadata region ---------
#
# A low-water mark fixed at 1 MiB could not catch this one: an offset
# inside the BAT or metadata region of a small image is still above
# 1 MiB. The check is now an overlap test against every region the
# image declares, which SPEC(VHDX) does not promise precedes the
# blocks it coexists with -- see the trailing-region case below for
# the layout that makes that matter. Each case here mutates only the
# overlap check, leaving the offset-zero guard beside it intact.

rust_case 'vhdx-read-sb-offset-inside-region-accepted' "${VHDX_READ_LIB}" \
    '        if self.block_overlaps_a_declared_region(file_offset, u64::from(SB_BLOCK_SIZE)) {
            return None;
        }' \
    '        if false { // MUTATED
            return None;
        }' \
    qcow2 'vhdx_arm_block_inside_a_declared_region_is_refused' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-full-payload-offset-inside-region-accepted' "${VHDX_READ_LIB}" \
    '                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    '                if false { // MUTATED
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    qcow2 'vhdx_arm_block_inside_a_declared_region_is_refused' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-read-partial-payload-offset-inside-region-accepted' "${VHDX_READ_LIB}" \
    '                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::PartiallyPresent {' \
    '                if false { // MUTATED
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::PartiallyPresent {' \
    qcow2 'vhdx_arm_block_inside_a_declared_region_is_refused' \
    --features "${QCOW2_FEATURES}"

# The overlap check narrowed back to differencing images only. Every
# case above drives a differencing child, so all three still pass: it
# is the plain dynamic read -- the one the fix quietly tightened, and
# the one a reader of the issue would not expect to be affected --
# that this catches.

rust_case 'vhdx-read-overlap-check-gated-on-has-parent' "${VHDX_READ_LIB}" \
    '                if self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size)) {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    '                if self.has_parent // MUTATED
                    && self.block_overlaps_a_declared_region(file_offset, u64::from(self.block_size))
                {
                    return None;
                }
                let intra_block_offset = virtual_offset % self.block_size as u64;
                Some(VhdxBlockLookup::Present {' \
    qcow2 'vhdx_arm_dynamic_block_inside_a_declared_region_is_refused' \
    --features "${QCOW2_FEATURES}"

# "Any entry in the region table" is any of the first eight, and the
# two entries every fixture writes both sit at the front -- so the
# claim rested on entries no test had ever moved. Stopping the scan
# after the BAT and metadata entries leaves every case above passing.

rust_case 'vhdx-read-region-scan-stops-before-the-eighth-entry' "${VHDX_READ_LIB}" \
    '        let mut region_count: u32 = 0;

        for i in 0..entry_count.min(8) {' \
    '        let mut region_count: u32 = 0;

        for i in 0..entry_count.min(2) { // MUTATED: scan stops after BAT + metadata' \
    qcow2 'vhdx_overlap_check_covers_the_eighth_region_table_entry' \
    --features "${QCOW2_FEATURES}"

# The regression the overlap test exists to prevent, which none of the
# cases above can catch: a bound that refuses everything below the end
# of the highest region. Every "inside a region" case still passes
# under it, because a block inside a region is also below that mark.
# Only a region declared *after* the blocks tells the two apart.

rust_case 'vhdx-read-overlap-replaced-by-a-high-water-mark' "${VHDX_READ_LIB}" \
    '        self.regions[..self.region_count as usize]
            .iter()
            .any(|&(region_offset, region_length)| {
                ranges_overlap(offset, len, region_offset, region_length)
            })' \
    '        // MUTATED: overlap test replaced by a high-water mark
        let _ = len;
        let mark = self.regions[..self.region_count as usize]
            .iter()
            .map(|&(region_offset, region_length)| region_offset + u64::from(region_length))
            .max()
            .unwrap_or(0);
        offset < mark' \
    qcow2 'vhdx_arm_block_before_a_trailing_region_is_not_refused' \
    --features "${QCOW2_FEATURES}"

# A region declaring zero length names no bytes, so it overlaps
# nothing. Dropping the early answer restores a predicate that reduced
# to `offset < region_offset < end` for an empty region: it waved
# through an entry at or below the block's start and refused one whose
# offset fell strictly inside the block. Every case above keeps passing,
# because the only zero-length entries they carry sit at offset 0.

rust_case 'vhdx-read-empty-region-not-answered-early' "${VHDX_READ_LIB}" \
    '    if len == 0 || region_len == 0 {
        return false;
    }' \
    '    if false { // MUTATED: empty ranges no longer answered early
        return false;
    }' \
    qcow2 'vhdx_zero_length_region_inside_a_block_does_not_refuse_it' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: the device a mixed chunk resumes on -----------------------

rust_case 'vhdx-read-mixed-arm-pins-device-zero' "${QCOW2_LIB}" \
    '                            let state = match &mut chain_states.vhdx_states[dev_idx] {
                                Some(s) => s,
                                None => return false,
                            };
                            // compressed_buf becomes the sub-sector' \
    '                            let state = match &mut chain_states.vhdx_states[0] { // MUTATED
                                Some(s) => s,
                                None => return false,
                            };
                            // compressed_buf becomes the sub-sector' \
    qcow2 'vhdx_arm_composes_a_differencing_child_over_a_differencing_parent' \
    --features "${QCOW2_FEATURES}"

# --- VHDX: a chunk group of no sectors is not a small group ----------

rust_case 'vhdx-read-zero-sector-group-allowed' "${VHDX_READ_LIB}" \
    '        if sectors == 0 {
            return None;
        }' \
    '        if false { // MUTATED
            return None;
        }' \
    vhdx 'sectors_per_chunk_group_refuses_a_degenerate_geometry'

# ---------------------------------------------------------------------
# Two chains in one device array, which is `compare` alone.
#
# `compare` is the only operation that reads two images at once, and it
# does it by packing both backing chains into the single device array
# the guest walks: the host writes one `ChainSegment` per chain, and the
# guest derives image2's first device by adding the two chain lengths.
# Every case below breaks one piece of that arithmetic, and each needs a
# test with a differencing child in a *second* chain to notice -- index
# 0 is the one position at which an array-absolute device offset and a
# chain-relative one agree, so a single-chain test cannot fail for any
# of these reasons.
#
# They are integration cases rather than unit ones because two of them
# mutate the host's segmentation, which no guest unit test can reach,
# and because the property being asserted is a user-visible verdict:
# the wrong answers here are "identical" and "a difference at some
# other offset", both of which exit in a way a weaker test accepts.
# ---------------------------------------------------------------------

COMPARE_OP='src/operations/compare/src/main.rs'
VMM_MAIN='src/vmm/src/main.rs'
TWO_CHAINS='test_differencing.TestDifferencingCompareTwoChains'
TWO_CHAINS_OWN_PARENT="${TWO_CHAINS}.test_compare_reads_each_chain_against_its_own_parent"
TWO_CHAINS_LOOKALIKE="${TWO_CHAINS}"
TWO_CHAINS_LOOKALIKE+='.test_compare_refuses_a_child_against_the_image2_that_would_look_identical'
TWO_CHAINS_OFFSET="${TWO_CHAINS}"
TWO_CHAINS_OFFSET+='.test_compare_reports_the_offset_of_one_altered_parent_owned_sector'
TWO_CHAINS_IDENTICAL="${TWO_CHAINS}.test_compare_two_differencing_chains_are_identical"

# image2 read from image1's chain start. The two chains then are the
# same chain, so every comparison reports "identical" -- the one wrong
# verdict that looks like success. The named test alters one chain's
# parent and expects a difference at that sector's offset, so it is the
# case this cannot slip past.
integration_case 'compare-op-image2-read-starts-at-image1' "${COMPARE_OP}" \
    '            image2_start,
            image2_device_count,
            virtual_offset,
            buf2,' \
    '            0, // MUTATED
            image2_device_count,
            virtual_offset,
            buf2,' \
    "${TWO_CHAINS_OWN_PARENT}"

# The host declares one segment spanning both chains instead of one per
# chain. `ChainSegment::covers` still accepts it -- it tiles the array
# exactly -- so nothing refuses the config; what changes is that a
# differencing child at index 0 of a two-device array now has the
# *other image* counted as the device behind it, which is issue #614
# exactly. The named test is the one whose image2 a wrongly composed
# read agrees with byte for byte, so the mutation's answer there is
# "identical" rather than anything that looks like a failure.
integration_case 'compare-host-segments-collapsed-into-one' "${VMM_MAIN}" \
    '    let segments = [
        shared::ChainSegment {
            first: 0,
            count: chain1_written as u32,
        },
        shared::ChainSegment {
            first: chain1_written as u32,
            count: chain2_written as u32,
        },
    ];' \
    '    // MUTATED
    let segments = [shared::ChainSegment {
        first: 0,
        count: (chain1_written + chain2_written) as u32,
    }];' \
    "${TWO_CHAINS_LOOKALIKE}"

# Each segment keeps its position but takes the other chain's length.
# The segmentation still tiles the array, so the host writes it and the
# guest accepts it; it is simply wrong whenever the two chains are
# different lengths. The named test compares a two-image chain against
# a one-image raw file, so image1's segment shrinks to one device and
# its differencing child is refused instead of composed.
integration_case 'compare-host-segments-sized-from-the-other-chain' "${VMM_MAIN}" \
    '    let segments = [
        shared::ChainSegment {
            first: 0,
            count: chain1_written as u32,
        },
        shared::ChainSegment {
            first: chain1_written as u32,
            count: chain2_written as u32,
        },
    ];' \
    '    let segments = [
        shared::ChainSegment {
            first: 0,
            count: chain2_written as u32, // MUTATED
        },
        shared::ChainSegment {
            first: chain2_written as u32,
            count: chain1_written as u32,
        },
    ];' \
    "${TWO_CHAINS_OFFSET}"

# The segmentation reverted to the array bound, caught where a user
# would meet it rather than in a unit test. `vhd-read-segmentation-
# reverted-to-device-count` already kills this clause from inside the
# `qcow2` crate; this case asserts the same revert is visible as a
# wrong answer from the command line, because that is the form issue
# #614 was reported in. The named test is the one whose image2 a child
# composed against "the next device in the array" matches byte for
# byte, so the mutation's verdict there is "identical".
integration_case 'compare-read-vhd-refusal-reverted-to-device-count' "${QCOW2_LIB}" \
    '                    && !parent_in_chain(chain_config, dev_idx)' \
    '                    && dev_idx + 1 >= device_count // MUTATED' \
    "${TWO_CHAINS_LOOKALIKE}"

# "Is there a parent behind me" asked with the device's array index
# rather than its offset within its own chain. Identical for chain 1,
# whose segment begins at 0, and wrong for chain 2: its child is told
# nothing is behind it and is refused. Only a test whose image2 is
# itself a differencing child can see this, which is why it is the one
# named.
integration_case 'compare-read-parent-in-chain-offset-is-array-absolute' "${QCOW2_LIB}" \
    '            devices_behind(seg.count as usize, dev_idx - seg.first as usize).unwrap_or(0) > 0' \
    '            devices_behind(seg.count as usize, dev_idx).unwrap_or(0) > 0 // MUTATED' \
    "${TWO_CHAINS_IDENTICAL}"

# ---------------------------------------------------------------------
# bench and rebase. Both read through the shared chain walker with no
# guest code of their own to mutate; the properties worth falsifying
# are the host-side capability flag (bench), the two places rebase's
# own build had to grow to reach that walker at all (the Cargo.toml
# feature list and the chain-reader's format allowlist), and the
# typed refusal rendering rebase gained alongside them.
# ---------------------------------------------------------------------

REBASE_OP='src/operations/rebase/src/main.rs'
REBASE_CARGO='src/operations/rebase/Cargo.toml'
BENCH_COMPOSES='test_differencing.TestDifferencingBenchComposes'
BENCH_END="${BENCH_COMPOSES}.test_bench_reads_to_the_end_of_the_full_virtual_size"
REBASE_COMPOSES='test_differencing.TestDifferencingRebaseThroughChain'
REBASE_DETACH="${REBASE_COMPOSES}.test_rebase_detach_composes_the_differencing_backing_chain"
REBASE_REFUSAL="${REBASE_COMPOSES}.test_rebase_old_chain_refusal_is_the_typed_message"
REBASE_TWO_CHAINS="${REBASE_COMPOSES}.test_rebase_onto_a_new_backing_keeps_the_two_chains_apart"

# `run_bench`'s own discovery call reverted to `Unsupported`: a
# differencing source refuses in the host walk before the guest ever
# runs, so the full-virtual-size range probe sees a refusal rather
# than a reading.
integration_case 'bench-host-capability-reverted-to-unsupported' "${VMM_MAIN}" \
    '    let chain = discover_backing_chain(
        Path::new(&invocation.filename),
        sector_size,
        &security_config,
        ChainUse::Compose,
        DifferencingComposition::Supported,
    )' \
    '    let chain = discover_backing_chain(
        Path::new(&invocation.filename),
        sector_size,
        &security_config,
        ChainUse::Compose,
        DifferencingComposition::Unsupported, // MUTATED
    )' \
    "${BENCH_END}"

# rebase's own Cargo.toml never gained the `vhd-input` / `vhdx-input`
# features: the host still resolves and attaches the differencing
# parent (rebase's capability to compose one is set host-side), but
# the qcow2 crate's VHD arm is not compiled into this binary, so
# `init_chain_states` cannot recognise the format at all. Caught
# through the real binary, so `make instar` after the Cargo.toml edit
# is load-bearing.
integration_case 'rebase-cargo-missing-vhd-vhdx-features' "${REBASE_CARGO}" \
    'qcow2 = { path = "../../crates/qcow2", features = ["create", "vhd-input", "vhdx-input", "vdi-input", "parallels-input", "qcow1-input", "dmg-input"] }' \
    'qcow2 = { path = "../../crates/qcow2", features = ["create", "vdi-input", "parallels-input", "qcow1-input", "dmg-input"] } # MUTATED' \
    "${REBASE_DETACH}"

# The chain reader's own format allowlist narrowed back to qcow2/raw.
# The qcow2 crate's VHD/VHDX composing arm is compiled in (the
# Cargo.toml features above are intact), but `read_chain_cluster`'s
# pre-flight loop refuses the format name before ever calling it, so
# the differencing child in the old chain is declined rather than
# read.
integration_case 'rebase-read-chain-cluster-vhd-vhdx-disallowed' "${REBASE_OP}" \
    '            ImageFormat::Qcow2 | ImageFormat::Raw | ImageFormat::Vhd | ImageFormat::Vhdx => {}' \
    '            ImageFormat::Qcow2 | ImageFormat::Raw => {} // MUTATED' \
    "${REBASE_DETACH}"

# `compressed_buf` pointed back at `CHAIN_CACHES`, aliasing the first
# chain device's own L1/BAT cache slot. A differencing VHD chunk's
# mixed-ownership arm genuinely writes through that parameter as its
# sub-sector bounce buffer, so the alias corrupts the cached sector
# mid-lookup -- the actual defect this step found and fixed, now
# pinned by the test that caught it.
integration_case 'rebase-compressed-buf-aliases-chain-caches' "${REBASE_OP}" \
    '    let compressed_buf = CHAIN_READ_COMPRESSED as *mut u8;' \
    '    let compressed_buf = CHAIN_CACHES as *mut u8; // MUTATED' \
    "${REBASE_DETACH}"

# Only the first chain gets a segment, so a rebase carrying both an
# old and a new chain stops accounting for the second chain's devices
# -- the host's own device-count check catches it before the config is
# written, which is the check that replaced a `debug_assert_eq!` that
# would have compiled to nothing in the shipping build. A detach has
# one chain and is unaffected, which is the point: the detach cases
# above keep passing and only the two-chain test fails, so it is that
# test, not them, that reaches the multi-segment path at all.
integration_case 'rebase-second-chain-gets-no-segment' "${VMM_MAIN}" \
    '        if count > 0 {
            segments.push(shared::ChainSegment {
                first: written as u32,
                count: count as u32,
            });' \
    '        if count > 0 && segments.is_empty() { // MUTATED
            segments.push(shared::ChainSegment {
                first: written as u32,
                count: count as u32,
            });' \
    "${REBASE_TWO_CHAINS}"

# The new `differencing_refusal_error` call site removed from
# `run_rebase_guest`: a differencing refusal in the old or new chain
# still fails the run, but renders the pre-existing generic
# ERROR_PARSE_FAILED text ("the overlay's header could not be
# parsed") instead of naming the format and the reason.
# The needle is the refusal block alone. It used to run on through the
# end of the function and into the next one's doc comment, which made
# the case BROKEN whenever that unrelated comment was edited. The
# `("rebase", ...)` argument pair is what makes this unique.
integration_case 'rebase-differencing-refusal-call-site-removed' "${VMM_MAIN}" \
    '    if serial_decoder.last_differencing_refusal.is_some() {
        return Err(serial_decoder
            .differencing_refusal_error("rebase", DifferencingComposition::Supported)
            .into());
    }' \
    '    // MUTATED: differencing_refusal_error call site removed' \
    "${REBASE_REFUSAL}"

# ---------------------------------------------------------------------
# The other half of the policy: map, measure and check still refuse a
# differencing source, each in its own code rather than through
# `init_chain_states`. Nothing above lifts these six guards -- they are
# what stops a later phase doing so by accident, by making the deletion
# visible as a failing, named test rather than a silent behaviour
# change. Each operation has one guard per format: a VHD arm testing
# the footer's disk type, and a VHDX arm testing the metadata's
# `has_parent` flag (map and measure read `VhdxState::has_parent`
# directly; check reads it off the metadata it already parsed).
# ---------------------------------------------------------------------

MAP_OP='src/operations/map/src/main.rs'
MEASURE_OP='src/operations/measure/src/main.rs'
CHECK_OP='src/operations/check/src/main.rs'
MAP_REFUSES='test_differencing.TestDifferencingMapStillRefuses.test_map_refuses_with_its_own_message'
MEASURE_REFUSES='test_differencing.TestDifferencingRefusal.test_measure_refuses_every_differencing_source'
CHECK_REFUSES='test_differencing.TestDifferencingRefusal.test_check_refuses_every_differencing_source'

integration_case 'map-vhd-refusal-removed' "${MAP_OP}" \
    '            if state.disk_type == vhd::DISK_TYPE_DIFFERENCING {' \
    '            if state.disk_type == vhd::DISK_TYPE_DIFFERENCING && false { // MUTATED' \
    "${MAP_REFUSES}"

integration_case 'map-vhdx-refusal-removed' "${MAP_OP}" \
    '            if state.has_parent {' \
    '            if state.has_parent && false { // MUTATED' \
    "${MAP_REFUSES}"

integration_case 'measure-vhd-refusal-removed' "${MEASURE_OP}" \
    '            if state.disk_type == vhd::DISK_TYPE_DIFFERENCING {' \
    '            if state.disk_type == vhd::DISK_TYPE_DIFFERENCING && false { // MUTATED' \
    "${MEASURE_REFUSES}"

integration_case 'measure-vhdx-refusal-removed' "${MEASURE_OP}" \
    '            if state.has_parent {' \
    '            if state.has_parent && false { // MUTATED' \
    "${MEASURE_REFUSES}"

integration_case 'check-vhd-refusal-removed' "${CHECK_OP}" \
    '    if footer.disk_type == vhd::DISK_TYPE_DIFFERENCING {' \
    '    if footer.disk_type == vhd::DISK_TYPE_DIFFERENCING && false { // MUTATED' \
    "${CHECK_REFUSES}"

integration_case 'check-vhdx-refusal-removed' "${CHECK_OP}" \
    '    if metadata.has_parent {' \
    '    if metadata.has_parent && false { // MUTATED' \
    "${CHECK_REFUSES}"

# Four more on the same three operations, and the one place they are not
# merely non-composing but were answering differently from the readers.
# `map` and `measure` do not go through `block_lookup` at all: each
# walks the whole BAT once, through `VhdxState::map_extents` and
# `VhdxState::scan_allocation`. Until `block_lookup`'s two guards
# reached both walks, `map` reported a payload block declared inside
# the metadata region -- or at file offset zero, where the headers live
# -- as data living at that offset, and `measure` counted its bytes,
# while `convert` refused to read that same block (issue #634, and
# #547 for the offset-zero half).
#
# Two cases per walk, one per guard, because neither guard subsumes
# the other: a block at offset zero does not overlap a declared region
# in this geometry, and a block inside a region has a non-zero offset.
# A single case per walk would have let either guard be deleted
# silently.
#
# These are `rust_case` rather than `integration_case` because the
# walks are crate functions a unit test can drive directly, and because
# the fixture is a hand-patched BAT entry that no image in
# instar-testdata carries. Each case reverts one call site only, so the
# other three keep passing and the verdict names the walk and the guard
# that was lost.

rust_case 'vhdx-map-extent-offset-inside-region-accepted' "${VHDX_READ_LIB}" \
    '                    if self.block_overlaps_a_declared_region(file_offset, block_size) {
                        self.block_table_malformed = true;
                        return None;
                    }' \
    '                    if false {
                        // MUTATED: map no longer applies the overlap test
                        self.block_table_malformed = true;
                        return None;
                    }' \
    qcow2 'vhdx_map_and_measure_refuse_a_block_inside_the_metadata_region' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-scan-block-offset-inside-region-accepted' "${VHDX_READ_LIB}" \
    '                    if self.block_overlaps_a_declared_region(file_offset, block_size) {
                        malformed = true;
                        return false;
                    }' \
    '                    let _ = block_size;
                    if false {
                        // MUTATED: measure no longer applies the overlap test
                        malformed = true;
                        return false;
                    }' \
    qcow2 'vhdx_map_and_measure_refuse_a_block_inside_the_bat_region' \
    --features "${QCOW2_FEATURES}"

# The other guard of the pair, one case per walk. The overlap test
# cannot stand in for this one: in the fixture geometry a 1 MiB block
# at offset zero ends exactly where the first declared region begins,
# so the two touch without overlapping and the overlap test returns
# false -- which is why dropping this guard leaves all four cases above
# passing. The two tests named here assert that independence directly,
# recomputing the overlap from the image's own region table rather than
# from the predicate under test.

rust_case 'vhdx-map-extent-offset-zero-accepted' "${VHDX_READ_LIB}" \
    '                    if file_offset == 0 {
                        self.block_table_malformed = true;
                        return None;
                    }' \
    '                    if false {
                        // MUTATED: map no longer refuses a present block at offset zero
                        self.block_table_malformed = true;
                        return None;
                    }' \
    qcow2 'vhdx_map_refuses_a_present_block_at_file_offset_zero' \
    --features "${QCOW2_FEATURES}"

rust_case 'vhdx-scan-block-offset-zero-accepted' "${VHDX_READ_LIB}" \
    '                    if file_offset == 0 {
                        malformed = true;
                        return false;
                    }' \
    '                    if false {
                        // MUTATED: measure no longer refuses a present block at offset zero
                        malformed = true;
                        return false;
                    }' \
    qcow2 'vhdx_measure_refuses_a_present_block_at_file_offset_zero' \
    --features "${QCOW2_FEATURES}"

# ---------------------------------------------------------------------
# The create guest operation. Caught through the real binary only.
# ---------------------------------------------------------------------

CREATE_OP='src/operations/create/src/main.rs'
ROUND_TRIP='test_create.TestCreateSmoke.test_create_vhd_and_vhdx_differencing_round_trip'
MISMATCH='test_create.TestCreateSmoke.test_create_vhd_and_vhdx_reject_mismatched_parent_format'
FIXED_PARENT='test_create.TestCreateSmoke.test_create_vhd_differencing_from_a_fixed_parent'
DIFF_BACKING='test_differencing.TestDifferencingCreateRefusesAsBacking'
DIFF_BACKING="${DIFF_BACKING}.test_create_refuses_a_differencing_backing_file"

# The same-format-child leg: a vpc child offered a differencing VHD
# parent, and a vhdx child offered a differencing VHDX parent, which
# DIFF_BACKING above never exercises (it always requests a qcow2
# child).
DIFF_BACKING_SAME_FMT='test_differencing.TestDifferencingCreateRefusesAsBacking'
DIFF_BACKING_SAME_FMT="${DIFF_BACKING_SAME_FMT}.test_create_refuses_a_differencing_backing_file_for_a_same_format_child"

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

# The same two arms again, but caught by the same-format-child leg
# rather than the qcow2-child one above, so a target-specific
# regression in either arm cannot hide behind a child format that
# happens not to trip it.
integration_case 'create-op-vhd-differencing-refusal-vpc-child' "${CREATE_OP}" \
    '            if footer.disk_type == vhd::DISK_TYPE_DIFFERENCING {' \
    '            if footer.disk_type == vhd::DISK_TYPE_FIXED {' \
    "${DIFF_BACKING_SAME_FMT}"

integration_case 'create-op-vhdx-differencing-refusal-vhdx-child' "${CREATE_OP}" \
    '            if state.has_parent {' \
    '            if state.has_parent && capacity == 0 {' \
    "${DIFF_BACKING_SAME_FMT}"

# The backing probe reads the parent's LAST sector, which is the only
# place a fixed VHD keeps its footer.
integration_case 'create-op-footer-reads-the-last-sector' "${CREATE_OP}" \
    '        && (call_table.read_input_sector)(0, capacity - 1, header_ptr, sector_size)' \
    '        && (call_table.read_input_sector)(0, 0, header_ptr, sector_size)' \
    "${FIXED_PARENT}"

# ---------------------------------------------------------------------
# The libvhdi oracle cross-check.
#
# These four are the only cases whose test reads instar's output with a
# parser instar did not write, so they are the only ones that can catch
# a field written consistently into the wrong place. They need
# `vhdiinfo` on PATH (Debian: libvhdi-utils); without it the tests skip
# and the harness reports BROKEN, which is the honest verdict -- the
# mutation applied and nothing looked at it.
# ---------------------------------------------------------------------

ORACLE_VHD='test_differencing.TestDifferencingLibvhdiOracle'
ORACLE_VHD="${ORACLE_VHD}.test_libvhdi_reads_a_vhd_child_as_naming_its_parent"
ORACLE_VHDX='test_differencing.TestDifferencingLibvhdiOracle'
ORACLE_VHDX="${ORACLE_VHDX}.test_libvhdi_reads_a_vhdx_child_as_naming_its_parent"

# The same two identity mutations as the round-trip cases above, but
# caught by the oracle rather than by instar reading its own bytes
# back. The point is not redundancy: the round-trip test compares the
# child's parent-identity fields against the parent's, both read by
# hand-rolled struct reads written from the same understanding of the
# format that produced them, so a field placed consistently wrong
# agrees with itself. libvhdi has no such loop to close.
integration_case 'oracle-vhd-parent-identity' "${CREATE_OP}" \
    '        (ParentIdentity::Vhd { uuid, timestamp }, true) => (uuid, timestamp),' \
    '        (ParentIdentity::Vhd { .. }, true) => ([0u8; 16], 0),' \
    "${ORACLE_VHD}"

integration_case 'oracle-vhdx-parent-identity' "${CREATE_OP}" \
    '        (ParentIdentity::Vhdx { data_write_guid }, true) => data_write_guid,' \
    '        (ParentIdentity::Vhdx { .. }, true) => [0u8; 16],' \
    "${ORACLE_VHDX}"

# The parent unicode name keeps the path AS TYPED, which is the field
# libvhdi (and qemu's block/vpc.c) resolve a VHD parent through. This
# mutation strips the directory from it, leaving the locator table
# untouched -- the shape of the defect round 4 of #581's review found,
# where producer and consumer disagreed about typed versus rendered.
# A bare parent name cannot see it, so only the subdirectory leg of the
# oracle test fires: that leg is why the test carries two path shapes.
#
# The call site is assembled line by line rather than written inline:
# replace-once takes a literal, and a six-line literal on one argument
# line is unreadable. Every fragment here must match the source byte
# for byte, indentation included, or replace-once reports BROKEN.
NAME_CALL_HEAD=$'                vhd::build_dynamic_header_parent(\n'
NAME_CALL_HEAD+=$'                    dyn_header_region,\n'
NAME_CALL_HEAD+=$'                    &opts.parent_unique_id,\n'
NAME_CALL_HEAD+=$'                    opts.parent_timestamp,\n'

NAME_CALL_SEARCH="${NAME_CALL_HEAD}"
NAME_CALL_SEARCH+=$'                    path,\n'
NAME_CALL_SEARCH+=$'                )'

NAME_CALL_REPLACE="${NAME_CALL_HEAD}"
NAME_CALL_REPLACE+=$'                    match path.rfind(\'/\') {\n'
NAME_CALL_REPLACE+=$'                        Some(index) => &path[index + 1..],\n'
NAME_CALL_REPLACE+=$'                        None => path,\n'
NAME_CALL_REPLACE+=$'                    },\n'
NAME_CALL_REPLACE+=$'                )'

integration_case 'oracle-vhd-parent-name-keeps-its-directory' "${CREATE_LIB}" \
    "${NAME_CALL_SEARCH}" "${NAME_CALL_REPLACE}" "${ORACLE_VHD}"

# The VHDX File Parameters `HasParent` bit. `round_trip.rs` pins it
# against a plan built from a constant GUID, and nothing in the Python
# suite asserted it at all before the oracle did -- the round-trip
# test's VHD arm checks `disk_type == 4` and its VHDX arm has no
# equivalent. libvhdi reads the bit back as "Disk type: Differential".
# The trailing `);` is part of the needle: `parent_path.is_some()` is
# now the argument to two calls -- this one, and the BAT sizing in
# `plan_vhdx` -- and only `build_metadata`'s ends the statement. The BAT
# sizing has its own case, `vhdx-write-differencing-bat-sized-as-dynamic`.
integration_case 'oracle-vhdx-has-parent-bit' "${CREATE_LIB}" \
    '        parent_path.is_some(),
    );' \
    '        false,
    );' \
    "${ORACLE_VHDX}"

# ---------------------------------------------------------------------
# Totals
# ---------------------------------------------------------------------

if [ "${LIST_ONLY}" = 'yes' ]; then
    echo "${TOTAL_COUNT} cases"
    check_selection_matched || exit 2
    check_case_count || exit 1
    exit 0
fi

echo
if [ "${CHECK_PATTERNS}" = 'yes' ]; then
    echo "${TOTAL_COUNT} patterns: ${PASS_COUNT} land, ${BROKEN_COUNT} drifted"
else
    echo "${TOTAL_COUNT} cases: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${BROKEN_COUNT} BROKEN"
fi

check_selection_matched || exit 2
check_case_count || exit 1

if [ "${FAIL_COUNT}" -ne 0 ] || [ "${BROKEN_COUNT}" -ne 0 ]; then
    if [ "${CHECK_PATTERNS}" = 'no' ]; then
        echo "the log of each case above that did not pass is kept under ${LOG_DIR}"
    fi
    exit 1
fi
exit 0
