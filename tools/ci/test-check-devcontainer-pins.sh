#!/usr/bin/env bash
#
# Tests for tools/ci/check-devcontainer-pins.sh.
#
# The check defends invariants that nothing else on the pull request
# path looks at: the two images agree on the Rust nightly and on every
# cargo tool they share, every `cargo install` runs with --locked, every
# pin stays visible to Renovate's customManager, and the customManager
# as written in renovate.json really does match them. All of them fail
# silently in production -- a drifted nightly builds guest binaries with
# a different compiler than the packages, a lost --locked reopens the
# tinyvec 1.13.0 outage, and a pin Renovate stops matching simply
# freezes forever with no error anywhere. So each one is exercised by
# breaking it on purpose here, rather than by reading the script.
#
# The guard resolves its own repository root from BASH_SOURCE and reads
# fixed paths under it, so the fixtures are a miniature tree -- the real
# scripts, the real Dockerfiles and the real renovate.json, copied into
# a temp directory in the same layout -- and it runs unmodified against
# them. That keeps the production script free of test-only path
# overrides, and means the mutations below are applied to exactly the
# files that ship.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK_REL="tools/ci/check-devcontainer-pins.sh"
MANAGER_REL="tools/ci/check-renovate-manager.py"
DEV_REL="src/.devcontainer/Dockerfile"
BUILD_REL="src/.devcontainer/build/Dockerfile"
RENOVATE_REL="renovate.json"

# The files a mutation is allowed to edit. Copied into the fixture tree,
# and diffed against the originals afterwards to prove the edit landed.
FIXTURES=("${DEV_REL}" "${BUILD_REL}" "${RENOVATE_REL}")

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

TREE="${WORK}/tree"

reset_tree() {
    rm -rf "${TREE}"
    mkdir -p "${TREE}/tools/ci" "${TREE}/src/.devcontainer/build"
    cp "${REPO_ROOT}/${CHECK_REL}" "${TREE}/${CHECK_REL}"
    cp "${REPO_ROOT}/${MANAGER_REL}" "${TREE}/${MANAGER_REL}"
    local rel
    for rel in "${FIXTURES[@]}"; do
        cp "${REPO_ROOT}/${rel}" "${TREE}/${rel}"
    done
}

RUN_STATUS=0
RUN_OUTPUT="${WORK}/output"

run_check() {
    # Sets RUN_STATUS and writes the combined output to RUN_OUTPUT. Not
    # a command substitution: that would run the assignment in a
    # subshell and RUN_STATUS would never come back.
    RUN_STATUS=0
    bash "${TREE}/${CHECK_REL}" > "${RUN_OUTPUT}" 2>&1 || RUN_STATUS=$?
}

# mutate DESCRIPTION EXPECTED_STATUS EXPECTED_MESSAGE_SUBSTRING -- COMMAND...
#
# COMMAND runs against the freshly reset fixture tree; ${DEV}, ${BUILD}
# and ${RENOVATE} name the mutable files inside it.
mutate() {
    local description="$1" expected="$2" needle="$3"
    shift 4  # description, status, needle, the literal --

    reset_tree
    DEV="${TREE}/${DEV_REL}" BUILD="${TREE}/${BUILD_REL}" \
        RENOVATE="${TREE}/${RENOVATE_REL}" "$@"

    # A mutation that quietly failed to apply -- a sed expression that
    # stopped matching after the Dockerfiles were reworded, say -- would
    # leave every assertion below testing the pristine tree and passing
    # for the wrong reason. Every case here is supposed to edit
    # something, so prove it did.
    local rel changed=0
    for rel in "${FIXTURES[@]}"; do
        if ! diff -q "${TREE}/${rel}" "${REPO_ROOT}/${rel}" > /dev/null; then
            changed=1
        fi
    done
    if [ "${changed}" -eq 0 ]; then
        fail "${description}: the mutation did not change any fixture"
        return
    fi

    run_check
    local output
    output="$(cat "${RUN_OUTPUT}")"

    if [ "${RUN_STATUS}" != "${expected}" ]; then
        fail "${description}: expected exit ${expected}, got ${RUN_STATUS}"
        printf '%s\n' "${output}" | sed 's/^/        /' >&2
        return
    fi
    if [ -n "${needle}" ] && [[ "${output}" != *"${needle}"* ]]; then
        fail "${description}: expected '${needle}' in output:"
        printf '%s\n' "${output}" | sed 's/^/        /' >&2
        return
    fi
    ok "${description}"
}

# Each mutation is a function rather than an inline `bash -c '...'`:
# these edits are full of dollar signs and nested quotes, and spelling
# them inside a single-quoted argument makes them unreadable and trips
# SC2016 on every line. ${DEV}, ${BUILD} and ${RENOVATE} name the
# mutable fixtures.

# The literal ${...} text is the point here -- these strings are
# written into a Dockerfile, where Docker expands them, so single
# quotes are correct and SC2016 is noise.
# shellcheck disable=SC2016
AUDIT_SPEC='cargo-audit@"${CARGO_AUDIT_VERSION}"'
AUDIT_COMMENT='# renovate: datasource=crate depName=cargo-audit'

drift_nightly() {
    sed -i 's/^ARG RUST_NIGHTLY=.*/ARG RUST_NIGHTLY=nightly-2020-01-01/' "${DEV}"
}
delete_nightly() { sed -i '/^ARG RUST_NIGHTLY=/d' "${BUILD}"; }
drift_shared_tool() {
    sed -i 's/^ARG CARGO_DEB_VERSION=.*/ARG CARGO_DEB_VERSION=0.0.1/' "${BUILD}"
}
delete_shared_tool() { sed -i '/^ARG CARGO_GENERATE_RPM_VERSION=/d' "${BUILD}"; }

# Appends a complete, correctly-formed pin for CRATE at VERSION to FILE.
# $1 = file, $2 = crate, $3 = ARG name, $4 = version.
#
# The literal ${...} is written into a Dockerfile for Docker to expand,
# so the single quotes are correct and SC2016 is noise.
# shellcheck disable=SC2016
append_pin() {
    {
        printf '# renovate: datasource=crate depName=%s\n' "$2"
        printf 'ARG %s=%s\n' "$3" "$4"
        printf 'RUN cargo install --locked %s@"${%s}"\n' "$2" "$3"
    } >> "$1"
}

# A cargo tool added to both images later, at versions that disagree.
# The whole point of deriving the shared set from the install lines: a
# hardcoded list would exempt this from the drift comparison, silently,
# which is the failure mode the guard exists to prevent.
append_drifting_new_shared_tool() {
    append_pin "${DEV}" cargo-nextest CARGO_NEXTEST_VERSION 0.9.100
    append_pin "${BUILD}" cargo-nextest CARGO_NEXTEST_VERSION 0.9.1
}
append_agreeing_new_shared_tool() {
    append_pin "${DEV}" cargo-nextest CARGO_NEXTEST_VERSION 0.9.100
    append_pin "${BUILD}" cargo-nextest CARGO_NEXTEST_VERSION 0.9.100
}

strip_locked() {
    sed -i 's/cargo install --locked cargo-audit@/cargo install cargo-audit@/' "${DEV}"
}
# shellcheck disable=SC2016
append_unlocked_install() {
    printf 'RUN cargo install cargo-nextest@"${CARGO_NEXTEST_VERSION}"\n' >> "${DEV}"
}
append_prose() {
    printf '# A comment about running cargo install by hand.\n' >> "${DEV}"
}

hardcode_version() { sed -i "s|${AUDIT_SPEC}|cargo-audit@0.22.2|" "${DEV}"; }
drop_version() { sed -i "s|${AUDIT_SPEC}|cargo-audit|" "${DEV}"; }
append_versionless_install() {
    printf 'RUN cargo install --locked cargo-nextest\n' >> "${DEV}"
}
mismatch_arg_name() {
    sed -i "s|${AUDIT_SPEC}|cargo-audit@\"\${CARGO_FUZZ_VERSION}\"|" "${DEV}"
}
# --locked is present and the ARG is named correctly for the crate, so
# only the "is it actually declared?" check stands between this and a
# silently unpinned install: Docker expands an undefined ARG to the
# empty string, making the spec `cargo-nextest@`.
# shellcheck disable=SC2016
append_undeclared_arg_install() {
    printf 'RUN cargo install --locked cargo-nextest@"${CARGO_NEXTEST_VERSION}"\n' \
        >> "${DEV}"
}
append_unreferenced_arg() {
    # Appended rather than inserted mid-file, so this trips the
    # reference check alone: inserting it above an existing ARG would
    # also detach that ARG from its renovate comment, and the assertion
    # could then pass on the wrong error.
    printf '# renovate: datasource=crate depName=cargo-unused\n' >> "${DEV}"
    printf 'ARG CARGO_UNUSED_VERSION=1.0.0\n' >> "${DEV}"
}

# A crate whose name does not start with "cargo-", pinned correctly in
# every respect except that nothing tells Renovate about it. Anchoring
# the Renovate-visibility checks on an ARG-name prefix would let this
# through, and the pin would then freeze forever with no error anywhere.
# shellcheck disable=SC2016
append_noncargo_crate_without_comment() {
    printf 'ARG SCCACHE_VERSION=0.8.0\n' >> "${DEV}"
    printf 'RUN cargo install --locked sccache@"${SCCACHE_VERSION}"\n' >> "${DEV}"
}
append_noncargo_crate() {
    append_pin "${DEV}" sccache SCCACHE_VERSION 0.8.0
}

# shellcheck disable=SC2016
append_two_installs() {
    printf 'RUN cargo install --locked cargo-deb@"${CARGO_DEB_VERSION}" && %s\n' \
        'cargo install --locked cargo-binutils@"${CARGO_BINUTILS_VERSION}"' >> "${DEV}"
}
# shellcheck disable=SC2016
append_chained_unlocked_install() {
    printf 'RUN cargo install --locked cargo-deb@"${CARGO_DEB_VERSION}" && %s\n' \
        'cargo install cargo-binutils@"${CARGO_BINUTILS_VERSION}"' >> "${DEV}"
}

split_install_across_lines() {
    # The same install, rewritten so --locked and the crate spec sit on
    # different physical lines.
    python3 - "${DEV}" <<'SPLIT'
import sys
path = sys.argv[1]
text = open(path).read()
old = 'cargo install --locked cargo-audit@'
new = 'cargo install \\\n        --locked \\\n        cargo-audit@'
assert text.count(old) == 1, text.count(old)
open(path, 'w').write(text.replace(old, new))
SPLIT
}

comment_inside_continuation() {
    # Docker strips a whole-line comment wherever it appears, including
    # inside a backslash continuation, and does not treat it as ending
    # the continuation. Annotating one crate of a multi-crate install is
    # a realistic edit in files this comment-dense, and it is valid.
    python3 - "${DEV}" <<'INLINE'
import sys
path = sys.argv[1]
text = open(path).read()
old = 'cargo install --locked cargo-audit@'
new = ('cargo install --locked \\\n'
       '    # cargo-audit is the RUSTSEC advisory checker\n'
       '        cargo-audit@')
assert text.count(old) == 1, text.count(old)
open(path, 'w').write(text.replace(old, new))
INLINE
}

quote_pin_value() {
    sed -i 's/^ARG CARGO_AUDIT_VERSION=\(.*\)/ARG CARGO_AUDIT_VERSION="\1"/' "${DEV}"
}
delete_renovate_comment() { sed -i "\|^${AUDIT_COMMENT}$|d" "${DEV}"; }
detach_renovate_comment() {
    sed -i "\|^${AUDIT_COMMENT}$|a # an interposed comment" "${DEV}"
}
misname_renovate_comment() {
    sed -i "s|^${AUDIT_COMMENT}$|${AUDIT_COMMENT}-typo|" "${DEV}"
}

# The mutations below break renovate.json itself. Every check above
# asserts the format the customManager needs from the script's own
# memory of it; these prove the script notices when the live config
# stops agreeing, which is the one path that could freeze all the pins
# at once while everything else still reports them healthy.
break_manager_regex() {
    sed -i 's/depName=(?<depName>/depNam=(?<depName>/' "${RENOVATE}"
}
uncompilable_manager_regex() {
    sed -i 's/depName=(?<depName>\[^\\\\s\]+?)/depName=(?<depName>[^\\\\s]+?(/' "${RENOVATE}"
}
narrow_manager_file_patterns() {
    python3 - "${RENOVATE}" <<'NARROW'
import json
import sys
path = sys.argv[1]
config = json.load(open(path))
for manager in config['customManagers']:
    patterns = manager.get('managerFilePatterns', [])
    if 'src/.devcontainer/build/Dockerfile' in patterns:
        patterns.remove('src/.devcontainer/build/Dockerfile')
json.dump(config, open(path, 'w'), indent=2)
NARROW
}
wrong_manager_datasource() {
    sed -i 's/datasource=(?<datasource>\[a-z-\]+?)/datasource=(?<datasource>[a-z-]+?)x/' \
        "${RENOVATE}"
}

start "the tree as it ships"
reset_tree
run_check
if [ "${RUN_STATUS}" = 0 ]; then
    ok "an unmodified tree passes"
else
    fail "an unmodified tree passes: exit ${RUN_STATUS}"
    sed 's/^/        /' "${RUN_OUTPUT}" >&2
fi

start "the Rust nightly comparison"
mutate "a drifted nightly fails" 1 "Rust nightly pin drift" -- drift_nightly
mutate "a missing nightly pin fails" 1 "no 'ARG RUST_NIGHTLY" -- delete_nightly

start "the shared cargo tool comparison"
mutate "a drifted shared tool fails" 1 "CARGO_DEB_VERSION drift" -- drift_shared_tool
mutate "a missing shared tool pin fails" 1 "is not declared as an ARG" -- \
    delete_shared_tool
# The shared set is the intersection of what the two files install, not
# a list kept in the script: a tool added to both images later is
# compared from the day it is added.
mutate "a newly shared tool that drifts fails" 1 "CARGO_NEXTEST_VERSION drift" -- \
    append_drifting_new_shared_tool
mutate "a newly shared tool that agrees passes" 0 "" -- append_agreeing_new_shared_tool

start "--locked on every install"
mutate "a stripped --locked fails" 1 "'cargo install' without --locked" -- strip_locked
mutate "a new unlocked install fails" 1 "'cargo install' without --locked" -- \
    append_unlocked_install
mutate "prose mentioning cargo install is not a hit" 0 "" -- append_prose

start "every crate arrives through its ARG"
mutate "a hardcoded crate version fails" 1 "crate must be installed as" -- hardcode_version
# The gap the first draft of this guard left: --locked is present, no
# version is hardcoded and no ARG is referenced, so a rule-by-rule check
# sees nothing wrong while the crate floats exactly as it did before.
mutate "an install with no version at all fails" 1 "crate must be installed as" -- \
    drop_version
mutate "a versionless install added later fails" 1 "crate must be installed as" -- \
    append_versionless_install
mutate "an ARG named after a different crate fails" 1 "name the ARG" -- mismatch_arg_name
mutate "an install referencing an undeclared ARG fails" 1 "is not declared as an ARG" -- \
    append_undeclared_arg_install
mutate "an unreferenced ARG fails" 1 "is never referenced" -- append_unreferenced_arg

start "several installs chained on one RUN"
# The images already write `umask 0000 && cargo install ...`, so a check
# that treated everything after the first `cargo install` as its
# arguments would misread a second one as a crate named "cargo".
mutate "two valid installs on one line pass" 0 "" -- append_two_installs
# One --locked must not cover both.
mutate "an unlocked install chained after a locked one fails" 1 "without --locked" -- \
    append_chained_unlocked_install

start "installs split across continuation lines"
# --locked and the crate spec need not share a physical line, and a
# guard that greps line by line would fail this valid form.
mutate "--locked on a continuation line passes" 0 "" -- split_install_across_lines
mutate "a comment inside a continuation passes" 0 "" -- comment_inside_continuation

start "pins stay visible to Renovate"
mutate "a quoted pin value fails" 1 "must be unquoted" -- quote_pin_value
mutate "a deleted renovate comment fails" 1 "must be directly preceded by" -- \
    delete_renovate_comment
mutate "a detached renovate comment fails" 1 "must be directly preceded by" -- \
    detach_renovate_comment
mutate "a renovate comment naming the wrong crate fails" 1 "must be directly preceded by" -- \
    misname_renovate_comment
# Not every crate is named cargo-something. Anchoring these checks on an
# ARG-name prefix would let a correctly-formed non-cargo- crate skip
# them entirely and freeze forever.
mutate "a non-cargo crate with no renovate comment fails" 1 "must be directly preceded by" -- \
    append_noncargo_crate_without_comment
mutate "a correctly pinned non-cargo crate passes" 0 "" -- append_noncargo_crate

start "renovate.json really matches the pins"
mutate "a typo in matchStrings fails" 1 "does not match it" -- break_manager_regex
mutate "an uncompilable matchStrings fails" 1 "does not compile" -- \
    uncompilable_manager_regex
mutate "dropping a file from managerFilePatterns fails" 1 \
    "no customManagers entry" -- narrow_manager_file_patterns
mutate "a manager that captures the wrong datasource fails" 1 \
    "does not match it" -- wrong_manager_datasource

start "every problem is reported before exiting"
# The checks used to exit on the first failure, so a contributor with
# two broken things fixed one, re-ran, and only then met the other.
reset_tree
DEV="${TREE}/${DEV_REL}" drift_nightly
DEV="${TREE}/${DEV_REL}" strip_locked
run_check
OUTPUT="$(cat "${RUN_OUTPUT}")"
if [ "${RUN_STATUS}" = 1 ] \
        && [[ "${OUTPUT}" == *"Rust nightly pin drift"* ]] \
        && [[ "${OUTPUT}" == *"without --locked"* ]]; then
    ok "two unrelated problems are both reported in one run"
else
    fail "two unrelated problems are both reported in one run (exit ${RUN_STATUS})"
    printf '%s\n' "${OUTPUT}" | sed 's/^/        /' >&2
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
