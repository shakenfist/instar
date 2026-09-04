#!/usr/bin/env bash
#
# Tests for tools/ci/check-devcontainer-pins.sh.
#
# The check defends four invariants that nothing else on the pull
# request path looks at: the two images agree on the Rust nightly and on
# every cargo tool they share, every `cargo install` runs with --locked,
# and every pin stays visible to Renovate's customManager. All four fail
# silently in production -- a drifted nightly builds guest binaries with
# a different compiler than the packages, a lost --locked reopens the
# tinyvec 1.13.0 outage, and a pin Renovate stops matching simply
# freezes forever with no error anywhere. So each one is exercised by
# breaking it on purpose here, rather than by reading the script.
#
# The guard resolves its own repository root from BASH_SOURCE and reads
# fixed paths under it, so the fixtures are a miniature tree -- the real
# script and the real Dockerfiles, copied into a temp directory in the
# same layout -- and it runs unmodified against them. That keeps the
# production script free of test-only path overrides, and means the
# mutations below are applied to exactly the files that ship.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK_REL="tools/ci/check-devcontainer-pins.sh"
DEV_REL="src/.devcontainer/Dockerfile"
BUILD_REL="src/.devcontainer/build/Dockerfile"

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
    cp "${REPO_ROOT}/${DEV_REL}" "${TREE}/${DEV_REL}"
    cp "${REPO_ROOT}/${BUILD_REL}" "${TREE}/${BUILD_REL}"
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
# COMMAND runs against the freshly reset fixture tree; ${DEV} and
# ${BUILD} name the two Dockerfiles inside it.
mutate() {
    local description="$1" expected="$2" needle="$3"
    shift 4  # description, status, needle, the literal --

    reset_tree
    DEV="${TREE}/${DEV_REL}" BUILD="${TREE}/${BUILD_REL}" "$@"

    # A mutation that quietly failed to apply -- a sed expression that
    # stopped matching after the Dockerfiles were reworded, say -- would
    # leave every assertion below testing the pristine tree and passing
    # for the wrong reason. Every case here is supposed to edit
    # something, so prove it did.
    if diff -q "${TREE}/${DEV_REL}" "${REPO_ROOT}/${DEV_REL}" > /dev/null \
            && diff -q "${TREE}/${BUILD_REL}" "${REPO_ROOT}/${BUILD_REL}" \
                > /dev/null; then
        fail "${description}: the mutation did not change either Dockerfile"
        return
    fi

    run_check
    local output
    output="$(cat "${RUN_OUTPUT}")"

    if [ "${RUN_STATUS}" != "${expected}" ]; then
        fail "${description}: expected exit ${expected}, got ${RUN_STATUS}"
        return
    fi
    if [ -n "${needle}" ] && [[ "${output}" != *"${needle}"* ]]; then
        fail "${description}: expected '${needle}' in output:"
        printf '%s\n' "${output}" | sed 's/^/        /' >&2
        return
    fi
    ok "${description}"
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
mutate "a drifted nightly fails" 1 "Rust nightly pin drift" -- \
    bash -c 'sed -i "s/^ARG RUST_NIGHTLY=.*/ARG RUST_NIGHTLY=nightly-2020-01-01/" "${DEV}"'
mutate "a missing nightly pin fails" 1 "no 'ARG RUST_NIGHTLY" -- \
    bash -c 'sed -i "/^ARG RUST_NIGHTLY=/d" "${BUILD}"'

start "the shared cargo tool comparison"
mutate "a drifted shared tool fails" 1 "CARGO_DEB_VERSION drift" -- \
    bash -c 'sed -i "s/^ARG CARGO_DEB_VERSION=.*/ARG CARGO_DEB_VERSION=0.0.1/" "${BUILD}"'
mutate "a missing shared tool pin fails" 1 "no 'ARG CARGO_GENERATE_RPM_VERSION" -- \
    bash -c 'sed -i "/^ARG CARGO_GENERATE_RPM_VERSION=/d" "${BUILD}"'

# From here the mutations target the dev image's dev-only tools
# (cargo-fuzz, cargo-audit), which the shared-pin comparison above does
# not look at. The earlier checks exit on failure, so a mutation that
# tripped one of them would never reach the check under test.
start "--locked on every install"
mutate "a stripped --locked fails" 1 "'cargo install' without --locked" -- \
    bash -c 'sed -i "s/cargo install --locked cargo-audit@/cargo install cargo-audit@/" "${DEV}"'
mutate "a new unlocked install fails" 1 "'cargo install' without --locked" -- \
    bash -c 'printf "RUN cargo install cargo-nextest@\"\${CARGO_NEXTEST_VERSION}\"\n" >> "${DEV}"'
mutate "prose mentioning cargo install is not a hit" 0 "" -- \
    bash -c 'printf "# A comment about running cargo install by hand.\n" >> "${DEV}"'

start "every crate arrives through its ARG"
mutate "a hardcoded crate version fails" 1 "crate must be installed as" -- \
    bash -c 'sed -i "s/cargo-audit@\"\${CARGO_AUDIT_VERSION}\"/cargo-audit@0.22.2/" "${DEV}"'
# The gap the first draft of this guard left: --locked is present, no
# version is hardcoded and no ARG is referenced, so a rule-by-rule check
# sees nothing wrong while the crate floats exactly as it did before.
mutate "an install with no version at all fails" 1 "crate must be installed as" -- \
    bash -c 'sed -i "s/cargo-audit@\"\${CARGO_AUDIT_VERSION}\"/cargo-audit/" "${DEV}"'
mutate "a versionless install added later fails" 1 "crate must be installed as" -- \
    bash -c 'printf "RUN cargo install --locked cargo-nextest\n" >> "${DEV}"'
mutate "an ARG named after a different crate fails" 1 "name the ARG" -- \
    bash -c 'sed -i "s/cargo-audit@\"\${CARGO_AUDIT_VERSION}\"/cargo-audit@\"\${CARGO_FUZZ_VERSION}\"/" "${DEV}"'
# Appended rather than inserted mid-file, so this trips the reference
# check alone: inserting it above an existing ARG would also detach that
# ARG from its renovate comment and the assertion could pass on the
# wrong error.
mutate "an unreferenced ARG fails" 1 "is never referenced" -- \
    bash -c 'printf "# renovate: datasource=crate depName=cargo-unused\nARG CARGO_UNUSED_VERSION=1.0.0\n" >> "${DEV}"'

start "installs split across continuation lines"
# --locked and the crate spec need not share a physical line, and a
# guard that greps line by line would fail this valid form.
mutate "--locked on a continuation line passes" 0 "" -- \
    bash -c 'perl -0pi -e "s/cargo install --locked cargo-audit\@/cargo install \\\\\n        --locked \\\\\n        cargo-audit\@/" "${DEV}"'

start "pins stay visible to Renovate"
mutate "a quoted pin value fails" 1 "must be unquoted" -- \
    bash -c 'sed -i "s/^ARG CARGO_AUDIT_VERSION=\(.*\)/ARG CARGO_AUDIT_VERSION=\"\1\"/" "${DEV}"'
mutate "a deleted renovate comment fails" 1 "must be directly preceded by" -- \
    bash -c 'sed -i "/^# renovate: datasource=crate depName=cargo-audit\$/d" "${DEV}"'
mutate "a detached renovate comment fails" 1 "must be directly preceded by" -- \
    bash -c 'sed -i "/^# renovate: datasource=crate depName=cargo-audit\$/a # an interposed comment" "${DEV}"'
mutate "a renovate comment naming the wrong crate fails" 1 "must be directly preceded by" -- \
    bash -c 'sed -i "s/^# renovate: datasource=crate depName=cargo-audit\$/# renovate: datasource=crate depName=cargo-audit-typo/" "${DEV}"'

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
