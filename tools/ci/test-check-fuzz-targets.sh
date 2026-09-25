#!/usr/bin/env bash
#
# Tests for tools/ci/check-fuzz-targets.sh.
#
# The guard's whole value is that it fails: a target absent from
# coverage-fuzz.yml's TARGETS array is never fuzzed in CI at all, and
# nothing else in the tree notices. Its three list parsers are awk
# programs matched against the current formatting of a Rust manifest, a
# GitHub workflow and a shell array, so the failure mode to guard
# against is a reformat that makes a parser return nothing -- which
# would otherwise pass as "0 targets agree with 0 targets".
#
# Fixtures are a synthetic four-target tree rather than the real one, so
# these stay meaningful as targets are added, and the guard is copied
# into it because it resolves its own repository root from BASH_SOURCE.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-fuzz-targets.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# build_tree DIR [targets...] -- a complete, self-consistent tree.
build_tree() {
    local dir="$1"; shift
    local targets=("$@")
    local t

    mkdir -p "${dir}/src/fuzz/fuzz_targets" \
             "${dir}/.github/workflows" \
             "${dir}/tools/ci"
    cp "${CHECK}" "${dir}/tools/ci/check-fuzz-targets.sh"

    for t in "${targets[@]}"; do
        echo "// ${t}" > "${dir}/src/fuzz/fuzz_targets/${t}.rs"
    done

    {
        echo '[package]'
        echo 'name = "instar-fuzz"'
        echo 'version = "0.0.0"'
        echo
        for t in "${targets[@]}"; do
            echo '[[bin]]'
            echo "name = \"${t}\""
            echo "path = \"fuzz_targets/${t}.rs\""
            echo
        done
    } > "${dir}/src/fuzz/Cargo.toml"

    {
        echo 'jobs:'
        echo '  fuzz:'
        echo '    steps:'
        echo '      - run: |'
        echo '          TARGETS=('
        for t in "${targets[@]}"; do
            echo "            ${t}"
        done
        echo '          )'
    } > "${dir}/.github/workflows/coverage-fuzz.yml"

    {
        echo '#!/usr/bin/env bash'
        echo 'FAST_TIER=('
        echo "    ${targets[0]}"
        echo ')'
    } > "${dir}/tools/ci/fuzz-tier.sh"
}

run_check() {
    "$1/tools/ci/check-fuzz-targets.sh" > "${WORK}/out" 2> "${WORK}/err"
}

# expect_pass NAME DIR
expect_pass() {
    if run_check "$2"; then
        ok "$1"
    else
        fail "$1: expected exit 0, got $?; stderr: $(cat "${WORK}/err")"
    fi
}

# expect_fail NAME DIR NEEDLE...
expect_fail() {
    local name="$1" dir="$2"; shift 2
    local needle
    if run_check "${dir}"; then
        fail "${name}: expected a non-zero exit, got 0"
        return
    fi
    for needle in "$@"; do
        if ! grep -q -- "${needle}" "${WORK}/err"; then
            fail "${name}: stderr does not mention '${needle}': $(cat "${WORK}/err")"
            return
        fi
    done
    ok "${name}"
}

FOUR=(fuzz_alpha fuzz_beta fuzz_gamma fuzz_delta)

start 'a self-consistent tree passes'
TREE="${WORK}/consistent"
build_tree "${TREE}" "${FOUR[@]}"
expect_pass 'four agreeing targets' "${TREE}"
if grep -q '4 fuzz targets agree' "${WORK}/out"; then
    ok 'the summary counts the targets it checked'
else
    fail "the summary does not name the count: $(cat "${WORK}/out")"
fi

start 'a target missing from one list fails, naming the target and the list'
for LIST in workflow cargo fs; do
    TREE="${WORK}/missing-${LIST}"
    build_tree "${TREE}" "${FOUR[@]}"
    case "${LIST}" in
        workflow)
            grep -v 'fuzz_gamma' "${TREE}/.github/workflows/coverage-fuzz.yml" \
                > "${TREE}/wf.tmp"
            mv "${TREE}/wf.tmp" "${TREE}/.github/workflows/coverage-fuzz.yml"
            expect_fail 'absent from the workflow array' "${TREE}" \
                'fuzz_gamma' 'TARGETS array'
            ;;
        cargo)
            grep -v 'name = "fuzz_gamma"' "${TREE}/src/fuzz/Cargo.toml" \
                > "${TREE}/ct.tmp"
            mv "${TREE}/ct.tmp" "${TREE}/src/fuzz/Cargo.toml"
            expect_fail 'absent from the Cargo.toml bins' "${TREE}" \
                'fuzz_gamma' 'Cargo.toml'
            ;;
        fs)
            rm "${TREE}/src/fuzz/fuzz_targets/fuzz_gamma.rs"
            expect_fail 'absent from fuzz_targets/' "${TREE}" \
                'fuzz_gamma' 'fuzz_gamma.rs'
            ;;
    esac
done

start 'every mismatch is reported, not just the first'
TREE="${WORK}/two-missing"
build_tree "${TREE}" "${FOUR[@]}"
rm "${TREE}/src/fuzz/fuzz_targets/fuzz_gamma.rs" \
   "${TREE}/src/fuzz/fuzz_targets/fuzz_delta.rs"
expect_fail 'both absent targets are named' "${TREE}" 'fuzz_gamma' 'fuzz_delta'
if grep -q '2 problem(s) found' "${WORK}/err"; then
    ok 'the failure count matches the number of mismatches'
else
    fail "expected 2 problems: $(cat "${WORK}/err")"
fi

start 'a parser that stops matching fails rather than passing empty'
TREE="${WORK}/renamed-array"
build_tree "${TREE}" "${FOUR[@]}"
sed -i 's/TARGETS=(/FUZZ_TARGETS=(/' "${TREE}/.github/workflows/coverage-fuzz.yml"
expect_fail 'a renamed TARGETS array is not "0 agrees with 0"' "${TREE}" \
    'found no TARGETS'

TREE="${WORK}/reindented-bins"
build_tree "${TREE}" "${FOUR[@]}"
sed -i 's/^\[\[bin\]\]/  [[bin]]/' "${TREE}/src/fuzz/Cargo.toml"
expect_fail 'a reindented [[bin]] stanza is not "0 agrees with 0"' "${TREE}" \
    'found no \[\[bin\]\] name entries'

TREE="${WORK}/empty-fast-tier"
build_tree "${TREE}" "${FOUR[@]}"
sed -i 's/^FAST_TIER=(/FAST=(/' "${TREE}/tools/ci/fuzz-tier.sh"
expect_fail 'a renamed FAST_TIER array is caught' "${TREE}" 'found no FAST_TIER'

start 'the [package] name is not mistaken for a [[bin]] name'
TREE="${WORK}/package-name"
build_tree "${TREE}" "${FOUR[@]}"
expect_pass 'the crate name does not count as a target' "${TREE}"
if grep -q 'instar-fuzz' "${WORK}/err" "${WORK}/out"; then
    fail 'the crate name leaked into the target set'
else
    ok 'the crate name is absent from the report'
fi

start 'FAST_TIER is checked as a subset, not for equality'
TREE="${WORK}/fast-subset"
build_tree "${TREE}" "${FOUR[@]}"
expect_pass 'one of four in the fast tier is fine' "${TREE}"

TREE="${WORK}/fast-unknown"
build_tree "${TREE}" "${FOUR[@]}"
sed -i 's/    fuzz_alpha/    fuzz_alpha\n    fuzz_nonexistent/' \
    "${TREE}/tools/ci/fuzz-tier.sh"
expect_fail 'a FAST_TIER name that is not a target fails' "${TREE}" \
    'fuzz_nonexistent'

if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-fuzz-targets: ${FAILURES} test(s) failed" >&2
    exit 1
fi
echo 'test-check-fuzz-targets: all tests passed'
