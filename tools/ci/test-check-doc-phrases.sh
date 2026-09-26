#!/usr/bin/env bash
#
# Tests for tools/ci/check-doc-phrases.sh.
#
# The guard's whole value is that it fails: a mangled plan-filename
# phrase reads as a minor typo, not a break, so nothing forces a human
# to notice and report it -- 17 of them spread across five pages before
# anything looked. The guard uses `git grep`, so these fixtures are
# real git repositories rather than plain directories, and the guard is
# copied into each one because it resolves its own repository root from
# BASH_SOURCE.
#
# The risk this guard itself carries is a false positive on a
# legitimate string -- "PLAN-differencing workflow" reads similarly to
# the corrupted phrase at a glance -- so that case is asserted here
# alongside the positive ones.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${REPO_ROOT}/tools/ci/check-doc-phrases.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# build_tree DIR -- a real git repo with the guard installed and a
# committed docs/ tree, so `git grep` has something tracked to search.
build_tree() {
    local dir="$1"

    mkdir -p "${dir}/tools/ci" "${dir}/docs/plans"
    cp "${CHECK}" "${dir}/tools/ci/check-doc-phrases.sh"

    git -C "${dir}" init -q
    git -C "${dir}" config user.email "test@example.com"
    git -C "${dir}" config user.name "Test"
}

commit_tree() {
    local dir="$1"
    git -C "${dir}" add -A
    git -C "${dir}" commit -q -m "fixture"
}

run_check() {
    "$1/tools/ci/check-doc-phrases.sh" > "${WORK}/out" 2> "${WORK}/err"
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

start 'a clean tree passes'
TREE="${WORK}/clean"
build_tree "${TREE}"
cat > "${TREE}/docs/quirks.md" <<'EOF'
# Quirks

See the PLAN-map work for the composition rules.
EOF
commit_tree "${TREE}"
expect_pass 'a clean tree' "${TREE}"
if grep -q 'no mangled plan-filename phrases' "${WORK}/out"; then
    ok 'the summary states the tree is clean'
else
    fail "the summary is missing: $(cat "${WORK}/out")"
fi

start 'a corrupted phrase fails, naming the file and line'
TREE="${WORK}/corrupted"
build_tree "${TREE}"
cat > "${TREE}/docs/quirks.md" <<'EOF'
# Quirks

See the PLAN-m workap for the composition rules.
EOF
commit_tree "${TREE}"
expect_fail 'a single corrupted phrase' "${TREE}" \
    'docs/quirks.md:3' 'PLAN-m workap'

start 'every hit is reported, not just the first'
TREE="${WORK}/two-corrupted"
build_tree "${TREE}"
cat > "${TREE}/docs/quirks.md" <<'EOF'
See the PLAN-m workap for details.
EOF
cat > "${TREE}/docs/commit.md" <<'EOF'
See the PLAN-c workommit note.
EOF
commit_tree "${TREE}"
expect_fail 'both corrupted phrases are named' "${TREE}" \
    'docs/quirks.md' 'docs/commit.md'
if grep -q '2 problem(s) found' "${WORK}/err"; then
    ok 'the failure count matches the number of hits'
else
    fail "expected 2 problems: $(cat "${WORK}/err")"
fi

start 'docs/plans/ is exempt because it quotes the corruption as an example'
TREE="${WORK}/plans-exempt"
build_tree "${TREE}"
cat > "${TREE}/docs/plans/PLAN-example.md" <<'EOF'
Phase 9 found phrases such as "the PLAN-s worknapshot" and repaired them.
EOF
commit_tree "${TREE}"
expect_pass 'a quoted example inside docs/plans/ does not trip the guard' "${TREE}"

start 'the scope is every tracked file, not just docs/'
TREE="${WORK}/toplevel-covered"
build_tree "${TREE}"
cat > "${TREE}/CHANGELOG.md" <<'EOF'
# Changelog

Since the PLAN-q workcow2-write-infrastructure, writes are supported.
EOF
commit_tree "${TREE}"
expect_fail 'a corrupted phrase in a top-level page is caught' "${TREE}" \
    'CHANGELOG.md'

start 'tools/ci/ is exempt because its own fixtures carry the pattern'
TREE="${WORK}/toolsci-exempt"
build_tree "${TREE}"
cat > "${TREE}/tools/ci/test-something.sh" <<'EOF'
# A fixture asserting the guard catches "the PLAN-s worknapshot".
EOF
commit_tree "${TREE}"
expect_pass 'a fixture inside tools/ci/ does not trip the guard' "${TREE}"

start 'no false positive on legitimate strings'
TREE="${WORK}/no-false-positive"
build_tree "${TREE}"
cat > "${TREE}/docs/quirks.md" <<'EOF'
# Quirks

See the PLAN-map work for the composition rules.

This behaviour is covered by the PLAN-differencing workflow.
EOF
commit_tree "${TREE}"
expect_pass '"the PLAN-map work" and "PLAN-differencing workflow" both pass' "${TREE}"

if [ "${FAILURES}" -ne 0 ]; then
    echo "test-check-doc-phrases: ${FAILURES} test(s) failed" >&2
    exit 1
fi
echo 'test-check-doc-phrases: all tests passed'
