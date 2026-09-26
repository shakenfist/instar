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

    # The guard decides a candidate is corruption by rejoining it and
    # asking whether that names a real plan file, so the fixture needs
    # plans to rejoin to. These are the ones the cases below reference;
    # deliberately NOT PLAN-differencingflow.md or the like, because a
    # legitimate "PLAN-differencing workflow" must rejoin to nothing.
    local plan
    for plan in PLAN-map PLAN-commit PLAN-differencing PLAN-snapshot \
                PLAN-format-coverage PLAN-qcow2-write-infrastructure \
                PLAN-distro-matrix-ci; do
        echo "# ${plan}" > "${dir}/docs/plans/${plan}.md"
    done

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

start 'the splice is caught at any offset, not just after one letter'
# The survey happened to find only one-letter splices. Pinning the
# guard to that shape would let the same bad replace spread from a
# different offset exactly as the original did, so each of these
# rejoins to a real plan file and must be caught.
for SPLICE in 'the PLAN-di workfferencing work is done' \
              'the PLAN-m workap work is done' \
              'see the PLAN-format-coverag worke work' \
              'the PLAN-qcow2-write-infrastructur worke work'; do
    TREE="${WORK}/offset-$(echo "${SPLICE}" | md5sum | cut -c1-8)"
    build_tree "${TREE}"
    printf '# Quirks\n\n%s\n' "${SPLICE}" > "${TREE}/docs/quirks.md"
    commit_tree "${TREE}"
    expect_fail "caught: ${SPLICE}" "${TREE}" 'quirks.md'
done

start 'a legitimate plan name before "work" is not a splice'
# These rejoin to plan files that do not exist, which is how the guard
# tells a real English continuation from a spliced filename without
# guessing at a list of words that may follow "work".
for OK in 'the PLAN-differencing workflow is documented' \
          'the PLAN-map work is documented' \
          'the PLAN-snapshot workaround is documented' \
          'the PLAN-distro-matrix-ci workflow is documented'; do
    TREE="${WORK}/ok-$(echo "${OK}" | md5sum | cut -c1-8)"
    build_tree "${TREE}"
    printf '# Quirks\n\n%s\n' "${OK}" > "${TREE}/docs/quirks.md"
    commit_tree "${TREE}"
    expect_pass "not a splice: ${OK}" "${TREE}"
done

start 'a git failure is an error, not a clean tree'
# The whole point of the guard is to catch something nobody notices, so
# it must not have a silent-success path of its own. Outside a checkout
# git grep exits 128, and an `if` around the assignment would read that
# as "no matches" and pass.
TREE="${WORK}/not-a-repo"
mkdir -p "${TREE}/tools/ci"
cp "${CHECK}" "${TREE}/tools/ci/check-doc-phrases.sh"
STATUS=0
run_check "${TREE}" || STATUS=$?
if [ "${STATUS}" -eq 2 ]; then
    ok 'running outside a git checkout exits 2'
elif [ "${STATUS}" -eq 0 ]; then
    fail 'running outside a git checkout passed as clean'
else
    fail "running outside a git checkout exited ${STATUS}, expected 2"
fi
if grep -q 'git grep failed' "${WORK}/err"; then
    ok 'the error names the git failure'
else
    fail "the error does not name the git failure: $(cat "${WORK}/err")"
fi

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
