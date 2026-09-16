#!/usr/bin/env bash
#
# Tests for tools/ci/push-fuzz-corpus.sh.
#
# The script clones with --filter=blob:none --sparse and stages paths
# that lie outside the checked-out cone, which is the whole reason it is
# fast -- and also the part that fails quietly if it is wrong. Two ways
# it could go wrong are silent and expensive:
#
#   - staging outside the sparse cone without `git add --sparse` leaves
#     the new entries unstaged, so the nightly reports success and
#     pushes nothing; and
#   - an empty index (which `git clone --no-checkout` would give) makes
#     the commit *delete* every fixture in instar-testdata rather than
#     add to the corpus.
#
# So these tests assert the resulting commit, not the script's output:
# the new entry is present, and nothing that was there before is gone.
#
# Everything runs against local repositories under a temp dir via
# PUSH_URL, so no network, no token and no GitLab are involved.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUSHER="${REPO_ROOT}/tools/ci/push-fuzz-corpus.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

ok() {
    echo "    ok: $1"
}

fail() {
    echo "    FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

check() {
    # check DESCRIPTION ACTUAL EXPECTED
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        fail "$1: expected '$3', got '$2'"
    fi
}

git_q() {
    git -c init.defaultBranch=main -c user.name=t -c user.email=t@t "$@"
}

# An upstream that looks like instar-testdata in the ways that matter:
# a corpus under custom/fuzz-corpus/<target>/, and unrelated fixtures
# elsewhere that must survive the push.
make_upstream() {
    local dir="$1"
    mkdir -p "${dir}/custom/fuzz-corpus/fuzz_alpha" \
             "${dir}/custom/fuzz-corpus/fuzz_beta" \
             "${dir}/custom/security"
    echo old-a > "${dir}/custom/fuzz-corpus/fuzz_alpha/aaaa1111"
    echo old-b > "${dir}/custom/fuzz-corpus/fuzz_beta/bbbb2222"
    echo fixture > "${dir}/custom/security/some-image.qcow2"
    echo readme > "${dir}/README.md"
    git_q init -q "${dir}"
    git_q -C "${dir}" add -A
    git_q -C "${dir}" commit -q -m "seed"
    # Allow a push to the checked-out branch.
    git_q -C "${dir}" config receive.denyCurrentBranch updateInstead
}

# A local corpus as the fuzz step leaves it: everything the seeding step
# pulled down, plus whatever this run discovered.
make_local_corpus() {
    local dir="$1"
    mkdir -p "${dir}/fuzz_alpha" "${dir}/fuzz_beta"
    echo old-a > "${dir}/fuzz_alpha/aaaa1111"
    echo old-b > "${dir}/fuzz_beta/bbbb2222"
}

echo "--- a new entry is committed, and nothing else is disturbed"
UP="${WORK}/up1"
SRC="${WORK}/src1"
make_upstream "${UP}"
make_local_corpus "${SRC}"
echo brand-new > "${SRC}/fuzz_alpha/cccc3333"

PUSH_TOKEN=unused PUSH_URL="${UP}" CORPUS_SRC="${SRC}" \
    "${PUSHER}" > "${WORK}/out1" 2>&1 || fail "pusher exited non-zero"

check "counts the corpus correctly" \
    "$(grep -c '^corpus: 3 local, 2 committed, 1 new$' "${WORK}/out1" || true)" \
    "1"
check "new entry is in the upstream tree" \
    "$(git_q -C "${UP}" show HEAD:custom/fuzz-corpus/fuzz_alpha/cccc3333)" \
    "brand-new"
check "pre-existing corpus entry survives" \
    "$(git_q -C "${UP}" show HEAD:custom/fuzz-corpus/fuzz_beta/bbbb2222)" \
    "old-b"
check "unrelated fixture survives" \
    "$(git_q -C "${UP}" show HEAD:custom/security/some-image.qcow2)" \
    "fixture"
check "exactly one new commit" \
    "$(git_q -C "${UP}" rev-list --count HEAD)" "2"

echo "--- an entry for a brand-new target creates its directory"
UP="${WORK}/up2"
SRC="${WORK}/src2"
make_upstream "${UP}"
make_local_corpus "${SRC}"
mkdir -p "${SRC}/fuzz_gamma"
echo gamma > "${SRC}/fuzz_gamma/dddd4444"

PUSH_TOKEN=unused PUSH_URL="${UP}" CORPUS_SRC="${SRC}" \
    "${PUSHER}" > "${WORK}/out2" 2>&1 || fail "pusher exited non-zero"

check "new target's entry is committed" \
    "$(git_q -C "${UP}" show HEAD:custom/fuzz-corpus/fuzz_gamma/dddd4444)" \
    "gamma"

echo "--- an unchanged corpus pushes nothing"
UP="${WORK}/up3"
SRC="${WORK}/src3"
make_upstream "${UP}"
make_local_corpus "${SRC}"

PUSH_TOKEN=unused PUSH_URL="${UP}" CORPUS_SRC="${SRC}" \
    "${PUSHER}" > "${WORK}/out3" 2>&1 || fail "pusher exited non-zero"

check "says there is nothing to push" \
    "$(grep -c 'No new corpus entries' "${WORK}/out3" || true)" "1"
check "no commit was made" \
    "$(git_q -C "${UP}" rev-list --count HEAD)" "1"

echo "--- missing token and missing corpus are not failures"
if PUSH_URL="${UP}" CORPUS_SRC="${SRC}" "${PUSHER}" \
        > "${WORK}/out4" 2>&1; then
    check "no token exits 0 with a reason" \
        "$(grep -c 'PUSH_TOKEN not set' "${WORK}/out4" || true)" "1"
else
    fail "missing token should exit 0"
fi

if PUSH_TOKEN=unused PUSH_URL="${UP}" CORPUS_SRC="${WORK}/nope" \
        "${PUSHER}" > "${WORK}/out5" 2>&1; then
    check "no corpus exits 0 with a reason" \
        "$(grep -c 'No corpus directory' "${WORK}/out5" || true)" "1"
else
    fail "missing corpus should exit 0"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
