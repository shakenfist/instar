#!/usr/bin/env bash
#
# Tests the git behaviour tools/ci/prepare-testdata.sh's changed-file
# list rests on, against a real git.
#
# On the cache path that script derives the narrow resparsify's work
# list from two things: `git diff --name-only -z PREVIOUS_REV HEAD`
# across the update, and the paths whose index stat data was stale
# before it. The whole saving of the testdata dependencies disk
# depends on one property of that union: **every path the reset
# rewrote is in it**. A path the reset rewrote and the list missed
# comes back through the LFS smudge filter fully allocated, is never
# resparsified, and sits in the copy-on-write overlay at full size --
# which costs the disk its reason to exist and shows up as nothing
# worse than a job that looks slightly slow.
#
# tools/ci/test-prepare-testdata.sh stubs git, so it can prove what the
# script does with the two lists and not what git puts in them. This
# file is the other half, and it is deliberately not a test of the
# script: it runs the same sequence of git commands against a local
# bare repository and asserts what git does, so the premise is pinned
# by something that fails if a future git changes it.
#
# The second source exists because of what is measured below. The disk
# build resparsifies after its own checkout, and resparsifying is a cp
# + mv, so the index's stored stat data no longer matches the file.
# `git reset --hard` rewrites those entries even though their content
# is identical and no diff of the two trees names them -- while an
# unchanged file whose stat data is clean is left alone. That
# difference is asserted here in both directions, because it is the
# entire justification for carrying a second list.
#
# WHAT THIS DOES NOT COVER. There is no git-LFS here: the fixtures are
# ordinary small files, because ci-tooling's runner is not guaranteed
# to have git-lfs and a case that can only be skipped proves nothing.
# LFS does not change which entries the reset rewrites -- that is
# decided before any filter runs -- but it does change what a rewrite
# costs, and that is the half this cannot show: git's own blob writer
# leaves holes, so a rewrite here is cheap, where a rewrite through
# the smudge filter lands fully allocated. The expensive half is why
# the list matters; the decision this file pins is which paths belong
# in it.

set -euo pipefail

# Hermetic against whoever is running it. This file asserts what git
# does, so anything git reads from the environment is part of the
# measurement: the first version of it passed here and failed on every
# CI runner because this developer has init.defaultBranch=main set and
# the runners do not, which left the bare repository's HEAD pointing
# at an unborn master while the push created main -- and `git clone`
# reports that as "you appear to have cloned an empty repository"
# rather than as an error. Every repository below is created by this
# script in its own temporary directory, so there is no user or system
# configuration it needs.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESPARSIFY="${REPO_ROOT}/tools/ci/resparsify-testdata.sh"

FAILURES=0
start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

blocks() { stat -c %b "$1"; }

# An image with a large run of zeros, so that resparsifying it is
# measurable.
make_image() {
    python3 -c "
import os, sys
with open(sys.argv[1], 'wb') as f:
    f.write(os.urandom(65536))
    f.write(b'\0' * (8 * 1024 * 1024))
    f.write(os.urandom(65536))
" "$1"
}

# Git's own blob writer leaves holes, so a plain checkout of a
# zero-heavy file is already sparse and there would be nothing for a
# resparsify to do. The real fixtures do not arrive that way: they come
# through the git-LFS smudge filter, which copies them out of the
# object store fully allocated, and that is why resparsify exists at
# all. Inflating stands in for it.
inflate() { cp --sparse=never "$1" "$1.full" && mv "$1.full" "$1"; }

git_q() { git -C "$1" -c user.email=ci@example.invalid -c user.name=ci "${@:2}"; }

start "what a shallow fetch and reset rewrites, with real git"

REMOTE="${WORK}/remote.git"
git init -q -b main --bare "${REMOTE}"

SEED="${WORK}/seed"
git init -q -b main "${SEED}"
mkdir -p "${SEED}/downloaded/qemu-iotests"
for name in stale-stat control modified renamed-from deleted; do
    make_image "${SEED}/downloaded/qemu-iotests/${name}.qcow2"
done
printf 'testdata\n' > "${SEED}/README.md"
git_q "${SEED}" add -A
git_q "${SEED}" commit -qm 'first'
git_q "${SEED}" push -q "file://${REMOTE}" HEAD:main

# The cache a runner meets when the disk is attached: shallow, like the
# fleet's, inflated to the allocation LFS would leave, and then
# resparsified the way the disk build resparsifies -- but only one file
# of it, so that the file next to it is a control with clean stat data.
CACHE="${WORK}/cache"
git clone -q --branch main --depth 1 "file://${REMOTE}" "${CACHE}"
if [ -d "${CACHE}/downloaded" ]; then
    ok "the seeded remote clones out to a populated tree"
else
    fail "the clone produced no tree; the remote may have no main branch"
    echo "${FAILURES} check(s) failed -- nothing below can run" >&2
    exit 1
fi
STALE="${CACHE}/downloaded/qemu-iotests/stale-stat.qcow2"
CONTROL="${CACHE}/downloaded/qemu-iotests/control.qcow2"
while IFS= read -r image; do inflate "${image}"; done \
    < <(find "${CACHE}/downloaded" -type f -name '*.qcow2')
# Backdated before the refresh, and not for tidiness. Git calls an
# entry whose mtime is not older than the index file "racily clean"
# and may re-examine or re-record it, so a control refreshed in the
# same second it was written could read as stat-dirty on one
# filesystem's timestamp resolution and clean on another -- an
# intermittent failure of the one assertion here that is supposed to
# be the quiet half of the comparison.
find "${CACHE}/downloaded" -type f -exec touch -d '-1 minute' {} +
git -C "${CACHE}" update-index --refresh > /dev/null
INFLATED_BLOCKS="$(blocks "${STALE}")"
bash "${RESPARSIFY}" "${CACHE}" downloaded/qemu-iotests/stale-stat.qcow2 > /dev/null
if [ "$(blocks "${STALE}")" -lt "${INFLATED_BLOCKS}" ]; then
    ok "the disk build's resparsify is measurable (${INFLATED_BLOCKS} -> $(blocks "${STALE}") blocks)"
else
    fail "resparsify did not reduce allocation: ${INFLATED_BLOCKS} -> $(blocks "${STALE}")"
fi
if [ "$(git -C "${CACHE}" diff-files --name-only)" = 'downloaded/qemu-iotests/stale-stat.qcow2' ]; then
    ok "and leaves exactly that one entry stat-dirty"
else
    fail "stat-dirty set was '$(git -C "${CACHE}" diff-files --name-only | tr '\n' ' ')'"
fi

# The update: one image modified, one renamed, one deleted, a
# non-image changed, and two images left alone -- the stat-dirty one
# and its clean control.
PUSHER="${WORK}/pusher"
git clone -q --branch main "file://${REMOTE}" "${PUSHER}"
make_image "${PUSHER}/downloaded/qemu-iotests/modified.qcow2"
git_q "${PUSHER}" mv downloaded/qemu-iotests/renamed-from.qcow2 \
    downloaded/qemu-iotests/renamed-to.qcow2
git_q "${PUSHER}" rm -q downloaded/qemu-iotests/deleted.qcow2
printf 'testdata, updated\n' > "${PUSHER}/README.md"
git_q "${PUSHER}" add -A
git_q "${PUSHER}" commit -qm 'second'
git_q "${PUSHER}" push -q origin HEAD:main

# Modification times before the update, so that "what the reset
# rewrote" is measured rather than assumed. mtime and not inode: git
# overwrites an existing path in place, so the inode survives a
# rewrite and would report every file as untouched.
inventory() { find "${CACHE}/downloaded" -type f -printf '%P %T@\n' | sort; }
BEFORE="${WORK}/mtimes-before"
AFTER="${WORK}/mtimes-after"
inventory > "${BEFORE}"

# The sequence prepare-testdata.sh runs, in its order. diff-files is
# plumbing on purpose: the porcelain commands refresh the index and
# would erase what it is being asked about.
PREVIOUS_REV="$(git -C "${CACHE}" rev-parse --verify --quiet HEAD)"
STAT_DIRTY="$(git -C "${CACHE}" diff-files --name-only -z | tr '\0' '\n')"
git -C "${CACHE}" fetch -q --depth 1 "file://${REMOTE}" main
git -C "${CACHE}" reset --hard -q FETCH_HEAD

TREE_DIFF="${WORK}/tree-diff.txt"
CHANGED="${WORK}/changed.txt"
git -C "${CACHE}" diff --name-only -z "${PREVIOUS_REV}" FETCH_HEAD | tr '\0' '\n' \
    | sort -u > "${TREE_DIFF}"
{ cat "${TREE_DIFF}"; printf '%s\n' "${STAT_DIRTY}"; } | sort -u > "${CHANGED}"

inventory > "${AFTER}"

if [ -s "${TREE_DIFF}" ]; then
    ok "the pre-update revision is still diffable after a shallow fetch and reset"
else
    fail "the diff was empty; PREVIOUS_REV ${PREVIOUS_REV} may be unreachable"
fi

# Every path whose mtime moved, plus every path that is new. Compared
# as a set against the list rather than against the paths this test
# happens to change, so a git that starts rewriting something else
# fails here rather than passing quietly.
REWRITTEN="${WORK}/rewritten"
{
    join -j 1 -o 0,1.2,2.2 "${BEFORE}" "${AFTER}" | awk '$2 != $3 { print $1 }'
    comm -23 <(cut -d' ' -f1 "${AFTER}") <(cut -d' ' -f1 "${BEFORE}")
} | sort -u > "${REWRITTEN}"

listed() { sed -n 's|^downloaded/||p' "$1" | sort -u; }
MISSED="$(comm -23 "${REWRITTEN}" <(listed "${CHANGED}"))"
if [ -z "${MISSED}" ]; then
    ok "every path the reset rewrote is in the changed-file list"
else
    fail "the reset rewrote paths the list does not name: ${MISSED}"
fi

# The two directions that justify the second list. Without them the
# union reads as defensive padding, and the next person to read this
# script would be right to delete it.
if grep -qx 'qemu-iotests/stale-stat.qcow2' "${REWRITTEN}"; then
    ok "the reset rewrites a stat-dirty entry whose content did not change"
else
    fail "stale-stat.qcow2 was not rewritten; the second list may be unnecessary now"
fi
if ! grep -qx 'qemu-iotests/control.qcow2' "${REWRITTEN}"; then
    ok "and leaves an unchanged entry whose stat data is clean alone"
else
    fail "the reset rewrote the control, so stat-dirtiness is not the discriminator"
fi
if [ -n "$(comm -23 <(echo 'qemu-iotests/stale-stat.qcow2') <(listed "${TREE_DIFF}"))" ]; then
    ok "and the tree diff alone would have missed it"
else
    fail "the tree diff named stale-stat.qcow2; this test no longer proves the union is needed"
fi

start "what the list names"
expect_listed() {
    if grep -qx "$1" "${CHANGED}"; then
        ok "$2"
    else
        fail "$2 -- list holds: $(tr '\n' ' ' < "${CHANGED}")"
    fi
}
expect_listed 'downloaded/qemu-iotests/modified.qcow2' 'a modified image is named'
expect_listed 'downloaded/qemu-iotests/renamed-to.qcow2' 'a renamed image is named under its new path'
expect_listed 'downloaded/qemu-iotests/deleted.qcow2' 'a deleted image is named'
expect_listed 'README.md' 'a changed non-image is named, for the consumer to filter'
if ! grep -qx 'downloaded/qemu-iotests/control.qcow2' "${CHANGED}"; then
    ok "an untouched image with clean stat data is not named"
else
    fail "the list names the control"
fi

start "the resparsifier takes that list as it stands"
# The two halves have to fit against a real diff and not only a
# fabricated one. A real list carries two shapes the fabricated one
# never had: a path the update deleted, which is named and is no
# longer on disk, and a path that is not an image at all. Both must be
# skipped rather than refused, and the three that remain must be acted
# on -- the counts are asserted because "did nothing, quietly" and
# "did the right three things" share an exit status.
CONTROL_BLOCKS="$(blocks "${CONTROL}")"
STATUS=0
OUTPUT="$(bash "${RESPARSIFY}" "${CACHE}" --files-from "${CHANGED}" 2>&1)" || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    ok "exits 0 with a deleted path and a non-image in the list"
else
    fail "resparsifier exit ${STATUS}: ${OUTPUT}"
fi
case "${OUTPUT}" in
    *'resparsified 3 named image(s)'*'2 candidate(s) not in scope'*)
        ok "acted on the three surviving images and skipped the other two entries" ;;
    *) fail "unexpected accounting: ${OUTPUT}" ;;
esac
if [ "$(blocks "${CONTROL}")" = "${CONTROL_BLOCKS}" ]; then
    ok "an image outside the list was not rewritten into the overlay"
else
    fail "control.qcow2 went ${CONTROL_BLOCKS} -> $(blocks "${CONTROL}") blocks"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
