#!/usr/bin/env bash
# Prove that a change under review does not alter `instar info` output.
#
# Written for the change that taught crates/vhd and crates/vhdx to parse a
# differencing image's parent locators (docs/plans/PLAN-differencing.md).
# That change's premise was that parsing alone changes nothing about what
# any operation *does* with what it now knows. Any later change that
# touches those two crates without meaning to change info output can use
# this script as a gate; that is why it lives in tools/ rather than being
# run by hand once.
#
# Host-side chain discovery has since landed, so `instar info` now reports
# a backing file for a VHD/VHDX differencing child (see
# tests/test_differencing.py). The comparison against the base binary
# still holds as-is: it is relative, so a change that alters which images
# report a backing file shows up as a stdout difference.
#
# Base commit selection: this script never hardcodes a base SHA. It computes
# `git merge-base origin/develop HEAD` in the current worktree, i.e. the
# commit where the current branch diverged from develop. develop moves out
# from under long-lived branches, so the merge-base is the only stable
# definition of "before this branch's changes". Run `git fetch origin` before
# this script if origin/develop might be stale locally — the script does
# not fetch on your behalf, so a stale remote-tracking ref silently picks
# the wrong base.
#
# What it does:
#   1. Builds the current tree's instar (`make instar`).
#   2. Checks out the merge-base commit into a throwaway git worktree and
#      builds *that* tree's instar the same way.
#   3. For every image in tests/manifest.json that exists locally under
#      ../instar-testdata (or $INSTAR_TESTDATA_PATH), runs plain
#      `instar info FILE` and `instar info --output json FILE` — deliberately
#      NOT verbose (-v): a differencing VHDX costs a few extra sector reads
#      that land in bytes_read, which reaches send_complete and the host's
#      verbose formatter but never the info text or JSON, so a verbose
#      comparison would show a spurious difference that is not a behaviour
#      change — under both binaries and requires byte-identical stdout.
#      Both stdout and stderr are compared, along with the exit status.
#   4. Images absent from the local testdata checkout are skipped and
#      counted, never treated as failures -- except for the handful in
#      REQUIRED_IDS, the differencing fixtures (images with a parent
#      locator) that existed when the parsers were written. Skipping those, or comparing nothing at all, is
#      reported as an error rather than a pass: a gate that compared no
#      image that could have changed proves nothing.
#
# Exit status: 0 if every compared image matched; non-zero otherwise, so
# this can be used as a CI/review gate. A build failure in either tree, and a run that compared
# nothing, both exit 2 rather than falling through to a pass.
#
# Requires: docker (for `make instar`), git, jq, diff. Does not require
# sudo — /dev/kvm must be group-readable/writable by the invoking user (the
# instar-build image runs KVM ops unprivileged when that holds).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

TESTDATA_ROOT="${INSTAR_TESTDATA_PATH:-$REPO_ROOT/../instar-testdata}"
MANIFEST="$REPO_ROOT/tests/manifest.json"

if [ ! -f "$MANIFEST" ]; then
    echo "error: manifest not found at $MANIFEST" >&2
    exit 2
fi

if [ ! -d "$TESTDATA_ROOT" ]; then
    echo "error: testdata root not found at $TESTDATA_ROOT (set INSTAR_TESTDATA_PATH)" >&2
    exit 2
fi

echo "=== Determining base commit ==="
BASE="$(git merge-base origin/develop HEAD)"
if [ -z "$BASE" ]; then
    echo "error: could not compute merge-base with origin/develop" >&2
    exit 2
fi
# On develop the merge-base IS HEAD, so without this the script builds
# the same tree twice, finds it byte-identical, and prints PASS having
# compared nothing -- a green result that proves the opposite of what it
# claims. Comparing a commit with itself is a broken invocation, not a
# pass.
if [ "$BASE" = "$(git rev-parse HEAD)" ]; then
    echo "error: merge-base with origin/develop is HEAD itself, so there" >&2
    echo "       is nothing to compare. Run this from a branch that has" >&2
    echo "       commits origin/develop does not." >&2
    exit 2
fi
echo "Base commit (git merge-base origin/develop HEAD): $BASE"
echo "  $(git log -1 --format='%h %s' "$BASE")"

echo ""
echo "=== Building current tree's instar ==="
CURRENT_BINARY="$REPO_ROOT/src/target/release/instar"
# Remove the binary first and check make's exit status afterwards. The
# script runs without `set -e` (the comparison loop wants to keep going
# after a failing image), so a failed build would otherwise fall through
# to an existence check that a leftover artifact from an earlier run
# satisfies -- and the script would compare two stale binaries and print
# PASS. A false PASS is the worst thing this script can do, since its
# whole job is to prove that info output did not change.
rm -f "$CURRENT_BINARY"
if ! make -C "$REPO_ROOT" instar; then
    echo "error: building the current tree's instar failed" >&2
    exit 2
fi
if [ ! -x "$CURRENT_BINARY" ]; then
    echo "error: current instar binary not found at $CURRENT_BINARY after build" >&2
    exit 2
fi

echo ""
echo "=== Building base commit's ($BASE) instar in a throwaway worktree ==="
BASE_WORKTREE="$(mktemp -d)"
WORK="$(mktemp -d)"
# cleanup is invoked via 'trap cleanup EXIT' below. ShellCheck 0.11.0
# false-positives SC2329 ("never invoked") here because the script ends
# in an explicit `exit` after a while-read/process-substitution loop.
# shellcheck disable=SC2329
cleanup() {
    if [ -n "${BASE_WORKTREE:-}" ] && [ -d "$BASE_WORKTREE" ]; then
        git -C "$REPO_ROOT" worktree remove --force "$BASE_WORKTREE" >/dev/null 2>&1 || true
        rm -rf "$BASE_WORKTREE"
    fi
    [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT

git worktree add --detach "$BASE_WORKTREE" "$BASE" >/dev/null
BASE_BINARY="$BASE_WORKTREE/src/target/release/instar"
# The base worktree is freshly created so nothing stale can be here, but
# the exit status is still checked: a base build that fails silently is
# the same false PASS as above, arriving by a different route.
if ! make -C "$BASE_WORKTREE" instar; then
    echo "error: building the base commit's ($BASE) instar failed" >&2
    exit 2
fi
if [ ! -x "$BASE_BINARY" ]; then
    echo "error: base instar binary not found at $BASE_BINARY after build" >&2
    exit 2
fi

echo ""
echo "=== Comparing instar info output ==="

COMPARED=0
SKIPPED=0
FAILED=0
FAILED_IDS=()

# Images that must be present, not merely skipped. These are the
# differencing fixtures that existed when the parsers this script guards
# were written: those parsers read a parent locator, and these were then
# the only images in the manifest that had one. A run that skipped them
# compared nothing that could have changed.
REQUIRED_IDS=(
    vhd-differencing
    vhd-diff-child-aligned
    vhd-diff-locator-conflicting
    vhdx-diff-child
)
# Space-delimited so membership is a `case` glob rather than a nested
# loop over a possibly-empty array.
FOUND_REQUIRED=" "

# id, path as tab-separated records.
while IFS=$'\t' read -r img_id img_path; do
    full_path="$TESTDATA_ROOT/$img_path"

    if [ ! -f "$full_path" ]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    COMPARED=$((COMPARED + 1))
    entry_failed=0

    for required in "${REQUIRED_IDS[@]}"; do
        if [ "$img_id" = "$required" ]; then
            FOUND_REQUIRED+="$img_id "
        fi
    done

    for mode in human json; do
        if [ "$mode" = "human" ]; then
            cur_out="$WORK/${img_id}.current.human"
            base_out="$WORK/${img_id}.base.human"
            "$CURRENT_BINARY" info "$full_path" >"$cur_out" 2>"$cur_out.stderr"
            cur_rc=$?
            "$BASE_BINARY" info "$full_path" >"$base_out" 2>"$base_out.stderr"
            base_rc=$?
        else
            cur_out="$WORK/${img_id}.current.json"
            base_out="$WORK/${img_id}.base.json"
            "$CURRENT_BINARY" info --output json "$full_path" >"$cur_out" 2>"$cur_out.stderr"
            cur_rc=$?
            "$BASE_BINARY" info --output json "$full_path" >"$base_out" 2>"$base_out.stderr"
            base_rc=$?
        fi

        if [ "$cur_rc" -ne "$base_rc" ]; then
            echo "FAIL: $img_id ($mode): exit code differs (current=$cur_rc base=$base_rc)"
            entry_failed=1
        fi

        if ! cmp -s "$cur_out" "$base_out"; then
            echo "FAIL: $img_id ($mode): stdout differs"
            diff -u "$base_out" "$cur_out" | head -20 | sed 's/^/    /'
            entry_failed=1
        fi

        # stderr as well as stdout. Nothing in the change this script was
        # written for can plausibly write to stderr, but the script is
        # meant to be reused by later changes that can, and a new
        # diagnostic line is exactly the kind of change that would
        # otherwise slip through a stdout-only gate.
        if ! cmp -s "$cur_out.stderr" "$base_out.stderr"; then
            echo "FAIL: $img_id ($mode): stderr differs"
            diff -u "$base_out.stderr" "$cur_out.stderr" | head -20 | sed 's/^/    /'
            entry_failed=1
        fi

    done

    if [ "$entry_failed" -ne 0 ]; then
        FAILED=$((FAILED + 1))
        FAILED_IDS+=("$img_id")
    fi
done < <(jq -r '.images[] | [.id, .path] | @tsv' "$MANIFEST")

echo ""
echo "=== Summary ==="
echo "Compared: $COMPARED"
echo "Skipped (not present locally under $TESTDATA_ROOT): $SKIPPED"
echo "Failed:   $FAILED"

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Failing image ids:"
    for id in "${FAILED_IDS[@]}"; do
        echo "  - $id"
    done
    exit 1
fi

# A gate that compared nothing proves nothing. Zero comparisons is what a
# fresh testdata checkout or a wrong INSTAR_TESTDATA_PATH produces, and
# without this the script would print PASS over it. REQUIRED_IDS is the
# same argument one level down: those images are the only ones whose
# behaviour the parsers this script guards could change, so a run that
# skipped them is a vacuous pass even when it compared two hundred
# others.
if [ "$COMPARED" -eq 0 ]; then
    echo ""
    echo "error: no manifest image was found under $TESTDATA_ROOT, so nothing was compared." >&2
    echo "       Set INSTAR_TESTDATA_PATH, or fetch the testdata checkout." >&2
    exit 2
fi

MISSING_REQUIRED=()
for required in "${REQUIRED_IDS[@]}"; do
    case "$FOUND_REQUIRED" in
        *" $required "*) ;;
        *) MISSING_REQUIRED+=("$required") ;;
    esac
done
if [ "${#MISSING_REQUIRED[@]}" -ne 0 ]; then
    echo ""
    echo "error: these images must be present for this check to mean anything:" >&2
    for id in "${MISSING_REQUIRED[@]}"; do
        echo "  - $id" >&2
    done
    exit 2
fi

echo ""
echo "PASS: instar info output is byte-identical between $BASE and $(git rev-parse HEAD) for all $COMPARED compared images."
exit 0
