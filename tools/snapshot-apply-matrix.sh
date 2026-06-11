#!/usr/bin/env bash
# Phase 8e verification matrix for `instar snapshot -a` against
# qemu-img 10.0.8. Apply writes no timestamps, no snapshot-table
# bytes, and no header bytes (phase plan fact 7), so FULL
# byte-identity against qemu holds for every scenario — including
# diverged applies — which is this harness's bar: prepare each
# fixture ONCE with qemu, `cp` to A and B, apply with instar on A
# and qemu-img on B, then compare bytes.
#
# The qemu side runs with `file.discard=ignore`: apply frees the
# old active chain's clusters and qemu would punch holes over them
# by default (QCOW2_DISCARD_SNAPSHOT), while instar deliberately
# never writes to freed clusters (stale bytes remain — fact 6's
# cache-discard behaviour). Disabling the protocol-level discard on
# the qemu side removes that documented divergence (docs/quirks.md)
# and the comparison is then exact: cmp over the common prefix,
# with any instar tail beyond qemu's length all zeroes.
#
# Content restoration is asserted independently of byte-identity:
# `qemu-img compare` against a reference copy taken at snapshot
# time must report "Images are identical" after a diverged apply.
#
# Not a committed test (phase 11 owns that) — this is the phase 8
# validation harness. Exits non-zero on any failure.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

# qemu-img snapshot -a with protocol-level discard disabled (see
# the header comment). $1 = snapshot arg, $2 = image.
qemu_apply_nodiscard() {
    qemu-img snapshot -a "$1" \
        --image-opts "driver=qcow2,file.filename=$2,file.discard=ignore"
}

# Assert A == B over the common prefix and that A's tail beyond B's
# length (if any) is all zeroes. $1 = label, $2 = A, $3 = B.
assert_byte_identical() {
    local label="$1" a="$2" b="$3"
    local la lb common
    la=$(stat -c %s "$a"); lb=$(stat -c %s "$b")
    common=$la
    [ "$lb" -lt "$common" ] && common=$lb
    if ! cmp -n "$common" "$a" "$b" >/dev/null 2>&1; then
        bad "$label: bytes differ within common prefix:"
        cmp -n "$common" "$a" "$b" 2>&1 | head -3 | sed 's/^/      /'
        return 1
    fi
    if [ "$la" -gt "$lb" ]; then
        if ! tail -c +$((lb + 1)) "$a" | tr -d '\0' | LC_ALL=C grep -q . ; then
            ok "$label: byte-identical (instar tail of $((la - lb)) bytes is all zero)"
        else
            bad "$label: instar tail beyond qemu length is not all zero"
            return 1
        fi
    elif [ "$la" -lt "$lb" ]; then
        bad "$label: instar image SHORTER than qemu's ($la < $lb)"
        return 1
    else
        ok "$label: byte-identical (equal length)"
    fi
}

# Assert qemu-img check is clean (exit 0, no leaks). $1=label $2=img.
assert_check_clean() {
    local label="$1" img="$2"
    if qemu-img check "$img" >"$WORK/chk.out" 2>&1 \
        && ! grep -qiE "Leaked|leaked clusters" "$WORK/chk.out"; then
        ok "$label: qemu-img check clean"
    else
        bad "$label: qemu-img check not clean:"
        sed 's/^/      /' "$WORK/chk.out"
    fi
}

# Assert `qemu-img compare $2 $3` reports identical content.
assert_content_identical() {
    local label="$1" a="$2" b="$3"
    local out
    out=$(qemu-img compare "$a" "$b" 2>&1)
    if [ "$out" = "Images are identical." ]; then
        ok "$label: qemu-img compare — images are identical"
    else
        bad "$label: qemu-img compare: $out"
    fi
}

# Core scheme: copy the prepared base, apply with each tool,
# compare bytes + check clean. $1 = fixture, $2 = scenario label,
# $3 = snapshot arg; $WORK/base.qcow2 must exist.
apply_and_compare() {
    local name="$1" scenario="$2" arg="$3"
    cp "$WORK/base.qcow2" "$WORK/A.qcow2"
    cp "$WORK/base.qcow2" "$WORK/B.qcow2"
    if ! "$INSTAR" snapshot -a "$arg" "$WORK/A.qcow2" >/dev/null 2>"$WORK/a.err"; then
        bad "$name/$scenario: instar -a failed: $(cat "$WORK/a.err")"
        return 1
    fi
    if ! qemu_apply_nodiscard "$arg" "$WORK/B.qcow2" >/dev/null 2>&1; then
        bad "$name/$scenario: qemu-img -a failed (unexpected)"
        return 1
    fi
    assert_byte_identical "$name/$scenario" "$WORK/A.qcow2" "$WORK/B.qcow2" || return 1
    assert_check_clean "$name/$scenario" "$WORK/A.qcow2"
}

# Fixture creators (mirroring the create/delete matrices) ------------------
mk_v3_64k() {
    qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write -P 0xA1 0 64k" -c "write -P 0xA2 1M 128k" -c "write -P 0xA3 5M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_v3_512() {
    qemu-img create -f qcow2 -o cluster_size=512 "$WORK/base.qcow2" 4M >/dev/null 2>&1
    qemu-io -c "write -P 0xA1 0 4k" -c "write -P 0xA2 1M 8k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_v2() {
    qemu-img create -f qcow2 -o compat=0.10 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write -P 0xA1 0 64k" -c "write -P 0xA2 2M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_backing() {
    qemu-img create -f qcow2 "$WORK/bk.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write -P 0xBB 0 64k" "$WORK/bk.qcow2" >/dev/null 2>&1
    qemu-img create -f qcow2 -b "$WORK/bk.qcow2" -F qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write -P 0xA1 1M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_ext_l2() {
    qemu-img create -f qcow2 -o extended_l2=on,cluster_size=64k "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write -P 0xA1 0 64k" -c "write -P 0xA2 1M 32k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_zero() {
    qemu-img create -f qcow2 "$WORK/base.qcow2" 0 >/dev/null 2>&1
}

# Divergent writes between snapshot and apply. Includes one write
# beyond the data range the fixture populated. No-op args via
# globals: $1 = small-image flag (512-byte-cluster 4M fixture).
diverge() {
    local small="${1:-no}"
    if [ "$small" = "small" ]; then
        qemu-io -c "write -P 0xD1 0 4k" -c "write -P 0xD2 3M 8k" "$WORK/base.qcow2" >/dev/null 2>&1
    else
        qemu-io -c "write -P 0xD1 0 64k" -c "write -P 0xD2 9M 128k" "$WORK/base.qcow2" >/dev/null 2>&1
    fi
}

# Per-fixture scenarios: fresh apply, then diverged apply with a
# snapshot-time reference for the content-restoration assertion.
run_fixture() {
    local name="$1"; shift
    local create_cmd="$1"; shift
    local small="${1:-no}"
    printf '\n=== Fixture: %s (fresh apply / diverged apply) ===\n' "$name"
    rm -f "$WORK"/base.qcow2 "$WORK"/A.qcow2 "$WORK"/B.qcow2 "$WORK"/ref.qcow2
    eval "$create_cmd"
    qemu-img snapshot -c snap1 "$WORK/base.qcow2" >/dev/null 2>&1
    # Reference copy at snapshot time (content oracle).
    cp "$WORK/base.qcow2" "$WORK/ref.qcow2"
    # Fresh apply: immediately after create. Per fact 6 the only
    # delta vs the pre-apply image is the snapshot-L1 flag scrub,
    # and instar must match qemu exactly.
    apply_and_compare "$name" "fresh" snap1 || return
    # Diverged apply (zero-byte disks cannot diverge).
    if [ "$name" != "zero-byte-disk" ]; then
        diverge "$small"
        apply_and_compare "$name" "diverged" snap1 || return
        assert_content_identical "$name/diverged" "$WORK/A.qcow2" "$WORK/ref.qcow2"
    fi
}

run_fixture "v3-64k-data"    mk_v3_64k
run_fixture "v3-512-cluster" mk_v3_512 small
run_fixture "v2"             mk_v2
run_fixture "backing-file"   mk_backing
run_fixture "extended-l2"    mk_ext_l2
run_fixture "zero-byte-disk" mk_zero

# --- Precedence fixture: -a matches ID first, then name (fact 2) ----------
# Snapshots: id=1 name="2", id=2 name="x". `-a 2` must apply the
# snapshot with ID 2 (named "x") under BOTH tools — a later entry
# matching by ID beats an earlier entry matching by name. The same
# fixture contrasts `-d 2` (phase 7: name-only) deleting the one
# NAMED "2".
printf '\n=== Precedence: -a 2 applies ID 2; -d 2 deletes the name "2" ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x11 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c 2 "$WORK/base.qcow2" >/dev/null 2>&1   # id=1, name="2"
qemu-io -c "write -P 0x22 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
cp "$WORK/base.qcow2" "$WORK/refx.qcow2"
qemu-img snapshot -c x "$WORK/base.qcow2" >/dev/null 2>&1   # id=2, name="x"
qemu-io -c "write -P 0x33 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
apply_and_compare "precedence" "-a 2" 2
# Content assertion: the applied state is snapshot "x" (id 2),
# i.e. the 0x22 content — NOT snapshot "2" (id 1, 0x11 content).
if qemu-io -c "read -P 0x22 0 64k" "$WORK/A.qcow2" >/dev/null 2>&1; then
    ok "precedence: -a 2 applied the snapshot with ID 2 (content 0x22, not 0x11)"
else
    bad "precedence: -a 2 applied the wrong snapshot (content is not 0x22)"
fi
assert_content_identical "precedence/-a 2" "$WORK/A.qcow2" "$WORK/refx.qcow2"
# Contrast: -d 2 on the same fixture targets the snapshot NAMED
# "2" (id 1), the phase 7 name-only behaviour.
cp "$WORK/base.qcow2" "$WORK/D.qcow2"
"$INSTAR" snapshot -d 2 "$WORK/D.qcow2" >/dev/null 2>&1
survivors=$(qemu-img snapshot -l "$WORK/D.qcow2" 2>&1 | awk 'NR>2 {print $1":"$2}')
if [ "$survivors" = "2:x" ]; then
    ok "precedence: -d 2 on the same fixture removed the snapshot NAMED 2 (survivor 2:x)"
else
    bad "precedence: -d 2 survivors wrong: $survivors (want 2:x)"
fi

# --- Apply by pure ID (works — unlike delete) ------------------------------
printf '\n=== Apply by pure ID: -a 1 works where -d 1 is not-found ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x44 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c alpha "$WORK/base.qcow2" >/dev/null 2>&1
qemu-io -c "write -P 0x55 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
apply_and_compare "pure-id" "-a 1" 1
if qemu-io -c "read -P 0x44 0 64k" "$WORK/A.qcow2" >/dev/null 2>&1; then
    ok "pure-id: -a 1 restored alpha's content (0x44)"
else
    bad "pure-id: -a 1 did not restore alpha's content"
fi
cp "$WORK/base.qcow2" "$WORK/D.qcow2"
if ! "$INSTAR" snapshot -d 1 "$WORK/D.qcow2" >/dev/null 2>&1; then
    ok "pure-id: -d 1 on the same image is not-found (delete has no ID path)"
else
    bad "pure-id: -d 1 unexpectedly succeeded"
fi

# --- Duplicate names: first name-match when no ID matches ------------------
printf '\n=== Duplicate names: first match in table order applied ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x66 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c dup "$WORK/base.qcow2" >/dev/null 2>&1   # id=1, content 0x66
qemu-io -c "write -P 0x77 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c dup "$WORK/base.qcow2" >/dev/null 2>&1   # id=2, content 0x77
qemu-io -c "write -P 0x88 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
apply_and_compare "dup-name" "-a dup" dup
if qemu-io -c "read -P 0x66 0 64k" "$WORK/A.qcow2" >/dev/null 2>&1; then
    ok "dup-name: first name-match (id=1, 0x66) applied"
else
    bad "dup-name: wrong duplicate applied (content is not 0x66)"
fi

# --- Round-trip: snap, write, apply, write, apply again --------------------
printf '\n=== Round-trip: apply restores the snapshot after each divergence ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x10 0 64k" -c "write -P 0x20 1M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c rt "$WORK/base.qcow2" >/dev/null 2>&1
cp "$WORK/base.qcow2" "$WORK/rtref.qcow2"
qemu-io -c "write -P 0x30 0 64k" -c "write -P 0x40 8M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
apply_and_compare "round-trip" "leg-1" rt || true
if [ -f "$WORK/A.qcow2" ]; then
    assert_content_identical "round-trip/leg-1" "$WORK/A.qcow2" "$WORK/rtref.qcow2"
    # Second leg continues on instar's own output (A): write, apply
    # again with both tools from the SAME diverged state.
    qemu-io -c "write -P 0x50 2M 64k" "$WORK/A.qcow2" >/dev/null 2>&1
    cp "$WORK/A.qcow2" "$WORK/base.qcow2"
    apply_and_compare "round-trip" "leg-2" rt || true
    assert_content_identical "round-trip/leg-2" "$WORK/A.qcow2" "$WORK/rtref.qcow2"
fi

# --- Apply middle of three snapshots, delete one, apply again --------------
# Cross-mode interaction (master plan open question 9). The
# snapshots are taken at DIFFERENT divergence points, so the apply
# exercises the surviving-old-active-L2 path: the old active chain
# shares L2s with s3 (not with the applied s2) — qemu's -1 walk
# refreshes those L2s' COPIED flags and flushes them because the
# clusters are not freed.
printf '\n=== Cross-mode: apply middle of three, delete one, apply again ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x01 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/base.qcow2" >/dev/null 2>&1
qemu-io -c "write -P 0x02 0 64k" -c "write -P 0x12 1M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s2 "$WORK/base.qcow2" >/dev/null 2>&1
cp "$WORK/base.qcow2" "$WORK/s2ref.qcow2"
qemu-io -c "write -P 0x03 0 64k" -c "write -P 0x13 2M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s3 "$WORK/base.qcow2" >/dev/null 2>&1
apply_and_compare "cross-mode" "apply-middle(s2)" s2
if [ -f "$WORK/A.qcow2" ]; then
    assert_content_identical "cross-mode/apply-middle" "$WORK/A.qcow2" "$WORK/s2ref.qcow2"
    # Continue cross-mode on the SAME image with both tools:
    # delete s3, then apply s1.
    cp "$WORK/A.qcow2" "$WORK/CA.qcow2"
    cp "$WORK/B.qcow2" "$WORK/CB.qcow2"
    if "$INSTAR" snapshot -d s3 "$WORK/CA.qcow2" >/dev/null 2>&1 \
        && qemu-img snapshot -d s3 --image-opts \
            "driver=qcow2,file.filename=$WORK/CB.qcow2,file.discard=ignore" >/dev/null 2>&1 \
        && "$INSTAR" snapshot -a s1 "$WORK/CA.qcow2" >/dev/null 2>&1 \
        && qemu_apply_nodiscard s1 "$WORK/CB.qcow2" >/dev/null 2>&1; then
        assert_byte_identical "cross-mode/delete-s3-then-apply-s1" "$WORK/CA.qcow2" "$WORK/CB.qcow2"
        assert_check_clean "cross-mode/delete-s3-then-apply-s1" "$WORK/CA.qcow2"
        if qemu-io -c "read -P 0x01 0 64k" "$WORK/CA.qcow2" >/dev/null 2>&1; then
            ok "cross-mode: final state is s1's content (0x01)"
        else
            bad "cross-mode: final content wrong (want s1's 0x01)"
        fi
    else
        bad "cross-mode: one of the four cross-mode operations failed"
    fi
fi

# --- Post-apply COW write probe ---------------------------------------------
# After an apply, every cluster reachable from the new active chain
# has refcount >= 2 (the flag invariant: the snapshot still
# references everything). A write through the active layer must
# therefore COW, leaving the snapshot intact — verified via qemu's
# own `snapshot -a` as the oracle on a copy.
printf '\n=== Post-apply write probe: write COWs, snapshot stays intact ===\n'
rm -f "$WORK"/p.qcow2
qemu-img create -f qcow2 "$WORK/p.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0xAA 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1
qemu-img snapshot -c ps "$WORK/p.qcow2" >/dev/null 2>&1
qemu-io -c "write -P 0xBB 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1
if ! "$INSTAR" snapshot -a ps "$WORK/p.qcow2" >/dev/null 2>"$WORK/p.err"; then
    bad "probe: instar -a ps failed: $(cat "$WORK/p.err")"
else
    ok "probe: instar -a ps succeeded"
    qemu-io -c "write -P 0xCC 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1
    assert_check_clean "probe(post-write)" "$WORK/p.qcow2"
    cp "$WORK/p.qcow2" "$WORK/p_apply.qcow2"
    qemu-img snapshot -a ps "$WORK/p_apply.qcow2" >/dev/null 2>&1
    if qemu-io -c "read -P 0xAA 0 64k" "$WORK/p_apply.qcow2" >/dev/null 2>&1; then
        ok "probe: snapshot ps intact under qemu's own apply (0xAA preserved -> the write COWed)"
    else
        bad "probe: snapshot ps CORRUPTED by the post-apply write (no COW)"
    fi
    if qemu-io -c "read -P 0xCC 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1; then
        ok "probe: active layer carries the new pattern (0xCC)"
    else
        bad "probe: active layer pattern wrong after post-apply write"
    fi
fi

printf '\n=== Apply matrix result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
