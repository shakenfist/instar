#!/usr/bin/env bash
# Phase 7e verification matrix for `instar snapshot -d` against
# qemu-img 10.0.8. The centrepiece is the byte-identity scheme that
# delete makes possible because it writes no timestamps (phase plan
# fact 5): prepare each fixture ONCE with qemu, `cp` to A and B,
# delete with instar on A and qemu-img on B, then compare bytes.
#
# The qemu side runs with `file.discard=ignore`: by default qemu-img
# punches holes (discard) over the clusters a delete frees
# (QCOW2_DISCARD_SNAPSHOT / QCOW2_DISCARD_ALWAYS default on), so the
# freed clusters read back as zeros, while instar deliberately never
# writes to freed clusters (stale bytes remain). Disabling the
# protocol-level discard on the qemu side removes that documented
# divergence (docs/quirks.md) and the qcow2 metadata comparison is
# then exact: cmp over the common prefix, with any instar tail
# beyond qemu's length all zeroes (the sector-granular tail quirk).
#
# Not a committed test (phase 11 owns that) — this is the phase 7
# validation harness. Exits non-zero on any failure.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

strip_date() {
    sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<DATE>/g'
}

# qemu-img snapshot -d with protocol-level discard disabled (see
# the header comment). $1 = snapshot arg, $2 = image.
qemu_delete_nodiscard() {
    qemu-img snapshot -d "$1" \
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

# Assert instar -l == qemu-img -l byte-identically. $1=label $2=img.
assert_list_identical() {
    local label="$1" img="$2" il ql
    il=$(TZ=UTC "$INSTAR" snapshot -l "$img" 2>&1)
    ql=$(TZ=UTC qemu-img snapshot -l "$img" 2>&1)
    if [ "$il" = "$ql" ]; then
        ok "$label: instar -l == qemu-img -l"
    else
        bad "$label: listings differ:"
        diff <(echo "$il") <(echo "$ql") | sed 's/^/      /'
    fi
}

# Core scheme: prepare once, copy, delete with each tool, compare.
# $1 = fixture name, $2 = scenario label, $3 = snapshot arg to
# delete; $WORK/base.qcow2 must exist with the snapshots staged.
delete_and_compare() {
    local name="$1" scenario="$2" arg="$3"
    cp "$WORK/base.qcow2" "$WORK/A.qcow2"
    cp "$WORK/base.qcow2" "$WORK/B.qcow2"
    if ! "$INSTAR" snapshot -d "$arg" "$WORK/A.qcow2" >/dev/null 2>"$WORK/a.err"; then
        bad "$name/$scenario: instar -d failed: $(cat "$WORK/a.err")"
        return
    fi
    if ! qemu_delete_nodiscard "$arg" "$WORK/B.qcow2" >/dev/null 2>&1; then
        bad "$name/$scenario: qemu-img -d failed (unexpected)"
        return
    fi
    assert_byte_identical "$name/$scenario" "$WORK/A.qcow2" "$WORK/B.qcow2" || return
    assert_check_clean "$name/$scenario" "$WORK/A.qcow2"
    assert_list_identical "$name/$scenario" "$WORK/A.qcow2"
}

run_fixture() {
    local name="$1"; shift
    local create_cmd="$1"; shift
    printf '\n=== Fixture: %s (delete first / middle / last of three) ===\n' "$name"
    rm -f "$WORK"/base.qcow2 "$WORK"/A.qcow2 "$WORK"/B.qcow2
    eval "$create_cmd"
    qemu-img snapshot -c alpha "$WORK/base.qcow2" >/dev/null 2>&1
    qemu-img snapshot -c beta  "$WORK/base.qcow2" >/dev/null 2>&1
    qemu-img snapshot -c gamma "$WORK/base.qcow2" >/dev/null 2>&1
    delete_and_compare "$name" "first(alpha)"  alpha
    delete_and_compare "$name" "middle(beta)"  beta
    delete_and_compare "$name" "last(gamma)"   gamma
}

# Fixture creators (mirroring the create matrix) ---------------------------
mk_v3_64k() {
    qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 0 64k" -c "write 1M 128k" -c "write 5M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_v3_512() {
    qemu-img create -f qcow2 -o cluster_size=512 "$WORK/base.qcow2" 4M >/dev/null 2>&1
    qemu-io -c "write 0 4k" -c "write 1M 8k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_v2() {
    qemu-img create -f qcow2 -o compat=0.10 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 0 64k" -c "write 2M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_backing() {
    qemu-img create -f qcow2 "$WORK/bk.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 0 64k" "$WORK/bk.qcow2" >/dev/null 2>&1
    qemu-img create -f qcow2 -b "$WORK/bk.qcow2" -F qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 1M 64k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_ext_l2() {
    qemu-img create -f qcow2 -o extended_l2=on,cluster_size=64k "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 0 64k" -c "write 1M 32k" "$WORK/base.qcow2" >/dev/null 2>&1
}
mk_zero() {
    qemu-img create -f qcow2 "$WORK/base.qcow2" 0 >/dev/null 2>&1
}

run_fixture "v3-64k-data"    mk_v3_64k
run_fixture "v3-512-cluster" mk_v3_512
run_fixture "v2"             mk_v2
run_fixture "backing-file"   mk_backing
run_fixture "extended-l2"    mk_ext_l2
run_fixture "zero-byte-disk" mk_zero

# --- Sole-snapshot delete: header must become (0, 0), fact 3 -------------
printf '\n=== Sole-snapshot delete: header (nb=0, offset=0) ===\n'
mk_v3_64k
qemu-img snapshot -c only "$WORK/base.qcow2" >/dev/null 2>&1
delete_and_compare "sole" "only" only
if python3 - "$WORK/A.qcow2" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
nb, off = struct.unpack_from('>IQ', d, 60)
sys.exit(0 if (nb == 0 and off == 0) else 1)
PY
then
    ok "sole: header bytes 60..72 are exactly nb=0, snapshots_offset=0"
else
    bad "sole: header bytes 60..72 not (0, 0)"
fi

# --- Duplicate names: the FIRST match in table order is deleted ----------
printf '\n=== Duplicate names: first match deleted, id-2 twin survives ===\n'
mk_v3_64k
qemu-img snapshot -c dup "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c dup "$WORK/base.qcow2" >/dev/null 2>&1
delete_and_compare "dup-name" "first-of-two" dup
remaining_id=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $1}')
remaining_tag=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $2}')
if [ "$remaining_id" = "2" ] && [ "$remaining_tag" = "dup" ]; then
    ok "dup-name: survivor is id=2 tag=dup (first match in table order deleted)"
else
    bad "dup-name: survivor wrong: id=$remaining_id tag=$remaining_tag (want id=2 tag=dup)"
fi

# --- Name-vs-ID precedence: -d matches by NAME only (fact 2) -------------
# Snapshots: id=1 name="2", id=2 name="x". `-d 2` must delete the
# one NAMED "2" (id 1), never the one with ID 2.
printf '\n=== Name-vs-ID precedence: -d 2 removes the snapshot NAMED "2" ===\n'
mk_v3_64k
qemu-img snapshot -c 2 "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c x "$WORK/base.qcow2" >/dev/null 2>&1
delete_and_compare "precedence" "-d 2" 2
survivors=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $1":"$2}')
if [ "$survivors" = "2:x" ]; then
    ok "precedence: survivor is id=2 name=x (the name-match was removed)"
else
    bad "precedence: survivors wrong: $survivors (want 2:x)"
fi

# --- Pure-ID not-found parity (fact 2: no ID matching path) --------------
# Image with snapshots alpha(id 1) and gamma(id 3): `-d 3` must fail
# with exit 1 and leave the image byte-identical, matching qemu.
printf '\n=== Pure-ID arg: -d 3 fails not-found, image untouched ===\n'
mk_v3_64k
qemu-img snapshot -c alpha "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c beta  "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c gamma "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -d beta --image-opts \
    "driver=qcow2,file.filename=$WORK/base.qcow2,file.discard=ignore" >/dev/null 2>&1
before=$(sha256sum "$WORK/base.qcow2" | awk '{print $1}')
"$INSTAR" snapshot -d 3 "$WORK/base.qcow2" >"$WORK/out" 2>&1
rc=$?
after=$(sha256sum "$WORK/base.qcow2" | awk '{print $1}')
if [ $rc -ne 0 ] && [ "$before" = "$after" ]; then
    ok "pure-ID: instar -d 3 refused (exit $rc), image byte-identical"
else
    bad "pure-ID: expected not-found refusal, got exit $rc (image changed: $([ "$before" != "$after" ] && echo yes || echo no))"
fi
qemu-img snapshot -d 3 "$WORK/base.qcow2" >/dev/null 2>&1
qrc=$?
if [ $qrc -ne 0 ]; then
    ok "pure-ID: qemu-img -d 3 also fails (exit $qrc) — parity"
else
    bad "pure-ID: qemu-img -d 3 unexpectedly succeeded"
fi

# --- Empty-name parity: qemu creates an empty-named snapshot; -d '' ------
printf '\n=== Empty -d argument matches an empty-named snapshot ===\n'
mk_v3_64k
if qemu-img snapshot -c '' "$WORK/base.qcow2" >/dev/null 2>&1; then
    delete_and_compare "empty-name" "-d ''" ""
else
    ok "empty-name: qemu-img refused creating an empty name (nothing to test)"
fi

# --- Delete-then-create reuses the freed clusters -------------------------
# Dates differ between the tools' creates, so byte-identity doesn't
# hold here; use the create matrix's modulo-date comparisons.
printf '\n=== Delete-then-create: freed clusters reused, structure equal ===\n'
mk_v3_64k
qemu-img snapshot -c alpha "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c beta  "$WORK/base.qcow2" >/dev/null 2>&1
cp "$WORK/base.qcow2" "$WORK/A.qcow2"
cp "$WORK/base.qcow2" "$WORK/B.qcow2"
size_before=$(stat -c %s "$WORK/A.qcow2")
if "$INSTAR" snapshot -d alpha "$WORK/A.qcow2" >/dev/null 2>&1 \
    && "$INSTAR" snapshot -c delta "$WORK/A.qcow2" >/dev/null 2>&1 \
    && qemu_delete_nodiscard alpha "$WORK/B.qcow2" >/dev/null 2>&1 \
    && qemu-img snapshot -c delta "$WORK/B.qcow2" >/dev/null 2>&1; then
    size_after=$(stat -c %s "$WORK/A.qcow2")
    if [ "$size_after" -le "$((size_before + 65536))" ]; then
        ok "del-create: file did not grow beyond one sector (clusters reused: $size_before -> $size_after)"
    else
        bad "del-create: file grew unexpectedly ($size_before -> $size_after)"
    fi
    assert_check_clean "del-create" "$WORK/A.qcow2"
    la=$(TZ=UTC qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | strip_date)
    lb=$(TZ=UTC qemu-img snapshot -l "$WORK/B.qcow2" 2>&1 | strip_date)
    if [ "$la" = "$lb" ]; then
        ok "del-create: snapshot -l A == B (modulo date)"
    else
        bad "del-create: snapshot -l A != B:"
        diff <(echo "$la") <(echo "$lb") | sed 's/^/      /'
    fi
    strip_re='filename|^image:|date|disk size|file length|refcount bits'
    ia=$(qemu-img info "$WORK/A.qcow2" 2>&1 | grep -v -iE "$strip_re" | strip_date)
    ib=$(qemu-img info "$WORK/B.qcow2" 2>&1 | grep -v -iE "$strip_re" | strip_date)
    if [ "$ia" = "$ib" ]; then
        ok "del-create: qemu-img info A == B (modulo date / physical size)"
    else
        bad "del-create: qemu-img info A != B:"
        diff <(echo "$ia") <(echo "$ib") | sed 's/^/      /'
    fi
else
    bad "del-create: one of the four operations failed"
fi

# --- Post-delete COPIED probe ---------------------------------------------
# Image with TWO snapshots: data at offset 0 written before s1
# (shared by active+s1+s2 -> refcount 3), data at 1M written between
# s1 and s2 (shared by active+s2 only -> refcount 2). Deleting s2
# must drop the 1M cluster 2 -> 1 with COPIED SET, and the offset-0
# cluster 3 -> 2 with COPIED still CLEAR. Then a write through the
# active layer must leave the SURVIVING snapshot (s1) intact —
# verified via qemu's own `snapshot -a` as the oracle.
printf '\n=== Post-delete COPIED probe (2 -> 1 sets the flag; survivor intact) ===\n'
rm -f "$WORK"/p.qcow2
qemu-img create -f qcow2 "$WORK/p.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write -P 0xAA 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/p.qcow2" >/dev/null 2>&1
qemu-io -c "write -P 0xBB 1M 64k" "$WORK/p.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s2 "$WORK/p.qcow2" >/dev/null 2>&1
if ! "$INSTAR" snapshot -d s2 "$WORK/p.qcow2" >/dev/null 2>"$WORK/p.err"; then
    bad "probe: instar -d s2 failed: $(cat "$WORK/p.err")"
else
    ok "probe: instar -d s2 succeeded"
    if python3 - "$WORK/p.qcow2" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
cluster_bits = struct.unpack_from('>I', d, 20)[0]
csize = 1 << cluster_bits
l1_size, l1_off = struct.unpack_from('>IQ', d, 36)
rt_off = struct.unpack_from('>Q', d, 48)[0]
rb_off = struct.unpack_from('>Q', d, rt_off)[0] & 0x00fffffffffffe00


def refcount(host_off):
    idx = host_off // csize
    return struct.unpack_from('>H', d, rb_off + 2 * idx)[0]


OFLAG_COPIED = 1 << 63
l2_off = struct.unpack_from('>Q', d, l1_off)[0] & 0x00fffffffffffe00
fails = []
# guest offset 0 -> L2 index 0; 1M -> index 16 (64k clusters).
for gidx, want_rc, want_copied, label in [
    (0, 2, False, 'offset-0 (active+s1)'),
    (16, 1, True, 'offset-1M (active only)'),
]:
    e = struct.unpack_from('>Q', d, l2_off + 8 * gidx)[0]
    host = e & 0x00fffffffffffe00
    rc = refcount(host)
    copied = bool(e & OFLAG_COPIED)
    if rc != want_rc or copied != want_copied:
        fails.append(f'{label}: rc={rc} (want {want_rc}) copied={copied} '
                     f'(want {want_copied})')
for f in fails:
    print('      ' + f)
sys.exit(1 if fails else 0)
PY
    then
        ok "probe: decoded refcounts/COPIED — 1M cluster 2->1 COPIED set, 0 cluster 3->2 clear"
    else
        bad "probe: refcount/COPIED decode mismatch (see above)"
    fi
    # Write through the active layer at both offsets. The COPIED-set
    # cluster (1M) must be written in place; the still-shared
    # cluster (0) must COW so s1 keeps 0xAA.
    qemu-io -c "write -P 0xCC 0 64k" -c "write -P 0xDD 1M 64k" "$WORK/p.qcow2" >/dev/null 2>&1
    assert_check_clean "probe(post-write)" "$WORK/p.qcow2"
    cp "$WORK/p.qcow2" "$WORK/p_apply.qcow2"
    qemu-img snapshot -a s1 "$WORK/p_apply.qcow2" >/dev/null 2>&1
    if qemu-io -c "read -P 0xAA 0 64k" "$WORK/p_apply.qcow2" >/dev/null 2>&1 \
        && qemu-io -c "read -P 0x00 1M 64k" "$WORK/p_apply.qcow2" >/dev/null 2>&1; then
        ok "probe: surviving snapshot s1 intact under qemu's own apply (0xAA at 0, zeros at 1M)"
    else
        bad "probe: surviving snapshot s1 CORRUPTED after post-delete active writes"
    fi
    if qemu-io -c "read -P 0xCC 0 64k" -c "read -P 0xDD 1M 64k" "$WORK/p.qcow2" >/dev/null 2>&1; then
        ok "probe: active layer carries the new patterns (0xCC / 0xDD)"
    else
        bad "probe: active layer patterns wrong after post-delete writes"
    fi
fi

# --- Shared-L2 surviving-snapshot COPIED refresh ---------------------------
# Regression for the phase 13 differential-fuzzer finding (soak2
# iteration 209). Two snapshots share an L2; guest writes then COW
# the ACTIVE chain onto fresh L2s, so the shared L2 belongs only to
# the two snapshots. Deleting one drops the shared data clusters
# 2 -> 1, and qemu's -1 walk writes the SURVIVING snapshot's L2
# back with COPIED set on those entries — instar must match
# byte-for-byte (delete_and_compare) AND the surviving snapshot's
# L2 must actually carry COPIED bits (so the scenario keeps
# covering the mechanism if cluster layouts drift).
printf '\n=== Shared-L2 delete: surviving snapshot L2 gains COPIED ===\n'
rm -f "$WORK"/base.qcow2
qemu-img create -f qcow2 -o cluster_size=4096 "$WORK/base.qcow2" 4M >/dev/null 2>&1
qemu-io -c "write -P 0x93 2608k 128k" "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c alpha  "$WORK/base.qcow2" >/dev/null 2>&1
qemu-img snapshot -c keeper "$WORK/base.qcow2" >/dev/null 2>&1
qemu-io -c "write -P 0x58 752k 4k" -c "write -P 0xFE 2700k 64k" "$WORK/base.qcow2" >/dev/null 2>&1
delete_and_compare "shared-l2" "delete-alpha" alpha
if python3 - "$WORK/A.qcow2" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
MASK = 0x00fffffffffffe00
COPIED = 1 << 63
nb, snap_off = struct.unpack_from('>IQ', d, 60)
pos = snap_off
copied_entries = 0
for _ in range(nb):
    pos = (pos + 7) & ~7
    l1_off, l1_size = struct.unpack_from('>QI', d, pos)
    il, nl = struct.unpack_from('>HH', d, pos + 12)
    ex = struct.unpack_from('>I', d, pos + 36)[0]
    for i in range(l1_size):
        l2 = struct.unpack_from('>Q', d, l1_off + 8 * i)[0] & MASK
        if not l2:
            continue
        for j in range(4096 // 8):
            e = struct.unpack_from('>Q', d, l2 + 8 * j)[0]
            if e & COPIED and e & MASK:
                copied_entries += 1
    pos += 40 + ex + il + nl
sys.exit(0 if copied_entries > 0 else 1)
PY
then
    ok "shared-l2: surviving snapshot's L2 carries COPIED entries (mechanism exercised)"
else
    bad "shared-l2: surviving snapshot's L2 has no COPIED entries — scenario no longer covers the refresh"
fi

printf '\n=== Delete matrix result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
