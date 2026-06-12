#!/usr/bin/env bash
# Phase 6f verification matrix for `instar snapshot -c` against
# qemu-img 10.0.8. For each fixture, run instar -c on copy A and
# qemu-img -c on copy B, then assert qemu-img check is clean on A
# and the snapshot listings / info match modulo the date columns.
#
# Not a committed test (phase 11 owns that) — this is the phase 6
# validation harness. Exits non-zero on any failure.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

note() { printf '  %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

# Strip the volatile DATE column from `qemu-img snapshot -l` output
# so instar/qemu listings can be compared structurally.
strip_date() {
    # qemu-img -l columns: ID TAG VM_SIZE DATE(2 fields) VM_CLOCK ICOUNT
    # Replace the date (yyyy-mm-dd hh:mm:ss) with a placeholder.
    sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<DATE>/g'
}

# Strip date-ish lines from `qemu-img info` snapshot section.
strip_info_dates() {
    sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<DATE>/g'
}

run_fixture() {
    local name="$1"; shift
    local create_cmd="$1"; shift   # function that creates $WORK/base.qcow2
    printf '\n=== Fixture: %s ===\n' "$name"
    rm -f "$WORK"/base.qcow2 "$WORK"/A.qcow2 "$WORK"/B.qcow2
    eval "$create_cmd"
    cp "$WORK/base.qcow2" "$WORK/A.qcow2"
    cp "$WORK/base.qcow2" "$WORK/B.qcow2"

    if ! "$INSTAR" snapshot -c snap1 "$WORK/A.qcow2" >/dev/null 2>"$WORK/a.err"; then
        bad "$name: instar snapshot -c failed: $(cat "$WORK/a.err")"
        return
    fi
    if ! qemu-img snapshot -c snap1 "$WORK/B.qcow2" >/dev/null 2>&1; then
        bad "$name: qemu-img snapshot -c failed (unexpected)"
        return
    fi

    # (1) qemu-img check clean on A: zero errors AND zero leaks.
    # qemu-img check exits 0 only when the image is fully consistent
    # (no errors, no leaks); a non-zero exit flags either. The
    # "No errors were found" success line contains the word "errors",
    # so we rely on the exit code, not a text grep.
    if qemu-img check "$WORK/A.qcow2" >"$WORK/chk.out" 2>&1 \
        && ! grep -qiE "Leaked|leaked clusters" "$WORK/chk.out"; then
        ok "$name: qemu-img check A clean (no errors, no leaks)"
    else
        bad "$name: qemu-img check on A not clean:"
        sed 's/^/      /' "$WORK/chk.out"
    fi

    # (2) qemu-img snapshot -l A vs B identical modulo DATE.
    local la lb
    la=$(TZ=UTC qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | strip_date)
    lb=$(TZ=UTC qemu-img snapshot -l "$WORK/B.qcow2" 2>&1 | strip_date)
    if [ "$la" = "$lb" ]; then
        ok "$name: snapshot -l A == B (modulo date)"
    else
        bad "$name: snapshot -l A != B:"
        diff <(echo "$la") <(echo "$lb") | sed 's/^/      /'
    fi

    # (3) qemu-img info A vs B identical modulo date and the
    # physical-size fields. instar writes through 64 KiB virtio
    # sectors, so the final table write rounds the file up to a
    # sector boundary; qemu writes at byte granularity. The result
    # is a benign trailing-sparseness difference in "disk size" /
    # "file length" (check stays clean; structure is identical). We
    # compare everything else structurally and exclude the filename /
    # date / physical-size lines.
    local strip_re='filename|^image:|date|disk size|file length|refcount bits'
    local ia ib
    ia=$(qemu-img info "$WORK/A.qcow2" 2>&1 | grep -v -iE "$strip_re" | strip_info_dates)
    ib=$(qemu-img info "$WORK/B.qcow2" 2>&1 | grep -v -iE "$strip_re" | strip_info_dates)
    if [ "$ia" = "$ib" ]; then
        ok "$name: qemu-img info A == B (modulo date / physical size)"
    else
        bad "$name: qemu-img info A != B:"
        diff <(echo "$ia") <(echo "$ib") | sed 's/^/      /'
    fi

    # (4) instar snapshot -l A byte-identical to qemu-img snapshot -l A.
    local ila qla
    ila=$(TZ=UTC "$INSTAR" snapshot -l "$WORK/A.qcow2" 2>&1)
    qla=$(TZ=UTC qemu-img snapshot -l "$WORK/A.qcow2" 2>&1)
    if [ "$ila" = "$qla" ]; then
        ok "$name: instar -l A == qemu-img -l A (byte-identical)"
    else
        bad "$name: instar -l A != qemu-img -l A:"
        diff <(echo "$ila") <(echo "$qla") | sed 's/^/      /'
    fi

    # (5) second create: duplicate name accepted, ID = max+1.
    # Capture the highest ID before the second create.
    local id_before
    id_before=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $1}' | sort -n | tail -1)
    "$INSTAR" snapshot -c snap1 "$WORK/A.qcow2" >/dev/null 2>"$WORK/a2.err"
    local rc=$?
    if [ $rc -ne 0 ]; then
        bad "$name: second instar -c (dup name) failed: $(cat "$WORK/a2.err")"
    else
        # Last two entries must both be tagged snap1, and the new ID
        # must be id_before + 1.
        local last_id last_tag prev_tag
        last_id=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $1}' | tail -1)
        last_tag=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $2}' | tail -1)
        prev_tag=$(qemu-img snapshot -l "$WORK/A.qcow2" 2>&1 | awk 'NR>2 {print $2}' | tail -2 | head -1)
        local want_id=$((id_before + 1))
        if [ "$last_id" = "$want_id" ] && [ "$last_tag" = "snap1" ] && [ "$prev_tag" = "snap1" ]; then
            ok "$name: dup create -> new ID $last_id, both tagged snap1 (dup allowed)"
        else
            bad "$name: dup-name wrong: last_id=$last_id (want $want_id) last_tag=$last_tag prev_tag=$prev_tag"
        fi
        # check must remain clean after the dup create.
        if qemu-img check "$WORK/A.qcow2" >"$WORK/chk2.out" 2>&1 \
            && ! grep -qiE "Leaked|leaked clusters" "$WORK/chk2.out"; then
            ok "$name: qemu-img check clean after dup create"
        else
            bad "$name: check not clean after dup create:"
            sed 's/^/      /' "$WORK/chk2.out"
        fi
    fi
}

# --- (6) Post-snapshot-write corruption probe ----------------------------
# THE test that catches the L2-table refcount gap (open question 2):
# create a snapshot with instar, then have qemu write new data
# through the active L1. Without the L2-table refcount bump, qemu's
# post-snapshot write would skip the L2 COW and corrupt the
# snapshot. We assert check stays clean and the snapshot's data is
# still the pre-write content.
post_write_probe() {
    printf '\n=== Probe (6): post-snapshot-write does not corrupt the snapshot ===\n'
    rm -f "$WORK"/p.qcow2
    qemu-img create -f qcow2 "$WORK/p.qcow2" 64M >/dev/null 2>&1
    # Write a known pattern into the cluster at guest offset 0.
    qemu-io -c "write -P 0xAA 0 64k" -c "write -P 0xBB 1M 64k" "$WORK/p.qcow2" >/dev/null 2>&1
    # instar snapshot.
    if ! "$INSTAR" snapshot -c snap1 "$WORK/p.qcow2" >/dev/null 2>"$WORK/p.err"; then
        bad "probe: instar snapshot -c failed: $(cat "$WORK/p.err")"
        return
    fi
    # qemu overwrites the active data at offset 0 with a NEW pattern.
    # This forces a COW: the snapshot must keep 0xAA, the active gets 0xCC.
    qemu-io -c "write -P 0xCC 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1
    # check must stay clean (exit 0, no leaks).
    if qemu-img check "$WORK/p.qcow2" >"$WORK/pchk.out" 2>&1 \
        && ! grep -qiE "Leaked|leaked clusters" "$WORK/pchk.out"; then
        ok "probe: qemu-img check clean after post-snapshot write"
    else
        bad "probe: qemu-img check after post-snapshot write not clean:"
        sed 's/^/      /' "$WORK/pchk.out"
    fi
    # The snapshot's data at offset 0 must still read 0xAA (not 0xCC).
    # Apply the snapshot into a copy and read it back.
    cp "$WORK/p.qcow2" "$WORK/p_snap.qcow2"
    qemu-img snapshot -a snap1 "$WORK/p_snap.qcow2" >/dev/null 2>&1
    if qemu-io -c "read -P 0xAA 0 64k" "$WORK/p_snap.qcow2" >/dev/null 2>&1; then
        ok "probe: snapshot data at offset 0 preserved (0xAA) after active write"
    else
        bad "probe: snapshot data CORRUPTED — offset 0 not 0xAA after active write"
        qemu-io -c "read 0 16" "$WORK/p_snap.qcow2" 2>&1 | sed 's/^/      /'
    fi
    # And the active image now reads 0xCC at offset 0.
    if qemu-io -c "read -P 0xCC 0 64k" "$WORK/p.qcow2" >/dev/null 2>&1; then
        ok "probe: active data at offset 0 is the new pattern (0xCC)"
    else
        bad "probe: active data at offset 0 wrong (expected 0xCC)"
    fi
}

# Fixture creators -------------------------------------------------------
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
mk_has_snapshot() {
    qemu-img create -f qcow2 "$WORK/base.qcow2" 64M >/dev/null 2>&1
    qemu-io -c "write 0 64k" "$WORK/base.qcow2" >/dev/null 2>&1
    qemu-img snapshot -c existing "$WORK/base.qcow2" >/dev/null 2>&1
}

run_fixture "v3-64k-data"      mk_v3_64k
run_fixture "v3-512-cluster"   mk_v3_512
run_fixture "v2"               mk_v2
run_fixture "backing-file"     mk_backing
run_fixture "extended-l2"      mk_ext_l2
run_fixture "zero-byte-disk"   mk_zero
run_fixture "has-one-snapshot" mk_has_snapshot
post_write_probe

printf '\n=== Matrix result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
