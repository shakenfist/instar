#!/usr/bin/env bash
# Phase 6f refusal-path checks for `instar snapshot -c`. Each case
# must fail (non-zero exit) with a sensible message; the image must
# not be mutated. Not a committed test — phase 6 validation only.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

# Assert instar refuses (non-zero exit) and the image is unchanged.
refuse() {
    local name="$1" img="$2"; shift 2
    local before after
    before=$(sha256sum "$img" 2>/dev/null | awk '{print $1}')
    "$INSTAR" snapshot -c snap1 "$@" "$img" >"$WORK/out" 2>&1
    local rc=$?
    after=$(sha256sum "$img" 2>/dev/null | awk '{print $1}')
    if [ $rc -ne 0 ]; then
        if [ "$before" = "$after" ]; then
            ok "$name: refused (exit $rc), image unchanged"
            printf '        msg: %s\n' "$(tail -1 "$WORK/out")"
        else
            bad "$name: refused but image was MUTATED"
        fi
    else
        bad "$name: expected refusal but exit 0"
    fi
}

# zstd compression (compression_type=1).
qemu-img create -f qcow2 -o compression_type=zstd "$WORK/zstd.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/zstd.qcow2" >/dev/null 2>&1
refuse "zstd-compression" "$WORK/zstd.qcow2"

# Compressed clusters (zlib; no header bit — detected in the L2 walk).
qemu-img create -f qcow2 "$WORK/raw_src.raw" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x11 0 1M" "$WORK/raw_src.raw" >/dev/null 2>&1
qemu-img convert -O qcow2 -c "$WORK/raw_src.raw" "$WORK/zlib.qcow2" >/dev/null 2>&1
refuse "zlib-compressed-clusters" "$WORK/zlib.qcow2"

# LUKS encryption.
if printf 'secret123' | qemu-img create -f qcow2 -o encrypt.format=luks,encrypt.key-secret=sec \
    --object secret,id=sec,data=secret123 "$WORK/luks.qcow2" 64M >/dev/null 2>&1; then
    refuse "luks-encryption" "$WORK/luks.qcow2"
else
    # Fallback: hand-set crypt_method in a plain image's header.
    qemu-img create -f qcow2 "$WORK/enc.qcow2" 64M >/dev/null 2>&1
    python3 - "$WORK/enc.qcow2" <<'PY'
import sys, struct
p=sys.argv[1]; d=bytearray(open(p,'rb').read())
struct.pack_into('>I', d, 32, 1)  # crypt_method = 1 (AES)
open(p,'wb').write(d)
PY
    refuse "encryption (hand-set crypt_method)" "$WORK/enc.qcow2"
fi

# External data file.
qemu-img create -f qcow2 -o data_file="$WORK/ext.data",data_file_raw=on \
    "$WORK/ext.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/ext.qcow2" >/dev/null 2>&1
refuse "external-data-file" "$WORK/ext.qcow2"

# Dirty image (hand-flip incompatible_features bit 0).
qemu-img create -f qcow2 "$WORK/dirty.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/dirty.qcow2" >/dev/null 2>&1
python3 - "$WORK/dirty.qcow2" <<'PY'
import sys, struct
p=sys.argv[1]; d=bytearray(open(p,'rb').read())
incompat=struct.unpack_from('>Q', d, 72)[0]
struct.pack_into('>Q', d, 72, incompat | 0x1)  # INCOMPAT_DIRTY
open(p,'wb').write(d)
PY
refuse "dirty-image" "$WORK/dirty.qcow2"

# Non-qcow2 input (raw).
qemu-img create -f raw "$WORK/plain.raw" 64M >/dev/null 2>&1
refuse "non-qcow2-raw" "$WORK/plain.raw"

# >255-char name (host-side rejection, before the guest runs).
qemu-img create -f qcow2 "$WORK/longname.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/longname.qcow2" >/dev/null 2>&1
LONG=$(python3 -c "print('a'*256)")
before=$(sha256sum "$WORK/longname.qcow2" | awk '{print $1}')
"$INSTAR" snapshot -c "$LONG" "$WORK/longname.qcow2" >"$WORK/out" 2>&1
rc=$?
after=$(sha256sum "$WORK/longname.qcow2" | awk '{print $1}')
if [ $rc -ne 0 ] && [ "$before" = "$after" ]; then
    ok ">255-char-name: refused (exit $rc), image unchanged"
    printf '        msg: %s\n' "$(tail -1 "$WORK/out")"
else
    bad ">255-char-name: expected refusal, got exit $rc"
fi

# Empty name (host-side rejection).
before=$(sha256sum "$WORK/longname.qcow2" | awk '{print $1}')
"$INSTAR" snapshot -c "" "$WORK/longname.qcow2" >"$WORK/out" 2>&1
rc=$?
after=$(sha256sum "$WORK/longname.qcow2" | awk '{print $1}')
if [ $rc -ne 0 ] && [ "$before" = "$after" ]; then
    ok "empty-name: refused (exit $rc)"
    printf '        msg: %s\n' "$(tail -1 "$WORK/out")"
else
    bad "empty-name: expected refusal, got exit $rc"
fi

# 16-snapshot cap. Create 16 snapshots with qemu-img, then instar -c
# must refuse the 17th with ERROR_SNAPSHOT_TABLE_FULL.
qemu-img create -f qcow2 "$WORK/cap.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/cap.qcow2" >/dev/null 2>&1
for i in $(seq 1 16); do
    qemu-img snapshot -c "s$i" "$WORK/cap.qcow2" >/dev/null 2>&1
done
before=$(sha256sum "$WORK/cap.qcow2" | awk '{print $1}')
"$INSTAR" snapshot -c s17 "$WORK/cap.qcow2" >"$WORK/out" 2>&1
rc=$?
after=$(sha256sum "$WORK/cap.qcow2" | awk '{print $1}')
if [ $rc -ne 0 ] && [ "$before" = "$after" ]; then
    ok "16-snapshot-cap: 17th refused (exit $rc), image unchanged"
    printf '        msg: %s\n' "$(tail -1 "$WORK/out")"
else
    bad "16-snapshot-cap: expected refusal, got exit $rc"
fi

printf '\n=== Refusal result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
