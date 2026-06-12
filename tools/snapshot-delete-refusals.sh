#!/usr/bin/env bash
# Phase 7e refusal-path checks for `instar snapshot -d`, a sibling
# of tools/snapshot-create-refusals.sh. Each case must fail
# (non-zero exit) with a sensible message and leave the image
# bit-for-bit untouched. Not a committed test — phase 7 validation
# only.
set -uo pipefail

INSTAR="${INSTAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/target/release/instar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

# Assert instar -d refuses (non-zero exit) and the image is
# unchanged. $1 = case name, $2 = image, $3 = snapshot arg.
refuse() {
    local name="$1" img="$2" arg="$3"
    local before after
    before=$(sha256sum "$img" 2>/dev/null | awk '{print $1}')
    "$INSTAR" snapshot -d "$arg" "$img" >"$WORK/out" 2>&1
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

# Not-found by name on a snapshot-bearing image.
qemu-img create -f qcow2 "$WORK/nf.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/nf.qcow2" >/dev/null 2>&1
qemu-img snapshot -c alpha "$WORK/nf.qcow2" >/dev/null 2>&1
refuse "not-found-by-name" "$WORK/nf.qcow2" "nosuch"

# Not-found by pure ID (fact 2: -d has no ID matching path).
refuse "not-found-by-id" "$WORK/nf.qcow2" "1"

# Delete on a 0-snapshot image.
qemu-img create -f qcow2 "$WORK/none.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/none.qcow2" >/dev/null 2>&1
refuse "zero-snapshot-image" "$WORK/none.qcow2" "alpha"

# zstd compression (compression_type=1), with a snapshot to target.
qemu-img create -f qcow2 -o compression_type=zstd "$WORK/zstd.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/zstd.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/zstd.qcow2" >/dev/null 2>&1
refuse "zstd-compression" "$WORK/zstd.qcow2" "s1"

# Compressed clusters (zlib; no header bit — detected in the L2
# walk of both staged chains).
qemu-img create -f qcow2 "$WORK/raw_src.raw" 64M >/dev/null 2>&1
qemu-io -c "write -P 0x11 0 1M" "$WORK/raw_src.raw" >/dev/null 2>&1
qemu-img convert -O qcow2 -c "$WORK/raw_src.raw" "$WORK/zlib.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/zlib.qcow2" >/dev/null 2>&1
refuse "zlib-compressed-clusters" "$WORK/zlib.qcow2" "s1"

# LUKS encryption (hand-set crypt_method on a snapshot-bearing
# image so the gate, not key handling, is what trips).
qemu-img create -f qcow2 "$WORK/enc.qcow2" 64M >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/enc.qcow2" >/dev/null 2>&1
python3 - "$WORK/enc.qcow2" <<'PY'
import sys, struct
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
struct.pack_into('>I', d, 32, 1)  # crypt_method = 1 (AES)
open(p, 'wb').write(d)
PY
refuse "encryption (hand-set crypt_method)" "$WORK/enc.qcow2" "s1"

# External data file (qemu refuses internal snapshots on these too,
# so the image carries no snapshot; the gate must fire regardless).
qemu-img create -f qcow2 -o data_file="$WORK/ext.data",data_file_raw=on \
    "$WORK/ext.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/ext.qcow2" >/dev/null 2>&1
refuse "external-data-file" "$WORK/ext.qcow2" "s1"

# Dirty image (hand-flip incompatible_features bit 0) with a
# snapshot present.
qemu-img create -f qcow2 "$WORK/dirty.qcow2" 64M >/dev/null 2>&1
qemu-io -c "write 0 64k" "$WORK/dirty.qcow2" >/dev/null 2>&1
qemu-img snapshot -c s1 "$WORK/dirty.qcow2" >/dev/null 2>&1
python3 - "$WORK/dirty.qcow2" <<'PY'
import sys, struct
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
incompat = struct.unpack_from('>Q', d, 72)[0]
struct.pack_into('>Q', d, 72, incompat | 0x1)  # INCOMPAT_DIRTY
open(p, 'wb').write(d)
PY
refuse "dirty-image" "$WORK/dirty.qcow2" "s1"

# Non-qcow2 input (raw).
qemu-img create -f raw "$WORK/plain.raw" 64M >/dev/null 2>&1
refuse "non-qcow2-raw" "$WORK/plain.raw" "s1"

printf '\n=== Delete refusal result: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
