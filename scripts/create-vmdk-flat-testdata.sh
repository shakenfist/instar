#!/bin/bash
# Generate VMDK monolithicFlat test fixtures for instar integration tests.
#
# Usage:
#   ./scripts/create-vmdk-flat-testdata.sh [output-dir]
#
# Default output: ../instar-testdata/custom/format-coverage/
#
# Creates a trio of qemu-img-generated monolithicFlat pairs
# (descriptor + flat extent) at small sizes, plus a
# parentFileNameHint variant that should be rejected by the
# VMM, and a twoGbMaxExtentFlat multi-extent variant that
# should also be rejected.

set -euo pipefail

OUTDIR="${1:-../instar-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"

echo "Creating VMDK monolithicFlat test images in $OUTDIR..."

# --- monolithicFlat, small (1 MiB) ---
# Canonical happy-path descriptor + flat extent pair.
rm -f "$OUTDIR/vmdk-flat-1m.vmdk" "$OUTDIR/vmdk-flat-1m-flat.vmdk"
qemu-img create -f vmdk -o subformat=monolithicFlat \
    "$OUTDIR/vmdk-flat-1m.vmdk" 1M

# --- monolithicFlat, 10 MiB with deterministic content ---
# Larger size with known content for cross-validation tests.
rm -f "$OUTDIR/vmdk-flat-10m.vmdk" "$OUTDIR/vmdk-flat-10m-flat.vmdk"
qemu-img create -f vmdk -o subformat=monolithicFlat \
    "$OUTDIR/vmdk-flat-10m.vmdk" 10M
# Seed the flat extent with a deterministic pattern so
# convert/compare tests can assert byte equality.
python3 -c '
import sys
pattern = bytes(range(256)) * (10 * 1024 * 1024 // 256)
with open(sys.argv[1], "wb") as f:
    f.write(pattern)
' "$OUTDIR/vmdk-flat-10m-flat.vmdk"

# --- monolithicFlat with parentFileNameHint (must be rejected) ---
# Hand-built: qemu-img won't emit parentFileNameHint for a
# flat subformat, so we synthesise the descriptor by hand.
cat > "$OUTDIR/vmdk-flat-with-parent.vmdk" <<'EOF'
# Disk DescriptorFile
version=1
CID=deadbeef
parentCID=cafefeed
createType="monolithicFlat"
parentFileNameHint="vmdk-flat-parent.vmdk"

# Extent description
RW 2048 FLAT "vmdk-flat-with-parent-flat.vmdk" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = "4"
ddb.geometry.cylinders = "2"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
EOF
dd if=/dev/zero of="$OUTDIR/vmdk-flat-with-parent-flat.vmdk" \
    bs=512 count=2048 status=none

# --- twoGbMaxExtentFlat multi-extent (descriptor-only reference) ---
# A 3 GiB input forces qemu-img to split into two extents.
# We keep only the descriptor file for reference (the real
# multi-extent test uses the hand-built small fixture below).
rm -f "$OUTDIR/vmdk-twogb-flat.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f001.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f002.vmdk"
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat \
    "$OUTDIR/vmdk-twogb-flat.vmdk" 3G
rm -f "$OUTDIR/vmdk-twogb-flat-f001.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f002.vmdk"

# --- Small multi-extent flat (3 × 512 KiB = 1.5 MiB total) ---
# Hand-built descriptor with three FLAT extents and small flat
# files, suitable for integration testing without shipping GiBs
# of flat data. Each flat file gets a distinct fill pattern so
# convert/compare can verify correct extent stitching.
cat > "$OUTDIR/vmdk-multi-flat.vmdk" <<'EOF'
# Disk DescriptorFile
version=1
CID=aabbccdd
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 1024 FLAT "vmdk-multi-flat-f001.vmdk" 0
RW 1024 FLAT "vmdk-multi-flat-f002.vmdk" 0
RW 1024 FLAT "vmdk-multi-flat-f003.vmdk" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = "4"
ddb.adapterType = "ide"
EOF

# 1024 sectors × 512 bytes = 512 KiB each
python3 -c '
import sys
# Extent 1: fill with 0xAA
with open(sys.argv[1] + "/vmdk-multi-flat-f001.vmdk", "wb") as f:
    f.write(b"\xAA" * (1024 * 512))
# Extent 2: fill with 0xBB
with open(sys.argv[1] + "/vmdk-multi-flat-f002.vmdk", "wb") as f:
    f.write(b"\xBB" * (1024 * 512))
# Extent 3: fill with 0xCC
with open(sys.argv[1] + "/vmdk-multi-flat-f003.vmdk", "wb") as f:
    f.write(b"\xCC" * (1024 * 512))
' "$OUTDIR"

echo "Done."
ls -la "$OUTDIR"/vmdk-flat-* "$OUTDIR"/vmdk-twogb-flat* "$OUTDIR"/vmdk-multi-flat*
