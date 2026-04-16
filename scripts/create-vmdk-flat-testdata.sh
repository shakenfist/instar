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

# --- twoGbMaxExtentFlat multi-extent (must be rejected) ---
# A 3 GiB input forces qemu-img to split into two extents
# because each twoGbMaxExtent* subformat caps an extent at 2 GiB.
# We keep only the descriptor file in testdata: the VMM's
# descriptor resolver rejects multi-extent descriptors before
# touching the individual flat files, so the fixtures don't
# need them and shipping 3 GiB of flat extents to the
# testdata repo would be wasteful.
rm -f "$OUTDIR/vmdk-twogb-flat.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f001.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f002.vmdk"
qemu-img create -f vmdk -o subformat=twoGbMaxExtentFlat \
    "$OUTDIR/vmdk-twogb-flat.vmdk" 3G
rm -f "$OUTDIR/vmdk-twogb-flat-f001.vmdk" \
      "$OUTDIR/vmdk-twogb-flat-f002.vmdk"

echo "Done."
ls -la "$OUTDIR"/vmdk-flat-* "$OUTDIR"/vmdk-twogb-flat*
