#!/bin/bash
# Generate a QCOW2 image with snapshots for testing.
#
# Usage:
#   ./scripts/create-qcow2-snapshot-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/format-coverage/
#
# Creates:
#   qcow2-snapshots.qcow2 - 10MB QCOW2 with 2 internal snapshots
#
# Requirements: qemu-img, qemu-io

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"
OUTPUT="$OUTDIR/qcow2-snapshots.qcow2"

echo "Creating QCOW2 snapshot test image in $OUTDIR..."

# Create a 10MB QCOW2 image
qemu-img create -f qcow2 "$OUTPUT" 10M

# Write pattern 0xAA to first 4KB
qemu-io -f qcow2 \
    -c "write -P 0xAA 0 4096" \
    "$OUTPUT"

# Take snapshot "snap1"
qemu-img snapshot -c snap1 "$OUTPUT"

# Write pattern 0xBB to first 4KB (overwrites 0xAA in active)
qemu-io -f qcow2 \
    -c "write -P 0xBB 0 4096" \
    "$OUTPUT"

# Take snapshot "snap2"
qemu-img snapshot -c snap2 "$OUTPUT"

# Write pattern 0xCC to first 4KB (overwrites 0xBB in active)
qemu-io -f qcow2 \
    -c "write -P 0xCC 0 4096" \
    "$OUTPUT"

echo "Created $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
echo "Snapshots:"
qemu-img snapshot -l "$OUTPUT"
echo ""
echo "Active image has 0xCC at offset 0"
echo "snap2 has 0xBB at offset 0"
echo "snap1 has 0xAA at offset 0"
