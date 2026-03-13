#!/bin/bash
# Generate QCOW2 compression bomb test images.
#
# These images contain compressed clusters with highly compressible data
# (all zeros) that achieve extreme expansion ratios. They test that imago's
# decompression buffer limits are enforced correctly.
#
# Usage:
#   ./scripts/create-compression-bomb-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/audit/
#
# Creates:
#   qcow2-compression-bomb-zlib.qcow2  - zlib-compressed bomb (v2)
#   qcow2-compression-bomb-zstd.qcow2  - zstd-compressed bomb (v3)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/audit}"
mkdir -p "$OUTDIR"

echo "Creating compression bomb test images in $OUTDIR..."

# Create a raw image with all zeros (highly compressible).
# Use 64MB virtual size — after compression this will be tiny on disk,
# but decompression should expand each cluster to full size.
RAW_TMP=$(mktemp /tmp/bomb-raw-XXXXXX.raw)
trap 'rm -f "$RAW_TMP"' EXIT

# Write 64MB of zeros
dd if=/dev/zero of="$RAW_TMP" bs=1M count=64 status=none

# Create zlib-compressed QCOW2 v2 (default compression)
OUTPUT_ZLIB="$OUTDIR/qcow2-compression-bomb-zlib.qcow2"
qemu-img convert -f raw -O qcow2 -c "$RAW_TMP" "$OUTPUT_ZLIB"
echo "Created $OUTPUT_ZLIB ($(wc -c < "$OUTPUT_ZLIB") bytes)"

# Create zstd-compressed QCOW2 v3
OUTPUT_ZSTD="$OUTDIR/qcow2-compression-bomb-zstd.qcow2"
qemu-img convert -f raw -O qcow2 -c \
    -o compat=1.1,compression_type=zstd \
    "$RAW_TMP" "$OUTPUT_ZSTD"
echo "Created $OUTPUT_ZSTD ($(wc -c < "$OUTPUT_ZSTD") bytes)"

echo "Done. Both images have 64MB virtual size with maximum compression."
