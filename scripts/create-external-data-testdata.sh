#!/bin/bash
# Create QCOW2 test images with external data files.
#
# Requires: qemu-img, qemu-io
#
# These images have a separate metadata file (QCOW2 headers, L1/L2
# tables, refcounts) and a raw data file (cluster data). Used for
# testing Phase 13 external data file support.
#
# Usage: ./create-external-data-testdata.sh <output_dir>

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output_dir>" >&2
    exit 1
fi

OUTPUT_DIR="$1"
mkdir -p "$OUTPUT_DIR"

# Check for required tools
for cmd in qemu-img qemu-io; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found" >&2
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---- Image 1: qcow2-external-data-raw ----
# A 1 GiB virtual QCOW2 with data_file_raw=on and an MBR partition
# table written to the first cluster. The data file can be used as a
# standalone raw disk image.
echo "Creating qcow2-external-data-raw..."

DATA_FILE="$TMPDIR/qcow2-external-data-raw.raw"
META_FILE="$TMPDIR/qcow2-external-data-raw.qcow2"

qemu-img create -f qcow2 \
    -o data_file="$DATA_FILE",data_file_raw=on \
    "$META_FILE" 1G >/dev/null 2>&1

# Write an MBR signature so the data file looks like a partitioned disk.
# Byte 510-511 = 0x55AA (MBR boot signature).
qemu-io -c 'write -P 0x00 0 512' "$META_FILE" >/dev/null 2>&1
qemu-io -c 'write -P 0x55 510 1' "$META_FILE" >/dev/null 2>&1
qemu-io -c 'write -P 0xAA 511 1' "$META_FILE" >/dev/null 2>&1

# Write some recognizable data at offset 1 MiB (proves data reads work)
qemu-io -c 'write -P 0xCD 1048576 65536' "$META_FILE" >/dev/null 2>&1

# Verify no errors
echo -n "  Verifying... "
qemu-img check "$META_FILE" >/dev/null 2>&1
echo "OK"

# The data_file path in the QCOW2 header is absolute (from creation).
# We need to fix it to be a relative path for portability. Create a
# fresh copy with a relative path.
FINAL_DATA="$OUTPUT_DIR/qcow2-external-data-raw.raw"
FINAL_META="$OUTPUT_DIR/qcow2-external-data-raw.qcow2"

# Copy data file first
cp "$DATA_FILE" "$FINAL_DATA"

# Recreate metadata with relative data_file path
qemu-img create -f qcow2 \
    -o data_file=qcow2-external-data-raw.raw,data_file_raw=on \
    "$FINAL_META" 1G >/dev/null 2>&1

# Write the same data patterns into the new image
qemu-io -c 'write -P 0x00 0 512' "$FINAL_META" >/dev/null 2>&1
qemu-io -c 'write -P 0x55 510 1' "$FINAL_META" >/dev/null 2>&1
qemu-io -c 'write -P 0xAA 511 1' "$FINAL_META" >/dev/null 2>&1
qemu-io -c 'write -P 0xCD 1048576 65536' "$FINAL_META" >/dev/null 2>&1

echo "  Created: $FINAL_META ($(stat -c%s "$FINAL_META") bytes)"
echo "  Data file: $FINAL_DATA ($(stat -c%s "$FINAL_DATA") bytes)"

echo ""
echo "All external data test images created in $OUTPUT_DIR"
