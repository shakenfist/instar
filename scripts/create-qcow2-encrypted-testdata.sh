#!/bin/bash
# Generate a QCOW2 image encrypted with legacy AES-128-CBC (crypt_method=1).
#
# Usage:
#   ./scripts/create-qcow2-encrypted-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/format-coverage/
#
# Creates:
#   qcow2-encrypted-aes.qcow2 - 1MB QCOW2 v2 with AES-128-CBC encryption
#
# Requirements: qemu-img, qemu-io (with --object secret support)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"
OUTPUT="$OUTDIR/qcow2-encrypted-aes.qcow2"
PASSWORD="testpass"

echo "Creating encrypted QCOW2 test image in $OUTDIR..."

# Create encrypted QCOW2 v2 image with legacy AES (crypt_method=1)
qemu-img create -f qcow2 \
    --object "secret,id=sec0,data=$PASSWORD" \
    -o encryption=on,encrypt.key-secret=sec0 \
    "$OUTPUT" 1M

# Write known data pattern: 0xAA in first 4KB, 0xBB in second 4KB
qemu-io \
    --object "secret,id=sec0,data=$PASSWORD" \
    --image-opts "driver=qcow2,encrypt.key-secret=sec0,file.driver=file,file.filename=$OUTPUT" \
    -c "write -P 0xAA 0 4096" \
    -c "write -P 0xBB 4096 4096"

echo "Created $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
echo "Password: $PASSWORD"
