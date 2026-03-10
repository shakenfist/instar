#!/bin/bash
# Generate a QCOW2 image encrypted with LUKS (crypt_method=2).
#
# Usage:
#   ./scripts/create-qcow2-luks-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/format-coverage/
#
# Creates:
#   qcow2-luks.qcow2 - 10MB QCOW2 v3 with LUKS encryption (crypt_method=2)
#
# Requirements: qemu-img, qemu-io (with --object secret support)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"
OUTPUT="$OUTDIR/qcow2-luks.qcow2"
PASSWORD="test-passphrase"

echo "Creating LUKS-encrypted QCOW2 test image in $OUTDIR..."

# Create encrypted QCOW2 with LUKS (crypt_method=2)
# Use iter-time=10 for fast key derivation in tests
qemu-img create -f qcow2 \
    --object "secret,id=sec0,data=$PASSWORD" \
    -o encrypt.format=luks,encrypt.key-secret=sec0,encrypt.iter-time=10 \
    "$OUTPUT" 10M

# Write known data pattern: 0xAA in first 4KB, 0xBB in second 4KB
qemu-io \
    --object "secret,id=sec0,data=$PASSWORD" \
    --image-opts "driver=qcow2,encrypt.key-secret=sec0,file.driver=file,file.filename=$OUTPUT" \
    -c "write -P 0xAA 0 4096" \
    -c "write -P 0xBB 4096 4096"

echo "Created $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
echo "Password: $PASSWORD"
