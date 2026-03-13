#!/bin/bash
# Generate QCOW2 images with deep backing chains.
#
# These images test imago's chain depth limit enforcement.
# The default max_chain_depth is 16, so:
# - A chain of 16 images should succeed
# - A chain of 17 images should be rejected
#
# Usage:
#   ./scripts/create-deep-chain-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/audit/
#
# Creates:
#   qcow2-chain-depth-16-*.qcow2 (16 files, base through overlay-15)
#   qcow2-chain-depth-17-*.qcow2 (17 files, base through overlay-16)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/audit}"
mkdir -p "$OUTDIR"
OUTDIR_ABS="$(cd "$OUTDIR" && pwd)"

echo "Creating deep chain test images in $OUTDIR..."

# Create a chain of N images. The base image has known data.
# Each overlay is a QCOW2 that backs to the previous image.
create_chain() {
    local prefix="$1"
    local depth="$2"

    # Create the base image with some data
    local base="$OUTDIR_ABS/${prefix}-base.qcow2"
    qemu-img create -f qcow2 "$base" 1M >/dev/null 2>&1
    qemu-io -f qcow2 -c "write -P 0xAA 0 4096" "$base" >/dev/null 2>&1

    local prev_filename="${prefix}-base.qcow2"

    # Create overlay layers (depth-1 overlays on top of the base)
    for i in $(seq 1 $((depth - 1))); do
        local filename="${prefix}-overlay-${i}.qcow2"
        local filepath="$OUTDIR_ABS/$filename"

        qemu-img create -f qcow2 \
            -b "$prev_filename" -F qcow2 \
            "$filepath" 1M >/dev/null 2>&1

        prev_filename="$filename"
    done

    echo "Created ${depth}-level chain: $prefix (top: $prev_filename)"
}

# Chain of exactly 16 images (should succeed)
create_chain "qcow2-chain-depth-16" 16

# Chain of exactly 17 images (should be rejected)
create_chain "qcow2-chain-depth-17" 17

echo "Done."
