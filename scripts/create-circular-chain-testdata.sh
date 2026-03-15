#!/bin/bash
# Generate QCOW2 images with circular backing file references.
#
# These images test that imago's circular reference detection
# (seen_paths in chain.rs) correctly identifies and rejects cycles
# without looping forever.
#
# Usage:
#   ./scripts/create-circular-chain-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/audit/
#
# Creates:
#   qcow2-circular-a.qcow2       - Part of A->B->A cycle
#   qcow2-circular-b.qcow2       - Part of A->B->A cycle
#   qcow2-circular-3a.qcow2      - Part of A->B->C->A cycle
#   qcow2-circular-3b.qcow2      - Part of A->B->C->A cycle
#   qcow2-circular-3c.qcow2      - Part of A->B->C->A cycle
#   qcow2-self-referencing.qcow2  - A->A (self-referencing)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/audit}"
mkdir -p "$OUTDIR"
# Resolve to absolute for cd later
OUTDIR_ABS="$(cd "$OUTDIR" && pwd)"

echo "Creating circular chain test images in $OUTDIR..."

# Helper: create a minimal QCOW2 with a specific backing file path.
# Uses just the filename (not a full path) so backing references are
# relative to the image's own directory.
create_with_backing() {
    local filename="$1"
    local backing_filename="$2"
    local tmpbase
    tmpbase=$(mktemp /tmp/circ-base-XXXXXX.qcow2)

    # Create a base image
    qemu-img create -f qcow2 "$tmpbase" 1M >/dev/null 2>&1

    # Create overlay pointing to the temp base
    qemu-img create -f qcow2 -b "$tmpbase" -F qcow2 \
        "$OUTDIR_ABS/$filename" 1M >/dev/null 2>&1

    # Rebase to use just the filename (relative to image directory)
    qemu-img rebase -f qcow2 -u -b "$backing_filename" -F qcow2 \
        "$OUTDIR_ABS/$filename"

    rm -f "$tmpbase"
}

# --- 2-level cycle: A -> B -> A ---
create_with_backing "qcow2-circular-b.qcow2" "qcow2-circular-a.qcow2"
create_with_backing "qcow2-circular-a.qcow2" "qcow2-circular-b.qcow2"
echo "Created 2-level cycle: A -> B -> A"

# --- 3-level cycle: A -> B -> C -> A ---
create_with_backing "qcow2-circular-3c.qcow2" "qcow2-circular-3a.qcow2"
create_with_backing "qcow2-circular-3b.qcow2" "qcow2-circular-3c.qcow2"
create_with_backing "qcow2-circular-3a.qcow2" "qcow2-circular-3b.qcow2"
echo "Created 3-level cycle: A -> B -> C -> A"

# --- Self-referencing: A -> A ---
# Use Python for this since qemu-img won't create an image backing itself
python3 -c "
import struct, os

outpath = os.path.join('$OUTDIR_ABS', 'qcow2-self-referencing.qcow2')
backing_name = b'qcow2-self-referencing.qcow2'

magic = b'QFI\xfb'
header = struct.pack('>4sI Q II Q I I Q Q I I Q',
    magic, 2,           # version 2
    72,                  # backing_file_offset (right after header)
    len(backing_name),   # backing_file_size
    16,                  # cluster_bits (64KB)
    1 * 1024 * 1024,    # size (1MB)
    0,                   # crypt_method
    1,                   # l1_size
    65536,               # l1_table_offset
    2 * 65536,           # refcount_table_offset
    1,                   # refcount_table_clusters
    0,                   # nb_snapshots
    0,                   # snapshots_offset
)

with open(outpath, 'wb') as f:
    f.write(header[:72])
    f.write(backing_name)
    pos = 72 + len(backing_name)
    f.write(b'\x00' * (65536 - pos))
    f.write(b'\x00' * 65536)   # L1 table
    f.write(b'\x00' * 65536)   # Refcount table

print(f'Created {outpath} ({os.path.getsize(outpath)} bytes)')
"
echo "Created self-referencing: A -> A"

echo "Done."
