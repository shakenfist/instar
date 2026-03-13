#!/bin/bash
# Generate QCOW2 images with integer overflow and boundary value fields.
#
# These images test that imago's header validation catches extreme values
# without crashing or triggering undefined behavior.
#
# Usage:
#   ./scripts/create-overflow-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/audit/
#
# Creates:
#   qcow2-l1-overflow.qcow2     - l1_size near u32::MAX
#   qcow2-l1-zero.qcow2         - l1_size = 0
#   qcow2-cluster-bits-low.qcow2  - cluster_bits = 8 (below min 9)
#   qcow2-cluster-bits-high.qcow2 - cluster_bits = 22 (above max 21)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/audit}"
mkdir -p "$OUTDIR"

echo "Creating integer overflow test images in $OUTDIR..."

python3 -c "
import struct
import os

outdir = '$OUTDIR'

def write_qcow2(filename, cluster_bits=16, l1_size=1, virtual_size=1*1024*1024):
    \"\"\"Write a minimal QCOW2 v2 header with specified field values.\"\"\"
    outpath = os.path.join(outdir, filename)
    magic = b'QFI\xfb'
    version = 2
    backing_file_offset = 0
    backing_file_size = 0
    crypt_method = 0

    # Place L1 table at cluster 1, refcount table at cluster 2
    cluster_size = 1 << cluster_bits if cluster_bits < 32 else 65536
    l1_table_offset = cluster_size
    refcount_table_offset = 2 * cluster_size
    refcount_table_clusters = 1
    nb_snapshots = 0
    snapshots_offset = 0

    header = struct.pack('>4sI Q II Q I I Q Q I I Q Q',
        magic, version,
        backing_file_offset, backing_file_size,
        cluster_bits,
        virtual_size,
        crypt_method,
        l1_size,
        l1_table_offset,
        refcount_table_offset,
        refcount_table_clusters,
        nb_snapshots,
        snapshots_offset,
        0,  # padding
    )

    with open(outpath, 'wb') as f:
        f.write(header[:72])
        # Pad to at least 3 clusters to have valid-ish structure
        f.write(b'\x00' * (3 * cluster_size - 72))

    print(f'Created {outpath} ({os.path.getsize(outpath)} bytes)')

# 1. L1 table size near u32::MAX — should trigger overflow checks
#    in checked_add/saturating_mul when computing L1 table byte size
write_qcow2('qcow2-l1-overflow.qcow2', cluster_bits=16, l1_size=0x7FFFFFFF)

# 2. L1 table size = 0 — degenerate case, no L1 entries
write_qcow2('qcow2-l1-zero.qcow2', cluster_bits=16, l1_size=0)

# 3. cluster_bits = 8 — below minimum valid value of 9
write_qcow2('qcow2-cluster-bits-low.qcow2', cluster_bits=8)

# 4. cluster_bits = 22 — above maximum valid value of 21
write_qcow2('qcow2-cluster-bits-high.qcow2', cluster_bits=22)
"

echo "Done."
