#!/bin/bash
# Generate synthetic VMDK test images for imago integration tests.
#
# Usage:
#   ./scripts/create-vmdk-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/format-coverage/
#
# Creates:
#   vmdk-multi-extent.vmdk  - Binary VMDK4 with two extent lines

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"

echo "Creating VMDK test images in $OUTDIR..."

# --- Multi-Extent VMDK ---
#
# Structure: VMDK4 binary header (sector 0) + text descriptor
# (sectors 1-20) with two RW SPARSE extent lines. This exercises
# count_extent_lines() and the FLAG_NOT_SUPPORTED error path in
# the check operation.

python3 -c '
import struct, sys, os

outdir = sys.argv[1]

# VMDK4 header (little-endian, 512 bytes = 1 sector)
VMDK4_MAGIC = 0x564D444B
SECTOR_SIZE = 512

# Descriptor content with two extent lines
descriptor = (
    "# Disk DescriptorFile\n"
    "version=1\n"
    "CID=fffffffe\n"
    "parentCID=ffffffff\n"
    "createType=\"twoGbMaxExtentSparse\"\n"
    "\n"
    "# Extent description\n"
    "RW 2097152 SPARSE \"extent-s001.vmdk\"\n"
    "RW 2097152 SPARSE \"extent-s002.vmdk\"\n"
    "\n"
    "# The Disk Data Base\n"
    "#DDB\n"
    "\n"
    "ddb.virtualHWVersion = \"4\"\n"
    "ddb.geometry.cylinders = \"130\"\n"
    "ddb.geometry.heads = \"16\"\n"
    "ddb.geometry.sectors = \"63\"\n"
    "ddb.adapterType = \"ide\"\n"
)

desc_bytes = descriptor.encode("ascii")
# Pad to whole sectors
desc_sectors = (len(desc_bytes) + SECTOR_SIZE - 1) // SECTOR_SIZE
desc_padded = desc_bytes.ljust(desc_sectors * SECTOR_SIZE, b"\x00")

# Build VMDK4 header (sector 0)
header = bytearray(SECTOR_SIZE)
struct.pack_into("<I", header, 0, VMDK4_MAGIC)       # magic
struct.pack_into("<I", header, 4, 1)                  # version
struct.pack_into("<I", header, 8, 0)                  # flags
struct.pack_into("<Q", header, 12, 4194304)           # capacity (sectors)
struct.pack_into("<Q", header, 20, 128)               # grain_size
struct.pack_into("<Q", header, 28, 1)                 # desc_offset (sector 1)
struct.pack_into("<Q", header, 36, desc_sectors)      # desc_size
struct.pack_into("<I", header, 44, 512)               # num_gtes_per_gt

path = os.path.join(outdir, "vmdk-multi-extent.vmdk")
with open(path, "wb") as f:
    f.write(header)
    f.write(desc_padded)

print(f"  Created {path} ({os.path.getsize(path)} bytes)")
' "$OUTDIR"

echo "Done. Verify with: xxd -l 4 $OUTDIR/vmdk-multi-extent.vmdk"
