#!/bin/bash
# Generate synthetic VHD test images for imago integration tests.
#
# Usage:
#   ./scripts/create-vhd-testdata.sh [output-dir]
#
# Default output: ../imago-testdata/custom/format-coverage/
#
# Creates:
#   vhd-fixed.vhd  - 10 MiB fixed VHD (disk_type=2)

set -euo pipefail

OUTDIR="${1:-../imago-testdata/custom/format-coverage}"
mkdir -p "$OUTDIR"

echo "Creating VHD test images in $OUTDIR..."

# --- Fixed VHD (disk_type=2) ---
#
# Structure: raw data (10 MiB) + 512-byte footer at EOF.
# MBR signature at bytes 510-511 so imago detects as vpc.
# Recognizable 0xBE pattern at 1 MiB offset for content verification.

python3 -c '
import struct, sys, os

outdir = sys.argv[1]
disk_size = 10 * 1024 * 1024  # 10 MiB

def compute_vhd_geometry(size):
    """VPC/Hyper-V CHS geometry algorithm."""
    total_sectors = size // 512
    total_sectors = min(total_sectors, 65535 * 16 * 255)

    if total_sectors >= 65535 * 16 * 63:
        return (65535, 16, 255)

    if total_sectors >= 65535 * 3 * 17:
        spt = 255
        heads = 16
        cyls = total_sectors // (255 * 16)
        return (cyls, heads, spt)

    spt = 17
    cth = total_sectors // spt
    heads = max(4, (cth + 1023) // 1024)

    if cth >= heads * 1024 or heads > 16:
        spt = 31
        heads = 16
        cth = total_sectors // spt

    if cth >= heads * 1024:
        spt = 63
        heads = 16
        cth = total_sectors // spt

    cyls = cth // heads
    return (cyls, heads, spt)


def build_footer(disk_size, disk_type):
    """Build a 512-byte VHD footer."""
    cookie = b"conectix"
    features = 0x00000002  # FEATURES_RESERVED
    fmt_version = 0x00010000
    # Fixed: data_offset = 0xFFFFFFFFFFFFFFFF
    data_offset = 0xFFFFFFFFFFFFFFFF
    timestamp = 0
    creator_app = b"imgo"
    creator_ver = 0x00010000
    creator_os = b"Wi2k"
    original_size = disk_size
    current_size = disk_size

    cyls, heads, spt = compute_vhd_geometry(disk_size)
    geometry = struct.pack(">HBB", cyls, heads, spt)

    uuid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    uuid += b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"

    # Pack footer without checksum
    footer = bytearray(512)
    footer[0:8] = cookie
    struct.pack_into(">I", footer, 8, features)
    struct.pack_into(">I", footer, 12, fmt_version)
    struct.pack_into(">Q", footer, 16, data_offset)
    struct.pack_into(">I", footer, 24, timestamp)
    footer[28:32] = creator_app
    struct.pack_into(">I", footer, 32, creator_ver)
    footer[36:40] = creator_os
    struct.pack_into(">Q", footer, 40, original_size)
    struct.pack_into(">Q", footer, 48, current_size)
    footer[56:60] = geometry
    struct.pack_into(">I", footer, 60, disk_type)
    # checksum at offset 64, set to 0 for now
    footer[68:84] = uuid
    footer[84] = 0  # saved_state

    # Compute checksum: ones complement of sum of all bytes
    total = 0
    for b in footer:
        total = (total + b) & 0xFFFFFFFF
    checksum = (~total) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)

    return bytes(footer)


# Build fixed VHD
path = os.path.join(outdir, "vhd-fixed.vhd")
with open(path, "wb") as f:
    # Write 10 MiB of raw data
    data = bytearray(disk_size)

    # MBR signature at bytes 510-511
    data[510] = 0x55
    data[511] = 0xAA

    # Recognizable pattern at 1 MiB
    offset_1m = 1024 * 1024
    for i in range(512):
        data[offset_1m + i] = 0xBE

    f.write(data)

    # Append 512-byte footer
    footer = build_footer(disk_size, 2)  # disk_type=2 (fixed)
    f.write(footer)

print(f"  Created {path} ({os.path.getsize(path)} bytes)")
' "$OUTDIR"

echo "Done. Verify with: qemu-img info $OUTDIR/vhd-fixed.vhd"
