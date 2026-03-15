#!/usr/bin/env python3
"""Generate adversarial images with boundary-value fields (Phase 2).

Creates images that test edge cases in format parsing:
- QCOW2 refcount_order edge cases (7, 255)
- QCOW2 oversized virtual sizes (petabyte, max)
- VMDK grain_size_sectors boundaries (0, huge)
- VHDX conflicting dual headers
- VHD BAT entry beyond EOF
- VHDX BAT entry beyond EOF

Usage:
    python3 scripts/create-boundary-testdata.py [output-dir]

Default output: ../imago-testdata/custom/audit/
"""

import os
import struct
import sys

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else '../imago-testdata/custom/audit'
os.makedirs(OUTDIR, exist_ok=True)


def write_file(filename, data):
    path = os.path.join(OUTDIR, filename)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'Created {path} ({os.path.getsize(path)} bytes)')


# ---------------------------------------------------------------------------
# 2a. QCOW2 refcount_order edge cases (v3 only, offset 96)
# ---------------------------------------------------------------------------

def make_qcow2_v3(refcount_order, virtual_size=1 * 1024 * 1024):
    """Build a minimal QCOW2 v3 header with specified refcount_order."""
    cluster_bits = 16  # 64KB clusters
    cluster_size = 1 << cluster_bits
    l1_size = 1
    l1_table_offset = cluster_size
    refcount_table_offset = 2 * cluster_size
    header_length = 104

    # QCOW2 v3 header (104 bytes)
    hdr = struct.pack('>4sI', b'QFI\xfb', 3)           # magic, version
    hdr += struct.pack('>Q', 0)                          # backing_file_offset
    hdr += struct.pack('>I', 0)                          # backing_file_size
    hdr += struct.pack('>I', cluster_bits)               # cluster_bits
    hdr += struct.pack('>Q', virtual_size)               # size
    hdr += struct.pack('>I', 0)                          # crypt_method
    hdr += struct.pack('>I', l1_size)                    # l1_size
    hdr += struct.pack('>Q', l1_table_offset)            # l1_table_offset
    hdr += struct.pack('>Q', refcount_table_offset)      # refcount_table_offset
    hdr += struct.pack('>I', 1)                          # refcount_table_clusters
    hdr += struct.pack('>I', 0)                          # nb_snapshots
    hdr += struct.pack('>Q', 0)                          # snapshots_offset
    # v3 fields
    hdr += struct.pack('>Q', 0)                          # incompatible_features
    hdr += struct.pack('>Q', 0)                          # compatible_features
    hdr += struct.pack('>Q', 0)                          # autoclear_features
    hdr += struct.pack('>I', refcount_order)             # refcount_order (offset 96)
    hdr += struct.pack('>I', header_length)              # header_length

    # Pad to 3 clusters
    data = hdr + b'\x00' * (3 * cluster_size - len(hdr))
    return data


print('=== Phase 2a: Refcount order edge cases ===')
write_file('qcow2-refcount-order-7.qcow2', make_qcow2_v3(refcount_order=7))
write_file('qcow2-refcount-order-255.qcow2', make_qcow2_v3(refcount_order=255))


# ---------------------------------------------------------------------------
# 2b. Oversized virtual size
# ---------------------------------------------------------------------------

print('\n=== Phase 2b: Oversized virtual size ===')
write_file('qcow2-vsize-petabyte.qcow2', make_qcow2_v3(
    refcount_order=4, virtual_size=(1 << 50)
))
write_file('qcow2-vsize-max.qcow2', make_qcow2_v3(
    refcount_order=4, virtual_size=((1 << 63) - 1)
))


# ---------------------------------------------------------------------------
# 2c. VMDK grain size boundary
# ---------------------------------------------------------------------------

def make_vmdk4(grain_size_sectors, capacity_sectors=2048):
    """Build a minimal VMDK4 sparse header."""
    magic = 0x564D444B  # "KDMV" in LE
    version = 1
    flags = 0
    num_gtes = 512
    descriptor_offset = 0
    descriptor_size = 0
    rgd_offset = 0
    gd_offset = 0
    overhead = 0

    hdr = struct.pack('<I', magic)
    hdr += struct.pack('<I', version)
    hdr += struct.pack('<I', flags)
    hdr += struct.pack('<Q', capacity_sectors)
    hdr += struct.pack('<Q', grain_size_sectors)
    hdr += struct.pack('<Q', descriptor_offset)
    hdr += struct.pack('<Q', descriptor_size)
    hdr += struct.pack('<I', num_gtes)
    hdr += struct.pack('<Q', rgd_offset)
    hdr += struct.pack('<Q', gd_offset)
    hdr += struct.pack('<Q', overhead)
    # unclean_shutdown (1 byte), single_end_line_char (1 byte),
    # non_end_line_char (1 byte), double_end_line_char1 (1 byte),
    # compress_algorithm (2 bytes)
    hdr += struct.pack('<BBBB', 0, 0x0a, 0x20, 0x0d)
    hdr += struct.pack('<H', 0)
    # Pad to 512 bytes (sector aligned)
    hdr += b'\x00' * (512 - len(hdr))
    return hdr


print('\n=== Phase 2c: VMDK grain size boundary ===')
write_file('vmdk-grain-size-zero.vmdk', make_vmdk4(grain_size_sectors=0))
write_file('vmdk-grain-size-huge.vmdk', make_vmdk4(
    grain_size_sectors=0x7FFFFFFFFFFFFFFF
))


# ---------------------------------------------------------------------------
# 2d. VHDX conflicting dual headers
# ---------------------------------------------------------------------------

def crc32c(data):
    """CRC-32C (Castagnoli) — used by VHDX."""
    # Use the crcmod-like table approach
    crc = 0xFFFFFFFF
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0x82F63B78 ^ (c >> 1)
            else:
                c >>= 1
        table.append(c)
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def make_vhdx_header(sequence_number, log_guid=b'\x00' * 16):
    """Build a 4KB VHDX header with CRC-32C."""
    hdr = bytearray(4096)
    # Signature "head"
    struct.pack_into('<4s', hdr, 0, b'head')
    # Checksum placeholder (offset 4)
    struct.pack_into('<I', hdr, 4, 0)
    # Sequence number (offset 8)
    struct.pack_into('<Q', hdr, 8, sequence_number)
    # File write GUID (offset 16) — just use non-zero bytes
    hdr[16:32] = os.urandom(16)
    # Data write GUID (offset 32)
    hdr[32:48] = os.urandom(16)
    # Log GUID (offset 48) — all zeros means no dirty log
    hdr[48:64] = log_guid
    # Log version (offset 64)
    struct.pack_into('<H', hdr, 64, 0)
    # Version (offset 66)
    struct.pack_into('<H', hdr, 66, 1)
    # Log length (offset 68)
    struct.pack_into('<I', hdr, 68, 1024 * 1024)
    # Log offset (offset 72)
    struct.pack_into('<Q', hdr, 72, 0x100000)  # 1MB

    # Compute CRC-32C over entire 4KB with checksum field zeroed
    crc = crc32c(bytes(hdr))
    struct.pack_into('<I', hdr, 4, crc)
    return bytes(hdr)


def make_vhdx_region_table():
    """Build a minimal VHDX region table (64KB) with BAT and metadata regions."""
    rt = bytearray(65536)
    # Signature "regi"
    struct.pack_into('<4s', rt, 0, b'regi')
    # Checksum placeholder (offset 4)
    struct.pack_into('<I', rt, 4, 0)
    # Entry count (offset 8)
    struct.pack_into('<I', rt, 8, 2)

    # BAT region entry (offset 16, 32 bytes)
    # BAT GUID: 2DC27766-F623-4200-9D64-115E9BFD4A08
    bat_guid = bytes([
        0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
        0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08
    ])
    rt[16:32] = bat_guid
    struct.pack_into('<Q', rt, 32, 3 * 1024 * 1024)   # file offset 3MB
    struct.pack_into('<I', rt, 40, 1024 * 1024)        # length 1MB
    struct.pack_into('<I', rt, 44, 1)                   # required=1

    # Metadata region entry (offset 48, 32 bytes)
    # Metadata GUID: 8B7CA206-4612-B831-4BA0-D5B5E6D44EF9
    meta_guid = bytes([
        0x06, 0xA2, 0x7C, 0x8B, 0x12, 0x46, 0x31, 0xB8,
        0x4B, 0xA0, 0xD5, 0xB5, 0xE6, 0xD4, 0x4E, 0xF9
    ])
    rt[48:64] = meta_guid
    struct.pack_into('<Q', rt, 64, 4 * 1024 * 1024)   # file offset 4MB
    struct.pack_into('<I', rt, 72, 1024 * 1024)        # length 1MB
    struct.pack_into('<I', rt, 76, 1)                   # required=1

    # Compute CRC-32C
    crc = crc32c(bytes(rt))
    struct.pack_into('<I', rt, 4, crc)
    return bytes(rt)


print('\n=== Phase 2d: VHDX conflicting dual headers ===')

# Build a VHDX file with two headers that have different sequence numbers
# and different data write GUIDs. Header 2 has the higher sequence number.
vhdx = bytearray(6 * 1024 * 1024)  # 6MB file

# File identifier (offset 0, 1MB)
struct.pack_into('<8s', vhdx, 0, b'vhdxfile')

# Header 1 at 64KB — sequence number 1
hdr1 = make_vhdx_header(sequence_number=1)
vhdx[0x10000:0x10000 + 4096] = hdr1

# Header 2 at 128KB — sequence number 5 (higher, should be selected)
hdr2 = make_vhdx_header(sequence_number=5)
vhdx[0x20000:0x20000 + 4096] = hdr2

# Region table at 192KB
rt = make_vhdx_region_table()
vhdx[0x30000:0x30000 + 65536] = rt
# Duplicate region table at 256KB
vhdx[0x40000:0x40000 + 65536] = rt

write_file('vhdx-conflicting-headers.vhdx', bytes(vhdx))


# ---------------------------------------------------------------------------
# 2e. VHD BAT beyond EOF
# ---------------------------------------------------------------------------

def vhd_checksum(data):
    """One's complement checksum for VHD footer/dynamic header."""
    total = 0
    for b in data:
        total += b
    return (~total) & 0xFFFFFFFF


print('\n=== Phase 2e: VHD BAT beyond EOF ===')

# Build a minimal dynamic VHD with a BAT entry pointing beyond EOF.
# VHD structure: [footer copy (512)] [dynamic header (1024)] [BAT] ... [footer (512)]
virtual_size = 2 * 1024 * 1024  # 2MB
block_size = 2 * 1024 * 1024     # 2MB blocks
num_blocks = virtual_size // block_size  # 1 block

# Footer (512 bytes)
footer = bytearray(512)
struct.pack_into('>8s', footer, 0, b'conectix')     # cookie
struct.pack_into('>I', footer, 8, 2)                 # features
struct.pack_into('>I', footer, 12, 0x00010000)       # format version 1.0
struct.pack_into('>Q', footer, 16, 512)              # data_offset (-> dynamic header)
struct.pack_into('>I', footer, 24, 0)                # timestamp
struct.pack_into('>4s', footer, 28, b'test')         # creator app
struct.pack_into('>I', footer, 32, 0x00010000)       # creator version
struct.pack_into('>I', footer, 36, 0x5769326B)       # creator host (Wi2k)
struct.pack_into('>Q', footer, 40, virtual_size)     # original size
struct.pack_into('>Q', footer, 48, virtual_size)     # current size
# CHS geometry (fake but valid)
struct.pack_into('>H', footer, 56, 4)                # cylinders
struct.pack_into('>B', footer, 58, 16)               # heads
struct.pack_into('>B', footer, 59, 63)               # sectors per track
struct.pack_into('>I', footer, 60, 3)                # disk_type = dynamic
footer[64:68] = b'\x00\x00\x00\x00'                  # checksum placeholder
footer[68:84] = os.urandom(16)                        # uuid
footer[84] = 0                                        # saved state

# Compute footer checksum
chk = vhd_checksum(footer)
struct.pack_into('>I', footer, 64, chk)

# Dynamic header (1024 bytes) at offset 512
dynhdr = bytearray(1024)
struct.pack_into('>8s', dynhdr, 0, b'cxsparse')      # cookie
struct.pack_into('>Q', dynhdr, 8, 0xFFFFFFFFFFFFFFFF)  # data_offset (unused)
struct.pack_into('>Q', dynhdr, 16, 1536)              # table_offset (BAT at 1536)
struct.pack_into('>I', dynhdr, 24, 0x00010000)        # header version
struct.pack_into('>I', dynhdr, 28, num_blocks)        # max_table_entries
struct.pack_into('>I', dynhdr, 32, block_size)        # block_size
dynhdr[36:40] = b'\x00\x00\x00\x00'                   # checksum placeholder

# Compute dynamic header checksum
chk = vhd_checksum(dynhdr)
struct.pack_into('>I', dynhdr, 36, chk)

# BAT: 1 entry pointing far beyond EOF
bat = bytearray(512)  # Sector-aligned
# Point to sector 0xFFFFFFFE (just under the "unallocated" marker 0xFFFFFFFF)
struct.pack_into('>I', bat, 0, 0xFFFFFFFE)

# Assemble: footer copy + dynamic header + BAT + footer
vhd_data = bytes(footer) + bytes(dynhdr) + bytes(bat)
# Pad to at least a few KB
vhd_data += b'\x00' * (4096 - len(vhd_data))
# Append footer at end
vhd_data += bytes(footer)

write_file('vhd-bat-beyond-eof.vhd', vhd_data)


# ---------------------------------------------------------------------------
# 2e. VHDX BAT beyond EOF
# ---------------------------------------------------------------------------

print('\n=== Phase 2e (cont): VHDX BAT beyond EOF ===')

# Reuse the VHDX from 2d but add a BAT entry pointing way beyond EOF.
# BAT is at 3MB, metadata at 4MB. We'll write a BAT entry with state=6
# (fully present) and offset pointing to 100MB (way beyond our 6MB file).
vhdx_bat = bytearray(6 * 1024 * 1024)

# File identifier
struct.pack_into('<8s', vhdx_bat, 0, b'vhdxfile')

# Headers
hdr = make_vhdx_header(sequence_number=1)
vhdx_bat[0x10000:0x10000 + 4096] = hdr
vhdx_bat[0x20000:0x20000 + 4096] = hdr

# Region tables
rt = make_vhdx_region_table()
vhdx_bat[0x30000:0x30000 + 65536] = rt
vhdx_bat[0x40000:0x40000 + 65536] = rt

# BAT at 3MB: one entry with state=6 (fully present), offset=100MB
# BAT entry = (offset_mb << 20) | state
bat_offset_mb = 100
bat_entry = (bat_offset_mb << 20) | 6  # state 6 = PAYLOAD_BLOCK_FULLY_PRESENT
struct.pack_into('<Q', vhdx_bat, 3 * 1024 * 1024, bat_entry)

# Minimal metadata at 4MB (just enough to be parseable)
# We need: file parameters, virtual size, logical sector size, physical sector size
meta_offset = 4 * 1024 * 1024
# Metadata table header
struct.pack_into('<8s', vhdx_bat, meta_offset, b'metadata')
struct.pack_into('<H', vhdx_bat, meta_offset + 10, 4)  # entry_count = 4

# Metadata entries start at meta_offset + 32
# Each entry: 16-byte GUID + 4-byte offset + 4-byte length + 4-byte flags
entry_base = meta_offset + 32

# File Parameters GUID: CAA16737-FA36-4D43-B3B6-33F0AA44E76B
fp_guid = bytes([
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
    0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B
])
vhdx_bat[entry_base:entry_base + 16] = fp_guid
struct.pack_into('<I', vhdx_bat, entry_base + 16, 65536)  # offset within metadata
struct.pack_into('<I', vhdx_bat, entry_base + 20, 8)       # length
struct.pack_into('<I', vhdx_bat, entry_base + 24, 3)       # flags: is_user + is_required

# Virtual Size GUID: 2FA54224-CD1B-4876-B211-5DBED83BF4B8
vs_guid = bytes([
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48,
    0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8
])
entry2 = entry_base + 32
vhdx_bat[entry2:entry2 + 16] = vs_guid
struct.pack_into('<I', vhdx_bat, entry2 + 16, 65536 + 8)
struct.pack_into('<I', vhdx_bat, entry2 + 20, 8)
struct.pack_into('<I', vhdx_bat, entry2 + 24, 3)

# Logical Sector Size GUID: 8141BF1D-A96F-4709-BA47-F233A8FAAB5F
ls_guid = bytes([
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
    0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F
])
entry3 = entry_base + 64
vhdx_bat[entry3:entry3 + 16] = ls_guid
struct.pack_into('<I', vhdx_bat, entry3 + 16, 65536 + 16)
struct.pack_into('<I', vhdx_bat, entry3 + 20, 4)
struct.pack_into('<I', vhdx_bat, entry3 + 24, 3)

# Physical Sector Size GUID: CDA348C7-445D-4471-9CC9-E9885251C556
ps_guid = bytes([
    0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44,
    0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56
])
entry4 = entry_base + 96
vhdx_bat[entry4:entry4 + 16] = ps_guid
struct.pack_into('<I', vhdx_bat, entry4 + 16, 65536 + 20)
struct.pack_into('<I', vhdx_bat, entry4 + 20, 4)
struct.pack_into('<I', vhdx_bat, entry4 + 24, 3)

# Write actual metadata values
md_data = meta_offset + 65536
# File parameters: block_size=32MB (0x2000000), no flags
struct.pack_into('<I', vhdx_bat, md_data, 32 * 1024 * 1024)
struct.pack_into('<I', vhdx_bat, md_data + 4, 0)
# Virtual size: 32MB
struct.pack_into('<Q', vhdx_bat, md_data + 8, 32 * 1024 * 1024)
# Logical sector size: 512
struct.pack_into('<I', vhdx_bat, md_data + 16, 512)
# Physical sector size: 4096
struct.pack_into('<I', vhdx_bat, md_data + 20, 4096)

write_file('vhdx-bat-beyond-eof.vhdx', bytes(vhdx_bat))

print('\nDone.')
