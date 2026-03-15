#!/usr/bin/env python3
"""Generate adversarial images for format confusion testing (Phase 3).

Creates images that test format detection robustness and parser isolation:
- Polyglot files (valid magic but wrong body content)
- Truncated headers (cut mid-field)
- VMDK descriptor attacks (null bytes, multi-extent, huge descriptor)

Usage:
    python3 scripts/create-format-confusion-testdata.py [output-dir]

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
# 3a. Polyglot files
# ---------------------------------------------------------------------------

print('=== Phase 3a: Polyglot files ===')

# polyglot-qcow2-vmdk: Valid QCOW2 magic header but VMDK descriptor as body.
# Format detection should identify as QCOW2 (magic wins), but structural
# validation should fail since the L1/refcount tables are garbage.
cluster_bits = 16
cluster_size = 1 << cluster_bits
qcow2_hdr = struct.pack(
    '>4sI Q II Q I I Q Q I I Q Q',
    b'QFI\xfb', 2,       # magic, version
    0, 0,                 # backing_file_offset, backing_file_size
    cluster_bits,         # cluster_bits
    1024 * 1024,          # virtual_size (1MB)
    0,                    # crypt_method
    1,                    # l1_size
    cluster_size,         # l1_table_offset
    2 * cluster_size,     # refcount_table_offset
    1,                    # refcount_table_clusters
    0,                    # nb_snapshots
    0,                    # snapshots_offset
    0,                    # padding
)

# Fill the rest with a VMDK descriptor text (confusing body)
vmdk_desc = b'''# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicSparse"

# Extent description
RW 2097152 SPARSE "polyglot.vmdk"
'''

polyglot_data = qcow2_hdr[:72]
polyglot_data += vmdk_desc
polyglot_data += b'\x00' * (3 * cluster_size - len(polyglot_data))
write_file('polyglot-qcow2-vmdk.qcow2', polyglot_data)


# polyglot-qcow2-elf: Valid QCOW2 magic at offset 0 but ELF binary content
# after the header. Tests that the parser doesn't get confused by executable
# content in the data area.
elf_header = b'\x7fELF'  # ELF magic
elf_header += b'\x02'     # 64-bit
elf_header += b'\x01'     # little-endian
elf_header += b'\x01'     # current version
elf_header += b'\x00' * 9  # padding
elf_header += struct.pack('<H', 2)    # ET_EXEC
elf_header += struct.pack('<H', 0x3E)  # x86-64
elf_header += struct.pack('<I', 1)     # version
elf_header += struct.pack('<Q', 0x400000)  # entry point
elf_header += struct.pack('<Q', 64)    # program header offset
elf_header += struct.pack('<Q', 0)     # section header offset
elf_header += struct.pack('<I', 0)     # flags
elf_header += struct.pack('<H', 64)    # ELF header size
elf_header += struct.pack('<H', 56)    # program header entry size
elf_header += struct.pack('<H', 1)     # program header count
elf_header += struct.pack('<H', 0)     # section header entry size
elf_header += struct.pack('<H', 0)     # section header count
elf_header += struct.pack('<H', 0)     # section name string table index

polyglot_elf = qcow2_hdr[:72]
polyglot_elf += elf_header
polyglot_elf += b'\x00' * (3 * cluster_size - len(polyglot_elf))
write_file('polyglot-qcow2-elf.qcow2', polyglot_elf)


# ---------------------------------------------------------------------------
# 3b. Truncated headers
# ---------------------------------------------------------------------------

print('\n=== Phase 3b: Truncated headers ===')

# qcow2-truncated-header-v2: QCOW2 v2 header cut at offset 32.
# This is mid-field — after version and backing file info, but before
# virtual_size and L1 table offset. Parser should fail gracefully.
truncated_qcow2 = struct.pack(
    '>4sI Q II',
    b'QFI\xfb', 2,   # magic, version
    0, 0,             # backing_file_offset, backing_file_size
    cluster_bits,     # cluster_bits (but no virtual_size follows)
)
# Cut at exactly 32 bytes (after backing_file_size, before cluster_bits value
# is fully useful — the header needs at least 72 bytes for v2)
write_file('qcow2-truncated-header-v2.qcow2', qcow2_hdr[:32])


# vmdk-truncated-after-magic: VMDK sparse header magic (4 bytes for magic +
# 4 bytes for version) then nothing else. The parser needs at least the full
# header to extract grain size, capacity, etc.
vmdk_magic = struct.pack('<I', 0x564D444B)   # KDMV
vmdk_version = struct.pack('<I', 1)
write_file('vmdk-truncated-after-magic.vmdk', vmdk_magic + vmdk_version)


# vhd-truncated-footer: VHD with footer cookie and a few fields, but
# truncated before the disk type and checksum. A real VHD footer is 512
# bytes; we provide only 48 bytes.
vhd_partial = bytearray(48)
struct.pack_into('>8s', vhd_partial, 0, b'conectix')     # cookie
struct.pack_into('>I', vhd_partial, 8, 2)                 # features
struct.pack_into('>I', vhd_partial, 12, 0x00010000)       # format version
struct.pack_into('>Q', vhd_partial, 16, 0xFFFFFFFFFFFFFFFF)  # data_offset (fixed)
struct.pack_into('>I', vhd_partial, 24, 0)                 # timestamp
struct.pack_into('>4s', vhd_partial, 28, b'test')          # creator app
struct.pack_into('>I', vhd_partial, 32, 0x00010000)        # creator version
struct.pack_into('>I', vhd_partial, 36, 0x5769326B)        # creator host
struct.pack_into('>Q', vhd_partial, 40, 2 * 1024 * 1024)  # original size
# Truncated here — no current_size, geometry, disk_type, checksum, uuid
write_file('vhd-truncated-footer.vhd', bytes(vhd_partial))


# ---------------------------------------------------------------------------
# 3c. VMDK descriptor attacks
# ---------------------------------------------------------------------------

print('\n=== Phase 3c: VMDK descriptor attacks ===')


def make_vmdk4_with_descriptor(desc_bytes, capacity_sectors=2048, grain_size=128):
    """Build a VMDK4 sparse header with an embedded descriptor."""
    magic = 0x564D444B  # KDMV
    version = 1
    flags = 0
    num_gtes = 512

    # Descriptor starts at sector 1 (offset 512)
    desc_offset_sectors = 1
    # Round up to sector boundary
    desc_size_sectors = (len(desc_bytes) + 511) // 512

    # GD and overhead come after descriptor
    gd_sector = desc_offset_sectors + desc_size_sectors + 1
    overhead = gd_sector + 1

    hdr = struct.pack('<I', magic)
    hdr += struct.pack('<I', version)
    hdr += struct.pack('<I', flags)
    hdr += struct.pack('<Q', capacity_sectors)
    hdr += struct.pack('<Q', grain_size)
    hdr += struct.pack('<Q', desc_offset_sectors)
    hdr += struct.pack('<Q', desc_size_sectors)
    hdr += struct.pack('<I', num_gtes)
    hdr += struct.pack('<Q', 0)           # rgd_offset (none)
    hdr += struct.pack('<Q', gd_sector)   # gd_offset
    hdr += struct.pack('<Q', overhead)
    hdr += struct.pack('<BBBB', 0, 0x0a, 0x20, 0x0d)
    hdr += struct.pack('<H', 0)           # compress_algorithm
    # Pad header to 512 bytes
    hdr += b'\x00' * (512 - len(hdr))

    # Pad descriptor to sector boundary
    desc_padded = desc_bytes + b'\x00' * (desc_size_sectors * 512 - len(desc_bytes))

    return hdr + desc_padded


# vmdk-descriptor-null-bytes: Descriptor with embedded null bytes.
# The parser should handle null-terminated strings gracefully and not
# read past the null or misinterpret content after it.
desc_with_nulls = (
    b'# Disk DescriptorFile\n'
    b'version=1\n'
    b'CID=fffffffe\n'
    b'\x00\x00\x00'  # embedded nulls mid-descriptor
    b'createType="monolithicSparse"\n'
    b'\x00'
    b'RW 2048 SPARSE "output.vmdk"\n'
)
write_file('vmdk-descriptor-null-bytes.vmdk', make_vmdk4_with_descriptor(desc_with_nulls))


# vmdk-descriptor-multi-extent: Descriptor with multiple extent lines.
# Imago should reject this since multi-extent VMDKs are not supported.
desc_multi_extent = (
    b'# Disk DescriptorFile\n'
    b'version=1\n'
    b'CID=fffffffe\n'
    b'parentCID=ffffffff\n'
    b'createType="monolithicSparse"\n\n'
    b'# Extent description\n'
    b'RW 1024 SPARSE "extent1.vmdk"\n'
    b'RW 1024 SPARSE "extent2.vmdk"\n'
    b'RW 1024 SPARSE "extent3.vmdk"\n'
)
write_file('vmdk-descriptor-multi-extent.vmdk', make_vmdk4_with_descriptor(desc_multi_extent))


# vmdk-descriptor-huge: Header claims a descriptor >1MB (2048 sectors).
# The parser reads one sector at a time, so this tests bounds checking
# on the descriptor size field without actually needing 1MB of data.
desc_normal = (
    b'# Disk DescriptorFile\n'
    b'version=1\n'
    b'CID=fffffffe\n'
    b'parentCID=ffffffff\n'
    b'createType="monolithicSparse"\n\n'
    b'RW 2048 SPARSE "output.vmdk"\n'
)
# Build header manually with inflated desc_size_sectors
magic = 0x564D444B
hdr = struct.pack('<I', magic)
hdr += struct.pack('<I', 1)              # version
hdr += struct.pack('<I', 0)              # flags
hdr += struct.pack('<Q', 2048)           # capacity_sectors
hdr += struct.pack('<Q', 128)            # grain_size_sectors
hdr += struct.pack('<Q', 1)              # desc_offset_sectors
hdr += struct.pack('<Q', 2048)           # desc_size_sectors (1MB!)
hdr += struct.pack('<I', 512)            # num_gtes
hdr += struct.pack('<Q', 0)              # rgd_offset
hdr += struct.pack('<Q', 2050)           # gd_offset (past huge descriptor)
hdr += struct.pack('<Q', 2051)           # overhead
hdr += struct.pack('<BBBB', 0, 0x0a, 0x20, 0x0d)
hdr += struct.pack('<H', 0)
hdr += b'\x00' * (512 - len(hdr))

# Only provide a small actual file — the descriptor size claim is bogus
desc_padded = desc_normal + b'\x00' * (512 - len(desc_normal))
write_file('vmdk-descriptor-huge.vmdk', hdr + desc_padded)


print('\nDone.')
