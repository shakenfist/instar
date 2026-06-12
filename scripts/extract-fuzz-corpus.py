#!/usr/bin/env python3
"""Extract seed corpus for coverage-guided fuzzing from instar-testdata.

Copies test images from the instar-testdata repository into per-target
corpus directories under src/fuzz/corpus/. Images are filtered by
format and optionally truncated for header-only targets.

Usage:
    python3 scripts/extract-fuzz-corpus.py --testdata /path/to/instar-testdata

The script reads tests/manifest.json to find images and their formats.
"""

import argparse
import hashlib
import json
import os
import sys


# Map manifest format names to fuzz target groups
FORMAT_TO_TARGETS = {
    'qcow2': [
        'fuzz_qcow2_header',
        'fuzz_qcow2_l1l2',
        'fuzz_qcow2_refcount',
        'fuzz_qcow2_decompress',
        'fuzz_snapshot_parse',
    ],
    'vmdk': ['fuzz_vmdk_header', 'fuzz_vmdk_grain'],
    'vpc': ['fuzz_vhd_footer', 'fuzz_vhd_bat'],
    'vhd': ['fuzz_vhd_footer', 'fuzz_vhd_bat'],
    'vhdx': ['fuzz_vhdx_header', 'fuzz_vhdx_metadata'],
    'raw': ['fuzz_raw_partition'],
    'luks': ['fuzz_luks_header'],
}

# Targets that only need the first few sectors (header-only)
HEADER_ONLY_TARGETS = {
    'fuzz_qcow2_header': 8192,     # 16 sectors
    'fuzz_vmdk_header': 8192,
    'fuzz_vhd_footer': None,        # needs full file (footer at end)
    'fuzz_vhdx_header': 65536 * 2,  # headers + region tables
    'fuzz_raw_partition': 512,       # first sector only
    'fuzz_luks_header': 8192,
    'fuzz_format_detect': 8192,
}

# Max seed file size (4MB) - skip larger files for full-image targets
MAX_SEED_SIZE = 4 * 1024 * 1024


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()[:16]


def copy_seed(src_path, dest_dir, truncate_bytes=None):
    """Copy a file into the corpus directory, optionally truncated."""
    if not os.path.exists(src_path):
        return False

    file_size = os.path.getsize(src_path)
    if truncate_bytes is None and file_size > MAX_SEED_SIZE:
        return False

    os.makedirs(dest_dir, exist_ok=True)

    with open(src_path, 'rb') as f:
        if truncate_bytes is not None:
            data = f.read(truncate_bytes)
        else:
            data = f.read()

    # Name by content hash to avoid duplicates
    name = sha256_hex(data)
    dest_path = os.path.join(dest_dir, name)
    if not os.path.exists(dest_path):
        with open(dest_path, 'wb') as f:
            f.write(data)
    return True


def walk_qcow2_snapshot_table(blob, nb_snapshots, max_entries=4096):
    """Walk a raw qcow2 snapshot table and return its byte length.

    Mirrors the entry walk in the snapshot crate's
    snapshot_table_byte_len: entries start 8-aligned; each is
    40 bytes of header + extra_data_size + id_str_size + name_size.
    Returns None if the walk escapes the blob.
    """
    pos = 0
    for _ in range(min(nb_snapshots, max_entries)):
        pos = (pos + 7) & ~7
        if pos + 40 > len(blob):
            return None
        extra = int.from_bytes(blob[pos + 36:pos + 40], 'big')
        id_len = int.from_bytes(blob[pos + 12:pos + 14], 'big')
        name_len = int.from_bytes(blob[pos + 14:pos + 16], 'big')
        end = pos + 40 + extra + id_len + name_len
        if end > len(blob):
            return None
        pos = end
    return pos


def build_snapshot_parse_seed(header_sector, nb_snapshots, table):
    """Build a fuzz_snapshot_parse seed from a header + snapshot table.

    The target's input layout is: device sector 0 (qcow2 header),
    a control block at 512..544, and the rest of the input is the
    mock device. The seed relocates the snapshot table to byte
    1024 and patches the header (nb_snapshots at offset 60,
    snapshots_offset at 64, both big-endian) so the header-led
    parse, the header-independent parse (control bytes 512..524)
    and the pure-table-reader window (control bytes 524..530) all
    land on the table.
    """
    seed = bytearray(1024 + len(table))
    seed[0:512] = header_sector[:512]
    seed[60:64] = nb_snapshots.to_bytes(4, 'big')
    seed[64:72] = (1024).to_bytes(8, 'big')
    # Control block (little-endian, per the target's doc comment).
    seed[512:520] = (1024).to_bytes(8, 'little')   # variant-2 snapshots_offset
    seed[520:524] = nb_snapshots.to_bytes(4, 'little')  # variant-2 nb
    seed[524:528] = (1024).to_bytes(4, 'little')   # pure-reader window start
    seed[528:530] = min(nb_snapshots, 0xffff).to_bytes(2, 'little')  # pure nb
    seed[530] = 0                                   # early stop: never
    # Needle: point at the first entry's id bytes if decodable.
    if len(table) >= 40:
        id_len = int.from_bytes(table[12:14], 'big')
        extra = int.from_bytes(table[36:40], 'big')
        seed[531] = min(id_len, 64)
        seed[532:540] = (1024 + 40 + extra).to_bytes(8, 'little')
    seed[1024:1024 + len(table)] = table
    return bytes(seed)


def extract_snapshot_parse_seed(src_path, dest_dir):
    """Snapshot-aware seed extraction for fuzz_snapshot_parse.

    Header-only truncation would chop the snapshot table (it
    usually lives megabytes into the image), and whole-image
    copies are skipped above MAX_SEED_SIZE, so snapshot-bearing
    fixtures get a compact relocated seed: header sector +
    control block + the snapshot table itself.
    """
    try:
        with open(src_path, 'rb') as f:
            header = f.read(512)
            if len(header) < 512:
                return False
            nb_snapshots = int.from_bytes(header[60:64], 'big')
            snapshots_offset = int.from_bytes(header[64:72], 'big')
            if nb_snapshots == 0 or snapshots_offset == 0:
                return False
            if snapshots_offset > os.path.getsize(src_path):
                return False
            f.seek(snapshots_offset)
            blob = f.read(1024 * 1024)
    except (OSError, IOError):
        return False

    table_len = walk_qcow2_snapshot_table(blob, nb_snapshots)
    if table_len is None or table_len == 0:
        return False

    seed = build_snapshot_parse_seed(header, nb_snapshots, blob[:table_len])
    os.makedirs(dest_dir, exist_ok=True)
    name = 'snaptable_' + sha256_hex(seed)
    dest_path = os.path.join(dest_dir, name)
    if not os.path.exists(dest_path):
        with open(dest_path, 'wb') as f:
            f.write(seed)
    return True


def build_snapshot_refcount_seed(op):
    """Build one fuzz_snapshot_refcount seed for the given op selector.

    Mirrors the target's 32-byte structured header and sequential
    pool layout (refblocks, L1-A, L1-B, L2 pool, id, name,
    old-table window). The staged state is a small consistent
    image fragment: cluster_bits 9 (512-byte clusters), one
    refblock, one L1 entry -> L2 table at host 0x800 (flat index
    4, refcount 1) with one data cluster at host 0x1000 (flat
    index 8, refcount 1), so the refcount ops, the flag walker
    and the allocator all take their success paths.
    """
    header = bytearray(32)
    header[0] = op
    header[1] = 0          # standard L2, helper clears
    header[2] = 4          # refcount_bits = 16
    header[3] = 0          # cluster_bits = 9
    header[4] = 0          # refblock_count = 1
    header[5] = 1          # one L1 entry
    header[6] = 1          # L2 slot = 16 bytes (two entries)
    header[7] = 1          # id_len = 1
    header[8] = 4          # name_len = 4
    header[9] = 2          # allocator count = 2
    header[10:12] = (0).to_bytes(2, 'little')   # helper entry index
    header[12:20] = (0xffffffffffffffff).to_bytes(8, 'little')  # presence
    header[20:28] = (0).to_bytes(8, 'little')   # host_refblocks_start
    header[28] = 1         # old table has one entry
    header[29] = 0         # cursor refblock seed
    header[30:32] = (0).to_bytes(2, 'little')   # cursor entry seed

    refblocks = bytearray(512)
    refblocks[8:10] = (1).to_bytes(2, 'big')    # flat 4 (L2 table) rc = 1
    refblocks[16:18] = (1).to_bytes(2, 'big')   # flat 8 (data) rc = 1
    l1a = (0x800).to_bytes(8, 'big')
    l1b = (0x800).to_bytes(8, 'big')
    l2 = (0x1000).to_bytes(8, 'big') + (0).to_bytes(8, 'big')
    id_bytes = b'1'
    name_bytes = b'snap'
    old_table = bytearray(1024)
    old_table[0:8] = (0x800).to_bytes(8, 'big')      # l1_table_offset
    old_table[8:12] = (1).to_bytes(4, 'big')         # l1_size
    old_table[12:14] = (1).to_bytes(2, 'big')        # id_str_size
    old_table[14:16] = (4).to_bytes(2, 'big')        # name_size
    old_table[36:40] = (24).to_bytes(4, 'big')       # extra_data_size
    old_table[64:65] = b'9'                          # id
    old_table[65:69] = b'old '                       # name

    return bytes(header) + bytes(refblocks) + l1a + l1b + l2 + \
        id_bytes + name_bytes + bytes(old_table)


def create_minimal_seeds(corpus_base):
    """Create hand-crafted minimal seed inputs for each target."""

    # fuzz_snapshot_parse: a synthetic snapshot-bearing qcow2
    # (v3 header + two-entry table), independent of testdata.
    sp_header = bytearray(512)
    sp_header[0:4] = b'\x51\x46\x49\xfb'              # magic
    sp_header[4:8] = (3).to_bytes(4, 'big')           # version 3
    sp_header[20:24] = (16).to_bytes(4, 'big')        # cluster_bits
    sp_header[24:32] = (1 << 30).to_bytes(8, 'big')   # virtual_size
    sp_header[96:100] = (4).to_bytes(4, 'big')        # refcount_order
    sp_header[100:104] = (112).to_bytes(4, 'big')     # header_length
    sp_table = bytearray()
    for i, (sid, sname) in enumerate([(b'1', b'snap1'), (b'2', b'snap2')]):
        if len(sp_table) % 8 != 0:
            sp_table += bytes(8 - len(sp_table) % 8)
        entry = bytearray(40)
        entry[0:8] = (0x10000 * (i + 1)).to_bytes(8, 'big')  # l1_table_offset
        entry[8:12] = (1).to_bytes(4, 'big')                 # l1_size
        entry[12:14] = len(sid).to_bytes(2, 'big')
        entry[14:16] = len(sname).to_bytes(2, 'big')
        entry[36:40] = (24).to_bytes(4, 'big')               # extra_data_size
        sp_table += bytes(entry) + bytes(24) + sid + sname
    sp_seed = build_snapshot_parse_seed(bytes(sp_header), 2, bytes(sp_table))
    dest = os.path.join(corpus_base, 'fuzz_snapshot_parse')
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, 'minimal_snapshot_table'), 'wb') as f:
        f.write(sp_seed)

    # fuzz_snapshot_refcount: one structured-header seed per op
    # selector (the target is synthetic; no natural seeds exist).
    dest = os.path.join(corpus_base, 'fuzz_snapshot_refcount')
    os.makedirs(dest, exist_ok=True)
    for op in range(8):
        with open(os.path.join(dest, f'minimal_op{op}'), 'wb') as f:
            f.write(build_snapshot_refcount_seed(op))

    # QCOW2 minimal v2 header (105 bytes minimum)
    qcow2_header = bytearray(512)
    qcow2_header[0:4] = b'\x51\x46\x49\xfb'  # magic (big-endian)
    qcow2_header[4:8] = (2).to_bytes(4, 'big')  # version 2
    qcow2_header[20:24] = (16).to_bytes(4, 'big')  # cluster_bits=16 (64KB)
    qcow2_header[24:32] = (1 << 30).to_bytes(8, 'big')  # virtual_size=1GB
    for target in FORMAT_TO_TARGETS['qcow2']:
        dest = os.path.join(corpus_base, target)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, 'minimal_qcow2_v2'), 'wb') as f:
            f.write(bytes(qcow2_header))

    # QCOW2 minimal v3 header
    qcow2v3 = bytearray(qcow2_header)
    qcow2v3[4:8] = (3).to_bytes(4, 'big')  # version 3
    qcow2v3[96:100] = (4).to_bytes(4, 'big')  # refcount_order=4 (16-bit)
    qcow2v3[100:104] = (112).to_bytes(4, 'big')  # header_length=112
    for target in FORMAT_TO_TARGETS['qcow2']:
        dest = os.path.join(corpus_base, target)
        with open(os.path.join(dest, 'minimal_qcow2_v3'), 'wb') as f:
            f.write(bytes(qcow2v3))

    # VMDK minimal header (79 bytes)
    vmdk_header = bytearray(512)
    vmdk_header[0:4] = (0x564d444b).to_bytes(4, 'little')  # VMDK magic
    vmdk_header[4:8] = (1).to_bytes(4, 'little')  # version
    for target in FORMAT_TO_TARGETS['vmdk']:
        dest = os.path.join(corpus_base, target)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, 'minimal_vmdk4'), 'wb') as f:
            f.write(bytes(vmdk_header))

    # VHD minimal footer (512 bytes)
    vhd_footer = bytearray(512)
    vhd_footer[0:8] = b'conectix'  # cookie
    vhd_footer[60:64] = (2).to_bytes(4, 'big')  # disk_type=2 (fixed)
    for target in FORMAT_TO_TARGETS['vpc']:
        dest = os.path.join(corpus_base, target)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, 'minimal_vhd_footer'), 'wb') as f:
            f.write(bytes(vhd_footer))

    # VHDX minimal file identifier
    vhdx_header = bytearray(65536)
    vhdx_header[0:8] = b'vhdxfile'  # signature
    for target in FORMAT_TO_TARGETS['vhdx']:
        dest = os.path.join(corpus_base, target)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, 'minimal_vhdx'), 'wb') as f:
            f.write(bytes(vhdx_header))

    # RAW with MBR signature
    mbr = bytearray(512)
    mbr[510] = 0x55
    mbr[511] = 0xAA
    mbr[0x1BE] = 0x80       # active partition
    mbr[0x1BE + 4] = 0x83   # Linux type
    dest = os.path.join(corpus_base, 'fuzz_raw_partition')
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, 'minimal_mbr'), 'wb') as f:
        f.write(bytes(mbr))

    # RAW with GPT protective MBR
    gpt = bytearray(mbr)
    gpt[0x1BE] = 0x00       # inactive
    gpt[0x1BE + 4] = 0xEE   # GPT protective
    with open(os.path.join(dest, 'minimal_gpt'), 'wb') as f:
        f.write(bytes(gpt))

    # LUKS v1 header (6-byte magic + version)
    luks = bytearray(592)
    luks[0:6] = bytes([0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe])  # LUKS magic
    luks[6:8] = (1).to_bytes(2, 'big')  # version 1
    dest = os.path.join(corpus_base, 'fuzz_luks_header')
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, 'minimal_luks_v1'), 'wb') as f:
        f.write(bytes(luks))

    # Format detection seeds (one per format magic)
    fd_dest = os.path.join(corpus_base, 'fuzz_format_detect')
    os.makedirs(fd_dest, exist_ok=True)
    with open(os.path.join(fd_dest, 'seed_qcow2'), 'wb') as f:
        f.write(bytes(qcow2_header[:512]))
    with open(os.path.join(fd_dest, 'seed_vmdk'), 'wb') as f:
        f.write(bytes(vmdk_header[:512]))
    with open(os.path.join(fd_dest, 'seed_vhd'), 'wb') as f:
        f.write(bytes(vhd_footer[:512]))
    with open(os.path.join(fd_dest, 'seed_vhdx'), 'wb') as f:
        f.write(bytes(vhdx_header[:512]))
    with open(os.path.join(fd_dest, 'seed_luks'), 'wb') as f:
        f.write(bytes(luks[:512]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--testdata',
        required=True,
        help='Path to instar-testdata repository',
    )
    parser.add_argument(
        '--corpus-dir',
        default=None,
        help='Output corpus directory (default: src/fuzz/corpus/)',
    )
    parser.add_argument(
        '--manifest',
        default=None,
        help='Path to manifest.json (default: tests/manifest.json)',
    )
    args = parser.parse_args()

    # Resolve paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    corpus_base = args.corpus_dir or os.path.join(repo_root, 'src', 'fuzz', 'corpus')
    manifest_path = args.manifest or os.path.join(repo_root, 'tests', 'manifest.json')

    if not os.path.exists(manifest_path):
        print(f'Error: manifest not found at {manifest_path}', file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.testdata):
        print(f'Error: testdata directory not found at {args.testdata}', file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Process each image from the manifest
    copied = 0
    skipped = 0
    for image in manifest.get('images', []):
        fmt = image.get('format', 'unknown')
        path = image.get('path', '')
        src_path = os.path.join(args.testdata, path)

        if not os.path.exists(src_path):
            skipped += 1
            continue

        # Get target list for this format
        targets = FORMAT_TO_TARGETS.get(fmt, [])

        # All images also go to format detection
        all_targets = set(targets) | {'fuzz_format_detect'}

        for target in all_targets:
            truncate = HEADER_ONLY_TARGETS.get(target)
            dest = os.path.join(corpus_base, target)
            if copy_seed(src_path, dest, truncate):
                copied += 1

        # Snapshot-bearing qcow2 fixtures additionally get a
        # compact relocated header+table seed (whole-image copies
        # are skipped above MAX_SEED_SIZE and would bury the
        # table megabytes into the input).
        if fmt == 'qcow2':
            dest = os.path.join(corpus_base, 'fuzz_snapshot_parse')
            if extract_snapshot_parse_seed(src_path, dest):
                copied += 1

    # Also scan for images not in the manifest (custom/audit/ etc.)
    for root, dirs, files in os.walk(args.testdata):
        for name in files:
            src_path = os.path.join(root, name)
            if os.path.getsize(src_path) == 0:
                continue

            # Read first 8 bytes to detect format
            try:
                with open(src_path, 'rb') as f:
                    header = f.read(512)
            except (OSError, IOError):
                continue

            if len(header) < 8:
                continue

            # Detect format from magic
            fmt = detect_format(header)
            targets = FORMAT_TO_TARGETS.get(fmt, [])
            all_targets = set(targets) | {'fuzz_format_detect'}

            for target in all_targets:
                truncate = HEADER_ONLY_TARGETS.get(target)
                dest = os.path.join(corpus_base, target)
                if copy_seed(src_path, dest, truncate):
                    copied += 1

            if fmt == 'qcow2':
                dest = os.path.join(corpus_base, 'fuzz_snapshot_parse')
                if extract_snapshot_parse_seed(src_path, dest):
                    copied += 1

    # Create minimal hand-crafted seeds
    create_minimal_seeds(corpus_base)

    print(f'Corpus seeding complete: {copied} files copied, {skipped} skipped')
    print(f'Corpus directory: {corpus_base}')

    # Print per-target counts
    for target_dir in sorted(os.listdir(corpus_base)):
        target_path = os.path.join(corpus_base, target_dir)
        if os.path.isdir(target_path):
            count = len(os.listdir(target_path))
            print(f'  {target_dir}: {count} seeds')


def detect_format(header):
    """Detect image format from header bytes (simplified)."""
    if len(header) < 8:
        return 'raw'

    # QCOW2 (big-endian magic)
    magic_be = int.from_bytes(header[0:4], 'big')
    if magic_be == 0x514649fb:
        return 'qcow2'

    # VMDK (little-endian)
    magic_le = int.from_bytes(header[0:4], 'little')
    if magic_le == 0x564d444b:
        return 'vmdk'

    # VHDX (little-endian signature)
    sig_le = int.from_bytes(header[0:8], 'little')
    if sig_le == 0x656c696678646876:
        return 'vhdx'

    # VHD (big-endian cookie)
    cookie_be = int.from_bytes(header[0:8], 'big')
    if cookie_be == 0x636f6e6563746978:
        return 'vpc'

    # LUKS magic
    if header[0:6] == bytes([0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe]):
        return 'luks'

    return 'raw'


if __name__ == '__main__':
    main()
