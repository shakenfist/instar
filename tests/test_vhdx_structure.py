"""Tests for the structural VHDX parser in helpers/vhdx_structure.py.

The parser is the oracle later tests use to judge instar's VHDX output, so
it is checked here against qemu-img, never against instar: an emitter must
not be the reference for the comparator that judges it. Each qemu-written
image is compared with the layout qemu's own source says it writes, computed
in this file from the formulas in qemu 7.0.0's `block/vhdx.c` and
`block/vhdx.h` (instar-testdata `qemu-sources/7.0.0/`) and SPEC(VHDX) 2.5,
with the line each value comes from cited beside it. A misreading in the
parser therefore shows up as a disagreement with qemu's arithmetic rather
than being copied into the expected values.

The rest of the file checks that the comparison reports what it should
(nothing for two runs of one command, the named field for two different
commands), that every safe VHDX fixture in the manifest parses, and that
malformed files raise `VhdxParseError` rather than an incidental
`IndexError` or `struct.error`, because the differential fuzzer feeds the
parser output that may be wrong.
"""

import dataclasses
import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from base import QEMU_TOOL_TIMEOUT, InstarTestBase
from helpers import load_manifest_images
from helpers.vhdx_structure import (
    VhdxParseError,
    VhdxStructure,
    allocated_bytes,
    parse_vhdx,
    structural_diff,
    summarise,
)

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB
TiB = 1024 * GiB

# BAT entry states, block/vhdx.h:224-229.
PAYLOAD_BLOCK_NOT_PRESENT = 0
PAYLOAD_BLOCK_ZERO = 2
PAYLOAD_BLOCK_FULLY_PRESENT = 6

# Metadata entry flags, block/vhdx.h:258-261.
META_FLAGS_IS_VIRTUAL_DISK = 0x02
META_FLAGS_IS_REQUIRED = 0x04

# Where the headers and the first region table live (block/vhdx.h:37-43),
# and the offsets inside them this file patches or reads directly.
HEADER_1_OFFSET = 64 * KiB
HEADER_DATA_WRITE_GUID = 32
REGION_TABLE_1_OFFSET = 192 * KiB
REGION_TABLE_2_OFFSET = 256 * KiB
REGION_TABLE_HEADER_SIZE = 16
REGION_TABLE_ENTRY_SIZE = 32
REGION_ENTRY_FILE_OFFSET = 16


def _round_up(value, multiple):
    return -(-value // multiple) * multiple


def _ceil_div(value, divisor):
    return -(-value // divisor)


def qemu_create_layout(size, fixed, block_state_zero, block_size=None):
    """What `qemu-img create -f vhdx` writes, from qemu 7.0.0's source.

    Returns `(summary, entries)`: the fields `summarise()` reports, except
    the BAT, and the BAT as a list of `(index, kind, state, file_offset)`
    for every slot of the BAT region. Every value is computed here from the
    cited lines of `block/vhdx.c` and `block/vhdx.h`, never from a parse.
    """
    # Default block size by virtual size: vhdx.c:1962-1974.
    if block_size is None:
        if size > 32 * TiB:
            block_size = 64 * MiB
        elif size > 100 * GiB:
            block_size = 32 * MiB
        elif size > 1 * GiB:
            block_size = 16 * MiB
        else:
            block_size = 8 * MiB
    # vhdx_co_create passes a 512-byte sector size to both the region table
    # and the metadata writer (vhdx.c:2035, :2043), which stores it as both
    # the logical and the physical sector size (vhdx.c:1610-1611).
    sector_size = 512
    # Default log size, DEFAULT_LOG_SIZE (vhdx.h:22, vhdx.c:1925-1926). The
    # header records it, at VHDX_HEADER_SECTION_END = 1 MiB (vhdx.h:45,
    # vhdx.c:1519-1520).
    log_size = 1 * MiB
    log_offset = 1 * MiB
    # VHDX_MAX_SECTORS_PER_BLOCK is 1 << 23 (vhdx.h:236); vhdx.c:1802-1803.
    chunk_ratio = (1 << 23) * sector_size // block_size
    chunk_ratio_bits = chunk_ratio.bit_length() - 1

    # vhdx_calc_bat_entries, vhdx.c:868-882, for an image with no parent.
    data_blocks = _ceil_div(size, block_size)
    entry_count = data_blocks + ((data_blocks - 1) >> chunk_ratio_bits)

    # Region table: the BAT after the log, the metadata after the BAT, each
    # rounded to 1 MiB (vhdx.c:1828-1836). No region entry's data_bits are
    # set, so Required is 0; both copies are the same buffer (vhdx.c:1859,
    # :1866).
    bat_offset = _round_up(log_offset + log_size, MiB)
    bat_length = _round_up(entry_count * 8, MiB)
    metadata_offset = _round_up(bat_offset + bat_length, MiB)
    metadata_length = 1 * MiB
    region_table = [
        {'region': 'bat', 'offset': bat_offset, 'length': bat_length, 'required': 0},
        {'region': 'metadata', 'offset': metadata_offset, 'length': metadata_length, 'required': 0},
    ]

    # Metadata items packed from 64 KiB into the region, in this order and
    # with these sizes and flags (vhdx.c:1622-1661).
    items = {}
    item_offset = 64 * KiB
    for name, length, flags in (
            ('file_parameters', 8, META_FLAGS_IS_REQUIRED),
            ('virtual_disk_size', 8, META_FLAGS_IS_REQUIRED | META_FLAGS_IS_VIRTUAL_DISK),
            ('page83', 16, META_FLAGS_IS_REQUIRED | META_FLAGS_IS_VIRTUAL_DISK),
            ('logical_sector_size', 4, META_FLAGS_IS_REQUIRED | META_FLAGS_IS_VIRTUAL_DISK),
            ('physical_sector_size', 4, META_FLAGS_IS_REQUIRED | META_FLAGS_IS_VIRTUAL_DISK)):
        items[name] = {'offset': item_offset, 'length': length, 'flags': flags}
        item_offset += length

    # Data starts 5 MiB past the end of the BAT (vhdx.c:1708). A dynamic
    # file ends there (vhdx.c:1714); a fixed one extends past it by the
    # virtual size (vhdx.c:1720).
    data_start = bat_offset + bat_length + 5 * MiB
    file_length = data_start + size if fixed else data_start

    # The BAT region is zeroed (vhdx.c:1735) and then filled for a fixed
    # image or with block_state_zero; a dynamic image without it on a
    # file that reads back as zero is left all zero (vhdx.c:1731-1733).
    # Only payload slots are filled: block j lands at index
    # j + (j >> chunk_ratio_bits) (vhdx.c:1123, :1130), so the slot after
    # each chunk_ratio payload slots is a sector bitmap left zero, and
    # every slot past entry_count is padding. The state is FULLY_PRESENT
    # for fixed, NOT_PRESENT for dynamic, and ZERO if block_state_zero
    # (vhdx.c:1741-1743). A FULLY_PRESENT entry's offset is
    # data_start + j * block_size rounded up to 1 MiB (vhdx.c:1747-1749);
    # every other state stores offset 0 (vhdx.c:1291-1302).
    capacity = bat_length // 8
    payload_indices = {j + (j >> chunk_ratio_bits): j for j in range(data_blocks)}
    filled = fixed or block_state_zero
    if block_state_zero:
        state = PAYLOAD_BLOCK_ZERO
    elif fixed:
        state = PAYLOAD_BLOCK_FULLY_PRESENT
    else:
        state = PAYLOAD_BLOCK_NOT_PRESENT
    entries = []
    for index in range(capacity):
        if index in payload_indices:
            if filled and state == PAYLOAD_BLOCK_FULLY_PRESENT:
                offset = _round_up(data_start + payload_indices[index] * block_size, MiB)
                entries.append((index, 'payload', state, offset))
            elif filled:
                entries.append((index, 'payload', state, 0))
            else:
                entries.append((index, 'payload', PAYLOAD_BLOCK_NOT_PRESENT, 0))
        elif index < entry_count:
            entries.append((index, 'sector_bitmap', 0, 0))
        else:
            entries.append((index, 'padding', 0, 0))

    summary = {
        'file_length': file_length,
        'region_table_1': region_table,
        'region_table_2': region_table,
        'region_tables_agree': True,
        'log_offset': log_offset,
        'log_length': log_size,
        'metadata_items': items,
        'block_size': block_size,
        'logical_sector_size': sector_size,
        'physical_sector_size': sector_size,
        'virtual_disk_size': size,
        # LeaveBlocksAllocated only for a fixed image (vhdx.c:1602-1605).
        'leave_blocks_allocated': fixed,
        'has_parent': False,
        'chunk_ratio': chunk_ratio,
        'bat_capacity': capacity,
        'bat_entry_count': entry_count,
    }
    return summary, entries


class _VhdxTestCase(InstarTestBase):
    """Shared scratch directory and qemu-img wrapper."""

    def setUp(self):
        super().setUp()
        self.workdir = Path(tempfile.mkdtemp(prefix='instar-vhdx-structure-'))
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    def qemu_create(self, name, size, *options):
        """Create `name` with `qemu-img create -f vhdx`, return its path."""
        self._require_qemu_img()
        self.skip_unless_qemu_supports('vhdx')
        path = self.workdir / name
        argv = ['qemu-img', 'create', '-q', '-f', 'vhdx']
        if options:
            argv += ['-o', ','.join(options)]
        argv += [str(path), str(size)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=QEMU_TOOL_TIMEOUT)
        command = ' '.join(argv)
        self.assertEqual(0, result.returncode, f'{command} failed: {result.stderr}')
        return path


class TestVhdxStructureQemuImages(_VhdxTestCase):
    """The parse of a qemu-written image matches qemu's create arithmetic."""

    def assert_qemu_layout(self, size, fixed, block_state_zero, block_size=None):
        options = ['subformat=fixed' if fixed else 'subformat=dynamic',
                   'block_state_zero=on' if block_state_zero else 'block_state_zero=off']
        if block_size is not None:
            options.append(f'block_size={block_size}')
        path = self.qemu_create('image.vhdx', size, *options)
        structure = parse_vhdx(path)

        expected_summary, expected_entries = qemu_create_layout(size, fixed, block_state_zero, block_size)
        actual_summary = summarise(structure)
        del actual_summary['bat']
        self.assertEqual(expected_summary, actual_summary)

        actual_entries = list(structure.bat_entries())
        self.assertEqual(len(expected_entries), len(actual_entries))
        mismatches = [(e, a) for e, a in zip(expected_entries, actual_entries) if e != a]
        self.assertEqual([], mismatches[:5], f'{len(mismatches)} BAT slots differ from qemu\'s arithmetic')

    def test_fixed_64m_zero_blocks(self):
        self.assert_qemu_layout(64 * MiB, fixed=True, block_state_zero=True)

    def test_fixed_64m_fully_present(self):
        self.assert_qemu_layout(64 * MiB, fixed=True, block_state_zero=False)

    def test_fixed_65m_zero_blocks(self):
        self.assert_qemu_layout(65 * MiB, fixed=True, block_state_zero=True)

    def test_fixed_65m_fully_present(self):
        self.assert_qemu_layout(65 * MiB, fixed=True, block_state_zero=False)

    def test_dynamic_64m_zero_blocks(self):
        self.assert_qemu_layout(64 * MiB, fixed=False, block_state_zero=True)

    def test_dynamic_64m_not_present(self):
        self.assert_qemu_layout(64 * MiB, fixed=False, block_state_zero=False)

    def test_dynamic_65m_zero_blocks(self):
        self.assert_qemu_layout(65 * MiB, fixed=False, block_state_zero=True)

    def test_dynamic_65m_not_present(self):
        self.assert_qemu_layout(65 * MiB, fixed=False, block_state_zero=False)

    def test_fixed_64m_1m_blocks_zero_blocks(self):
        self.assert_qemu_layout(64 * MiB, fixed=True, block_state_zero=True, block_size=1 * MiB)

    def test_fixed_64m_1m_blocks_fully_present(self):
        self.assert_qemu_layout(64 * MiB, fixed=True, block_state_zero=False, block_size=1 * MiB)

    def test_dynamic_64m_1m_blocks_zero_blocks(self):
        self.assert_qemu_layout(64 * MiB, fixed=False, block_state_zero=True, block_size=1 * MiB)

    def test_dynamic_64m_1m_blocks_not_present(self):
        self.assert_qemu_layout(64 * MiB, fixed=False, block_state_zero=False, block_size=1 * MiB)

    def test_dynamic_131041m_1m_blocks(self):
        # 131041 payload blocks at a chunk ratio of 4096 need 31 sector
        # bitmap slots, 131072 entries in all: exactly the 1 MiB BAT
        # region, the geometry at which a reader that counts one bitmap
        # slot per started chunk would run past the region.
        self.assert_qemu_layout(131041 * MiB, fixed=False, block_state_zero=True, block_size=1 * MiB)

    def test_dynamic_4096m_1m_blocks(self):
        # 4096 payload blocks are exactly one chunk at a chunk ratio of
        # 4096, so the sector bitmap slot that would follow them lies past
        # the last payload block and is not counted: 4096 entries, not
        # 4097 (vhdx.c:878-879, SPEC(VHDX) 2.5).
        self.assert_qemu_layout(4096 * MiB, fixed=False, block_state_zero=True, block_size=1 * MiB)

    def test_fixed_64m_fully_present_runs(self):
        """The run-length encoding of a simple fixed BAT, written out.

        Eight 8 MiB blocks FULLY_PRESENT from the data start, 8 MiB apart,
        then padding to the end of the 1 MiB region. Data start is the
        2 MiB BAT offset plus its 1 MiB length plus 5 MiB (vhdx.c:1708,
        :1828-1830); offsets advance by the block size (vhdx.c:1747-1749).
        """
        path = self.qemu_create('image.vhdx', 64 * MiB, 'subformat=fixed', 'block_state_zero=off')
        data_start = 2 * MiB + 1 * MiB + 5 * MiB
        expected = [
            [0, 8, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, data_start, 8 * MiB],
            [8, MiB // 8 - 8, 'padding', 0, 0, 0],
        ]
        self.assertEqual(expected, summarise(parse_vhdx(path))['bat'])


class TestVhdxStructuralDiff(_VhdxTestCase):
    """`structural_diff` ignores what varies per run and names what differs."""

    def test_same_command_has_no_difference(self):
        first = self.qemu_create('first.vhdx', 64 * MiB, 'subformat=fixed', 'block_state_zero=off')
        second = self.qemu_create('second.vhdx', 64 * MiB, 'subformat=fixed', 'block_state_zero=off')
        # The premise: the two files are not byte-identical, because qemu
        # generates fresh GUIDs on every create (vhdx.c:1521-1522).
        guids = []
        for path in (first, second):
            with open(path, 'rb') as f:
                f.seek(HEADER_1_OFFSET + HEADER_DATA_WRITE_GUID)
                guids.append(f.read(16))
        self.assertNotEqual(guids[0], guids[1])

        self.assertEqual([], structural_diff(parse_vhdx(first), parse_vhdx(second)))
        self.assertEqual(parse_vhdx(first), parse_vhdx(second))

    def test_fixed_versus_dynamic_names_the_fields(self):
        fixed = parse_vhdx(self.qemu_create('fixed.vhdx', 64 * MiB, 'subformat=fixed'))
        dynamic = parse_vhdx(self.qemu_create('dynamic.vhdx', 64 * MiB, 'subformat=dynamic'))
        differences = structural_diff(fixed, dynamic)
        self.assertIn('leave_blocks_allocated: True != False', differences)
        self.assertIn(f'file_length: {72 * MiB} != {8 * MiB}', differences)
        # Both BATs hold eight ZERO entries at offset 0, so the BAT is not
        # where these two differ.
        self.assertEqual([], [d for d in differences if d.startswith('bat')])

    def test_block_state_zero_modes_name_the_bat(self):
        zero = parse_vhdx(self.qemu_create('zero.vhdx', 64 * MiB, 'subformat=fixed', 'block_state_zero=on'))
        present = parse_vhdx(self.qemu_create('present.vhdx', 64 * MiB, 'subformat=fixed', 'block_state_zero=off'))
        differences = structural_diff(zero, present)
        self.assertEqual(
            ['bat run 0: 8 x payload ZERO from entry 0, offset 0 stride 0 != '
             f'8 x payload FULLY_PRESENT from entry 0, offset {8 * MiB} stride {8 * MiB}'],
            differences)

    def test_summary_round_trips_through_json(self):
        path = self.qemu_create('image.vhdx', 65 * MiB, 'subformat=fixed', 'block_state_zero=off')
        structure = parse_vhdx(path)
        stored = json.loads(json.dumps(summarise(structure)))
        self.assertEqual([], structural_diff(structure, stored))
        self.assertEqual([], structural_diff(stored, structure))
        stored['block_size'] = 1 * MiB
        self.assertEqual([f'block_size: {8 * MiB} != {1 * MiB}'], structural_diff(structure, stored))

    def test_allocation_is_outside_equality_and_summary(self):
        path = self.qemu_create('image.vhdx', 64 * MiB, 'subformat=fixed')
        structure = parse_vhdx(path)
        self.assertEqual(allocated_bytes(path), structure.allocated_bytes)
        # A fixed image is extended sparsely (vhdx.c:1720), so it holds
        # fewer allocated bytes than its length on any sparse filesystem.
        self.assertLess(structure.allocated_bytes, structure.file_length)
        self.assertNotIn('allocated_bytes', summarise(structure))
        moved = dataclasses.replace(structure, allocated_bytes=structure.allocated_bytes + 4096)
        self.assertEqual(structure, moved)
        self.assertEqual([], structural_diff(structure, moved))


class TestVhdxStructureManifest(InstarTestBase):
    """Every safe VHDX fixture in the manifest parses."""

    def test_safe_manifest_fixtures_parse(self):
        fixtures = [image for image in load_manifest_images()
                    if image.get('format') == 'vhdx' and image.get('safety') == 'safe']
        self.assertNotEqual([], fixtures)
        for image in fixtures:
            with self.subTest(image=image['id']):
                structure = parse_vhdx(self._testdata_root / image['path'])
                self.assertIsInstance(structure, VhdxStructure)
                self.assertLessEqual(structure.bat_entry_count, structure.bat_capacity)
                json.dumps(summarise(structure))


class TestVhdxStructureBatEncoding(_VhdxTestCase):
    """The run-length encoding keeps every entry's offset."""

    def test_runs_break_where_the_stride_changes(self):
        path = self.qemu_create('image.vhdx', 64 * MiB, 'subformat=dynamic', 'block_state_zero=off')
        bat_offset = 2 * MiB  # vhdx.c:1830, the 1 MiB log ending at 2 MiB
        # FULLY_PRESENT blocks at 10, 18, 26 and 30 MiB: a constant 8 MiB
        # stride for three entries, then 4 MiB, then a ZERO block.
        written = [(0, 10 * MiB), (1, 18 * MiB), (2, 26 * MiB), (3, 30 * MiB)]
        with open(path, 'r+b') as f:
            for index, offset in written:
                f.seek(bat_offset + index * 8)
                f.write(struct.pack('<Q', offset | PAYLOAD_BLOCK_FULLY_PRESENT))
            f.seek(bat_offset + 4 * 8)
            f.write(struct.pack('<Q', PAYLOAD_BLOCK_ZERO))
        structure = parse_vhdx(path)
        entries = list(structure.bat_entries())[:6]
        self.assertEqual(
            [(0, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 10 * MiB),
             (1, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 18 * MiB),
             (2, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 26 * MiB),
             (3, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 30 * MiB),
             (4, 'payload', PAYLOAD_BLOCK_ZERO, 0),
             (5, 'payload', PAYLOAD_BLOCK_NOT_PRESENT, 0)],
            entries)
        self.assertEqual(
            [[0, 3, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 10 * MiB, 8 * MiB],
             [3, 1, 'payload', PAYLOAD_BLOCK_FULLY_PRESENT, 30 * MiB, 0],
             [4, 1, 'payload', PAYLOAD_BLOCK_ZERO, 0, 0],
             [5, 3, 'payload', PAYLOAD_BLOCK_NOT_PRESENT, 0, 0]],
            summarise(structure)['bat'][:4])


class TestVhdxStructureMalformed(_VhdxTestCase):
    """Malformed files raise VhdxParseError and nothing else."""

    def setUp(self):
        super().setUp()
        self.image = self.qemu_create('image.vhdx', 64 * MiB, 'subformat=dynamic')

    def patched(self, name, offset, data):
        """A copy of the dynamic image with `data` written at `offset`."""
        path = self.workdir / name
        shutil.copyfile(self.image, path)
        with open(path, 'r+b') as f:
            f.seek(offset)
            f.write(data)
        return path

    def test_truncated_files(self):
        # Inside the file identifier, inside header 2, inside region table
        # 1, inside the BAT (2 MiB to 3 MiB) and inside the metadata region
        # (3 MiB to 4 MiB).
        for length in (0, 4, 100 * KiB, 200 * KiB, 2 * MiB + 4096, 3 * MiB + 32 * KiB):
            with self.subTest(length=length):
                path = self.workdir / f'truncated-{length}.vhdx'
                shutil.copyfile(self.image, path)
                os.truncate(path, length)
                self.assertRaises(VhdxParseError, parse_vhdx, path)

    def test_bad_region_table_signature(self):
        for table in (REGION_TABLE_1_OFFSET, REGION_TABLE_2_OFFSET):
            with self.subTest(table=table):
                path = self.patched(f'regi-{table}.vhdx', table, b'xxxx')
                self.assertRaisesRegex(VhdxParseError, 'signature', parse_vhdx, path)

    def test_region_past_eof(self):
        length = os.path.getsize(self.image)
        for entry in (0, 1):
            with self.subTest(entry=entry):
                at = (REGION_TABLE_1_OFFSET + REGION_TABLE_HEADER_SIZE + entry * REGION_TABLE_ENTRY_SIZE
                      + REGION_ENTRY_FILE_OFFSET)
                path = self.patched(f'past-eof-{entry}.vhdx', at, struct.pack('<Q', length))
                self.assertRaisesRegex(VhdxParseError, 'outside', parse_vhdx, path)

    def file_parameters_offset(self):
        structure = parse_vhdx(self.image)
        item = [i for i in structure.metadata_items if i.name == 'file_parameters'][0]
        return structure.metadata_region.offset + item.offset

    def test_zero_block_size(self):
        path = self.patched('zero-block.vhdx', self.file_parameters_offset(), struct.pack('<I', 0))
        self.assertRaisesRegex(VhdxParseError, 'block size', parse_vhdx, path)

    def test_block_size_not_power_of_two(self):
        path = self.patched('odd-block.vhdx', self.file_parameters_offset(), struct.pack('<I', 3 * MiB))
        self.assertRaisesRegex(VhdxParseError, 'power of two', parse_vhdx, path)

    def test_not_a_vhdx(self):
        path = self.workdir / 'raw.img'
        with open(path, 'wb') as f:
            f.truncate(4 * MiB)
        self.assertRaisesRegex(VhdxParseError, 'file identifier', parse_vhdx, path)
        self.assertRaises(VhdxParseError, parse_vhdx, self.workdir / 'missing.vhdx')

    def test_field_corruption_raises_only_parse_error(self):
        """Overwrite every 32-bit field the parser reads, one at a time.

        Covers both headers, region table 1, the metadata table and its
        items. Each corruption either still parses or raises
        VhdxParseError; any other exception fails the test.
        """
        structure = parse_vhdx(self.image)
        metadata = structure.metadata_region.offset
        areas = [
            (HEADER_1_OFFSET, 80),
            (2 * HEADER_1_OFFSET, 80),
            (REGION_TABLE_1_OFFSET, REGION_TABLE_HEADER_SIZE + 2 * REGION_TABLE_ENTRY_SIZE),
            (metadata, 32 + 5 * 32),
            (metadata + 64 * KiB, 40),
        ]
        path = self.workdir / 'corrupt.vhdx'
        shutil.copyfile(self.image, path)
        with open(path, 'r+b') as f:
            for start, length in areas:
                for at in range(start, start + length, 4):
                    f.seek(at)
                    original = f.read(4)
                    for value in (b'\x00\x00\x00\x00', b'\xff\xff\xff\xff'):
                        f.seek(at)
                        f.write(value)
                        f.flush()
                        # Either outcome is fine: some fields tolerate any
                        # value, others make the image unreadable. What
                        # must never happen is any other exception.
                        try:
                            parse_vhdx(path)
                        except VhdxParseError:
                            pass
                        except Exception as e:
                            self.fail(f'{value.hex()} at offset {at} raised {type(e).__name__}: {e}')
                    f.seek(at)
                    f.write(original)
                    f.flush()
