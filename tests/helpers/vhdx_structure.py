"""Structural reading of a VHDX file, for comparing images by layout.

`qemu-img info` cannot tell a fixed VHDX from a dynamic one, or a BAT of
`PAYLOAD_BLOCK_ZERO` entries from one of `PAYLOAD_BLOCK_FULLY_PRESENT`
entries: it reports the virtual size, the block size and little else. Two
writers can therefore produce images that `info` calls identical and that a
reader treats quite differently. This module reads the structures that
decide that -- the region tables, the active header's log location, the
metadata items, the file parameters and every BAT entry -- and reduces them
to the fields that are deterministic for a given creation command, so two
images can be compared by layout.

Compared: the file length; both region tables (entries in order, and
whether the two copies agree); the active header's log offset and length;
the metadata items present, with their offsets, lengths and flags; block
size, logical and physical sector size, virtual disk size; the
`LeaveBlocksAllocated` and `HasParent` bits; the chunk ratio; the BAT
region's capacity and the number of entries SPEC(VHDX) 2.5 says it holds;
and every BAT entry, run-length encoded.

Not compared, because they differ between two runs of the same command or
between filesystems: GUIDs, sequence numbers, checksums, the creator string,
and the bytes the file has allocated. Allocation is still read, as
`VhdxStructure.allocated_bytes`, for relative assertions ("no more than
qemu's image on the same filesystem"), but it is outside equality and the
summary.

Checksums are not validated either. `qemu-img check` and `qemu-img info`
already refuse an image whose header or region table CRC-32C is wrong; this
module's job is the layout those checks cannot see.

The layout facts come from [MS-VHDX] revision 8.0 and qemu's `block/vhdx.h`
and `block/vhdx.c` (7.0.0, in instar-testdata's `qemu-sources/`):

* The file identifier (`vhdxfile`) is at offset 0, the two headers at
  64 KiB and 128 KiB, the two region tables at 192 KiB and 256 KiB
  (`vhdx.h:40-43`). The active header is the one with the higher sequence
  number; on a tie the first wins, the rule instar's reader applies.
* A region table is a 16-byte header (`regi`, checksum, entry count u32 at
  +8, reserved) followed by 32-byte entries (GUID, file offset u64, length
  u32, flags u32 whose bit 0 is Required).
* The metadata region starts with a 32-byte table header (`metadata`,
  reserved, entry count u16 at +10) followed by 32-byte entries (item GUID,
  offset u32 relative to the region, length u32, flags u32, reserved).
* File Parameters is the block size u32 then a flags u32: bit 0
  `LeaveBlocksAllocated`, bit 1 `HasParent` (`vhdx.h:275-279`).
* A BAT entry is a little-endian u64 with the state in bits 0-2 and
  `FileOffsetMB` in bits 20-63 (`vhdx.h:240-241`).
* The chunk ratio is 2^23 x logical sector size / block size, and in the
  BAT every (chunk ratio + 1)th entry is a sector bitmap slot, so entry
  `i` is one when `(i + 1) % (chunk_ratio + 1) == 0`.
* SPEC(VHDX) 2.5 sizes the BAT: payload blocks = ceil(virtual size / block
  size); a dynamic or fixed file has payload + floor((payload - 1) / chunk
  ratio) entries, so the last entry locates the last payload block; a
  differencing file has ceil(payload / chunk ratio) x (chunk ratio + 1).
  qemu's `vhdx_calc_bat_entries` (`vhdx.c:868-882`) agrees. Slots inside
  the BAT region past that count are padding.

Malformed input raises `VhdxParseError`, never `IndexError` or
`struct.error`: the differential fuzzer feeds this module images that may be
wrong, and a parse failure has to be reportable as a finding about the
image. Every offset and length is bounds-checked against the file before it
is read, and the file is read with `seek` and `read` in bounded pieces,
never whole, because a fixed image is as large as its virtual disk.

GUIDs are rendered in the usual text form, which stores the first three
groups little-endian and the last eight bytes as written (the same order
the ad hoc parsers in `tests/test_create.py` and `tests/test_info_safe.py`
use).

Usage::

    from helpers.vhdx_structure import parse_vhdx, structural_diff, summarise
    ours = parse_vhdx(instar_image)
    theirs = parse_vhdx(qemu_image)
    assert not structural_diff(ours, theirs), structural_diff(ours, theirs)
"""

import os
import struct
from dataclasses import dataclass, field
from typing import List, Tuple, Union

KiB = 1024
MiB = 1024 * KiB

FILE_IDENTIFIER_SIGNATURE = b'vhdxfile'
HEADER_OFFSETS = (64 * KiB, 128 * KiB)
HEADER_SIGNATURE = b'head'
HEADER_SEQUENCE_NUMBER = 8
HEADER_LOG_LENGTH = 68
HEADER_LOG_OFFSET = 72
HEADER_PARSED_SIZE = 80

REGION_TABLE_OFFSETS = (192 * KiB, 256 * KiB)
REGION_TABLE_SIZE = 64 * KiB
REGION_TABLE_SIGNATURE = b'regi'
REGION_TABLE_HEADER_SIZE = 16
REGION_TABLE_ENTRY_SIZE = 32
# SPEC(VHDX) 2.2.3.1: EntryCount MUST be at most 2047, which is also every
# entry that fits in the 64 KiB table after its header.
REGION_TABLE_MAX_ENTRIES = 2047

METADATA_TABLE_SIGNATURE = b'metadata'
METADATA_TABLE_SIZE = 64 * KiB
METADATA_TABLE_HEADER_SIZE = 32
METADATA_TABLE_ENTRY_SIZE = 32
# SPEC(VHDX) 2.6.1.1: EntryCount MUST be at most 2047.
METADATA_TABLE_MAX_ENTRIES = 2047
# SPEC(VHDX) 2.6.1.2: bit 0 of a metadata entry's flags is IsUser.
METADATA_FLAG_IS_USER = 0x1

FILE_PARAMETERS_LEAVE_BLOCKS_ALLOCATED = 0x1
FILE_PARAMETERS_HAS_PARENT = 0x2

BAT_ENTRY_SIZE = 8
BAT_STATE_MASK = 0x7
BAT_FILE_OFFSET_MASK = 0xFFFFFFFFFFF00000
# Bound how much of the BAT is held in memory at once. Small enough that
# the all-zero padding after the last entry is mostly whole chunks, which
# `_parse_bat` encodes without unpacking.
BAT_READ_CHUNK = 64 * KiB

# SPEC(VHDX) 2.6.2.1: BlockSize MUST be at least 1 MB and at most 256 MB,
# and a power of two. 2.6.2.4 and 2.6.2.5: both sector sizes MUST be 512
# or 4096.
BLOCK_SIZE_MIN = 1 * MiB
BLOCK_SIZE_MAX = 256 * MiB
SECTOR_SIZES = (512, 4096)
CHUNK_RATIO_NUMERATOR = 1 << 23

KIND_PAYLOAD = 'payload'
KIND_SECTOR_BITMAP = 'sector_bitmap'
KIND_PADDING = 'padding'

# BAT entry states, SPEC(VHDX) 2.5.1.1 and 2.5.1.2 (vhdx.h:224-233). The
# names are for messages; the parse keeps the number.
BAT_STATE_NAMES = {
    0: 'NOT_PRESENT',
    1: 'UNDEFINED',
    2: 'ZERO',
    3: 'UNMAPPED',
    5: 'UNMAPPED_v095',
    6: 'FULLY_PRESENT',
    7: 'PARTIALLY_PRESENT',
}

BAT_REGION_GUID = '2DC27766-F623-4200-9D64-115E9BFD4A08'
METADATA_REGION_GUID = '8B7CA206-4790-4B9A-B8FE-575F050F886E'
FILE_PARAMETERS_GUID = 'CAA16737-FA36-4D43-B3B6-33F0AA44E76B'
VIRTUAL_DISK_SIZE_GUID = '2FA54224-CD1B-4876-B211-5DBED83BF4B8'
PAGE83_GUID = 'BECA12AB-B2E6-4523-93EF-C309E000C746'
LOGICAL_SECTOR_SIZE_GUID = '8141BF1D-A96F-4709-BA47-F233A8FAAB5F'
PHYSICAL_SECTOR_SIZE_GUID = 'CDA348C7-445D-4471-9CC9-E9885251C556'
PARENT_LOCATOR_GUID = 'A8D35F2D-B30B-454D-ABF7-D3D84834AB0C'

# Names for the GUIDs this module knows, used in summaries and messages so
# a difference reads as "metadata item virtual_disk_size" rather than as a
# GUID. Unknown GUIDs are kept in their text form.
GUID_NAMES = {
    BAT_REGION_GUID: 'bat',
    METADATA_REGION_GUID: 'metadata',
    FILE_PARAMETERS_GUID: 'file_parameters',
    VIRTUAL_DISK_SIZE_GUID: 'virtual_disk_size',
    PAGE83_GUID: 'page83',
    LOGICAL_SECTOR_SIZE_GUID: 'logical_sector_size',
    PHYSICAL_SECTOR_SIZE_GUID: 'physical_sector_size',
    PARENT_LOCATOR_GUID: 'parent_locator',
}

# How many differing BAT runs `structural_diff` lists before summarising
# the rest; a wrong stride on a large image differs in every run.
MAX_BAT_DIFFERENCES = 10


class VhdxParseError(ValueError):
    """The file is not a VHDX this module can read structurally."""


@dataclass(frozen=True)
class RegionEntry:
    """One region table entry."""

    guid: str
    offset: int
    length: int
    required: int

    @property
    def name(self) -> str:
        return GUID_NAMES.get(self.guid, self.guid)


@dataclass(frozen=True)
class MetadataItem:
    """One metadata table entry; `offset` is relative to the region."""

    guid: str
    offset: int
    length: int
    flags: int

    @property
    def is_user(self) -> bool:
        return bool(self.flags & METADATA_FLAG_IS_USER)

    @property
    def name(self) -> str:
        """The item's name, marked when it is user metadata.

        SPEC(VHDX) 2.6.1.2 makes the item GUID unique only together with
        the IsUser flag, so a system and a user item may share a GUID.
        """
        name = GUID_NAMES.get(self.guid, self.guid)
        return f'{name} (user)' if self.is_user else name


@dataclass(frozen=True)
class BatRun:
    """Consecutive BAT entries of one kind and state at a constant stride.

    Entry `first_index + k`, for `k` in `range(count)`, has file offset
    `first_offset + k * stride`. A run of one entry has stride 0.
    """

    first_index: int
    count: int
    kind: str
    state: int
    first_offset: int
    stride: int

    def as_list(self) -> list:
        return [self.first_index, self.count, self.kind, self.state, self.first_offset, self.stride]


@dataclass(frozen=True)
class VhdxStructure:
    """The deterministic structure of a VHDX file.

    Equality ignores `allocated_bytes`, which depends on the filesystem.
    """

    file_length: int
    region_table_1: Tuple[RegionEntry, ...]
    region_table_2: Tuple[RegionEntry, ...]
    log_offset: int
    log_length: int
    metadata_items: Tuple[MetadataItem, ...]
    block_size: int
    logical_sector_size: int
    physical_sector_size: int
    virtual_disk_size: int
    leave_blocks_allocated: bool
    has_parent: bool
    chunk_ratio: int
    bat_entry_count: int
    bat_runs: Tuple[BatRun, ...]
    allocated_bytes: int = field(compare=False)

    @property
    def region_tables_agree(self) -> bool:
        return self.region_table_1 == self.region_table_2

    @property
    def bat_region(self) -> RegionEntry:
        return _find_region(self.region_table_1, BAT_REGION_GUID)

    @property
    def metadata_region(self) -> RegionEntry:
        return _find_region(self.region_table_1, METADATA_REGION_GUID)

    @property
    def bat_capacity(self) -> int:
        """How many BAT entries the BAT region has room for."""
        return self.bat_region.length // BAT_ENTRY_SIZE

    def bat_entries(self):
        """Yield `(index, kind, state, file_offset)` for every BAT slot."""
        for run in self.bat_runs:
            for k in range(run.count):
                yield (run.first_index + k, run.kind, run.state, run.first_offset + k * run.stride)


def format_guid(raw: bytes) -> str:
    """Render 16 stored GUID bytes as upper-case text."""
    d1, d2, d3 = struct.unpack_from('<IHH', raw, 0)
    rest = raw[8:16].hex().upper()
    return '{:08X}-{:04X}-{:04X}-{}-{}'.format(d1, d2, d3, rest[:4], rest[4:])


def allocated_bytes(path) -> int:
    """Bytes the filesystem has allocated to `path` (from `st_blocks`).

    Differs between ext4, xfs and tmpfs for the same file, so it is only
    meaningful compared with another file on the same filesystem.
    """
    return os.stat(path).st_blocks * 512


def bat_entry_count(virtual_disk_size: int, block_size: int, chunk_ratio: int, has_parent: bool) -> int:
    """The BAT entry count SPEC(VHDX) 2.5 gives for this geometry."""
    payload = -(-virtual_disk_size // block_size)
    if has_parent:
        bitmaps = -(-payload // chunk_ratio)
        return bitmaps * (chunk_ratio + 1)
    if payload == 0:
        return 0
    return payload + (payload - 1) // chunk_ratio


class _Reader:
    """Bounds-checked reads from an open file of known length."""

    def __init__(self, handle, length: int):
        self.handle = handle
        self.length = length

    def check(self, offset: int, size: int, what: str) -> None:
        if offset < 0 or size < 0 or offset + size > self.length:
            raise VhdxParseError(
                f'{what} at offset {offset} length {size} lies outside the {self.length}-byte file')

    def read(self, offset: int, size: int, what: str) -> bytes:
        self.check(offset, size, what)
        self.handle.seek(offset)
        data = self.handle.read(size)
        if len(data) != size:
            raise VhdxParseError(f'{what} at offset {offset}: read {len(data)} of {size} bytes')
        return data


def _find_region(table: Tuple[RegionEntry, ...], guid: str) -> RegionEntry:
    matches = [entry for entry in table if entry.guid == guid]
    if not matches:
        raise VhdxParseError(f'region table has no {GUID_NAMES[guid]} region')
    if len(matches) > 1:
        raise VhdxParseError(f'region table lists the {GUID_NAMES[guid]} region {len(matches)} times')
    return matches[0]


def _parse_active_header(reader: _Reader) -> Tuple[int, int]:
    """Return the active header's (log_offset, log_length)."""
    best = None
    for offset in HEADER_OFFSETS:
        data = reader.read(offset, HEADER_PARSED_SIZE, f'header at {offset}')
        if data[:4] != HEADER_SIGNATURE:
            continue
        sequence = struct.unpack_from('<Q', data, HEADER_SEQUENCE_NUMBER)[0]
        if best is None or sequence > best[0]:
            log_length = struct.unpack_from('<I', data, HEADER_LOG_LENGTH)[0]
            log_offset = struct.unpack_from('<Q', data, HEADER_LOG_OFFSET)[0]
            best = (sequence, log_offset, log_length)
    if best is None:
        raise VhdxParseError('neither header carries the "head" signature')
    return best[1], best[2]


def _parse_region_table(reader: _Reader, offset: int) -> Tuple[RegionEntry, ...]:
    data = reader.read(offset, REGION_TABLE_SIZE, f'region table at {offset}')
    if data[:4] != REGION_TABLE_SIGNATURE:
        raise VhdxParseError(f'region table at {offset} has signature {data[:4]!r}, not {REGION_TABLE_SIGNATURE!r}')
    count = struct.unpack_from('<I', data, 8)[0]
    if count > REGION_TABLE_MAX_ENTRIES:
        raise VhdxParseError(f'region table at {offset} claims {count} entries, more than {REGION_TABLE_MAX_ENTRIES}')
    entries = []
    for i in range(count):
        at = REGION_TABLE_HEADER_SIZE + i * REGION_TABLE_ENTRY_SIZE
        guid = format_guid(data[at:at + 16])
        file_offset, length, required = struct.unpack_from('<QII', data, at + 16)
        entries.append(RegionEntry(guid, file_offset, length, required))
    return tuple(entries)


def _parse_metadata(reader: _Reader, region: RegionEntry) -> Tuple[Tuple[MetadataItem, ...], dict]:
    """Return the metadata items in table order, and where each system item lies by GUID."""
    if region.length < METADATA_TABLE_SIZE:
        raise VhdxParseError(
            f'metadata region is {region.length} bytes, smaller than its {METADATA_TABLE_SIZE}-byte table')
    reader.check(region.offset, region.length, 'metadata region')
    table = reader.read(region.offset, METADATA_TABLE_SIZE, 'metadata table')
    if table[:8] != METADATA_TABLE_SIGNATURE:
        raise VhdxParseError(f'metadata table has signature {table[:8]!r}, not {METADATA_TABLE_SIGNATURE!r}')
    count = struct.unpack_from('<H', table, 10)[0]
    if count > METADATA_TABLE_MAX_ENTRIES:
        raise VhdxParseError(f'metadata table claims {count} entries, more than {METADATA_TABLE_MAX_ENTRIES}')
    items = []
    seen = set()
    contents = {}
    for i in range(count):
        at = METADATA_TABLE_HEADER_SIZE + i * METADATA_TABLE_ENTRY_SIZE
        guid = format_guid(table[at:at + 16])
        item_offset, item_length, flags = struct.unpack_from('<III', table, at + 16)
        item = MetadataItem(guid, item_offset, item_length, flags)
        if item.name in seen:
            raise VhdxParseError(f'metadata table lists item {item.name} twice')
        seen.add(item.name)
        if item_offset + item_length > region.length:
            raise VhdxParseError(
                f'metadata item {item.name} at region offset {item_offset} length {item_length} '
                f'lies outside the {region.length}-byte metadata region')
        items.append(item)
        if not item.is_user:
            contents[guid] = (item_offset, item_length)
    return tuple(items), contents


def _read_item(reader: _Reader, region: RegionEntry, contents: dict, guid: str, size: int) -> bytes:
    if guid not in contents:
        raise VhdxParseError(f'metadata has no {GUID_NAMES[guid]} item')
    item_offset, item_length = contents[guid]
    if item_length < size:
        raise VhdxParseError(f'metadata item {GUID_NAMES[guid]} is {item_length} bytes, expected at least {size}')
    return reader.read(region.offset + item_offset, size, f'metadata item {GUID_NAMES[guid]}')


def _bat_kind(index: int, entry_count: int, chunk_ratio: int) -> str:
    if index >= entry_count:
        return KIND_PADDING
    if (index + 1) % (chunk_ratio + 1) == 0:
        return KIND_SECTOR_BITMAP
    return KIND_PAYLOAD


def _parse_bat(reader: _Reader, region: RegionEntry, entry_count: int, chunk_ratio: int) -> Tuple[BatRun, ...]:
    """Run-length encode every slot of the BAT region."""
    capacity = region.length // BAT_ENTRY_SIZE
    reader.check(region.offset, region.length, 'BAT region')

    runs = []
    # The open run, as [first_index, count, kind, state, first_offset, stride].
    current = None
    index = 0
    while index < capacity:
        batch = min(capacity - index, BAT_READ_CHUNK // BAT_ENTRY_SIZE)
        data = reader.read(region.offset + index * BAT_ENTRY_SIZE, batch * BAT_ENTRY_SIZE, 'BAT')
        if (index >= entry_count and current is not None
                and current[2] == KIND_PADDING and current[3] == 0 and current[4] == 0
                and (current[1] == 1 or current[5] == 0) and data == bytes(len(data))):
            # Every entry in this chunk is a zero padding slot continuing
            # the open zero padding run: the same result as the loop below,
            # without unpacking thousands of zeros.
            current[1] += batch
            current[5] = 0
            index += batch
            continue
        for (value,) in struct.iter_unpack('<Q', data):
            kind = _bat_kind(index, entry_count, chunk_ratio)
            state = value & BAT_STATE_MASK
            offset = value & BAT_FILE_OFFSET_MASK
            if current is not None and current[2] == kind and current[3] == state:
                if current[1] == 1:
                    current[5] = offset - current[4]
                    current[1] = 2
                    index += 1
                    continue
                if offset == current[4] + current[1] * current[5]:
                    current[1] += 1
                    index += 1
                    continue
            if current is not None:
                runs.append(BatRun(*current))
            current = [index, 1, kind, state, offset, 0]
            index += 1
    if current is not None:
        runs.append(BatRun(*current))
    return tuple(runs)


def parse_vhdx(path) -> VhdxStructure:
    """Read the structure of the VHDX at `path`.

    Raises `VhdxParseError` if the file is not a VHDX whose structures lie
    inside it and hold values SPEC(VHDX) permits.
    """
    try:
        handle = open(path, 'rb')
    except OSError as e:
        raise VhdxParseError(f'cannot open {path}: {e}') from e
    with handle:
        reader = _Reader(handle, os.fstat(handle.fileno()).st_size)
        allocated = allocated_bytes(path)

        if reader.read(0, 8, 'file identifier') != FILE_IDENTIFIER_SIGNATURE:
            raise VhdxParseError(f'no {FILE_IDENTIFIER_SIGNATURE!r} file identifier at offset 0')
        log_offset, log_length = _parse_active_header(reader)
        table_1 = _parse_region_table(reader, REGION_TABLE_OFFSETS[0])
        table_2 = _parse_region_table(reader, REGION_TABLE_OFFSETS[1])
        bat_region = _find_region(table_1, BAT_REGION_GUID)
        metadata_region = _find_region(table_1, METADATA_REGION_GUID)

        items, contents = _parse_metadata(reader, metadata_region)
        block_size, file_flags = struct.unpack(
            '<II', _read_item(reader, metadata_region, contents, FILE_PARAMETERS_GUID, 8))
        virtual_disk_size = struct.unpack(
            '<Q', _read_item(reader, metadata_region, contents, VIRTUAL_DISK_SIZE_GUID, 8))[0]
        logical_sector_size = struct.unpack(
            '<I', _read_item(reader, metadata_region, contents, LOGICAL_SECTOR_SIZE_GUID, 4))[0]
        physical_sector_size = struct.unpack(
            '<I', _read_item(reader, metadata_region, contents, PHYSICAL_SECTOR_SIZE_GUID, 4))[0]

        if block_size == 0 or block_size & (block_size - 1):
            raise VhdxParseError(f'block size {block_size} is not a power of two')
        if not BLOCK_SIZE_MIN <= block_size <= BLOCK_SIZE_MAX:
            raise VhdxParseError(f'block size {block_size} is outside {BLOCK_SIZE_MIN} to {BLOCK_SIZE_MAX}')
        if logical_sector_size not in SECTOR_SIZES:
            raise VhdxParseError(f'logical sector size {logical_sector_size} is not 512 or 4096')
        if physical_sector_size not in SECTOR_SIZES:
            raise VhdxParseError(f'physical sector size {physical_sector_size} is not 512 or 4096')
        chunk_ratio = CHUNK_RATIO_NUMERATOR * logical_sector_size // block_size
        has_parent = bool(file_flags & FILE_PARAMETERS_HAS_PARENT)
        entry_count = bat_entry_count(virtual_disk_size, block_size, chunk_ratio, has_parent)

        runs = _parse_bat(reader, bat_region, entry_count, chunk_ratio)

        return VhdxStructure(
            file_length=reader.length,
            region_table_1=table_1,
            region_table_2=table_2,
            log_offset=log_offset,
            log_length=log_length,
            metadata_items=items,
            block_size=block_size,
            logical_sector_size=logical_sector_size,
            physical_sector_size=physical_sector_size,
            virtual_disk_size=virtual_disk_size,
            leave_blocks_allocated=bool(file_flags & FILE_PARAMETERS_LEAVE_BLOCKS_ALLOCATED),
            has_parent=has_parent,
            chunk_ratio=chunk_ratio,
            bat_entry_count=entry_count,
            bat_runs=runs,
            allocated_bytes=allocated,
        )


def _region_table_summary(table: Tuple[RegionEntry, ...]) -> list:
    return [{'region': entry.name, 'offset': entry.offset, 'length': entry.length, 'required': entry.required}
            for entry in table]


def summarise(structure: VhdxStructure) -> dict:
    """The compared fields of `structure` as a JSON-able dict.

    Metadata items are keyed by name, because SPEC(VHDX) 2.6.1.2 places no
    order on them; region table entries stay a list, in table order.
    """
    return {
        'file_length': structure.file_length,
        'region_table_1': _region_table_summary(structure.region_table_1),
        'region_table_2': _region_table_summary(structure.region_table_2),
        'region_tables_agree': structure.region_tables_agree,
        'log_offset': structure.log_offset,
        'log_length': structure.log_length,
        'metadata_items': {item.name: {'offset': item.offset, 'length': item.length, 'flags': item.flags}
                           for item in structure.metadata_items},
        'block_size': structure.block_size,
        'logical_sector_size': structure.logical_sector_size,
        'physical_sector_size': structure.physical_sector_size,
        'virtual_disk_size': structure.virtual_disk_size,
        'leave_blocks_allocated': structure.leave_blocks_allocated,
        'has_parent': structure.has_parent,
        'chunk_ratio': structure.chunk_ratio,
        'bat_capacity': structure.bat_capacity,
        'bat_entry_count': structure.bat_entry_count,
        'bat': [run.as_list() for run in structure.bat_runs],
    }


def _as_summary(value: Union[VhdxStructure, dict]) -> dict:
    if isinstance(value, VhdxStructure):
        return summarise(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f'expected a VhdxStructure or a summarise() dict, not {type(value).__name__}')


def _describe_run(run) -> str:
    if run is None:
        return 'nothing'
    first_index, count, kind, state, first_offset, stride = run
    state_name = BAT_STATE_NAMES.get(state, str(state))
    return (f'{count} x {kind} {state_name} from entry {first_index}, '
            f'offset {first_offset} stride {stride}')


def _bat_diff(a: list, b: list) -> List[str]:
    differences = []
    for i in range(max(len(a), len(b))):
        run_a = a[i] if i < len(a) else None
        run_b = b[i] if i < len(b) else None
        if run_a != run_b:
            differences.append(f'bat run {i}: {_describe_run(run_a)} != {_describe_run(run_b)}')
    if len(differences) > MAX_BAT_DIFFERENCES:
        hidden = len(differences) - MAX_BAT_DIFFERENCES
        differences = differences[:MAX_BAT_DIFFERENCES] + [f'bat: {hidden} more differing runs']
    if len(a) != len(b):
        differences.insert(0, f'bat: {len(a)} runs != {len(b)} runs')
    return differences


def structural_diff(a: Union[VhdxStructure, dict], b: Union[VhdxStructure, dict]) -> List[str]:
    """Human-readable differences between two structures, empty if equal.

    Either side may be a `VhdxStructure` or the dict `summarise()` made of
    one, so a parsed image can be compared with a stored summary. Each
    message names the field first, then the value in `a`, then in `b`.
    """
    left = _as_summary(a)
    right = _as_summary(b)
    differences = []
    for key in sorted(set(left) | set(right)):
        value_a = left.get(key)
        value_b = right.get(key)
        if value_a == value_b:
            continue
        if key == 'bat' and isinstance(value_a, list) and isinstance(value_b, list):
            differences.extend(_bat_diff(value_a, value_b))
        elif key == 'metadata_items' and isinstance(value_a, dict) and isinstance(value_b, dict):
            for name in sorted(set(value_a) | set(value_b)):
                if value_a.get(name) != value_b.get(name):
                    differences.append(f'metadata item {name}: {value_a.get(name)} != {value_b.get(name)}')
        else:
            differences.append(f'{key}: {value_a!r} != {value_b!r}')
    return differences
