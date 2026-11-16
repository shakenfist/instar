"""Structural reading of a VMDK image, for comparing images by layout.

A VMDK is a descriptor plus one or more extent files, and `qemu-img info`
reports almost none of that: it gives the virtual size and the format, not
how many extents the image was split into, how many sectors each one
declares, what the extents are called, or where a sparse extent put its
grain directory. Two writers can therefore produce images that `info` calls
identical and that a reader walks quite differently -- a split at the wrong
boundary, extents emitted in the wrong order, or a descriptor pointing at a
file that is not the one beside it. This module reads the structures that
decide that, so two images can be compared by layout.

Compared, for the image as a whole: whether the descriptor was embedded in
a sparse file or standalone; the descriptor's `version`, `parentCID` and
`createType`; whether a `CID` line is present; and the extents in
descriptor order. For each extent: the access mode, the declared sector
count, the kind (`SPARSE`, `FLAT`, ...), the filename as the descriptor
spells it, the `FLAT` start offset, and the actual length of the file it
names. For a `SPARSE` extent, the VMDK4 header fields that fix its layout:
version, flags, capacity, grain size, descriptor offset and size, grain
directory and redundant grain directory offsets, and the overhead.

Not compared, deliberately:

* The `CID` value, which is random at create (`block/vmdk.c:2525-2526` in
  qemu 7.0.0, in instar-testdata's `qemu-sources/`); only its presence is
  recorded.
* The `ddb.*` block. It is deterministic, but it is text, and the committed
  `qemu-img` pin already stores the whole descriptor as normalised text, so
  recording it here would be a second, weaker copy of the same oracle.
* `num_gtes_per_gt` and `compressAlgorithm`, and everything a sparse extent
  holds past its header: the grain directory, the grain tables and the
  grain contents. Content parity between two images is established by
  flattening both to raw and comparing that; this module is about the
  container.
* The standalone descriptor file's own length. The `CID` is printed in hex
  without padding, so one create in sixteen writes a descriptor a byte
  shorter than the last, and the length is not a property of the command.

Malformed input raises `VmdkParseError`, never `IndexError`,
`struct.error`, `UnicodeDecodeError` or `OSError`: the differential fuzzer
feeds this module images that may be wrong, and a parse failure has to be
reportable as a finding about the image. Because that input is untrusted,
an extent is opened only when the name on its line resolves inside the
directory holding the descriptor and names a regular file; an absolute
path, a name that climbs out with `..` or through a symlink, a device or
a FIFO is refused rather than opened. Every offset and length is
bounds-checked against the file before it is read, and files are read with
`seek` and `read` in bounded pieces, never whole, because a `FLAT` extent
is as large as the slice of the disk it carries.

The layout facts come from qemu's `block/vmdk.c` (7.0.0):

* `VMDK4Header` (`vmdk.c:79-94`) follows the 4-byte `KDMV` magic and is
  packed, so its fields lie at fixed file offsets with no alignment
  padding. The same offsets are `src/crates/vmdk`'s header constants.
* A sparse file carries its descriptor inside itself, at the sector offset
  and sector count the header records (`vmdk_read_desc`, `vmdk.c:832`);
  qemu reserves 20 sectors for it. An extent of a multi-extent image has
  those fields set but leaves the descriptor area zeroed, so such a file is
  an extent and not an image in its own right.
* Extent lines read `RW <sectors> <KIND> "<filename>" [<offset>]`
  (`vmdk_parse_extents`, `vmdk.c:1077`). The offset is required for `FLAT`
  and absent otherwise, a filename is relative to the directory holding the
  descriptor, and qemu uses only the lines whose access mode is `RW`.
* A standalone descriptor file must carry a `createType` line
  (`vmdk_open_desc_file`, `vmdk.c:1229`), which is what tells it apart from
  a file that is not a VMDK at all. qemu reads at most 1 MiB - 1 of one
  (`vmdk_read_desc`), so a larger file is not a descriptor.

Usage::

    from helpers.vmdk_structure import parse_vmdk, structural_diff, summarise
    ours = parse_vmdk(instar_image)
    theirs = parse_vmdk(qemu_image)
    assert not structural_diff(ours, theirs), structural_diff(ours, theirs)
"""

import os
import re
import stat
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

SECTOR_SIZE = 512

VMDK4_MAGIC = b'KDMV'
VMDK3_MAGIC = b'COWD'

# VMDK4 header fields, as file offsets: the magic, then the packed
# VMDK4Header. `num_gtes_per_gt` (44) and `compressAlgorithm` (77) are
# deliberately not read; see the module docstring.
HEADER_VERSION = 4
HEADER_FLAGS = 8
HEADER_CAPACITY = 12
HEADER_GRAIN_SIZE = 20
HEADER_DESCRIPTOR_OFFSET = 28
HEADER_DESCRIPTOR_SIZE = 36
HEADER_RGD_OFFSET = 48
HEADER_GD_OFFSET = 56
HEADER_OVERHEAD = 64
# Everything above lies in the first 72 bytes, which is what is read.
HEADER_PARSED_SIZE = 72

# A grain directory offset of all ones says the directory is written at the
# end of the stream rather than at a known offset (streamOptimized), so it
# is a sentinel and not something to bounds-check.
GD_AT_END = 0xFFFFFFFFFFFFFFFF

# VMDK4 header flags, named for diagnostics only; the parse keeps the word.
FLAG_NAMES = (
    (1 << 0, 'valid_new_line'),
    (1 << 1, 'use_rgd'),
    (1 << 2, 'zero_grain'),
    (1 << 16, 'compressed'),
    (1 << 17, 'marker'),
)

# The most a standalone descriptor file may be, matching what qemu will
# read of one. Anything larger is some other file -- a FLAT extent, say --
# and not a descriptor.
MAX_DESCRIPTOR_BYTES = (1 << 20) - 1

# `RW 4194304 SPARSE "image-s001.vmdk"`, or a FLAT line with its start
# offset in sectors after the filename. A ZERO extent carries no filename.
EXTENT_LINE = re.compile(
    r'^(?P<access>RW|RDONLY|NOACCESS)\s+(?P<sectors>\d+)\s+(?P<kind>[A-Z]+)'
    r'(?:\s+"(?P<filename>[^"]*)"(?:\s+(?P<offset>\d+))?)?\s*$')

# A line opening with an access mode is an extent line, whether or not the
# rest of it parses. Anything else in a descriptor -- `version=1`, a
# `ddb.*` entry, a comment -- is not, and is passed over.
EXTENT_LINE_START = re.compile(r'^(?:RW|RDONLY|NOACCESS)\b')

KIND_SPARSE = 'SPARSE'
KIND_FLAT = 'FLAT'
KIND_ZERO = 'ZERO'

# `version=1`, `CID=1b59c15a`, `createType="twoGbMaxExtentSparse"`.
DESCRIPTOR_FIELD = re.compile(r'^(?P<name>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?P<value>.*?)\s*$')


class VmdkParseError(ValueError):
    """The file is not a VMDK this module can read structurally."""


def describe_flags(flags: int) -> str:
    """`flags` as its named bits, for a message; `0` has no names."""
    names = [name for bit, name in FLAG_NAMES if flags & bit]
    unknown = flags & ~sum(bit for bit, _ in FLAG_NAMES)
    if unknown:
        names.append(f'unknown {unknown:#x}')
    return '|'.join(names) if names else 'none'


@dataclass(frozen=True)
class SparseHeader:
    """The VMDK4 header fields that fix a sparse extent's layout.

    Sector counts and sector offsets are as the header stores them, which
    is in 512-byte sectors.
    """

    version: int
    flags: int
    capacity_sectors: int
    grain_size_sectors: int
    descriptor_offset_sectors: int
    descriptor_size_sectors: int
    rgd_offset_sectors: int
    gd_offset_sectors: int
    overhead_sectors: int

    def as_dict(self) -> dict:
        return {
            'version': self.version,
            'flags': self.flags,
            'capacity_sectors': self.capacity_sectors,
            'grain_size_sectors': self.grain_size_sectors,
            'descriptor_offset_sectors': self.descriptor_offset_sectors,
            'descriptor_size_sectors': self.descriptor_size_sectors,
            'rgd_offset_sectors': self.rgd_offset_sectors,
            'gd_offset_sectors': self.gd_offset_sectors,
            'overhead_sectors': self.overhead_sectors,
        }


@dataclass(frozen=True)
class Extent:
    """One extent: what the descriptor declares, and what the file is.

    `filename` is the name as the descriptor spells it, not the path it
    resolved to, so two images built by the same command in different
    directories compare equal. `flat_offset_sectors` is the start offset a
    `FLAT` line carries and is None for every other kind; `file_length` and
    `header` are None for a kind that names no file.
    """

    index: int
    access: str
    sectors: int
    kind: str
    filename: Optional[str]
    flat_offset_sectors: Optional[int]
    file_length: Optional[int]
    header: Optional[SparseHeader]

    def as_dict(self) -> dict:
        return {
            'access': self.access,
            'sectors': self.sectors,
            'kind': self.kind,
            'filename': self.filename,
            'flat_offset_sectors': self.flat_offset_sectors,
            'file_length': self.file_length,
            'header': self.header.as_dict() if self.header is not None else None,
        }


@dataclass(frozen=True)
class VmdkStructure:
    """The deterministic structure of a VMDK image.

    `has_cid` rather than the CID itself: the value is random at create.
    """

    descriptor_embedded: bool
    version: Optional[str]
    has_cid: bool
    parent_cid: Optional[str]
    create_type: Optional[str]
    extents: Tuple[Extent, ...]

    @property
    def extent_count(self) -> int:
        return len(self.extents)

    @property
    def total_sectors(self) -> int:
        """The sectors the extents declare between them."""
        return sum(extent.sectors for extent in self.extents)


class _Reader:
    """Bounds-checked reads from an open file of known length."""

    def __init__(self, handle, length: int, what: str):
        self.handle = handle
        self.length = length
        self.what = what

    def check(self, offset: int, size: int, what: str) -> None:
        if offset < 0 or size < 0 or offset + size > self.length:
            raise VmdkParseError(
                f'{self.what}: {what} at offset {offset} length {size} lies outside '
                f'the {self.length}-byte file')

    def read(self, offset: int, size: int, what: str) -> bytes:
        self.check(offset, size, what)
        self.handle.seek(offset)
        try:
            data = self.handle.read(size)
        except OSError as e:
            raise VmdkParseError(f'{self.what}: cannot read {what} at offset {offset}: {e}') from e
        if len(data) != size:
            raise VmdkParseError(f'{self.what}: {what} at offset {offset}: read {len(data)} of {size} bytes')
        return data


def _open_reader(path, what: str):
    """Open `path` for a bounds-checked read, raising `VmdkParseError`.

    Opened without blocking and refused unless it is a regular file. An
    extent line can name a FIFO, which a plain `open` waits on until
    something writes to it -- hanging a fuzzer that has no timeout around
    this module -- or a device, whose length is not a property of the
    image.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as e:
        raise VmdkParseError(f'{what}: cannot open {path}: {e}') from e
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VmdkParseError(f'{what}: {path} is not a regular file')
        handle = os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise
    return handle, _Reader(handle, info.st_size, what)


def _parse_sparse_header(reader: _Reader) -> SparseHeader:
    """Read the VMDK4 header at offset 0, or raise."""
    data = reader.read(0, HEADER_PARSED_SIZE, 'VMDK4 header')
    if data[:4] != VMDK4_MAGIC:
        raise VmdkParseError(f'{reader.what}: magic is {data[:4]!r}, not {VMDK4_MAGIC!r}')
    version, flags = struct.unpack_from('<II', data, HEADER_VERSION)
    capacity, grain_size = struct.unpack_from('<QQ', data, HEADER_CAPACITY)
    descriptor_offset, descriptor_size = struct.unpack_from('<QQ', data, HEADER_DESCRIPTOR_OFFSET)
    rgd_offset = struct.unpack_from('<Q', data, HEADER_RGD_OFFSET)[0]
    gd_offset = struct.unpack_from('<Q', data, HEADER_GD_OFFSET)[0]
    overhead = struct.unpack_from('<Q', data, HEADER_OVERHEAD)[0]

    if grain_size == 0:
        raise VmdkParseError(f'{reader.what}: the header declares a grain size of zero')
    # An offset of zero means the structure is absent; all ones means a
    # grain directory written at the end of the stream. Anything else has
    # to lie inside the file, or the image cannot be walked.
    for name, sectors in (('grain directory', gd_offset), ('redundant grain directory', rgd_offset)):
        if sectors in (0, GD_AT_END):
            continue
        reader.check(sectors * SECTOR_SIZE, SECTOR_SIZE, name)

    return SparseHeader(
        version=version,
        flags=flags,
        capacity_sectors=capacity,
        grain_size_sectors=grain_size,
        descriptor_offset_sectors=descriptor_offset,
        descriptor_size_sectors=descriptor_size,
        rgd_offset_sectors=rgd_offset,
        gd_offset_sectors=gd_offset,
        overhead_sectors=overhead,
    )


def _decode(raw: bytes, what: str) -> str:
    """Decode descriptor bytes, which qemu pads with NULs, as text."""
    try:
        return raw.rstrip(b'\0').decode('utf-8')
    except UnicodeDecodeError as e:
        raise VmdkParseError(f'{what}: the descriptor is not UTF-8 text: {e}') from e


def read_descriptor(path) -> Tuple[str, bool]:
    """Return `(descriptor_text, embedded)` for the VMDK at `path`.

    A file beginning with the `KDMV` magic carries its descriptor inside
    itself, at the sector offset and count its header records; any other
    file is a standalone descriptor, which has to carry a `createType` line
    to be one at all. Raises `VmdkParseError` for anything else.
    """
    handle, reader = _open_reader(path, str(path))
    with handle:
        head = reader.read(0, 4, 'magic')
        if head == VMDK4_MAGIC:
            header = _parse_sparse_header(reader)
            offset = header.descriptor_offset_sectors * SECTOR_SIZE
            size = header.descriptor_size_sectors * SECTOR_SIZE
            if size == 0:
                raise VmdkParseError(f'{path}: the sparse header reserves no descriptor')
            return _decode(reader.read(offset, size, 'embedded descriptor'), str(path)), True
        if head == VMDK3_MAGIC:
            raise VmdkParseError(f'{path}: a VMDK3 ({VMDK3_MAGIC.decode()}) image is not read structurally')
        if reader.length > MAX_DESCRIPTOR_BYTES:
            raise VmdkParseError(
                f'{path}: {reader.length} bytes with no {VMDK4_MAGIC!r} magic is larger than the '
                f'{MAX_DESCRIPTOR_BYTES}-byte maximum for a descriptor file')
        text = _decode(reader.read(0, reader.length, 'descriptor'), str(path))
    if not _descriptor_field(text, 'createType'):
        raise VmdkParseError(f'{path}: no {VMDK4_MAGIC!r} magic and no createType line, so not a VMDK')
    return text, False


def _descriptor_field(text: str, name: str) -> Optional[str]:
    """The value of the `name=` line, unquoted, or None if there is none."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = DESCRIPTOR_FIELD.match(line)
        if match is None or match.group('name') != name:
            continue
        value = match.group('value')
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        return value
    return None


def descriptor_extents(text: str) -> List[dict]:
    """The extent lines of `text`, in order, as parsed fields.

    Each is `{'access', 'sectors', 'kind', 'filename', 'flat_offset_sectors'}`,
    the last two None when the line carries no filename or no offset. This
    touches no extent file, so a caller that has to describe an image whose
    extents are missing -- a create that failed part way, say -- can read
    the names out of the descriptor without `parse_vmdk` refusing it.

    A line that opens with an access mode but does not parse raises, rather
    than being passed over: a descriptor with one good extent line and
    three broken ones is a corrupt image, not a one-extent image.
    """
    extents = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = EXTENT_LINE.match(line)
        if match is None:
            if EXTENT_LINE_START.match(line):
                # Skipping it would report a corrupt image as a smaller
                # intact one, which is the wrong answer rather than a
                # missing one.
                raise VmdkParseError(f'malformed extent line: {line!r}')
            continue
        sectors = int(match.group('sectors'))
        offset = match.group('offset')
        extents.append({
            'access': match.group('access'),
            'sectors': sectors,
            'kind': match.group('kind'),
            'filename': match.group('filename'),
            'flat_offset_sectors': None if offset is None else int(offset),
        })
    return extents


def resolve_extent_path(filename: str, directory, what: str) -> str:
    """Resolve an extent filename against the directory holding its descriptor.

    A descriptor is untrusted input, and the filename on an extent line is
    whatever its writer put there. qemu resolves one relative to the
    descriptor's own directory, so anything that leaves that directory --
    an absolute path, a `..` that climbs out of it, a symlink pointing
    away -- names a file this image does not own, and is refused rather
    than opened and measured.
    """
    if os.path.isabs(filename):
        raise VmdkParseError(f'{what}: absolute extent path {filename!r}')
    base = os.path.realpath(str(directory))
    path = os.path.realpath(os.path.join(base, filename))
    if path != base and not path.startswith(base + os.sep):
        raise VmdkParseError(f'{what}: extent path {filename!r} resolves outside {base}')
    return path


def _parse_extent(index: int, declared: dict, directory) -> Extent:
    """Resolve one declared extent against the file it names."""
    filename = declared['filename']
    kind = declared['kind']
    if declared['sectors'] <= 0:
        raise VmdkParseError(f'extent {index} declares {declared["sectors"]} sectors')
    if filename is None:
        if kind != KIND_ZERO:
            raise VmdkParseError(f'extent {index} is a {kind} extent with no filename')
        return Extent(index=index, access=declared['access'], sectors=declared['sectors'], kind=kind,
                      filename=None, flat_offset_sectors=None, file_length=None, header=None)
    if kind == KIND_FLAT and declared['flat_offset_sectors'] is None:
        raise VmdkParseError(f'extent {index} is a FLAT extent with no start offset')

    what = f'extent {index} ({filename})'
    path = resolve_extent_path(filename, directory, what)
    handle, reader = _open_reader(path, what)
    with handle:
        header = _parse_sparse_header(reader) if kind == KIND_SPARSE else None
        length = reader.length
    return Extent(index=index, access=declared['access'], sectors=declared['sectors'], kind=kind,
                  filename=filename, flat_offset_sectors=declared['flat_offset_sectors'],
                  file_length=length, header=header)


def parse_vmdk(path) -> VmdkStructure:
    """Read the structure of the VMDK at `path`.

    `path` is the descriptor: either a standalone one, or the sparse file
    that embeds it. Every extent it names is resolved relative to the
    directory holding it and opened, so a descriptor pointing at a file
    that is not there is a parse failure rather than a silent gap.

    Raises `VmdkParseError` if the file is not a VMDK, if an extent it
    names cannot be read, or if a structure lies outside the file holding
    it.
    """
    text, embedded = read_descriptor(path)
    declared = descriptor_extents(text)
    if not declared:
        raise VmdkParseError(f'{path}: the descriptor declares no extents')
    directory = os.path.dirname(os.path.abspath(os.fspath(path)))
    extents = tuple(_parse_extent(index, one, directory) for index, one in enumerate(declared))
    return VmdkStructure(
        descriptor_embedded=embedded,
        version=_descriptor_field(text, 'version'),
        has_cid=_descriptor_field(text, 'CID') is not None,
        parent_cid=_descriptor_field(text, 'parentCID'),
        create_type=_descriptor_field(text, 'createType'),
        extents=extents,
    )


def summarise(structure: VmdkStructure) -> dict:
    """The compared fields of `structure` as a JSON-able dict.

    Extents stay a list, in descriptor order, because the order is part of
    what is compared: the same extents in the wrong order is a different
    image.
    """
    return {
        'descriptor_embedded': structure.descriptor_embedded,
        'version': structure.version,
        'has_cid': structure.has_cid,
        'parent_cid': structure.parent_cid,
        'create_type': structure.create_type,
        'extent_count': structure.extent_count,
        'total_sectors': structure.total_sectors,
        'extents': [extent.as_dict() for extent in structure.extents],
    }


def _as_summary(value: Union[VmdkStructure, dict]) -> dict:
    if isinstance(value, VmdkStructure):
        return summarise(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f'expected a VmdkStructure or a summarise() dict, not {type(value).__name__}')


def _describe(key: str, value) -> str:
    if key == 'flags' and isinstance(value, int):
        return f'{value} ({describe_flags(value)})'
    return repr(value)


def _header_diff(index: int, a: Optional[dict], b: Optional[dict]) -> List[str]:
    if a is None or b is None:
        return [f'extent {index} header: {"present" if a is not None else "absent"} != '
                f'{"present" if b is not None else "absent"}']
    differences = []
    for key in sorted(set(a) | set(b)):
        if a.get(key) != b.get(key):
            differences.append(f'extent {index} header {key}: {_describe(key, a.get(key))} != '
                               f'{_describe(key, b.get(key))}')
    return differences


def _extent_diff(a: list, b: list) -> List[str]:
    differences = []
    if len(a) != len(b):
        differences.append(f'extents: {len(a)} != {len(b)}')
    for index in range(max(len(a), len(b))):
        if index >= len(a) or index >= len(b):
            missing = 'a' if index >= len(a) else 'b'
            differences.append(f'extent {index}: missing from {missing}')
            continue
        left, right = a[index], b[index]
        for key in sorted(set(left) | set(right)):
            if left.get(key) == right.get(key):
                continue
            if key == 'header':
                differences.extend(_header_diff(index, left.get(key), right.get(key)))
            else:
                differences.append(f'extent {index} {key}: {left.get(key)!r} != {right.get(key)!r}')
    return differences


def structural_diff(a: Union[VmdkStructure, dict], b: Union[VmdkStructure, dict]) -> List[str]:
    """Human-readable differences between two structures, empty if equal.

    Either side may be a `VmdkStructure` or the dict `summarise()` made of
    one, so a parsed image can be compared with a stored summary. Each
    message names the field first -- and the extent it belongs to, where it
    is one of an extent's -- then the value in `a`, then in `b`.
    """
    left = _as_summary(a)
    right = _as_summary(b)
    differences = []
    for key in sorted(set(left) | set(right)):
        value_a = left.get(key)
        value_b = right.get(key)
        if value_a == value_b:
            continue
        if key == 'extents' and isinstance(value_a, list) and isinstance(value_b, list):
            differences.extend(_extent_diff(value_a, value_b))
        else:
            differences.append(f'{key}: {value_a!r} != {value_b!r}')
    return differences
