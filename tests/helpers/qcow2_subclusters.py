"""qcow2 fixtures whose per-subcluster ownership is known by construction.

Every builder here makes a small qcow2 image in a caller-supplied directory
and returns a `SubclusterFixture`: the image path, its companion backing and
data files, and for every subcluster of the virtual disk the qemu subcluster
type and the device its bytes must come from (`OWNERS`). That is what lets a
test tell a hole from a zero: the backing file is filled with position-
dependent non-zero bytes, so a subcluster that should read from the backing
file and reads zeros instead (or the reverse) is visible in the output.

Well-formed shapes are written by `qemu-img create` and `qemu-io` only.
Shapes qemu will not write (the invalid ones, and the compressed entry with
a bitmap) are made by patching one L2 entry or bitmap of a qemu-built image
with `struct`.

The expected types are not hand-written. They are derived from the L2
entries actually present in the built image by `qemu_subcluster_type`, a
transcription of `qcow2_get_cluster_type` and `qcow2_get_subcluster_type`
(qemu v10.0.0 `block/qcow2.h:713-796`). Ownership then follows qemu's read
path (`block/qcow2.c:2414-2420` and `block/qcow2-cluster.c:666-719`). Each
builder also states which types it exists to exhibit, and fails loudly if
qemu stops producing them, so a change in qemu's allocation behaviour cannot
quietly turn a fixture into a different one.

Usage::

    from helpers import qcow2_subclusters
    fixture = qcow2_subclusters.BUILDERS['data_file_partial'](tmpdir)
    fixture.path, fixture.ownership, fixture.expected_raw
"""

import dataclasses
import struct
import subprocess
from pathlib import Path
from typing import Callable, Dict, FrozenSet, Optional, Sequence, Tuple

# qemu's subcluster types (block/qcow2.h:540-548, QCow2SubclusterType).
NORMAL = 'normal'
ZERO_ALLOC = 'zero-alloc'
ZERO_PLAIN = 'zero-plain'
UNALLOCATED_ALLOC = 'unallocated-alloc'
UNALLOCATED_PLAIN = 'unallocated-plain'
COMPRESSED = 'compressed'
INVALID = 'invalid'
SUBCLUSTER_TYPES = (NORMAL, ZERO_ALLOC, ZERO_PLAIN, UNALLOCATED_ALLOC, UNALLOCATED_PLAIN, COMPRESSED, INVALID)

# Where a subcluster's bytes come from.
CHILD = 'child'          # the qcow2 file itself, at the entry's host offset
DATA_FILE = 'data-file'  # the external data file, at the entry's host offset
BACKING = 'backing'      # the backing file, at the same virtual offset
ZERO = 'zero'            # zeros, from no device at all
REFUSE = 'refuse'        # the read fails; qemu returns EIO
OWNERS = (CHILD, DATA_FILE, BACKING, ZERO, REFUSE)

# block/qcow2.h:75-96, 256-263 and 591-593.
QCOW_OFLAG_COPIED = 1 << 63
QCOW_OFLAG_COMPRESSED = 1 << 62
QCOW_OFLAG_ZERO = 1
L1E_OFFSET_MASK = 0x00fffffffffffe00
L2E_OFFSET_MASK = 0x00fffffffffffe00
L2_BITMAP_ALL_ALLOC = 0x00000000ffffffff
INCOMPAT_DATA_FILE = 1 << 2
INCOMPAT_EXTL2 = 1 << 4

SUBCLUSTERS_PER_CLUSTER = 32
CLUSTERS_PER_FIXTURE = 8


def sub_alloc(index: int) -> int:
    """Return the bitmap bit that marks subcluster `index` allocated."""
    return 1 << index


def sub_zero(index: int) -> int:
    """Return the bitmap bit that marks subcluster `index` as reading zeros."""
    return 1 << (index + 32)


def qemu_cluster_type(l2_entry: int, extended_l2: bool, has_data_file: bool) -> str:
    """Transcribe qemu's qcow2_get_cluster_type (block/qcow2.h:713-737).

    Returns 'compressed', 'zero-plain', 'zero-alloc', 'unallocated' or 'normal'.
    Note line 729: with an external data file, host offset 0 is a real offset
    and an entry of QCOW_OFLAG_COPIED | 0 is a normal cluster.
    """
    if l2_entry & QCOW_OFLAG_COMPRESSED:
        return 'compressed'
    if (l2_entry & QCOW_OFLAG_ZERO) and not extended_l2:
        if l2_entry & L2E_OFFSET_MASK:
            return 'zero-alloc'
        return 'zero-plain'
    if not l2_entry & L2E_OFFSET_MASK:
        if has_data_file and (l2_entry & QCOW_OFLAG_COPIED):
            return 'normal'
        return 'unallocated'
    return 'normal'


def qemu_subcluster_type(l2_entry: int, l2_bitmap: int, sc_index: int, extended_l2: bool,
                         has_data_file: bool) -> str:
    """Transcribe qemu's qcow2_get_subcluster_type (block/qcow2.h:747-796).

    As in qemu, INVALID is a property of the whole entry and bitmap, not of
    the bits for `sc_index` alone (block/qcow2.h:741-745). Without extended
    L2 the bitmap is ignored and every cluster is one subcluster.
    """
    cluster_type = qemu_cluster_type(l2_entry, extended_l2, has_data_file)
    if not extended_l2:
        return {
            'compressed': COMPRESSED,
            'zero-plain': ZERO_PLAIN,
            'zero-alloc': ZERO_ALLOC,
            'normal': NORMAL,
            'unallocated': UNALLOCATED_PLAIN,
        }[cluster_type]

    if cluster_type == 'compressed':
        return COMPRESSED
    if cluster_type == 'normal':
        if (l2_bitmap >> 32) & l2_bitmap:
            return INVALID
        if l2_bitmap & sub_zero(sc_index):
            return ZERO_ALLOC
        if l2_bitmap & sub_alloc(sc_index):
            return NORMAL
        return UNALLOCATED_ALLOC
    # cluster_type == 'unallocated'
    if l2_bitmap & L2_BITMAP_ALL_ALLOC:
        return INVALID
    if l2_bitmap & sub_zero(sc_index):
        return ZERO_PLAIN
    return UNALLOCATED_PLAIN


def qemu_owner(sc_type: str, l2_entry: int, guest_cluster_offset: int, cluster_size: int,
               has_backing: bool, has_data_file: bool) -> str:
    """Return the device qemu reads a subcluster of type `sc_type` from.

    The read path is block/qcow2.c:2414-2420 (zero types, and unallocated
    types with no backing file, read zeros; everything else becomes a read
    task) and block/qcow2-cluster.c:666-719, which also refuses three shapes
    that classify as valid: a compressed entry in an image with a data file
    (:668-678), an unaligned host offset (:682-695), and a data-file host
    offset that differs from the guest offset (:696-705).
    """
    if sc_type == INVALID:
        return REFUSE
    if sc_type == COMPRESSED:
        return REFUSE if has_data_file else CHILD
    if sc_type in (NORMAL, ZERO_ALLOC, UNALLOCATED_ALLOC):
        host = l2_entry & L2E_OFFSET_MASK
        if host % cluster_size:
            return REFUSE
        if has_data_file and host != guest_cluster_offset:
            return REFUSE
    if sc_type in (ZERO_ALLOC, ZERO_PLAIN):
        return ZERO
    if sc_type in (UNALLOCATED_ALLOC, UNALLOCATED_PLAIN):
        return BACKING if has_backing else ZERO
    return DATA_FILE if has_data_file else CHILD


@dataclasses.dataclass(frozen=True)
class L2Slot:
    """One virtual cluster's L2 entry, and where it sits in the image file."""
    cluster_index: int
    entry_offset: int  # file offset of the 64-bit L2 word; 0 if no L2 table
    entry: int
    bitmap: int        # always 0 without extended L2


@dataclasses.dataclass(frozen=True)
class Qcow2Layout:
    """The header fields and L2 slots a fixture's expectations depend on."""
    cluster_size: int
    virtual_size: int
    extended_l2: bool
    has_data_file: bool
    slots: Tuple[L2Slot, ...]


def read_layout(path: Path) -> Qcow2Layout:
    """Parse the header and every L2 slot covering the virtual disk.

    The L1 offset is at header byte 40, an L2 offset is the L1 entry masked
    with L1E_OFFSET_MASK, and extended L2 entries are 16 bytes (the L2 word
    then the subcluster bitmap), classic ones 8.
    """
    with open(path, 'rb') as f:
        header = f.read(104)
        if header[:4] != b'QFI\xfb':
            raise ValueError(f'{path} is not a qcow2 image')
        cluster_bits = struct.unpack('>I', header[20:24])[0]
        virtual_size = struct.unpack('>Q', header[24:32])[0]
        l1_size = struct.unpack('>I', header[36:40])[0]
        l1_offset = struct.unpack('>Q', header[40:48])[0]
        version = struct.unpack('>I', header[4:8])[0]
        incompat = struct.unpack('>Q', header[72:80])[0] if version >= 3 else 0
        extended_l2 = bool(incompat & INCOMPAT_EXTL2)
        cluster_size = 1 << cluster_bits
        entry_size = 16 if extended_l2 else 8
        entries_per_l2 = cluster_size // entry_size

        f.seek(l1_offset)
        l1 = struct.unpack(f'>{l1_size}Q', f.read(8 * l1_size))
        n_clusters = (virtual_size + cluster_size - 1) // cluster_size
        slots = []
        for index in range(n_clusters):
            l2_offset = l1[index // entries_per_l2] & L1E_OFFSET_MASK
            if not l2_offset:
                slots.append(L2Slot(index, 0, 0, 0))
                continue
            entry_offset = l2_offset + (index % entries_per_l2) * entry_size
            f.seek(entry_offset)
            raw = f.read(entry_size)
            entry = struct.unpack('>Q', raw[:8])[0]
            bitmap = struct.unpack('>Q', raw[8:16])[0] if extended_l2 else 0
            slots.append(L2Slot(index, entry_offset, entry, bitmap))
    return Qcow2Layout(cluster_size, virtual_size, extended_l2, bool(incompat & INCOMPAT_DATA_FILE),
                       tuple(slots))


def patch_l2(path: Path, cluster_index: int, entry: Optional[int] = None, bitmap: Optional[int] = None) -> None:
    """Overwrite one virtual cluster's L2 word and/or subcluster bitmap in place."""
    layout = read_layout(path)
    slot = layout.slots[cluster_index]
    if not slot.entry_offset:
        raise ValueError(f'{path}: cluster {cluster_index} has no L2 table to patch')
    if bitmap is not None and not layout.extended_l2:
        raise ValueError(f'{path}: no subcluster bitmap without extended L2')
    with open(path, 'r+b') as f:
        if entry is not None:
            f.seek(slot.entry_offset)
            f.write(struct.pack('>Q', entry))
        if bitmap is not None:
            f.seek(slot.entry_offset + 8)
            f.write(struct.pack('>Q', bitmap))


def backing_byte(offset: int) -> int:
    """Return the backing file's byte at `offset`: never zero, varies per 512-byte sector."""
    return (offset // 512) % 255 + 1


def backing_content(size: int) -> bytes:
    """Return `size` bytes of backing content, as `backing_byte` describes."""
    return b''.join(bytes([backing_byte(o)]) * 512 for o in range(0, size, 512))[:size]


@dataclasses.dataclass(frozen=True)
class SubclusterFixture:
    """A built qcow2 image and what reading each of its subclusters must yield.

    `types` and `ownership` have one element per subcluster of the virtual
    disk, in virtual order; a classic (non-extended) image has one subcluster
    per cluster. `expected_raw` is the whole virtual disk as qemu reads it, or
    None when any subcluster is REFUSE, because qemu then fails the read.
    """
    name: str
    description: str
    path: Path
    backing: Optional[Path]
    data_file: Optional[Path]
    cluster_size: int
    extended_l2: bool
    virtual_size: int
    slots: Tuple[L2Slot, ...]
    types: Tuple[str, ...]
    ownership: Tuple[str, ...]
    expected_raw: Optional[bytes]

    @property
    def subcluster_size(self) -> int:
        """Return the subcluster size in bytes (the cluster size without extended L2)."""
        if self.extended_l2:
            return self.cluster_size // SUBCLUSTERS_PER_CLUSTER
        return self.cluster_size

    @property
    def refuses(self) -> bool:
        """Return True when qemu fails the read of at least one subcluster."""
        return REFUSE in self.ownership


# A qemu-io operation: ('write', pattern, offset, length) writes a byte
# pattern, ('compress', pattern, offset, length) writes it compressed, and
# ('zero', offset, length) is `write -z`.
Op = Tuple

# An L2 patch: (cluster_index, new L2 word or None, new bitmap or None).
Patch = Tuple[int, Optional[int], Optional[int]]


def _run(argv: Sequence[str]) -> None:
    result = subprocess.run(list(argv), capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        command = ' '.join(argv)
        raise RuntimeError(f'{command} failed ({result.returncode}): {result.stderr.strip()}')


def _qemu_io_command(op: Op) -> str:
    if op[0] == 'write':
        return f'write -P {op[1]:#x} {op[2]} {op[3]}'
    if op[0] == 'compress':
        return f'write -c -P {op[1]:#x} {op[2]} {op[3]}'
    if op[0] == 'zero':
        return f'write -z {op[1]} {op[2]}'
    raise ValueError(f'unknown qemu-io operation {op!r}')


def _apply_to_model(model: bytearray, op: Op) -> None:
    if op[0] in ('write', 'compress'):
        model[op[2]:op[2] + op[3]] = bytes([op[1]]) * op[3]
    else:
        model[op[1]:op[1] + op[2]] = bytes(op[2])


def _read_at(path: Path, offset: int, length: int) -> bytes:
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read(length)
    return data + bytes(length - len(data))


def build_fixture(target_dir: Path, name: str, description: str, *, cluster_size: int = 65536,
                  extended_l2: bool = True, backing: bool = False, data_file: bool = False,
                  ops: Sequence[Op] = (), patches: Sequence[Patch] = (),
                  patch_fn: Optional[Callable[[Qcow2Layout], Sequence[Patch]]] = None,
                  expect_types: FrozenSet[str] = frozenset()) -> SubclusterFixture:
    """Build one fixture, derive its expectations, and check it has `expect_types`.

    `patches` are (cluster_index, entry, bitmap) triples applied with
    `patch_l2` after qemu has written the image; `patch_fn` computes more of
    them from the qemu-built layout, for patches that depend on an offset qemu
    chose. Data and backing files are named by absolute path, because qemu
    resolves a relative data-file name against its working directory.
    """
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    virtual_size = cluster_size * CLUSTERS_PER_FIXTURE
    path = target_dir / f'{name}.qcow2'
    backing_path = target_dir / f'{name}.backing.raw' if backing else None
    data_path = target_dir / f'{name}.data' if data_file else None
    for stale in (path, backing_path, data_path):
        if stale is not None and stale.exists():
            stale.unlink()

    options = [f'cluster_size={cluster_size}', 'extended_l2=' + ('on' if extended_l2 else 'off')]
    if data_path is not None:
        options.append(f'data_file={data_path}')
    argv = ['qemu-img', 'create', '-q', '-f', 'qcow2', '-o', ','.join(options)]
    backing_bytes = backing_content(virtual_size) if backing_path is not None else bytes(virtual_size)
    model = bytearray(backing_bytes)
    if backing_path is not None:
        backing_path.write_bytes(backing_bytes)
        argv += ['-b', str(backing_path), '-F', 'raw']
    _run(argv + [str(path), str(virtual_size)])

    if ops:
        io_argv = ['qemu-io', '-f', 'qcow2']
        for op in ops:
            io_argv += ['-c', _qemu_io_command(op)]
            _apply_to_model(model, op)
        _run(io_argv + [str(path)])

    all_patches = list(patches)
    if patch_fn is not None:
        all_patches += list(patch_fn(read_layout(path)))
    for cluster_index, entry, bitmap in all_patches:
        patch_l2(path, cluster_index, entry=entry, bitmap=bitmap)

    layout = read_layout(path)
    if layout.has_data_file != data_file or layout.extended_l2 != extended_l2:
        raise RuntimeError(f'{name}: header does not carry the requested features')
    per_cluster = SUBCLUSTERS_PER_CLUSTER if extended_l2 else 1
    sc_size = cluster_size // per_cluster
    types = []
    ownership = []
    raw = bytearray()
    for slot in layout.slots:
        guest_cluster = slot.cluster_index * cluster_size
        for sc in range(per_cluster):
            sc_type = qemu_subcluster_type(slot.entry, slot.bitmap, sc, extended_l2, data_file)
            owner = qemu_owner(sc_type, slot.entry, guest_cluster, cluster_size, backing, data_file)
            types.append(sc_type)
            ownership.append(owner)
            guest = guest_cluster + sc * sc_size
            host = (slot.entry & L2E_OFFSET_MASK) + sc * sc_size
            if owner == CHILD and sc_type == COMPRESSED:
                raw += model[guest:guest + sc_size]
            elif owner == CHILD:
                raw += _read_at(path, host, sc_size)
            elif owner == DATA_FILE:
                raw += _read_at(data_path, host, sc_size)
            elif owner == BACKING:
                raw += backing_bytes[guest:guest + sc_size]
            else:
                raw += bytes(sc_size)

    missing = set(expect_types) - set(types)
    if missing:
        raise RuntimeError(f'{name}: qemu did not produce subcluster types {sorted(missing)}; '
                           f'got {sorted(set(types))}')
    return SubclusterFixture(
        name=name, description=description, path=path, backing=backing_path, data_file=data_path,
        cluster_size=cluster_size, extended_l2=extended_l2, virtual_size=virtual_size, slots=layout.slots,
        types=tuple(types), ownership=tuple(ownership),
        expected_raw=None if REFUSE in ownership else bytes(raw))


def mixed_ops(cluster_size: int, compressed: bool) -> Tuple[Op, ...]:
    """Return qemu-io operations that put a different shape in each cluster.

    With S the subcluster size (cluster_size / 32) and C the cluster size:
    cluster 0, the first 2S written (data_file_partial's shape at 64K clusters);
    cluster 1, 4S written then its second 2S zeroed; cluster 2, only its
    second subcluster zeroed; cluster 3 untouched; cluster 4 written whole
    then zeroed whole; cluster 5 written whole; cluster 6 written compressed
    when `compressed` (a data file forbids it); cluster 7 zeroed whole.
    """
    c = cluster_size
    s = cluster_size // SUBCLUSTERS_PER_CLUSTER
    ops = [
        ('write', 0x11, 0, 2 * s),
        ('write', 0x22, c, 4 * s),
        ('zero', c + 2 * s, 2 * s),
        ('zero', 2 * c + s, s),
        ('write', 0x44, 4 * c, c),
        ('zero', 4 * c, c),
        ('write', 0x55, 5 * c, c),
        ('zero', 7 * c, c),
    ]
    if compressed:
        ops.append(('compress', 0x66, 6 * c, c))
    return tuple(ops)


def _mixed(extended_l2: bool, backing: bool, data_file: bool, cluster_size: int = 65536):
    name = 'mixed_{}_{}_{}{}'.format(
        'ext' if extended_l2 else 'classic', 'backing' if backing else 'nobacking',
        'datafile' if data_file else 'nodatafile', '' if cluster_size == 65536 else f'_{cluster_size // 1024}k')
    if extended_l2:
        expect = {NORMAL, ZERO_ALLOC, ZERO_PLAIN, UNALLOCATED_ALLOC, UNALLOCATED_PLAIN}
    else:
        expect = {NORMAL, ZERO_ALLOC, ZERO_PLAIN, UNALLOCATED_PLAIN}
    if not data_file:
        expect.add(COMPRESSED)

    def build(target_dir: Path) -> SubclusterFixture:
        return build_fixture(
            target_dir, name,
            'One cluster of each qemu-written shape (see mixed_ops), {} L2, {}, {}, {}K clusters.'.format(
                'extended' if extended_l2 else 'classic', 'raw backing' if backing else 'no backing',
                'external data file' if data_file else 'no data file', cluster_size // 1024),
            cluster_size=cluster_size, extended_l2=extended_l2, backing=backing, data_file=data_file,
            ops=mixed_ops(cluster_size, compressed=not data_file), expect_types=frozenset(expect))
    return name, build


def _shape(name: str, description: str, expect_types: Sequence[str], **kwargs):
    def build(target_dir: Path) -> SubclusterFixture:
        return build_fixture(target_dir, name, description, expect_types=frozenset(expect_types), **kwargs)
    return name, build


def _set_bitmap_bits(cluster_index: int, extra: int):
    """Return a patch_fn that ORs `extra` into one cluster's existing bitmap."""
    def patch_fn(layout: Qcow2Layout):
        return [(cluster_index, None, layout.slots[cluster_index].bitmap | extra)]
    return patch_fn


def _clear_entry_flags(cluster_index: int, flags: int):
    """Return a patch_fn that clears `flags` in one cluster's existing L2 word."""
    def patch_fn(layout: Qcow2Layout):
        return [(cluster_index, layout.slots[cluster_index].entry & ~flags, None)]
    return patch_fn


def _move_host_offset(cluster_index: int, delta: int):
    """Return a patch_fn that adds `delta` to one cluster's existing host offset."""
    def patch_fn(layout: Qcow2Layout):
        return [(cluster_index, layout.slots[cluster_index].entry + delta, None)]
    return patch_fn


_K64 = 65536
_S64 = _K64 // SUBCLUSTERS_PER_CLUSTER
# Cluster 1 is written in every patched shape below so that the L2 table
# exists and cluster 0 can be patched without qemu ever having seen it.
_L2_ANCHOR = ('write', 0x77, _K64, _K64)

_BUILDER_LIST = [
    # The matrix of qemu-written shapes: {classic, extended} x {no backing,
    # raw backing} x {no data file, data file}, then extended L2 with backing
    # at cluster sizes whose subclusters are 512, 1K and 4K bytes.
    _mixed(False, False, False),
    _mixed(False, False, True),
    _mixed(False, True, False),
    _mixed(False, True, True),
    _mixed(True, False, False),
    _mixed(True, False, True),
    _mixed(True, True, False),
    _mixed(True, True, True),
    _mixed(True, True, False, cluster_size=16384),
    _mixed(True, True, False, cluster_size=32768),
    _mixed(True, True, False, cluster_size=131072),

    # The shapes of issues #653 and #654, and the data-file shapes that read wrongly beside them.
    _shape('issue_654', 'Extended L2 with backing; only subcluster 0 of cluster 0 zeroed (host 0, zero bit 0 set, '
           'no alloc bits): subclusters 1-31 read the backing file (#654).',
           [ZERO_PLAIN, UNALLOCATED_PLAIN], backing=True, ops=[('zero', 0, _S64)]),
    _shape('issue_653', 'Extended L2, no data file; cluster 0 patched to COPIED|0 with every alloc bit set (#653).',
           [INVALID], ops=[_L2_ANCHOR], patches=[(0, QCOW_OFLAG_COPIED, L2_BITMAP_ALL_ALLOC)]),
    _shape('issue_653_backing', 'As issue_653, over a raw backing file: qemu refuses rather than descending.',
           [INVALID], backing=True, ops=[_L2_ANCHOR], patches=[(0, QCOW_OFLAG_COPIED, L2_BITMAP_ALL_ALLOC)]),
    _shape('data_file_partial', 'Extended L2 with a data file; write -P 0xab 0 4k gives entry COPIED|0, bitmap 0x3: '
           'subclusters 0-1 read the data file at offset 0.',
           [NORMAL, UNALLOCATED_ALLOC], data_file=True, ops=[('write', 0xab, 0, 4096)]),
    _shape('data_file_partial_backing', 'As data_file_partial, over a raw backing file: subclusters 2-31 read '
           'the backing file.',
           [NORMAL, UNALLOCATED_ALLOC], data_file=True, backing=True, ops=[('write', 0xab, 0, 4096)]),
    _shape('data_file_classic', 'Classic L2 with a data file; cluster 0 written, so its entry is COPIED|0.',
           [NORMAL], extended_l2=False, data_file=True, ops=[('write', 0xab, 0, 4096)]),

    # The issue #653 entry shape, as qemu itself writes it with a data file.
    _shape('data_file_full_cluster', 'Extended L2 with a data file; cluster 0 written whole, so its entry is '
           'COPIED|0 with every alloc bit set: a valid NORMAL cluster read from the data file.',
           [NORMAL], data_file=True, ops=[('write', 0xcd, 0, _K64)]),
    # Host offset 0 without COPIED is unallocated even with a data file.
    _shape('data_file_ext_no_copied', 'As data_file_partial with COPIED cleared: host 0 is then unallocated, '
           'and its alloc bits make the entry invalid.',
           [INVALID], data_file=True, ops=[('write', 0xab, 0, 4096)],
           patch_fn=_clear_entry_flags(0, QCOW_OFLAG_COPIED)),
    _shape('data_file_classic_no_copied', 'As data_file_classic with COPIED cleared: the cluster is unallocated '
           'and reads zeros, not the data file.',
           [UNALLOCATED_PLAIN], extended_l2=False, data_file=True, ops=[('write', 0xab, 0, 4096)],
           patch_fn=_clear_entry_flags(0, QCOW_OFLAG_COPIED)),
    _shape('data_file_classic_no_copied_backing', 'As data_file_classic_no_copied over a raw backing file: '
           'cluster 0 reads the backing file, not the data file.',
           [UNALLOCATED_PLAIN], extended_l2=False, data_file=True, backing=True, ops=[('write', 0xab, 0, 4096)],
           patch_fn=_clear_entry_flags(0, QCOW_OFLAG_COPIED)),

    # Issue #650: host 0, no data file, a zero bit and an alloc bit in
    # different subclusters.
    _shape('issue_650', 'Extended L2, no data file; cluster 0 patched to entry 0 with bitmap 0x0000000100000002 '
           '(subcluster 0 zero, subcluster 1 allocated, no host cluster) (#650).',
           [INVALID], ops=[_L2_ANCHOR], patches=[(0, 0, sub_zero(0) | sub_alloc(1))]),
    _shape('issue_650_backing', 'As issue_650, over a raw backing file.',
           [INVALID], backing=True, ops=[_L2_ANCHOR], patches=[(0, 0, sub_zero(0) | sub_alloc(1))]),

    # One subcluster both allocated and zero, on an allocated cluster.
    _shape('alloc_zero_overlap', 'Extended L2; cluster 0 written whole, then zero bit 3 also set: alloc and '
           'zero overlap, so the whole entry is invalid.',
           [INVALID], ops=[('write', 0x11, 0, _K64)], patch_fn=_set_bitmap_bits(0, sub_zero(3))),
    _shape('alloc_zero_overlap_data_file', 'As alloc_zero_overlap on a data-file image, where the entry is '
           'COPIED|0.',
           [INVALID], data_file=True, ops=[('write', 0x11, 0, _K64)], patch_fn=_set_bitmap_bits(0, sub_zero(3))),

    # instar check's HostWithoutRef: host offset set, bitmap 0.
    _shape('host_without_ref', 'Extended L2; cluster 0 written (host offset set), then its bitmap cleared: 32 '
           'UNALLOCATED_ALLOC subclusters, reading zeros.',
           [UNALLOCATED_ALLOC], ops=[('write', 0x11, 0, 4096)], patches=[(0, None, 0)]),
    _shape('host_without_ref_backing', 'As host_without_ref over a raw backing file: every subcluster reads '
           'the backing file.',
           [UNALLOCATED_ALLOC], backing=True, ops=[('write', 0x11, 0, 4096)], patches=[(0, None, 0)]),

    # A compressed entry ignores its bitmap when read.
    _shape('compressed_bitmap_all_alloc', 'Extended L2; cluster 0 written compressed, then bitmap set to '
           '0x00000000ffffffff (the pattern old qemu wrote).',
           [COMPRESSED], ops=[('compress', 0x66, 0, _K64)], patches=[(0, None, L2_BITMAP_ALL_ALLOC)]),
    _shape('compressed_bitmap_arbitrary', 'Extended L2; cluster 0 written compressed, then bitmap set to '
           '0x0000000300000005, alloc and zero overlapping in subcluster 0.',
           [COMPRESSED], ops=[('compress', 0x66, 0, _K64)], patches=[(0, None, 0x0000000300000005)]),

    # Small subclusters, below a 4096-byte sector.
    _shape('issue_654_32k', 'As issue_654 at 32K clusters (1K subclusters).', [ZERO_PLAIN, UNALLOCATED_PLAIN],
           cluster_size=32768, backing=True, ops=[('zero', 0, 1024)]),
    _shape('data_file_partial_32k', 'As data_file_partial_backing at 32K clusters: write -P 0xab 0 1k gives '
           'entry COPIED|0, bitmap 0x1.',
           [NORMAL, UNALLOCATED_ALLOC], cluster_size=32768, data_file=True, backing=True,
           ops=[('write', 0xab, 0, 1024)]),
    _shape('issue_653_32k', 'As issue_653_backing at 32K clusters.', [INVALID], cluster_size=32768, backing=True,
           ops=[('write', 0x77, 32768, 32768)], patches=[(0, QCOW_OFLAG_COPIED, L2_BITMAP_ALL_ALLOC)]),
]

#: Every fixture whose ownership follows from qemu's subcluster
#: classification, keyed by name. Each value takes a target directory and
#: returns a SubclusterFixture.
BUILDERS: Dict[str, Callable[[Path], SubclusterFixture]] = dict(_BUILDER_LIST)

#: Shapes that classify as valid but that qemu's read path still refuses
#: (block/qcow2-cluster.c:668-705). They are kept apart from BUILDERS because
#: the refusal comes from qemu's host-offset checks, not from its
#: classification.
HOST_OFFSET_REFUSAL_BUILDERS: Dict[str, Callable[[Path], SubclusterFixture]] = dict([
    _shape('data_file_compressed', 'Extended L2 with a data file; cluster 0 written, then its entry patched to '
           'a compressed descriptor: qemu refuses compressed clusters with a data file.',
           [COMPRESSED], data_file=True, ops=[('write', 0xab, 0, _K64)],
           patches=[(0, QCOW_OFLAG_COMPRESSED | (_K64 * 3), 0)]),
    _shape('data_file_offset_mismatch', 'Extended L2 with a data file; cluster 1 written, then its host offset '
           'moved one cluster on: qemu refuses a data-file host offset that differs from the guest offset.',
           [NORMAL], data_file=True, ops=[('write', 0xab, _K64, _K64)], patch_fn=_move_host_offset(1, _K64)),
])


def build_all(target_dir: Path, include_host_offset_refusals: bool = False) -> Dict[str, SubclusterFixture]:
    """Build every fixture into `target_dir` and return them keyed by name."""
    builders = dict(BUILDERS)
    if include_host_offset_refusals:
        builders.update(HOST_OFFSET_REFUSAL_BUILDERS)
    return {name: build(Path(target_dir)) for name, build in builders.items()}
