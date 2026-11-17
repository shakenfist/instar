"""Tests for the structural VMDK parser in helpers/vmdk_structure.py.

The parser is the oracle later tests use to judge instar's VMDK output, so
it is checked here against qemu-img, never against instar: an emitter must
not be the reference for the comparator that judges it. The extent split a
multi-extent subformat produces is computed in this file from the rule the
subformat names -- 2 GiB of virtual disk per extent, the last one holding
the remainder -- rather than transcribed from a run, so a misreading in the
parser shows up as a disagreement with that arithmetic.

The rest of the file checks that the comparison reports what it should
(nothing for two runs of one command, the named field and extent index
otherwise), and that malformed images raise `VmdkParseError` rather than an
incidental `OSError`, `struct.error` or `UnicodeDecodeError`, because the
differential fuzzer feeds the parser output that may be wrong.
"""

import os
import shutil
import struct
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.vmdk_structure import (
    MAX_DESCRIPTOR_BYTES,
    SECTOR_SIZE,
    VMDK3_MAGIC,
    VMDK4_MAGIC,
    VmdkParseError,
    describe_flags,
    descriptor_extents,
    parse_vmdk,
    structural_diff,
    summarise,
)

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

# What `twoGbMaxExtent*` means: each extent carries 2 GiB of the virtual
# disk, and the last one carries what is left.
EXTENT_SECTORS = 2 * GiB // SECTOR_SIZE

# qemu's VMDK4 grain size, in sectors (block/vmdk.c, `vmdk_create_extent`).
GRAIN_SECTORS = 128

# The descriptor a sparse file reserves for itself: one sector in, twenty
# sectors long.
DESCRIPTOR_OFFSET_SECTORS = 1
DESCRIPTOR_SECTORS = 20


def extent_split(size: int) -> list:
    """The per-extent sector counts a 2 GiB-per-extent split gives `size`."""
    sectors = size // SECTOR_SIZE
    counts = [EXTENT_SECTORS] * (sectors // EXTENT_SECTORS)
    if sectors % EXTENT_SECTORS:
        counts.append(sectors % EXTENT_SECTORS)
    return counts


class _VmdkTestCase(InstarTestBase):
    """Shared scratch directory and qemu-img wrapper."""

    def setUp(self):
        super().setUp()
        self._require_qemu_img()
        self.skip_unless_qemu_supports('vmdk')
        self.workdir = Path(tempfile.mkdtemp(prefix='instar-vmdk-structure-'))
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    def qemu_create(self, subformat, size, directory=None, name='image.vmdk'):
        """Create `name` with `qemu-img create -f vmdk`, and return its path.

        `directory` is made if it is given, so that two images can be
        created under the same name and compared without their extent
        filenames differing for that reason alone.
        """
        parent = self.workdir if directory is None else self.workdir / directory
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / name
        self._run_tool(['qemu-img', 'create', '-q', '-f', 'vmdk', '-o', f'subformat={subformat}',
                        str(path), str(size)], parent)
        return path


class TestVmdkStructureQemuImages(_VmdkTestCase):
    """The parse of a qemu-written image matches what the subformat means."""

    def assert_sparse_header(self, extent):
        """A freshly created sparse extent's header, as qemu writes one."""
        header = extent.header
        self.assertIsNotNone(header, f'extent {extent.index} has no VMDK4 header')
        self.assertEqual(1, header.version)
        self.assertEqual(extent.sectors, header.capacity_sectors)
        self.assertEqual(GRAIN_SECTORS, header.grain_size_sectors)
        self.assertEqual(DESCRIPTOR_OFFSET_SECTORS, header.descriptor_offset_sectors)
        self.assertEqual(DESCRIPTOR_SECTORS, header.descriptor_size_sectors)
        # Both directories are written, the redundant one first, and an
        # empty image is exactly its own overhead long.
        self.assertLess(0, header.rgd_offset_sectors)
        self.assertLess(header.rgd_offset_sectors, header.gd_offset_sectors)
        self.assertEqual(extent.file_length, header.overhead_sectors * SECTOR_SIZE)

    def test_monolithic_sparse(self):
        structure = parse_vmdk(self.qemu_create('monolithicSparse', 64 * MiB))

        self.assertTrue(structure.descriptor_embedded)
        self.assertEqual('monolithicSparse', structure.create_type)
        self.assertEqual('1', structure.version)
        self.assertTrue(structure.has_cid)
        self.assertEqual('ffffffff', structure.parent_cid)
        self.assertEqual(1, structure.extent_count)
        self.assertEqual(64 * MiB // SECTOR_SIZE, structure.total_sectors)

        extent = structure.extents[0]
        self.assertEqual(('RW', 'SPARSE', 'image.vmdk'), (extent.access, extent.kind, extent.filename))
        self.assertIsNone(extent.flat_offset_sectors)
        self.assert_sparse_header(extent)

    def test_monolithic_flat(self):
        structure = parse_vmdk(self.qemu_create('monolithicFlat', 64 * MiB))

        self.assertFalse(structure.descriptor_embedded)
        self.assertEqual('monolithicFlat', structure.create_type)
        self.assertEqual(1, structure.extent_count)

        extent = structure.extents[0]
        self.assertEqual(('RW', 'FLAT', 'image-flat.vmdk'), (extent.access, extent.kind, extent.filename))
        self.assertEqual(0, extent.flat_offset_sectors)
        self.assertEqual(64 * MiB, extent.file_length)
        self.assertIsNone(extent.header)

    def test_two_gb_max_extent_sparse(self):
        structure = parse_vmdk(self.qemu_create('twoGbMaxExtentSparse', 5 * GiB))

        self.assertFalse(structure.descriptor_embedded)
        self.assertEqual('twoGbMaxExtentSparse', structure.create_type)
        self.assertEqual(extent_split(5 * GiB), [e.sectors for e in structure.extents])
        self.assertEqual(['image-s001.vmdk', 'image-s002.vmdk', 'image-s003.vmdk'],
                         [e.filename for e in structure.extents])
        self.assertEqual(5 * GiB // SECTOR_SIZE, structure.total_sectors)
        for extent in structure.extents:
            with self.subTest(extent=extent.index):
                self.assertEqual('SPARSE', extent.kind)
                self.assertIsNone(extent.flat_offset_sectors)
                self.assert_sparse_header(extent)

    def test_two_gb_max_extent_flat(self):
        structure = parse_vmdk(self.qemu_create('twoGbMaxExtentFlat', 5 * GiB))

        self.assertFalse(structure.descriptor_embedded)
        self.assertEqual('twoGbMaxExtentFlat', structure.create_type)
        self.assertEqual(extent_split(5 * GiB), [e.sectors for e in structure.extents])
        self.assertEqual(['image-f001.vmdk', 'image-f002.vmdk', 'image-f003.vmdk'],
                         [e.filename for e in structure.extents])
        for extent in structure.extents:
            with self.subTest(extent=extent.index):
                self.assertEqual('FLAT', extent.kind)
                self.assertEqual(0, extent.flat_offset_sectors)
                self.assertEqual(extent.sectors * SECTOR_SIZE, extent.file_length)
                self.assertIsNone(extent.header)


class TestVmdkStructuralDiff(_VmdkTestCase):
    """What the comparison says about two images."""

    def test_same_command_twice_is_no_difference(self):
        first = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB, directory='a')
        second = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB, directory='b')

        # Only the CID differs between the two, and the parse keeps its
        # presence and not its value.
        self.assertEqual([], structural_diff(parse_vmdk(first), parse_vmdk(second)))

    def test_summary_compares_equal_to_the_structure(self):
        structure = parse_vmdk(self.qemu_create('twoGbMaxExtentSparse', 5 * GiB))

        self.assertEqual([], structural_diff(structure, summarise(structure)))

    def test_sparse_and_flat_differ_by_create_type(self):
        sparse = self.qemu_create('monolithicSparse', 64 * MiB, directory='a')
        flat = self.qemu_create('monolithicFlat', 64 * MiB, directory='b')

        differences = structural_diff(parse_vmdk(sparse), parse_vmdk(flat))
        self.assertIn("create_type: 'monolithicSparse' != 'monolithicFlat'", differences)

    def test_a_changed_extent_is_named_by_index(self):
        first = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB, directory='a')
        second = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB, directory='b')
        text = second.read_text(encoding='utf-8')
        second.write_text(text.replace('RW 2097152 SPARSE', 'RW 2097151 SPARSE'), encoding='utf-8')

        differences = structural_diff(parse_vmdk(first), parse_vmdk(second))
        self.assertEqual(['extent 2 sectors: 2097152 != 2097151',
                          'total_sectors: 10485760 != 10485759'], differences)


class TestVmdkStructureMalformed(_VmdkTestCase):
    """Malformed images raise VmdkParseError and nothing else."""

    def truncated(self, source, length):
        """A copy of `source` cut to `length` bytes."""
        path = self.workdir / f'truncated-{length}.vmdk'
        shutil.copyfile(source, path)
        os.truncate(path, length)
        return path

    def test_truncated_file(self):
        image = self.qemu_create('monolithicSparse', 64 * MiB)
        # Shorter than the magic, inside the magic, inside the VMDK4
        # header, and past the header but short of the grain directory the
        # header points at.
        for length in (0, 3, 40, 2 * KiB):
            with self.subTest(length=length):
                self.assertRaises(VmdkParseError, parse_vmdk, self.truncated(image, length))

    def test_bad_magic(self):
        embedded = self.qemu_create('monolithicSparse', 64 * MiB, directory='a')
        multi = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB, directory='b')
        extent = multi.parent / 'image-s002.vmdk'
        for path in (embedded, extent):
            with open(path, 'r+b') as handle:
                handle.write(b'XXXX')
        self.assertNotEqual(VMDK4_MAGIC, embedded.read_bytes()[:4])

        # The image that is its own extent, and the second extent of one
        # whose descriptor is a file of its own.
        self.assertRaises(VmdkParseError, parse_vmdk, embedded)
        self.assertRaises(VmdkParseError, parse_vmdk, multi)

    def test_missing_extent(self):
        image = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB)
        os.unlink(image.parent / 'image-s003.vmdk')

        self.assertRaises(VmdkParseError, parse_vmdk, image)

    def test_descriptor_without_extents(self):
        image = self.qemu_create('twoGbMaxExtentSparse', 5 * GiB)
        text = image.read_text(encoding='utf-8')
        stripped = '\n'.join(line for line in text.splitlines() if not line.startswith('RW '))
        image.write_text(stripped + '\n', encoding='utf-8')

        self.assertRaises(VmdkParseError, parse_vmdk, image)


class TestVmdkStructureHostileDescriptor(_VmdkTestCase):
    """An extent line names a file this image does not own."""

    def rewritten(self, image, filename):
        """A copy of a flat image whose single extent line names `filename`."""
        source = self.qemu_create('monolithicFlat', 64 * MiB, directory=image, name='image.vmdk')
        text = source.read_text(encoding='utf-8')
        lines = [f'RW 131072 FLAT "{filename}" 0' if line.startswith('RW ') else line
                 for line in text.splitlines()]
        source.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return source

    def test_absolute_extent_path(self):
        image = self.rewritten('one', '/dev/zero')

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(image)
        # The reason, not just a refusal: without the absolute-path rule the
        # containment rule refuses this too, and an assertion that cannot
        # tell them apart cannot tell whether the first rule is still there.
        self.assertIn('absolute extent path', str(caught.exception))

    def test_extent_path_climbing_out(self):
        # A real file, so that without the containment rule the parse
        # succeeds rather than failing for want of something to open.
        target = self.workdir / 'target.raw'
        target.write_bytes(b'\0' * SECTOR_SIZE)
        image = self.rewritten('two', '../target.raw')

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(image)
        self.assertIn('resolves outside', str(caught.exception))

    def test_extent_symlink_pointing_away(self):
        outside = self.workdir / 'away.raw'
        outside.write_bytes(b'\0' * SECTOR_SIZE)
        image = self.rewritten('three', 'extent.vmdk')
        os.symlink(outside, image.parent / 'extent.vmdk')

        # The name stays inside the directory; what it resolves to does not.
        with self.assertRaises(VmdkParseError, msg='a symlink out of the directory was followed'):
            parse_vmdk(image)

    def test_extent_fifo_does_not_block(self):
        image = self.rewritten('four', 'extent.vmdk')
        os.mkfifo(image.parent / 'extent.vmdk')

        # With no writer, a blocking open of this never returns. The test
        # hanging rather than failing is itself the regression.
        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(image)
        self.assertIn('not a regular file', str(caught.exception))


class TestDescriptorExtentLines(InstarTestBase):
    """descriptor_extents reads every extent line, or refuses."""

    HEAD = 'version=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType="twoGbMaxExtentFlat"\n'

    def test_non_extent_lines_are_passed_over(self):
        text = self.HEAD + '\n# Extent description\nRW 4194304 FLAT "a-f001.vmdk" 0\n\nddb.adapterType = "ide"\n'

        extents = descriptor_extents(text)

        self.assertEqual(1, len(extents))
        self.assertEqual('a-f001.vmdk', extents[0]['filename'])

    def test_a_malformed_extent_line_is_refused(self):
        # One good line and one that opens like an extent and is not: the
        # count alone would read as a one-extent image.
        text = self.HEAD + 'RW 4194304 FLAT "a-f001.vmdk" 0\nRW 4194304 FLAT "a-f002.vmdk\n'

        with self.assertRaises(VmdkParseError) as caught:
            descriptor_extents(text)
        self.assertIn('malformed extent line', str(caught.exception))

    def test_non_rw_access_modes_are_read(self):
        text = self.HEAD + 'RDONLY 2048 FLAT "a-f001.vmdk" 0\nNOACCESS 4096 ZERO\n'

        extents = descriptor_extents(text)

        self.assertEqual(['RDONLY', 'NOACCESS'], [extent['access'] for extent in extents])
        self.assertEqual([2048, 4096], [extent['sectors'] for extent in extents])


class TestVmdkStructureRefusals(InstarTestBase):
    """The refusals that no qemu build produces, so nothing else reaches."""

    def setUp(self):
        super().setUp()
        self.workdir = Path(tempfile.mkdtemp(prefix='instar-vmdk-refusals-'))
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    def sparse_header(self, name, *, grain_size=128, descriptor_sectors=20, length=64 * KiB):
        """A file with a hand-built VMDK4 header and nothing else in it."""
        header = bytearray(length)
        header[0:4] = VMDK4_MAGIC
        struct.pack_into('<II', header, 4, 1, 0)
        struct.pack_into('<QQ', header, 12, 131072, grain_size)
        struct.pack_into('<QQ', header, 28, 1, descriptor_sectors)
        path = self.workdir / name
        path.write_bytes(bytes(header))
        return path

    def test_vmdk3_is_refused(self):
        path = self.workdir / 'cowd.vmdk'
        path.write_bytes(VMDK3_MAGIC + bytes(4096))

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(path)
        self.assertIn('VMDK3', str(caught.exception))

    def test_oversized_standalone_descriptor_is_refused(self):
        path = self.workdir / 'huge.vmdk'
        path.write_bytes(b'createType="monolithicFlat"\n'.ljust(MAX_DESCRIPTOR_BYTES + 1, b'#'))

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(path)
        self.assertIn('maximum for a descriptor file', str(caught.exception))

    def test_embedded_descriptor_larger_than_the_maximum_is_refused(self):
        # The sector count is the file's own, so without a cap this reads
        # as much of the image as the header asks for and decodes it.
        sectors = (MAX_DESCRIPTOR_BYTES // SECTOR_SIZE) + 1
        path = self.sparse_header('oversized.vmdk', descriptor_sectors=sectors, length=4 * MiB)

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(path)
        self.assertIn('past the', str(caught.exception))

    def test_embedded_descriptor_of_no_size_is_refused(self):
        path = self.sparse_header('empty-descriptor.vmdk', descriptor_sectors=0)

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(path)
        self.assertIn('reserves no descriptor', str(caught.exception))

    def test_zero_grain_size_is_refused(self):
        path = self.sparse_header('no-grain.vmdk', grain_size=0)

        with self.assertRaises(VmdkParseError) as caught:
            parse_vmdk(path)
        self.assertIn('grain size of zero', str(caught.exception))

    def test_describe_flags_names_the_bits_it_knows(self):
        self.assertEqual('none', describe_flags(0))
        self.assertIn('compressed', describe_flags(1 << 16))
        # An unknown bit is reported rather than dropped.
        self.assertIn('0x80000000', describe_flags(1 << 31))

    def test_structural_diff_refuses_something_that_is_neither(self):
        with self.assertRaises(TypeError):
            structural_diff({'extents': []}, 'not a structure')


class TestVmdkHeaderDiff(_VmdkTestCase):
    """A sparse header present on one side and absent on the other."""

    def test_header_present_on_one_side_only(self):
        sparse = summarise(parse_vmdk(self.qemu_create('monolithicSparse', 64 * MiB, directory='s')))
        flat = summarise(parse_vmdk(self.qemu_create('monolithicFlat', 64 * MiB, directory='f')))

        differences = structural_diff(sparse, flat)

        self.assertTrue(any('header' in message for message in differences), differences)

    def test_one_header_field_differs(self):
        image = self.qemu_create('monolithicSparse', 64 * MiB)
        one = summarise(parse_vmdk(image))
        other = summarise(parse_vmdk(image))
        other['extents'][0]['header']['grain_size_sectors'] = 999

        differences = structural_diff(one, other)

        self.assertEqual(1, len(differences), differences)
        self.assertIn('grain_size_sectors', differences[0])
