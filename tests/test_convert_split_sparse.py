"""Split-sparse VMDK images read correctly through the guest, byte for byte.

`tests/test_info_split_sparse.py` pins what these images *say* -- the
virtual size the descriptor declares, the format, the cluster size. It
cannot pin what they *hold*: `instar info` on a descriptor is answered
host-side in `discover_backing_chain`'s `peek_is_vmdk_descriptor`
branch, so it never writes the chain config's extent table, never
starts a guest, and never reaches `read_vmdk_descriptor_chunk`.

These tests go through the guest. `convert` and `compare` attach the
descriptor and all of its extents as one virtio-block device and read
them through the extent table, so they exercise the handshake the
host-side tests cannot: the table the host writes against the table the
guest reads, the concatenated backing store underneath it, and the
re-reading of per-extent sparse state at every extent crossing.

The oracle is `qemu-img compare` from the pinned 10.2.0 build rather
than a digest of the two conversions. It is hole-aware on both sides,
so it reads the allocated regions only -- four seconds against the one
hundred and eleven a `sha256` of the 100 GiB output costs -- and it
makes qemu read the split descriptor itself rather than trusting
instar's raw output to be its own reference.

The raw outputs are large but sparse: 100 GiB apparent and 1.3 GiB
actually written for the 26-extent image, a few hundred KiB for each of
the others. They go to `TMPDIR` like the rest of the suite's
temporaries, which is issue #944's subject.
"""

import os
import subprocess
import tempfile

from base import InstarTestBase
from helpers import qemu_pins
from helpers.vmdk_structure import descriptor_extents, read_descriptor

SECTOR = 512

# The pattern `vmdk-split-sparse-5g-boundary.vmdk` carries, straddling
# the end of its first extent. The test asserts the straddle rather
# than assuming it: the first extent's length comes from the
# descriptor, and the pattern has to start before it and end after it.
BOUNDARY_OFFSET = 2147418112
BOUNDARY_LENGTH = 131072
BOUNDARY_BYTE = 0xAB


class _SplitSparseBase(InstarTestBase):

    def _image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image.path

    def _qemu_img(self):
        builds = qemu_pins.qemu_img_builds(self._testdata_root / 'qemu-img-binaries' / 'x86_64')
        if '10.2.0' not in builds:
            self.skipTest('pinned qemu-img 10.2.0 not available')
        return builds['10.2.0']

    def _extents(self, path):
        text, _ = read_descriptor(path)
        extents = descriptor_extents(text)
        self.assertTrue(extents, f'{path} declares no extents')
        return extents

    def _declared_size(self, path):
        return sum(extent['sectors'] for extent in self._extents(path)) * SECTOR

    def _convert_to_raw(self, source, destination, timeout=1800):
        """`instar convert -O raw`, asserting it succeeded."""
        result = subprocess.run(
            [str(self.get_instar_binary()), 'convert', '-O', 'raw', str(source), str(destination)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(0, result.returncode,
                         f'instar convert failed: {result.stderr}')

    def _assert_qemu_sees_the_same_bytes(self, descriptor, raw, timeout=1800):
        """qemu-img reads the descriptor itself and compares it with `raw`."""
        result = subprocess.run(
            [str(self._qemu_img()), 'compare', '-f', 'vmdk', '-F', 'raw', str(descriptor), str(raw)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(0, result.returncode,
                         f'qemu-img compare: {result.stdout}{result.stderr}')
        self.assertIn('identical', result.stdout)


class TestConvertSplitSparse(_SplitSparseBase):
    """`convert -O raw` of a split-sparse descriptor, against qemu's own read."""

    IMAGES = [
        'vmdk-split-sparse-2049m',
        'vmdk-split-sparse-5g',
        'vmdk-split-sparse-5g-boundary',
        'vmdk-split-sparse-33g',
    ]

    def test_conversion_matches_qemus_own_read(self):
        for image_id in self.IMAGES:
            with self.subTest(image=image_id):
                source = self._image(image_id)
                with tempfile.TemporaryDirectory() as workdir:
                    output = os.path.join(workdir, 'out.raw')
                    self._convert_to_raw(source, output)
                    self._assert_qemu_sees_the_same_bytes(source, output)

    def test_conversion_length_is_the_size_the_descriptor_declares(self):
        # Every one of these ends in a partial extent -- the 2049 MiB
        # image's last extent holds 2048 sectors of the 4194304 a full
        # one would -- so an output sized from the extent count rather
        # than from the span each extent declares is too long by the
        # difference.
        for image_id in self.IMAGES:
            with self.subTest(image=image_id):
                source = self._image(image_id)
                declared = self._declared_size(source)
                self.assertGreater(declared, 0)
                with tempfile.TemporaryDirectory() as workdir:
                    output = os.path.join(workdir, 'out.raw')
                    self._convert_to_raw(source, output)
                    self.assertEqual(declared, os.path.getsize(output))

    def test_the_boundary_pattern_crosses_the_extent_edge(self):
        """Definition of done item 3 of the phase that made these readable.

        The fixture places 131072 bytes of 0xAB at 2 GiB - 64 KiB, so
        half of it lives in the first extent and half in the second. A
        read that stopped at the extent edge, repeated the first
        extent, or mislaid the second extent's base would return zeros
        or the wrong bytes for part of this window.
        """
        source = self._image('vmdk-split-sparse-5g-boundary')
        first_extent_end = self._extents(source)[0]['sectors'] * SECTOR
        self.assertGreater(first_extent_end, BOUNDARY_OFFSET,
                           'the pattern must start inside the first extent')
        self.assertLess(first_extent_end, BOUNDARY_OFFSET + BOUNDARY_LENGTH,
                        'the pattern must end inside the second extent')

        with tempfile.TemporaryDirectory() as workdir:
            output = os.path.join(workdir, 'out.raw')
            self._convert_to_raw(source, output)
            with open(output, 'rb') as handle:
                handle.seek(BOUNDARY_OFFSET - BOUNDARY_LENGTH)
                before = handle.read(BOUNDARY_LENGTH)
                pattern = handle.read(BOUNDARY_LENGTH)
                after = handle.read(BOUNDARY_LENGTH)

        self.assertEqual(BOUNDARY_LENGTH, len(pattern))
        self.assertEqual({BOUNDARY_BYTE}, set(pattern),
                         'the whole window is the pattern byte')
        self.assertEqual({0}, set(before),
                         'the bytes before the pattern are zeros')
        self.assertEqual({0}, set(after),
                         'the bytes after the pattern are zeros, not a repeat')


class TestCompareSplitSparse(_SplitSparseBase):
    """`compare` reads a split-sparse descriptor through the guest too."""

    def test_compare_against_qemus_conversion(self):
        source = self._image('vmdk-split-sparse-5g-boundary')
        with tempfile.TemporaryDirectory() as workdir:
            reference = os.path.join(workdir, 'qemu.raw')
            result = subprocess.run(
                [str(self._qemu_img()), 'convert', '-O', 'raw', str(source), reference],
                capture_output=True, text=True, timeout=1800)
            self.assertEqual(0, result.returncode, result.stderr)

            stdout, stderr, rc = self.run_instar_compare(source, reference, timeout=1800)
        self.assertEqual(0, rc, f'instar compare: {stdout}{stderr}')
        self.assertIn('identical', stdout)


class TestConvertSplitSparseRealWorld(_SplitSparseBase):
    """The 26-extent VMware image, past the 15 extents a device slot each allowed."""

    def test_twenty_six_extents_convert_to_raw(self):
        source = self._image('osboxes-vmdk-split-sparse')
        extents = self._extents(source)
        self.assertGreater(len(extents), 15,
                           'this image exists to exceed the old device-slot ceiling')
        with tempfile.TemporaryDirectory() as workdir:
            output = os.path.join(workdir, 'out.raw')
            self._convert_to_raw(source, output)
            self.assertEqual(self._declared_size(source), os.path.getsize(output))
            self._assert_qemu_sees_the_same_bytes(source, output)
