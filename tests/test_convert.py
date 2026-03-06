"""Tests for convert operation."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from base import ImagoTestBase


class TestConvertBasicQcow2ToRaw(ImagoTestBase):
    """Test basic QCOW2 to raw conversion."""

    def test_convert_empty_qcow2(self):
        """Convert an empty QCOW2 image to raw."""
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 qcow2.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(qcow2.name), Path(raw.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')
            self.assertEqual(stdout, '')

            # Verify output matches qemu-img convert
            with tempfile.NamedTemporaryFile(suffix='.raw') as qemu_raw:
                self.run_qemu_img_convert(
                    Path(qcow2.name), Path(qemu_raw.name)
                )
                cmp_out, cmp_err, cmp_rc = self.run_imago_compare(
                    Path(raw.name), Path(qemu_raw.name)
                )
                self.assertEqual(
                    cmp_rc, 0,
                    f'Output differs from qemu-img: {cmp_out}'
                )

    def test_convert_qcow2_with_data(self):
        """Convert QCOW2 with written data to raw."""
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 qcow2.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x42 0 4096', qcow2.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xAB 524288 8192', qcow2.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(qcow2.name), Path(raw.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Cross-validate with qemu-img
            with tempfile.NamedTemporaryFile(suffix='.raw') as qemu_raw:
                self.run_qemu_img_convert(
                    Path(qcow2.name), Path(qemu_raw.name)
                )
                cmp_out, _, cmp_rc = self.run_imago_compare(
                    Path(raw.name), Path(qemu_raw.name)
                )
                self.assertEqual(
                    cmp_rc, 0,
                    f'Output differs from qemu-img: {cmp_out}'
                )

    def test_convert_output_size_matches_virtual_size(self):
        """Converted raw output has the correct size."""
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 qcow2.name, '2M'],
                capture_output=True
            )
            self.run_imago_convert(
                Path(qcow2.name), Path(raw.name)
            )
            raw_size = os.path.getsize(raw.name)
            self.assertEqual(raw_size, 2 * 1024 * 1024)


class TestConvertCompressed(ImagoTestBase):
    """Test conversion of compressed QCOW2 images."""

    def test_convert_compressed_qcow2(self):
        """Convert a compressed QCOW2 image to raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as comp, \
                tempfile.NamedTemporaryFile(suffix='.raw') as output:
            # Create a raw base with data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 base.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xCC 0 65536', base.name],
                capture_output=True
            )
            # Compress it
            subprocess.run(
                ['qemu-img', 'convert', '-c', '-f', 'raw',
                 '-O', 'qcow2', base.name, comp.name],
                capture_output=True
            )
            # Convert back to raw
            stdout, stderr, rc = self.run_imago_convert(
                Path(comp.name), Path(output.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare with original raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(base.name), Path(output.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Decompressed output differs: {cmp_out}'
            )


class TestConvertBackingChain(ImagoTestBase):
    """Test conversion of QCOW2 images with backing chains."""

    def test_convert_with_raw_backing(self):
        """Convert QCOW2 overlay with raw backing to flat raw."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / 'base.raw'
            overlay_path = Path(tmpdir) / 'overlay.qcow2'
            output_path = Path(tmpdir) / 'output.raw'
            qemu_path = Path(tmpdir) / 'qemu.raw'

            # Create base with data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 str(base_path), '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xBB 0 4096', str(base_path)],
                capture_output=True
            )
            # Create overlay
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', str(base_path), '-F', 'raw',
                 str(overlay_path)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xAA 65536 4096',
                 str(overlay_path)],
                capture_output=True
            )

            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                overlay_path, output_path
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Convert with qemu-img for cross-validation
            self.run_qemu_img_convert(
                overlay_path, qemu_path
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                output_path, qemu_path
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from qemu-img: {cmp_out}'
            )

    def test_convert_deep_chain(self):
        """Convert QCOW2 with multiple backing layers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / 'base.raw'
            mid_path = Path(tmpdir) / 'mid.qcow2'
            top_path = Path(tmpdir) / 'top.qcow2'
            output_path = Path(tmpdir) / 'output.raw'
            qemu_path = Path(tmpdir) / 'qemu.raw'

            # base: raw with data at offset 0
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 str(base_path), '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x11 0 4096', str(base_path)],
                capture_output=True
            )
            # mid: qcow2 overlay on base, writes at offset 64K
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', str(base_path), '-F', 'raw',
                 str(mid_path)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x22 65536 4096', str(mid_path)],
                capture_output=True
            )
            # top: qcow2 overlay on mid, writes at offset 128K
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', str(mid_path), '-F', 'qcow2',
                 str(top_path)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x33 131072 4096', str(top_path)],
                capture_output=True
            )

            # Convert
            stdout, stderr, rc = self.run_imago_convert(
                top_path, output_path
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Cross-validate
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', str(top_path), str(qemu_path)],
                capture_output=True
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                output_path, qemu_path
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from qemu-img: {cmp_out}'
            )


class TestConvertRawToRaw(ImagoTestBase):
    """Test raw-to-raw passthrough conversion."""

    def test_convert_raw_passthrough(self):
        """Converting a raw image to raw is an identity operation."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x77 0 4096', src.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Raw passthrough differs: {cmp_out}'
            )


class TestConvertErrors(ImagoTestBase):
    """Test error handling in convert."""

    def test_convert_unsupported_output_format(self):
        """Converting to unsupported format returns an error."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(suffix='.vdi') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(dst.name),
                output_format='vdi'
            )
            self.assertNotEqual(rc, 0)
            self.assertIn('unsupported', stderr.lower())

    def test_convert_nonexistent_input(self):
        """Converting a nonexistent file returns an error."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            stdout, stderr, rc = self.run_imago_convert(
                Path('/nonexistent/image.qcow2'),
                Path(dst.name)
            )
            self.assertNotEqual(rc, 0)


class TestConvertManifestImages(ImagoTestBase):
    """Test convert against manifest QCOW2 images.

    For each safe standalone QCOW2 image in the manifest,
    convert to raw and cross-validate against qemu-img convert.

    Images with cluster_size > 64KB or < 64KB are skipped
    (unsupported — the guest binary uses 64KB sectors).
    Images whose virtual_size exceeds available temp space
    are skipped to avoid disk-full failures.
    """

    # Large clusters (up to 2MB) are supported; I/O uses 64KB chunks
    MAX_CLUSTER_SIZE = 2097152
    # Clusters smaller than sector size (64KB) can't be converted
    MIN_CLUSTER_SIZE = 65536

    # QCOW2 images that are safe standalone (no external backing
    # chain dependencies)
    STANDALONE_QCOW2_IDS = [
        'cirros-qcow2',
        'qcow2-v2',
        'qcow2-lazy-refcounts',
        'qcow2-min-cluster',
        'qcow2-refcount-bits-1',
        'qcow2-max-cluster',
        'debian-12-sfagent',
        'aurel32-debian-etch-sparc',
        'aurel32-debian-squeeze-armel',
        'aurel32-debian-squeeze-i386',
        'aurel32-debian-wheezy-powerpc',
    ]

    def _get_qcow2_info(self, image_path):
        """Get virtual_size and cluster_size via qemu-img info."""
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image_path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None, None
        info = json.loads(result.stdout)
        return (
            info.get('virtual-size'),
            info.get('cluster-size'),
        )

    def _timeout_for_vsize(self, vsize):
        """Compute a per-operation timeout based on virtual size.

        Returns a timeout in seconds that scales with image
        virtual size. Uses 120s as minimum and adds 30s per
        GiB of virtual size to accommodate CI I/O variance.
        """
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    # Max I/O buffer size: compressed clusters need a full-cluster
    # decompression buffer, limited to MAX_SECTOR_SIZE (64KB).
    MAX_DECOMPRESS_CLUSTER = 65536

    def _skip_if_unsupported(self, image_id, image_path):
        """Skip test if image has unsupported features."""
        vsize, csize = self._get_qcow2_info(image_path)
        if csize and csize > self.MAX_CLUSTER_SIZE:
            self.skipTest(
                f'{image_id}: cluster_size {csize} > '
                f'{self.MAX_CLUSTER_SIZE} (unsupported)'
            )
        if csize and csize < self.MIN_CLUSTER_SIZE:
            self.skipTest(
                f'{image_id}: cluster_size {csize} < '
                f'{self.MIN_CLUSTER_SIZE} (unsupported)'
            )

        # Compressed clusters with large cluster sizes can't be
        # decompressed (buffer limited to MAX_SECTOR_SIZE).
        if csize and csize > self.MAX_DECOMPRESS_CLUSTER:
            result = subprocess.run(
                [
                    'qemu-img', 'check', '--output=json',
                    '-f', 'qcow2', str(image_path),
                ],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 3):
                info = json.loads(result.stdout)
                comp = info.get('compressed-clusters', 0)
                if comp > 0:
                    self.skipTest(
                        f'{image_id}: {comp} compressed '
                        f'clusters with cluster_size '
                        f'{csize} (unsupported)'
                    )

        # Need 2x virtual_size of temp space (imago + qemu-img
        # outputs). Check available space with a safety margin.
        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 2 + 100 * 1024 * 1024  # +100MB
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB available'
                )

    def _test_manifest_convert(self, image_id):
        """Convert a manifest image and cross-validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        self.skip_if_hash_mismatch(image)
        self._skip_if_unsupported(image_id, image.path)

        vsize, _ = self._get_qcow2_info(image.path)
        timeout = self._timeout_for_vsize(vsize)

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            # Convert with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_convert_cirros_qcow2(self):
        """Convert cirros QCOW2 image."""
        self._test_manifest_convert('cirros-qcow2')

    def test_convert_qcow2_v2(self):
        """Convert QCOW2 v2 format image."""
        self._test_manifest_convert('qcow2-v2')

    def test_convert_qcow2_lazy_refcounts(self):
        """Convert QCOW2 with lazy refcounts."""
        self._test_manifest_convert('qcow2-lazy-refcounts')

    def test_convert_qcow2_min_cluster(self):
        """Convert QCOW2 with minimum cluster size."""
        self._test_manifest_convert('qcow2-min-cluster')

    def test_convert_qcow2_refcount_bits_1(self):
        """Convert QCOW2 with 1-bit refcounts."""
        self._test_manifest_convert('qcow2-refcount-bits-1')

    def test_convert_debian_12_sfagent(self):
        """Convert Debian 12 sfagent QCOW2 image."""
        self._test_manifest_convert('debian-12-sfagent')

    def test_convert_aurel32_sparc(self):
        """Convert Aurel32 Debian Etch SPARC image."""
        self._test_manifest_convert(
            'aurel32-debian-etch-sparc'
        )

    def test_convert_aurel32_armel(self):
        """Convert Aurel32 Debian Squeeze ARMEL image."""
        self._test_manifest_convert(
            'aurel32-debian-squeeze-armel'
        )

    def test_convert_aurel32_i386(self):
        """Convert Aurel32 Debian Squeeze i386 image."""
        self._test_manifest_convert(
            'aurel32-debian-squeeze-i386'
        )

    def test_convert_aurel32_powerpc(self):
        """Convert Aurel32 Debian Wheezy PowerPC image."""
        self._test_manifest_convert(
            'aurel32-debian-wheezy-powerpc'
        )

    def test_convert_qcow2_max_cluster(self):
        """Convert QCOW2 with maximum 2MB cluster size."""
        self._test_manifest_convert('qcow2-max-cluster')


class TestConvertRawToQcow2(ImagoTestBase):
    """Test raw to QCOW2 conversion."""

    def test_convert_empty_raw_to_qcow2(self):
        """Convert an empty raw image to QCOW2."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate with qemu-img check
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

    def test_convert_raw_with_data_to_qcow2(self):
        """Convert raw with written data to QCOW2."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xAB 524288 8192', raw.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

    def test_convert_qcow2_output_correct_virtual_size(self):
        """QCOW2 output has correct virtual size."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '2M'],
                capture_output=True
            )
            self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2'
            )
            result = subprocess.run(
                ['qemu-img', 'info', '--output=json',
                 qcow2.name],
                capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info['virtual-size'], 2 * 1024 * 1024
            )

    def test_convert_qcow2_output_smaller_than_virtual(self):
        """QCOW2 output file is smaller than virtual size."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '10M'],
                capture_output=True
            )
            # Write just a little data
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw.name],
                capture_output=True
            )
            self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2', skip_zeros=True
            )
            qcow2_size = os.path.getsize(qcow2.name)
            # QCOW2 with skip_zeros should be much smaller
            # than the 10M virtual size
            self.assertLess(
                qcow2_size, 5 * 1024 * 1024,
                f'QCOW2 output ({qcow2_size}) not smaller '
                f'than virtual size'
            )


class TestConvertRoundTrip(ImagoTestBase):
    """Test round-trip conversions."""

    def test_roundtrip_empty(self):
        """Round-trip: raw -> qcow2 -> raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            # raw -> qcow2
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # qcow2 -> raw
            stdout, stderr, rc = self.run_imago_convert(
                Path(mid.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs: {cmp_out}'
            )

    def test_roundtrip_with_data(self):
        """Round-trip with data: raw -> qcow2 -> raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xAB 524288 8192', src.name],
                capture_output=True
            )

            self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            self.run_imago_convert(
                Path(mid.name), Path(dst.name)
            )

            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs: {cmp_out}'
            )

    def test_roundtrip_with_skip_zeros(self):
        """Round-trip with skip_zeros: raw -> qcow2 -> raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )

            self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', skip_zeros=True
            )
            self.run_imago_convert(
                Path(mid.name), Path(dst.name)
            )

            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs: {cmp_out}'
            )

    def test_roundtrip_qcow2_to_qcow2(self):
        """Round-trip: qcow2 -> qcow2 (re-encode)."""
        with tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )

            # Re-encode qcow2 -> qcow2
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate re-encoded image
            result = subprocess.run(
                ['qemu-img', 'check', mid.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Convert both to raw and compare
            self.run_imago_convert(
                Path(src.name), Path(r1.name)
            )
            self.run_imago_convert(
                Path(mid.name), Path(r2.name)
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(r1.name), Path(r2.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Re-encoded differs: {cmp_out}'
            )


class TestConvertToQcow2CrossValidation(ImagoTestBase):
    """Cross-validate QCOW2 output with qemu-img."""

    def test_qemu_img_check_passes(self):
        """qemu-img check passes on imago QCOW2 output."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 65536', raw.name],
                capture_output=True
            )
            self.run_imago_convert(
                Path(raw.name), Path(q.name),
                output_format='qcow2'
            )
            result = subprocess.run(
                ['qemu-img', 'check', q.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

    def test_qemu_img_can_read_output(self):
        """qemu-img can convert imago QCOW2 output back."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as imago_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as qemu_raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )

            # imago raw -> qcow2
            self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            # imago qcow2 -> raw
            self.run_imago_convert(
                Path(mid.name), Path(imago_raw.name)
            )
            # qemu-img qcow2 -> raw
            self.run_qemu_img_convert(
                Path(mid.name), Path(qemu_raw.name)
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'qemu-img read differs: {cmp_out}'
            )

    def test_imago_check_passes(self):
        """imago check passes on imago QCOW2 output."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw.name],
                capture_output=True
            )
            self.run_imago_convert(
                Path(raw.name), Path(q.name),
                output_format='qcow2'
            )
            stdout, stderr, rc = self.run_imago_check(
                Path(q.name)
            )
            self.assertEqual(
                rc, 0,
                f'imago check failed: {stderr}'
            )


class TestConvertToQcow2BackingChain(ImagoTestBase):
    """Test flattening backing chains to standalone QCOW2."""

    def test_chain_to_qcow2(self):
        """Flatten a backing chain to standalone QCOW2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / 'base.raw'
            overlay = Path(tmpdir) / 'overlay.qcow2'
            output = Path(tmpdir) / 'output.qcow2'
            raw1 = Path(tmpdir) / 'raw1.raw'
            raw2 = Path(tmpdir) / 'raw2.raw'

            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 str(base), '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xBB 0 4096', str(base)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', str(base), '-F', 'raw',
                 str(overlay)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xAA 65536 4096',
                 str(overlay)],
                capture_output=True
            )

            # Flatten to standalone QCOW2
            stdout, stderr, rc = self.run_imago_convert(
                overlay, output, output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate structural integrity
            result = subprocess.run(
                ['qemu-img', 'check', str(output)],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Verify no backing file reference
            result = subprocess.run(
                ['qemu-img', 'info', '--output=json',
                 str(output)],
                capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            self.assertNotIn('backing-filename', info)

            # Compare virtual content
            self.run_imago_convert(overlay, raw1)
            self.run_imago_convert(output, raw2)
            cmp_out, _, cmp_rc = self.run_imago_compare(
                raw1, raw2
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Flattened differs: {cmp_out}'
            )


class TestConvertToQcow2ManifestRaw(ImagoTestBase):
    """Convert manifest raw images to QCOW2.

    For each raw image in the manifest, convert to QCOW2,
    validate with qemu-img check, and round-trip back to raw
    to verify content preservation.
    """

    # Images with QCOW2 magic bytes (raw-misleading-header) are
    # excluded because imago's format detection interprets them
    # as QCOW2, resulting in zero virtual size.
    RAW_IMAGE_IDS = [
        'raw-mbr-partitioned',
        'raw-gpt-partitioned',
        'raw-fat-no-partition',
        'raw-sparse-empty',
        'raw-zeros-1mb',
        'raw-mbr-truncated',
        'raw-gpt-truncated',
        'raw-mbr-corrupted',
        'raw-random-garbage',
        'raw-minimal-1byte',
        'raw-qcow2-magic-wrong-offset',
    ]

    _compress = False

    def _test_raw_to_qcow2(self, image_id):
        """Convert a raw manifest image to QCOW2."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as roundtrip:
            # Convert raw -> qcow2
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(qcow2.name),
                output_format='qcow2',
                compress=self._compress,
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            # Validate with qemu-img check
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed for {image_id}: '
                f'{result.stderr}'
            )

            # Round-trip: qcow2 -> raw
            stdout, stderr, rc = self.run_imago_convert(
                Path(qcow2.name), Path(roundtrip.name),
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'Round-trip convert failed for '
                f'{image_id}: {stderr}'
            )

            # Compare with original
            cmp_out, _, cmp_rc = self.run_imago_compare(
                image.path, Path(roundtrip.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs for {image_id}: '
                f'{cmp_out}'
            )

    def test_raw_mbr_partitioned(self):
        """Convert raw-mbr-partitioned to QCOW2."""
        self._test_raw_to_qcow2('raw-mbr-partitioned')

    def test_raw_gpt_partitioned(self):
        """Convert raw-gpt-partitioned to QCOW2."""
        self._test_raw_to_qcow2('raw-gpt-partitioned')

    def test_raw_fat_no_partition(self):
        """Convert raw-fat-no-partition to QCOW2."""
        self._test_raw_to_qcow2('raw-fat-no-partition')

    def test_raw_sparse_empty(self):
        """Convert raw-sparse-empty to QCOW2."""
        self._test_raw_to_qcow2('raw-sparse-empty')

    def test_raw_zeros_1mb(self):
        """Convert raw-zeros-1mb to QCOW2."""
        self._test_raw_to_qcow2('raw-zeros-1mb')

    def test_raw_mbr_truncated(self):
        """Convert raw-mbr-truncated to QCOW2."""
        self._test_raw_to_qcow2('raw-mbr-truncated')

    def test_raw_gpt_truncated(self):
        """Convert raw-gpt-truncated to QCOW2."""
        self._test_raw_to_qcow2('raw-gpt-truncated')

    def test_raw_mbr_corrupted(self):
        """Convert raw-mbr-corrupted to QCOW2."""
        self._test_raw_to_qcow2('raw-mbr-corrupted')

    def test_raw_random_garbage(self):
        """Convert raw-random-garbage to QCOW2."""
        self._test_raw_to_qcow2('raw-random-garbage')

    def test_raw_minimal_1byte(self):
        """Convert raw-minimal-1byte to QCOW2."""
        self._test_raw_to_qcow2('raw-minimal-1byte')

    def test_raw_qcow2_magic_wrong_offset(self):
        """Convert raw-qcow2-magic-wrong-offset to QCOW2."""
        self._test_raw_to_qcow2(
            'raw-qcow2-magic-wrong-offset'
        )


class TestConvertCompressedOutput(ImagoTestBase):
    """Test compressed QCOW2 output (-c flag)."""

    def test_compress_raw_to_qcow2(self):
        """Convert raw with data to compressed QCOW2."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 65536', raw.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate with qemu-img check
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

    def test_compress_round_trip(self):
        """Round-trip: raw -> compressed qcow2 -> raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xAB 524288 8192', src.name],
                capture_output=True
            )

            # raw -> compressed qcow2
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # compressed qcow2 -> raw
            stdout, stderr, rc = self.run_imago_convert(
                Path(mid.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare with original
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs: {cmp_out}'
            )

    def test_compress_output_smaller(self):
        """Compressed QCOW2 is smaller than uncompressed."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as uncomp, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as comp:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            # Write compressible pattern (repeated bytes)
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 1048576', raw.name],
                capture_output=True
            )

            # Uncompressed qcow2
            self.run_imago_convert(
                Path(raw.name), Path(uncomp.name),
                output_format='qcow2'
            )
            # Compressed qcow2
            self.run_imago_convert(
                Path(raw.name), Path(comp.name),
                output_format='qcow2', compress=True
            )

            uncomp_size = os.path.getsize(uncomp.name)
            comp_size = os.path.getsize(comp.name)
            self.assertLess(
                comp_size, uncomp_size,
                f'Compressed ({comp_size}) not smaller '
                f'than uncompressed ({uncomp_size})'
            )

    def test_compress_qcow2_to_compressed_qcow2(self):
        """Re-encode QCOW2 input as compressed QCOW2."""
        with tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as comp, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as r2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x42 0 4096', src.name],
                capture_output=True
            )

            # Re-encode with compression
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(comp.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', comp.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Compare virtual content via raw
            self.run_imago_convert(
                Path(src.name), Path(r1.name)
            )
            self.run_imago_convert(
                Path(comp.name), Path(r2.name)
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(r1.name), Path(r2.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Re-encoded differs: {cmp_out}'
            )

    def test_compress_with_backing_chain(self):
        """Flatten backing chain to compressed QCOW2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / 'base.raw'
            overlay = Path(tmpdir) / 'overlay.qcow2'
            output = Path(tmpdir) / 'output.qcow2'
            raw1 = Path(tmpdir) / 'raw1.raw'
            raw2 = Path(tmpdir) / 'raw2.raw'

            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 str(base), '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xBB 0 4096', str(base)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', str(base), '-F', 'raw',
                 str(overlay)],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xAA 65536 4096',
                 str(overlay)],
                capture_output=True
            )

            # Flatten to compressed QCOW2
            stdout, stderr, rc = self.run_imago_convert(
                overlay, output,
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', str(output)],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # No backing file reference
            result = subprocess.run(
                ['qemu-img', 'info', '--output=json',
                 str(output)],
                capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            self.assertNotIn('backing-filename', info)

            # Compare virtual content
            self.run_imago_convert(overlay, raw1)
            self.run_imago_convert(output, raw2)
            cmp_out, _, cmp_rc = self.run_imago_compare(
                raw1, raw2
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Flattened differs: {cmp_out}'
            )

    def test_compress_incompressible_data(self):
        """Compress random (incompressible) data."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as roundtrip:
            # Create raw with random data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )
            # Write random data via dd from /dev/urandom
            subprocess.run(
                ['dd', 'if=/dev/urandom',
                 f'of={raw.name}',
                 'bs=65536', 'count=16',
                 'conv=notrunc'],
                capture_output=True
            )

            stdout, stderr, rc = self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Must still be valid
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Round-trip must preserve data
            self.run_imago_convert(
                Path(qcow2.name), Path(roundtrip.name)
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(raw.name), Path(roundtrip.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs: {cmp_out}'
            )

    def test_compress_empty_image(self):
        """Compress an all-zero image."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True
            )

            stdout, stderr, rc = self.run_imago_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

    def test_compress_cross_validate_with_qemu(self):
        """Cross-validate imago compressed output with qemu."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as imago_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as qemu_raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 65536', src.name],
                capture_output=True
            )

            # imago raw -> compressed qcow2
            self.run_imago_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', compress=True
            )
            # imago compressed qcow2 -> raw
            self.run_imago_convert(
                Path(mid.name), Path(imago_raw.name)
            )
            # qemu-img compressed qcow2 -> raw
            self.run_qemu_img_convert(
                Path(mid.name), Path(qemu_raw.name)
            )
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'qemu-img read differs: {cmp_out}'
            )


class TestConvertCompressedManifestRaw(
    TestConvertToQcow2ManifestRaw
):
    """Convert manifest raw images to compressed QCOW2.

    Inherits all test cases from TestConvertToQcow2ManifestRaw
    but runs them with compression enabled.
    """

    _compress = True


class TestConvertToQcow2ManifestQcow2(ImagoTestBase):
    """Re-encode manifest QCOW2 images to fresh QCOW2.

    For each standalone QCOW2 in the manifest, re-encode to
    a fresh QCOW2, validate with qemu-img check, and
    round-trip both through raw to verify identical virtual
    content.
    """

    _compress = False

    STANDALONE_QCOW2_IDS = [
        'cirros-qcow2',
        'qcow2-v2',
        'qcow2-lazy-refcounts',
        'qcow2-min-cluster',
        'qcow2-refcount-bits-1',
        'qcow2-max-cluster',
        'debian-12-sfagent',
        'aurel32-debian-etch-sparc',
        'aurel32-debian-squeeze-armel',
        'aurel32-debian-squeeze-i386',
        'aurel32-debian-wheezy-powerpc',
    ]

    MAX_CLUSTER_SIZE = 2097152
    MIN_CLUSTER_SIZE = 65536

    def _get_qcow2_info(self, image_path):
        """Get virtual_size and cluster_size via qemu-img."""
        result = subprocess.run(
            ['qemu-img', 'info', '--output=json',
             str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None, None
        info = json.loads(result.stdout)
        return (
            info.get('virtual-size'),
            info.get('cluster-size'),
        )

    def _timeout_for_vsize(self, vsize):
        """Compute a per-operation timeout based on virtual size.

        Returns a timeout in seconds that scales with image
        virtual size. Uses 120s as minimum and adds 30s per
        GiB of virtual size to accommodate CI I/O variance.
        """
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    # Max I/O buffer size for decompression
    MAX_DECOMPRESS_CLUSTER = 65536

    def _skip_if_unsupported(self, image_id, image_path):
        """Skip if image has unsupported features."""
        vsize, csize = self._get_qcow2_info(image_path)
        if csize and csize > self.MAX_CLUSTER_SIZE:
            self.skipTest(
                f'{image_id}: cluster_size {csize} > '
                f'{self.MAX_CLUSTER_SIZE}'
            )
        if csize and csize < self.MIN_CLUSTER_SIZE:
            self.skipTest(
                f'{image_id}: cluster_size {csize} < '
                f'{self.MIN_CLUSTER_SIZE}'
            )

        # Compressed clusters with large cluster sizes
        # can't be decompressed (buffer limited).
        if csize and csize > self.MAX_DECOMPRESS_CLUSTER:
            result = subprocess.run(
                [
                    'qemu-img', 'check', '--output=json',
                    '-f', 'qcow2', str(image_path),
                ],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 3):
                info = json.loads(result.stdout)
                comp = info.get(
                    'compressed-clusters', 0
                )
                if comp > 0:
                    self.skipTest(
                        f'{image_id}: {comp} compressed '
                        f'clusters with cluster_size '
                        f'{csize} (unsupported)'
                    )

        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            # Need space for: re-encoded qcow2, 2x raw
            needed = vsize * 2 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp'
                )

    def _test_reencode_qcow2(self, image_id):
        """Re-encode a QCOW2 image and validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)
        self._skip_if_unsupported(image_id, image.path)

        vsize, _ = self._get_qcow2_info(image.path)
        timeout = self._timeout_for_vsize(vsize)

        with tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as reenc, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as raw_orig, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as raw_reenc:
            # Re-encode: qcow2 -> qcow2
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(reenc.name),
                output_format='qcow2',
                compress=self._compress,
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'Re-encode failed for {image_id}: '
                f'{stderr}'
            )

            # Validate with qemu-img check
            result = subprocess.run(
                ['qemu-img', 'check', reenc.name],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed for {image_id}: '
                f'{result.stderr}'
            )

            # Convert both to raw via qemu-img
            self.run_qemu_img_convert(
                image.path, Path(raw_orig.name),
                timeout=timeout
            )
            self.run_qemu_img_convert(
                Path(reenc.name), Path(raw_reenc.name),
                timeout=timeout
            )

            # Compare virtual content
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(raw_orig.name),
                Path(raw_reenc.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Re-encoded {image_id} differs: '
                f'{cmp_out}'
            )

    def test_reencode_cirros(self):
        """Re-encode cirros QCOW2."""
        self._test_reencode_qcow2('cirros-qcow2')

    def test_reencode_v2(self):
        """Re-encode QCOW2 v2."""
        self._test_reencode_qcow2('qcow2-v2')

    def test_reencode_lazy_refcounts(self):
        """Re-encode QCOW2 with lazy refcounts."""
        self._test_reencode_qcow2('qcow2-lazy-refcounts')

    def test_reencode_min_cluster(self):
        """Re-encode QCOW2 with minimum cluster size."""
        self._test_reencode_qcow2('qcow2-min-cluster')

    def test_reencode_refcount_bits_1(self):
        """Re-encode QCOW2 with 1-bit refcounts."""
        self._test_reencode_qcow2('qcow2-refcount-bits-1')

    def test_reencode_debian_12(self):
        """Re-encode Debian 12 sfagent QCOW2."""
        self._test_reencode_qcow2('debian-12-sfagent')

    def test_reencode_sparc(self):
        """Re-encode Aurel32 SPARC QCOW2."""
        self._test_reencode_qcow2(
            'aurel32-debian-etch-sparc'
        )

    def test_reencode_armel(self):
        """Re-encode Aurel32 ARMEL QCOW2."""
        self._test_reencode_qcow2(
            'aurel32-debian-squeeze-armel'
        )

    def test_reencode_i386(self):
        """Re-encode Aurel32 i386 QCOW2."""
        self._test_reencode_qcow2(
            'aurel32-debian-squeeze-i386'
        )

    def test_reencode_powerpc(self):
        """Re-encode Aurel32 PowerPC QCOW2."""
        self._test_reencode_qcow2(
            'aurel32-debian-wheezy-powerpc'
        )

    def test_reencode_max_cluster(self):
        """Re-encode QCOW2 with maximum 2MB cluster size."""
        self._test_reencode_qcow2('qcow2-max-cluster')


class TestConvertCompressedManifestQcow2(
    TestConvertToQcow2ManifestQcow2
):
    """Re-encode manifest QCOW2 images to compressed QCOW2.

    Inherits all test cases from TestConvertToQcow2ManifestQcow2
    but runs them with compression enabled.
    """

    _compress = True


class TestConvertLargeCluster(ImagoTestBase):
    """Test convert and compare with cluster sizes > 64KB.

    Verifies that large-cluster QCOW2 images can be converted to
    raw and that the output matches qemu-img conversion.
    """

    def test_convert_2mb_cluster_to_raw(self):
        """Convert a 2MB-cluster QCOW2 to raw, cross-validate."""
        with tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as f:
            qcow2_path = f.name
        try:
            subprocess.run(
                [
                    'qemu-img', 'create', '-f', 'qcow2',
                    '-o', 'cluster_size=2M',
                    qcow2_path, '64M',
                ],
                check=True, capture_output=True, timeout=30,
            )
            # Write data at various offsets
            for offset in ['0', '4M', '32M', '60M']:
                subprocess.run(
                    [
                        'qemu-io', '-f', 'qcow2', '-c',
                        f'write -P 0xAB {offset} 64K',
                        qcow2_path,
                    ],
                    check=True, capture_output=True,
                    timeout=30,
                )

            with tempfile.NamedTemporaryFile(
                suffix='.raw', delete=False
            ) as imago_f, tempfile.NamedTemporaryFile(
                suffix='.raw', delete=False
            ) as qemu_f:
                imago_raw = imago_f.name
                qemu_raw = qemu_f.name
                try:
                    # Convert with imago
                    stdout, stderr, rc = \
                        self.run_imago_convert(
                            Path(qcow2_path),
                            Path(imago_raw),
                        )
                    self.assertEqual(
                        rc, 0,
                        f'imago convert failed: {stderr}'
                    )

                    # Convert with qemu-img
                    subprocess.run(
                        [
                            'qemu-img', 'convert',
                            '-f', 'qcow2', '-O', 'raw',
                            qcow2_path, qemu_raw,
                        ],
                        check=True, capture_output=True,
                        timeout=120,
                    )

                    # Compare outputs
                    cmp_out, _, cmp_rc = \
                        self.run_imago_compare(
                            Path(imago_raw),
                            Path(qemu_raw),
                        )
                    self.assertEqual(
                        cmp_rc, 0,
                        f'Convert output differs from '
                        f'qemu-img: {cmp_out}'
                    )
                finally:
                    os.unlink(imago_raw)
                    os.unlink(qemu_raw)
        finally:
            os.unlink(qcow2_path)

    def test_compare_2mb_cluster_vs_raw(self):
        """Compare a 2MB-cluster QCOW2 against its raw equivalent."""
        with tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as qf, tempfile.NamedTemporaryFile(
            suffix='.raw', delete=False
        ) as rf:
            qcow2_path = qf.name
            raw_path = rf.name
        try:
            # Create raw with known content
            subprocess.run(
                [
                    'qemu-img', 'create', '-f', 'raw',
                    raw_path, '16M',
                ],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    'qemu-io', '-f', 'raw', '-c',
                    'write -P 0xBE 0 1M',
                    raw_path,
                ],
                check=True, capture_output=True, timeout=30,
            )

            # Convert raw to 2MB-cluster QCOW2 via qemu-img
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '-f', 'raw', '-O', 'qcow2',
                    '-o', 'cluster_size=2M',
                    raw_path, qcow2_path,
                ],
                check=True, capture_output=True, timeout=30,
            )

            # Compare QCOW2 against raw with imago
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(qcow2_path), Path(raw_path),
            )
            self.assertEqual(
                cmp_rc, 0,
                f'2MB-cluster QCOW2 differs from raw: '
                f'{cmp_out}'
            )
        finally:
            os.unlink(qcow2_path)
            os.unlink(raw_path)


class TestConvertVmdkToRaw(ImagoTestBase):
    """Test VMDK monolithicSparse to raw conversion.

    Converts monolithicSparse VMDK images to raw and
    cross-validates against qemu-img convert output.
    """

    VMDK_SPARSE_IDS = [
        'plaso-vmdk',
        'vmdk-multi-partition',
        'chain-base-vmdk',
    ]

    def _get_vmdk_info(self, image_path):
        """Get virtual_size via qemu-img info."""
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image_path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        info = json.loads(result.stdout)
        return info.get('virtual-size')

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _test_vmdk_convert(self, image_id):
        """Convert a VMDK image to raw and cross-validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vmdk_info(image.path)
        timeout = self._timeout_for_vsize(vsize)

        # Check available temp space
        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 2 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            # Convert with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_convert_plaso_vmdk(self):
        """Convert plaso monolithicSparse VMDK to raw."""
        self._test_vmdk_convert('plaso-vmdk')

    def test_convert_vmdk_multi_partition(self):
        """Convert multi-partition VMDK to raw."""
        self._test_vmdk_convert('vmdk-multi-partition')

    def test_convert_chain_base_vmdk(self):
        """Convert backing chain base VMDK to raw."""
        self._test_vmdk_convert('chain-base-vmdk')


class TestConvertVmdkCompare(ImagoTestBase):
    """Test comparing VMDK images against raw equivalents.

    Uses imago compare to verify VMDK virtual content matches
    the qemu-img-converted raw baseline.
    """

    def _compare_vmdk_vs_raw(self, image_id):
        """Compare VMDK against its qemu-img-converted raw."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with qemu-img as baseline
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=120
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare VMDK directly against raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                image.path, Path(qemu_raw.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Sparse VMDK {image_id} content '
                f'differs from raw: {cmp_out}'
            )

    def test_compare_plaso_vmdk_vs_raw(self):
        """Compare plaso VMDK against qemu-img raw."""
        self._compare_vmdk_vs_raw('plaso-vmdk')

    def test_compare_vmdk_multi_partition_vs_raw(self):
        """Compare multi-partition VMDK against raw."""
        self._compare_vmdk_vs_raw('vmdk-multi-partition')

    def test_compare_chain_base_vmdk_vs_raw(self):
        """Compare chain base VMDK against raw."""
        self._compare_vmdk_vs_raw('chain-base-vmdk')


class TestConvertVmdkStreamOptimized(ImagoTestBase):
    """Test streamOptimized VMDK conversion and comparison.

    streamOptimized VMDKs use DEFLATE-compressed grains with
    grain markers, and store the grain directory at the end of
    the file (GD_AT_END). This tests decompression and footer
    reading.
    """

    STREAM_OPT_IDS = [
        'vmdk-streamoptimized',
        'vmdk-v3',
    ]

    def _get_vmdk_info(self, image_path):
        """Get virtual_size via qemu-img info."""
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image_path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        info = json.loads(result.stdout)
        return info.get('virtual-size')

    def _test_streamopt_convert(self, image_id):
        """Convert streamOptimized VMDK to raw, validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vmdk_info(image.path)
        timeout = max(120, int(120 + (vsize or 0)
                                / (1024 ** 3) * 10))

        # Check temp space
        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 2 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            # Convert with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_convert_vmdk_streamoptimized(self):
        """Convert streamOptimized VMDK to raw."""
        self._test_streamopt_convert(
            'vmdk-streamoptimized'
        )

    def test_convert_vmdk_v3(self):
        """Convert VMDK v3 (streamOptimized) to raw."""
        self._test_streamopt_convert('vmdk-v3')

    def _compare_streamopt_vs_raw(self, image_id):
        """Compare streamOptimized VMDK vs raw baseline."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vmdk_info(image.path)

        # Check temp space
        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        timeout = max(120, int(120 + (vsize or 0)
                                / (1024 ** 3) * 10))

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            cmp_out, _, cmp_rc = self.run_imago_compare(
                image.path, Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'StreamOpt VMDK {image_id} differs '
                f'from raw: {cmp_out}'
            )

    def test_compare_vmdk_streamoptimized_vs_raw(self):
        """Compare streamOptimized VMDK against raw."""
        self._compare_streamopt_vs_raw(
            'vmdk-streamoptimized'
        )

    def test_compare_vmdk_v3_vs_raw(self):
        """Compare VMDK v3 (streamOptimized) vs raw."""
        self._compare_streamopt_vs_raw('vmdk-v3')


class TestConvertToVmdk(ImagoTestBase):
    """Test converting images to VMDK monolithicSparse output.

    Converts images to VMDK with imago, then verifies the output
    by converting back to raw and comparing against qemu-img.
    """

    def _test_to_vmdk_roundtrip(self, image_id):
        """Convert image to VMDK, then back to raw, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vmdk') as vmdk_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert to VMDK with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vmdk failed for '
                f'{image_id}: {stderr}'
            )

            # Verify qemu-img can read the VMDK
            result = subprocess.run(
                [
                    'qemu-img', 'info', '--output=json',
                    vmdk_out.name,
                ],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img info failed on imago VMDK: '
                f'{result.stderr}'
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info.get('format'), 'vmdk',
                f'Output is not VMDK format: '
                f'{info.get("format")}'
            )

            # Round-trip: convert VMDK back to raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(vmdk_out.name),
                    Path(rt_raw.name),
                    timeout=120
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip convert failed for '
                f'{image_id}: {rt_stderr}'
            )

            # Convert original to raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=120
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed: {q_stderr}'
            )

            # Compare round-tripped raw vs qemu-img raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip mismatch for {image_id}: '
                f'{cmp_out}'
            )

    def test_raw_to_vmdk_roundtrip(self):
        """Round-trip: raw -> vmdk -> raw."""
        self._test_to_vmdk_roundtrip('raw-mbr-partitioned')

    def test_qcow2_to_vmdk_roundtrip(self):
        """Round-trip: qcow2 -> vmdk -> raw."""
        self._test_to_vmdk_roundtrip('cirros-qcow2')

    def test_vmdk_to_vmdk_roundtrip(self):
        """Round-trip: vmdk -> vmdk -> raw."""
        self._test_to_vmdk_roundtrip('plaso-vmdk')


class TestConvertToVmdkCompressed(ImagoTestBase):
    """Test converting images to streamOptimized VMDK output.

    Uses -O vmdk -c to produce compressed streamOptimized VMDKs,
    then verifies by converting back to raw and comparing.
    """

    def _test_to_vmdk_compressed_roundtrip(
        self, image_id, timeout=120
    ):
        """Convert to streamOptimized VMDK, round-trip, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vmdk') as vmdk_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert to streamOptimized VMDK
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                compress=True,
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to streamOptimized vmdk '
                f'failed for {image_id}: {stderr}'
            )

            # Verify qemu-img can read and reports
            # streamOptimized format
            result = subprocess.run(
                [
                    'qemu-img', 'info', '--output=json',
                    vmdk_out.name,
                ],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img info failed: {result.stderr}'
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info.get('format'), 'vmdk',
                f'Not VMDK: {info.get("format")}'
            )

            # Round-trip: streamOptimized VMDK -> raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(vmdk_out.name),
                    Path(rt_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip convert failed for '
                f'{image_id}: {rt_stderr}'
            )

            # Convert original to raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed: {q_stderr}'
            )

            # Compare round-tripped raw vs qemu-img raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip mismatch for {image_id}: '
                f'{cmp_out}'
            )

    def test_raw_to_streamoptimized_vmdk(self):
        """Round-trip: raw -> streamOptimized vmdk -> raw."""
        self._test_to_vmdk_compressed_roundtrip(
            'raw-mbr-partitioned'
        )

    def test_qcow2_to_streamoptimized_vmdk(self):
        """Round-trip: qcow2 -> streamOptimized vmdk -> raw."""
        self._test_to_vmdk_compressed_roundtrip(
            'cirros-qcow2'
        )

    def test_vmdk_to_streamoptimized_vmdk(self):
        """Round-trip: vmdk -> streamOptimized vmdk -> raw."""
        self._test_to_vmdk_compressed_roundtrip('plaso-vmdk')


class TestConvertVmdkToQcow2Roundtrip(ImagoTestBase):
    """Test VMDK -> QCOW2 -> raw roundtrip conversions.

    Converts VMDK images to QCOW2 with imago, then back to raw,
    and cross-validates against qemu-img.
    """

    def _test_vmdk_to_qcow2_roundtrip(self, image_id):
        """Convert VMDK to QCOW2, then to raw, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.qcow2') as qcow2_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert VMDK to QCOW2
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(qcow2_out.name),
                output_format='qcow2',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert vmdk->qcow2 failed for '
                f'{image_id}: {stderr}'
            )

            # Round-trip: QCOW2 -> raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(qcow2_out.name),
                    Path(rt_raw.name),
                    timeout=120
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip qcow2->raw failed for '
                f'{image_id}: {rt_stderr}'
            )

            # Convert original to raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=120
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed: {q_stderr}'
            )

            # Compare round-tripped raw vs qemu-img raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VMDK->QCOW2->raw mismatch for '
                f'{image_id}: {cmp_out}'
            )

    def test_plaso_vmdk_to_qcow2(self):
        """Round-trip: monolithicSparse vmdk -> qcow2 -> raw."""
        self._test_vmdk_to_qcow2_roundtrip('plaso-vmdk')

    def test_streamoptimized_vmdk_to_qcow2(self):
        """Round-trip: streamOptimized vmdk -> qcow2 -> raw."""
        self._test_vmdk_to_qcow2_roundtrip(
            'vmdk-streamoptimized'
        )

    def test_vmdk_multi_partition_to_qcow2(self):
        """Round-trip: multi-partition vmdk -> qcow2 -> raw."""
        self._test_vmdk_to_qcow2_roundtrip(
            'vmdk-multi-partition'
        )


class TestConvertVmdkCheckOutput(ImagoTestBase):
    """Test that imago-produced VMDK output passes check.

    Converts images to VMDK, then runs imago check to verify
    structural integrity of our own output.
    """

    def _test_vmdk_output_check(
        self, image_id, compress=False
    ):
        """Convert to VMDK, then check the output."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vmdk') as vmdk_out:
            # Convert to VMDK
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                compress=compress,
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vmdk failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VMDK
            chk_stdout, chk_stderr, chk_rc = \
                self.run_imago_check(
                    Path(vmdk_out.name),
                    output_format='json'
                )
            result = json.loads(chk_stdout)

            self.assertEqual(
                result.get('format', '').lower(), 'vmdk',
                f'Output should be detected as vmdk'
            )
            self.assertEqual(
                result.get('check-errors', -1), 0,
                f'imago VMDK output should have 0 errors: '
                f'{chk_stdout}'
            )

    def test_check_monolithic_sparse_output(self):
        """Check imago monolithicSparse VMDK output."""
        self._test_vmdk_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_streamoptimized_output(self):
        """Check imago streamOptimized VMDK output."""
        self._test_vmdk_output_check(
            'raw-mbr-partitioned', compress=True
        )

    def test_check_qcow2_to_vmdk_output(self):
        """Check imago VMDK output from QCOW2 input."""
        self._test_vmdk_output_check('cirros-qcow2')

    def test_check_vmdk_to_vmdk_output(self):
        """Check imago VMDK output from VMDK input."""
        self._test_vmdk_output_check('plaso-vmdk')


class TestConvertVhdxToRaw(ImagoTestBase):
    """Test VHDX to raw conversion.

    Converts VHDX images to raw and cross-validates against
    qemu-img convert output.
    """

    VHDX_IDS = [
        'qemu-vhdx',
        'vhdx-disk2vhd',
    ]

    def _get_vhdx_info(self, image_path):
        """Get virtual_size via qemu-img info."""
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image_path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        info = json.loads(result.stdout)
        return info.get('virtual-size')

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _test_vhdx_convert(self, image_id):
        """Convert a VHDX image to raw and cross-validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vhdx_info(image.path)
        timeout = self._timeout_for_vsize(vsize)

        # Check available temp space
        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 2 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            # Convert with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_convert_qemu_vhdx(self):
        """Convert QEMU iotest VHDX to raw."""
        self._test_vhdx_convert('qemu-vhdx')

    def test_convert_vhdx_disk2vhd(self):
        """Convert Disk2VHD VHDX to raw."""
        self._test_vhdx_convert('vhdx-disk2vhd')


class TestConvertVhdxCompare(ImagoTestBase):
    """Test comparing VHDX images against raw equivalents.

    Uses imago compare to verify VHDX virtual content matches
    the qemu-img-converted raw baseline.
    """

    def _compare_vhdx_vs_raw(self, image_id):
        """Compare VHDX against its qemu-img-converted raw."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with qemu-img as baseline
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=120
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare VHDX directly against raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                image.path, Path(qemu_raw.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHDX {image_id} content '
                f'differs from raw: {cmp_out}'
            )

    def test_compare_qemu_vhdx_vs_raw(self):
        """Compare QEMU iotest VHDX against raw."""
        self._compare_vhdx_vs_raw('qemu-vhdx')

    def test_compare_vhdx_disk2vhd_vs_raw(self):
        """Compare Disk2VHD VHDX against raw."""
        self._compare_vhdx_vs_raw('vhdx-disk2vhd')


class TestConvertToVhdx(ImagoTestBase):
    """Test converting images to VHDX output.

    Converts images to VHDX with imago, then verifies the output
    by converting back to raw and comparing against qemu-img.
    """

    def _test_to_vhdx_roundtrip(self, image_id):
        """Convert image to VHDX, then back to raw, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vhdx') as vhdx_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert to VHDX with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vhdx_out.name),
                output_format='vhdx',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vhdx failed for '
                f'{image_id}: {stderr}'
            )

            # Verify qemu-img can read the VHDX
            result = subprocess.run(
                [
                    'qemu-img', 'info', '--output=json',
                    vhdx_out.name,
                ],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img info failed on imago VHDX: '
                f'{result.stderr}'
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info.get('format'), 'vhdx',
                f'Output is not VHDX format: '
                f'{info.get("format")}'
            )

            # Round-trip: convert VHDX back to raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(vhdx_out.name),
                    Path(rt_raw.name),
                    timeout=120
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip convert failed for '
                f'{image_id}: {rt_stderr}'
            )

            # Convert original to raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=120
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed: {q_stderr}'
            )

            # Compare round-tripped raw vs qemu-img raw
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=120
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip mismatch for {image_id}: '
                f'{cmp_out}'
            )

    def test_raw_to_vhdx_roundtrip(self):
        """Round-trip: raw -> vhdx -> raw."""
        self._test_to_vhdx_roundtrip('raw-mbr-partitioned')

    def test_qcow2_to_vhdx_roundtrip(self):
        """Round-trip: qcow2 -> vhdx -> raw."""
        self._test_to_vhdx_roundtrip('cirros-qcow2')

    def test_vhdx_to_vhdx_roundtrip(self):
        """Round-trip: vhdx -> vhdx -> raw."""
        self._test_to_vhdx_roundtrip('qemu-vhdx')


class TestConvertVhdxCheckOutput(ImagoTestBase):
    """Test that imago-produced VHDX output passes check.

    Converts images to VHDX, then runs imago check to verify
    structural integrity of our own output.
    """

    def _test_vhdx_output_check(self, image_id):
        """Convert to VHDX, then check the output."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vhdx') as vhdx_out:
            # Convert to VHDX
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vhdx_out.name),
                output_format='vhdx',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vhdx failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VHDX
            chk_stdout, chk_stderr, chk_rc = \
                self.run_imago_check(
                    Path(vhdx_out.name),
                    output_format='json'
                )
            result = json.loads(chk_stdout)

            self.assertEqual(
                result.get('format', '').lower(),
                'vhdx',
                f'Output should be detected as vhdx'
            )
            self.assertEqual(
                result.get('check-errors', -1), 0,
                f'imago VHDX output should have 0 '
                f'errors: {chk_stdout}'
            )

    def test_check_raw_to_vhdx_output(self):
        """Check imago VHDX output from raw input."""
        self._test_vhdx_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_qcow2_to_vhdx_output(self):
        """Check imago VHDX output from QCOW2 input."""
        self._test_vhdx_output_check('cirros-qcow2')

    def test_check_vhdx_to_vhdx_output(self):
        """Check imago VHDX output from VHDX input."""
        self._test_vhdx_output_check('qemu-vhdx')


class TestConvertVhdToRaw(ImagoTestBase):
    """Test VHD to raw conversion.

    Converts dynamic VHD images to raw and cross-validates
    against qemu-img convert output.
    """

    VHD_IDS = [
        'hyperv-dynamic-vhd',
        'virtualpc-vhd',
        'vhd-d2v-zerofilled',
    ]

    def _get_vhd_info(self, image_path):
        """Get virtual_size via qemu-img info."""
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image_path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        info = json.loads(result.stdout)
        return info.get('virtual-size')

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _test_vhd_convert(self, image_id):
        """Convert a VHD image to raw and cross-validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vhd_info(image.path)
        timeout = self._timeout_for_vsize(vsize)

        if vsize:
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 2 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert failed for {image_id}: '
                f'{stderr}'
            )

            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed for '
                f'{image_id}: {q_stderr}'
            )

            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_large_convert_hyperv_dynamic_vhd(self):
        """Convert Hyper-V 2012 R2 dynamic VHD to raw."""
        self._test_vhd_convert('hyperv-dynamic-vhd')

    def test_large_convert_virtualpc_vhd(self):
        """Convert Virtual PC dynamic VHD to raw."""
        self._test_vhd_convert('virtualpc-vhd')

    def test_convert_vhd_d2v_zerofilled(self):
        """Convert Disk2VHD zerofilled VHD to raw."""
        self._test_vhd_convert('vhd-d2v-zerofilled')


class TestConvertVhdCompare(ImagoTestBase):
    """Test comparing VHD images against raw equivalents.

    Uses imago compare to verify VHD virtual content matches
    the qemu-img-converted raw baseline.
    """

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _compare_vhd_vs_raw(self, image_id):
        """Compare VHD against its qemu-img-converted raw."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # qemu-img converts VHD to raw at full virtual
        # size; skip if insufficient temp space.
        vsize = 0
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image.path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            vsize = json.loads(
                result.stdout
            ).get('virtual-size', 0)
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        timeout = self._timeout_for_vsize(vsize)

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img convert failed: {q_stderr}'
            )

            cmp_out, _, cmp_rc = self.run_imago_compare(
                image.path, Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHD {image_id} content '
                f'differs from raw: {cmp_out}'
            )

    def test_large_compare_hyperv_vhd_vs_raw(self):
        """Compare Hyper-V dynamic VHD against raw."""
        self._compare_vhd_vs_raw('hyperv-dynamic-vhd')

    def test_large_compare_virtualpc_vhd_vs_raw(self):
        """Compare Virtual PC dynamic VHD against raw."""
        self._compare_vhd_vs_raw('virtualpc-vhd')

    def test_compare_vhd_d2v_zerofilled_vs_raw(self):
        """Compare Disk2VHD zerofilled VHD against raw."""
        self._compare_vhd_vs_raw('vhd-d2v-zerofilled')


class TestConvertToVhd(ImagoTestBase):
    """Test converting images to VHD output.

    Converts images to VHD with imago, then verifies the output
    by converting back to raw and comparing against qemu-img.
    """

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _test_to_vhd_roundtrip(self, image_id):
        """Convert image to VHD, then back to raw, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # Need space for VHD + 2x raw at virtual size.
        # Use 3x vsize to account for VHD intermediate
        # plus two full raw files written concurrently.
        vsize = 0
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image.path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            vsize = json.loads(
                result.stdout
            ).get('virtual-size', 0)
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 3 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        timeout = self._timeout_for_vsize(vsize)

        with tempfile.NamedTemporaryFile(
                suffix='.vhd') as vhd_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert to VHD with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vhd_out.name),
                output_format='vpc',
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vpc failed for '
                f'{image_id}: {stderr}'
            )

            # Verify qemu-img can read the VHD
            result = subprocess.run(
                [
                    'qemu-img', 'info', '--output=json',
                    vhd_out.name,
                ],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img info failed on imago VHD: '
                f'{result.stderr}'
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info.get('format'), 'vpc',
                f'Output is not VHD format: '
                f'{info.get("format")}'
            )

            # Round-trip: convert VHD back to raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(vhd_out.name),
                    Path(rt_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip raw conversion failed '
                f'for {image_id}: {rt_stderr}'
            )

            # Convert original to raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img baseline failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare round-trip against baseline
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHD round-trip differs for '
                f'{image_id}: {cmp_out}'
            )

    def test_raw_to_vhd_roundtrip(self):
        """Round-trip: raw -> VHD -> raw."""
        self._test_to_vhd_roundtrip(
            'raw-mbr-partitioned'
        )

    def test_qcow2_to_vhd_roundtrip(self):
        """Round-trip: qcow2 -> VHD -> raw."""
        self._test_to_vhd_roundtrip('cirros-qcow2')

    def test_vhd_to_vhd_roundtrip(self):
        """Round-trip: VHD -> VHD -> raw."""
        self._test_to_vhd_roundtrip(
            'vhd-d2v-zerofilled'
        )


class TestConvertVhdCheckOutput(ImagoTestBase):
    """Test that imago-produced VHD output passes check.

    Converts images to VHD, then runs imago check to verify
    structural integrity of our own output.
    """

    def _test_vhd_output_check(self, image_id):
        """Convert to VHD, then check the output."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(
                suffix='.vhd') as vhd_out:
            # Convert to VHD
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(vhd_out.name),
                output_format='vpc',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'imago convert to vpc failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VHD
            chk_stdout, chk_stderr, chk_rc = \
                self.run_imago_check(
                    Path(vhd_out.name),
                    output_format='json'
                )
            result = json.loads(chk_stdout)
            self.assertEqual(
                result.get('format', '').lower(),
                'vhd',
                f'Output should be detected as vhd'
            )
            self.assertEqual(
                result.get('check-errors', -1), 0,
                f'imago VHD output should have 0 '
                f'errors: {chk_stdout}'
            )

    def test_check_raw_to_vhd_output(self):
        """Check imago VHD output from raw input."""
        self._test_vhd_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_qcow2_to_vhd_output(self):
        """Check imago VHD output from QCOW2 input."""
        self._test_vhd_output_check('cirros-qcow2')

    def test_check_vhd_to_vhd_output(self):
        """Check imago VHD output from VHD input."""
        self._test_vhd_output_check(
            'vhd-d2v-zerofilled'
        )


class TestConvertVhdToQcow2Roundtrip(ImagoTestBase):
    """Test VHD -> QCOW2 -> raw round-trip conversion.

    Converts VHD to QCOW2, then to raw, and compares
    against qemu-img VHD -> raw baseline.
    """

    def _timeout_for_vsize(self, vsize):
        """Compute timeout based on virtual size."""
        if not vsize:
            return 120
        gib = vsize / (1024 ** 3)
        return max(120, int(120 + gib * 30))

    def _test_vhd_qcow2_roundtrip(self, image_id):
        """VHD -> QCOW2 -> raw, compare against baseline."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # Need space for QCOW2 + 2x raw at virtual size.
        # Use 3x vsize to account for QCOW2 intermediate
        # plus two full raw files written concurrently.
        vsize = 0
        result = subprocess.run(
            [
                'qemu-img', 'info', '--output=json',
                str(image.path),
            ],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            vsize = json.loads(
                result.stdout
            ).get('virtual-size', 0)
            tmpdir = tempfile.gettempdir()
            st = os.statvfs(tmpdir)
            avail = st.f_bavail * st.f_frsize
            needed = vsize * 3 + 100 * 1024 * 1024
            if avail < needed:
                self.skipTest(
                    f'{image_id}: needs '
                    f'{needed // (1024**3)}GB temp, '
                    f'only {avail // (1024**3)}GB '
                    f'available'
                )

        timeout = self._timeout_for_vsize(vsize)

        with tempfile.NamedTemporaryFile(
                suffix='.qcow2') as qcow2_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # VHD -> QCOW2
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(qcow2_out.name),
                output_format='qcow2',
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'VHD->QCOW2 failed for '
                f'{image_id}: {stderr}'
            )

            # QCOW2 -> raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_imago_convert(
                    Path(qcow2_out.name),
                    Path(rt_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                rt_rc, 0,
                f'QCOW2->raw failed for '
                f'{image_id}: {rt_stderr}'
            )

            # Baseline: VHD -> raw with qemu-img
            q_stdout, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img baseline failed for '
                f'{image_id}: {q_stderr}'
            )

            # Compare round-trip against baseline
            cmp_out, _, cmp_rc = self.run_imago_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHD->QCOW2->raw differs for '
                f'{image_id}: {cmp_out}'
            )

    def test_large_hyperv_vhd_qcow2_roundtrip(self):
        """VHD (Hyper-V) -> QCOW2 -> raw round-trip."""
        self._test_vhd_qcow2_roundtrip(
            'hyperv-dynamic-vhd'
        )

    def test_large_virtualpc_vhd_qcow2_roundtrip(self):
        """VHD (Virtual PC) -> QCOW2 -> raw round-trip."""
        self._test_vhd_qcow2_roundtrip('virtualpc-vhd')
