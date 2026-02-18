"""Tests for convert operation (QCOW2 -> raw)."""

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
                tempfile.NamedTemporaryFile(suffix='.qcow2') as dst:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_convert(
                Path(src.name), Path(dst.name),
                output_format='qcow2'
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

    Images with cluster_size > 64KB are skipped (unsupported).
    Images whose virtual_size exceeds available temp space
    are skipped to avoid disk-full failures.
    """

    # Maximum cluster size supported by the guest binary
    MAX_CLUSTER_SIZE = 65536

    # QCOW2 images that are safe standalone (no external backing
    # chain dependencies)
    STANDALONE_QCOW2_IDS = [
        'cirros-qcow2',
        'qcow2-v2',
        'qcow2-lazy-refcounts',
        'qcow2-min-cluster',
        'qcow2-refcount-bits-1',
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

    def _skip_if_unsupported(self, image_id, image_path):
        """Skip test if image has unsupported features."""
        vsize, csize = self._get_qcow2_info(image_path)
        if csize and csize > self.MAX_CLUSTER_SIZE:
            self.skipTest(
                f'{image_id}: cluster_size {csize} > '
                f'{self.MAX_CLUSTER_SIZE} (unsupported)'
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

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                image.path, Path(imago_raw.name),
                timeout=120
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
                    timeout=120
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
                timeout=120
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
