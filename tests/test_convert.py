"""Tests for convert operation."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


class TestConvertBasicQcow2ToRaw(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')
            self.assertEqual(stdout, '')

            # Verify output matches qemu-img convert
            with tempfile.NamedTemporaryFile(suffix='.raw') as qemu_raw:
                self.run_qemu_img_convert(
                    Path(qcow2.name), Path(qemu_raw.name)
                )
                cmp_out, cmp_err, cmp_rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Cross-validate with qemu-img
            with tempfile.NamedTemporaryFile(suffix='.raw') as qemu_raw:
                self.run_qemu_img_convert(
                    Path(qcow2.name), Path(qemu_raw.name)
                )
                cmp_out, _, cmp_rc = self.run_instar_compare(
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
            self.run_instar_convert(
                Path(qcow2.name), Path(raw.name)
            )
            raw_size = os.path.getsize(raw.name)
            self.assertEqual(raw_size, 2 * 1024 * 1024)


class TestConvertCompressed(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(comp.name), Path(output.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare with original raw
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(base.name), Path(output.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Decompressed output differs: {cmp_out}'
            )


class TestConvertBackingChain(InstarTestBase):
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

            # Convert with instar
            stdout, stderr, rc = self.run_instar_convert(
                overlay_path, output_path
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Convert with qemu-img for cross-validation
            self.run_qemu_img_convert(
                overlay_path, qemu_path
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_convert(
                top_path, output_path
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Cross-validate
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', str(top_path), str(qemu_path)],
                capture_output=True
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
                output_path, qemu_path
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from qemu-img: {cmp_out}'
            )


class TestConvertRawToRaw(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(src.name), Path(dst.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Raw passthrough differs: {cmp_out}'
            )


class TestConvertErrors(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(src.name), Path(dst.name),
                output_format='vdi'
            )
            self.assertNotEqual(rc, 0)
            self.assertIn('unsupported', stderr.lower())

    def test_convert_nonexistent_input(self):
        """Converting a nonexistent file returns an error."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as dst:
            stdout, stderr, rc = self.run_instar_convert(
                Path('/nonexistent/image.qcow2'),
                Path(dst.name)
            )
            self.assertNotEqual(rc, 0)


class TestConvertManifestImages(InstarTestBase):
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
        return max(120, int(120 + gib * 15))

    # Max cluster size for compressed cluster decompression. Both the
    # decompression staging buffer and the compressed input buffer now
    # support clusters up to MAX_CLUSTER_SIZE (2MB).
    MAX_DECOMPRESS_CLUSTER = 2097152

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

        # Compressed clusters with cluster sizes exceeding the
        # decompression limit cannot be handled.
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
                as instar_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(instar_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name),
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


class TestConvertRawToQcow2(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
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
            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(
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
            self.run_instar_convert(
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


class TestConvertRoundTrip(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # qcow2 -> raw
            stdout, stderr, rc = self.run_instar_convert(
                Path(mid.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare
            cmp_out, _, cmp_rc = self.run_instar_compare(
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

            self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            self.run_instar_convert(
                Path(mid.name), Path(dst.name)
            )

            cmp_out, _, cmp_rc = self.run_instar_compare(
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

            self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', skip_zeros=True
            )
            self.run_instar_convert(
                Path(mid.name), Path(dst.name)
            )

            cmp_out, _, cmp_rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(
                Path(src.name), Path(r1.name)
            )
            self.run_instar_convert(
                Path(mid.name), Path(r2.name)
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(r1.name), Path(r2.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Re-encoded differs: {cmp_out}'
            )


class TestConvertToQcow2CrossValidation(InstarTestBase):
    """Cross-validate QCOW2 output with qemu-img."""

    def test_qemu_img_check_passes(self):
        """qemu-img check passes on instar QCOW2 output."""
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
            self.run_instar_convert(
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
        """qemu-img can convert instar QCOW2 output back."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as instar_raw, \
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

            # instar raw -> qcow2
            self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2'
            )
            # instar qcow2 -> raw
            self.run_instar_convert(
                Path(mid.name), Path(instar_raw.name)
            )
            # qemu-img qcow2 -> raw
            self.run_qemu_img_convert(
                Path(mid.name), Path(qemu_raw.name)
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'qemu-img read differs: {cmp_out}'
            )

    def test_instar_check_passes(self):
        """instar check passes on instar QCOW2 output."""
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
            self.run_instar_convert(
                Path(raw.name), Path(q.name),
                output_format='qcow2'
            )
            stdout, stderr, rc = self.run_instar_check(
                Path(q.name)
            )
            self.assertEqual(
                rc, 0,
                f'instar check failed: {stderr}'
            )


class TestConvertToQcow2BackingChain(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(overlay, raw1)
            self.run_instar_convert(output, raw2)
            cmp_out, _, cmp_rc = self.run_instar_compare(
                raw1, raw2
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Flattened differs: {cmp_out}'
            )


class TestConvertToQcow2ManifestRaw(InstarTestBase):
    """Convert manifest raw images to QCOW2.

    For each raw image in the manifest, convert to QCOW2,
    validate with qemu-img check, and round-trip back to raw
    to verify content preservation.
    """

    # Images with QCOW2 magic bytes (raw-misleading-header) are
    # excluded because instar's format detection interprets them
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(qcow2.name),
                output_format='qcow2',
                compress=self._compress,
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(roundtrip.name),
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'Round-trip convert failed for '
                f'{image_id}: {stderr}'
            )

            # Compare with original
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertCompressedOutput(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', compress=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # compressed qcow2 -> raw
            stdout, stderr, rc = self.run_instar_convert(
                Path(mid.name), Path(dst.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare with original
            cmp_out, _, cmp_rc = self.run_instar_compare(
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
            self.run_instar_convert(
                Path(raw.name), Path(uncomp.name),
                output_format='qcow2'
            )
            # Compressed qcow2
            self.run_instar_convert(
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
            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(
                Path(src.name), Path(r1.name)
            )
            self.run_instar_convert(
                Path(comp.name), Path(r2.name)
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(overlay, raw1)
            self.run_instar_convert(output, raw2)
            cmp_out, _, cmp_rc = self.run_instar_compare(
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

            stdout, stderr, rc = self.run_instar_convert(
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
            self.run_instar_convert(
                Path(qcow2.name), Path(roundtrip.name)
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
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

            stdout, stderr, rc = self.run_instar_convert(
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
        """Cross-validate instar compressed output with qemu."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as instar_raw, \
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

            # instar raw -> compressed qcow2
            self.run_instar_convert(
                Path(src.name), Path(mid.name),
                output_format='qcow2', compress=True
            )
            # instar compressed qcow2 -> raw
            self.run_instar_convert(
                Path(mid.name), Path(instar_raw.name)
            )
            # qemu-img compressed qcow2 -> raw
            self.run_qemu_img_convert(
                Path(mid.name), Path(qemu_raw.name)
            )
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name), Path(qemu_raw.name)
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


class TestConvertToQcow2ManifestQcow2(InstarTestBase):
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
        return max(120, int(120 + gib * 15))

    # Max cluster size for compressed cluster decompression
    MAX_DECOMPRESS_CLUSTER = 2097152

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

        # Compressed clusters exceeding the decompression
        # limit cannot be handled.
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
        # Compressed output is significantly slower due to
        # zlib compression of every cluster.
        if self._compress:
            timeout *= 3

        with tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as reenc, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as raw_orig, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw') as raw_reenc:
            # Re-encode: qcow2 -> qcow2
            stdout, stderr, rc = self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertLargeCluster(InstarTestBase):
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
            ) as instar_f, tempfile.NamedTemporaryFile(
                suffix='.raw', delete=False
            ) as qemu_f:
                instar_raw = instar_f.name
                qemu_raw = qemu_f.name
                try:
                    # Convert with instar
                    stdout, stderr, rc = \
                        self.run_instar_convert(
                            Path(qcow2_path),
                            Path(instar_raw),
                        )
                    self.assertEqual(
                        rc, 0,
                        f'instar convert failed: {stderr}'
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
                        self.run_instar_compare(
                            Path(instar_raw),
                            Path(qemu_raw),
                        )
                    self.assertEqual(
                        cmp_rc, 0,
                        f'Convert output differs from '
                        f'qemu-img: {cmp_out}'
                    )
                finally:
                    os.unlink(instar_raw)
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

            # Compare QCOW2 against raw with instar
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertLargeClusterOutput(InstarTestBase):
    """Test QCOW2 output with large cluster sizes (>64KB).

    Verifies that instar can produce valid QCOW2 images with
    cluster sizes of 128KB and 2MB, both uncompressed and
    compressed, and that round-trip fidelity is preserved.
    """

    def _roundtrip_large_cluster(
        self, cluster_size, compress=False, image_size='64M'
    ):
        """Helper: raw -> qcow2 (large cluster) -> raw, compare."""
        with tempfile.NamedTemporaryFile(
            suffix='.raw', delete=False
        ) as src_f, tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as mid_f, tempfile.NamedTemporaryFile(
            suffix='.raw', delete=False
        ) as dst_f:
            src = src_f.name
            mid = mid_f.name
            dst = dst_f.name
        try:
            # Create raw with data at multiple offsets
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 src, image_size],
                check=True, capture_output=True, timeout=30,
            )
            for offset in ['0', '4M', '32M']:
                subprocess.run(
                    ['qemu-io', '-f', 'raw', '-c',
                     f'write -P 0xAB {offset} 64K', src],
                    check=True, capture_output=True,
                    timeout=30,
                )

            # raw -> qcow2 with large cluster
            stdout, stderr, rc = self.run_instar_convert(
                Path(src), Path(mid),
                output_format='qcow2',
                cluster_size=cluster_size,
                compress=compress,
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'raw -> qcow2 (cluster={cluster_size}, '
                f'compress={compress}) failed: {stderr}'
            )

            # Validate with qemu-img check
            result = subprocess.run(
                ['qemu-img', 'check', mid],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Verify cluster size and format in qemu-img info
            info_result = subprocess.run(
                ['qemu-img', 'info', '--output=json', mid],
                capture_output=True, text=True, timeout=30,
            )
            info = json.loads(info_result.stdout)
            self.assertEqual(info['format'], 'qcow2')
            self.assertEqual(
                info['cluster-size'], cluster_size,
                f'Expected cluster-size {cluster_size}, '
                f'got {info["cluster-size"]}'
            )

            # qcow2 -> raw
            stdout, stderr, rc = self.run_instar_convert(
                Path(mid), Path(dst), timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'qcow2 -> raw failed: {stderr}'
            )

            # Compare round-trip
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(src), Path(dst),
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Round-trip differs (cluster={cluster_size},'
                f' compress={compress}): {cmp_out}'
            )
        finally:
            for p in [src, mid, dst]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_roundtrip_128k_cluster(self):
        """Round-trip raw -> qcow2 (128KB cluster) -> raw."""
        self._roundtrip_large_cluster(131072)

    def test_roundtrip_2m_cluster(self):
        """Round-trip raw -> qcow2 (2MB cluster) -> raw."""
        self._roundtrip_large_cluster(2097152)

    def test_roundtrip_128k_cluster_compressed(self):
        """Round-trip raw -> compressed qcow2 (128KB) -> raw."""
        self._roundtrip_large_cluster(131072, compress=True)

    def test_roundtrip_2m_cluster_compressed(self):
        """Round-trip raw -> compressed qcow2 (2MB) -> raw."""
        self._roundtrip_large_cluster(2097152, compress=True)

    def test_qcow2_to_qcow2_large_cluster(self):
        """Convert QCOW2 (default cluster) -> QCOW2 (128KB)."""
        with tempfile.NamedTemporaryFile(
            suffix='.raw', delete=False
        ) as raw_f, tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as src_f, tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as dst_f:
            raw = raw_f.name
            src = src_f.name
            dst = dst_f.name
        try:
            # Create a small QCOW2 with default cluster size
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw, '16M'],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xCD 0 64K', raw],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'raw',
                 '-O', 'qcow2', raw, src],
                check=True, capture_output=True, timeout=30,
            )

            # Convert QCOW2 -> QCOW2 with 128KB clusters
            stdout, stderr, rc = self.run_instar_convert(
                Path(src), Path(dst),
                output_format='qcow2',
                cluster_size=131072,
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'qcow2 -> qcow2 (128KB) failed: {stderr}'
            )

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', dst],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Verify cluster size
            info_result = subprocess.run(
                ['qemu-img', 'info', '--output=json', dst],
                capture_output=True, text=True, timeout=30,
            )
            info = json.loads(info_result.stdout)
            self.assertEqual(info['cluster-size'], 131072)

            # Compare content against original raw
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw), Path(dst),
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Content differs: {cmp_out}'
            )
        finally:
            for p in [raw, src, dst]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_2m_cluster_preserves_size(self):
        """2MB cluster output -> convert back preserves data."""
        with tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as src_f, tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as dst_f:
            src = src_f.name
            dst = dst_f.name
        try:
            # Create 2MB-cluster QCOW2 with qemu-img
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=2M', src, '64M'],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xEF 0 1M', src],
                check=True, capture_output=True, timeout=30,
            )

            # Convert with instar, preserving 2MB cluster size
            stdout, stderr, rc = self.run_instar_convert(
                Path(src), Path(dst),
                output_format='qcow2',
                cluster_size=2097152,
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'2MB re-encode failed: {stderr}'
            )

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', dst],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Verify cluster size preserved
            info_result = subprocess.run(
                ['qemu-img', 'info', '--output=json', dst],
                capture_output=True, text=True, timeout=30,
            )
            info = json.loads(info_result.stdout)
            self.assertEqual(info['cluster-size'], 2097152)

            # Compare content
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(src), Path(dst),
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Content differs: {cmp_out}'
            )
        finally:
            for p in [src, dst]:
                if os.path.exists(p):
                    os.unlink(p)


class TestConvertVmdkToRaw(InstarTestBase):
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
        return max(120, int(120 + gib * 15))

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

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as instar_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(instar_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name),
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

    def test_convert_vmdk_flat_1m(self):
        """Convert 1 MiB monolithicFlat VMDK to raw."""
        self._test_vmdk_convert('vmdk-flat-1m')

    def test_convert_vmdk_flat_10m(self):
        """Convert 10 MiB monolithicFlat VMDK to raw."""
        self._test_vmdk_convert('vmdk-flat-10m')


class TestConvertVmdkFlatRejection(InstarTestBase):
    """VMDK flat variants fail when referenced files are missing.

    The descriptor resolver now accepts parent hints and
    multi-extent descriptors, but these fixtures have missing
    backing/extent files. The errors are about missing files,
    not unsupported features.
    """

    def _run_convert_expecting_error(self, image_id, marker):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(out.name), timeout=60
            )
            self.assertNotEqual(
                rc, 0,
                f'Expected convert to fail for {image_id}, '
                f'got rc={rc} stdout={stdout}'
            )
            combined = (stdout or '') + (stderr or '')
            self.assertIn(
                marker, combined,
                f'Expected error message to mention {marker!r}, '
                f'got: {combined}'
            )

    def test_reject_monolithic_flat_with_parent(self):
        """parentFileNameHint accepted, but parent file is missing."""
        self._run_convert_expecting_error(
            'vmdk-flat-with-parent', 'not found'
        )

    def test_reject_twogb_max_extent_flat_missing_files(self):
        """twoGbMaxExtentFlat extents files are missing."""
        self._run_convert_expecting_error(
            'vmdk-twogb-flat', 'not found'
        )


class TestConvertVmdkMultiExtent(InstarTestBase):
    """Phase 23a: twoGbMaxExtentFlat multi-extent input."""

    def test_convert_multi_extent_flat_to_raw(self):
        """Convert 3-extent flat VMDK to raw and verify content."""
        image = self.get_image('vmdk-multi-flat')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(out.name), timeout=60
            )
            self.assertEqual(
                rc, 0,
                f'Convert failed: rc={rc} stderr={stderr}'
            )

            # Verify content: 3 × 512 KiB with fill patterns
            data = Path(out.name).read_bytes()
            expected_size = 3 * 1024 * 512
            self.assertEqual(
                len(data), expected_size,
                f'Expected {expected_size} bytes, '
                f'got {len(data)}'
            )
            # Check fill patterns without comparing huge byte
            # strings (subunit can't serialise large mismatches).
            extent_size = 524288
            for i, (offset, pattern) in enumerate([
                (0, 0xAA),
                (extent_size, 0xBB),
                (2 * extent_size, 0xCC),
            ]):
                chunk = data[offset:offset + extent_size]
                self.assertTrue(
                    all(b == pattern for b in chunk),
                    f'Extent {i} at offset {offset} should '
                    f'be 0x{pattern:02X}, first mismatch at '
                    f'byte {next((j for j, b in enumerate(chunk) if b != pattern), -1)}'
                )

    def test_info_multi_extent_flat(self):
        """Info reports correct virtual size for multi-extent."""
        image = self.get_image('vmdk-multi-flat')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        stdout, stderr, rc = self.run_instar_info(
            image.path, output_format='json'
        )
        self.assertEqual(
            rc, 0,
            f'Info failed: rc={rc} stderr={stderr}'
        )

        info = json.loads(stdout)
        # 3 × 1024 sectors × 512 bytes = 1572864
        expected_vsize = 3 * 1024 * 512
        self.assertEqual(
            info.get('virtual-size'), expected_vsize,
            f'Expected virtual-size {expected_vsize}, '
            f'got {info.get("virtual-size")}'
        )


class TestConvertVmdkFlatOutput(InstarTestBase):
    """Phase 23c: monolithicFlat VMDK output."""

    def test_convert_raw_to_vmdk_flat(self):
        """Convert raw input to monolithicFlat VMDK output."""
        # Use vmdk-flat-1m as input (convert to raw, then to flat)
        image = self.get_image('vmdk-flat-1m')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.TemporaryDirectory() as tmpdir:
            # First convert to raw
            raw_path = Path(tmpdir) / 'input.raw'
            stdout, stderr, rc = self.run_instar_convert(
                image.path, raw_path, timeout=60
            )
            self.assertEqual(
                rc, 0,
                f'Raw convert failed: rc={rc} stderr={stderr}'
            )

            # Now convert raw to monolithicFlat
            flat_desc = Path(tmpdir) / 'output.vmdk'
            flat_data = Path(tmpdir) / 'output-flat.vmdk'
            stdout, stderr, rc = self.run_instar_convert(
                raw_path, flat_desc,
                output_format='vmdk',
                subformat='monolithicFlat',
                timeout=60,
            )
            self.assertEqual(
                rc, 0,
                f'Flat convert failed: rc={rc} stderr={stderr}'
            )

            # Verify descriptor exists and is text
            self.assertTrue(
                flat_desc.exists(),
                'Descriptor file should exist'
            )
            desc_text = flat_desc.read_text()
            self.assertIn(
                'monolithicFlat', desc_text,
                'Descriptor should mention monolithicFlat'
            )
            self.assertIn(
                'output-flat.vmdk', desc_text,
                'Descriptor should reference flat extent file'
            )

            # Verify flat extent exists with correct size
            self.assertTrue(
                flat_data.exists(),
                'Flat extent file should exist'
            )
            self.assertEqual(
                flat_data.stat().st_size, 1048576,
                'Flat extent should be 1 MiB'
            )

            # Verify content matches raw input
            raw_data = raw_path.read_bytes()
            flat_bytes = flat_data.read_bytes()
            self.assertEqual(
                raw_data, flat_bytes,
                'Flat extent content should match raw input'
            )

    def test_convert_flat_to_vmdk_flat(self):
        """Convert flat VMDK input to monolithicFlat VMDK output."""
        image = self.get_image('vmdk-flat-1m')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.TemporaryDirectory() as tmpdir:
            flat_desc = Path(tmpdir) / 'out.vmdk'
            flat_data = Path(tmpdir) / 'out-flat.vmdk'
            stdout, stderr, rc = self.run_instar_convert(
                image.path, flat_desc,
                output_format='vmdk',
                subformat='monolithicFlat',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'Flat convert failed: rc={rc} stderr={stderr}'
            )

            self.assertTrue(flat_desc.exists())
            self.assertTrue(flat_data.exists())

            # Verify round-trip: the output flat should have
            # same content as the original flat extent
            orig_flat = image.path.parent / 'vmdk-flat-1m-flat.vmdk'
            if orig_flat.exists():
                orig_data = orig_flat.read_bytes()
                flat_bytes = flat_data.read_bytes()
                self.assertEqual(
                    orig_data, flat_bytes,
                    'Round-trip content mismatch'
                )

    def test_convert_vmdk_flat_roundtrip(self):
        """monolithicFlat -> raw -> monolithicFlat roundtrip."""
        image = self.get_image('vmdk-flat-1m')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: flat -> raw
            raw_path = Path(tmpdir) / 'step1.raw'
            stdout, stderr, rc = self.run_instar_convert(
                image.path, raw_path, timeout=60
            )
            self.assertEqual(rc, 0, f'Step 1 failed: {stderr}')

            # Step 2: raw -> flat
            flat2_desc = Path(tmpdir) / 'step2.vmdk'
            flat2_data = Path(tmpdir) / 'step2-flat.vmdk'
            stdout, stderr, rc = self.run_instar_convert(
                raw_path, flat2_desc,
                output_format='vmdk',
                subformat='monolithicFlat',
                timeout=60,
            )
            self.assertEqual(rc, 0, f'Step 2 failed: {stderr}')

            # Step 3: flat -> raw again
            raw2_path = Path(tmpdir) / 'step3.raw'
            stdout, stderr, rc = self.run_instar_convert(
                flat2_desc, raw2_path, timeout=60
            )
            self.assertEqual(rc, 0, f'Step 3 failed: {stderr}')

            # Verify: step1.raw == step3.raw
            raw1 = raw_path.read_bytes()
            raw2 = raw2_path.read_bytes()
            self.assertEqual(
                raw1, raw2,
                'Round-trip content mismatch'
            )


class TestConvertVmdkCompare(InstarTestBase):
    """Test comparing VMDK images against raw equivalents.

    Uses instar compare to verify VMDK virtual content matches
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertVmdkStreamOptimized(InstarTestBase):
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

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as instar_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(instar_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name),
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

            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertToVmdk(InstarTestBase):
    """Test converting images to VMDK monolithicSparse output.

    Converts images to VMDK with instar, then verifies the output
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
            # Convert to VMDK with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vmdk failed for '
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
                f'qemu-img info failed on instar VMDK: '
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
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertToVmdkCompressed(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                compress=True,
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to streamOptimized vmdk '
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
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertVmdkToQcow2Roundtrip(InstarTestBase):
    """Test VMDK -> QCOW2 -> raw roundtrip conversions.

    Converts VMDK images to QCOW2 with instar, then back to raw,
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(qcow2_out.name),
                output_format='qcow2',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert vmdk->qcow2 failed for '
                f'{image_id}: {stderr}'
            )

            # Round-trip: QCOW2 -> raw
            rt_stdout, rt_stderr, rt_rc = \
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertVmdkCheckOutput(InstarTestBase):
    """Test that instar-produced VMDK output passes check.

    Converts images to VMDK, then runs instar check to verify
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vmdk_out.name),
                output_format='vmdk',
                compress=compress,
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vmdk failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VMDK
            chk_stdout, chk_stderr, chk_rc = \
                self.run_instar_check(
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
                f'instar VMDK output should have 0 errors: '
                f'{chk_stdout}'
            )

    def test_check_monolithic_sparse_output(self):
        """Check instar monolithicSparse VMDK output."""
        self._test_vmdk_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_streamoptimized_output(self):
        """Check instar streamOptimized VMDK output."""
        self._test_vmdk_output_check(
            'raw-mbr-partitioned', compress=True
        )

    def test_check_qcow2_to_vmdk_output(self):
        """Check instar VMDK output from QCOW2 input."""
        self._test_vmdk_output_check('cirros-qcow2')

    def test_check_vmdk_to_vmdk_output(self):
        """Check instar VMDK output from VMDK input."""
        self._test_vmdk_output_check('plaso-vmdk')


class TestConvertVhdxToRaw(InstarTestBase):
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
        return max(120, int(120 + gib * 15))

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

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as instar_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(instar_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name),
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


class TestConvertVhdxCompare(InstarTestBase):
    """Test comparing VHDX images against raw equivalents.

    Uses instar compare to verify VHDX virtual content matches
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertToVhdx(InstarTestBase):
    """Test converting images to VHDX output.

    Converts images to VHDX with instar, then verifies the output
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
            # Convert to VHDX with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vhdx_out.name),
                output_format='vhdx',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vhdx failed for '
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
                f'qemu-img info failed on instar VHDX: '
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
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertVhdxCheckOutput(InstarTestBase):
    """Test that instar-produced VHDX output passes check.

    Converts images to VHDX, then runs instar check to verify
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vhdx_out.name),
                output_format='vhdx',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vhdx failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VHDX
            chk_stdout, chk_stderr, chk_rc = \
                self.run_instar_check(
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
                f'instar VHDX output should have 0 '
                f'errors: {chk_stdout}'
            )

    def test_check_raw_to_vhdx_output(self):
        """Check instar VHDX output from raw input."""
        self._test_vhdx_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_qcow2_to_vhdx_output(self):
        """Check instar VHDX output from QCOW2 input."""
        self._test_vhdx_output_check('cirros-qcow2')

    def test_check_vhdx_to_vhdx_output(self):
        """Check instar VHDX output from VHDX input."""
        self._test_vhdx_output_check('qemu-vhdx')


class TestConvertVhdToRaw(InstarTestBase):
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

    def _test_vhd_convert(self, image_id):
        """Convert a VHD image to raw and cross-validate."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        vsize = self._get_vhd_info(image.path)

        # Convert is fast with sparse output, but compare
        # reads the full virtual range even for sparse files.
        # Timeout scales with virtual size for the compare.
        if vsize:
            gib = vsize / (1024 ** 3)
            timeout = max(120, int(120 + gib * 15))
        else:
            timeout = 120

        with tempfile.NamedTemporaryFile(suffix='.raw') \
                as instar_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(instar_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for {image_id}: '
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

            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Convert output for {image_id} differs '
                f'from qemu-img: {cmp_out}'
            )

    def test_convert_hyperv_dynamic_vhd(self):
        """Convert Hyper-V 2012 R2 dynamic VHD to raw."""
        self._test_vhd_convert('hyperv-dynamic-vhd')

    def test_convert_virtualpc_vhd(self):
        """Convert Virtual PC dynamic VHD to raw."""
        self._test_vhd_convert('virtualpc-vhd')

    def test_convert_vhd_d2v_zerofilled(self):
        """Convert Disk2VHD zerofilled VHD to raw."""
        self._test_vhd_convert('vhd-d2v-zerofilled')

    def test_convert_vhd_fixed(self):
        """Convert fixed VHD (disk_type=2) to raw.

        qemu-img doesn't auto-detect fixed VHD, so we validate
        the conversion output independently rather than
        cross-validating against qemu-img.
        """
        image = self.get_image('vhd-fixed')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(out.name), timeout=60
            )
            self.assertEqual(
                rc, 0,
                f'instar convert failed for vhd-fixed: {stderr}'
            )

            # Output should be 10 MiB (no footer)
            out_size = Path(out.name).stat().st_size
            self.assertEqual(
                out_size, 10 * 1024 * 1024,
                f'Expected 10 MiB output, got {out_size}'
            )

            # Check 0xBE pattern at 1 MiB offset
            out.seek(1024 * 1024)
            data = out.read(512)
            self.assertEqual(
                data, bytes([0xBE] * 512),
                'Expected 0xBE pattern at 1 MiB offset'
            )


class TestConvertVhdCompare(InstarTestBase):
    """Test comparing VHD images against raw equivalents.

    Uses instar compare to verify VHD virtual content matches
    the qemu-img-converted raw baseline.
    """

    def _compare_vhd_vs_raw(self, image_id):
        """Compare VHD against its qemu-img-converted raw."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # qemu-img produces sparse raw output by default,
        # so disk usage is small regardless of virtual size.
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

        if vsize:
            gib = vsize / (1024 ** 3)
            timeout = max(120, int(120 + gib * 15))
        else:
            timeout = 120

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

            cmp_out, _, cmp_rc = self.run_instar_compare(
                image.path, Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHD {image_id} content '
                f'differs from raw: {cmp_out}'
            )

    def test_compare_hyperv_vhd_vs_raw(self):
        """Compare Hyper-V dynamic VHD against raw."""
        self._compare_vhd_vs_raw('hyperv-dynamic-vhd')

    def test_compare_virtualpc_vhd_vs_raw(self):
        """Compare Virtual PC dynamic VHD against raw."""
        self._compare_vhd_vs_raw('virtualpc-vhd')

    def test_compare_vhd_d2v_zerofilled_vs_raw(self):
        """Compare Disk2VHD zerofilled VHD against raw."""
        self._compare_vhd_vs_raw('vhd-d2v-zerofilled')


class TestConvertToVhd(InstarTestBase):
    """Test converting images to VHD output.

    Converts images to VHD with instar, then verifies the output
    by converting back to raw and comparing against qemu-img.
    """

    def _test_to_vhd_roundtrip(self, image_id):
        """Convert image to VHD, then back to raw, compare."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # With sparse output (default), disk usage is small
        # regardless of virtual size.
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

        if vsize:
            gib = vsize / (1024 ** 3)
            timeout = max(120, int(120 + gib * 15))
        else:
            timeout = 120

        with tempfile.NamedTemporaryFile(
                suffix='.vhd') as vhd_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert to VHD with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vhd_out.name),
                output_format='vpc',
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vpc failed for '
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
                f'qemu-img info failed on instar VHD: '
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
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
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


class TestConvertVhdCheckOutput(InstarTestBase):
    """Test that instar-produced VHD output passes check.

    Converts images to VHD, then runs instar check to verify
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
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(vhd_out.name),
                output_format='vpc',
                timeout=120
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to vpc failed for '
                f'{image_id}: {stderr}'
            )

            # Check the output VHD
            chk_stdout, chk_stderr, chk_rc = \
                self.run_instar_check(
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
                f'instar VHD output should have 0 '
                f'errors: {chk_stdout}'
            )

    def test_check_raw_to_vhd_output(self):
        """Check instar VHD output from raw input."""
        self._test_vhd_output_check(
            'raw-mbr-partitioned'
        )

    def test_check_qcow2_to_vhd_output(self):
        """Check instar VHD output from QCOW2 input."""
        self._test_vhd_output_check('cirros-qcow2')

    def test_check_vhd_to_vhd_output(self):
        """Check instar VHD output from VHD input."""
        self._test_vhd_output_check(
            'vhd-d2v-zerofilled'
        )


class TestConvertVhdToQcow2Roundtrip(InstarTestBase):
    """Test VHD -> QCOW2 -> raw round-trip conversion.

    Converts VHD to QCOW2, then to raw, and compares
    against qemu-img VHD -> raw baseline.
    """

    def _test_vhd_qcow2_roundtrip(self, image_id):
        """VHD -> QCOW2 -> raw, compare against baseline."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        # With sparse output (default), all intermediate and
        # output files are small regardless of virtual size.
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

        if vsize:
            gib = vsize / (1024 ** 3)
            timeout = max(120, int(120 + gib * 15))
        else:
            timeout = 120

        with tempfile.NamedTemporaryFile(
                suffix='.qcow2') as qcow2_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # VHD -> QCOW2
            stdout, stderr, rc = self.run_instar_convert(
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
                self.run_instar_convert(
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
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(rt_raw.name),
                Path(qemu_raw.name),
                timeout=timeout
            )
            self.assertEqual(
                cmp_rc, 0,
                f'VHD->QCOW2->raw differs for '
                f'{image_id}: {cmp_out}'
            )

    def test_hyperv_vhd_qcow2_roundtrip(self):
        """VHD (Hyper-V) -> QCOW2 -> raw round-trip."""
        self._test_vhd_qcow2_roundtrip(
            'hyperv-dynamic-vhd'
        )

    def test_virtualpc_vhd_qcow2_roundtrip(self):
        """VHD (Virtual PC) -> QCOW2 -> raw round-trip."""
        self._test_vhd_qcow2_roundtrip('virtualpc-vhd')


class TestConvertSnapshot(InstarTestBase):
    """Test conversion of specific QCOW2 snapshots."""

    def test_convert_snap1(self):
        """Convert snap1 and verify 0xAA pattern."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert snap1 with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                snapshot='snap1'
            )
            self.assertEqual(
                rc, 0,
                f'Snapshot convert failed: {stderr}'
            )

            # Convert snap1 with qemu-img
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '-l', 'snap1',
                    '-f', 'qcow2', '-O', 'raw',
                    str(image.path),
                    qemu_raw.name,
                ],
                capture_output=True, text=True,
                timeout=30, check=True
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'snap1 differs from qemu-img: '
                f'{cmp_out}'
            )

    def test_convert_snap2(self):
        """Convert snap2 and verify 0xBB pattern."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert snap2 with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                snapshot='snap2'
            )
            self.assertEqual(
                rc, 0,
                f'Snapshot convert failed: {stderr}'
            )

            # Convert snap2 with qemu-img
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '-l', 'snap2',
                    '-f', 'qcow2', '-O', 'raw',
                    str(image.path),
                    qemu_raw.name,
                ],
                capture_output=True, text=True,
                timeout=30, check=True
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'snap2 differs from qemu-img: '
                f'{cmp_out}'
            )

    def test_convert_by_snapshot_id(self):
        """Convert by numeric snapshot ID (1) instead of
        name."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert snapshot ID "1" with instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                snapshot='1'
            )
            self.assertEqual(
                rc, 0,
                f'Snapshot ID convert failed: '
                f'{stderr}'
            )

            # Convert snap1 with qemu-img
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '-l', 'snapshot.name=snap1',
                    '-f', 'qcow2', '-O', 'raw',
                    str(image.path),
                    qemu_raw.name,
                ],
                capture_output=True, text=True,
                timeout=30, check=True
            )

            # Compare outputs — ID "1" should match snap1
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Snapshot ID 1 differs from snap1: '
                f'{cmp_out}'
            )

    def test_convert_nonexistent_snapshot(self):
        """Converting a nonexistent snapshot should fail."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                snapshot='nonexistent'
            )
            self.assertNotEqual(
                rc, 0,
                'Should fail for nonexistent snapshot'
            )


class TestConvertEncryptedQcow2(InstarTestBase):
    """Test conversion of AES-encrypted QCOW2 images."""

    def test_convert_encrypted_aes_to_raw(self):
        """Convert AES-encrypted QCOW2 to raw with password."""
        image = self.get_image('qcow2-encrypted-aes')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert with instar using password
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                qcow2_password='testpass'
            )
            self.assertEqual(
                rc, 0,
                f'Encrypted convert failed: {stderr}'
            )

            # Convert with qemu-img for baseline
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '--object',
                    'secret,id=sec0,data=testpass',
                    '--image-opts',
                    'driver=qcow2,encrypt.key-secret=sec0,'
                    'file.driver=file,'
                    f'file.filename={image.path}',
                    '-O', 'raw',
                    qemu_raw.name,
                ],
                capture_output=True, text=True,
                timeout=30, check=True
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from qemu-img: '
                f'{cmp_out}'
            )

    def test_convert_encrypted_without_password(self):
        """Converting encrypted QCOW2 without password
        should fail or produce wrong output."""
        image = self.get_image('qcow2-encrypted-aes')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            # Convert without password - should still
            # produce output but data will be encrypted
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name)
            )
            # The conversion may succeed (data is just
            # not decrypted) or fail - either is acceptable
            # as long as it doesn't crash
            self.assertIn(
                rc, [0, 1],
                f'Unexpected crash: {stderr}'
            )

    def test_convert_encrypted_wrong_password(self):
        """Converting with wrong password should produce
        different output than correct password."""
        image = self.get_image('qcow2-encrypted-aes')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as correct_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as wrong_raw:
            # Convert with correct password
            _, _, rc1 = self.run_instar_convert(
                image.path, Path(correct_raw.name),
                qcow2_password='testpass'
            )
            self.assertEqual(rc1, 0)

            # Convert with wrong password
            _, _, rc2 = self.run_instar_convert(
                image.path, Path(wrong_raw.name),
                qcow2_password='wrongpass'
            )
            self.assertEqual(rc2, 0)

            # Outputs should differ
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(correct_raw.name),
                Path(wrong_raw.name)
            )
            self.assertNotEqual(
                cmp_rc, 0,
                'Wrong password produced same output '
                'as correct password'
            )


class TestConvertLuksQcow2(InstarTestBase):
    """Test conversion of LUKS-encrypted QCOW2 images
    (crypt_method=2)."""

    def test_convert_luks_qcow2_to_raw(self):
        """Convert LUKS-in-QCOW2 to raw with passphrase."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            # Convert with instar using LUKS passphrase
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase'
            )
            self.assertEqual(
                rc, 0,
                f'LUKS-QCOW2 convert failed: {stderr}'
            )

            # Convert with qemu-img for baseline
            subprocess.run(
                [
                    'qemu-img', 'convert',
                    '--object',
                    'secret,id=sec0,data=test-passphrase',
                    '--image-opts',
                    'driver=qcow2,'
                    'encrypt.key-secret=sec0,'
                    'file.driver=file,'
                    f'file.filename={image.path}',
                    '-O', 'raw',
                    qemu_raw.name,
                ],
                capture_output=True, text=True,
                timeout=30, check=True
            )

            # Compare outputs
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from qemu-img: '
                f'{cmp_out}'
            )

    def test_convert_luks_qcow2_without_passphrase(self):
        """Converting LUKS-QCOW2 without passphrase should
        fail gracefully."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name)
            )
            # Should fail or produce encrypted data
            self.assertIn(
                rc, [0, 1],
                f'Unexpected crash: {stderr}'
            )

    def test_convert_luks_qcow2_wrong_passphrase(self):
        """Converting with wrong passphrase should fail."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='wrong-passphrase'
            )
            # Key derivation should fail verification
            self.assertNotEqual(
                rc, 0,
                'Wrong passphrase should fail'
            )


class TestConvertNativeLuks(InstarTestBase):
    """Test conversion of native LUKS containers (not wrapped in
    QCOW2)."""

    def test_convert_native_luks_to_raw(self):
        """Convert native LUKS v1 container to raw."""
        image = self.get_image('luks-v1-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        # The expected inner content was created alongside the
        # LUKS image by create-native-luks-testdata.py
        expected_raw = image.path.parent / 'luks-v1-aes-xts-inner.raw'
        if not expected_raw.exists():
            self.skipTest(
                f'Expected raw not found: {expected_raw}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase'
            )
            self.assertEqual(
                rc, 0,
                f'Native LUKS convert failed: {stderr}'
            )

            # Compare against known expected content
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                expected_raw
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from expected: '
                f'{cmp_out}'
            )

    def test_convert_native_luks_without_passphrase(self):
        """Converting native LUKS without passphrase should
        fail gracefully."""
        image = self.get_image('luks-v1-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name)
            )
            # Should fail because no passphrase provided
            self.assertNotEqual(
                rc, 0,
                'Missing passphrase should fail'
            )

    def test_convert_native_luks_wrong_passphrase(self):
        """Converting native LUKS with wrong passphrase should
        fail."""
        image = self.get_image('luks-v1-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='wrong-passphrase'
            )
            # Key derivation should fail verification
            self.assertNotEqual(
                rc, 0,
                'Wrong passphrase should fail (v1)'
            )


class TestConvertNativeLuksV2(InstarTestBase):
    """Test conversion of native LUKS v2 containers (Argon2id
    KDF)."""

    def test_convert_native_luks_v2_to_raw(self):
        """Convert native LUKS v2 container to raw."""
        image = self.get_image('luks-v2-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        expected_raw = (
            image.path.parent / 'luks-v2-aes-xts-inner.raw'
        )
        if not expected_raw.exists():
            self.skipTest(
                f'Expected raw not found: {expected_raw}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase',
                max_guest_memory='64M',
            )
            self.assertEqual(
                rc, 0,
                f'Native LUKS v2 convert failed: {stderr}'
            )

            # Compare against known expected content
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(raw_out.name),
                expected_raw
            )
            self.assertEqual(
                cmp_rc, 0,
                f'Output differs from expected: '
                f'{cmp_out}'
            )

    def test_convert_native_luks_v2_without_memory(self):
        """LUKS v2 without --max-guest-memory should fail."""
        image = self.get_image('luks-v2-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase',
            )
            self.assertNotEqual(
                rc, 0,
                'Should fail without --max-guest-memory'
            )

    def test_convert_native_luks_v2_wrong_passphrase(self):
        """Wrong passphrase for LUKS v2 should fail."""
        image = self.get_image('luks-v2-aes-xts')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='wrong-passphrase',
                max_guest_memory='64M',
            )
            self.assertNotEqual(
                rc, 0,
                'Wrong passphrase should fail (v2)'
            )


class TestConvertLuksWrappedQcow2(InstarTestBase):
    """Test conversion of LUKS containers wrapping QCOW2 images."""

    def test_convert_luks_wrapped_qcow2_to_raw(self):
        """Convert LUKS v1 wrapping QCOW2 to raw."""
        image = self.get_image('luks-v1-qcow2-inner')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        expected_raw = (
            image.path.parent
            / 'luks-v1-qcow2-inner-inner.raw'
        )
        if not expected_raw.exists():
            self.skipTest(
                f'Expected raw not found: {expected_raw}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase',
            )
            self.assertEqual(
                rc, 0,
                f'LUKS-wrapped QCOW2 convert failed: '
                f'{stderr}'
            )

            # The output may be larger than the inner raw
            # (pre-allocated to LUKS payload size). Compare
            # only the expected number of bytes.
            expected_data = expected_raw.read_bytes()
            output_data = Path(raw_out.name).read_bytes()
            self.assertGreaterEqual(
                len(output_data), len(expected_data),
                f'Output too small: {len(output_data)} < '
                f'{len(expected_data)}'
            )
            self.assertEqual(
                output_data[:len(expected_data)],
                expected_data,
                'Output content does not match expected '
                'inner raw'
            )
            # Trailing bytes should be zero
            if len(output_data) > len(expected_data):
                trailing = output_data[len(expected_data):]
                self.assertEqual(
                    trailing,
                    b'\x00' * len(trailing),
                    'Trailing bytes are not zero'
                )

    def test_convert_luks_wrapped_qcow2_without_passphrase(
            self):
        """Missing passphrase should fail."""
        image = self.get_image('luks-v1-qcow2-inner')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix='.raw') as raw_out:
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
            )
            self.assertNotEqual(
                rc, 0,
                'Should fail without passphrase'
            )


class TestConvertExtendedL2Output(InstarTestBase):
    """Test QCOW2 output with extended L2 entries."""

    def test_convert_extended_l2_raw_to_qcow2(self):
        """Convert raw to QCOW2 with --extended-l2."""
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
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw.name), Path(qcow2.name),
                output_format='qcow2', extended_l2=True
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

            # Verify extended L2 in info output
            result = subprocess.run(
                ['qemu-img', 'info', '--output=json',
                 qcow2.name],
                capture_output=True, text=True
            )
            info = json.loads(result.stdout)
            ext_l2 = info.get(
                'format-specific', {}
            ).get('data', {}).get('extended-l2', False)
            self.assertTrue(
                ext_l2,
                f'Expected extended-l2=true in info: '
                f'{info.get("format-specific", {})}'
            )

    def test_convert_extended_l2_roundtrip(self):
        """Round-trip: raw -> extended L2 QCOW2 -> raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xAB 0 65536', raw_in.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xCD 524288 8192',
                 raw_in.name],
                capture_output=True
            )

            # raw -> extended L2 QCOW2
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2', extended_l2=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # extended L2 QCOW2 -> raw
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Compare original and round-tripped
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw_in.name), Path(raw_out.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

    def test_convert_extended_l2_qcow2_to_qcow2(self):
        """Re-encode standard QCOW2 as extended L2 QCOW2."""
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as q_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q_out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 q_in.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x55 0 4096', q_in.name],
                capture_output=True
            )

            # standard QCOW2 -> extended L2 QCOW2
            stdout, stderr, rc = self.run_instar_convert(
                Path(q_in.name), Path(q_out.name),
                output_format='qcow2', extended_l2=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate output
            result = subprocess.run(
                ['qemu-img', 'check', q_out.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Both to raw, then compare
            self.run_instar_convert(
                Path(q_in.name), Path(raw1.name),
                output_format='raw'
            )
            self.run_instar_convert(
                Path(q_out.name), Path(raw2.name),
                output_format='raw'
            )
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw1.name), Path(raw2.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

    def test_convert_extended_l2_compressed(self):
        """Extended L2 with compression."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 65536', raw_in.name],
                capture_output=True
            )

            # raw -> compressed extended L2 QCOW2
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2', compress=True,
                extended_l2=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Round-trip to raw and compare
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw_in.name), Path(raw_out.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

    def test_convert_extended_l2_non_qcow2_rejected(self):
        """--extended-l2 with non-QCOW2 output is rejected."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(raw_out.name),
                output_format='raw', extended_l2=True
            )
            self.assertNotEqual(
                rc, 0,
                'Should reject --extended-l2 with -O raw'
            )

    def test_convert_extended_l2_sparse(self):
        """Extended L2 with skip-zeros (sparse output)."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '10M'],
                capture_output=True
            )
            # Write a small amount of data
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw_in.name],
                capture_output=True
            )

            # Convert with skip-zeros
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2', extended_l2=True,
                skip_zeros=True
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')

            # Validate
            result = subprocess.run(
                ['qemu-img', 'check', qcow2.name],
                capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img check failed: {result.stderr}'
            )

            # Sparse output should be small
            qcow2_size = os.path.getsize(qcow2.name)
            self.assertLess(
                qcow2_size, 5 * 1024 * 1024,
                f'Extended L2 output ({qcow2_size}) not sparse'
            )

            # Round-trip and compare
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw'
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw_in.name), Path(raw_out.name)
            )
            self.assertEqual(rc, 0, f'stderr: {stderr}')


class TestConvertLuksEncryptOutput(InstarTestBase):
    """Test LUKS-encrypted QCOW2 output (crypt_method=2)."""

    def test_convert_luks_encrypt_raw_to_qcow2(self):
        """Convert raw to LUKS-encrypted QCOW2, decrypt back."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw_in.name],
                capture_output=True
            )

            # Encrypt
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2',
                luks_encrypt_passphrase='testpass123'
            )
            self.assertEqual(rc, 0, f'Encrypt failed: {stderr}')

            # Decrypt back to raw
            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw',
                luks_passphrase='testpass123'
            )
            self.assertEqual(rc, 0, f'Decrypt failed: {stderr}')

            # Compare
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw_in.name), Path(raw_out.name)
            )
            self.assertEqual(
                rc, 0,
                f'Round-trip mismatch: {stderr}'
            )

    def test_convert_luks_encrypt_roundtrip(self):
        """Encrypt with LUKS, decrypt, verify data at offsets."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '2M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xAB 0 65536', raw_in.name],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xCD 1048576 8192',
                 raw_in.name],
                capture_output=True
            )

            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2',
                luks_encrypt_passphrase='roundtrip'
            )
            self.assertEqual(rc, 0, f'Encrypt failed: {stderr}')

            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw',
                luks_passphrase='roundtrip'
            )
            self.assertEqual(rc, 0, f'Decrypt failed: {stderr}')

            stdout, stderr, rc = self.run_instar_compare(
                Path(raw_in.name), Path(raw_out.name)
            )
            self.assertEqual(
                rc, 0, f'Round-trip mismatch: {stderr}'
            )

    def test_convert_luks_encrypt_wrong_passphrase(self):
        """Decryption with wrong passphrase should fail."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', raw_in.name],
                capture_output=True
            )

            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2',
                luks_encrypt_passphrase='correctpass'
            )
            self.assertEqual(rc, 0, f'Encrypt failed: {stderr}')

            stdout, stderr, rc = self.run_instar_convert(
                Path(qcow2.name), Path(raw_out.name),
                output_format='raw',
                luks_passphrase='wrongpass'
            )
            self.assertNotEqual(
                rc, 0,
                'Should fail with wrong passphrase'
            )

    def test_convert_luks_encrypt_compress_rejected(self):
        """LUKS encrypt + compress should be rejected."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(qcow2.name),
                output_format='qcow2', compress=True,
                luks_encrypt_passphrase='test'
            )
            self.assertNotEqual(
                rc, 0,
                'Should reject LUKS encrypt + compress'
            )

    def test_convert_luks_encrypt_non_qcow2_rejected(self):
        """LUKS encrypt with non-QCOW2 output is rejected."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_in, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw_in.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_instar_convert(
                Path(raw_in.name), Path(raw_out.name),
                output_format='raw',
                luks_encrypt_passphrase='test'
            )
            self.assertNotEqual(
                rc, 0,
                'Should reject LUKS encrypt with -O raw'
            )


class TestConvertVmdkGrainSize(InstarTestBase):
    """Test VMDK output with configurable grain sizes."""

    def test_vmdk_grain_4k(self):
        """VMDK with 4KB grain size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=4096
        )

    def test_vmdk_grain_8k(self):
        """VMDK with 8KB grain size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=8192
        )

    def test_vmdk_grain_16k(self):
        """VMDK with 16KB grain size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=16384
        )

    def test_vmdk_grain_32k(self):
        """VMDK with 32KB grain size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=32768
        )

    def test_vmdk_grain_default_explicit(self):
        """VMDK with explicit default 64KB grain size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=65536
        )

    def test_vmdk_compressed_grain_4k(self):
        """streamOptimized VMDK with 4KB grains."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=4096, compress=True
        )

    def test_vmdk_compressed_grain_16k(self):
        """streamOptimized VMDK with 16KB grains."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vmdk', 'vmdk',
            '.vmdk', grain_size=16384, compress=True
        )

    def test_vmdk_grain_invalid_too_small(self):
        """Reject grain size smaller than 4096."""
        self.assert_convert_rejects(
            'vmdk', '.vmdk', grain_size=1024
        )

    def test_vmdk_grain_invalid_too_large(self):
        """Reject grain size larger than 65536."""
        self.assert_convert_rejects(
            'vmdk', '.vmdk', grain_size=131072
        )


class TestConvertVhdBlockSize(InstarTestBase):
    """Test VHD output with configurable block sizes."""

    def test_vhd_block_512k(self):
        """VHD with 512KB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vpc', 'vpc',
            '.vhd', block_size=524288
        )

    def test_vhd_block_1m(self):
        """VHD with 1MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vpc', 'vpc',
            '.vhd', block_size=1048576
        )

    def test_vhd_block_default_explicit(self):
        """VHD with explicit default 2MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vpc', 'vpc',
            '.vhd', block_size=2097152
        )

    def test_vhd_block_8m(self):
        """VHD with 8MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vpc', 'vpc',
            '.vhd', block_size=8388608
        )

    def test_vhd_block_invalid_not_power_of_2(self):
        """Reject non-power-of-2 VHD block size."""
        self.assert_convert_rejects(
            'vpc', '.vhd', block_size=3000000
        )

    def test_vhd_block_invalid_too_large(self):
        """Reject VHD block size above 256MB."""
        self.assert_convert_rejects(
            'vpc', '.vhd', block_size=536870912
        )


class TestConvertVhdxBlockSize(InstarTestBase):
    """Test VHDX output with configurable block sizes."""

    def test_vhdx_block_1m(self):
        """VHDX with 1MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vhdx', 'vhdx',
            '.vhdx', block_size=1048576
        )

    def test_vhdx_block_4m(self):
        """VHDX with 4MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vhdx', 'vhdx',
            '.vhdx', block_size=4194304
        )

    def test_vhdx_block_default_explicit(self):
        """VHDX with explicit default 32MB block size."""
        self.assert_size_roundtrip(
            'raw-mbr-partitioned', 'vhdx', 'vhdx',
            '.vhdx', block_size=33554432
        )

    def test_vhdx_block_invalid_too_small(self):
        """Reject VHDX block size below 1MB."""
        self.assert_convert_rejects(
            'vhdx', '.vhdx', block_size=524288
        )

    def test_vhdx_block_invalid_too_large(self):
        """Reject VHDX block size above 256MB."""
        self.assert_convert_rejects(
            'vhdx', '.vhdx', block_size=536870912
        )
