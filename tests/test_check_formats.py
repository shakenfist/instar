"""Tests for check operation format detection and validation."""

import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

from base import ImagoTestBase


class TestCheckFormatDetection(ImagoTestBase):
    """Test that check operation correctly detects and validates formats."""

    def test_check_qcow2_corrupt_detected(self):
        """Check operation should detect corrupt flag in QCOW2 images."""
        image = self.get_image('qcow2-corrupt')
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )

        # Should complete (possibly with non-zero exit for corruption)
        self.assertIn('qcow2', stdout.lower())

        # Parse JSON to check corruption flag
        result = json.loads(stdout)
        self.assertTrue(
            result.get('corrupt', False),
            'corrupt flag should be True for qcow2-corrupt.qcow2'
        )

    def test_check_vmdk_format_detected(self):
        """Check operation should detect VMDK format (not report as raw)."""
        # Use the plaso VMDK test image
        testdata_root = self._testdata_root
        vmdk_path = testdata_root / 'downloaded' / 'plaso' / 'image.vmdk'

        if not vmdk_path.exists():
            self.skipTest(f'VMDK test image not found: {vmdk_path}')

        stdout, stderr, rc = self.run_imago_check(
            vmdk_path, output_format='json'
        )

        # Parse JSON to check format
        result = json.loads(stdout)
        self.assertEqual(
            result.get('format', '').lower(), 'vmdk',
            'VMDK should be detected as vmdk, not raw'
        )

    def test_check_vmdk_unsafe_quirks_raw(self):
        """With --unsafe-quirks, VMDK should be reported as raw."""
        testdata_root = self._testdata_root
        vmdk_path = testdata_root / 'downloaded' / 'plaso' / 'image.vmdk'

        if not vmdk_path.exists():
            self.skipTest(f'VMDK test image not found: {vmdk_path}')

        stdout, stderr, rc = self.run_imago_check(
            vmdk_path, output_format='json', unsafe_quirks=True
        )

        # Parse JSON to check format
        result = json.loads(stdout)
        self.assertEqual(
            result.get('format', '').lower(), 'raw',
            'With --unsafe-quirks, VMDK should be reported as raw'
        )


class TestCheckCorruptImages(ImagoTestBase):
    """Test check operation with deliberately corrupt images.

    TODO: These tests are placeholders pending creation of corrupt test images
    in imago-testdata/custom/format-coverage/. The required images are:
    - vmdk-corrupt-version.vmdk: VMDK with invalid version (255)
    - vhdx-corrupt-region.vhdx: VHDX with invalid region table signature
    - vhd-corrupt-disktype.vhd: VHD with invalid disk type (255)

    Tests will skip gracefully until images are created.
    See docs/quirks.md "Test Images (Planned)" section for details.
    """

    def test_vmdk_corrupt_version(self):
        """VMDK with invalid version should report corruption."""
        testdata_root = self._testdata_root
        vmdk_path = (
            testdata_root / 'custom' / 'format-coverage' /
            'vmdk-corrupt-version.vmdk'
        )

        if not vmdk_path.exists():
            self.skipTest(f'Corrupt VMDK not found: {vmdk_path}')

        stdout, stderr, rc = self.run_imago_check(
            vmdk_path, output_format='json'
        )

        # Should detect VMDK format
        result = json.loads(stdout)
        self.assertIn(
            result.get('format', '').lower(), ['vmdk', 'vmdk4'],
            'Should detect as VMDK format'
        )

        # Should report corruption (check-errors > 0 or corruptions > 0)
        errors = result.get('check-errors', 0) + result.get('corruptions', 0)
        self.assertGreater(
            errors, 0,
            'Corrupt VMDK should report errors'
        )

    def test_vmdk_corrupt_descriptor(self):
        """VMDK with descriptor beyond file should report corruption."""
        testdata_root = self._testdata_root
        vmdk_path = (
            testdata_root / 'custom' / 'format-coverage' /
            'vmdk-corrupt-descriptor.vmdk'
        )

        if not vmdk_path.exists():
            self.skipTest(
                f'Corrupt VMDK not found: {vmdk_path}'
            )

        stdout, stderr, rc = self.run_imago_check(
            vmdk_path, output_format='json'
        )

        result = json.loads(stdout)
        self.assertIn(
            result.get('format', '').lower(),
            ['vmdk', 'vmdk4'],
            'Should detect as VMDK format'
        )

        self.assertGreater(
            result.get('corruptions', 0), 0,
            'VMDK with corrupt descriptor offset should '
            'report corruption'
        )

    def test_vhdx_corrupt_region(self):
        """VHDX with invalid region table should report corruption."""
        testdata_root = self._testdata_root
        vhdx_path = (
            testdata_root / 'custom' / 'format-coverage' /
            'vhdx-corrupt-region.vhdx'
        )

        if not vhdx_path.exists():
            self.skipTest(f'Corrupt VHDX not found: {vhdx_path}')

        stdout, stderr, rc = self.run_imago_check(
            vhdx_path, output_format='json'
        )

        # Should detect VHDX format
        result = json.loads(stdout)
        self.assertEqual(
            result.get('format', '').lower(), 'vhdx',
            'Should detect as VHDX format'
        )

        # Should report corruption
        errors = result.get('check-errors', 0) + result.get('corruptions', 0)
        self.assertGreater(
            errors, 0,
            'Corrupt VHDX should report errors'
        )

    def test_vhd_corrupt_disktype(self):
        """VHD with invalid disk type should report corruption."""
        testdata_root = self._testdata_root
        vhd_path = (
            testdata_root / 'custom' / 'format-coverage' /
            'vhd-corrupt-disktype.vhd'
        )

        if not vhd_path.exists():
            self.skipTest(f'Corrupt VHD not found: {vhd_path}')

        stdout, stderr, rc = self.run_imago_check(
            vhd_path, output_format='json'
        )

        # Should detect VHD format (reported as 'vpc' by qemu-img)
        result = json.loads(stdout)
        self.assertIn(
            result.get('format', '').lower(), ['vhd', 'vpc'],
            'Should detect as VHD/VPC format'
        )

        # Should report corruption
        errors = result.get('check-errors', 0) + result.get('corruptions', 0)
        self.assertGreater(
            errors, 0,
            'Corrupt VHD should report errors'
        )


class TestCheckQcow2Validation(ImagoTestBase):
    """Test improved QCOW2 structural validation.

    Uses deliberately corrupt images from
    imago-testdata/custom/check-validation/ to verify overlap
    detection, refcount validation, and leak detection.
    """

    def _get_check_validation_path(self, filename):
        """Get path to a check-validation test image."""
        path = (
            self._testdata_root / 'custom' /
            'check-validation' / filename
        )
        if not path.exists():
            self.skipTest(
                f'Test image not found: {path}. '
                f'Run create-corrupt-images.py first.'
            )
        return path

    def test_clean_qcow2_no_errors(self):
        """Clean QCOW2 should report 0 errors across all fields."""
        path = self._get_check_validation_path(
            'qcow2-clean-with-data.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            path, output_format='json'
        )

        self.assertEqual(rc, 0, f'Clean image failed: {stderr}')
        result = json.loads(stdout)
        self.assertEqual(result['format'], 'qcow2')
        self.assertEqual(result['check-errors'], 0)
        self.assertEqual(result['corruptions'], 0)
        self.assertEqual(result['leaks'], 0)
        self.assertEqual(result['refcount-errors'], 0)

    def test_clean_qcow2_cluster_count(self):
        """Clean QCOW2 should report correct allocated clusters."""
        path = self._get_check_validation_path(
            'qcow2-clean-with-data.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            path, output_format='json'
        )

        result = json.loads(stdout)
        # 4 data clusters + 1 L2 table = 5 allocated
        self.assertEqual(
            result['allocated-clusters'], 5,
            'Should report 5 allocated clusters '
            '(4 data + 1 L2 table)'
        )

    def test_overlapping_clusters_detected(self):
        """Overlapping L2 entries should be detected as corruption."""
        path = self._get_check_validation_path(
            'qcow2-overlapping-clusters.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            path, output_format='json'
        )

        self.assertNotEqual(rc, 0, 'Should exit non-zero')
        result = json.loads(stdout)
        self.assertGreater(
            result['corruptions'], 0,
            'Should detect overlapping cluster corruption'
        )

    def test_refcount_zero_detected(self):
        """Referenced cluster with refcount=0 should be detected."""
        path = self._get_check_validation_path(
            'qcow2-refcount-zero.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            path, output_format='json'
        )

        self.assertNotEqual(rc, 0, 'Should exit non-zero')
        result = json.loads(stdout)
        self.assertGreater(
            result['refcount-errors'], 0,
            'Should detect refcount=0 for referenced cluster'
        )

    def test_leaked_cluster_detected(self):
        """Cluster with refcount>0 but no L2 reference = leak."""
        path = self._get_check_validation_path(
            'qcow2-leaked-cluster.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            path, output_format='json'
        )

        self.assertNotEqual(rc, 0, 'Should exit non-zero')
        result = json.loads(stdout)
        self.assertGreater(
            result['leaks'], 0,
            'Should detect leaked cluster'
        )
        self.assertEqual(
            result['corruptions'], 0,
            'Leaked cluster should not be reported as corruption'
        )

    def test_clean_matches_qemu_img_end_offset(self):
        """image-end-offset should match qemu-img check."""
        path = self._get_check_validation_path(
            'qcow2-clean-with-data.qcow2'
        )

        # Run both tools
        imago_stdout, _, imago_rc = self.run_imago_check(
            path, output_format='json'
        )
        qemu_stdout, _, qemu_rc = self.run_qemu_img_check(
            path, output_format='json'
        )

        if qemu_rc != 0 and qemu_rc != 3:
            self.skipTest(
                f'qemu-img check failed unexpectedly: rc={qemu_rc}'
            )

        imago_result = json.loads(imago_stdout)
        qemu_result = json.loads(qemu_stdout)

        self.assertEqual(
            imago_result['image-end-offset'],
            qemu_result['image-end-offset'],
            'image-end-offset should match qemu-img check'
        )


class TestCheckUnsafeQuirksMode(ImagoTestBase):
    """Test that unsafe_quirks mode matches qemu-img behavior.

    TODO: test_unsafe_quirks_skips_vmdk_validation depends on
    vmdk-corrupt-version.vmdk from TestCheckCorruptImages. See that class
    docstring for details on the pending test image creation.
    """

    def test_unsafe_quirks_skips_vmdk_validation(self):
        """With --unsafe-quirks, corrupt VMDK should not report errors."""
        testdata_root = self._testdata_root
        vmdk_path = (
            testdata_root / 'custom' / 'format-coverage' /
            'vmdk-corrupt-version.vmdk'
        )

        if not vmdk_path.exists():
            self.skipTest(f'Corrupt VMDK not found: {vmdk_path}')

        stdout, stderr, rc = self.run_imago_check(
            vmdk_path, output_format='json', unsafe_quirks=True
        )

        # With unsafe_quirks, should be detected as raw
        result = json.loads(stdout)
        self.assertEqual(
            result.get('format', '').lower(), 'raw',
            'With --unsafe-quirks, should be detected as raw'
        )

        # Should not report corruption (raw has no metadata to check)
        errors = result.get('check-errors', 0) + result.get('corruptions', 0)
        self.assertEqual(
            errors, 0,
            'With --unsafe-quirks, no errors should be reported'
        )


class TestIncompatibleFeatureBits(ImagoTestBase):
    """Test that operations reject QCOW2 images with unsupported
    incompatible feature bits.

    Per the QCOW2 spec, unknown or unsupported incompatible feature
    bits MUST cause the reader to refuse to open the image. The info
    operation is exempt (it should always report what it can).
    """

    def _create_patched_qcow2(self, incompat_bits):
        """Create a v3 QCOW2 and patch incompatible_features.

        Returns a NamedTemporaryFile (caller must manage lifetime).
        The incompatible_features field is at offset 72, 8 bytes
        big-endian.
        """
        f = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'compat=1.1', f.name, '1M'],
            capture_output=True, check=True
        )
        # Patch the incompatible_features field (offset 72, 8 bytes BE)
        with open(f.name, 'r+b') as fh:
            fh.seek(72)
            fh.write(struct.pack('>Q', incompat_bits))
        return f

    def test_check_rejects_unknown_feature_bit(self):
        """Check should reject images with unknown feature bit 5."""
        with self._create_patched_qcow2(1 << 5) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            self.assertNotEqual(
                rc, 0,
                'check should reject unknown feature bit 5'
            )
            result = json.loads(stdout)
            self.assertGreater(result.get('corruptions', 0), 0)

    def test_check_accepts_external_data_bit(self):
        """Check should accept images with external data (bit 2).

        The external data incompatible feature bit is now supported.
        Check accepts the bit because structural validation (L1/L2
        tables, refcounts) works on the metadata file regardless of
        whether cluster data is in an external file.
        """
        with self._create_patched_qcow2(1 << 2) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                'external data bit should not cause corruption'
            )

    def test_check_accepts_extended_l2_bit(self):
        """Check should accept images with extended L2 (bit 4)."""
        with self._create_patched_qcow2(1 << 4) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                'extended L2 bit should not cause corruption'
            )

    def test_check_allows_dirty_bit(self):
        """Check should accept images with only the dirty bit set."""
        with self._create_patched_qcow2(1 << 0) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertTrue(
                result.get('dirty', False),
                'dirty flag should be reported'
            )

    def test_info_accepts_unknown_feature_bit(self):
        """Info should still work on images with unknown bits."""
        with self._create_patched_qcow2(1 << 5) as img:
            stdout, stderr, rc = self.run_imago_info(
                Path(img.name), output_format='json'
            )
            self.assertEqual(
                rc, 0,
                f'info should accept any image: {stderr}'
            )

    def test_compare_rejects_unknown_feature_bit(self):
        """Compare should reject images with unknown feature bits."""
        with self._create_patched_qcow2(1 << 5) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True, check=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(img.name), Path(raw.name)
            )
            self.assertNotEqual(
                rc, 0,
                'compare should reject unknown feature bits'
            )

    def test_convert_rejects_unknown_feature_bit(self):
        """Convert should reject images with unknown feature bits."""
        with self._create_patched_qcow2(1 << 5) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw:
            stdout, stderr, rc = self.run_imago_convert(
                Path(img.name), Path(raw.name)
            )
            self.assertNotEqual(
                rc, 0,
                'convert should reject unknown feature bits'
            )


class TestZstdCompression(ImagoTestBase):
    """Test ZSTD-compressed QCOW2 image handling.

    QCOW2 v3 images with compression_type=zstd (1) and the
    INCOMPAT_COMPRESSION bit (3) set use ZSTD instead of zlib
    for compressed clusters. These are created by QEMU 5.1+.
    """

    def _create_zstd_qcow2(self, size='1M', data_pattern=None):
        """Create a ZSTD-compressed QCOW2 and optionally write data.

        Returns a NamedTemporaryFile (caller manages lifetime).
        """
        # Create base raw with data
        raw = tempfile.NamedTemporaryFile(suffix='.raw')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw',
             raw.name, size],
            capture_output=True, check=True
        )
        if data_pattern:
            with open(raw.name, 'r+b') as f:
                f.write(data_pattern)

        # Convert to ZSTD-compressed QCOW2
        zstd = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'convert', '-f', 'raw',
             '-O', 'qcow2', '-c',
             '-o', 'compression_type=zstd',
             raw.name, zstd.name],
            capture_output=True, check=True
        )
        raw.close()
        return zstd

    def test_check_accepts_zstd_feature_bits(self):
        """Check should not reject ZSTD images for unsupported features.

        Verifies the INCOMPAT_COMPRESSION bit is accepted by check
        and that compressed clusters are correctly tracked in the
        overlap bitmap (no false leak reports).
        """
        with self._create_zstd_qcow2(
            data_pattern=b'\xaa' * 4096
        ) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                'ZSTD feature bits should not cause corruption'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'Compressed clusters should not cause '
                f'false leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'ZSTD image should have zero '
                f'check-errors: {stderr}'
            )

    def test_info_reports_zstd_image(self):
        """Info should report ZSTD-compressed images."""
        with self._create_zstd_qcow2(
            data_pattern=b'\xbb' * 4096
        ) as img:
            stdout, stderr, rc = self.run_imago_info(
                Path(img.name), output_format='json'
            )
            self.assertEqual(
                rc, 0,
                f'info should accept ZSTD image: {stderr}'
            )

    def test_convert_zstd_to_raw(self):
        """Convert a ZSTD-compressed QCOW2 to raw."""
        pattern = b'\xcc' * 65536  # One cluster of data
        with self._create_zstd_qcow2(
            data_pattern=pattern
        ) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                Path(img.name), Path(imago_raw.name)
            )
            self.assertEqual(
                rc, 0,
                f'convert should handle ZSTD: {stderr}'
            )

            # Convert with qemu-img for comparison
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, qemu_raw.name],
                capture_output=True, check=True
            )

            # Compare outputs
            stdout2, stderr2, rc2 = self.run_imago_compare(
                Path(imago_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                rc2, 0,
                'ZSTD convert output should match qemu-img'
            )

    def test_compare_zstd_vs_raw(self):
        """Compare a ZSTD-compressed QCOW2 against its raw equivalent."""
        pattern = b'\xdd' * 65536
        with self._create_zstd_qcow2(
            data_pattern=pattern
        ) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as raw:
            # Create matching raw via qemu-img
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, raw.name],
                capture_output=True, check=True
            )

            # Compare ZSTD qcow2 vs raw
            stdout, stderr, rc = self.run_imago_compare(
                Path(img.name), Path(raw.name)
            )
            self.assertEqual(
                rc, 0,
                f'ZSTD image should match raw: {stderr}'
            )


class TestExtendedL2(ImagoTestBase):
    """Test QCOW2 v3 extended L2 entry support.

    QCOW2 v3 images with INCOMPAT_EXTENDED_L2 (bit 4) use 16-byte
    L2 entries: the first 8 bytes are the standard L2 entry and the
    second 8 bytes are a subcluster allocation bitmap (32 subclusters
    per cluster). We treat the cluster as fully allocated if any
    subcluster is present (conservative but correct).
    """

    def _create_extended_l2_qcow2(
        self, size='1M', data_pattern=None
    ):
        """Create an extended L2 QCOW2 image.

        Returns a NamedTemporaryFile (caller manages lifetime).
        """
        img = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'extended_l2=on',
             img.name, size],
            capture_output=True, check=True
        )
        if data_pattern:
            subprocess.run(
                ['qemu-io', '-c',
                 f'write -P {data_pattern} 0 65536',
                 img.name],
                capture_output=True, check=True
            )
        return img

    def test_check_extended_l2_clean(self):
        """Check should accept a clean extended L2 image."""
        with self._create_extended_l2_qcow2(
            data_pattern=0xAA
        ) as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'clean ext L2 should have no corruptions: '
                f'{stderr}'
            )

    def test_info_extended_l2(self):
        """Info should report extended L2 images correctly."""
        with self._create_extended_l2_qcow2(
            data_pattern=0xBB
        ) as img:
            stdout, stderr, rc = self.run_imago_info(
                Path(img.name), output_format='json'
            )
            self.assertEqual(
                rc, 0,
                f'info should accept ext L2 image: {stderr}'
            )
            result = json.loads(stdout)
            qcow2_data = (
                result.get('format-specific', {})
                .get('data', {})
            )
            self.assertTrue(
                qcow2_data.get('extended-l2', False),
                'info should report extended-l2: true'
            )

    def test_convert_extended_l2_to_raw(self):
        """Convert an extended L2 QCOW2 to raw."""
        with self._create_extended_l2_qcow2(
            data_pattern=0xCC
        ) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                Path(img.name), Path(imago_raw.name)
            )
            self.assertEqual(
                rc, 0,
                f'convert should handle ext L2: {stderr}'
            )

            # Convert with qemu-img for comparison
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, qemu_raw.name],
                capture_output=True, check=True
            )

            # Compare outputs
            stdout2, stderr2, rc2 = self.run_imago_compare(
                Path(imago_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                rc2, 0,
                'ext L2 convert output should match '
                f'qemu-img: {stderr2}'
            )

    def test_compare_extended_l2_vs_raw(self):
        """Compare an extended L2 QCOW2 against raw equivalent."""
        with self._create_extended_l2_qcow2(
            data_pattern=0xDD
        ) as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as raw:
            # Create matching raw via qemu-img
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, raw.name],
                capture_output=True, check=True
            )

            # Compare ext L2 qcow2 vs raw
            stdout, stderr, rc = self.run_imago_compare(
                Path(img.name), Path(raw.name)
            )
            self.assertEqual(
                rc, 0,
                f'ext L2 should match raw: {stderr}'
            )

    def test_convert_extended_l2_compressed_to_raw(self):
        """Convert a compressed extended L2 QCOW2 to raw.

        Tests the combination of extended L2 entries (16-byte stride)
        with compressed clusters (zlib). These are orthogonal features
        that both affect L2 table interpretation.
        """
        # Create extended L2 image with data
        with self._create_extended_l2_qcow2(
            data_pattern=0xEE
        ) as ext_img, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2'
                ) as compressed, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw'
                ) as imago_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw'
                ) as qemu_raw:
            # Re-encode with compression
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'qcow2', '-c',
                 '-o', 'extended_l2=on',
                 ext_img.name, compressed.name],
                capture_output=True, check=True
            )

            # Convert with imago
            stdout, stderr, rc = self.run_imago_convert(
                Path(compressed.name),
                Path(imago_raw.name)
            )
            self.assertEqual(
                rc, 0,
                'convert should handle compressed '
                f'ext L2: {stderr}'
            )

            # Convert with qemu-img for comparison
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw',
                 compressed.name, qemu_raw.name],
                capture_output=True, check=True
            )

            # Compare outputs
            stdout2, stderr2, rc2 = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                rc2, 0,
                'compressed ext L2 convert output '
                f'should match qemu-img: {stderr2}'
            )


class TestExtendedL2Subclusters(ImagoTestBase):
    """Test correct per-subcluster handling in extended L2 images.

    Creates QCOW2 images with partially-allocated subclusters and
    verifies that convert/compare produce correct output by comparing
    against qemu-img convert (the gold standard).
    """

    def _create_partial_subcluster_qcow2(self):
        """Create an extended L2 QCOW2 with mixed subcluster states.

        Layout (64KB cluster = 32 subclusters of 2KB each):
        - Cluster 0: first 32KB written (0xAA), next 16KB zeroed,
          last 16KB unallocated
        - Cluster 1: fully written (0xBB)
        - Rest: unallocated

        Returns a NamedTemporaryFile.
        """
        img = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'extended_l2=on,cluster_size=65536',
             img.name, '1M'],
            capture_output=True, check=True
        )
        # Write first 32KB of cluster 0 (subclusters 0-15)
        subprocess.run(
            ['qemu-io', '-c', 'write -P 0xAA 0 32768',
             img.name],
            capture_output=True, check=True
        )
        # Zero next 16KB of cluster 0 (subclusters 16-23)
        subprocess.run(
            ['qemu-io', '-c', 'write -z 32768 16384',
             img.name],
            capture_output=True, check=True
        )
        # Write full cluster 1 (subclusters 0-31)
        subprocess.run(
            ['qemu-io', '-c', 'write -P 0xBB 65536 65536',
             img.name],
            capture_output=True, check=True
        )
        return img

    def test_convert_partial_subclusters(self):
        """Partially-allocated extended L2 cluster converts
        correctly when compared against qemu-img."""
        with self._create_partial_subcluster_qcow2() as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as qemu_raw:
            stdout, stderr, rc = self.run_imago_convert(
                Path(img.name), Path(imago_raw.name)
            )
            self.assertEqual(
                rc, 0,
                f'convert should handle partial subclusters: '
                f'{stderr}'
            )

            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, qemu_raw.name],
                capture_output=True, check=True
            )

            stdout2, stderr2, rc2 = self.run_imago_compare(
                Path(imago_raw.name), Path(qemu_raw.name)
            )
            self.assertEqual(
                rc2, 0,
                'partial subcluster convert should match '
                f'qemu-img: {stderr2}'
            )

    def test_convert_zero_subclusters(self):
        """Zero subclusters produce zeros in output even though
        host data may exist at the cluster offset."""
        with self._create_partial_subcluster_qcow2() as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as imago_raw:
            stdout, stderr, rc = self.run_imago_convert(
                Path(img.name), Path(imago_raw.name)
            )
            self.assertEqual(rc, 0, f'convert failed: {stderr}')

            with open(imago_raw.name, 'rb') as f:
                data = f.read()

            # First 32KB should be 0xAA (allocated subclusters)
            self.assertEqual(
                data[:32768], b'\xAA' * 32768,
                'first 32KB should be 0xAA'
            )
            # Next 16KB should be zeros (zero subclusters)
            self.assertEqual(
                data[32768:49152], b'\x00' * 16384,
                'bytes 32KB-48KB should be zeros'
            )
            # Next 16KB should be zeros (unallocated subclusters)
            self.assertEqual(
                data[49152:65536], b'\x00' * 16384,
                'bytes 48KB-64KB should be zeros (unalloc)'
            )
            # Cluster 1 should be 0xBB
            self.assertEqual(
                data[65536:131072], b'\xBB' * 65536,
                'cluster 1 should be 0xBB'
            )

    def test_compare_partial_vs_raw(self):
        """Compare extended L2 with partial subclusters against
        qemu-img convert output."""
        with self._create_partial_subcluster_qcow2() as img, \
                tempfile.NamedTemporaryFile(suffix='.raw') \
                as raw:
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw', img.name, raw.name],
                capture_output=True, check=True
            )

            stdout, stderr, rc = self.run_imago_compare(
                Path(img.name), Path(raw.name)
            )
            self.assertEqual(
                rc, 0,
                'partial subcluster qcow2 should match '
                f'raw: {stderr}'
            )

    def test_check_partial_subclusters(self):
        """Check should accept extended L2 images with partial
        subcluster allocation without reporting corruptions."""
        with self._create_partial_subcluster_qcow2() as img:
            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                'partial subclusters should not be corrupt: '
                f'{stderr}'
            )


class TestZstdBackingChain(ImagoTestBase):
    """Test ZSTD-compressed QCOW2 images with backing chains.

    Verifies that ZSTD decompression works correctly when the input
    image is part of a backing chain that needs to be flattened.
    """

    def _zstd_supported(self):
        """Check if qemu-img supports ZSTD compression."""
        result = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'compression_type=zstd',
             '/dev/null', '1M'],
            capture_output=True
        )
        return result.returncode == 0

    def test_convert_zstd_with_backing_chain(self):
        """Convert a ZSTD image that has a backing chain."""
        if not self._zstd_supported():
            self.skipTest(
                'qemu-img does not support ZSTD'
            )

        with tempfile.NamedTemporaryFile(
            suffix='.raw'
        ) as base_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2'
                ) as base_qcow2, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2'
                ) as overlay, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw'
                ) as imago_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw'
                ) as qemu_raw:
            # Create base raw with data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 base_raw.name, '1M'],
                capture_output=True, check=True
            )
            with open(base_raw.name, 'r+b') as f:
                f.write(b'\xAA' * 65536)

            # Convert base to QCOW2
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'raw',
                 '-O', 'qcow2',
                 base_raw.name, base_qcow2.name],
                capture_output=True, check=True
            )

            # Create ZSTD overlay with backing
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compression_type=zstd',
                 '-b', base_qcow2.name,
                 '-F', 'qcow2',
                 overlay.name, '1M'],
                capture_output=True, check=True
            )
            # Write different data to overlay
            subprocess.run(
                ['qemu-io', '-c',
                 'write -P 0xBB 65536 65536',
                 overlay.name],
                capture_output=True, check=True
            )

            # Convert with imago (flattens chain)
            stdout, stderr, rc = self.run_imago_convert(
                Path(overlay.name),
                Path(imago_raw.name)
            )
            self.assertEqual(
                rc, 0,
                'convert should handle ZSTD with '
                f'backing chain: {stderr}'
            )

            # Convert with qemu-img for comparison
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw',
                 overlay.name, qemu_raw.name],
                capture_output=True, check=True
            )

            # Compare outputs
            stdout2, stderr2, rc2 = self.run_imago_compare(
                Path(imago_raw.name),
                Path(qemu_raw.name)
            )
            self.assertEqual(
                rc2, 0,
                'ZSTD backing chain convert should '
                f'match qemu-img: {stderr2}'
            )

    def test_compare_zstd_backing_vs_flattened(self):
        """Compare a ZSTD overlay (with backing) against flat raw."""
        if not self._zstd_supported():
            self.skipTest(
                'qemu-img does not support ZSTD'
            )

        with tempfile.NamedTemporaryFile(
            suffix='.raw'
        ) as base_raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2'
                ) as base_qcow2, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2'
                ) as overlay, \
                tempfile.NamedTemporaryFile(
                    suffix='.raw'
                ) as flat_raw:
            # Create base raw with data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 base_raw.name, '1M'],
                capture_output=True, check=True
            )
            with open(base_raw.name, 'r+b') as f:
                f.write(b'\xCC' * 65536)

            # Convert base to QCOW2
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'raw',
                 '-O', 'qcow2',
                 base_raw.name, base_qcow2.name],
                capture_output=True, check=True
            )

            # Create ZSTD overlay with backing
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compression_type=zstd',
                 '-b', base_qcow2.name,
                 '-F', 'qcow2',
                 overlay.name, '1M'],
                capture_output=True, check=True
            )
            subprocess.run(
                ['qemu-io', '-c',
                 'write -P 0xDD 65536 65536',
                 overlay.name],
                capture_output=True, check=True
            )

            # Flatten with qemu-img for reference
            subprocess.run(
                ['qemu-img', 'convert', '-f', 'qcow2',
                 '-O', 'raw',
                 overlay.name, flat_raw.name],
                capture_output=True, check=True
            )

            # Compare ZSTD overlay vs flattened raw
            stdout, stderr, rc = self.run_imago_compare(
                Path(overlay.name),
                Path(flat_raw.name)
            )
            self.assertEqual(
                rc, 0,
                'ZSTD overlay should match flat '
                f'raw: {stderr}'
            )


class TestCheckCompressedLeaks(ImagoTestBase):
    """Compressed clusters should not cause false leak reports."""

    def test_compressed_zlib_no_leaks(self):
        """Zlib-compressed QCOW2 should have zero leaks."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as comp:
            # Create raw with data
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True, check=True
            )
            with open(raw.name, 'r+b') as f:
                f.write(b'\xAA' * 65536)

            # Convert to compressed QCOW2
            subprocess.run(
                ['qemu-img', 'convert', '-c',
                 '-f', 'raw', '-O', 'qcow2',
                 raw.name, comp.name],
                capture_output=True, check=True
            )

            stdout, stderr, rc = self.run_imago_check(
                Path(comp.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'Unexpected corruptions: {stderr}'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'Compressed clusters should not cause '
                f'false leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'Unexpected check-errors: {stderr}'
            )

    def test_compressed_matches_qemu_img(self):
        """Compressed check results should match qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as comp:
            # Create raw with multiple data patterns
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '4M'],
                capture_output=True, check=True
            )
            with open(raw.name, 'r+b') as f:
                for i in range(4):
                    f.seek(i * 65536)
                    f.write(bytes([0xAA + i]) * 65536)

            # Convert to compressed QCOW2
            subprocess.run(
                ['qemu-img', 'convert', '-c',
                 '-f', 'raw', '-O', 'qcow2',
                 raw.name, comp.name],
                capture_output=True, check=True
            )

            # Run qemu-img check
            qemu_result = subprocess.run(
                ['qemu-img', 'check', '-f', 'qcow2',
                 '--output=json', comp.name],
                capture_output=True, text=True
            )
            qemu_data = json.loads(qemu_result.stdout)
            qemu_leaks = qemu_data.get('leaks', 0)
            qemu_corruptions = qemu_data.get('corruptions', 0)

            # Run imago check
            stdout, stderr, rc = self.run_imago_check(
                Path(comp.name), output_format='json'
            )
            imago_data = json.loads(stdout)

            self.assertEqual(
                imago_data.get('corruptions', 0),
                qemu_corruptions,
                f'Corruption count mismatch: {stderr}'
            )
            self.assertEqual(
                imago_data.get('leaks', 0),
                qemu_leaks,
                f'Leak count mismatch: {stderr}'
            )

    def test_compressed_multi_cluster_no_leaks(self):
        """Multi-cluster compressed image should have zero leaks."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(
                    suffix='.qcow2') as comp:
            # Create larger image with many clusters
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '8M'],
                capture_output=True, check=True
            )
            with open(raw.name, 'r+b') as f:
                for i in range(128):
                    f.seek(i * 65536)
                    f.write(bytes([i & 0xFF]) * 65536)

            subprocess.run(
                ['qemu-img', 'convert', '-c',
                 '-f', 'raw', '-O', 'qcow2',
                 raw.name, comp.name],
                capture_output=True, check=True
            )

            stdout, stderr, rc = self.run_imago_check(
                Path(comp.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'Unexpected corruptions: {stderr}'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'Multi-cluster compressed should not '
                f'cause false leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'Unexpected check-errors: {stderr}'
            )


class TestCheckRefcountWidths(ImagoTestBase):
    """Test check with non-16-bit refcount widths."""

    def _create_refcount_qcow2(self, refcount_bits):
        """Create a QCOW2 v3 image with a specific refcount width."""
        f = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', f'refcount_bits={refcount_bits}',
             f.name, '1M'],
            capture_output=True, check=True
        )
        # Write some data so there are allocated clusters
        subprocess.run(
            ['qemu-io', '-c',
             'write -P 0xAA 0 65536', f.name],
            capture_output=True, check=True
        )
        return f

    def _check_no_errors(self, refcount_bits):
        """Run check on an image with given refcount_bits."""
        with self._create_refcount_qcow2(refcount_bits) as img:
            # Cross-validate with qemu-img check first
            qemu_result = subprocess.run(
                ['qemu-img', 'check', '-f', 'qcow2',
                 '--output=json', img.name],
                capture_output=True, text=True
            )
            if qemu_result.returncode not in (0, 3):
                self.skipTest(
                    f'qemu-img check failed for '
                    f'refcount_bits={refcount_bits}: '
                    f'{qemu_result.stderr}'
                )

            stdout, stderr, rc = self.run_imago_check(
                Path(img.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'refcount_bits={refcount_bits}: '
                f'unexpected corruptions: {stderr}'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'refcount_bits={refcount_bits}: '
                f'unexpected leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'refcount_bits={refcount_bits}: '
                f'unexpected check-errors: {stderr}'
            )

    def test_check_1bit_refcount(self):
        """Check should work with 1-bit refcounts."""
        self._check_no_errors(1)

    def test_check_2bit_refcount(self):
        """Check should work with 2-bit refcounts."""
        self._check_no_errors(2)

    def test_check_4bit_refcount(self):
        """Check should work with 4-bit refcounts."""
        self._check_no_errors(4)

    def test_check_8bit_refcount(self):
        """Check should work with 8-bit refcounts."""
        self._check_no_errors(8)

    def test_check_16bit_refcount(self):
        """Check should work with 16-bit refcounts (default)."""
        self._check_no_errors(16)

    def test_check_32bit_refcount(self):
        """Check should work with 32-bit refcounts."""
        self._check_no_errors(32)

    def test_check_64bit_refcount(self):
        """Check should work with 64-bit refcounts."""
        self._check_no_errors(64)

    def test_manifest_refcount_bits_1(self):
        """Manifest image with 1-bit refcounts should pass check."""
        image = self.get_image('qcow2-refcount-bits-1')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'Unexpected corruptions: {stderr}'
        )
        self.assertEqual(
            result.get('leaks', 0), 0,
            f'Unexpected leaks: {stderr}'
        )

    def test_manifest_refcount_bits_64(self):
        """Manifest image with 64-bit refcounts should pass check."""
        image = self.get_image('qcow2-refcount-bits-64')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'Unexpected corruptions: {stderr}'
        )
        self.assertEqual(
            result.get('leaks', 0), 0,
            f'Unexpected leaks: {stderr}'
        )


class TestCheckLargeCluster(ImagoTestBase):
    """Test check operation with cluster sizes > 64KB.

    QCOW2 supports cluster_bits 9-21 (512B to 2MB). These tests
    verify that the check operation correctly handles large cluster
    sizes that exceed the I/O sector size.
    """

    def test_check_2mb_cluster_clean(self):
        """A clean 2MB-cluster QCOW2 should pass check."""
        with tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as f:
            tmp = f.name
        try:
            subprocess.run(
                [
                    'qemu-img', 'create', '-f', 'qcow2',
                    '-o', 'cluster_size=2M',
                    tmp, '64M',
                ],
                check=True, capture_output=True, timeout=30,
            )
            # Write some data so it's not entirely empty
            subprocess.run(
                [
                    'qemu-io', '-f', 'qcow2', '-c',
                    'write -P 0xAB 0 4M',
                    tmp,
                ],
                check=True, capture_output=True, timeout=30,
            )

            # Verify qemu-img check passes
            qemu_result = subprocess.run(
                [
                    'qemu-img', 'check', '--output=json',
                    '-f', 'qcow2', tmp,
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertIn(
                qemu_result.returncode, (0, 3),
                f'qemu-img check failed: {qemu_result.stderr}'
            )

            # Verify imago check passes
            stdout, stderr, rc = self.run_imago_check(
                tmp, output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'Unexpected corruptions: {stderr}'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'Unexpected leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'Unexpected check-errors: {stderr}'
            )
        finally:
            os.unlink(tmp)

    def test_check_256k_cluster_clean(self):
        """A clean 256K-cluster QCOW2 should pass check."""
        with tempfile.NamedTemporaryFile(
            suffix='.qcow2', delete=False
        ) as f:
            tmp = f.name
        try:
            subprocess.run(
                [
                    'qemu-img', 'create', '-f', 'qcow2',
                    '-o', 'cluster_size=256K',
                    tmp, '32M',
                ],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                [
                    'qemu-io', '-f', 'qcow2', '-c',
                    'write -P 0xCD 0 2M',
                    tmp,
                ],
                check=True, capture_output=True, timeout=30,
            )

            stdout, stderr, rc = self.run_imago_check(
                tmp, output_format='json'
            )
            result = json.loads(stdout)
            self.assertEqual(
                result.get('corruptions', 0), 0,
                f'Unexpected corruptions: {stderr}'
            )
            self.assertEqual(
                result.get('leaks', 0), 0,
                f'Unexpected leaks: {stderr}'
            )
            self.assertEqual(
                result.get('check-errors', 0), 0,
                f'Unexpected check-errors: {stderr}'
            )
        finally:
            os.unlink(tmp)

    def test_check_manifest_max_cluster(self):
        """Manifest image with 2MB clusters should pass check."""
        image = self.get_image('qcow2-max-cluster')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'Unexpected corruptions: {stderr}'
        )
        self.assertEqual(
            result.get('leaks', 0), 0,
            f'Unexpected leaks: {stderr}'
        )

    def test_check_manifest_sf_vda_backing(self):
        """sf-vda-backing (2MB clusters) should pass check."""
        image = self.get_image('sf-vda-backing')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'Unexpected corruptions: {stderr}'
        )
        self.assertEqual(
            result.get('leaks', 0), 0,
            f'Unexpected leaks: {stderr}'
        )


class TestCheckExternalDataFile(ImagoTestBase):
    """Tests for check operation with QCOW2 external data files."""

    def test_check_external_data_no_errors_with_chain(self):
        """Check --chain on a well-formed external data file image.

        When the data file is available via --chain, check should
        report zero corruptions.
        """
        image = self.get_image('qcow2-external-data-raw')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json', chain=True
        )
        self.assertEqual(
            0, rc,
            f'check --chain should succeed: {stderr}'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'No corruptions expected with external data file: {stderr}'
        )

    def test_check_external_data_no_errors_without_chain(self):
        """Check without --chain on a QCOW2 with external data.

        When the external data bit is set, check should skip validation
        of standard cluster offsets (they point into the data file).
        Metadata validation (L1/L2 structure, refcounts) still works.
        """
        image = self.get_image('qcow2-external-data-raw')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        self.assertEqual(
            0, rc,
            f'check should succeed for external data: {stderr}'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'No corruptions expected (data offsets skipped): {stderr}'
        )


class TestCheckVhdFixed(ImagoTestBase):
    """Tests for check operation with fixed VHD (disk_type=2)."""

    def test_check_vhd_fixed_detects_vpc(self):
        """Check detects fixed VHD as vpc format with no errors."""
        image = self.get_image('vhd-fixed')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        self.assertEqual(
            0, rc,
            f'check should succeed for fixed VHD: {stderr}'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'No corruptions expected for fixed VHD: {stdout}'
        )

    def test_info_vhd_fixed_format(self):
        """Info detects fixed VHD as vpc format."""
        image = self.get_image('vhd-fixed')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(
            0, rc,
            f'info should succeed for fixed VHD: {stderr}'
        )
        self.assertIn(
            'vpc', stdout.lower(),
            f'Expected vpc format for fixed VHD: {stdout}'
        )


class TestCheckVhdDifferencing(ImagoTestBase):
    """Tests for check operation with differencing VHD (disk_type=4)."""

    def test_check_vhd_differencing_detects_vpc(self):
        """Check detects differencing VHD as vpc/vhd format."""
        image = self.get_image('vhd-differencing')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        self.assertEqual(
            0, rc,
            f'check should succeed for differencing VHD: {stderr}'
        )
        result = json.loads(stdout)
        self.assertIn(
            result.get('format', '').lower(), ('vpc', 'vhd'),
            f'Expected vpc/vhd format for differencing VHD: {stdout}'
        )
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'No corruptions expected: {stdout}'
        )

    def test_info_vhd_differencing_format(self):
        """Info detects differencing VHD as vpc format."""
        image = self.get_image('vhd-differencing')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(
            0, rc,
            f'info should succeed for differencing VHD: {stderr}'
        )
        self.assertIn(
            'vpc', stdout.lower(),
            f'Expected vpc format: {stdout}'
        )


class TestCheckSecurityExternalData(ImagoTestBase):
    """Tests for check with external data file security images."""

    def test_check_security_image_external_data(self):
        """Check should succeed on the CVE-2024-32498 security test image.

        The malicious test image has the external data bit set. Check
        should accept it without reporting false corruptions from data
        cluster offsets.
        """
        image = self.get_image('qcow2-external-data-file')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        self.assertEqual(
            0, rc,
            f'check should succeed for external data: {stderr}'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', 0), 0,
            f'No corruptions expected: {stderr}'
        )


class TestCheckVmdkMultiExtent(ImagoTestBase):
    """Tests for check operation with multi-extent VMDK."""

    def test_check_vmdk_multi_extent_detected(self):
        """Check detects multi-extent VMDK as vmdk format."""
        image = self.get_image('vmdk-multi-extent')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('format', '').lower(), 'vmdk',
            f'Expected vmdk format: {stdout}'
        )

    def test_check_vmdk_multi_extent_not_supported(self):
        """Check reports not-supported for multi-extent VMDK.

        Multi-extent VMDKs trigger FLAG_NOT_SUPPORTED in check, which
        causes early return with 0 clusters checked. In human output
        this prints "does not support checks".
        """
        image = self.get_image('vmdk-multi-extent')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # JSON output: early bail means 0 clusters checked
        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('total-clusters', -1), 0,
            f'Multi-extent VMDK should bail early with 0 clusters: {stdout}'
        )

        # Human output: "does not support checks"
        stdout_h, stderr_h, rc_h = self.run_imago_check(
            image.path, output_format='human'
        )
        self.assertIn(
            'does not support checks', stdout_h.lower(),
            f'Expected not-supported message: {stdout_h}'
        )

    def test_info_vmdk_multi_extent_format(self):
        """Info detects multi-extent VMDK as vmdk format."""
        image = self.get_image('vmdk-multi-extent')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(
            0, rc,
            f'info should succeed for multi-extent VMDK: {stderr}'
        )
        self.assertIn(
            'vmdk', stdout.lower(),
            f'Expected vmdk format: {stdout}'
        )


class TestCheckQcow2Snapshots(ImagoTestBase):
    """Test that info detects and reports QCOW2 snapshots."""

    def test_info_reports_snapshot_count(self):
        """Info should report snapshot count for images
        with snapshots."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        stdout, stderr, rc = self.run_imago_info(
            image.path
        )
        self.assertEqual(
            0, rc,
            f'info failed: {stderr}'
        )
        self.assertIn(
            'Snapshot count: 2', stdout,
            f'Expected snapshot count: {stdout}'
        )

    def test_check_with_snapshots_reports_leaks(self):
        """Check on snapshot images should report leaked
        clusters (snapshot L1/L2/data clusters have refcount
        but are not referenced by the active L1 table)."""
        image = self.get_image('qcow2-snapshots')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        stdout, stderr, rc = self.run_imago_check(
            image.path
        )
        # Leaked clusters are expected — snapshot metadata
        # has refcount > 0 but no active L2 reference
        self.assertIn(
            'leaked', stdout,
            f'Expected leaked clusters: {stdout}'
        )

    def test_info_no_snapshots_for_normal_image(self):
        """Info should not report snapshot count for images
        without snapshots."""
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        stdout, stderr, rc = self.run_imago_info(
            image.path
        )
        self.assertEqual(
            0, rc,
            f'info failed: {stderr}'
        )
        self.assertNotIn(
            'Snapshot count', stdout,
            f'Should not report snapshots: {stdout}'
        )


class TestCheckEnhancedValidation(ImagoTestBase):
    """Test enhanced structural validation for VMDK, VHD, VHDX.

    Phase 22 validation: grain markers, RGD, block bitmaps,
    geometry, region table fallback, log detection, fragmentation.
    """

    def test_check_streamoptimized_vmdk_clean(self):
        """StreamOptimized VMDK should pass grain marker checks."""
        image = self.get_image('vmdk-streamoptimized')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        stdout, stderr, rc = self.run_imago_check(
            image.path, output_format='json'
        )
        self.assertEqual(
            rc, 0,
            f'check failed for streamOptimized VMDK: '
            f'{stderr}'
        )
        result = json.loads(stdout)
        self.assertEqual(
            result.get('corruptions', -1), 0,
            f'Clean streamOptimized VMDK reported '
            f'corruptions: {stdout}'
        )

    def test_check_vmdk_corrupt_grain_marker(self):
        """VMDK with corrupt grain marker LBA should report error."""
        image = self.get_image('raw-mbr-partitioned')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
            suffix='.vmdk'
        ) as vmdk_tmp:
            # Create a streamOptimized VMDK with data
            _, stderr, rc = self.run_imago_convert(
                image.path, Path(vmdk_tmp.name),
                output_format='vmdk', compress=True,
                timeout=60
            )
            self.assertEqual(
                rc, 0,
                f'convert to vmdk failed: {stderr}'
            )

            data = Path(vmdk_tmp.name).read_bytes()

            # Find first grain marker after descriptor
            desc_off = struct.unpack_from(
                '<Q', data, 28
            )[0]
            desc_sz = struct.unpack_from(
                '<Q', data, 36
            )[0]
            grain_start = (desc_off + desc_sz) * 512

            # Verify there's a grain marker with data
            if grain_start + 12 > len(data):
                self.skipTest(
                    'VMDK too small for grain marker'
                )
            _, comp_size = struct.unpack_from(
                '<QI', data, grain_start
            )
            if comp_size == 0:
                self.skipTest(
                    'No compressed grain data found'
                )

            # Corrupt the LBA field
            with open(vmdk_tmp.name, 'r+b') as f:
                f.seek(grain_start)
                f.write(struct.pack('<Q', 0xDEADBEEF))

            stdout, stderr, rc = self.run_imago_check(
                Path(vmdk_tmp.name),
                output_format='json'
            )
            result = json.loads(stdout)
            self.assertGreater(
                result.get('corruptions', 0), 0,
                'Corrupt grain marker LBA should '
                'be detected'
            )
