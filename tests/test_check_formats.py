"""Tests for check operation format detection and validation."""

import json
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
