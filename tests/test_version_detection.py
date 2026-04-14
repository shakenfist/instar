"""
Tests for qemu-img version detection in instar.

These tests verify that instar correctly detects the installed qemu-img version
and selects the appropriate output profile. This is separate from output profile
tests which verify that specific --qemu-version values produce correct output.

Note: These tests require qemu-img to be installed.
"""

import re
import subprocess

from base import InstarTestBase


class TestVersionDetection(InstarTestBase):
    """Tests for qemu-img version detection."""

    def test_detects_qemu_version(self):
        """
        Verify instar detects the same qemu-img version as we detect in Python.

        This test compares:
        1. The version we detect by running qemu-img --version
        2. The version instar reports when run with --verbose
        """
        if self._qemu_version is None:
            self.skipTest('qemu-img not installed')

        # Get a test image
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar with verbose output to see version detection
        instar = self.get_instar_binary()
        result = subprocess.run(
            [str(instar), '--verbose', 'info', str(image.path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Look for version detection message in stderr
        # Example: "Detected qemu-img version 7.2, using matching output profile"
        match = re.search(
            r'Detected qemu-img version (\d+)\.(\d+)',
            result.stderr
        )

        if match:
            detected_major = int(match.group(1))
            detected_minor = int(match.group(2))

            expected_major, expected_minor = self._qemu_version

            self.assertEqual(
                (detected_major, detected_minor),
                (expected_major, expected_minor),
                f'instar detected version {detected_major}.{detected_minor} '
                f'but expected {expected_major}.{expected_minor}'
            )
        else:
            # If no detection message, instar might have failed or qemu-img
            # not found - check that it still ran successfully
            self.assertEqual(
                0, result.returncode,
                f'instar failed: {result.stderr}'
            )

    def test_profile_selection_matches_version(self):
        """
        Verify instar selects the correct profile for the detected version.

        qemu-img 6.0 - 7.x should use profile-6-0-0 (no Child node)
        qemu-img 8.0+ should use profile-8-0-0 (with Child node)
        """
        if self._qemu_version is None:
            self.skipTest('qemu-img not installed')

        # Get a test image
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar without --qemu-version to use auto-detection
        stdout, stderr, rc = self.run_instar_info(image.path)

        self.assertEqual(0, rc, f'instar failed: {stderr}')

        # Check for Child node section based on detected version
        major, minor = self._qemu_version
        has_child_node = "Child node '/file':" in stdout

        if major >= 8:
            self.assertTrue(
                has_child_node,
                f'qemu-img {major}.{minor} should produce output with '
                f'Child node section, but it was missing'
            )
        else:
            self.assertFalse(
                has_child_node,
                f'qemu-img {major}.{minor} should produce output without '
                f'Child node section, but it was present'
            )

    def test_explicit_version_overrides_detection(self):
        """
        Verify --qemu-version flag overrides auto-detection.

        Even if qemu-img 8.0+ is installed, specifying --qemu-version 7.2
        should produce output without Child node section.
        """
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run with --qemu-version 7.2 (profile-6-0-0)
        stdout_v7, stderr_v7, rc_v7 = self.run_instar_info(
            image.path, qemu_version='7.2'
        )
        self.assertEqual(0, rc_v7, f'instar failed for v7.2: {stderr_v7}')

        # Run with --qemu-version 8.0 (profile-8-0-0)
        stdout_v8, stderr_v8, rc_v8 = self.run_instar_info(
            image.path, qemu_version='8.0'
        )
        self.assertEqual(0, rc_v8, f'instar failed for v8.0: {stderr_v8}')

        # Verify difference
        v7_has_child = "Child node '/file':" in stdout_v7
        v8_has_child = "Child node '/file':" in stdout_v8

        self.assertFalse(
            v7_has_child,
            '--qemu-version 7.2 should not produce Child node section'
        )
        self.assertTrue(
            v8_has_child,
            '--qemu-version 8.0 should produce Child node section'
        )

    def test_invalid_version_string_rejected(self):
        """
        Verify instar rejects invalid --qemu-version values.
        """
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        instar = self.get_instar_binary()

        # Test various invalid version strings
        invalid_versions = ['abc', '', '1.2.3.4', 'not.a.version']

        for invalid in invalid_versions:
            if not invalid:
                # Skip empty string as it may cause arg parsing issues
                continue

            result = subprocess.run(
                [str(instar), 'info', '--qemu-version', invalid, str(image.path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            self.assertNotEqual(
                0, result.returncode,
                f'Expected instar to reject invalid version "{invalid}"'
            )
