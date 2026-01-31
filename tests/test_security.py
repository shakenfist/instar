"""
Security-focused tests for imago.

These tests verify that imago correctly detects and reports security-relevant
features in disk images (backing files, external data files, etc.) without
being exploited by them.
"""

import testtools

from base import ImagoTestBase


class TestSecurityFeatureDetection(ImagoTestBase):
    """Tests for security feature detection."""

    def test_imago_does_not_follow_backing_files(self):
        """
        Verify imago detects but doesn't follow backing file references.

        This is a placeholder for future security tests. When malicious
        images with backing files are tested, we should verify:
        1. imago reports the backing file reference
        2. imago does NOT read the referenced file
        3. No sensitive data is leaked in output
        """
        # TODO: Implement when we have backing file test infrastructure
        self.skipTest('Backing file security test not yet implemented')

    def test_imago_does_not_follow_external_data(self):
        """
        Verify imago detects but doesn't follow external data file references.

        QCOW2 v3 supports external data files which could reference
        sensitive system files. imago should report these but not read them.
        """
        # TODO: Implement when we have external data file test infrastructure
        self.skipTest('External data file security test not yet implemented')

    def test_imago_handles_vmdk_descriptor_safely(self):
        """
        Verify imago handles VMDK descriptors without following extent paths.

        VMDK descriptor files can reference arbitrary files as extents.
        imago should parse the descriptor but not read referenced extents.
        """
        # TODO: Implement when we have VMDK descriptor test infrastructure
        self.skipTest('VMDK descriptor security test not yet implemented')


class TestRawFormatValidation(ImagoTestBase):
    """Tests for RAW format validation (partition table detection).

    These tests verify imago's secure default behavior: files without valid
    format headers OR valid partition tables are rejected as 'unknown' format.
    This prevents arbitrary files (like /etc/passwd) from being accepted as
    disk images, which is the root cause of backing file disclosure attacks.
    """

    def test_rejects_garbage_without_unsafe_quirks(self):
        """
        Verify imago rejects random data without --unsafe-quirks.

        Files without valid format headers and without valid partition tables
        should be rejected as 'unknown' format in secure mode.
        """
        image = self.get_image('raw-random-garbage')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Without --unsafe-quirks, should fail to detect format
        stdout, stderr, rc = self.run_imago_info(
            image.path,
            unsafe_quirks=False
        )

        # Should report as unknown format (not 'raw')
        # The exact error message may vary, but it should indicate rejection
        self.assertIn(
            'unknown',
            stdout.lower() + stderr.lower(),
            f'Expected imago to reject garbage file, got: {stdout}{stderr}'
        )

    def test_accepts_garbage_with_unsafe_quirks(self):
        """
        Verify imago accepts random data WITH --unsafe-quirks.

        With --unsafe-quirks, imago should match qemu-img behavior and
        accept any file as 'raw' format.
        """
        image = self.get_image('raw-random-garbage')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # With --unsafe-quirks, should accept as raw
        stdout, stderr, rc = self.run_imago_info(
            image.path,
            unsafe_quirks=True
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'imago with --unsafe-quirks should accept garbage file: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected imago to report garbage as raw, got: {stdout}'
        )

    def test_accepts_mbr_partitioned_without_unsafe_quirks(self):
        """
        Verify imago accepts MBR-partitioned raw images without --unsafe-quirks.

        RAW images with valid MBR partition tables should be accepted in
        secure mode because they are recognizably disk images.
        """
        image = self.get_image('raw-mbr-partitioned')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Should succeed without --unsafe-quirks
        stdout, stderr, rc = self.run_imago_info(
            image.path,
            unsafe_quirks=False
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'imago should accept MBR-partitioned image: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected imago to report MBR image as raw, got: {stdout}'
        )

    def test_accepts_gpt_partitioned_without_unsafe_quirks(self):
        """
        Verify imago accepts GPT-partitioned raw images without --unsafe-quirks.

        RAW images with valid GPT partition tables should be accepted in
        secure mode because they are recognizably disk images.
        """
        image = self.get_image('raw-gpt-partitioned')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Should succeed without --unsafe-quirks
        stdout, stderr, rc = self.run_imago_info(
            image.path,
            unsafe_quirks=False
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'imago should accept GPT-partitioned image: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected imago to report GPT image as raw, got: {stdout}'
        )
