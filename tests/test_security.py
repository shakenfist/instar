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
