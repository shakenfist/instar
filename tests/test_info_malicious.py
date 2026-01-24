"""
Integration tests for malicious images using expected output overrides.

These tests verify that imago correctly handles malicious disk images.
Instead of running qemu-img (which could be exploited), we compare against
stored expected output files.

WARNING: These tests process known malicious images. They should only be
run in isolated test environments.
"""

import testscenarios

from base import ImagoTestBase


class TestInfoMalicious(testscenarios.WithScenarios, ImagoTestBase):
    """Test imago info against malicious images with expected overrides."""

    # Scenarios for malicious images - add entries as we create override files
    # Each scenario needs a corresponding expected output file
    scenarios = [
        # ('qcow2-backing-passwd', {'image_id': 'qcow2-backing-passwd'}),
        # ('vmdk-descriptor-passwd', {'image_id': 'vmdk-descriptor-passwd'}),
    ]

    def test_output_matches_expected(self):
        """Test that imago output matches expected override for malicious image."""
        if not self.scenarios:
            self.skipTest('No malicious image scenarios configured yet')

        image = self.get_image(self.image_id)

        # Skip if image file doesn't exist
        if not image.path.exists():
            self.skipTest(f'Image file not found: {image.path}')

        # Skip if no expected override is configured
        if not image.expected_override:
            self.skipTest(
                f'No expected_override configured for {image.id}. '
                f'Add expected output to tests/expected_outputs/'
            )

        # Load expected output from override file
        expected_output = self.load_expected_override(image.expected_override)
        if expected_output is None:
            self.skipTest(
                f'Expected override file not found: {image.expected_override}'
            )

        # Run imago (but NOT qemu-img - that would be dangerous)
        imago_stdout, imago_stderr, imago_rc = self.run_imago_info(image.path)

        # imago should succeed
        self.assertEqual(
            0, imago_rc,
            f'imago failed for {image.id}: {imago_stderr}'
        )

        # Output should match expected
        self.assert_outputs_match(image.id, imago_stdout, expected_output)
