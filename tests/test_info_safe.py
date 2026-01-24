"""
Integration tests comparing imago info output to qemu-img info for safe images.

These tests verify that imago produces identical output to qemu-img for
known-safe disk images. Any difference, including whitespace, is a failure
since imago aims to be a drop-in replacement.
"""

import testscenarios

from base import ImagoTestBase


class TestInfoSafe(testscenarios.WithScenarios, ImagoTestBase):
    """Test imago info against safe images."""

    # Scenarios are loaded from the manifest - only safe images
    scenarios = [
        ('cirros-qcow2', {'image_id': 'cirros-qcow2'}),
        ('qcow2-v2', {'image_id': 'qcow2-v2'}),
        ('plaso-vmdk', {'image_id': 'plaso-vmdk'}),
        ('hyperv-dynamic-vhd', {'image_id': 'hyperv-dynamic-vhd'}),
    ]

    def test_output_matches_qemu_img(self):
        """Test that imago info output exactly matches qemu-img info output."""
        image = self.get_image(self.image_id)

        # Skip if image file doesn't exist
        if not image.path.exists():
            self.skipTest(f'Image file not found: {image.path}')

        # Run both commands
        imago_stdout, imago_stderr, imago_rc = self.run_imago_info(image.path)
        qemu_stdout, qemu_stderr, qemu_rc = self.run_qemu_img_info(image.path)

        # Both should succeed
        self.assertEqual(
            0, qemu_rc,
            f'qemu-img failed for {image.id}: {qemu_stderr}'
        )
        self.assertEqual(
            0, imago_rc,
            f'imago failed for {image.id}: {imago_stderr}'
        )

        # Outputs should match exactly
        self.assert_outputs_match(image.id, imago_stdout, qemu_stdout)
