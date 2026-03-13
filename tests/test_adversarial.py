"""
Adversarial image tests for imago.

These tests verify that imago safely handles malicious and malformed images
without crashing, hanging, or consuming excessive resources. Each test uses
the run_adversarial() helper which enforces timeouts and memory limits.

See PLAN-adversarial-images.md for the full adversarial testing strategy.
"""

import tempfile
from pathlib import Path

from base import ImagoTestBase


class TestAdversarialCompressionBomb(ImagoTestBase):
    """Verify compression bomb images are handled safely."""

    def _get_adversarial_image(self, image_id):
        """Get an adversarial image, skipping if not found."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def test_info_compression_bomb_zlib(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zlib')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )
        # info may succeed or fail — either is acceptable as long as
        # no crash or hang

    def test_check_compression_bomb_zlib(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zlib')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zlib(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zlib')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            # Output file should not be excessively large
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                'Output file suspiciously large for compression bomb'
            )

    def test_info_compression_bomb_zstd(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zstd')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_compression_bomb_zstd(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zstd')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zstd(self):
        image = self._get_adversarial_image('qcow2-compression-bomb-zstd')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                'Output file suspiciously large for compression bomb'
            )


class TestAdversarialCircularChain(ImagoTestBase):
    """Verify circular backing chain images are detected and rejected."""

    def _get_adversarial_image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def test_info_circular_2(self):
        image = self._get_adversarial_image('qcow2-circular-2')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )
        # Info on the overlay itself should work (no chain traversal)

    def test_check_chain_circular_2(self):
        image = self._get_adversarial_image('qcow2-circular-2')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        # Should reject with non-zero exit, not loop forever
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_2(self):
        image = self._get_adversarial_image('qcow2-circular-2')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_circular_3(self):
        image = self._get_adversarial_image('qcow2-circular-3')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_3(self):
        image = self._get_adversarial_image('qcow2-circular-3')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_self_referencing(self):
        image = self._get_adversarial_image('qcow2-self-referencing')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')

    def test_convert_self_referencing(self):
        image = self._get_adversarial_image('qcow2-self-referencing')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')


class TestAdversarialDeepChain(ImagoTestBase):
    """Verify deep backing chains are handled correctly at the depth limit."""

    def _get_adversarial_image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def test_convert_chain_depth_16(self):
        """Chain at 16 levels exceeds device limit for convert.

        Convert needs an output device, so 16 input + 1 output = 17
        exceeds the 16-device maximum. This should be rejected cleanly.
        """
        image = self._get_adversarial_image('qcow2-chain-depth-16')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            self.assertNotEqual(
                0, rc,
                'Chain depth 16 convert should be rejected (needs output device)'
            )

    def test_convert_chain_depth_17(self):
        """Chain at 17 levels should be rejected."""
        image = self._get_adversarial_image('qcow2-chain-depth-17')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(
                0, rc,
                'Chain depth 17 should be rejected'
            )

    def test_check_chain_depth_16(self):
        image = self._get_adversarial_image('qcow2-chain-depth-16')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=30
        )
        self.assertEqual(
            0, rc,
            f'Chain depth 16 check should succeed: {stderr}'
        )

    def test_check_chain_depth_17(self):
        image = self._get_adversarial_image('qcow2-chain-depth-17')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(
            0, rc,
            'Chain depth 17 check should be rejected'
        )


class TestAdversarialIntegerOverflow(ImagoTestBase):
    """Verify integer overflow triggers in header fields are handled safely."""

    def _get_adversarial_image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def test_info_l1_overflow(self):
        image = self._get_adversarial_image('qcow2-l1-overflow')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_overflow(self):
        image = self._get_adversarial_image('qcow2-l1-overflow')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_l1_zero(self):
        image = self._get_adversarial_image('qcow2-l1-zero')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_zero(self):
        image = self._get_adversarial_image('qcow2-l1-zero')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_low(self):
        """Info reports header fields — no crash expected for cluster_bits=8."""
        image = self._get_adversarial_image('qcow2-cluster-bits-low')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_high(self):
        """Info reports header fields — no crash expected for cluster_bits=22."""
        image = self._get_adversarial_image('qcow2-cluster-bits-high')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_l1_overflow(self):
        image = self._get_adversarial_image('qcow2-l1-overflow')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_convert_cluster_bits_low(self):
        image = self._get_adversarial_image('qcow2-cluster-bits-low')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'cluster_bits=8 should be rejected')
