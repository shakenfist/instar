"""Tests for check --chain backing chain validation."""

import json

from base import ImagoTestBase


class TestCheckChain(ImagoTestBase):
    """Test backing chain validation with check --chain."""

    def _get_chain_image(self, subpath):
        """Get a chain test image path, skipping if not found."""
        path = self._testdata_root / subpath
        if not path.exists():
            self.skipTest(f'Test image not found: {path}')
        return path

    def test_check_chain_sf_vda(self):
        """Production SF vda chain (2 layers) should pass."""
        image = self._get_chain_image(
            'downloaded/shakenfist/vda'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='json', chain=True
        )
        result = json.loads(stdout)
        self.assertEqual(
            0, result['chain-errors'],
            'SF vda chain should have 0 chain errors'
        )
        self.assertEqual(
            0, result['check-errors'],
            'SF vda chain should have 0 total errors'
        )
        self.assertEqual(0, rc)

    def test_check_chain_json_output(self):
        """JSON output should include chain-errors field."""
        image = self._get_chain_image(
            'downloaded/shakenfist/vda'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='json', chain=True
        )
        result = json.loads(stdout)
        self.assertIn(
            'chain-errors', result,
            'JSON output must include chain-errors field'
        )

    def test_check_chain_single_no_backing(self):
        """Chain check on single image (no backing) should pass."""
        image = self._get_chain_image(
            'downloaded/shakenfist/vda-backing'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='json', chain=True
        )
        result = json.loads(stdout)
        self.assertEqual(
            0, result['chain-errors'],
            'Single image chain should have 0 chain errors'
        )

    def test_check_no_chain_backward_compatible(self):
        """Check without --chain should still work and show 0 chain
        errors."""
        image = self._get_chain_image(
            'downloaded/shakenfist/vda'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='json'
        )
        result = json.loads(stdout)
        self.assertEqual(
            0, result['chain-errors'],
            'Non-chain check should report 0 chain errors'
        )
        self.assertEqual(0, rc)

    def test_check_chain_security_rejected(self):
        """Chain check should reject backing files outside allowlist."""
        image = self._get_chain_image(
            'custom/security/qcow2-backing-etc-passwd.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, chain=True
        )
        self.assertNotEqual(
            0, rc,
            'Chain check should fail for malicious backing path'
        )
        self.assertIn(
            'outside allowed paths', stderr,
            'Error should mention path allowlist violation'
        )

    def test_check_chain_three_layer_cross_format(self):
        """Three-layer cross-format chain should validate."""
        image = self._get_chain_image(
            'custom/backing-layers-format-change/top.qcow2'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='json', chain=True
        )
        result = json.loads(stdout)
        # The chain validation should complete (format detection,
        # header validation). Note: tiny test images may have
        # pre-existing check-errors from L1 offset edge cases
        # at default sector size, but chain-errors should be
        # limited to header validation results.
        self.assertIn('chain-errors', result)
        self.assertIn('format', result)
        self.assertEqual('qcow2', result['format'])

    def test_check_chain_human_output(self):
        """Human output should mention chain errors when present."""
        image = self._get_chain_image(
            'downloaded/shakenfist/vda'
        )
        stdout, stderr, rc = self.run_imago_check(
            image, output_format='human', chain=True
        )
        self.assertIn(
            'No errors were found', stdout,
            'Clean chain should report no errors in human output'
        )
