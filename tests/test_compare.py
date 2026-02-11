"""Tests for compare operation (Phase 2a: raw-vs-raw)."""

import json
import subprocess
import tempfile
from pathlib import Path

from base import ImagoTestBase


class TestCompareRawIdentical(ImagoTestBase):
    """Test comparing identical raw images."""

    def test_compare_identical_self(self):
        """Comparing a raw image with itself returns identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f.name), Path(f.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(stdout, 'Images are identical.\n')
            self.assertEqual(stderr, '')

    def test_compare_identical_two_files(self):
        """Two separate raw images with identical content are identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(stdout, 'Images are identical.\n')
            self.assertEqual(stderr, '')

    def test_compare_identical_matches_qemu(self):
        """Imago output matches qemu-img compare for identical images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            imago_out, imago_err, imago_rc = self.run_imago_compare(
                Path(f.name), Path(f.name)
            )
            qemu_out, qemu_err, qemu_rc = self.run_qemu_img_compare(
                Path(f.name), Path(f.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)


class TestCompareRawDifferent(ImagoTestBase):
    """Test comparing raw images with different content."""

    def test_compare_different_content(self):
        """Raw images with different content report mismatch at offset 0."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '1M'],
                capture_output=True
            )
            # Write different data to second image
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', f2.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Content mismatch at offset 0!\n'
            )
            self.assertEqual(stderr, '')

    def test_compare_mismatch_middle(self):
        """Mismatch in the middle of the file reports correct offset."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '1M'],
                capture_output=True
            )
            # Write at offset 512K
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 524288 4096', f2.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Content mismatch at offset 524288!\n'
            )

    def test_compare_different_matches_qemu(self):
        """Imago output matches qemu-img compare for different images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', f2.name],
                capture_output=True
            )
            imago_out, imago_err, imago_rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, qemu_err, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)


class TestCompareRawSizeMismatch(ImagoTestBase):
    """Test comparing raw images with different sizes."""

    def test_size_mismatch_zeros_nonstrict(self):
        """Different sizes (extra zeros) in non-strict: identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 0)
            self.assertIn('Warning: Image size mismatch!', stdout)
            self.assertIn('Images are identical.', stdout)

    def test_size_mismatch_zeros_nonstrict_matches_qemu(self):
        """Size mismatch (zeros) non-strict matches qemu-img output."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_size_mismatch_nonzero_nonstrict(self):
        """Different sizes with non-zero extra data: mismatch."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            # Write data beyond 1MB boundary
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 1048576 4096', f2.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 1)
            self.assertIn('Warning: Image size mismatch!', stdout)
            self.assertIn(
                'Content mismatch at offset 1048576!', stdout
            )

    def test_size_mismatch_nonzero_nonstrict_matches_qemu(self):
        """Size mismatch with non-zero data matches qemu-img output."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 1048576 4096', f2.name],
                capture_output=True
            )
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_size_mismatch_strict(self):
        """Strict mode: size mismatch alone causes failure."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name), strict=True
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Strict mode: Image size mismatch!\n'
            )

    def test_size_mismatch_strict_matches_qemu(self):
        """Strict size mismatch matches qemu-img -s output."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name), strict=True
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name), strict=True
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)


class TestCompareRawJson(ImagoTestBase):
    """Test JSON output for compare operation."""

    def test_identical_json(self):
        """JSON output for identical images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f.name), Path(f.name), output_format='json'
            )
            self.assertEqual(rc, 0)
            result = json.loads(stdout)
            self.assertTrue(result['identical'])
            self.assertEqual(result['total-bytes-compared'], 1048576)
            self.assertFalse(result['size-mismatch'])

    def test_different_json(self):
        """JSON output for different images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x42 0 4096', f2.name],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name), output_format='json'
            )
            self.assertEqual(rc, 1)
            result = json.loads(stdout)
            self.assertFalse(result['identical'])
            self.assertEqual(result['first-mismatch-offset'], 0)
            self.assertFalse(result['size-mismatch'])

    def test_size_mismatch_json(self):
        """JSON output includes size-mismatch flag."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as f2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f1.name, '1M'],
                capture_output=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f2.name, '2M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(f1.name), Path(f2.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertTrue(result['size-mismatch'])
            self.assertTrue(result['identical'])
