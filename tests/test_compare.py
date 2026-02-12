"""Tests for compare operation (raw-vs-raw and QCOW2)."""

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


class TestCompareQcow2VsRaw(ImagoTestBase):
    """Test comparing QCOW2 images against raw images."""

    def _create_raw_with_data(self, path, size='1M', pattern=0xAA,
                              offset=0, length=65536):
        """Create a raw image and write a data pattern."""
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', path, size],
            capture_output=True, check=True
        )
        if length > 0:
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 f'write -P 0x{pattern:02X} {offset} {length}',
                 path],
                capture_output=True, check=True
            )

    def _convert_to_qcow2(self, raw_path, qcow2_path,
                           compressed=False):
        """Convert a raw image to QCOW2."""
        cmd = ['qemu-img', 'convert', '-f', 'raw',
               '-O', 'qcow2']
        if compressed:
            cmd.append('-c')
        cmd.extend([raw_path, qcow2_path])
        subprocess.run(cmd, capture_output=True, check=True)

    def test_qcow2_vs_raw_identical(self):
        """QCOW2 and raw with identical content are identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, qcow2.name)
            stdout, stderr, rc = self.run_imago_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_qcow2_vs_raw_identical_matches_qemu(self):
        """QCOW2 vs raw identical matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, qcow2.name)
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(raw.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_qcow2_vs_raw_different(self):
        """QCOW2 and raw with different content report mismatch."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            # Create raw with pattern 0xAA
            self._create_raw_with_data(raw1.name, pattern=0xAA)
            self._convert_to_qcow2(raw1.name, qcow2.name)
            # Create different raw with pattern 0xBB
            self._create_raw_with_data(raw2.name, pattern=0xBB)
            stdout, stderr, rc = self.run_imago_compare(
                Path(raw2.name), Path(qcow2.name)
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Content mismatch at offset 0!\n'
            )

    def test_qcow2_vs_raw_different_matches_qemu(self):
        """QCOW2 vs raw different matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as raw2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            self._create_raw_with_data(raw1.name, pattern=0xAA)
            self._convert_to_qcow2(raw1.name, qcow2.name)
            self._create_raw_with_data(raw2.name, pattern=0xBB)
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(raw2.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw2.name), Path(qcow2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_qcow2_vs_raw_all_zeros(self):
        """QCOW2 and raw with all-zero content are identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 raw.name, '1M'],
                capture_output=True, check=True
            )
            self._convert_to_qcow2(raw.name, qcow2.name)
            stdout, stderr, rc = self.run_imago_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )


class TestCompareQcow2VsQcow2(ImagoTestBase):
    """Test comparing two QCOW2 images."""

    def _create_raw_with_data(self, path, size='1M', pattern=0xAA,
                              offset=0, length=65536):
        """Create a raw image and write a data pattern."""
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', path, size],
            capture_output=True, check=True
        )
        if length > 0:
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 f'write -P 0x{pattern:02X} {offset} {length}',
                 path],
                capture_output=True, check=True
            )

    def _convert_to_qcow2(self, raw_path, qcow2_path,
                           compressed=False):
        """Convert a raw image to QCOW2."""
        cmd = ['qemu-img', 'convert', '-f', 'raw',
               '-O', 'qcow2']
        if compressed:
            cmd.append('-c')
        cmd.extend([raw_path, qcow2_path])
        subprocess.run(cmd, capture_output=True, check=True)

    def test_qcow2_vs_qcow2_identical(self):
        """Two QCOW2 images with identical content are identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, q1.name)
            self._convert_to_qcow2(raw.name, q2.name)
            stdout, stderr, rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_qcow2_vs_qcow2_identical_matches_qemu(self):
        """QCOW2 vs QCOW2 identical matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, q1.name)
            self._convert_to_qcow2(raw.name, q2.name)
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_qcow2_vs_qcow2_different(self):
        """Two QCOW2 images with different content report mismatch."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(r1.name, pattern=0xAA)
            self._create_raw_with_data(r2.name, pattern=0xBB)
            self._convert_to_qcow2(r1.name, q1.name)
            self._convert_to_qcow2(r2.name, q2.name)
            stdout, stderr, rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Content mismatch at offset 0!\n'
            )

    def test_qcow2_vs_qcow2_different_matches_qemu(self):
        """QCOW2 vs QCOW2 different matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(r1.name, pattern=0xAA)
            self._create_raw_with_data(r2.name, pattern=0xBB)
            self._convert_to_qcow2(r1.name, q1.name)
            self._convert_to_qcow2(r2.name, q2.name)
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_qcow2_vs_qcow2_size_mismatch(self):
        """QCOW2 images with different virtual sizes."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 r1.name, '1M'],
                capture_output=True, check=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 r2.name, '2M'],
                capture_output=True, check=True
            )
            self._convert_to_qcow2(r1.name, q1.name)
            self._convert_to_qcow2(r2.name, q2.name)
            stdout, stderr, rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(rc, 0)
            self.assertIn('Warning: Image size mismatch!', stdout)
            self.assertIn('Images are identical.', stdout)

    def test_qcow2_vs_qcow2_size_mismatch_matches_qemu(self):
        """QCOW2 size mismatch matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as r1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as r2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 r1.name, '1M'],
                capture_output=True, check=True
            )
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw',
                 r2.name, '2M'],
                capture_output=True, check=True
            )
            self._convert_to_qcow2(r1.name, q1.name)
            self._convert_to_qcow2(r2.name, q2.name)
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)


class TestCompareQcow2Compressed(ImagoTestBase):
    """Test comparing compressed QCOW2 images."""

    def _create_raw_with_data(self, path, size='1M', pattern=0xAA,
                              offset=0, length=65536):
        """Create a raw image and write a data pattern."""
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', path, size],
            capture_output=True, check=True
        )
        if length > 0:
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 f'write -P 0x{pattern:02X} {offset} {length}',
                 path],
                capture_output=True, check=True
            )

    def _convert_to_qcow2(self, raw_path, qcow2_path,
                           compressed=False):
        """Convert a raw image to QCOW2."""
        cmd = ['qemu-img', 'convert', '-f', 'raw',
               '-O', 'qcow2']
        if compressed:
            cmd.append('-c')
        cmd.extend([raw_path, qcow2_path])
        subprocess.run(cmd, capture_output=True, check=True)

    def test_compressed_qcow2_vs_raw_identical(self):
        """Compressed QCOW2 vs raw with same content: identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(
                raw.name, qcow2.name, compressed=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_compressed_qcow2_vs_raw_matches_qemu(self):
        """Compressed QCOW2 vs raw matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(
                raw.name, qcow2.name, compressed=True
            )
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(raw.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)

    def test_compressed_vs_uncompressed_qcow2_identical(self):
        """Compressed vs uncompressed QCOW2 with same content."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, q1.name)
            self._convert_to_qcow2(
                raw.name, q2.name, compressed=True
            )
            stdout, stderr, rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_compressed_vs_uncompressed_matches_qemu(self):
        """Compressed vs uncompressed matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as raw, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as q2:
            self._create_raw_with_data(raw.name)
            self._convert_to_qcow2(raw.name, q1.name)
            self._convert_to_qcow2(
                raw.name, q2.name, compressed=True
            )
            imago_out, _, imago_rc = self.run_imago_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(imago_out, qemu_out)
            self.assertEqual(imago_rc, qemu_rc)
