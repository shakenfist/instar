"""Tests for compare operation (raw-vs-raw, QCOW2, backing chains, LUKS).

Note: VHD compare integration tests (VHD vs raw comparison) are in
test_convert.py (TestConvertVhdCompare). VHDX compare integration
tests are in test_convert.py (TestConvertVhdxCompare).
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


class TestCompareRawIdentical(InstarTestBase):
    """Test comparing identical raw images."""

    def test_compare_identical_self(self):
        """Comparing a raw image with itself returns identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(stdout, 'Images are identical.\n')
            self.assertEqual(stderr, '')

    def test_compare_identical_matches_qemu(self):
        """Instar output matches qemu-img compare for identical images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            instar_out, instar_err, instar_rc = self.run_instar_compare(
                Path(f.name), Path(f.name)
            )
            qemu_out, qemu_err, qemu_rc = self.run_qemu_img_compare(
                Path(f.name), Path(f.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)


class TestCompareRawDifferent(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                stdout, 'Content mismatch at offset 524288!\n'
            )

    def test_compare_different_matches_qemu(self):
        """Instar output matches qemu-img compare for different images."""
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
            instar_out, instar_err, instar_rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, qemu_err, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)


class TestCompareRawSizeMismatch(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name), strict=True
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(f1.name), Path(f2.name), strict=True
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)


class TestCompareRawJson(InstarTestBase):
    """Test JSON output for compare operation."""

    def test_identical_json(self):
        """JSON output for identical images."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as f:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', f.name, '1M'],
                capture_output=True
            )
            stdout, stderr, rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_compare(
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
            stdout, stderr, rc = self.run_instar_compare(
                Path(f1.name), Path(f2.name), output_format='json'
            )
            result = json.loads(stdout)
            self.assertTrue(result['size-mismatch'])
            self.assertTrue(result['identical'])


class TestCompareQcow2VsRaw(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(raw.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(raw2.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw2.name), Path(qcow2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )


class TestCompareQcow2VsQcow2(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)


class TestCompareQcow2Compressed(InstarTestBase):
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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(raw.name), Path(qcow2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(raw.name), Path(qcow2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

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
            stdout, stderr, rc = self.run_instar_compare(
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
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(q1.name), Path(q2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(q1.name), Path(q2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)


class TestCompareBackingChain(InstarTestBase):
    """Test comparing images with backing chains."""

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

    def _create_overlay(self, backing_path, overlay_path,
                        backing_fmt='raw', size='1M'):
        """Create a QCOW2 overlay with a backing file."""
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-b', backing_path, '-F', backing_fmt,
             overlay_path, size],
            capture_output=True, check=True
        )

    def _write_to_qcow2(self, path, pattern=0xBB,
                         offset=65536, length=65536):
        """Write data to a QCOW2 image."""
        subprocess.run(
            ['qemu-io', '-f', 'qcow2', '-c',
             f'write -P 0x{pattern:02X} {offset} {length}',
             path],
            capture_output=True, check=True
        )

    def _flatten_to_raw(self, qcow2_path, raw_path):
        """Flatten a QCOW2 chain to a raw image."""
        subprocess.run(
            ['qemu-img', 'convert', '-f', 'qcow2',
             '-O', 'raw', qcow2_path, raw_path],
            capture_output=True, check=True
        )

    def test_qcow2_with_backing_vs_raw_identical(self):
        """QCOW2 overlay with backing vs flattened raw is identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(base.name)
            self._create_overlay(base.name, ov.name)
            self._write_to_qcow2(ov.name)
            self._flatten_to_raw(ov.name, flat.name)
            stdout, stderr, rc = self.run_instar_compare(
                Path(ov.name), Path(flat.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_qcow2_with_backing_vs_raw_matches_qemu(self):
        """QCOW2 overlay vs flattened raw matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(base.name)
            self._create_overlay(base.name, ov.name)
            self._write_to_qcow2(ov.name)
            self._flatten_to_raw(ov.name, flat.name)
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(ov.name), Path(flat.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(ov.name), Path(flat.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_qcow2_with_backing_vs_raw_different(self):
        """QCOW2 overlay vs different raw reports mismatch."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as diff:
            self._create_raw_with_data(base.name, pattern=0xAA)
            self._create_overlay(base.name, ov.name)
            self._write_to_qcow2(ov.name, pattern=0xBB)
            self._create_raw_with_data(
                diff.name, pattern=0xFF
            )
            stdout, stderr, rc = self.run_instar_compare(
                Path(ov.name), Path(diff.name)
            )
            self.assertEqual(rc, 1)
            self.assertIn('Content mismatch', stdout)

    def test_qcow2_with_backing_vs_raw_different_matches_qemu(
        self
    ):
        """QCOW2 overlay vs different raw matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as diff:
            self._create_raw_with_data(base.name, pattern=0xAA)
            self._create_overlay(base.name, ov.name)
            self._write_to_qcow2(ov.name, pattern=0xBB)
            self._create_raw_with_data(
                diff.name, pattern=0xFF
            )
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(ov.name), Path(diff.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(ov.name), Path(diff.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_deep_chain_vs_raw_identical(self):
        """3-level chain vs flattened raw is identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as top, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0x11
            )
            self._create_overlay(base.name, mid.name)
            self._write_to_qcow2(
                mid.name, pattern=0x22,
                offset=65536, length=65536
            )
            self._create_overlay(
                mid.name, top.name, backing_fmt='qcow2'
            )
            self._write_to_qcow2(
                top.name, pattern=0x33,
                offset=131072, length=65536
            )
            self._flatten_to_raw(top.name, flat.name)
            stdout, stderr, rc = self.run_instar_compare(
                Path(top.name), Path(flat.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_deep_chain_vs_raw_matches_qemu(self):
        """3-level chain vs flattened raw matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as top, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0x11
            )
            self._create_overlay(base.name, mid.name)
            self._write_to_qcow2(
                mid.name, pattern=0x22,
                offset=65536, length=65536
            )
            self._create_overlay(
                mid.name, top.name, backing_fmt='qcow2'
            )
            self._write_to_qcow2(
                top.name, pattern=0x33,
                offset=131072, length=65536
            )
            self._flatten_to_raw(top.name, flat.name)
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(top.name), Path(flat.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(top.name), Path(flat.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_both_chains_identical(self):
        """Two chains with same virtual content are identical."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as ba, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as oa, \
                tempfile.NamedTemporaryFile(suffix='.raw') as bb, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ob:
            # Chain A: base has 0xAA, overlay adds 0xBB
            self._create_raw_with_data(
                ba.name, pattern=0xAA
            )
            self._create_overlay(ba.name, oa.name)
            self._write_to_qcow2(oa.name, pattern=0xBB)
            # Chain B: base has 0xBB at offset 64K,
            # overlay adds 0xAA at offset 0
            self._create_raw_with_data(
                bb.name, pattern=0xBB,
                offset=65536, length=65536
            )
            self._create_overlay(bb.name, ob.name)
            self._write_to_qcow2(
                ob.name, pattern=0xAA,
                offset=0, length=65536
            )
            stdout, stderr, rc = self.run_instar_compare(
                Path(oa.name), Path(ob.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_both_chains_identical_matches_qemu(self):
        """Two chains with same content matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as ba, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as oa, \
                tempfile.NamedTemporaryFile(suffix='.raw') as bb, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ob:
            self._create_raw_with_data(
                ba.name, pattern=0xAA
            )
            self._create_overlay(ba.name, oa.name)
            self._write_to_qcow2(oa.name, pattern=0xBB)
            self._create_raw_with_data(
                bb.name, pattern=0xBB,
                offset=65536, length=65536
            )
            self._create_overlay(bb.name, ob.name)
            self._write_to_qcow2(
                ob.name, pattern=0xAA,
                offset=0, length=65536
            )
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(oa.name), Path(ob.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(oa.name), Path(ob.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_overlay_no_writes_vs_raw_identical(self):
        """Overlay with no writes (100% from backing) vs raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0xCC
            )
            # Create overlay with NO writes - all data from backing
            self._create_overlay(base.name, ov.name)
            self._flatten_to_raw(ov.name, flat.name)
            stdout, stderr, rc = self.run_instar_compare(
                Path(ov.name), Path(flat.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_overlay_no_writes_vs_raw_matches_qemu(self):
        """Overlay with no writes matches qemu-img compare."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as ov, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0xCC
            )
            self._create_overlay(base.name, ov.name)
            self._flatten_to_raw(ov.name, flat.name)
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(ov.name), Path(flat.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(ov.name), Path(flat.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_chains_different_virtual_sizes(self):
        """Two chains with different virtual sizes, zero-fill tail."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as b1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as o1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as b2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as o2:
            # Chain 1: 1M with data at offset 0
            self._create_raw_with_data(
                b1.name, size='1M', pattern=0xAA
            )
            self._create_overlay(b1.name, o1.name, size='1M')
            # Chain 2: 2M with same data at offset 0, rest zeros
            self._create_raw_with_data(
                b2.name, size='2M', pattern=0xAA
            )
            self._create_overlay(b2.name, o2.name, size='2M')
            stdout, stderr, rc = self.run_instar_compare(
                Path(o1.name), Path(o2.name)
            )
            # Non-strict: size mismatch but zeros = identical
            self.assertEqual(rc, 0)
            self.assertIn(
                'Warning: Image size mismatch!', stdout
            )
            self.assertIn('Images are identical.', stdout)

    def test_chains_different_virtual_sizes_matches_qemu(self):
        """Chains with different sizes matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as b1, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as o1, \
                tempfile.NamedTemporaryFile(suffix='.raw') as b2, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as o2:
            self._create_raw_with_data(
                b1.name, size='1M', pattern=0xAA
            )
            self._create_overlay(b1.name, o1.name, size='1M')
            self._create_raw_with_data(
                b2.name, size='2M', pattern=0xAA
            )
            self._create_overlay(b2.name, o2.name, size='2M')
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(o1.name), Path(o2.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(o1.name), Path(o2.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_passthrough_intermediate_vs_raw_identical(self):
        """Chain with empty intermediate overlay vs flattened raw."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as top, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0x55
            )
            # Mid overlay: no writes (passthrough)
            self._create_overlay(base.name, mid.name)
            # Top overlay: writes at different offset
            self._create_overlay(
                mid.name, top.name, backing_fmt='qcow2'
            )
            self._write_to_qcow2(
                top.name, pattern=0x66,
                offset=131072, length=65536
            )
            self._flatten_to_raw(top.name, flat.name)
            stdout, stderr, rc = self.run_instar_compare(
                Path(top.name), Path(flat.name)
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                stdout, 'Images are identical.\n'
            )

    def test_passthrough_intermediate_vs_raw_matches_qemu(self):
        """Empty intermediate overlay matches qemu-img."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as top, \
                tempfile.NamedTemporaryFile(suffix='.raw') as flat:
            self._create_raw_with_data(
                base.name, pattern=0x55
            )
            self._create_overlay(base.name, mid.name)
            self._create_overlay(
                mid.name, top.name, backing_fmt='qcow2'
            )
            self._write_to_qcow2(
                top.name, pattern=0x66,
                offset=131072, length=65536
            )
            self._flatten_to_raw(top.name, flat.name)
            instar_out, _, instar_rc = self.run_instar_compare(
                Path(top.name), Path(flat.name)
            )
            qemu_out, _, qemu_rc = self.run_qemu_img_compare(
                Path(top.name), Path(flat.name)
            )
            self.assertEqual(instar_out, qemu_out)
            self.assertEqual(instar_rc, qemu_rc)

    def test_corrupt_backing_chain_image(self):
        """Corrupt QCOW2 header in backing file is handled."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as base, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as mid, \
                tempfile.NamedTemporaryFile(suffix='.qcow2') as top:
            self._create_raw_with_data(base.name)
            self._create_overlay(base.name, mid.name)
            self._write_to_qcow2(mid.name, pattern=0xDD)
            self._create_overlay(
                mid.name, top.name, backing_fmt='qcow2'
            )
            self._write_to_qcow2(
                top.name, pattern=0xEE,
                offset=131072, length=65536
            )
            # Corrupt mid's QCOW2 magic number (first 4 bytes)
            with open(mid.name, 'r+b') as f:
                f.seek(0)
                f.write(b'\x00\x00\x00\x00')
            # instar should fail gracefully (non-zero exit)
            stdout, stderr, rc = self.run_instar_compare(
                Path(top.name), Path(base.name)
            )
            self.assertNotEqual(rc, 0)


class TestCompareLuksQcow2(InstarTestBase):
    """Test compare with LUKS-encrypted QCOW2 images (crypt_method=2)."""

    def test_compare_luks_qcow2_vs_raw(self):
        """Compare LUKS-in-QCOW2 against its decrypted raw equivalent."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            # First convert LUKS-QCOW2 to raw using instar
            stdout, stderr, rc = self.run_instar_convert(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase'
            )
            self.assertEqual(
                rc, 0,
                f'LUKS-QCOW2 convert to raw failed: {stderr}'
            )

            # Now compare the original LUKS-QCOW2 directly against
            # the decrypted raw, using --luks-passphrase
            stdout, stderr, rc = self.run_instar_compare(
                image.path, Path(raw_out.name),
                luks_passphrase='test-passphrase'
            )
            self.assertEqual(
                rc, 0,
                f'LUKS-QCOW2 vs raw compare failed: {stderr}'
            )
            self.assertIn('identical', stdout.lower())

    def test_compare_luks_qcow2_without_passphrase(self):
        """Compare LUKS-in-QCOW2 without passphrase should fail."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            # Create a small raw file for comparison target
            with open(raw_out.name, 'wb') as f:
                f.write(b'\x00' * 1048576)

            # Compare without passphrase should fail
            stdout, stderr, rc = self.run_instar_compare(
                image.path, Path(raw_out.name)
            )
            self.assertNotEqual(rc, 0)

    def test_compare_luks_qcow2_wrong_passphrase(self):
        """Compare LUKS-in-QCOW2 with wrong passphrase should fail."""
        image = self.get_image('qcow2-luks')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        with tempfile.NamedTemporaryFile(suffix='.raw') as raw_out:
            # Create a small raw file for comparison target
            with open(raw_out.name, 'wb') as f:
                f.write(b'\x00' * 1048576)

            # Compare with wrong passphrase should fail
            stdout, stderr, rc = self.run_instar_compare(
                image.path, Path(raw_out.name),
                luks_passphrase='wrong-passphrase'
            )
            self.assertNotEqual(rc, 0)


class TestCompareDetectOnlyRefusal(InstarTestBase):
    """compare refuses detect-only input formats instead of reading raw.

    Without the refusal gate compare would report "Images are identical."
    for a qed/vdi file compared with itself (both read as raw), masking
    that neither container is actually read (issue #444).  iso keeps its
    raw pass-through per the post-1a management decision.
    """

    def _refusal_image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def _assert_refused(self, image_id, fmt):
        image = self._refusal_image(image_id)
        stdout, stderr, rc = self.run_instar_compare(image.path, image.path)
        self.assertNotEqual(
            rc, 0,
            f'compare should refuse {fmt} input; stdout={stdout!r} '
            f'stderr={stderr!r}'
        )
        expected = (
            f"compare: input format '{fmt}' is detected but not supported "
            f'for reading (detection and info only)'
        )
        self.assertIn(
            expected, stdout + stderr,
            f'missing typed refusal for {fmt}: stderr={stderr!r}'
        )

    def test_compare_refuses_qed(self):
        """compare refuses a qed input with the typed message."""
        self._assert_refused('qed-simple', 'qed')

    def test_compare_refuses_vdi(self):
        """compare refuses a vdi input with the typed message."""
        self._assert_refused('vdi-simple', 'vdi')

    def test_compare_refuses_bochs(self):
        """compare refuses a bochs-growing input with the typed message."""
        self._assert_refused('bochs-growing', 'bochs')

    def test_compare_refuses_cloop(self):
        """compare refuses a cloop-simple input with the typed message."""
        self._assert_refused('cloop-simple', 'cloop')

    def test_compare_refuses_dmg(self):
        """compare refuses a dmg-simple input with the typed message."""
        self._assert_refused('dmg-simple', 'dmg')

    def test_compare_iso_passthrough(self):
        """compare keeps reading iso as raw (deliberate qemu parity)."""
        image = self._refusal_image('iso-simple')
        stdout, stderr, rc = self.run_instar_compare(image.path, image.path)
        self.assertEqual(
            rc, 0,
            f'iso compare should succeed; stderr={stderr!r}'
        )
        self.assertIn('identical', (stdout + stderr).lower())
