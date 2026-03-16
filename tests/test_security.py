"""
Security-focused tests for imago.

These tests verify that imago correctly detects and reports security-relevant
features in disk images (backing files, external data files, etc.) without
being exploited by them. The TestCVEReproduction class specifically validates
that known qemu-img CVEs are mitigated by imago's architecture.
"""

import json
import subprocess
import tempfile
import time

import testtools

from base import ImagoTestBase


class TestSecurityFeatureDetection(ImagoTestBase):
    """Tests for security feature detection."""

    def test_imago_reports_backing_file_without_reading_content(self):
        """
        Verify imago reports backing file path without leaking file contents.

        A QCOW2 with a backing file pointing to a text file should:
        1. Report the backing file reference in output
        2. NOT include any content from the backing file
        3. NOT require the backing file to be a valid disk image
        """
        image = self.get_image('qcow2-backing-textfile')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run imago info on the QCOW2
        stdout, stderr, rc = self.run_imago_info(image.path)

        # Should succeed - the overlay QCOW2 itself is valid
        self.assertEqual(
            0, rc,
            f'imago should process QCOW2 overlay successfully: {stderr}'
        )

        # Should report the backing file path
        self.assertIn(
            'backing file',
            stdout.lower(),
            f'Expected backing file reference in output: {stdout}'
        )

        # Should NOT contain content from the backing file
        # The fake-passwd.txt contains "This simulates a sensitive file"
        self.assertNotIn(
            'simulates',
            stdout.lower() + stderr.lower(),
            'Backing file content leaked in output!'
        )
        self.assertNotIn(
            'sensitive',
            stdout.lower() + stderr.lower(),
            'Backing file content leaked in output!'
        )

    def test_imago_reports_backing_file_to_etc_passwd(self):
        """
        Verify imago reports backing file reference to /etc/passwd.

        This simulates CVE-2015-5163 where an attacker crafts a QCOW2 with
        backing_file=/etc/passwd. imago should:
        1. Report the backing file path
        2. NOT read or leak /etc/passwd contents
        """
        image = self.get_image('qcow2-backing-etc-passwd')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run imago info on the QCOW2
        stdout, stderr, rc = self.run_imago_info(image.path)

        # Should succeed - the overlay QCOW2 itself is valid
        self.assertEqual(
            0, rc,
            f'imago should process QCOW2 overlay successfully: {stderr}'
        )

        # Should report /etc/passwd as the backing file path
        self.assertIn(
            '/etc/passwd',
            stdout,
            f'Expected /etc/passwd in backing file reference: {stdout}'
        )

        # Should NOT contain content from /etc/passwd
        # /etc/passwd typically contains "root:" as the first line
        self.assertNotIn(
            'root:',
            stdout + stderr,
            '/etc/passwd content leaked in output!'
        )

    def test_imago_reports_external_data_file_without_reading_content(self):
        """
        Verify imago reports external data file path without reading its content.

        QCOW2 v3 supports external data files (CVE-2024-32498) which could
        reference sensitive system files. The info operation should report
        the path from the DATA header extension without opening or reading
        the data file itself.
        """
        image = self.get_image('qcow2-external-data-file')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run imago info (without --chain, so no file opens)
        stdout, stderr, rc = self.run_imago_info(image.path)

        # Should succeed — the QCOW2 metadata is valid
        self.assertEqual(
            0, rc,
            f'imago should process QCOW2 with external data: {stderr}'
        )

        # Should report the data file path
        self.assertIn(
            'data file',
            stdout.lower(),
            f'Expected data file reference in output: {stdout}'
        )
        self.assertIn(
            'external-data.raw',
            stdout,
            f'Expected external-data.raw in data file path: {stdout}'
        )

    def test_imago_reports_external_data_file_in_json(self):
        """
        Verify imago reports external data file in JSON format-specific data.
        """
        image = self.get_image('qcow2-external-data-file')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_info(
            image.path, output_format='json'
        )

        self.assertEqual(
            0, rc,
            f'imago should process QCOW2 with external data: {stderr}'
        )

        import json
        data = json.loads(stdout)
        fmt_data = data.get('format-specific', {}).get('data', {})
        self.assertIn(
            'data-file', fmt_data,
            f'Expected data-file in format-specific.data: {fmt_data}'
        )
        self.assertEqual(
            'external-data.raw',
            fmt_data['data-file'],
            f'Expected external-data.raw as data-file value: {fmt_data}'
        )

    def test_imago_handles_vmdk_descriptor_safely(self):
        """
        Verify imago handles VMDK descriptors without following extent paths.

        VMDK descriptor files can reference arbitrary files as extents
        (e.g. /etc/passwd). Text-only VMDK descriptors have no binary
        magic, so imago rejects them as unknown format — extent paths
        are never followed.
        """
        image = self.get_image('vmdk-path-traversal')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Text-only descriptor has no binary magic, so imago
        # reports "unknown" format — extent paths never followed
        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(
            0, rc,
            f'imago info failed unexpectedly: {stderr}'
        )
        self.assertIn(
            'unknown', stdout.lower(),
            f'Expected unknown format for text descriptor: {stdout}'
        )

        # No /etc/passwd content should appear in output
        combined = stdout.lower() + stderr.lower()
        self.assertNotIn(
            'root:', combined,
            '/etc/passwd content leaked in output!'
        )

        # With --unsafe-quirks, accepted as raw (still no leak)
        stdout_u, stderr_u, rc_u = self.run_imago_info(
            image.path, unsafe_quirks=True
        )
        self.assertEqual(
            0, rc_u,
            f'--unsafe-quirks should accept as raw: {stderr_u}'
        )
        self.assertIn(
            'raw', stdout_u.lower(),
            'Expected raw format with --unsafe-quirks'
        )
        combined_u = stdout_u.lower() + stderr_u.lower()
        self.assertNotIn(
            'root:', combined_u,
            '/etc/passwd content leaked with --unsafe-quirks!'
        )

    def test_imago_handles_vmdk_no_extents_safely(self):
        """
        Verify imago rejects VMDK descriptors with no extent declarations.

        A VMDK descriptor with no RW/RDONLY/NOACCESS extent lines is
        invalid. imago should reject it as unknown format (no binary
        magic).
        """
        image = self.get_image('vmdk-no-extents')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(
            0, rc,
            f'imago info failed unexpectedly: {stderr}'
        )
        self.assertIn(
            'unknown', stdout.lower(),
            f'Expected unknown format for no-extent descriptor: {stdout}'
        )

        # With --unsafe-quirks, accepted as raw
        stdout_u, stderr_u, rc_u = self.run_imago_info(
            image.path, unsafe_quirks=True
        )
        self.assertEqual(
            0, rc_u,
            f'--unsafe-quirks should accept as raw: {stderr_u}'
        )
        self.assertIn(
            'raw', stdout_u.lower(),
            'Expected raw format with --unsafe-quirks'
        )


class TestBackingChainSecurity(ImagoTestBase):
    """Tests for backing chain discovery security.

    These tests verify that imago info --chain correctly handles invalid
    or malicious backing files in the chain.
    """

    def run_imago_info_chain(self, image_path, timeout=30, unsafe_quirks=False):
        """
        Run imago info --chain on an image.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        imago = self.get_imago_binary()

        cmd = [str(imago), 'info', '--chain']
        if unsafe_quirks:
            cmd.append('--unsafe-quirks')
        cmd.append(str(image_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def test_chain_rejects_invalid_raw_backing_file(self):
        """
        Verify that chain discovery rejects backing files without valid format.

        When a QCOW2 overlay references a backing file that is random garbage
        (no partition table), the chain discovery should fail with an
        appropriate error when running without --unsafe-quirks.
        """
        image = self.get_image('qcow2-backing-garbage')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # The backing file (random-garbage.raw) should be rejected
        backing = self.get_image('raw-random-garbage')
        if not backing.path.exists():
            self.skipTest(f'Backing image not found: {backing.path}')

        # Run imago info --chain without --unsafe-quirks
        stdout, stderr, rc = self.run_imago_info_chain(
            image.path,
            unsafe_quirks=False
        )

        # The chain discovery should fail because the backing file is rejected
        # as unknown format (no valid partition table)
        self.assertNotEqual(
            0, rc,
            f'Chain discovery should fail for invalid backing file: {stdout}'
        )

        # Error should indicate the problem
        combined_output = stdout.lower() + stderr.lower()
        self.assertTrue(
            'unknown' in combined_output or 'error' in combined_output,
            f'Expected error about unknown format: {stdout}{stderr}'
        )

    def test_chain_rejects_backing_file_outside_allowlist(self):
        """
        Verify that chain discovery rejects backing files outside the allowlist.

        When a QCOW2 references /etc/passwd as a backing file, the chain
        discovery should reject it as being outside the allowed paths.
        """
        image = self.get_image('qcow2-backing-etc-passwd')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run imago info --chain
        stdout, stderr, rc = self.run_imago_info_chain(image.path)

        # Should fail - /etc/passwd is outside the allowed path
        self.assertNotEqual(
            0, rc,
            f'Chain discovery should reject /etc/passwd: {stdout}'
        )

        # Error should mention the path restriction
        combined_output = stdout.lower() + stderr.lower()
        self.assertTrue(
            'allowed' in combined_output
            or 'outside' in combined_output
            or 'not found' in combined_output,
            f'Expected path allowlist error: {stdout}{stderr}'
        )


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


class TestCVEReproduction(ImagoTestBase):
    """CVE reproduction tests (Phase 4 of security audit).

    Each test uses a purpose-built reproducer image that mimics the attack
    vector from a known qemu-img CVE. Tests verify that imago's mitigations
    (KVM sandbox, host-side path allowlist, bounded buffers, checked
    arithmetic) prevent exploitation.
    """

    def run_imago_info_chain(self, image_path, timeout=30):
        """Run imago info --chain on an image."""
        imago = self.get_imago_binary()
        cmd = [str(imago), 'info', '--chain', str(image_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    # ----------------------------------------------------------------
    # CVE-2024-32498: QCOW2 external data file path traversal
    # ----------------------------------------------------------------

    def test_cve_2024_32498_info_reports_data_file_path(self):
        """External data file path is reported without opening the file."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_imago_info(image.path, output_format='json')
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')

        data = json.loads(stdout)
        fmt_data = data.get('format-specific', {}).get('data', {})
        self.assertEqual(fmt_data.get('data-file'), '/etc/passwd', f'Expected data-file=/etc/passwd: {fmt_data}')

    def test_cve_2024_32498_no_passwd_content_leaked(self):
        """No /etc/passwd content appears in info output."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        combined = stdout + stderr
        self.assertNotIn('root:', combined, '/etc/passwd content leaked in output!')

    def test_cve_2024_32498_chain_rejects_external_data_file(self):
        """Chain mode rejects external data file outside allowlist."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_imago_info_chain(image.path)
        # Chain should fail — /etc/passwd is outside the allowed directories
        self.assertNotEqual(rc, 0, f'Chain should reject /etc/passwd as external data file: {stdout}')

    def test_cve_2024_32498_convert_rejects_external_data_file(self):
        """Convert rejects image with external data file pointing to host path."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_imago_convert(image.path, out.name)
            # Convert should fail — external data file can't be accessed
            self.assertNotEqual(rc, 0, f'Convert should reject external data file: {stdout}')
            # No /etc/passwd content in output file
            out_data = open(out.name, 'rb').read(1024)
            self.assertNotIn(b'root:', out_data, '/etc/passwd content in converted output!')

    # ----------------------------------------------------------------
    # CVE-2015-5163: Backing file path traversal
    # ----------------------------------------------------------------

    def test_cve_2015_5163_dotdot_info_reports_path(self):
        """Info reports the ../../../etc/passwd backing path without reading it."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        self.assertIn('etc/passwd', stdout, f'Expected backing file path in output: {stdout}')
        self.assertNotIn('root:', stdout + stderr, '/etc/passwd content leaked!')

    def test_cve_2015_5163_dotdot_chain_rejects(self):
        """Chain mode rejects ../ traversal backing path."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        stdout, stderr, rc = self.run_imago_info_chain(image.path)
        self.assertNotEqual(rc, 0, f'Chain should reject traversal path: {stdout}')

    def test_cve_2015_5163_dotdot_convert_rejects(self):
        """Convert rejects image with ../ traversal backing path."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_imago_convert(image.path, out.name)
            self.assertNotEqual(rc, 0, f'Convert should reject traversal backing path: {stdout}')

    def test_cve_2015_5163_null_byte_info(self):
        """Backing file path with embedded null byte is handled safely."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-null')
        stdout, stderr, rc = self.run_imago_info(image.path)
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        # Should report some form of the backing file path
        self.assertNotIn('root:', stdout + stderr, '/etc/passwd content leaked via null byte bypass!')

    def test_cve_2015_5163_null_byte_chain_rejects(self):
        """Chain mode rejects backing path with embedded null byte."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-null')
        stdout, stderr, rc = self.run_imago_info_chain(image.path)
        self.assertNotEqual(rc, 0, f'Chain should reject null-byte path: {stdout}')

    # ----------------------------------------------------------------
    # CVE-2022-47951: VMDK descriptor with host file extent paths
    # ----------------------------------------------------------------

    def test_cve_2022_47951_info_no_shadow_content(self):
        """Binary VMDK with /etc/shadow extent does not leak file content."""
        image = self.get_adversarial_image('cve-2022-47951-vmdk-hostile-extent')
        stdout, stderr, rc = self.run_imago_info(image.path)
        # imago should detect this as VMDK (binary magic present)
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        combined = (stdout + stderr).lower()
        # /etc/shadow content should never appear
        for forbidden in ['root:', 'daemon:', 'bin:']:
            self.assertNotIn(forbidden, combined, f'/etc/shadow content leaked: {forbidden}')

    def test_cve_2022_47951_convert_no_shadow_content(self):
        """Converting VMDK with hostile extent does not produce /etc/shadow data."""
        image = self.get_adversarial_image('cve-2022-47951-vmdk-hostile-extent')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_imago_convert(image.path, out.name)
            # Convert may succeed or fail — either way, no shadow content
            out_data = open(out.name, 'rb').read(4096)
            for forbidden in [b'root:', b'daemon:', b'bin:']:
                self.assertNotIn(forbidden, out_data, f'/etc/shadow in converted output: {forbidden}')

    # ----------------------------------------------------------------
    # CVE-2015-5162: Resource exhaustion via tiny petabyte image
    # ----------------------------------------------------------------

    def test_cve_2015_5162_info_completes_quickly(self):
        """Info on a tiny image claiming 1 PB completes within 5 seconds."""
        image = self.get_adversarial_image('cve-2015-5162-tiny-petabyte')
        start = time.monotonic()
        stdout, stderr, rc = self.run_imago_info(image.path)
        elapsed = time.monotonic() - start
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        self.assertLess(elapsed, 5.0, f'Info took {elapsed:.1f}s on petabyte image (expected <5s)')

    def test_cve_2015_5162_check_completes_quickly(self):
        """Check on a tiny image claiming 1 PB completes within 10 seconds."""
        image = self.get_adversarial_image('cve-2015-5162-tiny-petabyte')
        start = time.monotonic()
        stdout, stderr, rc = self.run_imago_check(image.path)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 10.0, f'Check took {elapsed:.1f}s on petabyte image (expected <10s)')

    # ----------------------------------------------------------------
    # CVE-2014-0223: Integer overflow in L1 table size
    # ----------------------------------------------------------------

    def test_cve_2014_0223_info_no_crash(self):
        """Info on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)], timeout=10
        )
        # Should complete without signal (no crash)

    def test_cve_2014_0223_check_no_crash(self):
        """Check on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)], timeout=10
        )

    def test_cve_2014_0223_convert_no_crash(self):
        """Convert on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert', str(image.path), out.name], timeout=10
            )

    # ----------------------------------------------------------------
    # CVE-2024-4467: json:{} block device specification
    # ----------------------------------------------------------------

    def test_cve_2024_4467_json_prefix_rejected(self):
        """File with json:{} content is rejected as unknown format."""
        image = self.get_adversarial_image('cve-2024-4467-json-prefix')
        stdout, stderr, rc = self.run_imago_info(image.path)
        # Should be detected as unknown (no valid format magic or partition table)
        self.assertEqual(rc, 0, f'imago info failed: {stderr}')
        self.assertIn('unknown', stdout.lower(), f'Expected unknown format for json: content: {stdout}')

    def test_cve_2024_4467_no_shadow_content(self):
        """File with json:{} referencing /etc/shadow does not leak content."""
        image = self.get_adversarial_image('cve-2024-4467-json-prefix')
        stdout, stderr, rc = self.run_imago_info(image.path)
        combined = (stdout + stderr).lower()
        for forbidden in ['root:', 'daemon:', 'bin:']:
            self.assertNotIn(forbidden, combined, f'/etc/shadow content leaked via json: {forbidden}')

    def test_cve_2024_4467_cli_treats_json_as_filename(self):
        """imago CLI does not interpret json:{} as a block device spec.

        This tests that passing a literal 'json:{...}' string as an argument
        is treated as a filename, not parsed as a block driver specification.
        """
        imago = self.get_imago_binary()
        json_arg = 'json:{"driver":"raw","file":{"driver":"file","filename":"/etc/shadow"}}'
        result = subprocess.run(
            [str(imago), 'info', json_arg],
            capture_output=True, text=True, timeout=10
        )
        # Should fail because the file doesn't exist (treated as literal path)
        combined = (result.stdout + result.stderr).lower()
        self.assertNotIn('root:', combined, 'json: argument was interpreted as block driver!')
        self.assertNotIn('daemon:', combined, 'json: argument was interpreted as block driver!')
