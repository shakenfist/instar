"""
Security-focused tests for instar.

These tests verify that instar correctly detects and reports security-relevant
features in disk images (backing files, external data files, etc.) without
being exploited by them. The TestCVEReproduction class specifically validates
that known qemu-img CVEs are mitigated by instar's architecture.
"""

import json
import subprocess
import tempfile
import time

import testtools

from base import InstarTestBase

# Markers that indicate /etc/passwd or /etc/shadow content has leaked.
# Used by assert_no_sensitive_content() across multiple test classes.
_SENSITIVE_MARKERS = ['root:', 'daemon:', 'bin:']


class TestSecurityFeatureDetection(InstarTestBase):
    """Tests for security feature detection."""

    def test_instar_reports_backing_file_without_reading_content(self):
        """
        Verify instar reports backing file path without leaking file contents.

        A QCOW2 with a backing file pointing to a text file should:
        1. Report the backing file reference in output
        2. NOT include any content from the backing file
        3. NOT require the backing file to be a valid disk image
        """
        image = self.get_image('qcow2-backing-textfile')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar info on the QCOW2
        stdout, stderr, rc = self.run_instar_info(image.path)

        # Should succeed - the overlay QCOW2 itself is valid
        self.assertEqual(
            0, rc,
            f'instar should process QCOW2 overlay successfully: {stderr}'
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

    def test_instar_reports_backing_file_to_etc_passwd(self):
        """
        Verify instar reports backing file reference to /etc/passwd.

        This simulates CVE-2015-5163 where an attacker crafts a QCOW2 with
        backing_file=/etc/passwd. instar should:
        1. Report the backing file path
        2. NOT read or leak /etc/passwd contents
        """
        image = self.get_image('qcow2-backing-etc-passwd')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar info on the QCOW2
        stdout, stderr, rc = self.run_instar_info(image.path)

        # Should succeed - the overlay QCOW2 itself is valid
        self.assertEqual(
            0, rc,
            f'instar should process QCOW2 overlay successfully: {stderr}'
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

    def test_instar_reports_external_data_file_without_reading_content(self):
        """
        Verify instar reports external data file path without reading its content.

        QCOW2 v3 supports external data files (CVE-2024-32498) which could
        reference sensitive system files. The info operation should report
        the path from the DATA header extension without opening or reading
        the data file itself.
        """
        image = self.get_image('qcow2-external-data-file')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar info (without --chain, so no file opens)
        stdout, stderr, rc = self.run_instar_info(image.path)

        # Should succeed — the QCOW2 metadata is valid
        self.assertEqual(
            0, rc,
            f'instar should process QCOW2 with external data: {stderr}'
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

    def test_instar_reports_external_data_file_in_json(self):
        """
        Verify instar reports external data file in JSON format-specific data.
        """
        image = self.get_image('qcow2-external-data-file')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_instar_info(
            image.path, output_format='json'
        )

        self.assertEqual(
            0, rc,
            f'instar should process QCOW2 with external data: {stderr}'
        )

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

    def test_instar_handles_vmdk_descriptor_safely(self):
        """
        Verify instar rejects VMDK descriptors with non-FLAT extents.

        VMDK descriptor files can reference arbitrary files as extents
        (e.g. /etc/passwd). Phase 22 added host-side descriptor
        recognition: instar now detects the ``# Disk DescriptorFile``
        prefix and validates the descriptor before launching the guest.
        A descriptor with a SPARSE extent (instead of FLAT) is rejected
        outright — extent paths are never followed.
        """
        image = self.get_image('vmdk-path-traversal')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Descriptor has a SPARSE extent pointing to /etc/passwd.
        # The host-side pre-flight rejects non-FLAT extents, so
        # instar exits with an error without following any paths.
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertNotEqual(
            0, rc,
            'instar should reject VMDK descriptor with non-FLAT extent'
        )

        # No /etc/passwd content should appear in output
        combined = stdout.lower() + stderr.lower()
        self.assertNotIn(
            'root:', combined,
            '/etc/passwd content leaked in output!'
        )

    def test_instar_handles_vmdk_no_extents_safely(self):
        """
        Verify instar rejects VMDK descriptors with no extent declarations.

        A VMDK descriptor with no RW/RDONLY/NOACCESS extent lines is
        invalid. The host-side descriptor pre-flight detects the
        ``# Disk DescriptorFile`` prefix and rejects the file when
        extent parsing fails.
        """
        image = self.get_image('vmdk-no-extents')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertNotEqual(
            0, rc,
            'instar should reject VMDK descriptor with no extents'
        )


class TestBackingChainSecurity(InstarTestBase):
    """Tests for backing chain discovery security.

    These tests verify that instar info --chain correctly handles invalid
    or malicious backing files in the chain.
    """

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

        # Run instar info --chain without --unsafe-quirks
        stdout, stderr, rc = self.run_instar_info(
            image.path, chain=True, unsafe_quirks=False
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

        # Run instar info --chain
        stdout, stderr, rc = self.run_instar_info(image.path, chain=True)

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


class TestRawFormatValidation(InstarTestBase):
    """Tests for RAW format validation (partition table detection).

    These tests verify instar's secure default behavior: files without valid
    format headers OR valid partition tables are rejected as 'unknown' format.
    This prevents arbitrary files (like /etc/passwd) from being accepted as
    disk images, which is the root cause of backing file disclosure attacks.
    """

    def test_rejects_garbage_without_unsafe_quirks(self):
        """
        Verify instar rejects random data without --unsafe-quirks.

        Files without valid format headers and without valid partition tables
        should be rejected as 'unknown' format in secure mode.
        """
        image = self.get_image('raw-random-garbage')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Without --unsafe-quirks, should fail to detect format
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            unsafe_quirks=False
        )

        # Should report as unknown format (not 'raw')
        # The exact error message may vary, but it should indicate rejection
        self.assertIn(
            'unknown',
            stdout.lower() + stderr.lower(),
            f'Expected instar to reject garbage file, got: {stdout}{stderr}'
        )

    def test_accepts_garbage_with_unsafe_quirks(self):
        """
        Verify instar accepts random data WITH --unsafe-quirks.

        With --unsafe-quirks, instar should match qemu-img behavior and
        accept any file as 'raw' format.
        """
        image = self.get_image('raw-random-garbage')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # With --unsafe-quirks, should accept as raw
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            unsafe_quirks=True
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'instar with --unsafe-quirks should accept garbage file: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected instar to report garbage as raw, got: {stdout}'
        )

    def test_accepts_mbr_partitioned_without_unsafe_quirks(self):
        """
        Verify instar accepts MBR-partitioned raw images without --unsafe-quirks.

        RAW images with valid MBR partition tables should be accepted in
        secure mode because they are recognizably disk images.
        """
        image = self.get_image('raw-mbr-partitioned')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Should succeed without --unsafe-quirks
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            unsafe_quirks=False
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'instar should accept MBR-partitioned image: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected instar to report MBR image as raw, got: {stdout}'
        )

    def test_accepts_gpt_partitioned_without_unsafe_quirks(self):
        """
        Verify instar accepts GPT-partitioned raw images without --unsafe-quirks.

        RAW images with valid GPT partition tables should be accepted in
        secure mode because they are recognizably disk images.
        """
        image = self.get_image('raw-gpt-partitioned')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Should succeed without --unsafe-quirks
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            unsafe_quirks=False
        )

        # Should succeed and report as 'raw'
        self.assertEqual(
            0, rc,
            f'instar should accept GPT-partitioned image: {stderr}'
        )
        self.assertIn(
            'raw',
            stdout.lower(),
            f'Expected instar to report GPT image as raw, got: {stdout}'
        )


class TestCVEReproduction(InstarTestBase):
    """CVE reproduction tests (Phase 4 of security audit).

    Each test uses a purpose-built reproducer image that mimics the attack
    vector from a known qemu-img CVE. Tests verify that instar's mitigations
    (KVM sandbox, host-side path allowlist, bounded buffers, checked
    arithmetic) prevent exploitation.
    """

    def assert_no_sensitive_content(self, output, context=''):
        """Assert that no /etc/passwd or /etc/shadow content appears in output.

        Checks for common markers (root:, daemon:, bin:) that indicate
        sensitive file content has leaked into command output.

        Args:
            output: Combined stdout+stderr string to check
            context: Optional context string for the error message
        """
        combined = output.lower()
        prefix = f'{context}: ' if context else ''
        for marker in _SENSITIVE_MARKERS:
            self.assertNotIn(
                marker, combined,
                f'{prefix}Sensitive file content leaked: {marker}'
            )

    # ----------------------------------------------------------------
    # CVE-2024-32498: QCOW2 external data file path traversal
    # ----------------------------------------------------------------

    def test_cve_2024_32498_info_reports_data_file_path(self):
        """External data file path is reported without opening the file."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_instar_info(image.path, output_format='json')
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')

        data = json.loads(stdout)
        fmt_data = data.get('format-specific', {}).get('data', {})
        self.assertEqual(
            fmt_data.get('data-file'), '/etc/passwd',
            f'Expected data-file=/etc/passwd: {fmt_data}'
        )

    def test_cve_2024_32498_no_passwd_content_leaked(self):
        """No /etc/passwd content appears in info output."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')
        self.assert_no_sensitive_content(stdout + stderr, 'CVE-2024-32498 info')

    def test_cve_2024_32498_chain_rejects_external_data_file(self):
        """Chain mode rejects external data file outside allowlist."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        stdout, stderr, rc = self.run_instar_info(image.path, chain=True)
        self.assertNotEqual(
            rc, 0,
            f'Chain should reject /etc/passwd as external data file: {stdout}'
        )

    def test_cve_2024_32498_convert_rejects_external_data_file(self):
        """Convert rejects image with external data file pointing to host path."""
        image = self.get_adversarial_image('cve-2024-32498-extdata-etc-passwd')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_convert(image.path, out.name)
            self.assertNotEqual(
                rc, 0,
                f'Convert should reject external data file: {stdout}'
            )
            with open(out.name, 'rb') as f:
                out_data = f.read(1024)
            self.assertNotIn(
                b'root:', out_data,
                '/etc/passwd content in converted output!'
            )

    # ----------------------------------------------------------------
    # CVE-2015-5163: Backing file path traversal
    # ----------------------------------------------------------------

    def test_cve_2015_5163_dotdot_info_reports_path(self):
        """Info reports the ../../../etc/passwd backing path without reading it."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')
        self.assertIn(
            'etc/passwd', stdout,
            f'Expected backing file path in output: {stdout}'
        )
        self.assert_no_sensitive_content(stdout + stderr, 'CVE-2015-5163 dotdot info')

    def test_cve_2015_5163_dotdot_chain_rejects(self):
        """Chain mode rejects ../ traversal backing path."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        _stdout, _stderr, rc = self.run_instar_info(image.path, chain=True)
        self.assertNotEqual(rc, 0, f'Chain should reject traversal path: {_stdout}')

    def test_cve_2015_5163_dotdot_convert_rejects(self):
        """Convert rejects image with ../ traversal backing path."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-dotdot')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_instar_convert(image.path, out.name)
            self.assertNotEqual(
                rc, 0,
                f'Convert should reject traversal backing path: {_stdout}'
            )

    def test_cve_2015_5163_null_byte_info(self):
        """Backing file path with embedded null byte is handled safely."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-null')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')
        self.assert_no_sensitive_content(
            stdout + stderr, 'CVE-2015-5163 null byte info'
        )

    def test_cve_2015_5163_null_byte_chain_rejects(self):
        """Chain mode rejects backing path with embedded null byte."""
        image = self.get_adversarial_image('cve-2015-5163-traversal-null')
        _stdout, _stderr, rc = self.run_instar_info(image.path, chain=True)
        self.assertNotEqual(rc, 0, f'Chain should reject null-byte path: {_stdout}')

    # ----------------------------------------------------------------
    # CVE-2022-47951: VMDK descriptor with host file extent paths
    # ----------------------------------------------------------------

    def test_cve_2022_47951_info_no_shadow_content(self):
        """VMDK descriptor with /etc/shadow extent does not leak file content.

        The descriptor references /etc/shadow as a FLAT extent. The
        host-side pre-flight rejects the extent path via the backing
        allowlist, so instar exits with an error. The key security
        property is that no /etc/shadow content appears in the output.
        """
        image = self.get_adversarial_image('cve-2022-47951-vmdk-hostile-extent')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertNotEqual(
            rc, 0,
            'instar should reject VMDK descriptor with '
            '/etc/shadow extent (allowlist violation)'
        )
        self.assert_no_sensitive_content(
            stdout + stderr, 'CVE-2022-47951 info'
        )

    def test_cve_2022_47951_convert_no_shadow_content(self):
        """Converting VMDK with hostile extent does not produce /etc/shadow data."""
        image = self.get_adversarial_image('cve-2022-47951-vmdk-hostile-extent')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _ = self.run_instar_convert(image.path, out.name)
            with open(out.name, 'rb') as f:
                out_data = f.read(4096)
            for forbidden in [b'root:', b'daemon:', b'bin:']:
                self.assertNotIn(
                    forbidden, out_data,
                    f'/etc/shadow in converted output: {forbidden}'
                )

    # ----------------------------------------------------------------
    # CVE-2015-5162: Resource exhaustion via tiny petabyte image
    # ----------------------------------------------------------------

    def test_cve_2015_5162_info_completes_quickly(self):
        """Info on a tiny image claiming 1 PB completes within 5 seconds."""
        image = self.get_adversarial_image('cve-2015-5162-tiny-petabyte')
        start = time.monotonic()
        stdout, stderr, rc = self.run_instar_info(image.path)
        elapsed = time.monotonic() - start
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')
        self.assertLess(
            elapsed, 5.0,
            f'Info took {elapsed:.1f}s on petabyte image (expected <5s)'
        )

    def test_cve_2015_5162_check_completes_quickly(self):
        """Check on a tiny image claiming 1 PB completes within 10 seconds."""
        image = self.get_adversarial_image('cve-2015-5162-tiny-petabyte')
        start = time.monotonic()
        self.run_instar_check(image.path)
        elapsed = time.monotonic() - start
        self.assertLess(
            elapsed, 10.0,
            f'Check took {elapsed:.1f}s on petabyte image (expected <10s)'
        )

    # ----------------------------------------------------------------
    # CVE-2014-0223: Integer overflow in L1 table size
    # ----------------------------------------------------------------

    def test_cve_2014_0223_info_no_crash(self):
        """Info on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_cve_2014_0223_check_no_crash(self):
        """Check on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_cve_2014_0223_convert_no_crash(self):
        """Convert on image with L1 overflow boundary does not crash."""
        image = self.get_adversarial_image('cve-2014-0223-l1-overflow-boundary')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    # ----------------------------------------------------------------
    # CVE-2024-4467: json:{} block device specification
    # ----------------------------------------------------------------

    def test_cve_2024_4467_json_prefix_rejected(self):
        """File with json:{} content is rejected as unknown format."""
        image = self.get_adversarial_image('cve-2024-4467-json-prefix')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assertEqual(rc, 0, f'instar info failed: {stderr}')
        self.assertIn(
            'unknown', stdout.lower(),
            f'Expected unknown format for json: content: {stdout}'
        )

    def test_cve_2024_4467_no_shadow_content(self):
        """File with json:{} referencing /etc/shadow does not leak content."""
        image = self.get_adversarial_image('cve-2024-4467-json-prefix')
        stdout, stderr, rc = self.run_instar_info(image.path)
        self.assert_no_sensitive_content(
            stdout + stderr, 'CVE-2024-4467 info'
        )

    def test_cve_2024_4467_cli_treats_json_as_filename(self):
        """instar CLI does not interpret json:{} as a block device spec.

        This tests that passing a literal 'json:{...}' string as an argument
        is treated as a filename, not parsed as a block driver specification.
        """
        instar = self.get_instar_binary()
        json_arg = (
            'json:{"driver":"raw","file":'
            '{"driver":"file","filename":"/etc/shadow"}}'
        )
        result = subprocess.run(
            [str(instar), 'info', json_arg],
            capture_output=True, text=True, timeout=10
        )
        # Should fail because the file doesn't exist (treated as literal path)
        self.assert_no_sensitive_content(
            result.stdout + result.stderr,
            'CVE-2024-4467 json: CLI argument'
        )
