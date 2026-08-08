"""
Tests for qemu-img version detection in instar.

These tests verify that instar correctly detects the installed qemu-img version
and selects the appropriate output profile. This is separate from output profile
tests which verify that specific --qemu-version values produce correct output.

Note: These tests require qemu-img to be installed.
"""

import re
import subprocess

import testtools

from base import InstarTestBase, parse_qemu_version


class TestVersionDetection(InstarTestBase):
    """Tests for qemu-img version detection."""

    def test_detects_qemu_version(self):
        """
        Verify instar detects the same qemu-img version as we detect in Python.

        This test compares:
        1. The version we detect by running qemu-img --version
        2. The version instar reports when run with --verbose
        """
        if self._qemu_version is None:
            self.skipTest('qemu-img not installed')

        # Get a test image
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar with verbose output to see version detection
        instar = self.get_instar_binary()
        result = subprocess.run(
            [str(instar), '--verbose', 'info', str(image.path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Look for version detection message in stderr
        # Example: "Detected qemu-img version 7.2, using matching output profile"
        match = re.search(
            r'Detected qemu-img version (\d+)\.(\d+)',
            result.stderr
        )

        if match:
            detected_major = int(match.group(1))
            detected_minor = int(match.group(2))

            expected_major, expected_minor, _ = self._qemu_version

            self.assertEqual(
                (detected_major, detected_minor),
                (expected_major, expected_minor),
                f'instar detected version {detected_major}.{detected_minor} '
                f'but expected {expected_major}.{expected_minor}'
            )
        else:
            # If no detection message, instar might have failed or qemu-img
            # not found - check that it still ran successfully
            self.assertEqual(
                0, result.returncode,
                f'instar failed: {result.stderr}'
            )

    def test_profile_selection_matches_version(self):
        """
        Verify instar selects the correct profile for the detected version.

        qemu-img 6.0 - 7.x should use profile-6-0-0 (no Child node)
        qemu-img 8.0+ should use profile-8-0-0 (with Child node)
        """
        if self._qemu_version is None:
            self.skipTest('qemu-img not installed')

        # Get a test image
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run instar without --qemu-version to use auto-detection
        stdout, stderr, rc = self.run_instar_info(image.path)

        self.assertEqual(0, rc, f'instar failed: {stderr}')

        # Check for Child node section based on detected version
        major, minor, _ = self._qemu_version
        has_child_node = "Child node '/file':" in stdout

        if major >= 8:
            self.assertTrue(
                has_child_node,
                f'qemu-img {major}.{minor} should produce output with '
                f'Child node section, but it was missing'
            )
        else:
            self.assertFalse(
                has_child_node,
                f'qemu-img {major}.{minor} should produce output without '
                f'Child node section, but it was present'
            )

    def test_explicit_version_overrides_detection(self):
        """
        Verify --qemu-version flag overrides auto-detection.

        Even if qemu-img 8.0+ is installed, specifying --qemu-version 7.2
        should produce output without Child node section.
        """
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        # Run with --qemu-version 7.2 (profile-6-0-0)
        stdout_v7, stderr_v7, rc_v7 = self.run_instar_info(
            image.path, qemu_version='7.2'
        )
        self.assertEqual(0, rc_v7, f'instar failed for v7.2: {stderr_v7}')

        # Run with --qemu-version 8.0 (profile-8-0-0)
        stdout_v8, stderr_v8, rc_v8 = self.run_instar_info(
            image.path, qemu_version='8.0'
        )
        self.assertEqual(0, rc_v8, f'instar failed for v8.0: {stderr_v8}')

        # Verify difference
        v7_has_child = "Child node '/file':" in stdout_v7
        v8_has_child = "Child node '/file':" in stdout_v8

        self.assertFalse(
            v7_has_child,
            '--qemu-version 7.2 should not produce Child node section'
        )
        self.assertTrue(
            v8_has_child,
            '--qemu-version 8.0 should produce Child node section'
        )

    def test_invalid_version_string_rejected(self):
        """
        Verify instar rejects invalid --qemu-version values.
        """
        image = self.get_image('cirros-qcow2')
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')

        instar = self.get_instar_binary()

        # Test various invalid version strings
        invalid_versions = ['abc', '', '1.2.3.4', 'not.a.version']

        for invalid in invalid_versions:
            if not invalid:
                # Skip empty string as it may cause arg parsing issues
                continue

            result = subprocess.run(
                [str(instar), 'info', '--qemu-version', invalid, str(image.path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            self.assertNotEqual(
                0, result.returncode,
                f'Expected instar to reject invalid version "{invalid}"'
            )


# The exact `qemu-img --version` strings the CI matrix distros ship,
# captured empirically by tools/probe-qemu-versions.sh (phase-2 step 2a).
# These pin the parser against the real distro suffix and Debian epoch
# forms so a regression that fell back to the newest profile (silently
# wrong output on an older-qemu distro) fails here.
REAL_QEMU_VERSION_STRINGS = [
    ('qemu-img version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)', (7, 2, 22)),
    ('qemu-img version 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1)', (10, 0, 11)),
    ('qemu-img version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.31)', (6, 2, 0)),
    ('qemu-img version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)', (8, 2, 2)),
    ('qemu-img version 10.2.2 (qemu-10.2.2-1.fc44)', (10, 2, 2)),
    ('qemu-img version 10.1.0 (qemu-kvm-10.1.0-17.el9_8.5)', (10, 1, 0)),
    ('qemu-img version 10.1.0 (qemu-kvm-10.1.0-16.el10_2.2)', (10, 1, 0)),
]


class TestQemuVersionParsing(testtools.TestCase):
    """Pure unit tests for parse_qemu_version (no qemu-img/KVM needed)."""

    def test_parses_real_distro_version_strings(self):
        for text, expected in REAL_QEMU_VERSION_STRINGS:
            self.assertEqual(parse_qemu_version(text), expected, text)

    def test_ignores_debian_epoch_in_parenthetical(self):
        # The epoch '1:7.2' inside the parenthetical must not win over
        # the leading 7.2.22 token.
        self.assertEqual(
            parse_qemu_version(
                'qemu-img version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)'),
            (7, 2, 22))

    def test_patch_defaults_to_zero_when_absent(self):
        self.assertEqual(parse_qemu_version('qemu-img version 8.2'), (8, 2, 0))

    def test_returns_none_when_absent(self):
        self.assertIsNone(parse_qemu_version('qemu-img: command not found'))
        self.assertIsNone(parse_qemu_version(''))


class TestVersionMatchSelection(testtools.TestCase):
    """Pure unit tests for InstarTestBase._select_version_match, the
    full-version profile/baseline selector that replaced the buggy
    first-`{major}.{minor}.`-prefix match."""

    # The profile-transition structure around the 7.2.19 boundary that
    # the prefix match got wrong.
    SEVEN_TWO = ['7.2.0', '7.2.18', '7.2.19', '7.2.22']

    def sel(self, candidates, detected):
        return InstarTestBase._select_version_match(candidates, detected)

    def test_exact_match(self):
        self.assertEqual(self.sel(self.SEVEN_TWO, (7, 2, 19)), '7.2.19')

    def test_debian12_7_2_22_selects_post_transition(self):
        # The regression guard: a prefix match returned '7.2.0'
        # (profile-6-1-0) for every 7.2.x; Debian 12 ships 7.2.22.
        self.assertEqual(self.sel(self.SEVEN_TWO, (7, 2, 22)), '7.2.22')

    def test_pre_transition_patch(self):
        self.assertEqual(self.sel(self.SEVEN_TWO, (7, 2, 5)), '7.2.0')
        self.assertEqual(self.sel(self.SEVEN_TWO, (7, 2, 18)), '7.2.18')

    def test_unenumerated_patch_picks_highest_below(self):
        # Debian 13 (10.0.11) and Fedora (10.2.2) ship patch levels the
        # baseline map doesn't enumerate.
        self.assertEqual(self.sel(['10.0.0', '10.0.7'], (10, 0, 11)), '10.0.7')
        self.assertEqual(self.sel(['10.2.0'], (10, 2, 2)), '10.2.0')

    def test_minor_scoping(self):
        cands = ['8.0.0', '8.1.0', '8.2.0']
        self.assertEqual(self.sel(cands, (8, 1, 3)), '8.1.0')
        self.assertEqual(self.sel(cands, (8, 2, 2)), '8.2.0')

    def test_none_detected_picks_highest(self):
        # Mirrors instar's OutputProfile::newest() fallback.
        self.assertEqual(self.sel(self.SEVEN_TWO, None), '7.2.22')

    def test_older_than_all_picks_lowest(self):
        self.assertEqual(self.sel(['6.1.0', '6.2.0'], (6, 0, 0)), '6.1.0')

    def test_empty_candidates(self):
        self.assertIsNone(self.sel([], (7, 2, 0)))


class TestProfileSelectionMatrix(InstarTestBase):
    """Guard get_profile_for_installed_qemu against the real testdata
    version map for every distro qemu version in the CI matrix
    (docs/plans/PLAN-distro-matrix-ci-phase-02-qemu-profiles.md 2a)."""

    # (version string, expected info profile) per matrix distro.
    MATRIX = [
        ('7.2.22', 'profile-7-2-19'),   # Debian 12 (bug: was profile-6-1-0)
        ('10.0.11', 'profile-10-0-0'),  # Debian 13
        ('6.2.0', 'profile-6-1-0'),     # Ubuntu 22.04
        ('8.2.2', 'profile-8-0-0'),     # Ubuntu 24.04
        ('10.2.2', 'profile-10-2-0'),   # Fedora latest
        ('10.1.0', 'profile-10-0-0'),   # Rocky 9 / Rocky 10
    ]

    def test_matrix_versions_select_expected_info_profile(self):
        for vstr, expected in self.MATRIX:
            # Shadow the class-level detected version for this iteration.
            self._qemu_version = parse_qemu_version(
                f'qemu-img version {vstr}')
            for output_type in ('human', 'json'):
                got = self.get_profile_for_installed_qemu(
                    output_type=output_type, command='info')
                self.assertEqual(
                    got, expected,
                    f'{vstr} ({output_type}) selected {got}, '
                    f'expected {expected}')
