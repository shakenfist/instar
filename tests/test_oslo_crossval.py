"""
Cross-validation tests: instar vs oslo.utils format_inspector.

oslo.utils is the safety gate for image uploads in OpenStack
(Glance, Nova, Cinder). These tests verify that instar's format
detection and safety reporting agree with oslo.utils, documenting
any intentional divergences.

Tests are skipped automatically if oslo.utils is not installed.
"""

import json

import testscenarios

from base import InstarTestBase
from helpers import load_manifest_images

try:
    from oslo_utils.imageutils import format_inspector
    HAS_OSLO = True
except ImportError:
    HAS_OSLO = False


# Images oslo.utils cannot detect or would error on.
# Excluded from all cross-validation tests.
OSLO_SKIP_IMAGES = {
    # Raw images without partition tables (oslo returns None)
    'raw-fat-no-partition',
    'raw-sparse-empty',
    'raw-zeros-1mb',
    'security-fake-passwd',
    # Malformed raw images
    'raw-mbr-truncated',
    'raw-gpt-truncated',
    'raw-mbr-corrupted',
    'raw-random-garbage',
    'raw-misleading-header',
    'raw-minimal-1byte',
    'raw-qcow2-magic-wrong-offset',
    # Corrupt format-specific images
    'vmdk-corrupt-version',
    'vmdk-corrupt-descriptor',
    'vhdx-corrupt-region',
    'vhd-corrupt-disktype',
    # AFL-discovered malformed images
    'afl-vhd-max-table-entries',
    'afl-vmdk-l1-too-big',
    # Script-generated check validation images
    'check-qcow2-clean',
    'check-qcow2-overlapping',
    'check-qcow2-refcount-zero',
    'check-qcow2-leaked',
    # Malformed VMDK descriptors
    'vmdk-no-extents',
    'vmdk-path-traversal',
    # Flat descriptors — oslo.utils cannot parse descriptor text
    'vmdk-multi-flat',
    'vmdk-flat-parent',
    # Adversarial images — deliberately malformed, not suitable for
    # cross-validation against oslo.utils format_inspector
    'qcow2-compression-bomb-zlib',
    'qcow2-compression-bomb-zstd',
    'qcow2-circular-2',
    'qcow2-circular-3',
    'qcow2-self-referencing',
    'qcow2-chain-depth-16',
    'qcow2-chain-depth-17',
    'qcow2-l1-overflow',
    'qcow2-l1-zero',
    'qcow2-cluster-bits-low',
    'qcow2-cluster-bits-high',
    'qcow2-refcount-order-7',
    'qcow2-refcount-order-255',
    'qcow2-vsize-petabyte',
    'qcow2-vsize-max',
    'vmdk-grain-size-zero',
    'vmdk-grain-size-huge',
    'vhdx-conflicting-headers',
    'vhd-bat-beyond-eof',
    'vhdx-bat-beyond-eof',
    'polyglot-qcow2-vmdk',
    'polyglot-qcow2-elf',
    'qcow2-truncated-header-v2',
    'vmdk-truncated-after-magic',
    'vhd-truncated-footer',
    'vmdk-descriptor-null-bytes',
    'vmdk-descriptor-multi-extent',
    'vmdk-descriptor-huge',
    # CVE reproducer images — deliberately malicious, not suitable
    # for cross-validation against oslo.utils format_inspector
    'cve-2024-32498-extdata-etc-passwd',
    'cve-2015-5163-traversal-dotdot',
    'cve-2015-5163-traversal-null',
    'cve-2022-47951-vmdk-hostile-extent',
    'cve-2015-5162-tiny-petabyte',
    'cve-2014-0223-l1-overflow-boundary',
    'cve-2024-4467-json-prefix',
    # Malformed DMG koly-trailer fixtures (format-coverage phase 1).
    # safety: "malformed", run_in_ci: true, so (unlike the run_in_ci:
    # false raw-*-truncated entries above) they are not filtered out
    # by _generate_scenarios and need an explicit skip here, matching
    # the precedent set by the malicious/malformed VMDK, VHD, and
    # qcow2 fixtures just above: deliberately broken container
    # metadata is not suitable for cross-validation against oslo's
    # format_inspector.
    'dmg-truncated-koly',
    'dmg-sectorcount-negative',
    'dmg-sectorcount-huge',
    'dmg-no-chunk-table',
    # Malformed VDI header fixtures (format-coverage phase 2). Like the
    # malformed DMG fixtures above they are safety: "malformed",
    # run_in_ci: true, so they are enrolled by _generate_scenarios and
    # need an explicit skip. oslo.utils' VDIInspector only reads the
    # signature (0x40) and disk_size (0x170); it does not validate the
    # version, block-map offset, block size, parent UUID, or block count,
    # so it detects all five as safe 'vdi' with a plausible virtual size.
    # qemu (and instar after graduation) refuse every one of them at open,
    # so cross-validating oslo's blind acceptance against instar's refusal
    # is not meaningful.
    'vdi-bad-version',
    'vdi-unaligned-bmap',
    'vdi-wrong-blocksize',
    'vdi-nonnull-parent',
    'vdi-too-many-blocks',
    # Malformed Parallels header fixtures (format-coverage phase 3,
    # PLAN-format-coverage-phase-03-parallels-read.md). Like the malformed
    # VDI/DMG fixtures above they are safety: "malformed", run_in_ci: true, so
    # they are enrolled by _generate_scenarios and need an explicit skip.
    # oslo.utils ships no Parallels inspector, so it falls back to
    # RawFileInspector (format_match unconditionally True) and reports every
    # one as a safely-openable 'raw' image, while qemu (and instar after
    # graduation) refuse each at open (zero tracks, too-big cluster, catalog
    # too large, bad format-extension magic). Cross-validating oslo's blind
    # acceptance against instar's refusal is not meaningful.
    'parallels-zero-tracks',
    'parallels-huge-tracks',
    'parallels-huge-catalog',
    'parallels-ext-bad-magic',
}

# Format name mapping: instar -> oslo.utils.
# Most formats use the same name; only divergences listed.
INSTAR_TO_OSLO_FORMAT = {
    'vpc': 'vhd',
}

# Images where format detection intentionally diverges.
# Maps image_id -> (instar_format, oslo_format).
KNOWN_FORMAT_DIVERGENCES = {
    # oslo.utils GPTInspector detects both MBR and GPT
    # partitioned raw images as 'gpt'. instar reports 'raw'
    # (matching qemu-img behaviour).
    'raw-mbr-partitioned': ('raw', 'gpt'),
    'raw-gpt-partitioned': ('raw', 'gpt'),
    # vmdk-multi-partition is detected as 'raw' by instar
    # and 'gpt' by oslo (the file appears to be a raw disk
    # with GPT partitions despite the .vmdk extension).
    'vmdk-multi-partition': ('raw', 'gpt'),
    # instar reports ISO as 'raw' (with --unsafe-quirks);
    # oslo detects as 'iso'.
    'iso-simple': ('raw', 'iso'),
    # instar reports LUKS as 'unknown'; oslo detects
    # as 'luks'.
    'luks-v1': ('unknown', 'luks'),
    'luks-v2': ('unknown', 'luks'),
    'luks-v1-raw-gpt': ('unknown', 'luks'),
    'luks-v1-qcow2': ('unknown', 'luks'),
    'luks-v2-raw-gpt': ('unknown', 'luks'),
    # Format-coverage phase 1: oslo.utils' format_inspector ships no
    # Parallels, Bochs, cloop, or DMG inspector. detect_file_format()
    # still returns a real inspector (not None) for these — it falls
    # back to RawFileInspector, whose `format_match` is unconditionally
    # True, so oslo reports 'raw' for all four. instar has dedicated
    # content/trailer probes for all four (see
    # src/shared/src/format_detection.rs) and reports the real format.
    'parallels-v1': ('parallels', 'raw'),
    'parallels-v2': ('parallels', 'raw'),
    # Format-coverage phase 3 (PLAN-format-coverage-phase-03-parallels-read.md):
    # the five new safe Parallels fixtures detect the same way as the two
    # existing parallels-v1/v2 images -- oslo has no Parallels inspector and
    # falls back to RawFileInspector ('raw'), while instar reports 'parallels'.
    'parallels-data-v2': ('parallels', 'raw'),
    'parallels-data-v1': ('parallels', 'raw'),
    'parallels-inuse': ('parallels', 'raw'),
    'parallels-bat-past-eof': ('parallels', 'raw'),
    'parallels-cluster-4k': ('parallels', 'raw'),
    'bochs-growing': ('bochs', 'raw'),
    'cloop-simple': ('cloop', 'raw'),
    'dmg-simple': ('dmg', 'raw'),
}

# Known safety divergences: images where instar does not
# expose certain safety-relevant fields in JSON output
# (handled via KVM sandbox instead).
KNOWN_SAFETY_DIVERGENCES = {
    # No remaining divergences: instar now reports
    # the data-file path in JSON output (Phase 13).
}

# Formats where virtual size is not comparable between
# tools. QED is included because oslo.utils bans QED and
# may not parse its virtual size correctly.
VSIZE_SKIP_FORMATS = {'iso', 'luks', 'qed'}

# Images where instar and oslo.utils are known to report
# different virtual sizes by design. Maps image_id to
# (expected_oslo_vsize, expected_instar_vsize). The test
# asserts both tools still report these exact values, so
# that any future convergence (e.g. oslo learning to read
# VMDK descriptor extents) fails loudly and forces us to
# re-evaluate the special case instead of silently skipping.
#
# VMDK monolithicFlat: the descriptor carries the extent's
# sector count, and instar honours it. oslo.utils' VMDK
# inspector parses only the binary sparse header and
# reports virtual_size=0 for plain descriptor files.
KNOWN_VSIZE_DIVERGENCES = {
    'vmdk-flat-1m': (0, 1 * 1024 * 1024),
    'vmdk-flat-10m': (0, 10 * 1024 * 1024),
    'vmdk-flat-with-parent': (0, 1 * 1024 * 1024),
    # Format-coverage phase 1, paired with the KNOWN_FORMAT_DIVERGENCES
    # entries above. RawFileInspector.virtual_size returns however many
    # bytes oslo's detection loop consumed before it settled on 'raw',
    # not necessarily the full file length: for bochs-growing (2560 B),
    # cloop-simple (1690 B), and dmg-simple (11747 B) that happens to
    # equal the exact file size (the whole file fits in oslo's first
    # read chunk); for parallels-v1/v2 (327680 B on disk) oslo stops
    # after consuming only 262144 B. instar reports the real virtual
    # disk size parsed from each format's own header/trailer. Values
    # below were captured from a live run against oslo.utils 10.1.2.dev8
    # (git master, matching .github/workflows/functional-tests.yml's
    # `pip install ... git+https://github.com/openstack/oslo.utils.git`)
    # and instar's `info --output json` on the exact staged fixtures.
    #
    # NOTE: because 'parallels-v1'/'parallels-v2'/'bochs-growing'/
    # 'cloop-simple'/'dmg-simple' are also KNOWN_FORMAT_DIVERGENCES
    # entries, TestOsloVirtualSize.test_virtual_size_agrees skips them
    # before ever reaching this dict (see its `if self.image_id in
    # KNOWN_FORMAT_DIVERGENCES: self.skipTest(...)` guard) — identical
    # to the pre-existing raw-mbr-partitioned/raw-gpt-partitioned/
    # vmdk-multi-partition entries, none of which has a paired
    # KNOWN_VSIZE_DIVERGENCES entry either. These five are recorded
    # here anyway as a documented, verified reference of the actual
    # numbers rather than being asserted at runtime.
    'parallels-v1': (262144, 2 * 1024 * 1024),
    'parallels-v2': (262144, 2 * 1024 * 1024),
    # Format-coverage phase 3 (PLAN-format-coverage-phase-03-parallels-read.md):
    # the five new safe Parallels fixtures follow the same oslo rule as
    # parallels-v1/v2 -- RawFileInspector.virtual_size is min(file_size,
    # 262144), i.e. however many bytes oslo's detection loop consumed before
    # settling on 'raw' (capped at its first 262144 B read chunk), while instar
    # reports the real virtual size parsed from the Parallels header
    # (nb_sectors * 512). The four 327680 B images stop oslo at the 262144 B
    # cap; parallels-cluster-4k (20480 B on disk) fits entirely in the first
    # read chunk, so oslo returns its whole 20480 B file length. Because these
    # five are also KNOWN_FORMAT_DIVERGENCES entries, TestOsloVirtualSize skips
    # them before reaching this dict, so (like parallels-v1/v2 above) the pairs
    # are a documented, verified reference rather than a runtime assertion.
    # Values captured from a live oslo.utils run against the staged fixtures.
    'parallels-data-v2': (262144, 2 * 1024 * 1024),
    'parallels-data-v1': (262144, 2 * 1024 * 1024),
    'parallels-inuse': (262144, 2 * 1024 * 1024),
    'parallels-bat-past-eof': (262144, 2 * 1024 * 1024),
    'parallels-cluster-4k': (20480, 256 * 1024),
    'bochs-growing': (2560, 1032192),
    'cloop-simple': (1690, 1024 * 1024),
    'dmg-simple': (11747, 4 * 1024 * 1024),
    # Format-coverage phase 2 (PLAN-format-coverage-phase-02-vdi-read.md):
    # vdi-odd-size has its VDI header disk_size patched to 1048577, a non-512
    # multiple. oslo.utils' VDIInspector reports the raw disk_size u64 verbatim
    # (1048577), while qemu's vdi_open rounds an odd disk_size up to the next
    # 512 boundary (1049088) and instar mirrors that round-up for byte parity.
    # This entry is asserted at runtime (vdi-odd-size is NOT a
    # KNOWN_FORMAT_DIVERGENCES entry), so both tools must keep reporting these
    # exact values or the test fails and forces a re-evaluation.
    'vdi-odd-size': (1048577, 1049088),
}


def _generate_scenarios(skip_formats=None):
    """Generate test scenarios from manifest.

    Args:
        skip_formats: Optional set of format names to exclude.
    """
    skip_formats = skip_formats or set()
    scenarios = []
    for img in load_manifest_images():
        if not img.get('run_in_ci', True):
            continue
        if img['id'] in OSLO_SKIP_IMAGES:
            continue
        if img['format'] in skip_formats:
            continue
        scenarios.append(
            (img['id'], {'image_id': img['id']})
        )
    return scenarios


class OsloCrossvalMixin:
    """Shared setUp and helpers for oslo crossval tests."""

    def setUp(self):
        super().setUp()
        if not HAS_OSLO:
            self.skipTest('oslo.utils not installed')

    def _get_oslo_inspector(self):
        """Get image and oslo inspector, skipping if unavailable.

        Returns:
            (image, inspector) tuple.
        """
        image = self.get_image(self.image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        inspector = format_inspector.detect_file_format(
            str(image.path)
        )
        if inspector is None:
            self.skipTest(
                f'oslo.utils returned None for '
                f'{self.image_id}'
            )
        return image, inspector


class TestOsloFormatDetection(
    testscenarios.WithScenarios,
    OsloCrossvalMixin,
    InstarTestBase,
):
    """Cross-validate format detection: instar vs oslo.utils."""

    scenarios = _generate_scenarios()

    def test_format_agrees(self):
        """Verify instar and oslo.utils detect the same format."""
        image, inspector = self._get_oslo_inspector()
        oslo_format = inspector.NAME

        # Known divergences: verify oslo side only
        if self.image_id in KNOWN_FORMAT_DIVERGENCES:
            _, expected_oslo = (
                KNOWN_FORMAT_DIVERGENCES[self.image_id]
            )
            self.assertEqual(
                expected_oslo, oslo_format,
                f'{self.image_id}: expected oslo '
                f'{expected_oslo!r}, got {oslo_format!r}'
            )
            return

        # Run instar to get its format detection
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            output_format='json',
            unsafe_quirks=image.requires_unsafe_quirks,
        )
        if rc != 0:
            self.skipTest(
                f'instar failed: {stderr.strip()}'
            )

        instar_data = json.loads(stdout)
        instar_format = instar_data.get('format')

        # Map instar name to oslo convention
        expected_oslo = INSTAR_TO_OSLO_FORMAT.get(
            instar_format, instar_format
        )

        self.assertEqual(
            expected_oslo, oslo_format,
            f'{self.image_id}: instar={instar_format!r} '
            f'(mapped={expected_oslo!r}), '
            f'oslo={oslo_format!r}'
        )


class TestOsloSafetyCheck(
    testscenarios.WithScenarios,
    OsloCrossvalMixin,
    InstarTestBase,
):
    """Cross-validate safety verdicts: instar vs oslo.utils."""

    scenarios = _generate_scenarios()

    def test_safety_agrees(self):
        """Verify safety-relevant metadata agrees."""
        image, inspector = self._get_oslo_inspector()

        oslo_safe = True
        oslo_failures = {}
        try:
            inspector.safety_check()
        except format_inspector.SafetyCheckFailed as e:
            oslo_safe = False
            oslo_failures = e.failures
        except format_inspector.ImageFormatError:
            # Incomplete or unparseable file (e.g., LUKS
            # header stubs). Treat as rejection.
            oslo_safe = False

        # Known divergence: QED is always banned by oslo.utils
        # but instar detects without rejecting (KVM sandbox
        # makes it safe to inspect).
        if image.format == 'qed':
            self.assertFalse(
                oslo_safe,
                f'Expected oslo to reject QED: '
                f'{self.image_id}'
            )
            return

        # Known divergence: oslo.utils rejects LUKS v2+
        # (only supports v1). instar detects both.
        if image.format == 'luks':
            return

        # Run instar to get metadata
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            output_format='json',
            unsafe_quirks=image.requires_unsafe_quirks,
        )

        # If instar rejects, both tools may agree on rejection
        if rc != 0:
            return

        instar_data = json.loads(stdout)

        # Cross-validate backing file detection
        instar_has_backing = 'backing-filename' in instar_data
        oslo_flags_backing = 'backing_file' in oslo_failures

        if oslo_flags_backing:
            self.assertTrue(
                instar_has_backing,
                f'{self.image_id}: oslo flagged '
                f'backing_file but instar has no '
                f'backing-filename'
            )
        if instar_has_backing:
            self.assertTrue(
                oslo_flags_backing,
                f'{self.image_id}: instar reports '
                f'backing-filename but oslo did not '
                f'flag backing_file '
                f'(oslo_failures={oslo_failures})'
            )

        # Cross-validate external data file detection
        known = KNOWN_SAFETY_DIVERGENCES.get(
            self.image_id, set()
        )
        oslo_flags_data = 'data_file' in oslo_failures
        fmt_data = (
            instar_data
            .get('format-specific', {})
            .get('data', {})
        )
        instar_has_data_file = bool(
            fmt_data.get('data-file')
        )

        if oslo_flags_data and 'data_file' not in known:
            self.assertTrue(
                instar_has_data_file,
                f'{self.image_id}: oslo flagged '
                f'data_file but instar has no '
                f'data-file in format-specific'
            )
        if instar_has_data_file:
            self.assertTrue(
                oslo_flags_data,
                f'{self.image_id}: instar reports '
                f'data-file but oslo did not flag '
                f'data_file '
                f'(oslo_failures={oslo_failures})'
            )


class TestOsloVirtualSize(
    testscenarios.WithScenarios,
    OsloCrossvalMixin,
    InstarTestBase,
):
    """Cross-validate virtual size: instar vs oslo.utils."""

    scenarios = _generate_scenarios(
        skip_formats=VSIZE_SKIP_FORMATS
    )

    def test_virtual_size_agrees(self):
        """Verify virtual size matches between tools."""
        image, inspector = self._get_oslo_inspector()

        # Skip images where format detection diverges —
        # virtual size from different formats is not
        # comparable.
        if self.image_id in KNOWN_FORMAT_DIVERGENCES:
            self.skipTest(
                f'{self.image_id}: format diverges, '
                f'virtual size not comparable'
            )

        oslo_vsize = inspector.virtual_size
        if oslo_vsize is None:
            self.skipTest(
                f'oslo.utils reports no virtual size '
                f'for {self.image_id}'
            )

        # Run instar to get virtual size
        stdout, stderr, rc = self.run_instar_info(
            image.path,
            output_format='json',
            unsafe_quirks=image.requires_unsafe_quirks,
        )
        if rc != 0:
            self.skipTest(
                f'instar failed: {stderr.strip()}'
            )

        instar_data = json.loads(stdout)
        instar_vsize = instar_data.get('virtual-size')
        if instar_vsize is None:
            self.skipTest(
                f'instar reports no virtual-size for '
                f'{self.image_id}'
            )

        # Known divergence: assert both sides still report
        # the expected values so that a future change in
        # either tool fails this test and forces a review.
        if self.image_id in KNOWN_VSIZE_DIVERGENCES:
            exp_oslo, exp_instar = (
                KNOWN_VSIZE_DIVERGENCES[self.image_id]
            )
            self.assertEqual(
                oslo_vsize, exp_oslo,
                f'{self.image_id}: oslo virtual_size '
                f'changed (expected {exp_oslo}, got '
                f'{oslo_vsize}); re-evaluate '
                f'KNOWN_VSIZE_DIVERGENCES entry'
            )
            self.assertEqual(
                instar_vsize, exp_instar,
                f'{self.image_id}: instar virtual-size '
                f'changed (expected {exp_instar}, got '
                f'{instar_vsize}); re-evaluate '
                f'KNOWN_VSIZE_DIVERGENCES entry'
            )
            return

        # VPC/VHD virtual size may differ due to CHS
        # geometry rounding. Allow up to one cylinder
        # (255 * 63 * 512 = 8,225,280 bytes).
        if image.format == 'vpc':
            delta = abs(oslo_vsize - instar_vsize)
            self.assertLessEqual(
                delta, 8225280,
                f'{self.image_id}: virtual size delta '
                f'{delta} > 8225280 (CHS rounding) '
                f'(oslo={oslo_vsize}, '
                f'instar={instar_vsize})'
            )
        # Allow 512-byte delta for raw images due to
        # sector rounding differences between tools
        elif image.format == 'raw':
            delta = abs(oslo_vsize - instar_vsize)
            self.assertLessEqual(
                delta, 512,
                f'{self.image_id}: virtual size delta '
                f'{delta} > 512 bytes '
                f'(oslo={oslo_vsize}, '
                f'instar={instar_vsize})'
            )
        else:
            self.assertEqual(
                oslo_vsize, instar_vsize,
                f'{self.image_id}: '
                f'oslo={oslo_vsize}, '
                f'instar={instar_vsize}'
            )
