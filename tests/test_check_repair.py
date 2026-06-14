"""Integration tests for ``instar check --repair`` (qcow2 repair).

Codifies the behaviour verified by hand during phase 7 of
PLAN-check-repair: the leaks/all tiers repair the check-validation
fixtures to ``qemu-img check``-clean with guest data preserved; the
refuse paths (corrupt-bit / snapshot / compression) leave the image
byte-identical; and the overlapping case is a safe *partial* repair
(the genuine leak is reclaimed, the structural overlap is left
untouched and the image is not made worse).

Every test mutates a **copy** of the committed fixture (the
copy-to-tempdir idiom from ``test_snapshot.py``) so the fixtures stay
corrupt for repeatable runs. The oracles are the post-repair image
*state*:

* ``qemu-img check`` exit status (structural cleanliness),
* known data-pattern reads via ``qemu-io read -P`` (data survived),
* sha256 byte-identity (for the refuse paths).

They deliberately do **not** assert on instar's own repaired-counter
output: those per-counter fields are not yet on the guest->host wire
(PLAN-check-repair phase 6), and instar's own exit code still reflects
the *detected* corruption even after a successful repair (e.g.
refcount-zero exits 2 but is qemu-clean afterward).

The base fixtures carry four known data patterns written by
``create-corrupt-images.py``: 0xAA at 0, 0xBB at 64k, 0xCC at 128k,
0xDD at 192k (64k each).
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# (pattern_byte, offset, length) for the four data clusters every base
# fixture writes. qemu-io 'read -P' verifies the byte pattern.
DATA_PATTERNS = [
    ('0xAA', '0', '64k'),
    ('0xBB', '64k', '64k'),
    ('0xCC', '128k', '64k'),
    ('0xDD', '192k', '64k'),
]


class _RepairTestBase(InstarTestBase):
    """Shared helpers for the repair suite."""

    def setUp(self):
        super().setUp()
        # The repair oracles are qemu's own tools; skip cleanly if the
        # host lacks them rather than failing.
        for tool in ('qemu-img', 'qemu-io'):
            if shutil.which(tool) is None:
                self.skipTest(f'{tool} not available')

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def _make_copy(self, image_id: str) -> Path:
        """Copy a fixture into a per-test tempdir and return the copy.

        The committed fixture is never mutated; repair writes in place
        on the copy. The tempdir is cleaned up at test teardown.
        """
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'fixture not found: {image.path}')
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        copy = Path(td.name) / image.path.name
        shutil.copy2(str(image.path), str(copy))
        return copy

    def _repair_copy(self, image_id: str, repair=None, timeout: int = 60):
        """Copy a fixture, run ``instar check --repair`` on the copy.

        Returns ``(copy, stdout, stderr, rc, sha_before, sha_after)``.
        """
        copy = self._make_copy(image_id)
        sha_before = self._sha256(copy)
        stdout, stderr, rc = self.run_instar_check(
            copy, output_format='json', repair=repair, timeout=timeout
        )
        sha_after = self._sha256(copy)
        return copy, stdout, stderr, rc, sha_before, sha_after

    def _assert_qemu_clean(self, path: Path):
        """Assert ``qemu-img check`` reports no problems (exit 0)."""
        stdout, stderr, rc = self.run_qemu_img_check(path)
        self.assertEqual(
            rc, 0,
            f'qemu-img check should be clean after repair, got rc={rc}\n'
            f'{stdout}\n{stderr}'
        )

    def _qemu_check_json(self, path: Path):
        """Return ``(rc, parsed_json)`` for ``qemu-img check --output=json``."""
        result = subprocess.run(
            ['qemu-img', 'check', '--output=json', str(path)],
            capture_output=True, text=True, timeout=30
        )
        try:
            data = json.loads(result.stdout)
        except (ValueError, json.JSONDecodeError):
            data = {}
        return result.returncode, data

    def _assert_pattern(self, path: Path, pattern: str, offset: str,
                        length: str):
        """Assert ``qemu-io read -P`` confirms a known data pattern."""
        result = subprocess.run(
            ['qemu-io', '-c', f'read -P {pattern} {offset} {length}',
             str(path)],
            capture_output=True, text=True, timeout=30
        )
        self.assertEqual(
            result.returncode, 0,
            f'data pattern {pattern} at {offset} should still read after '
            f'repair:\n{result.stdout}\n{result.stderr}'
        )

    def _assert_all_patterns(self, path: Path):
        for pattern, offset, length in DATA_PATTERNS:
            self._assert_pattern(path, pattern, offset, length)

    @staticmethod
    def _repair_incomplete(stdout: str) -> bool:
        """Read the ``repair-incomplete`` key from instar's JSON output."""
        return bool(json.loads(stdout).get('repair-incomplete'))


class TestRepairLeaksTier(_RepairTestBase):
    """The crash-safe ``--repair=leaks`` tier reclaims genuine leaks."""

    def test_leaked_cluster_reclaimed_clean(self):
        """leaked-cluster + leaks -> qemu-clean, surviving data intact.

        The fixture zeroes L2[0], orphaning the 0xAA@0 data cluster
        (refcount still 1 -> a leak). Reclaiming it frees that cluster,
        so 0xAA@0 reads back as zero afterwards; the other three
        clusters (0xBB/0xCC/0xDD) remain referenced and must still read.
        """
        copy, _stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-leaked', repair='leaks')

        self.assertNotEqual(
            sha_before, sha_after,
            'leaks-tier repair should have modified the image'
        )
        self._assert_qemu_clean(copy)
        # 0xAA@0 was the leaked (now freed) cluster; the rest survive.
        for pattern, offset, length in DATA_PATTERNS[1:]:
            self._assert_pattern(copy, pattern, offset, length)


class TestRepairAllTier(_RepairTestBase):
    """The lossy ``--repair=all`` tier corrects refcounts and COPIED."""

    def test_refcount_zero_raised_clean(self):
        """refcount-zero + all -> qemu-clean, all data intact.

        The referenced 0xAA@0 cluster has refcount 0; the all tier
        raises it to 1. instar still exits 2 (it *detected* the
        corruption) -- the oracle is the post-repair qemu state, not
        instar's exit code.
        """
        copy, _stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-refcount-zero', repair='all')

        self.assertNotEqual(sha_before, sha_after)
        self._assert_qemu_clean(copy)
        self._assert_all_patterns(copy)

    def test_refcount_too_high_lowered_clean(self):
        """refcount-too-high + all -> qemu-clean, all data intact."""
        copy, _stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-refcount-too-high', repair='all')

        self.assertNotEqual(sha_before, sha_after)
        self._assert_qemu_clean(copy)
        self._assert_all_patterns(copy)

    def test_stale_copied_reconciled_clean(self):
        """stale-copied + all -> qemu-clean, all data intact.

        The 0xBB@64k cluster has OFLAG_COPIED set with refcount 2; the
        all tier lowers the refcount and reconciles the COPIED bit.
        """
        copy, _stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-stale-copied', repair='all')

        self.assertNotEqual(sha_before, sha_after)
        self._assert_qemu_clean(copy)
        self._assert_all_patterns(copy)


class TestRepairRefuse(_RepairTestBase):
    """Cases instar must refuse or only partially repair, never corrupt."""

    def test_corrupt_bit_set_refused_identical(self):
        """corrupt-bit-set + all -> byte-identical, repair-incomplete.

        instar reads INCOMPAT_CORRUPT directly and conservatively
        declines to repair; the image must be left exactly as-is.
        """
        _copy, stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-corrupt-bit-set', repair='all')

        self.assertEqual(
            sha_before, sha_after,
            'refused repair must leave the image byte-identical'
        )
        self.assertTrue(
            self._repair_incomplete(stdout),
            'corrupt-bit-set should report repair-incomplete'
        )

    def test_snapshot_leak_refused_identical(self):
        """snapshot-leak + leaks -> byte-identical, snapshot intact.

        instar refuses to repair a snapshotted image (its leak detector
        is blind to snapshot-owned clusters). The image stays
        byte-identical, snapshot s1 survives, and qemu-img check (which
        accounts snapshots correctly) is clean.
        """
        copy, stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-snapshot-leak', repair='leaks')

        self.assertEqual(
            sha_before, sha_after,
            'snapshotted image must be left byte-identical'
        )
        self.assertTrue(self._repair_incomplete(stdout))

        snap_out = subprocess.run(
            ['qemu-img', 'snapshot', '-l', str(copy)],
            capture_output=True, text=True, timeout=30
        ).stdout
        self.assertIn(
            's1', snap_out,
            f'snapshot s1 should still be listed:\n{snap_out}'
        )
        self._assert_qemu_clean(copy)

    def test_compressed_leak_refused_identical(self):
        """compressed-leak + all -> byte-identical, qemu-clean, data reads.

        instar declines the all tier on compressed images. The image is
        untouched and its (compressed) data still reads back.
        """
        copy, stdout, _stderr, _rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-compressed-leak', repair='all')

        self.assertEqual(
            sha_before, sha_after,
            'compressed image must be left byte-identical'
        )
        self.assertTrue(self._repair_incomplete(stdout))
        self._assert_qemu_clean(copy)
        self._assert_all_patterns(copy)

    def test_overlapping_partial_repair_not_worse(self):
        """overlapping + all -> leak reclaimed, overlap remains, not worse.

        Duplicating L2[0] into L2[1] makes the 0xAA cluster
        double-referenced (a structural overlap) and orphans the old
        L2[1] cluster (a genuine leak). The leaks tier reclaims the
        genuine leak; the structural overlap is left in place. The image
        must not gain new error classes: qemu still reports exactly the
        one pre-existing overlap corruption, the leak is gone, and
        instar exits 2 with repair-incomplete.
        """
        # Baseline: the untouched fixture has one leak and one overlap.
        before_rc, before = self._qemu_check_json(
            self.get_image('check-qcow2-overlapping').path
        )
        self.assertEqual(before.get('corruptions'), 1, before)
        self.assertEqual(before.get('leaks'), 1, before)

        copy, stdout, _stderr, rc, _sha_b, _sha_a = \
            self._repair_copy('check-qcow2-overlapping', repair='all')

        self.assertEqual(rc, 2, 'partial repair should exit 2')
        self.assertTrue(self._repair_incomplete(stdout))

        after_rc, after = self._qemu_check_json(copy)
        # The genuine leak is reclaimed...
        self.assertFalse(
            after.get('leaks'),
            f'genuine leak should be reclaimed, got {after}'
        )
        # ...but the structural overlap remains, and no NEW corruption
        # class was introduced (still exactly the one pre-existing
        # overlap).
        self.assertEqual(
            after.get('corruptions'), 1,
            f'overlap should remain and no new errors appear: {after}'
        )
        self.assertEqual(
            after.get('check-errors', 0), 0,
            f'repair must not introduce check-errors: {after}'
        )

    def test_all_tier_oversized_l2_set_aborts_cleanly(self):
        """Regression: more active L2 tables than the staging arena holds
        must abort cleanly, never overflow it.

        The all-tier L2 staging arena is 2 MiB. With 2 MiB clusters it
        holds exactly one L2 table, and each such L2 covers 512 GiB of
        virtual space, so writing at offset 0 and past 512 GiB allocates
        two L2 tables in an otherwise-sparse 1 TiB image — one more than
        the arena holds. Before the byte-extent guard was restored (it had
        been dropped from snapshot's `stage_l2_set` reference) this
        overran the arena into adjacent guest scratch. The repair must now
        abort (report incomplete) without crashing or corrupting data.
        """
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        img = Path(td.name) / 'bigclusters.qcow2'
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'cluster_size=2097152', str(img), '1T'],
            capture_output=True, timeout=30, check=True,
        )
        for off in ('0', '600G'):
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 f'write -P 0xAB {off} 4k', str(img)],
                capture_output=True, timeout=30, check=True,
            )

        stdout, stderr, rc = self.run_instar_check(
            img, output_format='json', repair='all', timeout=120
        )
        # No crash / hang (run_instar_check returns -1 on timeout; a
        # signal death would be negative too).
        self.assertGreaterEqual(rc, 0, f'instar must not crash/hang: {stderr}')
        self.assertTrue(
            self._repair_incomplete(stdout),
            f'over-capacity all-tier repair must report incomplete: {stdout}'
        )
        # Data survives — an arena overflow would clobber the staged
        # buffers (and the written-back metadata). The abort leaves the
        # corrupt bit set, so read with a read-only open.
        for off in ('0', '600G'):
            result = subprocess.run(
                ['qemu-io', '-r', '-f', 'qcow2', '-c',
                 f'read -P 0xAB {off} 4k', str(img)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'data at {off} must survive the aborted repair:\n'
                f'{result.stdout}\n{result.stderr}'
            )


class TestRepairCli(_RepairTestBase):
    """CLI guards, no-op repair, raw handling, idempotence."""

    def test_repair_with_chain_rejected(self):
        """--repair + --chain is rejected before touching the image."""
        copy = self._make_copy('check-qcow2-clean')
        sha_before = self._sha256(copy)
        _stdout, stderr, rc = self.run_instar_check(
            copy, repair='leaks', chain=True
        )
        self.assertNotEqual(rc, 0, 'combining --repair and --chain must fail')
        self.assertIn('chain', stderr.lower())
        self.assertEqual(
            sha_before, self._sha256(copy),
            'a rejected invocation must not modify the image'
        )

    def test_repair_clean_image_noop(self):
        """--repair=all on a clean image is a byte-identical no-op."""
        _copy, _stdout, _stderr, rc, sha_before, sha_after = \
            self._repair_copy('check-qcow2-clean', repair='all')

        self.assertEqual(rc, 0, 'clean image repair should exit 0')
        self.assertEqual(
            sha_before, sha_after,
            'repairing a clean image must not change it'
        )

    def test_repair_raw_image_not_supported(self):
        """--repair on a raw image is qcow2-only: not-supported, no crash.

        instar only repairs inside check_qcow2; a raw target reports
        not-supported (exit 63) and must not crash.
        """
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        raw = Path(td.name) / 'plain.raw'
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', str(raw), '1M'],
            capture_output=True, text=True, timeout=30
        )
        sha_before = self._sha256(raw)
        _stdout, _stderr, rc = self.run_instar_check(raw, repair='all')

        # Sane exit (not a signal / timeout) and the documented
        # qcow2-only not-supported code.
        self.assertGreaterEqual(rc, 0, 'instar must not crash on a raw image')
        self.assertEqual(
            rc, 63,
            'repair on a raw image should report not-supported (63)'
        )
        self.assertEqual(
            sha_before, self._sha256(raw),
            'a raw image must be left untouched'
        )

    def test_repair_idempotent(self):
        """Repairing an already-repaired image is a no-op."""
        copy = self._make_copy('check-qcow2-refcount-zero')

        self.run_instar_check(copy, output_format='json', repair='all')
        sha_first = self._sha256(copy)

        _stdout, _stderr, rc = self.run_instar_check(
            copy, output_format='json', repair='all'
        )
        sha_second = self._sha256(copy)

        self.assertEqual(rc, 0, 'second repair of a clean image should exit 0')
        self.assertEqual(
            sha_first, sha_second,
            'repairing an already-clean image must not change it'
        )
        self._assert_qemu_clean(copy)


class TestRepairCounters(_RepairTestBase):
    """The per-class repaired-* counters reach the host (guest+proto wire).

    These counters are guest-side state surfaced over the
    CheckResultMessage protobuf; they are emitted only when a repair
    actually fixed something, so a read-only check keeps its existing
    schema.
    """

    def test_leaks_counter_in_json(self):
        """leaked + leaks → JSON reports `repaired-leaks` for the reclaim."""
        _copy, stdout, _stderr, _rc, _sb, _sa = self._repair_copy(
            'check-qcow2-leaked', repair='leaks'
        )
        data = json.loads(stdout)
        self.assertEqual(
            data.get('repaired-leaks'), 1,
            f'expected one reclaimed leak in the JSON, got: {stdout}'
        )
        self.assertNotIn('repaired-refcounts', data)

    def test_refcount_counter_in_json(self):
        """refcount-too-high + all → JSON reports `repaired-refcounts`."""
        _copy, stdout, _stderr, _rc, _sb, _sa = self._repair_copy(
            'check-qcow2-refcount-too-high', repair='all'
        )
        data = json.loads(stdout)
        self.assertGreaterEqual(
            data.get('repaired-refcounts', 0), 1,
            f'expected a refcount correction in the JSON, got: {stdout}'
        )

    def test_plain_check_omits_repaired_keys(self):
        """A read-only check emits no `repaired-*` keys (schema preserved)."""
        copy = self._make_copy('check-qcow2-leaked')
        stdout, _stderr, _rc = self.run_instar_check(
            copy, output_format='json', repair=None
        )
        data = json.loads(stdout)
        for key in ('repaired-leaks', 'repaired-refcounts',
                    'repaired-corruptions'):
            self.assertNotIn(key, data)

    def test_human_output_reports_repaired(self):
        """Human output prints a `Repaired ...` summary line after a repair."""
        copy = self._make_copy('check-qcow2-leaked')
        stdout, _stderr, _rc = self.run_instar_check(
            copy, output_format=None, repair='leaks'
        )
        self.assertIn('Repaired', stdout)
        self.assertIn('1 leaked cluster', stdout)
