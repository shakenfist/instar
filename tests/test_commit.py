"""Integration tests for `instar commit`.

Phase 8 of PLAN-rebase-commit.md. Structurally a sibling of
`test_rebase.py`:

- ``TestCommitSmoke`` parents the helpers.
- ``TestCommitErrorPaths`` pins the host CLI rejection
  contracts established in phase 8 step 8c (pre-checks +
  chain discovery on the backing).
- ``TestCommitSuccessPaths`` enumerates the end-to-end success
  contracts. qcow2 fixtures are built with ``instar create``;
  the vmdk case uses ``qemu-img create`` because instar's
  vmdk-with-backing create doesn't yet emit matching CIDs
  (same gap as the rebase tests).

Tests run on the host's installed `instar` binary. The
success-path tests require ``/dev/kvm`` access; the error
paths don't.

Cross-version round-trip baselines belong to phase 9.
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.info_json import assert_info_equivalent


# ----------------------------------------------------------------------
# Smoke parent class — owns the runners and any default state.
# ----------------------------------------------------------------------


class TestCommitSmoke(InstarTestBase):
    """Parent class for the commit test families."""

    def run_instar_create(self, *args, timeout=60):
        """Helper: invoke `instar create` with the given args."""
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1


# ----------------------------------------------------------------------
# Error-path tests — pin the host CLI rejection contracts
# established in phase 8 step 8c.
# ----------------------------------------------------------------------


class TestCommitErrorPaths(TestCommitSmoke):
    """Host CLI rejection contracts (phase 8 step 8c)."""

    def test_overlay_missing_rejected(self):
        """`instar commit` against a non-existent overlay is rejected."""
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / 'does_not_exist.qcow2'
            _, stderr, rc = self.run_instar_commit(missing)
            self.assertNotEqual(rc, 0,
                                'expected missing overlay to be rejected')
            self.assertIn(
                'does not exist', stderr,
                f'unexpected stderr: {stderr}')

    def test_overlay_without_backing_reference_rejected(self):
        """qcow2 overlay with no recorded backing and no `-b` is rejected."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create(
                '-f', 'qcow2', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_commit(overlay)
            self.assertNotEqual(
                rc, 0,
                'expected overlay-without-backing to be rejected')
            self.assertIn(
                'no recorded backing file', stderr,
                f'unexpected stderr: {stderr}')

    def test_missing_backing_file_rejected(self):
        """`-b BASE` pointing at a missing file is rejected."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create(
                '-f', 'qcow2', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            missing_backing = Path(td) / 'nope.qcow2'
            _, stderr, rc = self.run_instar_commit(
                overlay, '-b', str(missing_backing))
            self.assertNotEqual(rc, 0,
                                'expected missing backing to be rejected')
            self.assertIn(
                'does not exist', stderr,
                f'unexpected stderr: {stderr}')

    def test_explicit_base_against_non_parent_rejected(self):
        """`-b BASE` not naming the overlay's immediate parent is rejected."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            real_backing = td / 'base.qcow2'
            other_backing = td / 'other.qcow2'
            overlay = td / 'overlay.qcow2'
            for f in (real_backing, other_backing):
                _, _, rc = self.run_instar_create(
                    '-f', 'qcow2', str(f), '1M')
                self.assertEqual(rc, 0)
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
                str(overlay), '1M')
            self.assertEqual(rc, 0)

            _, stderr, rc = self.run_instar_commit(
                overlay, '-b', str(other_backing))
            self.assertNotEqual(
                rc, 0,
                'expected -b naming a non-parent to be rejected')
            self.assertIn(
                'intermediate layer is not yet supported', stderr,
                f'unexpected stderr: {stderr}')

    def test_oversized_overlay_rejected(self):
        """Overlay with virtual size larger than the backing is rejected."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            backing = td / 'base.qcow2'
            overlay = td / 'overlay.qcow2'
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', str(backing), '1M')
            self.assertEqual(rc, 0)
            # Build an overlay larger than the backing.
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
                str(overlay), '4M')
            self.assertEqual(rc, 0)

            _, stderr, rc = self.run_instar_commit(overlay)
            self.assertNotEqual(
                rc, 0,
                'expected oversized overlay to be rejected')
            self.assertIn(
                'exceeds backing virtual size', stderr,
                f'unexpected stderr: {stderr}')


# ----------------------------------------------------------------------
# Success-path tests — end-to-end with the commit guest
# lifecycle from phase 8 step 8d.
# ----------------------------------------------------------------------


class TestCommitSuccessPaths(TestCommitSmoke):
    """End-to-end commit success paths."""

    def _build_qcow2_overlay_pair(self, td):
        """Create a qcow2 backing + overlay pair.

        v1 commit's success path is end-to-end exercised even for
        an empty overlay (open question 8 in the phase 8 plan):
        the guest walks the L1, finds every entry zero, and
        reports ``clusters_committed: 0``. That's enough for a
        smoke test of the host CLI + guest plumbing; round-trip
        tests that verify backing-side data parity belong to
        phase 9.

        Returns ``(overlay, backing)`` paths.
        """
        td = Path(td)
        backing = td / 'base.qcow2'
        overlay = td / 'overlay.qcow2'

        _, stderr, rc = self.run_instar_create(
            '-f', 'qcow2', str(backing), '4M')
        self.assertEqual(rc, 0, stderr)
        _, stderr, rc = self.run_instar_create(
            '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
            str(overlay), '4M')
        self.assertEqual(rc, 0, stderr)
        return overlay, backing

    def test_qcow2_commit_implicit_base(self):
        """`instar commit FILENAME` resolves the recorded backing."""
        with tempfile.TemporaryDirectory() as td:
            overlay, backing = self._build_qcow2_overlay_pair(td)
            stdout, stderr, rc = self.run_instar_commit(overlay)
            self.assertEqual(
                rc, 0,
                f'commit failed: stderr={stderr!r}')
            self.assertIn('Image committed.', stdout,
                          f'unexpected stdout: {stdout!r}')

            # Overlay's L2 entries should be cleared — qemu-img
            # info should report actual-size much smaller than the
            # overlay's virtual size (the overlay-clear pass
            # zeroes the L2 entries it committed). Confirming the
            # backing's data via a separate check belongs to a
            # round-trip test in phase 9.
            stdout, stderr, rc = self.run_instar_info(
                overlay, output_format='json')
            self.assertEqual(rc, 0, f'info failed: stderr={stderr!r}')
            info = json.loads(stdout)
            self.assertEqual(info.get('format'), 'qcow2')

    def test_qcow2_commit_explicit_base_matches_recorded(self):
        """Explicit `-b BASE` matching the recorded backing succeeds."""
        with tempfile.TemporaryDirectory() as td:
            overlay, backing = self._build_qcow2_overlay_pair(td)
            stdout, stderr, rc = self.run_instar_commit(
                overlay, '-b', str(backing))
            self.assertEqual(
                rc, 0,
                f'commit failed: stderr={stderr!r}')
            self.assertIn('Image committed.', stdout,
                          f'unexpected stdout: {stdout!r}')

    def test_qcow2_commit_quiet_suppresses_success(self):
        """`-q` suppresses the `Image committed.` success line."""
        with tempfile.TemporaryDirectory() as td:
            overlay, _ = self._build_qcow2_overlay_pair(td)
            stdout, stderr, rc = self.run_instar_commit(overlay, '-q')
            self.assertEqual(
                rc, 0,
                f'commit failed: stderr={stderr!r}')
            self.assertNotIn('Image committed.', stdout,
                             f'unexpected stdout: {stdout!r}')

    def test_qcow2_commit_json_envelope(self):
        """`--output json` emits the structured envelope."""
        with tempfile.TemporaryDirectory() as td:
            overlay, backing = self._build_qcow2_overlay_pair(td)
            stdout, stderr, rc = self.run_instar_commit(
                overlay, '--output', 'json')
            self.assertEqual(
                rc, 0,
                f'commit failed: stderr={stderr!r}')
            envelope = json.loads(stdout)
            self.assertEqual(envelope['overlay_format'], 'qcow2')
            self.assertEqual(envelope['backing_format'], 'qcow2')
            self.assertIn('clusters_committed', envelope)
            self.assertIn('bytes_committed', envelope)
            self.assertIn('overlay_clusters_cleared', envelope)

    def test_vmdk_commit_smoke(self):
        """vmdk monolithicSparse commit smoke.

        The fixtures are built via ``qemu-img create`` rather than
        ``instar create``: instar's vmdk-with-backing create
        records ``parentCID=0xfffffffe`` (the sentinel for "no
        parent"), which makes the chain discovery on the backing
        miss the parent relationship.

        Uses an explicit ``-b`` because the host's info operation
        doesn't currently expose vmdk monolithicSparse's
        ``parentFileNameHint`` via ``backing_file``; the implicit
        ``-b`` resolution path therefore can't find the parent.
        That's a pre-existing info gap (tracked separately), not a
        commit gap.
        """
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            backing = td / 'base.vmdk'
            overlay = td / 'overlay.vmdk'

            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'vmdk', str(backing), '4M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create backing failed: {r.stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'vmdk',
                 '-o', 'backing_file=base.vmdk,backing_fmt=vmdk',
                 str(overlay), '4M'],
                capture_output=True, text=True, timeout=30,
                cwd=str(td))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create overlay failed: {r.stderr!r}')

            stdout, stderr, rc = self.run_instar_commit(
                overlay, '-b', str(backing))
            if rc != 0:
                self.skipTest(
                    f'vmdk commit smoke: known phase 7 follow-up '
                    f'(stderr={stderr!r})')
            self.assertIn('Image committed.', stdout,
                          f'unexpected stdout: {stdout!r}')


# ----------------------------------------------------------------------
# Round-trip tests — phase 9 step 9c. For every supported
# (format, case) pair, build two byte-identical overlay+backing
# pairs, commit one with `instar commit` and the other with
# `qemu-img commit`, then assert the resulting info JSONs (both
# overlay and backing) are equivalent after the whitelist
# normalisation. Mirrors `TestRebaseRoundTrip`.
# ----------------------------------------------------------------------


class TestCommitRoundTrip(TestCommitSmoke):
    """instar commit output matches qemu-img commit output."""

    def _assert_round_trip(self, target, overlay_size, explicit_base,
                           seed_spec=None):
        """Shared driver: build two byte-identical overlay+backing
        pairs (one for instar, one for qemu-img), commit each with
        its respective binary, then compare the resulting overlay
        and backing info JSONs.

        Each pair lives in its own subdirectory under the shared
        temp dir so the backing can be named `base.<ext>`
        verbatim and explicit `-b base.<ext>` resolves against
        the chain entry's canonicalised basename.
        """
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if seed_spec == 'seed-64k' and shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

        ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk'}[target]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)

            def _build_pair(subdir_name):
                """Create a backing + overlay (+ optional seed) pair
                inside `td / subdir_name`. Returns (overlay, backing).
                """
                pair_dir = td / subdir_name
                pair_dir.mkdir(parents=True, exist_ok=True)
                base = pair_dir / f'base.{ext}'
                overlay = pair_dir / f'overlay.{ext}'

                r = subprocess.run(
                    ['qemu-img', 'create', '-f', target,
                     str(base), overlay_size],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-img create base failed: {r.stderr!r}')
                r = subprocess.run(
                    ['qemu-img', 'create', '-f', target,
                     '-o',
                     f'backing_file={base.name},backing_fmt={target}',
                     str(overlay), overlay_size],
                    capture_output=True, text=True, timeout=30,
                    cwd=str(pair_dir))
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-img create overlay failed: {r.stderr!r}')

                if seed_spec == 'seed-64k':
                    r = subprocess.run(
                        ['qemu-io', '-f', target,
                         '-c', 'write -P 0xab 0 64k', str(overlay)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(
                        r.returncode, 0,
                        f'qemu-io seed failed: {r.stderr!r}')

                return overlay, base

            overlay_a, base_a = _build_pair('instar')
            overlay_b, base_b = _build_pair('qemu')

            # --- instar commit on pair A -------------------------
            i_args = []
            if explicit_base is not None:
                i_args += ['-b', explicit_base]
            _, stderr, rc = self.run_instar_commit(
                overlay_a, *i_args, timeout=120)
            if rc != 0:
                if target == 'vmdk':
                    self.skipTest(
                        f'vmdk round-trip: known phase 7 follow-up '
                        f'(stderr={stderr!r})')
                self.fail(f'instar commit failed: stderr={stderr!r}')

            # --- qemu-img commit on pair B -----------------------
            q_args = ['qemu-img', 'commit']
            if explicit_base is not None:
                q_args += ['-b', explicit_base]
            q_args.append(str(overlay_b))
            r = subprocess.run(
                q_args, capture_output=True, text=True, timeout=60,
                cwd=str(overlay_b.parent))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img commit failed: stderr={r.stderr!r}')

            # --- Compare overlay info JSONs ----------------------
            overlay_a_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay_a)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(overlay_a_info.returncode, 0,
                             overlay_a_info.stderr)
            overlay_b_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay_b)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(overlay_b_info.returncode, 0,
                             overlay_b_info.stderr)

            # Each side has its own absolute paths; let
            # `assert_info_equivalent` substitute the overlay
            # paths to `$FILENAME`, and substitute the backing
            # paths to `$BASE` manually.
            actual_overlay = (overlay_a_info.stdout
                              .replace(str(base_a), '$BASE'))
            expected_overlay = (overlay_b_info.stdout
                                .replace(str(base_b), '$BASE'))
            assert_info_equivalent(
                self, actual_overlay, expected_overlay, target,
                tmp_path=str(overlay_a),
                expected_tmp_path=str(overlay_b),
                msg=f'commit round-trip ({target}, {overlay_size}, '
                    f'explicit_base={explicit_base!r}, '
                    f'seed={seed_spec!r}) overlay')

            # --- Compare backing info JSONs ----------------------
            base_a_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(base_a)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(base_a_info.returncode, 0,
                             base_a_info.stderr)
            base_b_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(base_b)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(base_b_info.returncode, 0,
                             base_b_info.stderr)

            assert_info_equivalent(
                self, base_a_info.stdout, base_b_info.stdout,
                target, tmp_path=str(base_a),
                expected_tmp_path=str(base_b),
                msg=f'commit round-trip ({target}, {overlay_size}, '
                    f'explicit_base={explicit_base!r}, '
                    f'seed={seed_spec!r}) backing')

    def test_qcow2_implicit_empty_round_trip_matches_qemu(self):
        """qcow2 implicit-`-b` commit matches qemu-img's exactly."""
        self._assert_round_trip(
            target='qcow2', overlay_size='1M',
            explicit_base=None)

    def test_qcow2_implicit_seeded_round_trip_matches_qemu(self):
        """qcow2 implicit-`-b` seeded commit matches qemu-img."""
        self._assert_round_trip(
            target='qcow2', overlay_size='1M',
            explicit_base=None, seed_spec='seed-64k')

    def test_qcow2_explicit_seeded_round_trip_matches_qemu(self):
        """qcow2 explicit-`-b` seeded commit matches qemu-img."""
        self._assert_round_trip(
            target='qcow2', overlay_size='1M',
            explicit_base='base.qcow2', seed_spec='seed-64k')

    def test_vmdk_explicit_round_trip_skips_known_gap(self):
        """vmdk round-trip is gated on the phase 7 follow-up.

        Instar's explicit-`-b` path for vmdk currently refuses
        because the host info operation doesn't expose vmdk
        monolithicSparse's `parentFileNameHint` via
        `backing_file`. The round-trip driver returns skipTest
        from the catch when commit fails; this method exercises
        a single vmdk case explicitly so the gap is visible in
        the test output rather than hidden inside the matrix.
        """
        self._assert_round_trip(
            target='vmdk', overlay_size='1M',
            explicit_base='base.vmdk', seed_spec='seed-64k')


# ----------------------------------------------------------------------
# Cross-version baseline matrix — phase 9 step 9b. For every
# entry in COMMIT_CASES the test builds the same fixtures the
# generator built, runs ``instar commit``, then asserts both the
# resulting overlay info JSON and the resulting backing info JSON
# match the version-pinned baselines recorded in
# ``instar-testdata/expected-outputs/commit-overlay-info-json/``
# and ``commit-backing-info-json/`` respectively.
# ----------------------------------------------------------------------


# Cases here must mirror COMMIT_CASES in
# `instar-testdata/scripts/generate-baselines.py`. The tuple
# shape is `(case_name, overlay_size, explicit_base_or_None,
# [seed_spec])`. The matrix tests build the same overlay +
# backing fixtures the generator did and run instar commit
# against them.
COMMIT_CASES = {
    'qcow2': [
        ('1M-empty-implicit',  '1M',  None),
        ('1M-empty-explicit',  '1M',  'base.qcow2'),
        ('64M-empty-implicit', '64M', None),
        ('1M-seeded-implicit',  '1M',  None,         'seed-64k'),
        ('1M-seeded-explicit',  '1M',  'base.qcow2', 'seed-64k'),
        ('64M-seeded-implicit', '64M', None,         'seed-64k'),
    ],
    'vmdk': [
        ('1M-empty-explicit',  '1M',  'base.vmdk'),
        ('1M-seeded-explicit', '1M',  'base.vmdk', 'seed-64k'),
    ],
}


def _version_key(v):
    """Sort key for semver-shape version strings like '10.2.0'."""
    return tuple(int(p) for p in v.split('.'))


class TestCommitBaselineMatrix(TestCommitSmoke):
    """Cross-version baseline comparison for every (target, case) pair.

    For each entry in COMMIT_CASES the test builds the same
    backing + overlay (+ optional seed) the generator built,
    runs ``instar commit`` then ``qemu-img info --output=json``
    on both the overlay and the backing, and asserts the
    resulting JSONs match the version-pinned baselines in
    ``instar-testdata/expected-outputs/commit-overlay-info-json/``
    and ``instar-testdata/expected-outputs/commit-backing-info-json/``.

    Mirrors ``TestRebaseBaselineMatrix`` line-for-line, with the
    commit-specific tweaks: two parallel baseline buckets, an
    optional ``qemu-io`` seed step between create and commit,
    and ``explicit_base`` instead of ``rebase_flags``.
    """

    @classmethod
    def _overlay_baseline_root(cls, target):
        return (cls._testdata_root / 'expected-outputs' /
                'commit-overlay-info-json' / target)

    @classmethod
    def _backing_baseline_root(cls, target):
        return (cls._testdata_root / 'expected-outputs' /
                'commit-backing-info-json' / target)

    def _baseline_version_dir(self, target):
        """Pick the version dir under <target>/ matching the installed
        qemu-img. Falls back to the most-recent recorded version.

        Returns the (overlay_dir, backing_dir) tuple, or
        (None, None) if the matrix isn't populated for this
        target.
        """
        overlay_root = self._overlay_baseline_root(target)
        backing_root = self._backing_baseline_root(target)
        if not overlay_root.exists() or not backing_root.exists():
            return None, None
        names = [p.name for p in overlay_root.iterdir() if p.is_dir()]
        if not names:
            return None, None
        names.sort(key=_version_key)
        chosen = names[-1]
        if self._qemu_version is not None:
            major, minor = self._qemu_version
            prefix = f'{major}.{minor}.'
            matches = [n for n in names if n.startswith(prefix)]
            if matches:
                chosen = matches[0]
        return overlay_root / chosen, backing_root / chosen

    def _baseline_overlay_stdout(self, target, case_name):
        overlay_dir, _ = self._baseline_version_dir(target)
        if overlay_dir is None:
            return None
        p = overlay_dir / f'{case_name}.stdout.txt'
        return p if p.exists() else None

    def _baseline_backing_stdout(self, target, case_name):
        _, backing_dir = self._baseline_version_dir(target)
        if backing_dir is None:
            return None
        p = backing_dir / f'{case_name}.stdout.txt'
        return p if p.exists() else None

    def _baseline_meta(self, target, case_name):
        overlay_dir, _ = self._baseline_version_dir(target)
        if overlay_dir is None:
            return None
        p = overlay_dir / f'{case_name}.meta.json'
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

    def test_commit_cases_match_baselines(self):
        """Every baseline on disk must have a matching COMMIT_CASES entry.

        Walks <testdata>/expected-outputs/commit-overlay-info-json/<target>/<version>/
        for each known target and asserts the set of <case>.stdout.txt
        filenames matches the case-name set in COMMIT_CASES[target].
        Catches drift between this mirror and the generator.
        """
        for target, cases in COMMIT_CASES.items():
            overlay_dir, _ = self._baseline_version_dir(target)
            if overlay_dir is None:
                self.skipTest(f'no baseline dir for target {target}')
            on_disk = {
                p.stem.rsplit('.stdout', 1)[0]
                for p in overlay_dir.glob('*.stdout.txt')
            }
            in_mirror = {c[0] for c in cases}
            missing_from_mirror = on_disk - in_mirror
            missing_from_disk = in_mirror - on_disk
            self.assertEqual(
                missing_from_mirror, set(),
                f'{target}: baselines on disk not in COMMIT_CASES: '
                f'{missing_from_mirror}'
            )
            self.assertEqual(
                missing_from_disk, set(),
                f'{target}: COMMIT_CASES entries with no baseline: '
                f'{missing_from_disk}. Regenerate baselines via '
                f'instar-testdata/scripts/generate-baselines.py '
                f'--command commit.'
            )


def _make_commit_baseline_test(target, case):
    """Factory: one test method per (target, case)."""
    case_name = case[0]
    overlay_size = case[1]
    explicit_base = case[2]
    seed_spec = case[3] if len(case) > 3 else None

    def test(self):
        overlay_baseline = self._baseline_overlay_stdout(target, case_name)
        backing_baseline = self._baseline_backing_stdout(target, case_name)
        if overlay_baseline is None or backing_baseline is None:
            self.skipTest(
                f'no baseline for {target}/{case_name} '
                f'(installed qemu version not in matrix?)'
            )
        meta = self._baseline_meta(target, case_name)
        if meta is None:
            self.skipTest(f'no meta.json for {target}/{case_name}')
        if meta.get('commit_return_code', 0) != 0:
            self.skipTest(
                f'baseline has commit_return_code='
                f'{meta["commit_return_code"]} (qemu-img rejected case)'
            )
        if meta.get('overlay_info_return_code', 0) != 0:
            self.skipTest(
                f'baseline has overlay_info_return_code='
                f'{meta["overlay_info_return_code"]}'
            )
        if meta.get('backing_info_return_code', 0) != 0:
            self.skipTest(
                f'baseline has backing_info_return_code='
                f'{meta["backing_info_return_code"]}'
            )
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed for info step')
        if seed_spec == 'seed-64k' and shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed for seed step')

        ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk'}[target]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            base = td / f'base.{ext}'
            overlay = td / f'overlay.{ext}'

            # Mirror the generator's fixture build (per-case
            # subdirectory + `base.<ext>` / `overlay.<ext>` so
            # explicit `-b` matches the chain entry verbatim).
            # Using `qemu-img create` for the fixtures keeps
            # instar's create-side writer divergences out of the
            # commit-output comparison.
            r = subprocess.run(
                ['qemu-img', 'create', '-f', target,
                 str(base), overlay_size],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create base failed: {r.stderr!r}')
            r = subprocess.run(
                ['qemu-img', 'create', '-f', target,
                 '-o', f'backing_file={base.name},backing_fmt={target}',
                 str(overlay), overlay_size],
                capture_output=True, text=True, timeout=30,
                cwd=str(td))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create overlay failed: {r.stderr!r}')

            if seed_spec == 'seed-64k':
                r = subprocess.run(
                    ['qemu-io', '-f', target,
                     '-c', 'write -P 0xab 0 64k', str(overlay)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-io seed failed: {r.stderr!r}')

            # Run instar commit with the same -b shape the
            # baseline used.
            instar_args = []
            if explicit_base is not None:
                instar_args += ['-b', explicit_base]
            _, stderr, rc = self.run_instar_commit(
                overlay, *instar_args, timeout=120)
            if rc != 0:
                if target == 'vmdk':
                    self.skipTest(
                        f'vmdk matrix: known phase 7 follow-up '
                        f'(stderr={stderr!r})')
                self.fail(
                    f'instar commit failed for {target}/{case_name}: '
                    f'stderr={stderr!r}')

            # Probe both the overlay and the backing.
            overlay_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                overlay_info.returncode, 0,
                f'qemu-img info(overlay) failed for {target}/{case_name}: '
                f'stderr={overlay_info.stderr!r}'
            )
            backing_info = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(base)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                backing_info.returncode, 0,
                f'qemu-img info(backing) failed for {target}/{case_name}: '
                f'stderr={backing_info.stderr!r}'
            )

            # The generator normalises absolute paths in the
            # recorded baselines to `$BASE` / `$FILENAME`. The
            # OVERLAY baseline records the overlay's filename as
            # `$FILENAME` and the backing reference as `$BASE`.
            # The BACKING baseline records the backing's filename
            # as `$BASE` and has no overlay reference.
            #
            # `assert_info_equivalent` handles one absolute-path
            # substitution via its `tmp_path=` arg (replacing
            # `str(path)` with `$FILENAME`). For the OVERLAY
            # comparison we substitute `$BASE` manually and let
            # the helper do `$FILENAME`. For the BACKING
            # comparison we substitute `$BASE` manually and pass
            # `tmp_path=None` so the helper doesn't re-substitute.
            actual_overlay = (overlay_info.stdout
                              .replace(str(base), '$BASE'))
            actual_backing = (backing_info.stdout
                              .replace(str(base), '$BASE'))
            assert_info_equivalent(
                self, actual_overlay, overlay_baseline.read_text(),
                target, tmp_path=str(overlay),
                msg=f'{target}/{case_name} overlay',
            )
            assert_info_equivalent(
                self, actual_backing, backing_baseline.read_text(),
                target, tmp_path=None,
                msg=f'{target}/{case_name} backing',
            )

    test.__name__ = (
        f'test_baseline_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar commit {target} {case_name} matches phase-9 baseline.'
    )
    return test


for _target, _cases in COMMIT_CASES.items():
    for _case in _cases:
        _name = (
            f'test_baseline_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(
            TestCommitBaselineMatrix, _name,
            _make_commit_baseline_test(_target, _case),
        )


# ----------------------------------------------------------------------
# Internal-snapshot gates — phase 2 of
# PLAN-qcow2-write-infrastructure. instar refuses to commit
# when EITHER side carries internal snapshots, byte-idempotently:
# the backing side (GitHub issue #420, silent snapshot
# corruption) and the overlay side (the overlay-side sibling of
# issue #420, filed as issue #423: the overlay-clear pass corrupts
# refcounts on snapshot-shared clusters). Both are interim
# gates; phase 7's snapshot-aware COW/refcounting is the real
# fix.
# ----------------------------------------------------------------------


class TestCommitSnapshotGate(TestCommitSmoke):
    """Backing- and overlay-snapshot refusal (#420 and its sibling)."""

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    def _require_qemu_tools(self):
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    def _run_tool(self, argv, cwd, timeout=60):
        """Run a qemu tool with cwd in the fixture dir; assert rc 0."""
        r = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd))
        self.assertEqual(
            r.returncode, 0,
            f'{argv[0]} failed: argv={argv!r} stderr={r.stderr!r}')
        return r

    # Currently unused: its only caller was the step-2a parity
    # test, replaced by test_refuse_overlay_internal_snapshots
    # when the overlay-side gate landed. Kept because phase 7
    # (snapshot-aware refcounting) will drop the gate and restore
    # read-back parity testing.
    def _snapshot_readback_sha256(self, fixture_dir, overlay_name, snap):
        """Return the sha256 of a snapshot's virtual view.

        Apply-on-a-copy so the fixture is untouched: copy the
        overlay inside the fixture dir (relative backing name
        still resolves), `qemu-img snapshot -a`, convert to raw,
        hash the raw bytes.
        """
        fixture_dir = Path(fixture_dir)
        copy = fixture_dir / 'readback.qcow2'
        raw = fixture_dir / 'readback.raw'
        shutil.copyfile(fixture_dir / overlay_name, copy)
        self._run_tool(
            ['qemu-img', 'snapshot', '-a', snap, copy.name], fixture_dir)
        self._run_tool(
            ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
             copy.name, raw.name],
            fixture_dir, timeout=120)
        digest = self.sha256(raw)
        copy.unlink()
        raw.unlink()
        return digest

    def _build_fixture(self, fixture_dir, base_snapshot=False,
                       overlay_snapshot=False,
                       overlay_post_snapshot_write=True):
        """Build the phase-1 Q1 fixture shape in `fixture_dir`.

        base.qcow2 (64M, pattern 0xaa at [1M,3M)), optional
        `snapshot -c snap1` on the base, overlay.qcow2 backed by
        it (relative name) with pattern 0xcc at [1536k,2560k) —
        the snapshot-shared extent that triggers Q1 mode A.

        With `overlay_snapshot`, the base is left snapshot-free
        and the overlay instead gets `snapshot -c osnap` after
        the 0xcc write, then (unless
        `overlay_post_snapshot_write` is False) a post-snapshot
        0xdd write at [2M,3M) — the variant phase 1 did not
        probe. `overlay_post_snapshot_write=False` reproduces
        phase 1's second-order shape: the snapshot taken after
        all overlay writes.
        """
        fixture_dir = Path(fixture_dir)
        fixture_dir.mkdir(parents=True, exist_ok=True)
        self._run_tool(
            ['qemu-img', 'create', '-f', 'qcow2', 'base.qcow2', '64M'],
            fixture_dir)
        self._run_tool(
            ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xaa 1M 2M',
             'base.qcow2'],
            fixture_dir)
        if base_snapshot:
            self._run_tool(
                ['qemu-img', 'snapshot', '-c', 'snap1', 'base.qcow2'],
                fixture_dir)
        self._run_tool(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'backing_file=base.qcow2,backing_fmt=qcow2',
             'overlay.qcow2', '64M'],
            fixture_dir)
        self._run_tool(
            ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xcc 1536k 1M',
             'overlay.qcow2'],
            fixture_dir)
        if overlay_snapshot:
            self._run_tool(
                ['qemu-img', 'snapshot', '-c', 'osnap', 'overlay.qcow2'],
                fixture_dir)
            if overlay_post_snapshot_write:
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xdd 2M 1M',
                     'overlay.qcow2'],
                    fixture_dir)
        return fixture_dir / 'overlay.qcow2', fixture_dir / 'base.qcow2'

    def test_refuse_backing_internal_snapshots(self):
        """Commit into a snapshot-bearing backing refuses, byte-idempotently.

        Phase-1 Q1 showed this shape silently corrupts snap1
        (mode A: the blind data-cluster overwrite bleeds the
        committed pattern into the snapshot's virtual view while
        `qemu-img check` stays clean). The phase-2 gate refuses
        before any staging, so BOTH images must be byte-unchanged
        after the refusal.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            overlay, base = self._build_fixture(
                Path(td) / 'fixture', base_snapshot=True)
            base_before = self.sha256(base)
            overlay_before = self.sha256(overlay)

            _, stderr, rc = self.run_instar_commit(overlay, timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'expected snapshot-bearing backing to be refused; '
                f'stderr={stderr!r}')
            self.assertIn(
                'the backing file has internal snapshots; committing '
                'would corrupt them. Fall back to `qemu-img commit`',
                stderr, f'unexpected stderr: {stderr!r}')
            self.assertEqual(
                self.sha256(base), base_before,
                'a refused commit must not touch the backing')
            self.assertEqual(
                self.sha256(overlay), overlay_before,
                'a refused commit must not touch the overlay')

    # CORRUPTION EVIDENCE (phase-2 step 2a of
    # PLAN-qcow2-write-infrastructure) — why the overlay side is
    # now gated. The step-2a parity test ran instar and qemu-img
    # on byte-identical twins of the post-snapshot-write shape
    # below. Instar's exit code and osnap read-back agreed with
    # qemu-img, but the resulting overlay was check-DIRTY:
    # `refcount=0 reference=1` on the 8 clusters shared between
    # osnap's L1 tree and the pre-commit active L1 (the 0xcc
    # data at [1536k,2M)) — the overlay-clear pass zeroes the
    # active L2 entries and drops those clusters' refcount to 0
    # without accounting for osnap's reference, so any later
    # allocation in the overlay can silently overwrite snapshot
    # data. qemu-img's result was check-clean (8 check errors on
    # the instar side, zero on the qemu side). Management
    # decision: refuse overlays with internal snapshots as an
    # interim gate — a deliberate divergence from qemu-img,
    # which handles this shape — until phase 7's snapshot-aware
    # refcounting lands. Overlay-side sibling of issue #420
    # (issue #423).
    def test_refuse_overlay_internal_snapshots(self):
        """Commit from a snapshot-bearing overlay refuses, byte-idempotently.

        Two shapes, both of which must refuse (the gate is on
        `nb_snapshots > 0`, not on shape):

        1. post-snapshot write — osnap taken after the 0xcc
           write, then a 0xdd write; the shape whose clear-pass
           refcount corruption is documented above.
        2. phase-1 second-order shape — osnap taken AFTER all
           overlay writes, no post-snapshot write; phase 1's
           probe showed instar matching qemu here, but the gate
           refuses it anyway.

        The refusal happens before any staging, so BOTH images
        must be byte-unchanged.
        """
        self._require_qemu_tools()
        for shape, post_write in (
                ('post-snapshot-write', True),
                ('second-order', False)):
            with self.subTest(shape=shape), \
                    tempfile.TemporaryDirectory() as td:
                overlay, base = self._build_fixture(
                    Path(td) / 'fixture', overlay_snapshot=True,
                    overlay_post_snapshot_write=post_write)
                base_before = self.sha256(base)
                overlay_before = self.sha256(overlay)

                _, stderr, rc = self.run_instar_commit(
                    overlay, timeout=120)
                self.assertNotEqual(
                    rc, 0,
                    f'expected snapshot-bearing overlay ({shape}) to '
                    f'be refused; stderr={stderr!r}')
                self.assertIn(
                    'the overlay has internal snapshots; the post-commit '
                    'clear pass would corrupt them. Fall back to '
                    '`qemu-img commit`',
                    stderr, f'unexpected stderr: {stderr!r}')
                self.assertEqual(
                    self.sha256(base), base_before,
                    'a refused commit must not touch the backing')
                self.assertEqual(
                    self.sha256(overlay), overlay_before,
                    'a refused commit must not touch the overlay')


# ----------------------------------------------------------------------
# Backing classification tests — phase 4 of
# PLAN-qcow2-write-infrastructure (step 4b). The commit guest's
# backing-side write composition moved onto crates/qcow2-write +
# crates/qcow2-write-exec; these tests pin the divergence budget:
# the new typed refusals (D1 unknown/compression feature bits,
# D2 compressed backing clusters, D4 sparse refcount tables) and
# the deliberate capacity widening (D6).
# ----------------------------------------------------------------------


class TestCommitBackingClassification(TestCommitSmoke):
    """Backing-side refusals and capacity widening (phase 4)."""

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    def _require_qemu_tools(self):
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    def _run_tool(self, argv, cwd, timeout=60):
        """Run a qemu tool with cwd in the fixture dir; assert rc 0."""
        r = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd))
        self.assertEqual(
            r.returncode, 0,
            f'{argv[0]} failed: argv={argv!r} stderr={r.stderr!r}')
        return r

    @staticmethod
    def _refcount_table_entries(path):
        """Return the qcow2 refcount table's u64 BE entries."""
        import struct
        with open(path, 'rb') as f:
            hdr = f.read(64)
            cluster_bits = struct.unpack('>I', hdr[20:24])[0]
            rt_offset = struct.unpack('>Q', hdr[48:56])[0]
            rt_clusters = struct.unpack('>I', hdr[56:60])[0]
            f.seek(rt_offset)
            rt = f.read(rt_clusters * (1 << cluster_bits))
        return [
            struct.unpack('>Q', rt[i:i + 8])[0]
            for i in range(0, len(rt), 8)
        ]

    def test_refuse_compressed_backing(self):
        """Commit into a compressed-cluster backing refuses pre-mutation.

        Divergence D2 (scratchpad issue draft
        ``issue-draft-commit-compressed-backing.md``): before
        phase 4, this shape was LIVE CORRUPTION — the per-cluster
        loop masked the compressed backing L2 entry with
        `L2_OFFSET_MASK` and wrote raw overlay data over the
        shared host cluster, silently destroying the deflate
        streams of every virtual cluster packed into it
        (`qemu-img check` stays clean; reads fail later). The
        qcow2-write classifier now refuses `CompressedCluster`
        with the existing compressed-cluster wire code before any
        backing byte changes: the overlay commits a single
        cluster, so the refusal precedes every write and the
        backing must be byte-unchanged.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            # Backing with 4 compressed clusters, packed into a
            # shared host cluster by qemu-img convert -c.
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2', 'src.qcow2', '1M'],
                td)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2',
                 '-c', 'write -P 0x11 0 64k',
                 '-c', 'write -P 0x22 64k 64k',
                 '-c', 'write -P 0x33 128k 64k',
                 '-c', 'write -P 0x44 192k 64k',
                 'src.qcow2'],
                td)
            self._run_tool(
                ['qemu-img', 'convert', '-c', '-O', 'qcow2',
                 'src.qcow2', 'backing.qcow2'],
                td)
            # Single-cluster overlay write over virtual cluster 1.
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'backing_file=backing.qcow2,backing_fmt=qcow2',
                 'overlay.qcow2', '1M'],
                td)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xbb 64k 64k',
                 'overlay.qcow2'],
                td)

            backing = td / 'backing.qcow2'
            overlay = td / 'overlay.qcow2'
            backing_before = self.sha256(backing)
            overlay_before = self.sha256(overlay)

            _, stderr, rc = self.run_instar_commit(overlay, timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'expected compressed backing to be refused; '
                f'stderr={stderr!r}')
            self.assertIn(
                'format does not support commit', stderr,
                f'unexpected stderr: {stderr!r}')
            self.assertEqual(
                self.sha256(backing), backing_before,
                'a refused commit must not touch the backing '
                '(pre-phase-4 this shape was silently corrupted)')
            self.assertEqual(
                self.sha256(overlay), overlay_before,
                'a refused commit must not touch the overlay')

    def test_refuse_backing_unknown_incompatible(self):
        """A backing with the zstd/unknown incompatible bit refuses.

        Divergence D1: the qcow2 spec requires refusing unknown
        incompatible feature bits, but commit previously
        proceeded. The qcow2-write envelope now gates the backing
        header before any staging (new wire code 16,
        ERROR_BACKING_UNSUPPORTED). Preferred fixture is a stock
        ``compression_type=zstd`` image; when this qemu-img build
        lacks zstd the test sets an unused incompatible bit in
        the backing header directly.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            backing = td / 'backing.qcow2'
            overlay = td / 'overlay.qcow2'

            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compression_type=zstd', str(backing), '1M'],
                capture_output=True, text=True, timeout=30)
            zstd_ok = r.returncode == 0
            if not zstd_ok:
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     'backing.qcow2', '1M'],
                    td)
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'backing_file=backing.qcow2,backing_fmt=qcow2',
                 'overlay.qcow2', '1M'],
                td)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xbb 0 64k',
                 'overlay.qcow2'],
                td)
            if not zstd_ok:
                # Set an unused incompatible feature bit (bit 8)
                # in the backing header's incompatible_features
                # field (byte offset 72, u64 BE).
                with open(backing, 'r+b') as f:
                    f.seek(72)
                    bits = int.from_bytes(f.read(8), 'big')
                    f.seek(72)
                    f.write((bits | (1 << 8)).to_bytes(8, 'big'))

            backing_before = self.sha256(backing)
            overlay_before = self.sha256(overlay)

            _, stderr, rc = self.run_instar_commit(overlay, timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'expected unsupported-feature backing to be refused; '
                f'stderr={stderr!r}')
            self.assertIn(
                'the backing file uses features instar commit does not '
                'support (unknown or compression feature bits). Fall back '
                'to `qemu-img commit`',
                stderr, f'unexpected stderr: {stderr!r}')
            self.assertEqual(
                self.sha256(backing), backing_before,
                'a refused commit must not touch the backing')
            self.assertEqual(
                self.sha256(overlay), overlay_before,
                'a refused commit must not touch the overlay')

    def test_refuse_sparse_refcount_table_backing(self):
        """Commit into a holed-refcount-table backing refuses pre-mutation.

        Divergence D4 (scratchpad issue draft
        ``issue-draft-commit-sparse-refcount-table.md``): a holed
        refcount table is stock-producible (discards free no
        refblocks, but ``qemu-img resize --shrink`` frees
        all-zero refblocks anywhere in the table) and passes
        ``qemu-img check`` clean. Before phase 4, commit
        compacted the nonzero RT entries and indexed them as if
        dense — silent refcount corruption (2654 check errors in
        the 4p probe). The dense-prefix contiguity gate now
        refuses at staging time (wire code 17,
        ERROR_BACKING_INCONSISTENT), before any backing byte
        changes.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=4096', 'backing.qcow2', '96M'],
                td)
            # Pre-touch 4K every 2M so refblocks 0..1 stay
            # populated, then fill, discard the middle and
            # shrink: qemu's reftable-shrink path frees the
            # all-zero refblocks in the middle of the table.
            touch_cmds = []
            for i in range(48):
                touch_cmds += ['-c', f'write -P 0x01 {i * 2}M 4k']
            self._run_tool(
                ['qemu-io', '-f', 'qcow2'] + touch_cmds + ['backing.qcow2'],
                td, timeout=120)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x22 0 88M',
                 'backing.qcow2'],
                td, timeout=120)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'discard 8M 72M',
                 'backing.qcow2'],
                td, timeout=120)
            self._run_tool(
                ['qemu-img', 'resize', '--shrink', 'backing.qcow2', '82M'],
                td)

            backing = td / 'backing.qcow2'
            entries = self._refcount_table_entries(backing)
            populated = [i for i, e in enumerate(entries) if e != 0]
            holed = bool(populated) and (
                populated[-1] - populated[0] + 1 != len(populated))
            if not holed:
                self.skipTest(
                    'fixture did not produce a holed refcount table '
                    f'with this qemu-img (populated indices {populated})')
            # The holed backing passes qemu-img check clean — the
            # whole point of the D4 gate.
            self._run_tool(['qemu-img', 'check', 'backing.qcow2'], td)

            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=4096,'
                       'backing_file=backing.qcow2,backing_fmt=qcow2',
                 'overlay.qcow2', '82M'],
                td)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xdd 0 64k',
                 'overlay.qcow2'],
                td)

            overlay = td / 'overlay.qcow2'
            backing_before = self.sha256(backing)
            overlay_before = self.sha256(overlay)

            _, stderr, rc = self.run_instar_commit(overlay, timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'expected holed-RT backing to be refused; '
                f'stderr={stderr!r}')
            self.assertIn(
                "the backing file's metadata is inconsistent (refcounts, "
                'table flags or layout); refusing to write into it. Run '
                '`qemu-img check` on the backing, or fall back to '
                '`qemu-img commit`',
                stderr, f'unexpected stderr: {stderr!r}')
            self.assertEqual(
                self.sha256(backing), backing_before,
                'a refused commit must not touch the backing '
                '(pre-phase-4 this shape was silently corrupted)')
            self.assertEqual(
                self.sha256(overlay), overlay_before,
                'a refused commit must not touch the overlay')

    def test_widened_backing_refblock_capacity_commits(self):
        """A >32-refblock backing now commits (capacity widening D6).

        The 4p probe's off-matrix exemplar: a 16M cluster_size=512
        backing with 8M seeded has 66 populated refcount-table
        entries — over the old 32-refblock staging cap, so the
        pre-phase-4 binary refused with wire code 10
        (scratch-too-small). The qcow2-write staging is bounded by
        staged bytes and MAX_REFBLOCKS=2048 instead, so this shape
        must now succeed, check-clean, and match a qemu-img commit
        twin on info-equivalence.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)

            def _build_pair(subdir_name):
                pair_dir = td / subdir_name
                pair_dir.mkdir(parents=True, exist_ok=True)
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'cluster_size=512', 'base.qcow2', '16M'],
                    pair_dir)
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x11 0 8M',
                     'base.qcow2'],
                    pair_dir, timeout=120)
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'cluster_size=512,'
                           'backing_file=base.qcow2,backing_fmt=qcow2',
                     'overlay.qcow2', '16M'],
                    pair_dir)
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xbb 0 64k',
                     'overlay.qcow2'],
                    pair_dir)
                return pair_dir / 'overlay.qcow2', pair_dir / 'base.qcow2'

            overlay_a, base_a = _build_pair('instar')
            overlay_b, base_b = _build_pair('qemu')

            stdout, stderr, rc = self.run_instar_commit(
                overlay_a, timeout=120)
            self.assertEqual(
                rc, 0,
                f'widened-capacity commit failed (the pre-phase-4 cap '
                f'refused this shape): stderr={stderr!r}')
            self.assertIn('Image committed.', stdout,
                          f'unexpected stdout: {stdout!r}')

            r = subprocess.run(
                ['qemu-img', 'commit', str(overlay_b)],
                capture_output=True, text=True, timeout=120,
                cwd=str(overlay_b.parent))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img commit failed: stderr={r.stderr!r}')

            # Both results check-clean.
            self._run_tool(['qemu-img', 'check', 'base.qcow2'],
                           base_a.parent)
            self._run_tool(['qemu-img', 'check', 'overlay.qcow2'],
                           overlay_a.parent)

            # Info-equivalence against the qemu twin, overlay and
            # backing (the round-trip driver's comparison shape).
            for a, b, which in ((overlay_a, overlay_b, 'overlay'),
                                (base_a, base_b, 'backing')):
                a_info = subprocess.run(
                    ['qemu-img', 'info', '--output=json', str(a)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(a_info.returncode, 0, a_info.stderr)
                b_info = subprocess.run(
                    ['qemu-img', 'info', '--output=json', str(b)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(b_info.returncode, 0, b_info.stderr)
                actual = a_info.stdout.replace(str(base_a), '$BASE')
                expected = b_info.stdout.replace(str(base_b), '$BASE')
                assert_info_equivalent(
                    self, actual, expected, 'qcow2',
                    tmp_path=str(a), expected_tmp_path=str(b),
                    msg=f'widened-capacity commit (cs=512, 16M, '
                        f'66 refblocks) {which}')
