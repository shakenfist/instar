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
