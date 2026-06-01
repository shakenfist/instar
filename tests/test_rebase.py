"""Integration tests for `instar rebase`.

Phase 5 of PLAN-rebase-commit.md. Structurally a sibling of
`test_resize.py`'s phase-11 layout:

- ``TestRebaseSmoke`` parents the helpers and is the place to
  hang the runner overrides (timeouts, default flags) for
  child classes.
- ``TestRebaseErrorPaths`` pins the host CLI rejection
  contracts established in phase 4 step 4c (pre-checks +
  chain discovery).
- ``TestRebaseSuccessPaths`` enumerates the success-path
  contracts. The qcow2 in-place rewrite paths use ``instar
  create`` to build the fixtures; the vmdk path uses
  ``qemu-img create`` because instar's vmdk-with-backing
  create doesn't yet emit matching CIDs (out-of-scope for the
  rebase plan; tracked under PLAN-create's vmdk follow-ups).
- ``TestRebaseRoundTrip`` (step 5f) runs ``instar rebase``
  and ``qemu-img rebase`` against identically-seeded
  fixtures and asserts the resulting ``qemu-img info
  --output=json`` outputs are byte-equivalent after
  whitelist normalisation.
- ``TestRebaseBaselineMatrix`` (step 5e) consumes the
  cross-version baselines step 5d generates in
  ``instar-testdata`` and asserts ``instar rebase``'s output
  matches the version-pinned ``qemu-img rebase`` baseline
  for every ``(target, case)`` pair.

Tests run on the host's installed `instar` binary. The
success-path tests require ``/dev/kvm`` access; the error
paths don't.
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


class TestRebaseSmoke(InstarTestBase):
    """Parent class for the rebase test families.

    The runner helpers live on `InstarTestBase` (step 5a);
    this class is a stable parent that the child classes
    inherit from in case any test-family-specific defaults
    are needed later.
    """

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
# established in phase 4 step 4c.
# ----------------------------------------------------------------------


class TestRebaseErrorPaths(TestRebaseSmoke):
    """Host CLI rejection contracts (phase 4 step 4c)."""

    def test_overlay_missing_rejected(self):
        """`instar rebase` against a non-existent overlay is rejected."""
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / 'does_not_exist.qcow2'
            _, stderr, rc = self.run_instar_rebase(
                missing, '-u', '-b', '/tmp/anything.qcow2')
            self.assertNotEqual(rc, 0,
                                'expected missing overlay to be rejected')
            self.assertIn(
                'does not exist', stderr,
                f'unexpected stderr: {stderr}')

    def test_missing_backing_flag_rejected_by_clap(self):
        """`instar rebase` without `-b` is rejected by clap."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create(
                '-f', 'qcow2', str(path), '1M')
            self.assertEqual(c_rc, 0)
            _, _, rc = self.run_instar_rebase(path)
            self.assertNotEqual(
                rc, 0,
                'expected missing -b to be rejected by clap')

    def test_missing_backing_file_rejected_safe_mode(self):
        """Missing new backing file is rejected in safe mode."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create(
                '-f', 'qcow2', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            missing_backing = Path(td) / 'nope.qcow2'
            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', str(missing_backing))
            self.assertNotEqual(rc, 0,
                                'expected missing backing to be rejected')
            self.assertIn(
                'does not exist', stderr,
                f'unexpected stderr: {stderr}')
            self.assertIn(
                '-u', stderr,
                'error message should point at the -u escape')

    def test_oversized_backing_path_rejected(self):
        """`-b PATH` longer than 1024 bytes is rejected."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.qcow2'
            _, _, c_rc = self.run_instar_create(
                '-f', 'qcow2', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            oversized = 'x' * 1025
            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', oversized)
            self.assertNotEqual(rc, 0,
                                'expected oversized path to be rejected')
            self.assertIn(
                '1024', stderr,
                f'unexpected stderr: {stderr}')

    def test_unsupported_forced_format_rejected(self):
        """`-f raw` is rejected by the probe with a clear message."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create(
                '-f', 'raw', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_rebase(
                overlay, '-f', 'raw', '-u', '-b', '/tmp/anything')
            self.assertNotEqual(rc, 0,
                                'expected -f raw to be rejected')
            self.assertIn(
                'not supported', stderr,
                f'unexpected stderr: {stderr}')

    def test_raw_overlay_rejected_by_probe(self):
        """A raw overlay (auto-detected) is rejected by the probe."""
        with tempfile.TemporaryDirectory() as td:
            overlay = Path(td) / 'foo.raw'
            _, _, c_rc = self.run_instar_create(
                '-f', 'raw', str(overlay), '1M')
            self.assertEqual(c_rc, 0)
            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', '/tmp/anything')
            self.assertNotEqual(rc, 0,
                                'expected raw overlay auto-detect to be rejected')
            self.assertIn(
                'does not support rebase', stderr.lower(),
                f'unexpected stderr: {stderr}')


# ----------------------------------------------------------------------
# Success-path tests — end-to-end with the rebase guest
# lifecycle from phase 4 step 4d. The qcow2 in-place cases
# run today; vmdk and qemu-img round-trip are still skipped
# pending the test scaffolding in phase 5 step 5f.
# ----------------------------------------------------------------------


class TestRebaseSuccessPaths(TestRebaseSmoke):
    """End-to-end success-path tests."""

    def test_qcow2_unsafe_rebase_records_new_backing(self):
        """qcow2 `-u` rebase rewrites the overlay's backing reference.

        Uses an equal-length new backing path so the new
        reference fits into the overlay's existing
        backing_file_size slot. Long-path relocation is a v2
        item (`ERROR_BACKING_PATH_TOO_LONG` from the planner).
        """
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            old_backing = td / 'base.qcow2'
            new_backing = td / 'next.qcow2'  # same length as old
            overlay = td / 'overlay.qcow2'

            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', str(old_backing), '1M')
            self.assertEqual(rc, 0)
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', str(new_backing), '1M')
            self.assertEqual(rc, 0)
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
                str(overlay), '1M')
            self.assertEqual(rc, 0)

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', 'next.qcow2')
            self.assertEqual(
                rc, 0,
                f'rebase failed: stderr={stderr!r}')

            stdout, stderr, rc = self.run_instar_info(
                overlay, output_format='json')
            self.assertEqual(rc, 0, f'info failed: stderr={stderr!r}')
            info = json.loads(stdout)
            self.assertEqual(info.get('backing-filename'), 'next.qcow2')

    def test_qcow2_unsafe_detach(self):
        """qcow2 `-u -b ""` clears the overlay's backing reference."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            backing = td / 'base.qcow2'
            overlay = td / 'overlay.qcow2'

            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', str(backing), '1M')
            self.assertEqual(rc, 0)
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
                str(overlay), '1M')
            self.assertEqual(rc, 0)

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', '')
            self.assertEqual(
                rc, 0,
                f'detach failed: stderr={stderr!r}')

            stdout, stderr, rc = self.run_instar_info(
                overlay, output_format='json')
            self.assertEqual(rc, 0, f'info failed: stderr={stderr!r}')
            info = json.loads(stdout)
            self.assertNotIn('backing-filename', info)
            self.assertNotIn('full-backing-filename', info)

    def test_vmdk_unsafe_rebase_records_new_backing(self):
        """vmdk monolithicSparse `-u` rebase rewrites parentFileNameHint.

        The fixtures are built via ``qemu-img create`` rather than
        ``instar create``. instar's vmdk-with-backing create does
        not yet emit matching CIDs (the descriptor records
        `parentCID=0xfffffffe`, the sentinel for "no parent"),
        which makes the post-rebase ``backing-filename`` field
        absent from ``qemu-img info``. Using ``qemu-img create``
        for the fixture isolates this from the rebase test — the
        instar vmdk-create gap is a separate item under PLAN-create's
        vmdk follow-ups.
        """
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            old_backing = td / 'base.vmdk'
            new_backing = td / 'next.vmdk'  # same length as 'base'
            overlay = td / 'overlay.vmdk'

            for name, fp in (('base', old_backing), ('next', new_backing)):
                r = subprocess.run(
                    ['qemu-img', 'create', '-f', 'vmdk', str(fp), '1M'],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-img create {name} failed: {r.stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'vmdk',
                 '-o', f'backing_file=base.vmdk,backing_fmt=vmdk',
                 str(overlay), '1M'],
                capture_output=True, text=True, timeout=30,
                cwd=str(td))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create overlay failed: {r.stderr!r}')

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', 'next.vmdk', '-F', 'vmdk')
            self.assertEqual(
                rc, 0, f'rebase failed: stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0,
                             f'qemu-img info failed: {r.stderr!r}')
            info = json.loads(r.stdout)
            self.assertEqual(
                info.get('backing-filename'), 'next.vmdk',
                f'unexpected backing-filename in {info!r}')


# ----------------------------------------------------------------------
# Round-trip tests — for every supported (format, mode) pair, build
# two byte-identical overlays, rebase one with `instar rebase` and
# the other with `qemu-img rebase`, then assert `qemu-img info
# --output=json` produces equivalent JSON after the whitelist
# normalisation. This is the canonical "instar matches qemu-img"
# assertion shape for the rebase planner.
# ----------------------------------------------------------------------


class TestRebaseRoundTrip(TestRebaseSmoke):
    """instar rebase output matches qemu-img rebase output."""

    def _assert_round_trip(self, target, overlay_factory,
                           backing_pair, instar_flags, qemu_flags):
        """Shared driver: build two copies of the overlay via
        ``overlay_factory(td)``, run instar against the first and
        qemu-img against the second with matching arguments, then
        compare the resulting info JSONs.

        ``overlay_factory`` is a callable taking a temp dir Path and
        returning ``(overlay_path, base_backing_name)``; it is
        expected to also create the old + new backing files in the
        same directory at the same relative names so both invocations
        can resolve them.

        ``backing_pair`` is ``(new_backing_relative_name,
        new_backing_format_hint_or_None)``; passed to both rebase
        commands.
        """
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')

        new_backing_name, new_backing_format = backing_pair
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            overlay_a, _ = overlay_factory(td, 'overlay_a')
            overlay_b, _ = overlay_factory(td, 'overlay_b')

            i_args = ['-u', '-b', new_backing_name]
            q_args = ['-u', '-b', new_backing_name]
            if new_backing_format is not None:
                i_args += ['-F', new_backing_format]
                q_args += ['-F', new_backing_format]
            i_args += instar_flags
            q_args += qemu_flags

            _, stderr, rc = self.run_instar_rebase(overlay_a, *i_args)
            self.assertEqual(
                rc, 0, f'instar rebase failed: stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'rebase', *q_args, str(overlay_b)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img rebase failed: stderr={r.stderr!r}')

            actual = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay_a)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(actual.returncode, 0, actual.stderr)
            expected = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay_b)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(expected.returncode, 0, expected.stderr)

            assert_info_equivalent(
                self, actual.stdout, expected.stdout, target,
                tmp_path=str(overlay_a),
                expected_tmp_path=str(overlay_b),
                msg=f'rebase round-trip ({target}, {new_backing_name})')

    def _qcow2_overlay(self, td, name):
        """Create a qcow2 overlay backed by ``base.qcow2`` in ``td``.

        Both backings are created with ``instar create`` so the test
        is exercising end-to-end instar primitives. Returns
        ``(overlay_path, 'base.qcow2')``.
        """
        base = td / 'base.qcow2'
        new = td / 'next.qcow2'
        if not base.exists():
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(base), '1M')
            self.assertEqual(rc, 0, stderr)
        if not new.exists():
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(new), '1M')
            self.assertEqual(rc, 0, stderr)
        overlay = td / f'{name}.qcow2'
        _, stderr, rc = self.run_instar_create(
            '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
            str(overlay), '1M')
        self.assertEqual(rc, 0, stderr)
        return overlay, 'base.qcow2'

    def _vmdk_overlay(self, td, name):
        """Create a vmdk overlay backed by ``base.vmdk`` via
        ``qemu-img create`` (see notes on
        ``test_vmdk_unsafe_rebase_records_new_backing`` for why
        qemu-img owns the create step).
        """
        base = td / 'base.vmdk'
        new = td / 'next.vmdk'
        for fp in (base, new):
            if fp.exists():
                continue
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'vmdk', str(fp), '1M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create {fp.name} failed: {r.stderr!r}')
        overlay = td / f'{name}.vmdk'
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'vmdk',
             '-o', 'backing_file=base.vmdk,backing_fmt=vmdk',
             str(overlay), '1M'],
            capture_output=True, text=True, timeout=30,
            cwd=str(td))
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img create overlay failed: {r.stderr!r}')
        return overlay, 'base.vmdk'

    def test_qcow2_unsafe_round_trip_matches_qemu(self):
        """qcow2 `-u` rebase output matches qemu-img's exactly."""
        self._assert_round_trip(
            target='qcow2',
            overlay_factory=self._qcow2_overlay,
            backing_pair=('next.qcow2', 'qcow2'),
            instar_flags=[],
            qemu_flags=[],
        )

    def test_qcow2_unsafe_detach_round_trip_matches_qemu(self):
        """qcow2 `-u -b ""` detach output matches qemu-img's exactly."""
        self._assert_round_trip(
            target='qcow2',
            overlay_factory=self._qcow2_overlay,
            backing_pair=('', None),
            instar_flags=[],
            qemu_flags=[],
        )

    def test_vmdk_unsafe_round_trip_skips_no_qemu_support(self):
        """vmdk rebase has no qemu-img counterpart to round-trip against.

        ``qemu-img rebase`` on a vmdk overlay returns ``Operation
        not supported`` on every shipped qemu version we test, so
        there is no reference to compare instar against. This test
        records that fact rather than silently disappearing; the
        ``test_vmdk_unsafe_rebase_records_new_backing`` test in
        ``TestRebaseSuccessPaths`` covers the instar-side
        contract via ``qemu-img info`` instead.
        """
        self.skipTest(
            'qemu-img rebase does not support vmdk '
            '(reports "Operation not supported"); vmdk rebase is '
            'covered by test_vmdk_unsafe_rebase_records_new_backing')


# ----------------------------------------------------------------------
# Baseline matrix (step 5e) — instar rebase output matches the
# version-pinned qemu-img rebase baseline for every (target, case)
# pair. Factory-generated, mirroring TestCreateBaselineMatrix.
# ----------------------------------------------------------------------


# Cases here must mirror REBASE_CASES in
# `instar-testdata/scripts/generate-baselines.py`. The format is
# `(case_name, overlay_size, new_backing_size_or_None,
# rebase_flags)`. The matrix tests build the same overlay + backing
# fixtures the generator does and run instar rebase against them.
REBASE_CASES = {
    'qcow2': [
        ('1M-unsafe-to-default-parent', '1M', '1M',
            ['-u', '-F', 'qcow2']),
        ('1M-unsafe-to-larger-parent', '1M', '64M',
            ['-u', '-F', 'qcow2']),
        ('1M-unsafe-detach', '1M', None, ['-u']),
        ('64M-unsafe-to-default-parent', '64M', '64M',
            ['-u', '-F', 'qcow2']),
        ('1M-safe-to-default-parent', '1M', '1M', ['-F', 'qcow2']),
        ('1M-safe-detach', '1M', None, []),
    ],
}


def _version_key(v):
    """Sort key for semver-shape version strings like '10.2.0'."""
    return tuple(int(p) for p in v.split('.'))


class TestRebaseBaselineMatrix(TestRebaseSmoke):
    """Cross-version baseline comparison for every (target, case) pair.

    For each entry in REBASE_CASES the test builds the same overlay
    + backings the generator built, runs ``instar rebase`` then
    ``qemu-img info --output=json`` on the result, normalises both
    sides via the divergence whitelist, and asserts byte-equivalence
    against the version-matched baseline recorded in instar-testdata.

    Bypasses ``get_expected_output()`` and reads
    ``expected-outputs/rebase-info-json/<target>/<version>/<case>.stdout.txt``
    directly — phase 7's ``detect-profiles.py`` flat-copies into
    ``profiles/profile-NN/`` keyed by case-name only, so collisions
    between targets silently overwrite. Reading the raw per-target
    bucket sidesteps the bug (same approach as
    ``TestCreateBaselineMatrix``).
    """

    @classmethod
    def _baseline_root(cls, target):
        return (cls._testdata_root / 'expected-outputs' /
                'rebase-info-json' / target)

    def _baseline_version_dir(self, target):
        """Pick the version dir under <target>/ matching the installed
        qemu-img. Falls back to the most-recent recorded version.

        Returns the Path, or None if the matrix isn't populated for
        this target.
        """
        root = self._baseline_root(target)
        if not root.exists():
            return None
        names = [p.name for p in root.iterdir() if p.is_dir()]
        if not names:
            return None
        names.sort(key=_version_key)
        if self._qemu_version is not None:
            major, minor = self._qemu_version
            prefix = f'{major}.{minor}.'
            matches = [n for n in names if n.startswith(prefix)]
            if matches:
                return root / matches[0]
        return root / names[-1]

    def _baseline_stdout(self, target, case_name):
        v_dir = self._baseline_version_dir(target)
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.stdout.txt'
        return p if p.exists() else None

    def _baseline_meta(self, target, case_name):
        v_dir = self._baseline_version_dir(target)
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.meta.json'
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

    def test_rebase_cases_match_baselines(self):
        """Every baseline on disk must have a matching REBASE_CASES entry.

        Walks <testdata>/expected-outputs/rebase-info-json/<target>/<version>/
        for each known target and asserts the set of <case>.stdout.txt
        filenames matches the case-name set in REBASE_CASES[target].
        Catches drift between this mirror and the generator.
        """
        for target, cases in REBASE_CASES.items():
            v_dir = self._baseline_version_dir(target)
            if v_dir is None:
                self.skipTest(f'no baseline dir for target {target}')
            on_disk = {
                p.stem.rsplit('.stdout', 1)[0]
                for p in v_dir.glob('*.stdout.txt')
            }
            in_mirror = {c[0] for c in cases}
            missing_from_mirror = on_disk - in_mirror
            missing_from_disk = in_mirror - on_disk
            self.assertEqual(
                missing_from_mirror, set(),
                f'{target}: baselines on disk not in REBASE_CASES: '
                f'{missing_from_mirror}'
            )
            self.assertEqual(
                missing_from_disk, set(),
                f'{target}: REBASE_CASES entries with no baseline: '
                f'{missing_from_disk}. Regenerate baselines via '
                f'instar-testdata/scripts/generate-baselines.py '
                f'--command rebase.'
            )


def _make_rebase_baseline_test(target, case):
    """Factory: one test method per (target, case)."""
    case_name, overlay_size, new_backing_size, rebase_flags = case
    detach = new_backing_size is None

    def test(self):
        baseline_path = self._baseline_stdout(target, case_name)
        if baseline_path is None:
            self.skipTest(
                f'no baseline for {target}/{case_name} '
                f'(installed qemu version not in matrix?)'
            )
        meta = self._baseline_meta(target, case_name)
        if meta is None:
            self.skipTest(f'no meta.json for {target}/{case_name}')
        if meta.get('rebase_return_code', 0) != 0:
            self.skipTest(
                f'baseline has rebase_return_code='
                f'{meta["rebase_return_code"]} (qemu-img rejected case)'
            )
        if meta.get('info_return_code', 0) != 0:
            self.skipTest(
                f'baseline has info_return_code='
                f'{meta["info_return_code"]} (no comparable JSON)'
            )

        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed for info step')

        ext = {'qcow2': 'qcow2'}[target]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            base = td / f'{target}-{case_name}-base.{ext}'
            new = td / f'{target}-{case_name}-next.{ext}'
            overlay = td / f'{target}-{case_name}-overlay.{ext}'

            # The baseline generator uses `qemu-img create` for the
            # fixture images. The matrix test does the same so the
            # bytes the rebase actually mutates match what the
            # baseline recorded. Using `instar create` for the
            # overlay would mix instar's create-side writer
            # divergences into the rebase comparison.
            r = subprocess.run(
                ['qemu-img', 'create', '-f', target,
                 str(base), overlay_size],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create base failed: {r.stderr!r}')
            if not detach:
                r = subprocess.run(
                    ['qemu-img', 'create', '-f', target,
                     str(new), new_backing_size],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(
                    r.returncode, 0,
                    f'qemu-img create new failed: {r.stderr!r}')
            r = subprocess.run(
                ['qemu-img', 'create', '-f', target,
                 '-o', f'backing_file={base.name},backing_fmt={target}',
                 str(overlay), overlay_size],
                capture_output=True, text=True, timeout=30,
                cwd=str(td))
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create overlay failed: {r.stderr!r}')

            # Run instar rebase with the same flags + backing
            # filename the baseline used.
            instar_args = []
            if detach:
                instar_args += ['-b', '']
            else:
                instar_args += ['-b', new.name]
            instar_args += list(rebase_flags)
            _, stderr, rc = self.run_instar_rebase(overlay, *instar_args)
            self.assertEqual(
                rc, 0,
                f'instar rebase failed for {target}/{case_name}: '
                f'stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img info failed for {target}/{case_name}: '
                f'stderr={r.stderr!r}'
            )
            # The generator normalises absolute paths in the
            # recorded baseline to `$BASE` / `$NEXT` / `$FILENAME`;
            # apply the same normalisation here so the comparison
            # is path-host-independent. `assert_info_equivalent`
            # handles `$FILENAME` via its `tmp_path=` arg; `$BASE`
            # and `$NEXT` are rebase-specific and substituted here.
            actual = (r.stdout
                      .replace(str(base), '$BASE')
                      .replace(str(new), '$NEXT'))
            expected = baseline_path.read_text()
            assert_info_equivalent(
                self, actual, expected, target,
                tmp_path=str(overlay),
                msg=f'{target}/{case_name}',
            )

    test.__name__ = (
        f'test_baseline_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar rebase {target} {case_name} matches phase-5 baseline.'
    )
    return test


for _target, _cases in REBASE_CASES.items():
    for _case in _cases:
        _name = (
            f'test_baseline_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(
            TestRebaseBaselineMatrix, _name,
            _make_rebase_baseline_test(_target, _case),
        )
