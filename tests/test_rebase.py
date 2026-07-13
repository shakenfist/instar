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


# ----------------------------------------------------------------------
# Internal-snapshot gate — phase 2 of
# PLAN-qcow2-write-infrastructure (GitHub issue #421). Safe-mode
# `instar rebase` (any mode without -u, including safe detach)
# refuses, byte-idempotently, when the overlay carries internal
# snapshots: safe mode mutates snapshot-shared L2 tables in place
# and sets refcount=1 on clusters two L1 trees reference, so a
# routine `qemu-img snapshot -d` afterwards frees live
# active-view data. `-u` metadata-only rebase never touches
# snapshot-shared clusters and stays allowed (parity-tested
# below). Phase 7's snapshot-aware COW is the real fix.
# ----------------------------------------------------------------------


class TestRebaseSnapshotGate(TestRebaseSmoke):
    """Safe-mode overlay-snapshot refusal + `-u` parity (#421)."""

    def setUp(self):
        super().setUp()
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    def _run_tool(self, argv, cwd, timeout=60):
        """Run a qemu tool with cwd in the fixture dir; assert rc 0."""
        r = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd))
        self.assertEqual(
            r.returncode, 0,
            f'{argv[0]} failed: argv={argv!r} stderr={r.stderr!r}')
        return r

    def _build_bases(self, fixture_dir):
        """Create the phase-1 Q2 backing pair in `fixture_dir`.

        base_old.qcow2 (6M, 0x11 at [0,4M)) and base_new.qcow2
        (6M, 0x22 at [2M,6M)), both at 64K clusters. Idempotent
        so twin overlays can share one pair (identical
        `full-backing-filename` keeps the info JSONs
        comparable).
        """
        fixture_dir = Path(fixture_dir)
        fixture_dir.mkdir(parents=True, exist_ok=True)
        for name, pattern in (
                ('base_old.qcow2', 'write -P 0x11 0 4M'),
                ('base_new.qcow2', 'write -P 0x22 2M 4M')):
            if (fixture_dir / name).exists():
                continue
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=65536', name, '6M'],
                fixture_dir)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', pattern, name],
                fixture_dir)
        return fixture_dir / 'base_old.qcow2', fixture_dir / 'base_new.qcow2'

    def _build_overlay(self, fixture_dir, name, post_snapshot_write):
        """Create a snapshot-bearing Q2 overlay on base_old.qcow2.

        6M overlay at 64K clusters backed by base_old.qcow2
        (relative name), 0x33 at [1M,2M), then `snapshot -c
        snap1`. With `post_snapshot_write` a 0x44 write at
        [3M,4M) follows the snapshot, so the active L1 tree has
        been COWed away from snap1's; without it the active L2
        stays snapshot-shared — the shape whose safe-mode rebase
        corrupts refcounts (issue #421).
        """
        fixture_dir = Path(fixture_dir)
        self._run_tool(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', 'backing_file=base_old.qcow2,backing_fmt=qcow2,'
                   'cluster_size=65536',
             name, '6M'],
            fixture_dir)
        self._run_tool(
            ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x33 1M 1M', name],
            fixture_dir)
        self._run_tool(
            ['qemu-img', 'snapshot', '-c', 'snap1', name], fixture_dir)
        if post_snapshot_write:
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x44 3M 1M',
                 name],
                fixture_dir)
        return fixture_dir / name

    def _snapshot_readback_sha256(self, fixture_dir, overlay_name, snap):
        """Return the sha256 of a snapshot's virtual view.

        Apply-on-a-copy so the overlay is untouched: copy it
        inside the fixture dir (the relative backing name still
        resolves), `qemu-img snapshot -a`, convert to raw, hash
        the raw bytes.
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

    def test_refuse_safe_rebase_overlay_internal_snapshots(self):
        """Safe-mode rebase of a snapshot-bearing overlay refuses.

        Two shapes, both of which must refuse (the gate keys on
        `nb_snapshots > 0`, not on whether metadata is actually
        snapshot-shared):

        1. snapshot-shared active L2 (psw=no, no write after the
           snapshot) — the corrupting shape from phase-1 Q2:
           safe mode writes new mappings into the shared L2 in
           place and sets refcount=1 on clusters two L1 trees
           reference; a later `qemu-img snapshot -d` frees live
           active-view data (issue #421).
        2. already-COWed active L2 (psw=yes, 0x44 write after
           the snapshot) — phase 1 showed instar matching qemu
           byte-identically here, but the gate refuses anyway.

        qemu-img rebase proceeds on BOTH shapes (its contract
        covers the active view only; the snapshot's virtual view
        silently re-resolves through the new backing). Refusing
        where qemu proceeds is the documented interim divergence
        until phase 7's snapshot-aware COW lands.

        The refusal precedes all staging and writes, so the
        overlay and both backings must be byte-unchanged.
        """
        for shape, post_write in (
                ('snapshot-shared-l2', False),
                ('post-snapshot-write', True)):
            with self.subTest(shape=shape), \
                    tempfile.TemporaryDirectory() as td:
                fixture = Path(td) / 'fixture'
                base_old, base_new = self._build_bases(fixture)
                overlay = self._build_overlay(
                    fixture, 'overlay.qcow2',
                    post_snapshot_write=post_write)
                before = {
                    p: self.sha256(p)
                    for p in (overlay, base_old, base_new)}

                _, stderr, rc = self.run_instar_rebase(
                    overlay, '-b', 'base_new.qcow2', '-F', 'qcow2',
                    timeout=120)
                self.assertNotEqual(
                    rc, 0,
                    f'expected safe-mode rebase of a snapshot-bearing '
                    f'overlay ({shape}) to be refused; stderr={stderr!r}')
                self.assertIn(
                    'the overlay has internal snapshots; a safe-mode '
                    'rebase would corrupt them. Use -u for a '
                    'metadata-only rebase or fall back to '
                    '`qemu-img rebase`',
                    stderr, f'unexpected stderr: {stderr!r}')
                for p, digest in before.items():
                    self.assertEqual(
                        self.sha256(p), digest,
                        f'a refused rebase must not touch {p.name}')

    def test_unsafe_rebase_overlay_internal_snapshots_matches_qemu(self):
        """`-u` rebase of a snapshot-bearing overlay matches qemu-img.

        Metadata-only rebase rewrites only the header's
        backing-pointer region, which is never snapshot-shared,
        so it stays allowed. Twin overlays in one fixture dir
        (shared backing pair), instar `-u` vs qemu-img `-u`:
        exit codes agree, both results are check-clean and
        info-equivalent, and snap1's virtual-view read-back is
        IDENTICAL between the two results. The view legitimately
        CHANGES from pre-rebase — unallocated snapshot ranges
        now resolve through base_new — so the assertion is
        instar-vs-qemu equality, not before/after equality.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / 'fixture'
            self._build_bases(fixture)
            overlay_i = self._build_overlay(
                fixture, 'overlay_i.qcow2', post_snapshot_write=False)
            overlay_q = self._build_overlay(
                fixture, 'overlay_q.qcow2', post_snapshot_write=False)

            _, stderr, rc = self.run_instar_rebase(
                overlay_i, '-u', '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertEqual(
                rc, 0, f'instar rebase -u failed: stderr={stderr!r}')
            self._run_tool(
                ['qemu-img', 'rebase', '-u', '-b', 'base_new.qcow2',
                 '-F', 'qcow2', overlay_q.name],
                fixture)

            for overlay in (overlay_i, overlay_q):
                self._run_tool(
                    ['qemu-img', 'check', overlay.name], fixture,
                    timeout=120)

            actual = self._run_tool(
                ['qemu-img', 'info', '--output=json', str(overlay_i)],
                fixture, timeout=30)
            expected = self._run_tool(
                ['qemu-img', 'info', '--output=json', str(overlay_q)],
                fixture, timeout=30)
            assert_info_equivalent(
                self, actual.stdout, expected.stdout, 'qcow2',
                tmp_path=str(overlay_i),
                expected_tmp_path=str(overlay_q),
                msg='-u rebase of snapshot-bearing overlay (qcow2)')

            self.assertEqual(
                self._snapshot_readback_sha256(
                    fixture, overlay_i.name, 'snap1'),
                self._snapshot_readback_sha256(
                    fixture, overlay_q.name, 'snap1'),
                'snap1 virtual view must change identically on the '
                'instar and qemu-img sides')


# ----------------------------------------------------------------------
# Staged-L2 arena growth (issue #422) — phase 2 step 2d of
# PLAN-qcow2-write-infrastructure.
# ----------------------------------------------------------------------


class TestRebaseStagedL2Growth(TestRebaseSmoke):
    """Safe-mode staged-L2 arena growth regressions (#422).

    Issue #422 presented as a "rebase livelock on 512-byte
    clusters" but was neither cluster-size-specific nor a
    livelock: whenever the comparison loop staged a FRESH L2
    table (a divergent cluster in an L1 entry the overlay left
    zero) and then visited another cluster in that L2's
    coverage, the lookup indexed a slice sized from the INITIAL
    staged-L2 count, panicked out of bounds, and the guest
    panic handler's `loop {}` spun forever at 100% CPU
    (defect A). Fixing the lookup unmasked defect B: the arena
    grew over the staged refcount-block host offsets, which the
    refblock flush dereferences as host WRITE offsets. Both are
    fixed by re-deriving the arena view per access and carving
    the growable arena last in scratch.
    """

    def setUp(self):
        super().setUp()
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    def _run_tool(self, argv, cwd, timeout=60):
        """Run a qemu tool with cwd in the fixture dir; assert rc 0."""
        r = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd))
        self.assertEqual(
            r.returncode, 0,
            f'{argv[0]} failed: argv={argv!r} stderr={r.stderr!r}')
        return r

    def _build_bases(self, fixture_dir, cluster_size):
        """Create the #422 backing pair in `fixture_dir`.

        base_old.qcow2 (64M, 0x11 at [0,4M)) and base_new.qcow2
        (64M, 0x22 at [2M,6M)) at the given cluster size. The
        divergent range [0,6M) spans many clusters so the
        comparison loop revisits a freshly staged L2 repeatedly.
        """
        fixture_dir = Path(fixture_dir)
        fixture_dir.mkdir(parents=True, exist_ok=True)
        for name, pattern in (
                ('base_old.qcow2', 'write -P 0x11 0 4M'),
                ('base_new.qcow2', 'write -P 0x22 2M 4M')):
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', f'cluster_size={cluster_size}', name, '64M'],
                fixture_dir)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', pattern, name],
                fixture_dir, timeout=120)
        return fixture_dir / 'base_old.qcow2', fixture_dir / 'base_new.qcow2'

    def _build_overlay(self, fixture_dir, name, cluster_size,
                       io_command=None):
        """Create a 64M overlay on base_old.qcow2 (relative name).

        With `io_command` None the overlay stays EMPTY: every L1
        entry is zero, so the first divergent cluster forces the
        comparison loop to stage a fresh L2 table — the growth
        shape that hung pre-fix at EVERY cluster size.
        """
        fixture_dir = Path(fixture_dir)
        self._run_tool(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', f'backing_file=base_old.qcow2,backing_fmt=qcow2,'
                   f'cluster_size={cluster_size}',
             name, '64M'],
            fixture_dir)
        if io_command is not None:
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', io_command, name],
                fixture_dir, timeout=120)
        return fixture_dir / name

    def test_512_cluster_safe_rebase_terminates(self):
        """The exact #422 fixture terminates promptly with a refusal.

        64M at 512-byte clusters, overlay owning [1M,2M): safe
        mode wants ~12k copied clusters plus fresh L2 tables,
        which exhausts the overlay's single refcount block's
        coverage (v1 never appends refblocks), so the run must
        REFUSE with ERROR_REFCOUNT_EXHAUSTED — in under a second,
        not the pre-fix infinite `loop {}` (the runner timeout
        helper returns rc -1 on expiry, distinct from any real
        exit code).

        The refusal aborts before any metadata flush, so the
        overlay must still be check-clean and both backings
        byte-unchanged. The overlay FILE may legitimately change:
        the pre-refusal data-cluster writes land in unreferenced
        clusters (byte-idempotence of this path is deferred to
        phase 3's ordering contract).
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / 'fixture'
            base_old, base_new = self._build_bases(fixture, 512)
            overlay = self._build_overlay(
                fixture, 'overlay.qcow2', 512,
                io_command='write -P 0x33 1M 1M')
            backing_before = {
                p: self.sha256(p) for p in (base_old, base_new)}

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertNotEqual(
                rc, -1,
                'safe rebase of the #422 fixture timed out — the '
                'staged-L2 growth hang is back')
            self.assertNotEqual(
                rc, 0,
                f'expected the refcount-exhausted refusal; the rebase '
                f'unexpectedly succeeded: stderr={stderr!r}')
            self.assertIn(
                "the overlay's refcount blocks are full; v1 doesn't "
                'append new ones. Fall back to -u or use '
                '`qemu-img rebase`',
                stderr, f'unexpected stderr: {stderr!r}')

            self._run_tool(
                ['qemu-img', 'check', overlay.name], fixture,
                timeout=120)
            for p, digest in backing_before.items():
                self.assertEqual(
                    self.sha256(p), digest,
                    f'a refused rebase must not touch {p.name}')

    def test_64k_sparse_overlay_safe_rebase_completes(self):
        """Empty overlay at the default cluster size completes.

        The genuinely-fixed silent hang: at 64K clusters one L2
        covers 512M, so an EMPTY 64M overlay stages a single
        fresh L2 for the first divergent cluster and then visits
        ~95 more divergent clusters in its coverage — every one
        of which indexed past the stale slice pre-fix. Twin
        fixtures, instar vs qemu-img rebase: both must complete,
        both must be check-clean, and the rebased virtual
        contents must be identical.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / 'fixture'
            self._build_bases(fixture, 65536)
            overlay_i = self._build_overlay(
                fixture, 'overlay_i.qcow2', 65536)
            overlay_q = self._build_overlay(
                fixture, 'overlay_q.qcow2', 65536)

            _, stderr, rc = self.run_instar_rebase(
                overlay_i, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertEqual(
                rc, 0,
                f'instar safe rebase of an empty 64K overlay must '
                f'complete: stderr={stderr!r}')
            self._run_tool(
                ['qemu-img', 'rebase', '-b', 'base_new.qcow2',
                 '-F', 'qcow2', overlay_q.name],
                fixture, timeout=120)

            for overlay in (overlay_i, overlay_q):
                self._run_tool(
                    ['qemu-img', 'check', overlay.name], fixture,
                    timeout=120)

            self._run_tool(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 overlay_i.name, 'instar.raw'],
                fixture, timeout=120)
            self._run_tool(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 overlay_q.name, 'qemu.raw'],
                fixture, timeout=120)
            self.assertEqual(
                self.sha256(fixture / 'instar.raw'),
                self.sha256(fixture / 'qemu.raw'),
                'rebased virtual content must match qemu-img rebase')


# ----------------------------------------------------------------------
# Overlay classification and capacity tests — phase 5 of
# PLAN-qcow2-write-infrastructure (the safe-mode migration onto
# crates/qcow2-write). New typed refusals (wire codes 15/16),
# the stage-everything capacity widening, and the L2-window
# eviction path.
# ----------------------------------------------------------------------


class TestRebaseOverlayClassification(TestRebaseSmoke):
    """Overlay-side refusals and capacity changes (phase 5)."""

    def setUp(self):
        super().setUp()
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

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
            int.from_bytes(rt[i:i + 8], 'big')
            for i in range(0, len(rt), 8)]

    def test_holed_refcount_table_overlay_refused(self):
        """A holed-refcount-table overlay refuses pre-mutation.

        Replaces a live corruption (divergence R-D4, the rebase
        sibling of GitHub issue #428): the old staging compacted
        non-zero refcount-table entries into a dense array and
        indexed them as dense, so a safe rebase of an overlay
        whose RT had a zero entry below populated ones wrote
        copied data at wrong host offsets and refcounts into the
        wrong refblocks — 1092 `qemu-img check` errors + 32
        leaked clusters at exit 0 on this very recipe. Holed RTs
        are stock-producible (discard history + `qemu-img resize
        --shrink` frees all-zero refblocks below populated ones)
        and pass `qemu-img check` clean. The migrated op stages
        refblocks dense-prefix and gates on RT contiguity: wire
        16, before any image mutation.

        Recipe adapted from the phase-5 probes: qemu >= 10 turns
        discards into zero-plain clusters (which would mask the
        backing), so the divergent region (50M+) stays untouched
        by the discard/shrink history and the backing is attached
        afterwards via a metadata-only `qemu-img rebase -u`.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td)
            overlay = fixture / 'overlay.qcow2'
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=4096', overlay.name, '96M'],
                fixture)
            # Pre-touch 4K every 2M over [0,44M) so the write
            # history populates several refblocks, then discard
            # the middle and shrink: rt[2..4] become holes below
            # the still-populated rt[5].
            touch = []
            for i in range(22):
                touch += ['-c', f'write -P 0x01 {i * 2}M 4k']
            self._run_tool(
                ['qemu-io', '-f', 'qcow2'] + touch + [overlay.name],
                fixture, timeout=120)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x22 0 44M',
                 overlay.name], fixture, timeout=120)
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'discard 8M 32M',
                 overlay.name], fixture, timeout=120)
            self._run_tool(
                ['qemu-img', 'resize', '--shrink', overlay.name, '82M'],
                fixture)

            # Precondition: the RT really is holed (a zero entry
            # below a populated one) and the image is check-clean.
            entries = self._refcount_table_entries(overlay)
            populated = [i for i, e in enumerate(entries) if e]
            self.assertTrue(
                any(entries[i] == 0 for i in range(populated[-1])),
                f'fixture RT is not holed: populated={populated}')
            self._run_tool(
                ['qemu-img', 'check', overlay.name], fixture, timeout=120)

            # Backings diverging over a region the overlay leaves
            # unmapped, attached without touching the RT.
            for name, pattern in (
                    ('base_old.qcow2', 'write -P 0xaa 50M 10M'),
                    ('base_new.qcow2', 'write -P 0xbb 50M 10M')):
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'cluster_size=4096', name, '96M'], fixture)
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2', '-c', pattern, name],
                    fixture, timeout=120)
            self._run_tool(
                ['qemu-img', 'rebase', '-u', '-b', 'base_old.qcow2',
                 '-F', 'qcow2', overlay.name], fixture)

            before = {
                p: self.sha256(fixture / p)
                for p in ('overlay.qcow2', 'base_old.qcow2',
                          'base_new.qcow2')}

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'holed-RT overlay must refuse: stderr={stderr!r}')
            self.assertIn(
                "the overlay's metadata is inconsistent (refcounts, "
                'table flags or layout); refusing to write into it. '
                'Run `qemu-img check` on the overlay, or fall back to '
                '`qemu-img rebase`',
                stderr, f'unexpected stderr: {stderr!r}')

            for name, digest in before.items():
                self.assertEqual(
                    self.sha256(fixture / name), digest,
                    f'the wire-16 refusal must be pre-mutation: '
                    f'{name} changed')

    def test_extended_l2_overlay_refused(self):
        """An extended-L2 overlay refuses pre-mutation (wire 15).

        Replaces a live silent corruption (divergence R-D1): the
        old safe-mode walk hard-coded 8-byte L2 entries, so on an
        extended_l2=on overlay every second "entry" it read was a
        subcluster bitmap — the rebase exited 0 having garbled the
        mapping (old-backing bytes readable at virtual offsets
        that never contained them, 32 leaked clusters). The
        migrated op runs `qcow2_write::check_envelope` on the
        overlay header before any staging or mutation.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td)
            for name, pattern in (
                    ('base_old.qcow2', 'write -P 0x11 1M 4M'),
                    ('base_new.qcow2', 'write -P 0x22 1M 4M')):
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2', name, '16M'],
                    fixture)
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2', '-c', pattern, name],
                    fixture, timeout=120)
            overlay = fixture / 'overlay.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'extended_l2=on,cluster_size=65536',
                 '-b', 'base_old.qcow2', '-F', 'qcow2', overlay.name],
                capture_output=True, text=True, cwd=str(fixture))
            if r.returncode != 0:
                self.skipTest(
                    f'qemu-img cannot create extended_l2 images: '
                    f'{r.stderr!r}')
            self._run_tool(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x33 8M 1M',
                 overlay.name], fixture, timeout=120)

            before = {
                p: self.sha256(fixture / p)
                for p in ('overlay.qcow2', 'base_old.qcow2',
                          'base_new.qcow2')}

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertNotEqual(
                rc, 0,
                f'extended-L2 overlay must refuse: stderr={stderr!r}')
            self.assertIn(
                'the overlay uses features instar rebase does not '
                'support (extended L2 entries, or unknown/compression '
                'feature bits). Use -u for a metadata-only rebase or '
                'fall back to `qemu-img rebase`',
                stderr, f'unexpected stderr: {stderr!r}')

            for name, digest in before.items():
                self.assertEqual(
                    self.sha256(fixture / name), digest,
                    f'the wire-15 refusal must be pre-mutation: '
                    f'{name} changed')

    def test_zstd_overlay_refused(self):
        """A zstd-compression-type overlay refuses (wire 15).

        Deliberate narrowing (spec-mandated, like commit's D1):
        an overlay with the zstd incompatible bit but no actual
        compressed clusters rebased CORRECTLY before this phase —
        the bit is inert without compressed data — but the qcow2
        spec requires refusing writes under unknown/compression
        incompatible bits, and a zstd-compressed cluster would
        have been corrupted. Now a typed pre-mutation refusal.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td)
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2', 'base_new.qcow2',
                 '16M'], fixture)
            overlay = fixture / 'overlay.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compression_type=zstd',
                 '-b', 'base_new.qcow2', '-F', 'qcow2', overlay.name,
                 '16M'],
                capture_output=True, text=True, cwd=str(fixture))
            if r.returncode != 0:
                self.skipTest(
                    f'qemu-img cannot create zstd images: {r.stderr!r}')

            before = {
                p: self.sha256(fixture / p)
                for p in ('overlay.qcow2', 'base_new.qcow2')}

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=120)
            self.assertNotEqual(
                rc, 0, f'zstd overlay must refuse: stderr={stderr!r}')
            self.assertIn(
                'the overlay uses features instar rebase does not '
                'support', stderr, f'unexpected stderr: {stderr!r}')

            for name, digest in before.items():
                self.assertEqual(
                    self.sha256(fixture / name), digest,
                    f'the wire-15 refusal must be pre-mutation: '
                    f'{name} changed')

    def test_many_l2_overlay_capacity_widened(self):
        """A 512-populated-L2 overlay now rebases (was wire 9).

        The R-D6 capacity widening: the old runner staged EVERY
        pre-existing L2 table up front and refused past
        MAX_STAGED_L2 == 256 even when nothing needed copying.
        The migrated runner probes original L2 tables one at a
        time and windows planner-side tables, so this cs=512 /
        64M overlay with 512 populated L2 tables (one 512-byte
        write per 32K of L2 coverage over [0,16M)) and IDENTICAL
        old/new chains succeeds, check-clean and info-equivalent
        to a qemu-img rebase twin.
        """
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td)
            for name in ('base_old.qcow2', 'base_new.qcow2'):
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'cluster_size=512', name, '64M'], fixture)
            writes = []
            for i in range(512):
                writes += ['-c', f'write -P 0x33 {i * 32768} 512']
            for name in ('overlay_i.qcow2', 'overlay_q.qcow2'):
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'backing_file=base_old.qcow2,'
                           'backing_fmt=qcow2,cluster_size=512',
                     name, '64M'], fixture)
                self._run_tool(
                    ['qemu-io', '-f', 'qcow2'] + writes + [name],
                    fixture, timeout=300)

            overlay_i = fixture / 'overlay_i.qcow2'
            _, stderr, rc = self.run_instar_rebase(
                overlay_i, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=300)
            self.assertEqual(
                rc, 0,
                f'many-L2 overlay must now rebase (the R-D6 '
                f'widening): stderr={stderr!r}')
            self._run_tool(
                ['qemu-img', 'rebase', '-b', 'base_new.qcow2',
                 '-F', 'qcow2', 'overlay_q.qcow2'], fixture,
                timeout=300)

            self._run_tool(
                ['qemu-img', 'check', overlay_i.name], fixture,
                timeout=120)

            actual = self._run_tool(
                ['qemu-img', 'info', '--output=json', 'overlay_i.qcow2'],
                fixture)
            expected = self._run_tool(
                ['qemu-img', 'info', '--output=json', 'overlay_q.qcow2'],
                fixture)
            # qemu-img info ran with cwd=fixture, so the JSON
            # carries the relative names; substitute those.
            assert_info_equivalent(
                self, actual.stdout, expected.stdout, 'qcow2',
                tmp_path='overlay_i.qcow2',
                expected_tmp_path='overlay_q.qcow2',
                msg='many-L2 capacity widening (cs=512)')

    def test_eviction_exercising_safe_rebase(self):
        """Safe rebase touching more L2 tables than window slots.

        At cs=64K the migrated runner's L2 window holds 32 slots
        (2 MiB / 64K); one L2 table covers 512M of virtual
        space, so a sparse 17408M overlay with a divergent
        cluster in each of its 34 coverage spans forces at least
        two window evictions mid-loop. The structural safety
        argument (R-D5): the walk never revisits a table, so an
        evicted table is written exactly once and never reloaded
        — content parity with a qemu-img rebase twin proves the
        final bytes.

        Also asserts the deferred header patch landed (the
        backing path names the new backing) — the runtime half
        of the "header bytes unchanged until after flush" review
        item: the header rewrite is deferred metadata applied
        only after the plan_flush epoch.
        """
        size = '17408M'  # 34 x 512M L2-coverage spans at cs=64K
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td)
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=65536', 'base_old.qcow2', size],
                fixture)
            writes = []
            for k in range(34):
                writes += ['-c', f'write -P 0x11 {k * 512}M 64k']
            self._run_tool(
                ['qemu-io', '-f', 'qcow2'] + writes + ['base_old.qcow2'],
                fixture, timeout=300)
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'cluster_size=65536', 'base_new.qcow2', size],
                fixture)
            for name in ('overlay_i.qcow2', 'overlay_q.qcow2'):
                self._run_tool(
                    ['qemu-img', 'create', '-f', 'qcow2',
                     '-o', 'backing_file=base_old.qcow2,'
                           'backing_fmt=qcow2,cluster_size=65536',
                     name, size], fixture)

            overlay_i = fixture / 'overlay_i.qcow2'
            _, stderr, rc = self.run_instar_rebase(
                overlay_i, '-b', 'base_new.qcow2', '-F', 'qcow2',
                timeout=300)
            self.assertEqual(
                rc, 0,
                f'eviction-exercising safe rebase must complete: '
                f'stderr={stderr!r}')
            self._run_tool(
                ['qemu-img', 'rebase', '-b', 'base_new.qcow2',
                 '-F', 'qcow2', 'overlay_q.qcow2'], fixture,
                timeout=300)

            self._run_tool(
                ['qemu-img', 'check', overlay_i.name], fixture,
                timeout=300)

            # The deferred header patch landed: the overlay now
            # names the new backing.
            info = self._run_tool(
                ['qemu-img', 'info', '--output=json',
                 'overlay_i.qcow2'], fixture)
            self.assertEqual(
                json.loads(info.stdout).get('backing-filename'),
                'base_new.qcow2',
                'deferred header/backing-path patch did not land')

            self._run_tool(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 'overlay_i.qcow2', 'instar.raw'], fixture,
                timeout=600)
            self._run_tool(
                ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                 'overlay_q.qcow2', 'qemu.raw'], fixture, timeout=600)
            self.assertEqual(
                self.sha256(fixture / 'instar.raw'),
                self.sha256(fixture / 'qemu.raw'),
                'rebased virtual content must match qemu-img rebase '
                'across L2 window evictions')
