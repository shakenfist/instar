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
  contracts. The qcow2 ``-u`` rebase and detach paths run
  end-to-end now that step 4d (KVM guest lifecycle) ships.
  The vmdk and round-trip cases still skip — they need test
  scaffolding (vmdk creation with a backing reference,
  qemu-img round-trip harness) that lives in phase 5 step 5f.

Steps 5d (cross-version baselines in the instar-testdata
repo) and 5e (`TestRebaseBaselineMatrix`) are deferred to a
follow-up; the matrix factory pattern from
`tests/test_resize.py:359` is the template when they land.

Tests run on the host's installed `instar` binary. The
success-path tests require ``/dev/kvm`` access; the error
paths don't.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


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
        """vmdk monolithicSparse `-u` rebase rewrites parentFileNameHint."""
        self.skipTest(
            'vmdk test scaffolding (overlay-with-backing creation) '
            'lands in phase 5 step 5f')

    def test_qcow2_rebase_round_trip_matches_qemu(self):
        """Round-trip: instar's rebased overlay matches qemu-img's."""
        self.skipTest(
            'qemu-img round-trip harness lands in phase 5 step 5f')
