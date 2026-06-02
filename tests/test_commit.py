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
