"""Smoke tests for `instar create`.

Phase 3 of PLAN-create.md ships the host CLI subcommand; these
tests confirm end-to-end invocation works for each target format
plus a couple of error and option-flag paths. The comprehensive
matrix (every cluster_size, every refcount_bits, every backing /
preallocation combination, qemu-img info equivalence across the
~80 qemu-img versions) lives in phase 8.

These tests require /dev/kvm access for the non-raw paths.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


class TestCreateSmoke(InstarTestBase):
    """End-to-end smoke tests for `instar create`."""

    def run_instar_create(self, *args, timeout=60):
        """Helper: invoke `instar create` with the given args.

        Returns (stdout, stderr, returncode).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_instar_info(self, path, *, output='human', timeout=30):
        """Helper: invoke `instar info <path>`.

        Returns (stdout, stderr, returncode).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'info']
        if output == 'json':
            cmd += ['--output', 'json']
        cmd.append(str(path))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    # ------------------------------------------------------------------
    # Baseline reachability (phase 8a)
    # ------------------------------------------------------------------

    def test_create_baselines_present(self):
        """Phase 7's baselines must be reachable via get_output_profiles."""
        profiles = self.get_output_profiles(output_type='json', command='create')
        self.assertIn('profiles', profiles)
        self.assertGreater(len(profiles['profiles']), 0,
                           'expected at least one create-info-json profile')
        self.assertIn('version_to_profile', profiles)
        self.assertGreater(len(profiles['version_to_profile']), 0,
                           'expected at least one qemu version in the map')

    # ------------------------------------------------------------------
    # Happy paths: raw + every guest-emitted format default
    # ------------------------------------------------------------------

    def test_create_raw_produces_sparse_file_of_requested_size(self):
        """`-f raw foo.raw 4M` produces a 4 MiB sparse file."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            stdout, stderr, rc = self.run_instar_create('-f', 'raw', str(path), '4M')
            self.assertEqual(rc, 0, f'create raw failed: rc={rc}, stderr={stderr}')
            self.assertTrue(path.exists(), 'raw output file was not created')
            st = path.stat()
            self.assertEqual(st.st_size, 4 * 1024 * 1024,
                             f'raw file size {st.st_size} != 4 MiB')
            # Sparse (no blocks allocated) when preallocation is off.
            self.assertEqual(st.st_blocks, 0,
                             'raw file should be sparse (st_blocks == 0)')
            self.assertIn('Created:', stdout)

    def test_create_raw_falloc_allocates_blocks(self):
        """`-f raw --preallocation falloc` actually reserves blocks."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            _, stderr, rc = self.run_instar_create(
                '-f', 'raw', '--preallocation', 'falloc', str(path), '4M')
            self.assertEqual(rc, 0, f'create raw+falloc failed: rc={rc}, stderr={stderr}')
            st = path.stat()
            self.assertEqual(st.st_size, 4 * 1024 * 1024)
            self.assertGreater(st.st_blocks, 0,
                               'falloc should reserve blocks (st_blocks > 0)')

    def test_create_qcow2_default(self):
        """`-f qcow2 foo.qcow2 16M` produces a parseable qcow2."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create('-f', 'qcow2', str(path), '16M')
            self.assertEqual(rc, 0, f'create qcow2 failed: rc={rc}, stderr={stderr}')
            self.assertTrue(path.exists())
            self._assert_info_reports(path, fmt='qcow2', virtual_size=16 * 1024 * 1024)

    def test_create_vmdk_default(self):
        """`-f vmdk foo.vmdk 16M` produces a parseable monolithicSparse vmdk."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.vmdk'
            _, stderr, rc = self.run_instar_create('-f', 'vmdk', str(path), '16M')
            self.assertEqual(rc, 0, f'create vmdk failed: rc={rc}, stderr={stderr}')
            self._assert_info_reports(path, fmt='vmdk', virtual_size=16 * 1024 * 1024)

    def test_create_vhd_default(self):
        """`-f vpc foo.vhd 16M` produces a parseable dynamic VHD."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.vhd'
            _, stderr, rc = self.run_instar_create('-f', 'vpc', str(path), '16M')
            self.assertEqual(rc, 0, f'create vpc failed: rc={rc}, stderr={stderr}')
            self._assert_info_reports(path, fmt='vpc', virtual_size=16 * 1024 * 1024)

    def test_create_vhdx_default(self):
        """`-f vhdx foo.vhdx 16M` produces a parseable Dynamic VHDX."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.vhdx'
            _, stderr, rc = self.run_instar_create('-f', 'vhdx', str(path), '16M')
            self.assertEqual(rc, 0, f'create vhdx failed: rc={rc}, stderr={stderr}')
            self._assert_info_reports(path, fmt='vhdx', virtual_size=16 * 1024 * 1024)

    # ------------------------------------------------------------------
    # Per-format option flags
    # ------------------------------------------------------------------

    def test_create_qcow2_cluster_size_4k_round_trips(self):
        """`--cluster-size 4096` round-trips through `instar info`."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '--cluster-size', '4096', str(path), '16M')
            self.assertEqual(rc, 0, f'create with --cluster-size failed: {stderr}')
            self._assert_info_reports(
                path, fmt='qcow2', virtual_size=16 * 1024 * 1024,
                cluster_size=4096)

    # ------------------------------------------------------------------
    # Backing files
    # ------------------------------------------------------------------

    def test_create_qcow2_with_backing_defaults_virtual_size(self):
        """`-b parent.qcow2 -F qcow2` defaults child's virtual_size to parent's."""
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.qcow2'
            child = Path(td) / 'child.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(parent), '32M')
            self.assertEqual(rc, 0, f'parent create failed: {stderr}')

            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'parent.qcow2', '-F', 'qcow2',
                str(child))
            self.assertEqual(rc, 0, f'child create failed: {stderr}')
            self._assert_info_reports(
                child, fmt='qcow2', virtual_size=32 * 1024 * 1024,
                backing_file='parent.qcow2')

    def test_create_qcow2_explicit_size_overrides_backing(self):
        """Explicit SIZE wins over backing-derived default."""
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.qcow2'
            child = Path(td) / 'child.qcow2'
            _, _, rc = self.run_instar_create('-f', 'qcow2', str(parent), '32M')
            self.assertEqual(rc, 0)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'parent.qcow2', '-F', 'qcow2',
                str(child), '64M')
            self.assertEqual(rc, 0, f'child create with explicit size failed: {stderr}')
            self._assert_info_reports(
                child, fmt='qcow2', virtual_size=64 * 1024 * 1024)

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def test_create_qcow2_json_output_is_well_formed(self):
        """`--output json` emits a parseable JSON object with the right keys."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            stdout, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '--output', 'json', str(path), '16M')
            self.assertEqual(rc, 0, f'json create failed: {stderr}')
            obj = json.loads(stdout)
            self.assertEqual(obj['format'], 'qcow2')
            self.assertEqual(obj['virtual_size'], 16 * 1024 * 1024)
            self.assertEqual(obj['filename'], str(path))
            self.assertGreater(obj['metadata_bytes_written'], 0)
            self.assertGreaterEqual(obj['file_size_after'], obj['metadata_bytes_written'])
            self.assertEqual(obj['resolved_unit_size'], 65536)

    def test_create_quiet_suppresses_human_output(self):
        """`-q` produces no stdout on success."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            stdout, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-q', str(path), '16M')
            self.assertEqual(rc, 0)
            self.assertEqual(stdout, '', f'-q should be silent, got {stdout!r}')
            self.assertTrue(path.exists())

    # ------------------------------------------------------------------
    # Error paths
    # ------------------------------------------------------------------

    def test_create_qcow2_without_size_or_backing_errors(self):
        """`instar create -f qcow2 foo.qcow2` (no SIZE, no -b) is an error."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create('-f', 'qcow2', str(path))
            self.assertNotEqual(rc, 0,
                                'expected error when neither SIZE nor -b given')
            self.assertIn('SIZE', stderr)
            self.assertFalse(path.exists(),
                             'no file should be created on validation failure')

    def test_create_qcow2_missing_backing_errors_without_u(self):
        """Missing backing without -u rejects up front."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            missing = Path(td) / 'nonexistent.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', str(missing), '-F', 'qcow2', str(path))
            self.assertNotEqual(rc, 0)
            self.assertIn('not accessible', stderr)

    def test_create_raw_rejects_backing(self):
        """`-f raw -b BACKING` is rejected."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.raw'
            parent = Path(td) / 'parent.raw'
            parent.write_bytes(b'\x00' * 4096)
            _, stderr, rc = self.run_instar_create(
                '-f', 'raw', '-b', str(parent), '-u', str(path), '4M')
            self.assertNotEqual(rc, 0)
            self.assertIn('raw', stderr.lower())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_info_reports(self, path, *, fmt, virtual_size,
                             cluster_size=None, backing_file=None):
        """Run `instar info --output json` and assert key fields match."""
        stdout, stderr, rc = self.run_instar_info(path, output='json')
        self.assertEqual(rc, 0, f'info on {path} failed: {stderr}')
        info = json.loads(stdout)
        # info's JSON puts format under "format" at the top level.
        self.assertEqual(info.get('format'), fmt,
                         f'format mismatch: expected {fmt}, got {info!r}')
        self.assertEqual(info.get('virtual-size'), virtual_size,
                         f'virtual-size mismatch for {path}')
        if cluster_size is not None:
            self.assertEqual(info.get('cluster-size'), cluster_size,
                             f'cluster-size mismatch for {path}')
        if backing_file is not None:
            self.assertEqual(info.get('backing-filename'), backing_file,
                             f'backing-filename mismatch for {path}')


class TestCreateOOptions(InstarTestBase):
    """Integration tests for `-o key=value,...` parsing wired through to run_create."""

    def run_instar_create(self, *args, timeout=60):
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_instar_info(self, path, *, timeout=30):
        instar = self.get_instar_binary()
        cmd = [str(instar), 'info', '--output', 'json', str(path)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _info_json(self, path):
        stdout, stderr, rc = self.run_instar_info(path)
        self.assertEqual(rc, 0, f'info on {path} failed: {stderr}')
        return json.loads(stdout)

    # ------------------------------------------------------------------
    # Happy paths
    # ------------------------------------------------------------------

    def test_o_cluster_size_round_trips(self):
        """`-o cluster_size=4k` round-trips through info."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'cluster_size=4k', str(path), '16M')
            self.assertEqual(rc, 0, f'create failed: {stderr}')
            info = self._info_json(path)
            self.assertEqual(info['cluster-size'], 4096)

    def test_o_extended_l2_round_trips(self):
        """`-o extended_l2=on` sets the bit."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'extended_l2=on', str(path), '16M')
            self.assertEqual(rc, 0, f'create failed: {stderr}')
            info = self._info_json(path)
            self.assertTrue(info.get('format-specific', {})
                            .get('data', {}).get('extended-l2', False),
                            f'extended_l2 should be set; got info={info!r}')

    def test_o_size_alone_works_without_positional(self):
        """`-o size=16M` works as the only size source."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'size=16M', str(path))
            self.assertEqual(rc, 0, f'create -o size failed: {stderr}')
            info = self._info_json(path)
            self.assertEqual(info['virtual-size'], 16 * 1024 * 1024)

    def test_o_size_overrides_positional(self):
        """`-o size=64M` wins over positional SIZE=16M."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'size=64M', str(path), '16M')
            self.assertEqual(rc, 0, f'override failed: {stderr}')
            info = self._info_json(path)
            self.assertEqual(info['virtual-size'], 64 * 1024 * 1024,
                             f'-o size should win; got {info}')

    def test_o_backing_file_and_fmt(self):
        """`-o backing_file=...,backing_fmt=qcow2` as an alternative to -b -F."""
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.qcow2'
            child = Path(td) / 'child.qcow2'
            _, _, rc = self.run_instar_create('-f', 'qcow2', str(parent), '32M')
            self.assertEqual(rc, 0, 'parent create failed')
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2',
                '-o', 'backing_file=parent.qcow2,backing_fmt=qcow2',
                str(child))
            self.assertEqual(rc, 0, f'-o backing create failed: {stderr}')
            info = self._info_json(child)
            self.assertEqual(info.get('backing-filename'), 'parent.qcow2')
            self.assertEqual(info['virtual-size'], 32 * 1024 * 1024)

    def test_o_compound_value_with_multiple_keys(self):
        """Comma-separated values parse multiple keys in one -o.

        Uses cluster_size + extended_l2 because both round-trip
        through `instar info`. Note: refcount_bits != 16 currently
        does *not* round-trip — qcow2::create::build_header
        hardcodes refcount_order=4 to match convert's behaviour.
        Phase-1's unit tests document this limitation.
        """
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2',
                '-o', 'cluster_size=4k,extended_l2=on',
                str(path), '16M')
            self.assertEqual(rc, 0, f'compound -o failed: {stderr}')
            info = self._info_json(path)
            self.assertEqual(info['cluster-size'], 4096)
            self.assertTrue(info.get('format-specific', {})
                            .get('data', {}).get('extended-l2', False))

    def test_o_wins_over_individual_flag(self):
        """When both --cluster-size and -o cluster_size are given, -o wins."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2',
                '--cluster-size', '65536',
                '-o', 'cluster_size=4k',
                str(path), '16M')
            self.assertEqual(rc, 0, f'override-flag failed: {stderr}')
            info = self._info_json(path)
            self.assertEqual(info['cluster-size'], 4096,
                             '-o should win over --cluster-size')

    # ------------------------------------------------------------------
    # Error paths
    # ------------------------------------------------------------------

    def test_o_unknown_key_errors(self):
        """`-o nonsense=1` returns non-zero with the unknown-key message."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'nonsense=1', str(path), '16M')
            self.assertNotEqual(rc, 0)
            self.assertIn('nonsense', stderr)
            self.assertIn('qcow2', stderr)

    def test_o_encrypt_key_errors_with_future_work(self):
        """`-o encrypt.cipher=aes` returns the deferred message."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'foo.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'encrypt.cipher=aes', str(path), '16M')
            self.assertNotEqual(rc, 0)
            self.assertIn('encrypt', stderr)
            self.assertIn('deferred', stderr)



class TestCreateBackingChain(InstarTestBase):
    """Phase-5 backing-file polish tests.

    Covers cases the master plan explicitly called out: vhdx-as-
    backing (phase 5a), vmdk-from-vmdk CID round-trip (phase 5b),
    non-recursion through grandparent chains, format-mismatch
    auto-detect, and the new BACKING_SIZE_TOO_LARGE error.
    """

    def run_instar_create(self, *args, timeout=60):
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_instar_info(self, path, *, timeout=30):
        instar = self.get_instar_binary()
        cmd = [str(instar), 'info', '--output', 'json', str(path)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _info_json(self, path):
        stdout, stderr, rc = self.run_instar_info(path)
        self.assertEqual(rc, 0, f'info on {path} failed: {stderr}')
        return json.loads(stdout)

    def test_vhdx_as_backing(self):
        """Phase 5a: create a vhdx parent, use it as backing for a qcow2 child.

        The child's virtual_size should be inferred from the parent
        via VhdxState::init's metadata-region walk.
        """
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.vhdx'
            child = Path(td) / 'child.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vhdx', str(parent), '32M')
            self.assertEqual(rc, 0, f'vhdx parent failed: {stderr}')

            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'parent.vhdx', '-F', 'vhdx', str(child))
            self.assertEqual(rc, 0, f'qcow2-with-vhdx-backing failed: {stderr}')

            info = self._info_json(child)
            self.assertEqual(info['virtual-size'], 32 * 1024 * 1024,
                             f'child should inherit parent size; got {info!r}')
            self.assertEqual(info.get('backing-filename'), 'parent.vhdx')
            self.assertEqual(info.get('backing-filename-format'), 'vhdx')

    def test_vmdk_from_vmdk_parentcid(self):
        """Phase 5b: vmdk-from-vmdk reads the parent's CID into parentCID."""
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.vmdk'
            child = Path(td) / 'child.vmdk'
            _, _, rc = self.run_instar_create('-f', 'vmdk', str(parent), '32M')
            self.assertEqual(rc, 0)
            _, stderr, rc = self.run_instar_create(
                '-f', 'vmdk', '-b', 'parent.vmdk', '-F', 'vmdk', str(child))
            self.assertEqual(rc, 0, f'vmdk-from-vmdk failed: {stderr}')

            # The descriptor's parentCID should match the parent's CID,
            # not the old 0xdeadbeef sentinel.
            parent_bytes = parent.read_bytes()[:1024]
            child_bytes = child.read_bytes()[:1024]
            # Extract CID= from the parent (first 8 hex chars).
            parent_cid = None
            for line in parent_bytes.split(b'\n'):
                if line.startswith(b'CID='):
                    parent_cid = line[4:12]
                    break
            self.assertIsNotNone(parent_cid, 'parent CID line not found')
            # Extract parentCID= from the child.
            child_parent_cid = None
            for line in child_bytes.split(b'\n'):
                if line.startswith(b'parentCID='):
                    child_parent_cid = line[10:18]
                    break
            self.assertIsNotNone(child_parent_cid, 'child parentCID line not found')
            self.assertEqual(
                child_parent_cid, parent_cid,
                f"child's parentCID={child_parent_cid!r} should match "
                f"parent's CID={parent_cid!r} (not deadbeef sentinel)")
            self.assertNotEqual(child_parent_cid, b'deadbeef',
                                'parentCID should no longer be the sentinel')

    def test_backing_chain_non_recursion(self):
        """Three-level chain: child references its immediate parent only.

        instar (like qemu-img) records one backing reference per
        image. info on the child should report `backing-filename=
        parent.qcow2` — not `grandparent.qcow2`.
        """
        with tempfile.TemporaryDirectory() as td:
            grand = Path(td) / 'grandparent.qcow2'
            parent = Path(td) / 'parent.qcow2'
            child = Path(td) / 'child.qcow2'

            _, _, rc = self.run_instar_create('-f', 'qcow2', str(grand), '32M')
            self.assertEqual(rc, 0)
            _, _, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'grandparent.qcow2', '-F', 'qcow2',
                str(parent))
            self.assertEqual(rc, 0)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'parent.qcow2', '-F', 'qcow2', str(child))
            self.assertEqual(rc, 0, f'child create failed: {stderr}')

            info = self._info_json(child)
            self.assertEqual(info.get('backing-filename'), 'parent.qcow2',
                             'child should reference the immediate parent only')
            # virtual_size inherits up the chain via the same lookup.
            self.assertEqual(info['virtual-size'], 32 * 1024 * 1024)

    def test_backing_format_mismatch_auto_detect_wins(self):
        """When -F lies, auto-detect picks the real format from the magic.

        Create a qcow2 file, then `create -b foo.qcow2 -F raw child.qcow2`
        — the guest's first-sector detect-format helper returns qcow2
        from the magic, ignoring the wrong -F hint. The child still
        inherits the parent's virtual_size.
        """
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'parent.qcow2'
            child = Path(td) / 'child.qcow2'
            _, _, rc = self.run_instar_create('-f', 'qcow2', str(parent), '32M')
            self.assertEqual(rc, 0)

            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'parent.qcow2', '-F', 'raw', str(child))
            self.assertEqual(rc, 0,
                             f'auto-detect should override wrong -F: {stderr}')
            info = self._info_json(child)
            self.assertEqual(info['virtual-size'], 32 * 1024 * 1024,
                             'child should inherit real virtual_size')

    def test_backing_too_large_for_target(self):
        """A 4 TiB raw backing exceeds qcow2 cluster_size=512 addressable range.

        Phase 5c's ceiling check should fire, returning
        ERROR_BACKING_SIZE_TOO_LARGE with the actionable hint in
        stderr.
        """
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'big.raw'
            # truncate is the cheapest way to make a 4 TiB sparse file
            with open(parent, 'wb') as f:
                f.truncate(4 * 1024 * 1024 * 1024 * 1024)
            child = Path(td) / 'small.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'big.raw', '-F', 'raw',
                '--cluster-size', '512', str(child))
            self.assertNotEqual(rc, 0, 'expected failure for backing-too-large')
            self.assertIn('too large', stderr.lower())
            self.assertIn('cluster size', stderr.lower())


class TestCreatePreallocation(InstarTestBase):
    """Phase-6 preallocation tests.

    Covers the new accept set: raw + falloc/full, qcow2 +
    metadata/falloc/full, plus rejections for raw+metadata and
    vmdk/vpc/vhdx + non-`off`.
    """

    def run_instar_create(self, *args, timeout=120):
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def test_raw_full_writes_zeros(self):
        """`-f raw --preallocation full` allocates blocks and content is zero."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'r.raw'
            _, stderr, rc = self.run_instar_create(
                '-f', 'raw', '--preallocation', 'full', str(path), '4M')
            self.assertEqual(rc, 0, f'raw + full failed: {stderr}')
            st = path.stat()
            self.assertEqual(st.st_size, 4 * 1024 * 1024)
            # st_blocks counts 512-byte units; expect ≈ size/512.
            self.assertGreaterEqual(st.st_blocks * 512, 4 * 1024 * 1024,
                                    f'raw + full should allocate blocks; '
                                    f'got st_blocks={st.st_blocks}')
            # Whole file should be zero.
            with open(path, 'rb') as f:
                data = f.read()
            self.assertEqual(data, b'\x00' * (4 * 1024 * 1024),
                             'raw + full content should be all zero')

    def test_qcow2_off_stays_sparse(self):
        """`-f qcow2` default (off) produces a small sparse file."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'q.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(path), '64M')
            self.assertEqual(rc, 0, f'qcow2 default failed: {stderr}')
            st = path.stat()
            # Off-mode qcow2 file is just header + L1 + refcount —
            # well under 1 MiB for 64 MiB virtual.
            self.assertLess(st.st_size, 1 * 1024 * 1024,
                            f'qcow2 off should be tiny; got {st.st_size}')

    def test_qcow2_metadata_extends_file(self):
        """`-o preallocation=metadata` extends the file past the data region."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'q.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'preallocation=metadata',
                str(path), '64M')
            self.assertEqual(rc, 0, f'qcow2 metadata failed: {stderr}')
            st = path.stat()
            # File must cover header + metadata + 64 MiB data region.
            self.assertGreaterEqual(st.st_size, 64 * 1024 * 1024,
                                    f'qcow2 metadata file_size={st.st_size} '
                                    f'should cover 64 MiB data region')
            # No host falloc/zero pass — file stays sparse on the data
            # region (single trailing-sector write on most filesystems).
            self.assertLess(st.st_blocks * 512, 64 * 1024 * 1024,
                            f'qcow2 metadata should be sparse; '
                            f'st_blocks={st.st_blocks}')

    def test_qcow2_falloc_reserves_blocks(self):
        """`-o preallocation=falloc` reserves the data region via posix_fallocate."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'q.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'preallocation=falloc',
                str(path), '4M')
            self.assertEqual(rc, 0, f'qcow2 falloc failed: {stderr}')
            st = path.stat()
            self.assertGreaterEqual(st.st_size, 4 * 1024 * 1024)
            # Falloc should reserve ≈ 4 MiB on disk.
            self.assertGreaterEqual(st.st_blocks * 512, 4 * 1024 * 1024,
                                    f'qcow2 falloc should allocate blocks; '
                                    f'st_blocks={st.st_blocks}')

    def test_qcow2_full_writes_zeros(self):
        """`-o preallocation=full` reserves blocks and the data region is zero."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'q.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-o', 'preallocation=full',
                str(path), '4M')
            self.assertEqual(rc, 0, f'qcow2 full failed: {stderr}')
            st = path.stat()
            self.assertGreaterEqual(st.st_blocks * 512, 4 * 1024 * 1024,
                                    f'qcow2 full should allocate blocks; '
                                    f'st_blocks={st.st_blocks}')
            # The trailing 4 MiB data region should be all zero.
            with open(path, 'rb') as f:
                f.seek(st.st_size - 4 * 1024 * 1024)
                data = f.read(4 * 1024 * 1024)
            self.assertEqual(data, b'\x00' * (4 * 1024 * 1024),
                             'qcow2 full data region should be all zero')

    def test_raw_metadata_rejected(self):
        """`-f raw --preallocation metadata` is rejected (raw has no metadata)."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'r.raw'
            _, stderr, rc = self.run_instar_create(
                '-f', 'raw', '--preallocation', 'metadata', str(path), '4M')
            self.assertNotEqual(rc, 0)
            self.assertIn('raw has no metadata', stderr)

    def test_vmdk_metadata_deferred(self):
        """`-f vmdk -o preallocation=metadata` returns the future-work error."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'v.vmdk'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vmdk', '-o', 'preallocation=metadata', str(path), '4M')
            self.assertNotEqual(rc, 0)
            self.assertIn('non-qcow2 preallocation is future work', stderr)
