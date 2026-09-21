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
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.info_json import assert_info_equivalent

# ----------------------------------------------------------------------
# Differencing identity readers
#
# These parse the few fields a differencing child records about its
# parent, so a round-trip test can compare the child's claim against the
# parent's own bytes. Kept here rather than reaching for instar itself:
# the point is to check instar's output against the format, not against
# instar's reader.
# ----------------------------------------------------------------------

# VHD footer, big-endian, 512 bytes at the end of the file (with a copy
# at offset 0 for dynamic and differencing disks).
_VHD_FOOTER_SIZE = 512
_VHD_FOOTER_DATA_OFFSET = 16
_VHD_FOOTER_TIMESTAMP = 24
_VHD_FOOTER_DISK_TYPE = 60
_VHD_FOOTER_UUID = 68

# VHD dynamic-disk header, big-endian, at the footer's data_offset.
_VHD_DYN_PARENT_UUID = 40
_VHD_DYN_PARENT_TIMESTAMP = 56

# VHDX headers, little-endian, at fixed offsets.
_VHDX_HEADER_OFFSETS = (64 * 1024, 128 * 1024)
_VHDX_HEADER_SEQUENCE_NUMBER = 8
_VHDX_HEADER_DATA_WRITE_GUID = 32


def _vhd_footer_disk_type(data):
    """The disk_type of the VHD footer at offset 0 (4 == differencing)."""
    return struct.unpack_from('>I', data, _VHD_FOOTER_DISK_TYPE)[0]


def _vhd_footer_identity(data):
    """The (uuid, timestamp) a child of this VHD would record.

    Read from the trailing footer, which every VHD has; the copy at
    offset 0 exists only for dynamic and differencing disks.
    """
    footer = data[-_VHD_FOOTER_SIZE:]
    uuid = footer[_VHD_FOOTER_UUID:_VHD_FOOTER_UUID + 16]
    timestamp = struct.unpack_from('>I', footer, _VHD_FOOTER_TIMESTAMP)[0]
    return uuid, timestamp


def _vhd_child_parent_identity(data):
    """The (parent uuid, parent timestamp) recorded in a VHD child."""
    dyn_offset = struct.unpack_from('>Q', data, _VHD_FOOTER_DATA_OFFSET)[0]
    header = data[dyn_offset:dyn_offset + 1024]
    uuid = header[_VHD_DYN_PARENT_UUID:_VHD_DYN_PARENT_UUID + 16]
    timestamp = struct.unpack_from(
        '>I', header, _VHD_DYN_PARENT_TIMESTAMP)[0]
    return uuid, timestamp


def _fixed_vhd_from(dynamic_path, dest):
    """Write a fixed-subformat VHD carrying a dynamic fixture's identity.

    A fixed VHD is `current_size` bytes of data followed by the
    512-byte footer, with `disk_type` 2 and `data_offset` all-ones --
    and, crucially, *no* copy of the footer at offset 0. That is what
    makes header-only format detection call it raw.

    Built from a fixture's own footer rather than by instar so the
    identity is a real third-party one: every VHD instar writes today
    carries the same constant identity (#566), so a child of an
    instar-written parent would satisfy an identity check by comparing
    zeros to zeros.
    """
    footer = bytearray(Path(dynamic_path).read_bytes()[-_VHD_FOOTER_SIZE:])
    current_size = struct.unpack_from('>Q', footer, 48)[0]
    struct.pack_into('>Q', footer, _VHD_FOOTER_DATA_OFFSET, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into('>I', footer, _VHD_FOOTER_DISK_TYPE, 2)
    # Checksum is the ones' complement of the byte sum with the
    # checksum field zeroed. instar's reader does not validate it, but
    # a fixture that would fail a validating reader is not a fixture.
    struct.pack_into('>I', footer, 64, 0)
    struct.pack_into('>I', footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    with open(dest, 'wb') as f:
        f.truncate(current_size)
        f.seek(current_size)
        f.write(bytes(footer))
    return Path(dest)


def _vhdx_active_data_write_guid(data):
    """The DataWriteGuid of the VHDX's active header.

    The active header is the one with the higher sequence number, with
    header 1 winning a tie -- the same rule instar's reader applies.
    """
    best = None
    for offset in _VHDX_HEADER_OFFSETS:
        if data[offset:offset + 4] != b'head':
            continue
        sequence = struct.unpack_from(
            '<Q', data, offset + _VHDX_HEADER_SEQUENCE_NUMBER)[0]
        if best is None or sequence > best[0]:
            guid_at = offset + _VHDX_HEADER_DATA_WRITE_GUID
            best = (sequence, data[guid_at:guid_at + 16])
    if best is None:
        raise AssertionError('no VHDX header found')
    return best[1]


def _format_guid(raw):
    """Render 16 raw GUID bytes the way VHDX writes parent_linkage.

    Mixed endian: the first three groups are little-endian, the rest
    are byte order as stored, wrapped in braces and lower case.
    """
    d1, d2, d3 = struct.unpack_from('<IHH', raw, 0)
    rest = raw[8:]
    return '{{{:08x}-{:04x}-{:04x}-{}-{}}}'.format(
        d1, d2, d3, rest[:2].hex(), rest[2:].hex())


class TestCreateSmoke(InstarTestBase):
    """End-to-end smoke tests for `instar create`."""

    def run_instar_create(self, *args, timeout=60, cwd=None):
        """Helper: invoke `instar create` with the given args.

        `cwd` runs the command from a directory, so a relative `-b`
        resolves the way a user's would.

        Returns (stdout, stderr, returncode).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'create', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               cwd=str(cwd) if cwd is not None else None)
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

    def _copy_diff_parent(self, name, dest_dir):
        """Copy a third-party differencing parent fixture into dest_dir.

        Copying rather than referencing in place keeps the emitted
        parent path short and relative, and keeps the test from writing
        beside the fixture.

        An absent fixture fails rather than skips. Every end-to-end
        proof that this feature works at all goes through this helper,
        so a skip here would turn the feature's only integration
        coverage green while testing nothing. A missing testdata
        checkout needs no branch of its own: `InstarTestBase._load_manifest`
        already raises in `setUpClass` (tests/base.py), so no test in
        this class runs without one.
        """
        src = (self._testdata_root / 'custom' / 'format-coverage' / name)
        self.assertTrue(
            src.exists(),
            f'testdata is present but the parent fixture is not: {src}')
        dest = Path(dest_dir) / name
        shutil.copyfile(src, dest)
        return dest

    def test_create_vhd_and_vhdx_differencing_round_trip(self):
        """`-f vpc|vhdx -b PARENT` writes a child that names its parent.

        Both planners could always build the metadata for a differencing
        child; what was missing was a parent identity to put in it, so
        the create operation refused `-b` outright. It now reads the
        parent's identity -- a VHD parent's footer `uuid` and
        `timestamp`, a VHDX parent's active-header `DataWriteGuid` --
        and records it in the child. See
        docs/plans/PLAN-differencing.md.

        The parents are third-party fixtures rather than images this
        test creates, deliberately. Every image instar writes today
        carries the same constant identity (#566), so a child instar
        wrote against a parent instar wrote would satisfy an identity
        check by comparing zeros to zeros and would keep passing if the
        plumbing were ripped out. A qemu-img-written parent has a real,
        non-zero identity, so the comparison below can actually fail.
        """
        cases = (
            ('vpc', 'vhd-diff-parent.vhd', 'child.vhd'),
            ('vhdx', 'vhdx-diff-parent.vhdx', 'child.vhdx'),
        )
        for fmt, fixture, child_name in cases:
            with self.subTest(format=fmt):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    child = Path(td) / child_name

                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-F', fmt,
                        str(child), cwd=td)
                    self.assertEqual(
                        rc, 0, f'creating the {fmt} child failed: {stderr}')
                    self.assertTrue(child.exists(),
                                    f'{fmt} -b exited 0 but wrote no child')

                    # instar's own reader sees a child with a parent.
                    stdout, stderr, rc = self.run_instar_info(
                        child, output='json')
                    self.assertEqual(rc, 0, f'info on {child} failed: {stderr}')
                    info = json.loads(stdout)
                    self.assertEqual(info.get('format'), fmt)
                    self.assertEqual(info.get('backing-filename-format'), fmt)
                    # The exact string, not merely that one exists.
                    # `-b parent.name` was typed relative, so both
                    # formats must report it back as typed. VHD did
                    # already -- info reads its parent *unicode name*
                    # field, which the emitter keeps verbatim -- while
                    # VHDX has no such field and info reads the parent
                    # locator, whose `relative_path` key holds the
                    # Windows rendering `.\\parent.vhdx`. Asserting
                    # only that a backing filename existed is what let
                    # `info` report an unopenable path on the VHDX side
                    # while this test stayed green.
                    self.assertEqual(
                        info.get('backing-filename'), parent.name,
                        f'{fmt} child reports a backing filename that is '
                        f'not what -b was given: {info!r}')

                    child_bytes = child.read_bytes()
                    parent_bytes = parent.read_bytes()
                    if fmt == 'vpc':
                        self.assertEqual(
                            _vhd_footer_disk_type(child_bytes), 4,
                            'child VHD disk_type is not differencing')
                        want_uuid, want_ts = _vhd_footer_identity(parent_bytes)
                        self.assertNotEqual(
                            want_uuid, b'\x00' * 16,
                            'parent fixture has a zero uuid, so this test '
                            'cannot tell a real identity from the placeholder')
                        got_uuid, got_ts = _vhd_child_parent_identity(child_bytes)
                        self.assertEqual(
                            got_uuid, want_uuid,
                            'child parent_unique_id does not match the '
                            "parent's footer uuid")
                        self.assertEqual(
                            got_ts, want_ts,
                            'child parent_timestamp does not match the '
                            "parent's footer timestamp")
                    else:
                        guid = _vhdx_active_data_write_guid(parent_bytes)
                        self.assertNotEqual(
                            guid, b'\x00' * 16,
                            'parent fixture has a zero DataWriteGuid, so this '
                            'test cannot tell a real identity from the '
                            'placeholder')
                        linkage = _format_guid(guid)
                        self.assertIn(
                            linkage.encode('utf-16-le'), child_bytes,
                            f'child does not record parent_linkage {linkage}')

    def test_create_vhd_differencing_from_a_fixed_parent(self):
        """A fixed-subformat VHD is a valid differencing parent.

        A fixed VHD carries the `conectix` cookie only in its trailing
        footer, so detecting its format from the first sector alone
        calls it raw -- and a vpc child then gets refused for having a
        non-VHD parent, even though `instar info` reports the same file
        as vpc and instar itself writes fixed VHDs with `-o
        subformat=fixed`. Hyper-V accepts a fixed parent. The probe now
        falls back to the footer, as info, check and resize already do.

        The child is necessarily dynamic: only a dynamic VHD has the
        header and BAT a differencing disk needs. The *parent* is the
        fixed one.
        """
        with tempfile.TemporaryDirectory() as td:
            dynamic = self._copy_diff_parent('vhd-diff-parent.vhd', td)
            parent = _fixed_vhd_from(dynamic, Path(td) / 'fixed-parent.vhd')
            dynamic.unlink()

            # The premise: the first sector says nothing, the footer
            # says VHD. Without the fallback there is nothing to find.
            self.assertNotEqual(
                parent.read_bytes()[:8], b'conectix',
                'a fixed VHD must not carry a footer copy at offset 0, '
                'or this test is not exercising the fallback')
            stdout, stderr, rc = self.run_instar_info(parent, output='json')
            self.assertEqual(rc, 0, f'info on the fixed parent failed: {stderr}')
            self.assertEqual(
                json.loads(stdout).get('format'), 'vpc',
                'instar info does not call this parent vpc, so create '
                'refusing it would not be an inconsistency')

            child = Path(td) / 'child.vhd'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vpc', '-b', parent.name, '-F', 'vpc',
                str(child), cwd=td)
            self.assertEqual(
                rc, 0, f'a fixed VHD parent was refused: {stderr}')

            child_bytes = child.read_bytes()
            self.assertEqual(
                _vhd_footer_disk_type(child_bytes), 4,
                'child VHD disk_type is not differencing')
            want_uuid, want_ts = _vhd_footer_identity(parent.read_bytes())
            self.assertNotEqual(
                want_uuid, b'\x00' * 16,
                'the fixed parent has a zero uuid, so this test cannot '
                'tell a real identity from the placeholder')
            self.assertEqual(
                _vhd_child_parent_identity(child_bytes), (want_uuid, want_ts),
                "child does not record the fixed parent's identity")

    def test_create_differencing_relative_parent_in_a_subdirectory(self):
        """A relative parent with a separator, write and read.

        Every other CLI test passes a bare filename as the relative
        `-b`, so the separator substitution itself was only ever
        exercised at the crate level. The two halves live in different
        crates and run in different guest binaries -- `crates/create`
        renders `/` to `\\` on the way in, `crates/vhdx` renders it
        back on the way out for `info` -- and nothing proved they
        compose until a path had a separator in it to compose over.

        `full-backing-filename` is the assertion that matters. It is
        resolved against the child's own directory, so it is only
        correct if the reported path is the POSIX one; the Windows
        rendering would resolve to `<dir>/.\\sub\\parent.vhdx`, which
        names nothing.
        """
        cases = (
            ('vpc', 'vhd-diff-parent.vhd', 'child.vhd'),
            ('vhdx', 'vhdx-diff-parent.vhdx', 'child.vhdx'),
        )
        for fmt, fixture, child_name in cases:
            with self.subTest(format=fmt):
                with tempfile.TemporaryDirectory() as td:
                    sub = Path(td) / 'sub'
                    sub.mkdir()
                    parent = self._copy_diff_parent(fixture, str(sub))
                    child = Path(td) / child_name
                    typed = f'sub/{parent.name}'

                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', typed, '-F', fmt,
                        str(child), cwd=td)
                    self.assertEqual(
                        rc, 0,
                        f'a {fmt} parent in a subdirectory was refused: '
                        f'{stderr}')

                    # Written in the Windows convention...
                    self.assertIn(
                        f'.\\sub\\{parent.name}'.encode('utf-16-le'),
                        child.read_bytes(),
                        f'a nested relative {fmt} parent did not reach the '
                        f'image as .\\sub\\{parent.name}')

                    # ...and reported back in the POSIX one.
                    stdout, stderr, rc = self.run_instar_info(
                        child, output='json')
                    self.assertEqual(
                        rc, 0, f'info on {child} failed: {stderr}')
                    info = json.loads(stdout)
                    self.assertEqual(
                        info.get('backing-filename'), typed,
                        f'{fmt} child does not report the parent path as '
                        f'typed: {info!r}')
                    resolved = info.get('full-backing-filename')
                    self.assertIsNotNone(
                        resolved,
                        f'{fmt} child reports no resolved parent path')
                    self.assertTrue(
                        Path(resolved).exists(),
                        f'the resolved parent path does not exist, so the '
                        f'reported path is not openable: {resolved!r}')
                    self.assertEqual(
                        Path(resolved).resolve(), parent.resolve(),
                        f'the resolved parent path is not the parent: '
                        f'{resolved!r}')

    def test_create_differencing_absolute_parent_and_absent_hint(self):
        """Two CLI routes the crate-level tests cannot reach.

        The locator's absolute-vs-relative split is pinned byte-wise in
        the create crate, but nothing drove it through the CLI: an
        absolute `-b` must keep its POSIX bytes rather than being
        rendered into the Windows convention a relative one gets.

        And `parent_format_matches` accepts a parent whose format the
        user did not assert, which from the CLI means `-u` in place of
        `-F` -- the only way to omit `-F` at all.
        """
        cases = (('vpc', 'vhd-diff-parent.vhd'), ('vhdx', 'vhdx-diff-parent.vhdx'))
        for fmt, fixture in cases:
            with self.subTest(format=fmt, path='absolute'):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    child = Path(td) / f'child-abs.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', str(parent), '-F', fmt, str(child))
                    self.assertEqual(
                        rc, 0, f'an absolute {fmt} parent was refused: {stderr}')
                    child_bytes = child.read_bytes()
                    self.assertIn(
                        str(parent).encode('utf-16-le'), child_bytes,
                        'the absolute parent path is not recorded verbatim')
                    self.assertNotIn(
                        str(parent).replace('/', '\\').encode('utf-16-le'),
                        child_bytes,
                        'an absolute path was rendered into the Windows '
                        'convention; only relative paths are')
                    # And it reads back verbatim. A VHDX absolute parent
                    # lands under `absolute_win32_path`, the key info
                    # reports without rewriting separators -- the other
                    # branch of the rendering the relative case exercises.
                    stdout, stderr, rc = self.run_instar_info(
                        child, output='json')
                    self.assertEqual(rc, 0, f'info on {child} failed: {stderr}')
                    self.assertEqual(
                        json.loads(stdout).get('backing-filename'),
                        str(parent),
                        f'an absolute {fmt} parent is not reported verbatim')

            with self.subTest(format=fmt, hint='absent'):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    child = Path(td) / f'child-u.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-u',
                        str(child), cwd=td)
                    self.assertEqual(
                        rc, 0,
                        f'-u without -F was refused for {fmt}: {stderr}')
                    stdout, stderr, rc = self.run_instar_info(
                        child, output='json')
                    self.assertEqual(rc, 0, f'info on {child} failed: {stderr}')
                    self.assertEqual(
                        json.loads(stdout).get('backing-filename'),
                        parent.name,
                        f'{fmt} child created with -u reports a backing '
                        f'filename that is not what -b was given')
                    # The relative leg of the locator split, through the
                    # CLI. round_trip.rs pins the bytes the emitters
                    # write, but only this path exercises the seam where
                    # the host embeds the typed path and the guest
                    # normalises it -- which could break without a crate
                    # test noticing.
                    self.assertIn(
                        f'.\\{parent.name}'.encode('utf-16-le'),
                        child.read_bytes(),
                        f'a relative {fmt} parent did not reach the image as '
                        f'.\\{parent.name}')

    def test_create_differencing_refuses_a_backslash_in_a_relative_parent(self):
        """A backslash a user typed cannot be told from one instar wrote.

        A parent locator holds a Windows path, so instar renders `/` as
        `\\` when it fills one. A `\\` already in a POSIX filename is
        then indistinguishable from a separator: `a\\b.vhd` (one file)
        and `a/b.vhd` (a file in a subdirectory) would emit the same
        locator, and a VHDX child has no other record of its parent's
        path to disambiguate with. Refused rather than written.
        """
        cases = (('vpc', 'vhd-diff-parent.vhd'), ('vhdx', 'vhdx-diff-parent.vhdx'))
        for fmt, fixture in cases:
            with self.subTest(format=fmt):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    odd = parent.with_name('back\\slash-' + parent.name)
                    parent.rename(odd)
                    child = Path(td) / f'child.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', odd.name, '-F', fmt,
                        str(child), cwd=td)
                    self.assertNotEqual(
                        rc, 0,
                        f'{fmt} accepted a backslash in a relative parent')
                    self.assertIn('backslash', stderr)
                    self.assertFalse(
                        child.exists(),
                        f'{fmt} refused the parent but still wrote {child}')

    def test_create_vhd_and_vhdx_reject_mismatched_parent_format(self):
        """A differencing child must be the same format as its parent.

        Neither VHD nor VHDX has a way to say "my parent is some other
        format", so a mismatch is refused rather than written as an
        image whose parent can never be resolved. Detection decides:
        the `-F` hint is only populated when the user passes one, and a
        hint that the parent's bytes disprove is refused too.
        """
        cases = (
            ('vpc', 'vhdx-diff-parent.vhdx', 'vhdx', 'child.vhd'),
            ('vhdx', 'vhd-diff-parent.vhd', 'vpc', 'child.vhdx'),
            # The bytes are a VHD and the target is vpc, but the user
            # asserted qcow2; refuse rather than silently prefer the
            # bytes and hide the mistake.
            ('vpc', 'vhd-diff-parent.vhd', 'qcow2', 'child.vhd'),
        )
        for fmt, fixture, hint, child_name in cases:
            with self.subTest(format=fmt, parent=fixture, hint=hint):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    child = Path(td) / child_name
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-F', hint,
                        str(child), cwd=td)
                    self.assertNotEqual(rc, 0)
                    self.assertIn('required parent', stderr)
                    self.assertFalse(
                        child.exists(),
                        f'{fmt} mismatch was refused but still wrote {child}')

    def test_create_honours_an_explicit_raw_backing_hint(self):
        """`-F raw` stops the probe second-guessing the user.

        A fixed VHD has no `conectix` at offset 0, so header detection
        calls it raw and the footer fallback reclassifies it as VHD.
        That is what makes a fixed parent usable for a differencing
        child -- but it must not override a user who said `-F raw`,
        because the hint is also what the child records as its backing
        format. Sizing the parent from a VHD footer while writing
        `raw` into the child's metadata would have the two disagree by
        the footer's 512 bytes.

        The two readings of the same file differ, which is what makes
        this test able to fail: the VHD reading is the footer's
        `current_size`, the raw reading is the whole file.

        `-u` is checked here too, and takes the *other* answer: it
        asserts nothing about the format, so the fallback still
        applies. Only a literal `-F raw` suppresses it.
        """
        with tempfile.TemporaryDirectory() as td:
            dynamic = self._copy_diff_parent('vhd-diff-parent.vhd', td)
            parent = _fixed_vhd_from(dynamic, Path(td) / 'fixed.vhd')
            dynamic.unlink()
            current_size = struct.unpack_from(
                '>Q', parent.read_bytes()[-_VHD_FOOTER_SIZE:], 48)[0]
            file_len = parent.stat().st_size
            self.assertEqual(
                file_len, current_size + _VHD_FOOTER_SIZE,
                'the two readings must differ or this test cannot fail')

            def child_size(name, *hint):
                child = Path(td) / name
                _, stderr, rc = self.run_instar_create(
                    '-f', 'qcow2', '-b', parent.name, *hint,
                    str(child), cwd=td)
                self.assertEqual(
                    rc, 0, f'{" ".join(hint)} was refused: {stderr}')
                stdout, stderr, rc = self.run_instar_info(
                    child, output='json')
                self.assertEqual(rc, 0, stderr)
                return json.loads(stdout)['virtual-size']

            self.assertEqual(
                child_size('as-vpc.qcow2', '-F', 'vpc'), current_size,
                'a vpc-hinted parent was not sized from its footer')
            self.assertGreaterEqual(
                child_size('as-raw.qcow2', '-F', 'raw'), file_len,
                'a raw-hinted parent was sized from its VHD footer, so the '
                'child records a backing format the probe disagreed with')

            # `-u` is not `-F raw`. It says "do not fail if the backing
            # file is inaccessible" and asserts nothing about the
            # format, so the footer fallback still applies and the
            # parent is sized as a VHD. Pinned because the two
            # spellings of "assume raw" behaving differently is a trap,
            # and because documenting it (docs/create.md) without a
            # test would leave the claim unchecked.
            self.assertEqual(
                child_size('as-unsafe.qcow2', '-u'), current_size,
                '-u suppressed the footer fallback; it asserts nothing '
                'about the format, so only -F raw should')

    def test_create_differencing_refuses_a_size_that_is_not_the_parents(self):
        """A differencing child inherits its parent's size, or is refused.

        The child stores only the blocks that differ and reads every
        other block from the parent at the same offset, so a chain
        whose two images describe different disks cannot be composed.

        The case that bites is not a deliberate mismatch: qemu-img
        rounds a VHD's virtual size up to CHS geometry and instar does
        not, so a parent qemu-img created as 64M declares 67,125,248
        bytes and `-b parent.vhd ... 64M` disagrees with it by 16,384.
        """
        for fmt, fixture in (('vpc', 'vhd-diff-parent.vhd'),
                             ('vhdx', 'vhdx-diff-parent.vhdx')):
            with self.subTest(format=fmt):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(fixture, td)
                    if fmt == 'vpc':
                        parent_size = struct.unpack_from(
                            '>Q', parent.read_bytes()[-_VHD_FOOTER_SIZE:], 48)[0]
                    else:
                        stdout, _, rc = self.run_instar_info(
                            parent, output='json')
                        self.assertEqual(rc, 0)
                        parent_size = json.loads(stdout)['virtual-size']

                    # A size that is not the parent's is refused...
                    child = Path(td) / f'wrong.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-F', fmt,
                        str(child), str(parent_size + 1024 * 1024), cwd=td)
                    self.assertNotEqual(
                        rc, 0,
                        f'{fmt} accepted a size that is not the parent\'s')
                    self.assertIn('same virtual size as its', stderr)
                    self.assertFalse(child.exists())

                    # ...the parent's own size is accepted...
                    exact = Path(td) / f'exact.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-F', fmt,
                        str(exact), str(parent_size), cwd=td)
                    self.assertEqual(
                        rc, 0,
                        f'{fmt} refused the parent\'s own size: {stderr}')

                    # ...and omitting it inherits.
                    inherited = Path(td) / f'inherit.{fmt}'
                    _, stderr, rc = self.run_instar_create(
                        '-f', fmt, '-b', parent.name, '-F', fmt,
                        str(inherited), cwd=td)
                    self.assertEqual(rc, 0, stderr)
                    stdout, _, rc = self.run_instar_info(
                        inherited, output='json')
                    self.assertEqual(rc, 0)
                    self.assertEqual(
                        json.loads(stdout)['virtual-size'], parent_size,
                        f'{fmt} child did not inherit the parent size')

    def test_create_accepts_a_backing_image_it_cannot_size(self):
        """An unsizeable parent is only fatal where a size is needed.

        The backing probe runs whenever `-b` is given (#579), but what
        it could not determine is not automatically an error: qcow2 and
        vmdk record a parent by path and never ask how big it is. These
        all worked on develop with an explicit size, and under qemu-img,
        so refusing them would be a regression rather than a new check.
        """
        # vmdk and vdi are in every qemu-img the project targets, but
        # qed is not: the RHEL-family builds omit that driver, so the
        # arm is asked for only where the host can drive it. This is a
        # capability check and not a version one -- Rocky 9, Rocky 10
        # and Fedora all ship qemu-img 10.1.0 and only Fedora has qed.
        wanted = [
            ('flat.vmdk', ('-f', 'vmdk', '-o',
                           'subformat=monolithicFlat')),
            ('disk.vdi', ('-f', 'vdi',)),
        ]
        if self.qemu_img_supports_format('qed'):
            wanted.append(('disk.qed', ('-f', 'qed',)))

        with tempfile.TemporaryDirectory() as td:
            parents = {}
            for name, args in wanted:
                path = Path(td) / name
                r = subprocess.run(
                    ['qemu-img', 'create', *args, str(path), '8M'],
                    capture_output=True, text=True)
                if r.returncode == 0 and path.exists():
                    parents[name] = path
            # Whatever survived the capability check is then required in
            # full. Keeping whichever parents qemu-img happened to manage
            # would let this narrow to one format and still report green,
            # hiding a regression in the arms it stopped covering.
            missing = sorted({n for n, _ in wanted} - set(parents))
            self.assertEqual(
                missing, [],
                f'qemu-img did not create {missing}; the probe arms for those '
                f'formats would go unexercised')

            for name, parent in parents.items():
                with self.subTest(parent=name):
                    child = Path(td) / f'child-{name}.qcow2'
                    _, stderr, rc = self.run_instar_create(
                        '-f', 'qcow2', '-b', str(parent), '-u',
                        str(child), '8M')
                    self.assertEqual(
                        rc, 0,
                        f'a qcow2 child of {name} with an explicit size was '
                        f'refused: {stderr}')
                    self.assertTrue(child.exists())

                    # Without a size there is nothing to infer, so this
                    # one is refused -- and that is the only reason.
                    nosize = Path(td) / f'nosize-{name}.qcow2'
                    _, stderr, rc = self.run_instar_create(
                        '-f', 'qcow2', '-b', str(parent), '-u', str(nosize))
                    self.assertNotEqual(
                        rc, 0,
                        f'{name} yielded a size it cannot have')

    def test_create_differencing_names_a_corrupt_parent_as_corrupt(self):
        """A parent of the right format that will not parse says so.

        A dynamic VHD carries a copy of its footer at offset 0, so
        header detection still calls a footerless one `vpc` -- the
        format is right, and only the trailing structures are gone.
        Before this, the probe returned that format with no identity,
        `parent_format_matches` passed it, and the refusal surfaced
        from `vhd_opts_from` as a *format mismatch*: telling the user
        their VHD parent is not a VHD, which is false and gives them
        nothing to act on.

        The ordering is the substance of the test. A genuinely
        wrong-format parent must still be reported as a mismatch, so
        the mismatch check has to run first and only a parent that
        passed it can be diagnosed as corrupt.

        Both cases carry an explicit SIZE, and that is load-bearing
        rather than incidental. Omitting it reaches
        `ERROR_BACKING_PARSE_FAILED` by an entirely different route --
        a size was asked for and the probe could not supply one -- so a
        no-size version of this test passes whether the parse-failure
        diagnosis exists or not. Mutating the guard away is what
        surfaced that; it is the only reason the sizes are here.
        """
        with tempfile.TemporaryDirectory() as td:
            parent = self._copy_diff_parent('vhd-diff-parent.vhd', td)
            intact = parent.read_bytes()

            # Truncating the trailing footer leaves the offset-0 copy,
            # so the file still detects as vpc.
            truncated = Path(td) / 'truncated.vhd'
            truncated.write_bytes(intact[:-_VHD_FOOTER_SIZE])
            child = Path(td) / 'child.vhd'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vpc', '-b', truncated.name, '-F', 'vpc',
                str(child), '16M', cwd=td)
            self.assertNotEqual(rc, 0, 'a footerless VHD parent was accepted')
            self.assertIn(
                'could not be parsed', stderr,
                f'a corrupt VHD parent was not diagnosed as corrupt: {stderr}')
            # Named honestly, too. This parent's *header* parsed
            # perfectly -- it is the trailing footer that is gone -- so
            # a message blaming the header is false in the same way the
            # format-mismatch one it replaced was. Asserting only the
            # substring above passes on either wording.
            self.assertIn(
                'footer', stderr,
                f'the parse failure blames the header alone, but this '
                f'parent lost its footer: {stderr}')
            self.assertNotIn(
                'does not match the target format', stderr,
                'a VHD parent was reported as not being a VHD')

            # ...and the other side of the ordering: a parent that
            # really is the wrong format still says so. `-F` is not
            # optional here -- the CLI refuses to guess a backing
            # format -- so the hint agrees with the bytes and the
            # refusal comes from the target/parent rule alone.
            qcow2_parent = Path(td) / 'parent.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', str(qcow2_parent), '64M'],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            child2 = Path(td) / 'child2.vhd'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vpc', '-b', qcow2_parent.name, '-F', 'qcow2',
                str(child2), '64M', cwd=td)
            self.assertNotEqual(rc, 0, 'a qcow2 parent was accepted for a vpc child')
            self.assertIn(
                'does not match the target format', stderr,
                f'a wrong-format parent lost its mismatch diagnosis: {stderr}')

    def test_create_vpc_fixed_subformat_still_refuses_backing(self):
        """A differencing child is necessarily dynamic.

        Only a dynamic VHD has the header and BAT a parent reference
        lives in. Documented in docs/create.md; this pins it now that
        `-b` is accepted for vpc at all, and that `vhd_opts_from` runs
        before `plan_vhd`'s Fixed arm can reach it.
        """
        with tempfile.TemporaryDirectory() as td:
            parent = self._copy_diff_parent('vhd-diff-parent.vhd', td)
            child = Path(td) / 'child.vhd'
            _, stderr, rc = self.run_instar_create(
                '-f', 'vpc', '-o', 'subformat=fixed', '-b', parent.name,
                '-F', 'vpc', str(child), cwd=td)
            self.assertNotEqual(
                rc, 0, 'a fixed VHD was created with a backing file')
            self.assertIn('invalid option', stderr)
            self.assertFalse(child.exists())

    def test_create_backing_checks_run_with_explicit_size(self):
        """An explicit SIZE does not skip the checks on the parent.

        The backing probe used to run only when the virtual size had to
        be inferred from the parent, so passing a size skipped the
        differencing refusal, the parse check and the format detection
        alike (#579). A differencing parent is refused either way now.
        """
        for args in ((), ('64M',)):
            with self.subTest(size=args or 'inferred'):
                with tempfile.TemporaryDirectory() as td:
                    parent = self._copy_diff_parent(
                        'vhd-differencing.vhd', td)
                    child = Path(td) / 'child.qcow2'
                    _, stderr, rc = self.run_instar_create(
                        '-f', 'qcow2', '-b', parent.name, '-F', 'vpc',
                        str(child), *args, cwd=td)
                    self.assertNotEqual(
                        rc, 0,
                        'a differencing parent was accepted with '
                        f'args={args!r}')
                    self.assertIn('differencing', stderr)
                    self.assertFalse(
                        child.exists(),
                        f'refused but still wrote {child}')

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
        through `instar info`. (refcount_bits != 16 also round-trips
        now that build_header derives refcount_order from
        refcount_bits — instar #365.)
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


# ----------------------------------------------------------------------
# Phase 8b: cross-version baseline matrix
# ----------------------------------------------------------------------
#
# Mirror of instar-testdata/scripts/generate-baselines.py:CREATE_CASES.
# Each entry: (case_name, size_str, options_list).
#
# Drift between this mirror and the generator is caught by
# TestCreateBaselineMatrix.test_create_cases_match_baselines.
CREATE_CASES = {
    'qcow2': [
        ('1M-default',              '1M',  []),
        ('64M-default',             '64M', []),
        ('1G-default',              '1G',  []),
        ('1G-cs-512',               '1G',  ['cluster_size=512']),
        ('1G-cs-4k',                '1G',  ['cluster_size=4k']),
        ('1G-cs-64k',               '1G',  ['cluster_size=64k']),
        ('1G-cs-1M',                '1G',  ['cluster_size=1M']),
        ('1G-cs-2M',                '1G',  ['cluster_size=2M']),
        ('1G-rb-1',                 '1G',  ['refcount_bits=1']),
        ('1G-rb-8',                 '1G',  ['refcount_bits=8']),
        ('1G-rb-64',                '1G',  ['refcount_bits=64']),
        ('1G-extended-l2',          '1G',  ['extended_l2=on,cluster_size=64k']),
        ('64M-extended-l2',         '64M', ['extended_l2=on,cluster_size=64k']),
        ('1G-compat-v2',            '1G',  ['compat=0.10']),
        ('1G-lazy-refcounts',       '1G',  ['lazy_refcounts=on']),
        ('1G-zstd',                 '1G',  ['compression_type=zstd']),
        ('1M-prealloc-metadata',    '1M',  ['preallocation=metadata']),
        ('1M-prealloc-falloc',      '1M',  ['preallocation=falloc']),
        ('1M-prealloc-full',        '1M',  ['preallocation=full']),
    ],
    'vmdk': [
        ('1M-default',              '1M',  []),
        ('64M-default',             '64M', []),
        ('1G-default',              '1G',  []),
        ('1G-stream-optimized',     '1G',  ['subformat=streamOptimized']),
        ('1G-monolithic-sparse',    '1G',  ['subformat=monolithicSparse']),
    ],
    'vhd': [
        ('1M-default',              '1M',  []),
        ('64M-default',             '64M', []),
        ('1G-default',              '1G',  []),
        ('1M-fixed',                '1M',  ['subformat=fixed']),
        ('16M-fixed',               '16M', ['subformat=fixed']),
    ],
    'vhdx': [
        ('1M-default',              '1M',  []),
        ('64M-default',             '64M', []),
        ('1G-default',              '1G',  []),
        ('1G-block-16M',            '1G',  ['block_size=16M']),
        ('1G-block-32M',            '1G',  ['block_size=32M']),
    ],
    'raw': [
        ('1M-default',              '1M',  []),
        ('1G-default',              '1G',  []),
    ],
}


def _instar_target_name(target):
    """Translate the CREATE_CASES key to instar's CLI -f value.

    The case-dict key follows the on-disk baseline directory name
    (which mirrors instar's user-facing format vocabulary). instar
    itself accepts 'vpc' for the VHD format, matching qemu-img's
    canonical name; the dict uses 'vhd' for symmetry with
    PLAN-create-phase-07-baselines.md.
    """
    return 'vpc' if target == 'vhd' else target


# Cases where instar's writer is known to diverge from qemu-img's writer
# in a documented way. Each entry maps (target, case_name) to a reason
# the test skips. These should shrink over time as instar gains feature
# parity; in the meantime the divergence is on the record.
#
# A case NOT in this dict that fails baseline comparison is a real
# regression (a new divergence between instar and qemu-img) and must
# be investigated rather than added to the dict to make CI green.
KNOWN_WRITER_DIVERGENCES = {
    # NOTE: the qcow2 refcount_bits cases ('1G-rb-1', '1G-rb-8',
    # '1G-rb-64') were removed once build_header began deriving
    # refcount_order from refcount_bits (and set_refcount_to_one was
    # corrected to LSB-first) — instar now emits the requested width and
    # matches qemu (instar #365).
    # qcow2: build_header hardcodes compat=1.1; -o compat=0.10 is ignored.
    ('qcow2', '1G-compat-v2'): 'instar hardcodes compat=1.1',
    # qcow2: compression_type=zstd is accept-ignored, header records zlib.
    ('qcow2', '1G-zstd'): 'instar accept-ignores compression_type=zstd',
    # vhdx: default block_size differs (instar 8 MiB vs qemu 32 MiB) for
    # virtual sizes ≤ 1 GiB. Explicit block_size cases (1G-block-16M,
    # 1G-block-32M) round-trip correctly.
    ('vhdx', '1M-default'):  'instar default block_size differs from qemu',
    ('vhdx', '64M-default'): 'instar default block_size differs from qemu',
    ('vhdx', '1G-default'):  'instar default block_size differs from qemu',
    # vhd: qemu-img rounds virtual_size up to the next CHS-aligned
    # multiple (legacy geometry layout); instar uses the exact byte
    # count. Both files are valid VHDs but report different
    # virtual-size values in qemu-img info.
    ('vhd', '1M-default'):  'qemu rounds VHD virtual_size to CHS geometry',
    ('vhd', '64M-default'): 'qemu rounds VHD virtual_size to CHS geometry',
    ('vhd', '1G-default'):  'qemu rounds VHD virtual_size to CHS geometry',
    ('vhd', '1M-fixed'):    'qemu rounds VHD virtual_size to CHS geometry',
    ('vhd', '16M-fixed'):   'qemu rounds VHD virtual_size to CHS geometry',
}


class TestCreateBaselineMatrix(TestCreateSmoke):
    """Cross-version baseline comparison for every (target, case) pair.

    For each entry in CREATE_CASES the test runs ``instar create`` then
    ``qemu-img info --output=json`` on the produced file, normalises both
    sides via the divergence whitelist, and asserts byte-equivalence
    against the version-matched baseline recorded in instar-testdata.

    Reads the derived profile for the host's qemu-img, the same way
    every other output type does. This class used to bypass the profile
    layer and read the raw per-target buckets, because
    ``detect-profiles.py`` flat-copied into ``profiles/profile-NN/``
    under bare case names and the five targets' shared cases
    (1M-default, 64M-default, 1G-default) silently overwrote each other,
    leaving only vmdk. The generator now names create-info-json profile
    files ``<target>-<case>``, so the workaround is gone.
    """

    @classmethod
    def _profile_dir(cls, profile):
        return (cls._testdata_root / 'expected-outputs' /
                'create-info-json' / 'profiles' / profile)

    def _baseline_profile(self):
        """Resolve the create-info-json profile matching the host qemu."""
        return self.get_profile_for_installed_qemu('json', 'create')

    def _baseline_path(self, target, case_name, suffix):
        """Path to one baseline file, or None when it isn't recorded.

        create-info-json qualifies every profile filename with its
        target bucket, so ``vhd-`` and ``vhdx-`` stay distinct and a
        name is derivable from (target, case) without listing the
        directory.
        """
        p = self._profile_dir(self._baseline_profile()) / (
            f'{target}-{case_name}.{suffix}')
        return p if p.exists() else None

    def _baseline_stdout(self, target, case_name):
        return self._baseline_path(target, case_name, 'stdout.txt')

    def _baseline_meta(self, target, case_name):
        p = self._baseline_path(target, case_name, 'meta.json')
        if p is None:
            return None
        with open(p) as f:
            return json.load(f)

    @staticmethod
    def _args_for_case(target, case):
        case_name, size_str, options_list = case
        # instar's CLI uses 'vpc' for VHD; the CREATE_CASES key uses
        # 'vhd' for symmetry with the baseline directory layout.
        args = ['-f', _instar_target_name(target)]
        for opt in options_list:
            args.extend(['-o', opt])
        # Filename + size positional — appended by caller (needs tempdir).
        return args, case_name, size_str

    @staticmethod
    def _run_qemu_img_info(path, timeout=30):
        """Run system qemu-img info --output=json. No -f flag so the
        auto-detect path matches what phase 7's generator recorded.
        Returns (stdout, stderr, rc).
        """
        try:
            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(path)],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return '', 'qemu-img not installed', -1
        except subprocess.TimeoutExpired:
            return '', f'qemu-img info timeout after {timeout}s', -1

    def test_create_cases_match_baselines(self):
        """Every baseline on disk must have a matching CREATE_CASES entry.

        Walks the host's create-info-json profile and asserts that, for
        each target, the set of <target>-<case>.stdout.txt files matches
        the case-name set in CREATE_CASES[target]. Catches drift between
        this mirror and the generator.
        """
        profile_dir = self._profile_dir(self._baseline_profile())
        if not profile_dir.is_dir():
            self.skipTest(f'no create-info-json profile at {profile_dir}')

        for target, cases in CREATE_CASES.items():
            prefix = f'{target}-'
            on_disk = {
                p.name[len(prefix):-len('.stdout.txt')]
                for p in profile_dir.glob(f'{prefix}*.stdout.txt')
            }
            if not on_disk:
                self.skipTest(f'no baselines for target {target}')
            in_mirror = {c[0] for c in cases}
            missing_from_mirror = on_disk - in_mirror
            missing_from_disk = in_mirror - on_disk
            self.assertEqual(
                missing_from_mirror, set(),
                f'{target}: baselines on disk not in CREATE_CASES: '
                f'{missing_from_mirror}'
            )
            self.assertEqual(
                missing_from_disk, set(),
                f'{target}: CREATE_CASES entries with no baseline: '
                f'{missing_from_disk}. Regenerate baselines via '
                f'instar-testdata.'
            )


def _make_baseline_test(target, case):
    """Factory: one test method per (target, case)."""
    case_name = case[0]

    def test(self):
        known = KNOWN_WRITER_DIVERGENCES.get((target, case_name))
        if known is not None:
            self.skipTest(f'known writer divergence: {known}')
        baseline_path = self._baseline_stdout(target, case_name)
        if baseline_path is None:
            self.skipTest(
                f'no baseline for {target}/{case_name} '
                f'(installed qemu version not in matrix?)'
            )
        meta = self._baseline_meta(target, case_name)
        if meta is None:
            self.skipTest(f'no meta.json for {target}/{case_name}')
        if meta.get('create_return_code', 0) != 0:
            self.skipTest(
                f'baseline has create_return_code='
                f'{meta["create_return_code"]} (qemu-img rejected case)'
            )
        if meta.get('info_return_code', 0) != 0:
            self.skipTest(
                f'baseline has info_return_code='
                f'{meta["info_return_code"]} (no comparable JSON)'
            )

        args, _, size_str = self._args_for_case(target, case)
        with tempfile.TemporaryDirectory() as td:
            ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk', 'vhd': 'vhd',
                   'vhdx': 'vhdx', 'raw': 'raw'}[target]
            tmp_path = Path(td) / f'image.{ext}'
            full_args = [*args, str(tmp_path), size_str]
            stdout, stderr, rc = self.run_instar_create(*full_args)
            self.assertEqual(
                rc, 0,
                f'instar create failed for {target}/{case_name}: '
                f'stderr={stderr}'
            )
            info_stdout, info_stderr, info_rc = self._run_qemu_img_info(
                tmp_path)
            if info_rc == -1 and 'not installed' in info_stderr:
                self.skipTest('system qemu-img not installed')
            self.assertEqual(
                info_rc, 0,
                f'qemu-img info failed on instar output for '
                f'{target}/{case_name}: stderr={info_stderr}'
            )
            expected = baseline_path.read_text()
            assert_info_equivalent(
                self, info_stdout, expected, target,
                tmp_path=str(tmp_path),
                msg=f'{target}/{case_name}',
            )

    test.__name__ = (
        f'test_baseline_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar create -f {target} {" ".join(case[2])} {case[1]} '
        f'matches phase-7 baseline.'
    )
    return test


for _target, _cases in CREATE_CASES.items():
    for _case in _cases:
        _name = (
            f'test_baseline_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(
            TestCreateBaselineMatrix, _name,
            _make_baseline_test(_target, _case),
        )


# ----------------------------------------------------------------------
# Phase 8c: instar-vs-qemu-img cross-validation via instar info
# ----------------------------------------------------------------------
#
# Curated subset of CREATE_CASES chosen to avoid the known writer
# divergences. Each test creates the same image twice — once with
# `instar create`, once with the system `qemu-img create` — then runs
# `instar info --output=json` on both and asserts the normalised dicts
# match. Validates the master-plan contract that "instar create |
# instar info ≡ qemu-img create | instar info" (modulo the divergence
# whitelist) on the live system qemu-img rather than against frozen
# baselines.
CROSS_VALIDATION_CASES = [
    ('qcow2', ('1M-default',          '1M', [])),
    ('qcow2', ('1G-default',          '1G', [])),
    ('qcow2', ('1G-cs-64k',           '1G', ['cluster_size=64k'])),
    ('qcow2', ('1G-extended-l2',      '1G', ['extended_l2=on,cluster_size=64k'])),
    ('qcow2', ('1G-lazy-refcounts',   '1G', ['lazy_refcounts=on'])),
    ('vmdk',  ('1M-default',          '1M', [])),
    ('vmdk',  ('1G-default',          '1G', [])),
    ('vmdk',  ('1G-stream-optimized', '1G', ['subformat=streamOptimized'])),
    ('vhdx',  ('1G-block-16M',        '1G', ['block_size=16M'])),
    ('vhdx',  ('1G-block-32M',        '1G', ['block_size=32M'])),
    ('raw',   ('1M-default',          '1M', [])),
    ('raw',   ('1G-default',          '1G', [])),
]


class TestCreateCrossValidation(TestCreateSmoke):
    """Runtime cross-validation against the system qemu-img.

    Compares `instar create | instar info` to `qemu-img create | instar
    info` on the live system qemu-img — no baseline lookup. Catches
    writer divergences that surface against the *currently installed*
    qemu-img version rather than the frozen phase-7 matrix. Independent
    of the testdata repo.

    The same KNOWN_WRITER_DIVERGENCES set applies: if instar's writer
    deliberately picks a different layout from qemu's, this surface
    will also fail. Skip via the dict; do not extend it to silence new
    failures.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            r = subprocess.run(['qemu-img', '--version'],
                               capture_output=True, text=True)
            cls._system_qemu_available = (r.returncode == 0)
        except FileNotFoundError:
            cls._system_qemu_available = False

    def _run_qemu_create(self, target, size_str, options_list, out_path,
                         timeout=60):
        """Invoke the system qemu-img create. Returns (stdout, stderr, rc)."""
        qemu_target = 'vpc' if target == 'vhd' else target
        cmd = ['qemu-img', 'create', '-f', qemu_target]
        for opt in options_list:
            cmd.extend(['-o', opt])
        cmd.extend([str(out_path), size_str])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'qemu-img create timeout after {timeout}s', -1


def _make_xval_test(target, case):
    case_name, size_str, options_list = case

    def test(self):
        if not getattr(type(self), '_system_qemu_available', False):
            self.skipTest('system qemu-img not available')
        known = KNOWN_WRITER_DIVERGENCES.get((target, case_name))
        if known is not None:
            self.skipTest(f'known writer divergence: {known}')

        ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk', 'vhd': 'vhd',
               'vhdx': 'vhdx', 'raw': 'raw'}[target]
        with tempfile.TemporaryDirectory() as td_a, \
                tempfile.TemporaryDirectory() as td_b:
            inst_path = Path(td_a) / f'instar.{ext}'
            qemu_path = Path(td_b) / f'qemu.{ext}'

            inst_args = ['-f', _instar_target_name(target)]
            for opt in options_list:
                inst_args.extend(['-o', opt])
            inst_args.extend([str(inst_path), size_str])
            _, stderr, rc = self.run_instar_create(*inst_args)
            self.assertEqual(
                rc, 0,
                f'instar create failed for {target}/{case_name}: '
                f'stderr={stderr}',
            )

            _, q_stderr, q_rc = self._run_qemu_create(
                target, size_str, options_list, qemu_path)
            if q_rc != 0:
                self.skipTest(
                    f'qemu-img rejected case (rc={q_rc}): '
                    f'{q_stderr.strip()}'
                )

            inst_info, inst_err, inst_rc = self.run_instar_info(
                inst_path, output='json')
            self.assertEqual(
                inst_rc, 0,
                f'instar info on instar output failed: {inst_err}',
            )
            qemu_info, qemu_err, qemu_rc = self.run_instar_info(
                qemu_path, output='json')
            self.assertEqual(
                qemu_rc, 0,
                f'instar info on qemu output failed: {qemu_err}',
            )

            assert_info_equivalent(
                self, inst_info, qemu_info, target,
                tmp_path=str(inst_path),
                expected_tmp_path=str(qemu_path),
                msg=(f'cross-validation {target}/{case_name}: '
                     f'instar={inst_path}, qemu={qemu_path}'),
            )

    test.__name__ = (
        f'test_xval_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar create vs qemu-img create for -f {target} '
        f'{" ".join(options_list)} {size_str} agree via instar info.'
    )
    return test


for _target, _case in CROSS_VALIDATION_CASES:
    _name = f'test_xval_{_target}_{_case[0].replace("-", "_")}'
    setattr(TestCreateCrossValidation, _name,
            _make_xval_test(_target, _case))


# ----------------------------------------------------------------------
# Phase 8d: instar check round-trip across the full matrix
# ----------------------------------------------------------------------
#
# Light-weight write-then-read sanity check: for each (target, case),
# instar create the image, then instar check it, assert rc==0. Catches
# any case-specific writer bug that produces a file `qemu-img info`
# accepts (matrix surface) but `instar check` flags.
#
# raw isn't checkable (instar check rejects raw inputs), so it's
# skipped here.


# Cases where `instar create` produces a file that `instar check`
# flags as malformed. These are tighter than KNOWN_WRITER_DIVERGENCES
# (which lists every instar/qemu disagreement); the check-failing set
# is the subset where instar's writer emits a header/payload pair the
# instar reader itself rejects. Each entry should have a tracking
# issue or a planned fix; the skip is documented in line.
KNOWN_CHECK_FAILURES = {
    # (Previously held ('qcow2', '1G-rb-64'): instar emitted a
    # refcount_order=4 header over differently-packed on-disk entries and
    # instar check rejected it. Fixed by deriving refcount_order from
    # refcount_bits and packing sub-byte widths LSB-first — instar #365.)
}


class TestCreateRoundTripCheck(TestCreateSmoke):
    """`instar create` then `instar check` for every CREATE_CASES entry.

    Excludes raw targets (instar check is a no-op for raw). Skips cases
    listed in KNOWN_CHECK_FAILURES (writer/reader disagreement inside
    instar — distinct from KNOWN_WRITER_DIVERGENCES which is about
    instar-vs-qemu).
    """

    pass


def _make_check_test(target, case):
    case_name, size_str, options_list = case

    def test(self):
        if target == 'raw':
            self.skipTest('instar check does not apply to raw images')
        check_skip = KNOWN_CHECK_FAILURES.get((target, case_name))
        if check_skip is not None:
            self.skipTest(f'known check failure: {check_skip}')

        ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk', 'vhd': 'vhd',
               'vhdx': 'vhdx'}[target]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / f'image.{ext}'
            args = ['-f', _instar_target_name(target)]
            for opt in options_list:
                args.extend(['-o', opt])
            args.extend([str(path), size_str])
            _, c_stderr, c_rc = self.run_instar_create(*args)
            if c_rc != 0:
                self.skipTest(
                    f'instar create rejected {target}/{case_name}: '
                    f'{c_stderr.strip()}'
                )
            _, k_stderr, k_rc = self.run_instar_check(path)
            self.assertEqual(
                k_rc, 0,
                f'instar check failed on freshly-created '
                f'{target}/{case_name}: stderr={k_stderr}',
            )

    test.__name__ = (
        f'test_check_{target}_{case_name.replace("-", "_")}'
    )
    test.__doc__ = (
        f'instar check passes on instar create -f {target} '
        f'{" ".join(options_list)} {size_str}.'
    )
    return test


for _target, _cases in CREATE_CASES.items():
    for _case in _cases:
        _name = (
            f'test_check_{_target}_{_case[0].replace("-", "_")}'
        )
        setattr(TestCreateRoundTripCheck, _name,
                _make_check_test(_target, _case))
