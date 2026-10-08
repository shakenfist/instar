"""
Integration tests verifying instar info output matches stored baselines.

These tests iterate over all known output profiles (qemu-img version groups) and
verify that instar produces correct output when given the --qemu-version flag.
This ensures instar can correctly emulate any supported qemu-img version.

Tests compare against pre-generated baselines stored in instar-testdata, so
qemu-img does not need to be installed.
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import testscenarios

from base import InstarTestBase
from helpers import load_manifest_images


def _get_safe_images_from_manifest():
    """Load safe image IDs from the manifest file."""
    return [
        img['id']
        for img in load_manifest_images()
        if img.get('safety') == 'safe'
    ]


def _generate_scenarios():
    """Generate test scenarios for all profile/image combinations.

    This function is called at module load time to populate scenarios
    before testscenarios performs test multiplication.
    """
    scenarios = []

    tests_dir = Path(__file__).parent

    # Resolve testdata root - can be overridden by environment variable
    testdata_env = os.environ.get('INSTAR_TESTDATA_PATH')
    if testdata_env:
        testdata_root = Path(testdata_env)
    else:
        testdata_root = tests_dir.parent.parent / 'instar-testdata'

    if not testdata_root.exists():
        # Return empty scenarios if testdata not available
        # Tests will be skipped appropriately
        return scenarios

    # Test both human and json output formats
    for output_type in ['human', 'json']:
        output_type_dir = f'qemu-img-{output_type}'
        version_map_path = (
            testdata_root / 'expected-outputs' /
            output_type_dir / 'version-map.json'
        )

        if not version_map_path.exists():
            continue

        with open(version_map_path) as f:
            version_map = json.load(f)

        profiles = version_map.get('profiles', {})

        for profile_name in sorted(profiles.keys()):
            for image_id in _get_safe_images_from_manifest():
                # Check if baseline exists for this image/profile
                baseline_path = (
                    testdata_root / 'expected-outputs' /
                    output_type_dir / 'profiles' / profile_name /
                    f'{image_id}.stdout.txt'
                )
                if baseline_path.exists():
                    # Skip profiles where qemu-img itself refused the image
                    # (baseline meta records a non-zero return code): there is
                    # no output parity to assert, and instar may deliberately
                    # diverge. First case: parallels-bat-past-eof, which qemu
                    # 8.1.0-8.1.5 refuse at open while every other version
                    # (and instar, uniformly) zero-fills — see
                    # docs/plans/PLAN-format-coverage-phase-03-parallels-read.md.
                    meta_path = baseline_path.with_name(f'{image_id}.meta.json')
                    if meta_path.exists():
                        with open(meta_path) as mf:
                            if json.load(mf).get('return_code', 0) != 0:
                                continue
                    scenario_name = f'{output_type}-{profile_name}-{image_id}'
                    scenarios.append((scenario_name, {
                        'profile': profile_name,
                        'image_id': image_id,
                        'output_type': output_type,
                    }))

    return scenarios


class TestInfoSafe(testscenarios.WithScenarios, InstarTestBase):
    """Test instar info output against stored baselines for all profiles."""

    # Scenarios must be populated at class definition time for testscenarios
    scenarios = _generate_scenarios()

    def test_output_matches_baseline(self):
        """Test that instar output matches the stored baseline for this profile."""
        image = self.get_image(self.image_id)

        # Skip if image file doesn't exist
        if not image.path.exists():
            self.skipTest(f'Image file not found: {image.path}')

        # Skip images whose format instar does not implement yet. qemu-img
        # reads these fine, so a baseline exists and the parity gap stays
        # measurable, but asserting equality would just pin a known TODO as a
        # hard failure. Currently twoGbMaxExtentSparse: multi-extent SPARSE
        # descriptors report FLAG_NOT_SUPPORTED (docs/format-coverage.md).
        # Clear the manifest field to re-enable these tests.
        if image.is_instar_unsupported:
            self.skipTest(
                f'instar does not support {self.image_id} yet: '
                f'{image.instar_unsupported}'
            )

        # Skip if image hash doesn't match (indicates baselines need regeneration)
        self.skip_if_hash_mismatch(image)

        # Get the qemu version string for this profile
        qemu_version = self.get_qemu_version_for_profile(self.profile)

        # Map output_type to instar --output flag value
        output_format = self.output_type if self.output_type != 'human' else None

        # Run instar with explicit --qemu-version and output format
        # Use --unsafe-quirks for images that require it (e.g., raw files without
        # partition tables that qemu-img would accept but instar rejects by default)
        instar_stdout, instar_stderr, instar_rc = self.run_instar_info(
            image.path,
            qemu_version=qemu_version,
            output_format=output_format,
            unsafe_quirks=image.requires_unsafe_quirks
        )

        # Should succeed
        self.assertEqual(
            0, instar_rc,
            f'instar failed for {self.image_id} with --qemu-version {qemu_version}: '
            f'{instar_stderr}'
        )

        # Load expected output from baseline
        expected = self.get_expected_output(
            self.image_id,
            self.profile,
            self.output_type
        )

        # Outputs should match (with actual disk size substituted from filesystem)
        self.assert_outputs_match(
            self.image_id, instar_stdout, expected, image_path=image.path
        )


class TestInfoChainJsonOutput(InstarTestBase):
    """`info --chain --output json` for a chain of more than one image.

    `info --chain` has always discovered and printed a backing chain in
    human form. Its `--output json` flag used to be accepted and then
    silently ignored: the command printed the same human text and still
    exited 0, so a script asking for JSON got prose with no signal that
    anything was wrong. These tests pin the JSON array this flag now
    produces, and that the human form printed without the flag is
    untouched by adding it.
    """

    def _chain_image(self, image_id):
        """Resolve a manifest image by id, skipping if it is absent."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image.path

    def test_chain_json_has_one_element_per_chain_member(self):
        """The JSON array has one element per chain member.

        Covers a differencing VHD child, a differencing VHDX child and
        a qcow2 chain: every format `discover_backing_chain` walks, not
        only the two formats this phase newly resolves a parent for.
        """
        # The qcow2 case needs both members present. A qcow2 chain is
        # not fail-soft, so a tree holding only the top image gives a
        # non-zero exit rather than the skip a partial checkout should
        # get; the VHD and VHDX children are self-describing and need
        # no companion entry here because their parents sit beside them
        # under the same manifest id prefix.
        cases = (
            ('vhd-diff-child-aligned', ()),
            ('vhdx-diff-child', ()),
            ('sf-vda', ('sf-vda-backing',)),
        )
        for image_id, companions in cases:
            with self.subTest(image=image_id):
                source = self._chain_image(image_id)
                for companion in companions:
                    self._chain_image(companion)
                stdout, stderr, rc = self.run_instar_info(
                    source, chain=True, output_format='json'
                )
                self.assertEqual(
                    0, rc,
                    f'{image_id}: info --chain --output json must not error; '
                    f'stderr={stderr!r}'
                )
                chain = json.loads(stdout)
                self.assertIsInstance(
                    chain, list, f'{image_id}: expected a JSON array, got {chain!r}'
                )
                self.assertEqual(
                    2, len(chain),
                    f'{image_id}: expected a two-element chain; got {chain!r}'
                )
                # Chain discovery canonicalises, so the manifest path is
                # only equal to the reported one where no component of it
                # is a symlink. `test_chain_human_output_is_unchanged`
                # resolves for the same reason.
                self.assertEqual(str(Path(source).resolve()), chain[0]['filename'])
                for member in chain:
                    for key in ('filename', 'format', 'virtual-size', 'actual-size'):
                        self.assertIn(
                            key, member,
                            f'{image_id}: missing {key!r} in {member!r}'
                        )

    def test_chain_json_child_names_its_parent_as_backing_filename(self):
        """The child's `backing-filename` is the unresolved reference.

        It is the same key the non-chain `info --output json` path uses
        for a single image's own backing reference, reused here rather
        than invented. The parent element, which has nothing left to
        resolve, carries no `backing-filename` key at all.
        """
        source = self._chain_image('vhd-diff-child-aligned')
        stdout, stderr, rc = self.run_instar_info(
            source, chain=True, output_format='json'
        )
        self.assertEqual(0, rc, f'stderr={stderr!r}')
        chain = json.loads(stdout)
        self.assertEqual('vhd-diff-parent.vhd', chain[0]['backing-filename'])
        self.assertNotIn('backing-filename', chain[1])

    def test_chain_json_truncated_listing_keeps_backing_filename(self):
        """A truncated chain's last element still names its parent.

        The key is what tells a complete listing from a truncated one.
        A chain that ran to its end finishes on a member whose header
        names no parent, so that member has no `backing-filename`; a
        walk that stopped early leaves the unresolved reference on the
        last element it did list. A reader that assumed the last
        element is always resolved would take this one-element array
        for a standalone image rather than an orphaned child, which is
        the opposite conclusion.
        """
        source = self._chain_image('vhd-diff-child-aligned')
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        orphan = Path(tmp) / Path(source).name
        shutil.copy2(source, orphan)

        stdout, stderr, rc = self.run_instar_info(
            orphan, chain=True, output_format='json'
        )
        self.assertEqual(0, rc, f'a missing parent must not error; stderr={stderr!r}')
        chain = json.loads(stdout)
        self.assertEqual(1, len(chain), f'expected a truncated one-element chain; got {chain!r}')
        self.assertEqual(
            'vhd-diff-parent.vhd', chain[0]['backing-filename'],
            f'the unresolved reference must survive on the last element: {chain!r}'
        )
        self.assertIn(
            'was not found', stderr,
            f'a truncated listing must say why on stderr; stderr={stderr!r}'
        )

    def test_chain_json_is_valid_for_a_hostile_parent_reference(self):
        """A hostile reference round-trips as JSON, escaped not rewritten.

        `vhd-diff-locator-unc` names a UNC path. Its backslashes are the
        characters most likely to produce invalid JSON if the reference
        were interpolated rather than escaped, so this asserts the array
        parses at all and that the value survives byte for byte --
        neither mangled by escaping nor rewritten into a POSIX path,
        which is what makes the reported value usable as evidence about
        the image.
        """
        source = self._chain_image('vhd-diff-locator-unc')
        stdout, stderr, rc = self.run_instar_info(
            source, chain=True, output_format='json'
        )
        self.assertEqual(0, rc, f'info must not refuse; stderr={stderr!r}')
        chain = json.loads(stdout)
        self.assertEqual(1, len(chain), f'the walk must not follow it; got {chain!r}')
        self.assertEqual(
            '\\\\attacker\\share\\probe', chain[0]['backing-filename'],
            f'the UNC reference must round-trip verbatim: {chain!r}'
        )

    def test_chain_human_output_is_unchanged(self):
        """`info --chain` with no `--output` renders the pinned human text.

        `--output json` selects a separate printer (`print_backing_chain_json`)
        chosen in `run_info` alongside the existing `print_backing_chain`;
        this pins that adding it left the default human form byte for
        byte the same.

        The disk size numbers below are not read off this host's
        filesystem: `info` reports a size computed from the VHD's own
        sparse block bitmap, not from `stat`, so it is stable across
        checkouts the same way the fixture's own bytes are (git-LFS
        content addressing). Hard-coding it here is pinning that
        computed value, not the filesystem's.
        """
        source = self._chain_image('vhd-diff-child-aligned')
        parent = self._chain_image('vhd-diff-parent')
        stdout, stderr, rc = self.run_instar_info(source, chain=True)
        self.assertEqual(0, rc, f'stderr={stderr!r}')

        # Chain discovery canonicalises every path it reports, so the
        # expected text must too. Comparing against the manifest path
        # would pass here and fail on any checkout reached through a
        # symlink, for a reason that has nothing to do with the output.
        source = Path(source).resolve()
        parent = Path(parent).resolve()

        expected = (
            'Chain: 2 image(s)\n'
            f'  [0] {source} (vpc) -> vhd-diff-parent.vhd\n'
            '      virtual size: 16 MiB (16777216 bytes)\n'
            '      disk size: 4 MiB (4198912 bytes)\n'
            '      cluster size: 2097152 bytes\n'
            f'  [1] {parent} (vpc)\n'
            '      virtual size: 16 MiB (16777216 bytes)\n'
            '      disk size: 6 MiB (6295552 bytes)\n'
            '      cluster size: 2097152 bytes\n'
        )
        self.assertEqual(expected, stdout)


# VHDX region table at 192 KiB: a 16-byte header ('regi', checksum,
# entry count, reserved) then 32-byte entries of (GUID, file offset
# u64, length u32, required u32). The metadata table at the start of
# the metadata region: a 32-byte header ('metadata', reserved, entry
# count u16 at +10) then 32-byte entries of (item GUID, offset u32
# relative to the region, length u32, flags u32, reserved).
_VHDX_REGION_TABLE_OFFSET = 192 * 1024
_VHDX_TABLE_HEADER_SIZE = 16
_VHDX_METADATA_TABLE_HEADER_SIZE = 32
_VHDX_TABLE_ENTRY_SIZE = 32
# GUIDs stored mixed-endian: the first three groups little-endian, the
# last eight bytes as written.
_VHDX_METADATA_REGION_GUID = (struct.pack('<IHH', 0x8B7CA206, 0x4790, 0x4B9A)
                              + bytes.fromhex('B8FE575F050F886E'))
_VHDX_FILE_PARAMETERS_GUID = (struct.pack('<IHH', 0xCAA16737, 0xFA36, 0x4D43)
                              + bytes.fromhex('B3B633F0AA44E76B'))
_VHDX_VIRTUAL_DISK_SIZE_GUID = (struct.pack('<IHH', 0x2FA54224, 0xCD1B, 0x4876)
                                + bytes.fromhex('B2115DBED83BF4B8'))


def _vhdx_swap_file_parameters_and_virtual_disk_size(path):
    """Swap where the File Parameters and Virtual Disk Size items live.

    Both items are 8 bytes, so swapping their contents and the offsets
    their metadata table entries give leaves a valid image: SPEC(VHDX)
    2.6.1.2 places no order on metadata items, and the metadata table
    carries no checksum. A reader that walks the table sees the same
    image as before; one that assumes File Parameters sits first, with
    Virtual Disk Size straight after it, reads each item as the other.
    """
    data = bytearray(Path(path).read_bytes())

    table = _VHDX_REGION_TABLE_OFFSET
    if data[table:table + 4] != b'regi':
        raise AssertionError('no VHDX region table')
    region = None
    for i in range(struct.unpack_from('<I', data, table + 8)[0]):
        at = table + _VHDX_TABLE_HEADER_SIZE + i * _VHDX_TABLE_ENTRY_SIZE
        if data[at:at + 16] == _VHDX_METADATA_REGION_GUID:
            region = struct.unpack_from('<Q', data, at + 16)[0]
            break
    if region is None:
        raise AssertionError('no metadata region entry in the region table')
    if data[region:region + 8] != b'metadata':
        raise AssertionError('no VHDX metadata table')

    entries = {}
    for i in range(struct.unpack_from('<H', data, region + 10)[0]):
        at = region + _VHDX_METADATA_TABLE_HEADER_SIZE + i * _VHDX_TABLE_ENTRY_SIZE
        entries[bytes(data[at:at + 16])] = at
    fp_entry = entries[_VHDX_FILE_PARAMETERS_GUID]
    vds_entry = entries[_VHDX_VIRTUAL_DISK_SIZE_GUID]

    fp_offset = struct.unpack_from('<I', data, fp_entry + 16)[0]
    vds_offset = struct.unpack_from('<I', data, vds_entry + 16)[0]
    fp_item = bytes(data[region + fp_offset:region + fp_offset + 8])
    vds_item = bytes(data[region + vds_offset:region + vds_offset + 8])

    data[region + fp_offset:region + fp_offset + 8] = vds_item
    data[region + vds_offset:region + vds_offset + 8] = fp_item
    struct.pack_into('<I', data, fp_entry + 16, vds_offset)
    struct.pack_into('<I', data, vds_entry + 16, fp_offset)
    Path(path).write_bytes(bytes(data))


class TestInfoVhdxMetadataLayout(InstarTestBase):
    """`info` finds VHDX metadata items through the metadata table.

    SPEC(VHDX) 2.6.1.2 gives metadata items no fixed order or position.
    qemu and instar's own `create` both put File Parameters first with
    Virtual Disk Size straight after it, which is why reading them at
    those fixed offsets went unnoticed: every fixture uses that layout.
    These tests move the items, so a fixed-offset reader reports the
    block size as the virtual size and the other way round, and exits 0.
    """

    VIRTUAL_SIZE = 100 * 1024 * 1024

    def _create(self, *args, cwd):
        instar = self.get_instar_binary()
        r = subprocess.run([str(instar), 'create', *args], capture_output=True,
                           text=True, timeout=60, cwd=cwd)
        self.assertEqual(0, r.returncode, f'create {args} failed: {r.stderr}')

    def _info_json(self, path):
        stdout, stderr, rc = self.run_instar_info(path, output_format='json')
        self.assertEqual(0, rc, f'info on {path} failed: stderr={stderr!r}')
        return json.loads(stdout)

    def test_moved_items_report_the_same_sizes(self):
        """Swapping the two items changes nothing `info` reports."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'moved.vhdx'
            self._create('-f', 'vhdx', str(path), str(self.VIRTUAL_SIZE), cwd=td)
            before = self._info_json(path)
            self.assertEqual(self.VIRTUAL_SIZE, before['virtual-size'])

            _vhdx_swap_file_parameters_and_virtual_disk_size(path)
            after = self._info_json(path)
            self.assertEqual(self.VIRTUAL_SIZE, after['virtual-size'])
            self.assertEqual(before['cluster-size'], after['cluster-size'])

    def test_moved_items_match_qemu_img(self):
        """qemu-img walks the metadata table too, and agrees."""
        self._require_qemu_img()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'moved.vhdx'
            self._create('-f', 'vhdx', str(path), str(self.VIRTUAL_SIZE), cwd=td)
            _vhdx_swap_file_parameters_and_virtual_disk_size(path)

            r = subprocess.run(['qemu-img', 'info', '--output', 'json', str(path)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(0, r.returncode, f'qemu-img info failed: {r.stderr}')
            qemu = json.loads(r.stdout)
            ours = self._info_json(path)
            for key in ('virtual-size', 'cluster-size'):
                self.assertEqual(qemu[key], ours[key], f'{key} differs from qemu-img')

    def test_moved_items_in_a_differencing_child(self):
        """A child with moved items still reports its size and parent.

        The parent reference and the sizes come from one metadata parse,
        so this pins that moving the items breaks neither.
        """
        with tempfile.TemporaryDirectory() as td:
            self._create('-f', 'vhdx', 'parent.vhdx', str(self.VIRTUAL_SIZE), cwd=td)
            self._create('-f', 'vhdx', '-b', 'parent.vhdx', '-F', 'vhdx',
                         'child.vhdx', cwd=td)
            child = Path(td) / 'child.vhdx'
            _vhdx_swap_file_parameters_and_virtual_disk_size(child)

            info = self._info_json(child)
            self.assertEqual(self.VIRTUAL_SIZE, info['virtual-size'])
            self.assertEqual('parent.vhdx', info.get('backing-filename'))
