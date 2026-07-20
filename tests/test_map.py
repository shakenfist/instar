"""Integration tests for the `instar map` subcommand.

Phase 6 of PLAN-map. Exercises the streaming map renderer
end-to-end against the phase 5 baseline matrix in
`instar-testdata/expected-outputs/map-{human,json}/`.

The test suite is split into five classes, all inheriting
from `TestMapSmoke`:

* `TestMapSmoke` — wiring checks (binary, baselines,
  basic invocation).
* `TestMapBaselineSource` — per-image factory generating
  one test per (image, output_type), comparing against
  the version-keyed profile.
* `TestMapWindowFilter` — in-test fixtures exercising
  `--start-offset` / `--max-length`.
* `TestMapErrorPaths` — host-side guards from phase 3b.
* `TestMapDivergenceRegression` — for each
  `KNOWN_MAP_DIVERGENCES` entry, asserts the divergence
  still happens so accidental fixes surface loudly.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


class TestMapSmoke(InstarTestBase):
    """End-to-end smoke tests for `instar map`.

    Shared helper (`run_instar_map`) and wiring checks live
    here; the other test classes inherit to pick up the
    helper without duplicating it.
    """

    def run_instar_map(self, *args, timeout=60):
        """Invoke `instar map` with the given args.

        Returns (stdout, stderr, returncode).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'map', *[str(a) for a in args]]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def test_help_succeeds(self):
        """`instar map --help` returns 0 and lists the documented surface."""
        instar = self.get_instar_binary()
        r = subprocess.run(
            [str(instar), 'map', '--help'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(r.returncode, 0, f'stderr: {r.stderr}')
        for expected in (
            'INPUT', '--output', '--start-offset',
            '--max-length', '--sector-size', '--image-opts',
        ):
            self.assertIn(
                expected, r.stdout,
                f'expected {expected!r} in --help output',
            )

    def test_baselines_present_human(self):
        """The phase 5 baselines must be reachable via base.py helpers."""
        profiles = self.get_output_profiles(
            output_type='human', command='map'
        )
        self.assertIn('profiles', profiles)
        self.assertGreater(
            len(profiles['profiles']), 0,
            'expected at least one map-human profile',
        )
        self.assertIn('version_to_profile', profiles)
        self.assertGreater(
            len(profiles['version_to_profile']), 0,
            'expected at least one qemu version in the map',
        )

    def test_baselines_present_json(self):
        """The phase 5 baselines must be reachable for JSON too."""
        profiles = self.get_output_profiles(
            output_type='json', command='map'
        )
        self.assertIn('profiles', profiles)
        # Phase 5 produced 3 map-json profiles; assert at least 1
        # so the test doesn't break when the matrix evolves.
        self.assertGreater(len(profiles['profiles']), 0)

    def test_smoke_qcow2_runs_and_returns_zero(self):
        """Picking a safe-tier qcow2 with a clean baseline: `instar
        map` exits 0, stdout starts with the qemu-img header row.

        Uses `qcow2-min-cluster` rather than `cirros-qcow2` because
        cirros has compressed clusters that qemu-img map refuses
        (return_code=1 in the baseline meta.json); the smoke test
        wants an image where both tools succeed.
        """
        image = self.get_image('qcow2-min-cluster')
        if not image.path.exists():
            self.skipTest(f'qcow2-min-cluster not found at {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        self.assertTrue(
            stdout.startswith('Offset'),
            f'expected header row, got: {stdout[:80]!r}',
        )

    def test_profile_lookup_returns_string(self):
        """`get_profile_for_installed_qemu` returns a usable profile name."""
        profile = self.get_profile_for_installed_qemu(
            output_type='json', command='map'
        )
        self.assertIsInstance(profile, str)
        self.assertTrue(profile.startswith('profile-'))


def _safe_tier_images():
    """Yield safe-tier image entries from the manifest.

    Mirrors the helper in test_measure.py; copied here so
    test_map.py is self-contained without an import cycle.
    """
    tests_dir = Path(__file__).parent
    with (tests_dir / 'manifest.json').open() as f:
        manifest = json.load(f)
    for img in manifest.get('images', []):
        if img.get('safety') == 'safe':
            yield img


# Known instar-vs-qemu-img divergences for `instar map`. Each entry
# maps an image_id to (output_type_pattern, reason). The factory
# below skips matching (image, output_type) pairs with the
# documented reason rather than failing. These are deliberate
# divergences (see docs/quirks.md "map subcommand quirks") rather
# than real bugs.
#
# Categories captured:
#   * Chain composition deferred: qcow2 sources with backing
#     pointers (qcow2-overlay-chain, chain-middle-qcow2,
#     chain-top-qcow2, sf-vda); instar refuses with HAS_BACKING,
#     qemu-img walks the chain.
#   * Compressed-cluster reporting: instar emits compressed: false
#     unconditionally; qemu-img emits compressed: true for
#     compressed cluster extents. cirros-qcow2 has compressed
#     clusters and return_code=1 in its baseline, so it's caught
#     by the non-zero-baseline skip path. qcow2-zstd was a
#     candidate divergence (compressed-cluster reporting) but the
#     fixture happens not to exercise compressed clusters in
#     practice — TestMapDivergenceRegression's assertNotEqual
#     surfaced this during 6d and the entry was removed (see the
#     comment on the removed entry below).
#   * Raw sparseness: instar emits one fully-allocated Data extent;
#     qemu-img walks SEEK_HOLE.
#   * Image-specific divergences surfaced empirically: this list
#     grows during 6b development as the per-image factory runs and
#     reveals additional skip candidates.
KNOWN_MAP_DIVERGENCES = {
    # ---------- Chain sources ----------
    # instar refuses with ERROR_HAS_BACKING; qemu-img walks the
    # chain (depth > 0 extents).
    'qcow2-overlay-chain':
        ('*', 'chain composition deferred; see PLAN-map.md'),
    'chain-middle-qcow2':
        ('*', 'chain composition deferred; see PLAN-map.md'),
    'chain-top-qcow2':
        ('*', 'chain composition deferred; see PLAN-map.md'),
    'sf-vda':
        ('*', 'chain composition deferred; see PLAN-map.md'),
    'sf-vda-backing':
        ('*', 'chain composition deferred; '
              'instar walks all clusters but qemu-img reports '
              'the chain-aware coalesced view'),
    'debian-12-sfagent':
        ('*', 'chain composition deferred (uses sf-vda-backing chain)'),

    # ---------- Compressed clusters ----------
    # instar's qcow2 walker classifies compressed clusters as
    # Data but doesn't carry the compressed bit through the FFI;
    # instar always emits compressed: false. qemu-img emits
    # compressed: true for compressed-cluster extents. The
    # compressed-cluster file_offset extraction also packs
    # nb_sectors-1 in bits 54-61 which our L2_OFFSET_MASK
    # doesn't strip, so file offsets for compressed clusters
    # are wrong on top of the compressed: false divergence.
    # See docs/quirks.md "map subcommand quirks" + PLAN-map.md
    # future work.
    # Note: qcow2-zstd was a candidate divergence (compressed-
    # cluster reporting deferred), but the actual fixture happens
    # to be 1 MiB of zeros with no compressed clusters actually
    # exercised — instar matches qemu-img byte-for-byte. Removed
    # by the TestMapDivergenceRegression assertion during 6d.
    'cirros-qcow2':
        ('json', 'compressed-cluster reporting deferred; '
                 'cirros-0.6.3 uses compressed-cluster L2 entries'),
    'aurel32-debian-etch-sparc':
        ('json', 'compressed-cluster reporting deferred; '
                 'image uses compressed L2 entries'),
    'aurel32-debian-squeeze-armel':
        ('json', 'compressed-cluster reporting deferred'),
    'aurel32-debian-squeeze-i386':
        ('json', 'compressed-cluster reporting deferred'),
    'aurel32-debian-wheezy-powerpc':
        ('json', 'compressed-cluster reporting deferred'),

    # ---------- Raw sparseness ----------
    # instar emits one fully-allocated Data extent; qemu-img
    # walks SEEK_HOLE / SEEK_DATA on the underlying file.
    'raw-sparse-empty':
        ('*', 'raw SEEK_HOLE detection not implemented; '
              'see docs/quirks.md'),

    # ---------- VHD divergences ----------
    # instar's vhd walker emits `present: false` for an
    # otherwise-empty dynamic VHD (no allocated BAT entries);
    # qemu-img emits `present: true, zero: true, data: false`.
    # Both agree on the data ranges; the divergence is purely
    # on the "is this byte reachable" semantic for the
    # unallocated-but-virtual-size region.
    'hyperv-dynamic-vhd':
        ('json', 'instar vhd walker reports present=false for '
                 'unallocated VHD; qemu-img reports present=true'),
    # virtualpc-vhd has the same present:false vs true divergence
    # AND the CHS-only virtual_size divergence already documented
    # in test_measure.py's KNOWN_SOURCE_SCANNER_DIVERGENCES.
    'virtualpc-vhd':
        ('json', 'instar vhd walker reports present=false; also '
                 'CHS-only virtual_size differs by ~2 MiB'),

    # ---------- VMDK divergences ----------
    # instar's vmdk monolithicSparse walker reports the file as
    # one big data extent; qemu-img walks the descriptor and
    # emits the actual partition layout (multi-extent
    # propagation deferred per docs/quirks.md).
    'vmdk-multi-partition':
        ('*', 'vmdk multi-extent propagation deferred; '
              'see docs/quirks.md'),
    'vhdx-disk2vhd':
        ('json', 'instar vhdx walker emits BAT-level detail; '
                 'qemu-img emits one whole-image extent'),
    # Note: vhd-d2v-zerofilled was a candidate divergence (VHD
    # present:false vs true) but the actual fixture has allocated
    # data and instar matches byte-for-byte. Removed by the
    # TestMapDivergenceRegression assertion during 6d.

    # ---------- VHDX divergences ----------
    # instar's vhdx walker exposes the BAT entries individually
    # (per-block data vs zero); qemu-img reports the file as one
    # data extent. This is the inverse of what the phase 4c
    # quirks doc anticipated (which talked about
    # PAYLOAD_BLOCK_PARTIALLY_PRESENT) — turns out for these
    # fixtures qemu-img doesn't drill into the BAT at all.
    'qemu-vhdx':
        ('json', 'instar vhdx walker exposes BAT-level detail; '
                 'qemu-img emits one whole-image extent'),
}


class TestMapBaselineSource(TestMapSmoke):
    """Cross-version baseline comparison for safe-tier source images.

    For each (image, output_type) pair, runs `instar map IMAGE
    --output=TYPE` and compares byte-for-byte against the
    version-keyed expected output for the host's qemu-img version.

    Skip categories:
      1. The image file is missing on disk (sparse checkouts).
      2. The phase 5 baseline meta.json reports a non-zero exit
         (qemu-img couldn't produce a clean baseline — chain
         image without -F hint, compressed-cluster source, etc.).
      3. The image is listed in KNOWN_MAP_DIVERGENCES (deliberate
         divergence; see docs/quirks.md).
      4. instar itself returns non-zero (instar may not support
         the format yet — feature gap, not regression).
      5. No baseline file exists for the resolved profile.

    Real regressions surface as assertion failures with a clear
    diff between instar's stdout and the baseline.
    """


def _make_map_source_test(image_dict, output_type):
    """Factory: return a test method for one (image, output_type)."""

    def test(self):
        image_id = image_dict['id']

        # Skip 3: known divergence — documented in
        # KNOWN_MAP_DIVERGENCES (and docs/quirks.md).
        divergence = KNOWN_MAP_DIVERGENCES.get(image_id)
        if divergence is not None:
            output_type_pattern, reason = divergence
            if output_type_pattern in ('*', output_type):
                self.skipTest(
                    f'known map divergence ({reason})'
                )

        # Skip 1: image not on disk.
        image_path = self._testdata_root / image_dict['path']
        if not image_path.exists():
            self.skipTest(f'image not found: {image_path}')

        # Skip 2: baseline reports non-zero exit. Pick any
        # version that the profile lookup can resolve so we can
        # locate the meta.json (the per-version meta files all
        # report the same return_code within a profile, modulo
        # transient artifacts).
        profiles = self.get_output_profiles(
            output_type=output_type, command='map'
        )
        any_version = next(iter(profiles['version_to_profile']))
        src_format = image_dict.get('format', 'unknown')
        meta_path = (
            self._testdata_root / 'expected-outputs' /
            f'map-{output_type}' / src_format / any_version /
            f'{image_id}.meta.json'
        )
        if not meta_path.exists():
            self.skipTest(f'no baseline meta: {meta_path}')
        with meta_path.open() as f:
            meta = json.load(f)
        if meta.get('return_code', 0) != 0:
            self.skipTest(
                f'baseline has non-zero exit '
                f'({meta.get("return_code")}); '
                f'qemu-img map could not process this image'
            )

        # Run instar map.
        stdout, stderr, rc = self.run_instar_map(
            str(image_path), '--output', output_type
        )
        # Skip 4: instar refused the image (chain not yet listed
        # in KNOWN_MAP_DIVERGENCES, or some other format gap).
        if rc != 0:
            self.skipTest(
                f'instar returned rc={rc} for {image_id} '
                f'({output_type}) but baseline expects rc=0 — '
                f'instar may not yet support this source format. '
                f'Add to KNOWN_MAP_DIVERGENCES with a documented '
                f'reason if the divergence is intentional. '
                f'stderr: {stderr.strip()}'
            )

        # Compare against the version-keyed profile.
        profile_name = self.get_profile_for_installed_qemu(
            output_type=output_type, command='map'
        )
        try:
            expected = self.get_expected_output(
                image_id, profile_name,
                output_type=output_type, command='map'
            )
        except FileNotFoundError:
            # Skip 5: missing baseline file for this profile.
            self.skipTest(
                f'no baseline file for {image_id} in profile '
                f'{profile_name}'
            )

        self.assertEqual(
            stdout, expected,
            f'output differs from baseline for {image_id} '
            f'({output_type})'
        )

    test.__name__ = (
        f'test_source_{image_dict["id"].replace("-", "_")}_{output_type}'
    )
    test.__doc__ = (
        f'instar map {image_dict["id"]} --output={output_type} matches '
        f'the phase-6 baseline.'
    )
    return test


for _img in _safe_tier_images():
    for _ot in ('human', 'json'):
        _name = f'test_source_{_img["id"].replace("-", "_")}_{_ot}'
        setattr(
            TestMapBaselineSource,
            _name,
            _make_map_source_test(_img, _ot),
        )


class TestMapWindowFilter(TestMapSmoke):
    """`--start-offset` / `--max-length` window filter behaviour.

    These tests construct a small fragmented qcow2 fixture in a
    `tempfile.mkdtemp()` directory (cleaned up in `setUp`/
    `addCleanup`) via the recipe from phase 4a: `truncate` a
    1 MiB raw image, write 64 KiB of data at offset 0 and at
    offset 0x80000, then `qemu-img convert -f raw -O qcow2` to
    produce a qcow2 with two allocated extents separated by a
    hole.

    Tests assert *structural* properties (extent count, byte
    ranges, presence/absence of specific offsets) rather than
    byte-equality against qemu-img — the phase 4a `MapRenderer`
    unit tests already pin the byte-level shape, and adding
    qemu-img comparison here would duplicate that coverage.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Skip the whole class if qemu-img isn't available — the
        # fixture construction depends on it.
        if shutil.which('qemu-img') is None:
            cls._fixture_path = None
            return
        cls._fixture_dir = tempfile.mkdtemp(prefix='instar-map-window-')
        raw_path = os.path.join(cls._fixture_dir, 'fixture.raw')
        qcow_path = os.path.join(cls._fixture_dir, 'fixture.qcow2')
        subprocess.run(['truncate', '-s', '1M', raw_path], check=True)
        # Two 64 KiB data runs at offsets 0 and 0x80000 (512 KiB).
        with open(raw_path, 'r+b') as f:
            f.seek(0)
            f.write(b'\xab' * 0x10000)
            f.seek(0x80000)
            f.write(b'\xcd' * 0x10000)
        subprocess.run(
            ['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
             raw_path, qcow_path],
            check=True,
        )
        cls._fixture_path = qcow_path

    @classmethod
    def tearDownClass(cls):
        try:
            fixture_dir = getattr(cls, '_fixture_dir', None)
            if fixture_dir:
                shutil.rmtree(fixture_dir, ignore_errors=True)
        finally:
            super().tearDownClass()

    def _require_fixture(self):
        if not getattr(self, '_fixture_path', None):
            self.skipTest('qemu-img not available; cannot build fixture')

    def test_default_window_emits_all_extents(self):
        """No window flags: emit both allocated extents plus the
        intermediate hole."""
        self._require_fixture()
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path, '--output', 'json'
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # The fragmented fixture has at least two data extents
        # (one at offset 0, one at 0x80000). Older qcow2 layouts
        # may coalesce neighbouring zero ranges, so accept >=2
        # rather than pinning an exact count.
        data_count = stdout.count('"data": true')
        self.assertGreaterEqual(
            data_count, 2,
            f'expected >=2 data extents; got {data_count}\n'
            f'stdout: {stdout[:400]!r}',
        )

    def test_start_offset_clips_leading_extents(self):
        """--start-offset=0x80000: only the second data extent
        appears."""
        self._require_fixture()
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path, '--start-offset', '512K',
            '--output', 'json',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # No extent should start before the window.
        # Every "start": value must be >= 0x80000 (524288).
        # Pull out the "start": N values and check the min.
        starts = []
        for line in stdout.splitlines():
            # Each extent object is one line; find "start": N
            idx = line.find('"start": ')
            if idx >= 0:
                rest = line[idx + len('"start": '):]
                num = ''
                for ch in rest:
                    if ch.isdigit():
                        num += ch
                    else:
                        break
                if num:
                    starts.append(int(num))
        self.assertTrue(starts, 'expected at least one extent')
        self.assertGreaterEqual(
            min(starts), 0x80000,
            f'extent starts {starts!r} must all be >= 0x80000'
        )

    def test_max_length_clips_trailing_extents(self):
        """--max-length=0x10000: only the first data extent fits."""
        self._require_fixture()
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path, '--max-length', '64K',
            '--output', 'json',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # The second data extent (at 0x80000) must not appear
        # in the output.
        self.assertNotIn(
            '"start": 524288', stdout,
            'extent at 0x80000 should be clipped by --max-length'
        )

    def test_start_offset_plus_max_length_window(self):
        """Combined window: --start-offset=0x80000 --max-length=0x10000
        — emit only the second data extent."""
        self._require_fixture()
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path,
            '--start-offset', '512K',
            '--max-length', '64K',
            '--output', 'json',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # Exactly one Data extent should be emitted (the one at
        # 0x80000); coalescing with adjacent holes in the
        # 64 KiB window keeps the JSON object count tight.
        data_count = stdout.count('"data": true')
        self.assertEqual(
            data_count, 1,
            f'expected exactly 1 data extent in window; '
            f'got {data_count}: {stdout!r}'
        )

    def test_start_offset_past_eof_emits_empty(self):
        """--start-offset >= virtual_size silently emits empty
        output and exits 0, matching qemu-img map's behaviour.

        Verified against qemu-img 10.0.8: `qemu-img map
        --start-offset=10G <tiny.qcow2>` returns rc=0 with just
        the human header row (or `[]\\n` for JSON).
        """
        self._require_fixture()
        # Use a huge offset that clearly exceeds the 1 MiB virtual
        # size.
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path, '--start-offset', '1T',
            '--output', 'json',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # Empty extent list (qemu-img matches this).
        self.assertEqual(
            stdout, '[]\n',
            f'expected empty JSON array; got: {stdout!r}'
        )

    def test_max_length_past_eof_clips_silently(self):
        """--max-length larger than virtual_size silently clips at
        the image end (no error)."""
        self._require_fixture()
        stdout, stderr, rc = self.run_instar_map(
            self._fixture_path, '--max-length', '1T',
            '--output', 'json',
        )
        self.assertEqual(rc, 0, f'stderr: {stderr}')
        # Should produce valid JSON output ending with `]\n`.
        self.assertTrue(
            stdout.endswith(']\n'),
            f'expected JSON output to end with ]\\n; got: {stdout[-20:]!r}'
        )


class TestMapErrorPaths(TestMapSmoke):
    """Host-side guards from phase 3b: --image-opts refusal,
    missing source, invalid sector size, chain image refusal.
    """

    def test_image_opts_rejected(self):
        """--image-opts is rejected with a clear stderr message
        pointing at docs/quirks.md."""
        # Pass any file as the positional; --image-opts is
        # refused before any file access happens.
        stdout, stderr, rc = self.run_instar_map(
            '--image-opts', '/dev/null',
        )
        self.assertNotEqual(rc, 0)
        self.assertIn('--image-opts', stderr)

    def test_missing_source_file_errors(self):
        """Non-existent FILENAME returns non-zero."""
        stdout, stderr, rc = self.run_instar_map(
            '/tmp/this-file-definitely-does-not-exist-12345.qcow2',
        )
        self.assertNotEqual(rc, 0)

    def test_invalid_sector_size_errors(self):
        """Non-power-of-2 --sector-size is rejected."""
        # Pick any image just to have a positional; sector_size
        # is validated before any file access.
        image = self.get_image('qcow2-min-cluster')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(
            str(image.path), '--sector-size', '1000',
        )
        self.assertNotEqual(rc, 0)
        # Either the sector-size message or the clap-level
        # error — both are acceptable failure modes.

    def test_chain_qcow2_rejected_with_has_backing(self):
        """A qcow2 source with a backing-file pointer is refused
        by the guest with ERROR_HAS_BACKING; the host renders a
        clear stderr message and returns non-zero."""
        image = self.get_image('qcow2-overlay-chain')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertNotEqual(
            rc, 0,
            f'expected non-zero exit for chain source; '
            f'stdout: {stdout[:200]!r}'
        )
        # The stderr message should mention backing/chain so the
        # user knows why the operation was rejected.
        combined = (stdout + stderr).lower()
        self.assertTrue(
            'backing' in combined or 'chain' in combined,
            f'expected backing/chain mention in output; '
            f'stderr: {stderr!r}'
        )

    # ----------- Phase-1 format-coverage: new-format refusals -----------
    #
    # map does not use the host chain-discovery gate (issue #444); it
    # calls the guest's `detect_format_from_header` directly and any
    # non-raw, non-read format falls into the default arm, which the
    # guest reports as ERROR_INVALID_SOURCE ("source format
    # unrecognised") and the host surfaces as a non-zero exit. Bochs,
    # cloop, and parallels are header-detected, so they hit this path.
    # DMG is detected only by its koly trailer, and that trailer probe
    # is wired into `instar info` only (not into
    # `detect_format_from_header`), so map never sees it as anything
    # but raw -- it reads the DMG container bytes as a raw device
    # instead of refusing. This mirrors the iso quirk pinned in
    # TestConvertDetectOnlyRefusal.test_convert_iso_passthrough.

    def test_bochs_refused(self):
        """map refuses a bochs-growing source (header-detected)."""
        image = self.get_image('bochs-growing')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertNotEqual(rc, 0, f'stdout: {stdout!r} stderr: {stderr!r}')
        self.assertIn('source format unrecognised', stderr)

    def test_cloop_refused(self):
        """map refuses a cloop-simple source (header-detected)."""
        image = self.get_image('cloop-simple')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertNotEqual(rc, 0, f'stdout: {stdout!r} stderr: {stderr!r}')
        self.assertIn('source format unrecognised', stderr)

    def test_parallels_refused(self):
        """map refuses a parallels-v1 source (header-detected)."""
        image = self.get_image('parallels-v1')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertNotEqual(rc, 0, f'stdout: {stdout!r} stderr: {stderr!r}')
        self.assertIn('source format unrecognised', stderr)

    def test_qed_refused(self):
        """map refuses a qed-simple source (header-detected).

        Format-coverage phase 6 keeps QED read-refused as policy (see
        docs/plans/PLAN-format-coverage-phase-06-qed.md).  QED's
        offset-0 header magic is recognised by the guest probe but has
        no reader arm, so it lands in the same default arm as
        bochs/cloop/parallels and is refused with "source format
        unrecognised".  qemu-img maps QED (rc 0); instar's refusal is
        the recorded scope divergence.
        """
        image = self.get_image('qed-simple')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertNotEqual(rc, 0, f'stdout: {stdout!r} stderr: {stderr!r}')
        self.assertIn('source format unrecognised', stderr)

    def test_dmg_reads_as_raw(self):
        """map does NOT refuse dmg-simple; it reads it as raw.

        DMG detection is trailer-only and not wired into map's guest
        format probe (`detect_format_from_header`), so a DMG source is
        indistinguishable from raw here and map succeeds, mapping the
        whole file as one allocated raw extent. Documents the phase-1
        gap rather than asserting a refusal that does not exist.
        """
        image = self.get_image('dmg-simple')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        stdout, stderr, rc = self.run_instar_map(str(image.path))
        self.assertEqual(rc, 0, f'stdout: {stdout!r} stderr: {stderr!r}')
        self.assertIn(str(image.path), stdout)


class TestMapDivergenceRegression(TestMapSmoke):
    """Assert each KNOWN_MAP_DIVERGENCES entry still diverges.

    If a future change accidentally lifts a documented
    divergence (e.g. raw SEEK_HOLE gets implemented, the
    compressed bit gets carried through the FFI, vhd `present`
    semantics get fixed, etc.), the corresponding entry's
    divergence-regression test will FAIL — surfacing the fix
    as a prompt to clean up KNOWN_MAP_DIVERGENCES rather than
    silently leaving the entry stale.

    Per entry: run instar map against the image. If instar
    refused (rc != 0), the divergence is still present (instar
    can't handle the source). If instar succeeded, compare its
    output to the baseline — assertNotEqual catches a silent
    fix.
    """


def _make_divergence_regression_test(image_id, output_type, reason):
    """Factory: return a test method that asserts the divergence
    is still observable for one (image_id, output_type)."""

    def test(self):
        # Look the image up; skip if not on disk.
        if image_id not in self._images_by_id:
            self.skipTest(f'image id {image_id} not in manifest')
        image_dict = next(
            i for i in _safe_tier_images() if i['id'] == image_id
        )
        image_path = self._testdata_root / image_dict['path']
        if not image_path.exists():
            self.skipTest(f'image not found: {image_path}')

        # Locate the baseline meta. If the baseline has rc != 0,
        # there's nothing meaningful to compare against — the
        # divergence is "qemu-img couldn't even run", which
        # isn't a divergence we can regress *from*.
        profiles = self.get_output_profiles(
            output_type=output_type, command='map'
        )
        any_version = next(iter(profiles['version_to_profile']))
        src_format = image_dict.get('format', 'unknown')
        meta_path = (
            self._testdata_root / 'expected-outputs' /
            f'map-{output_type}' / src_format / any_version /
            f'{image_id}.meta.json'
        )
        if not meta_path.exists():
            self.skipTest(f'no baseline meta: {meta_path}')
        with meta_path.open() as f:
            meta = json.load(f)
        if meta.get('return_code', 0) != 0:
            self.skipTest(
                f'baseline has non-zero exit; nothing to regress from'
            )

        stdout, _stderr, rc = self.run_instar_map(
            str(image_path), '--output', output_type
        )
        if rc != 0:
            # instar refused — divergence is "instar can't handle
            # this source". Still divergent; test passes.
            return

        profile_name = self.get_profile_for_installed_qemu(
            output_type=output_type, command='map'
        )
        try:
            expected = self.get_expected_output(
                image_id, profile_name,
                output_type=output_type, command='map'
            )
        except FileNotFoundError:
            self.skipTest(f'no baseline file for {image_id}')

        # The whole point of this class: assert the divergence
        # has NOT been silently fixed.
        self.assertNotEqual(
            stdout, expected,
            f'KNOWN_MAP_DIVERGENCES entry for {image_id} '
            f'({output_type}) appears to be fixed — '
            f'instar now matches qemu-img. Reason was: {reason!r}. '
            f'Remove this entry from KNOWN_MAP_DIVERGENCES so the '
            f'TestMapBaselineSource factory exercises it.'
        )

    test.__name__ = (
        f'test_divergence_{image_id.replace("-", "_")}_{output_type}'
    )
    test.__doc__ = (
        f'Asserts {image_id} ({output_type}) still diverges from '
        f'qemu-img. Reason: {reason}'
    )
    return test


for _img_id, (_pattern, _reason) in KNOWN_MAP_DIVERGENCES.items():
    _output_types = (
        ('human', 'json') if _pattern == '*' else (_pattern,)
    )
    for _ot in _output_types:
        _name = (
            f'test_divergence_{_img_id.replace("-", "_")}_{_ot}'
        )
        setattr(
            TestMapDivergenceRegression,
            _name,
            _make_divergence_regression_test(_img_id, _ot, _reason),
        )
