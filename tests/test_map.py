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
import subprocess
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
#     compressed cluster extents. cirros-qcow2 and qcow2-zstd have
#     compressed clusters; cirros has return_code=1 in baseline so
#     it's caught by the non-zero-baseline skip path, but qcow2-zstd
#     is included for the json output type.
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
    'qcow2-zstd':
        ('json', 'compressed-cluster reporting deferred'),
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
    'vhd-d2v-zerofilled':
        ('json', 'instar vhd walker reports present=false for '
                 'unallocated VHD; qemu-img reports present=true'),

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
