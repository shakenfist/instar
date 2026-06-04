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
