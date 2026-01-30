"""
Integration tests verifying imago info output matches stored baselines.

These tests iterate over all known output profiles (qemu-img version groups) and
verify that imago produces correct output when given the --qemu-version flag.
This ensures imago can correctly emulate any supported qemu-img version.

Tests compare against pre-generated baselines stored in imago-testdata, so
qemu-img does not need to be installed.
"""

import json
import os
from pathlib import Path

import testscenarios

from base import ImagoTestBase


def _get_safe_images_from_manifest():
    """Load safe image IDs from the manifest file."""
    tests_dir = Path(__file__).parent
    manifest_path = tests_dir / 'manifest.json'

    if not manifest_path.exists():
        return []

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Return IDs of all images marked as 'safe'
    return [
        img['id']
        for img in manifest.get('images', [])
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
    testdata_env = os.environ.get('IMAGO_TESTDATA_PATH')
    if testdata_env:
        testdata_root = Path(testdata_env)
    else:
        testdata_root = tests_dir.parent.parent / 'imago-testdata'

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
                    scenario_name = f'{output_type}-{profile_name}-{image_id}'
                    scenarios.append((scenario_name, {
                        'profile': profile_name,
                        'image_id': image_id,
                        'output_type': output_type,
                    }))

    return scenarios


class TestInfoSafe(testscenarios.WithScenarios, ImagoTestBase):
    """Test imago info output against stored baselines for all profiles."""

    # Scenarios must be populated at class definition time for testscenarios
    scenarios = _generate_scenarios()

    def test_output_matches_baseline(self):
        """Test that imago output matches the stored baseline for this profile."""
        image = self.get_image(self.image_id)

        # Skip if image file doesn't exist
        if not image.path.exists():
            self.skipTest(f'Image file not found: {image.path}')

        # Skip if image hash doesn't match (indicates baselines need regeneration)
        self.skip_if_hash_mismatch(image)

        # Get the qemu version string for this profile
        qemu_version = self.get_qemu_version_for_profile(self.profile)

        # Map output_type to imago --output flag value
        output_format = self.output_type if self.output_type != 'human' else None

        # Run imago with explicit --qemu-version and output format
        imago_stdout, imago_stderr, imago_rc = self.run_imago_info(
            image.path,
            qemu_version=qemu_version,
            output_format=output_format
        )

        # Should succeed
        self.assertEqual(
            0, imago_rc,
            f'imago failed for {self.image_id} with --qemu-version {qemu_version}: '
            f'{imago_stderr}'
        )

        # Load expected output from baseline
        expected = self.get_expected_output(
            self.image_id,
            self.profile,
            self.output_type
        )

        # Outputs should match (with actual disk size substituted from filesystem)
        self.assert_outputs_match(
            self.image_id, imago_stdout, expected, image_path=image.path
        )
