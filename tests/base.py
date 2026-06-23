"""Base test class for instar integration tests."""

import hashlib
import json
import os
import re
import resource
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

import testtools

from helpers.comparators import (
    compare_outputs,
    format_failure_message,
    get_disk_size,
    substitute_actual_size,
    substitute_testdata_root,
)
from helpers.types import TestImage


# Mapping from command names to output type directory prefixes
# 'info' uses legacy names for backwards compatibility
COMMAND_OUTPUT_DIRS = {
    'info': 'qemu-img',            # qemu-img-human, qemu-img-json
    'check': 'check',              # check-human, check-json
    'compare': 'compare',          # compare-human, compare-json
    'measure': 'measure',          # measure-human, measure-json
    'create': 'create-info',       # create-info-json (json-only, no human variant)
    'map': 'map',                  # map-human, map-json (PLAN-map phase 6)
    'snapshot-list': 'snapshot-list',  # snapshot-list-human (PLAN-snapshot phase 11)
    'dd': 'dd-info',               # dd-info-json (PLAN-dd phase 7)
}


class InstarTestBase(testtools.TestCase):
    """Base class for instar integration tests."""

    # Class-level cache for manifest and images
    _manifest = None
    _images_by_id = None
    _testdata_root = None
    _qemu_version: Optional[Tuple[int, int]] = None
    _hash_verification_results: dict = {}  # image_id -> (valid, actual_hash)

    @classmethod
    def setUpClass(cls):
        """Load manifest once for all tests in the class."""
        super().setUpClass()
        cls._load_manifest()
        cls._detect_qemu_version()

    @classmethod
    def _load_manifest(cls):
        """Load the test manifest and build image lookup."""
        if cls._manifest is not None:
            return

        tests_dir = Path(__file__).parent
        manifest_path = tests_dir / 'manifest.json'

        with open(manifest_path) as f:
            cls._manifest = json.load(f)

        # Resolve testdata root - can be overridden by environment variable
        testdata_env = os.environ.get('INSTAR_TESTDATA_PATH')
        if testdata_env:
            cls._testdata_root = Path(testdata_env)
        else:
            cls._testdata_root = tests_dir.parent.parent / 'instar-testdata'

        if not cls._testdata_root.exists():
            raise RuntimeError(
                f'Test data directory not found: {cls._testdata_root}\n'
                f'Set INSTAR_TESTDATA_PATH environment variable or ensure '
                f'instar-testdata is a sibling directory.'
            )

        # Build lookup by image id
        cls._images_by_id = {}
        for img_data in cls._manifest.get('images', []):
            image = TestImage.from_dict(img_data, cls._testdata_root)
            cls._images_by_id[image.id] = image

    @classmethod
    def _detect_qemu_version(cls):
        """
        Detect the installed qemu-img version.

        This is only used for tests that verify our version detection code.
        Profile output tests don't need this - they iterate all profiles
        explicitly with --qemu-version.
        """
        if cls._qemu_version is not None:
            return

        try:
            result = subprocess.run(
                ['qemu-img', '--version'],
                capture_output=True,
                text=True
            )
            match = re.search(r'qemu-img version (\d+)\.(\d+)', result.stdout)
            if match:
                cls._qemu_version = (int(match.group(1)), int(match.group(2)))
        except FileNotFoundError:
            pass

    def get_output_profiles(
        self,
        output_type: str = 'human',
        command: str = 'info'
    ) -> dict:
        """
        Get all output profiles for a given command and output type.

        Args:
            output_type: 'human' or 'json'
            command: 'info', 'check', 'compare', etc.

        Returns:
            dict with 'profiles' (profile_name -> representative_version)
            and 'version_to_profile' (version -> profile_name)
        """
        dir_prefix = COMMAND_OUTPUT_DIRS.get(command, command)
        output_type_dir = f'{dir_prefix}-{output_type}'
        version_map_path = (
            self._testdata_root / 'expected-outputs' /
            output_type_dir / 'version-map.json'
        )

        with open(version_map_path) as f:
            return json.load(f)

    def get_expected_output(
        self,
        image_id: str,
        profile: str,
        output_type: str = 'human',
        command: str = 'info'
    ) -> str:
        """
        Load expected output for a specific profile from testdata.

        Baselines use $TESTDATA_ROOT as a placeholder for portability.
        This method substitutes the placeholder with the actual testdata
        path for the current environment.

        Args:
            image_id: The test image identifier
            profile: Profile name (e.g., 'profile-6-0-0', 'profile-8-0-0')
            output_type: 'human' or 'json'
            command: 'info', 'check', 'compare', etc.

        Returns:
            Expected output string with paths resolved for current environment
        """
        dir_prefix = COMMAND_OUTPUT_DIRS.get(command, command)
        output_type_dir = f'{dir_prefix}-{output_type}'
        output_path = (
            self._testdata_root / 'expected-outputs' /
            output_type_dir / 'profiles' / profile / f'{image_id}.stdout.txt'
        )

        if not output_path.exists():
            raise FileNotFoundError(
                f'No expected output found: {output_path}'
            )

        # Substitute $TESTDATA_ROOT placeholder with actual path
        content = output_path.read_text()
        return substitute_testdata_root(content, str(self._testdata_root))

    def get_qemu_version_for_profile(self, profile: str) -> str:
        """
        Get a representative qemu version string for a profile.

        Args:
            profile: Profile name (e.g., 'profile-6-0-0', 'profile-8-0-0')

        Returns:
            Version string (e.g., '6.0', '8.0') suitable for --qemu-version
        """
        # Profile names are like 'profile-X-Y-Z', extract X.Y
        parts = profile.replace('profile-', '').split('-')
        if len(parts) >= 2:
            return f'{parts[0]}.{parts[1]}'
        return parts[0]

    def get_profile_for_installed_qemu(
        self,
        output_type: str,
        command: str,
    ) -> str:
        """
        Resolve the profile name matching the host's qemu-img version.

        Phase 5's map-json baselines produced 3 profiles (with two
        format transitions across the 6.0-10.2 range), so the
        existing `next(iter(profiles['profiles']))` pattern is no
        longer safe for any command that has multiple profiles for
        a given output_type. This helper looks up the host's
        qemu-img version in `version_to_profile` via major-minor
        prefix matching.

        Args:
            output_type: 'human' or 'json'
            command: 'info', 'check', 'measure', 'map', etc.

        Returns:
            Profile name (e.g. 'profile-10-0-0'). Falls back to
            the first profile in the version map when the host's
            qemu-img version isn't in the matrix (e.g. a newer
            qemu-img than the baselines cover); byte-equality
            assertions will then surface real format drift.
        """
        profiles = self.get_output_profiles(output_type, command)
        v2p = profiles.get('version_to_profile', {})
        if not v2p:
            return next(iter(profiles['profiles']))

        if self._qemu_version is None:
            return next(iter(v2p.values()))

        major, minor = self._qemu_version
        prefix = f'{major}.{minor}.'
        for key, profile in v2p.items():
            if key.startswith(prefix):
                return profile
        # Major-version fallback: pick the closest version with a
        # matching major, irrespective of minor. Useful when the
        # host runs qemu-img 10.99 and the baselines stop at 10.2.
        major_prefix = f'{major}.'
        for key, profile in v2p.items():
            if key.startswith(major_prefix):
                return profile
        # Last resort: first entry in the map. Real format drift
        # will fail the byte-equality assertion with a clear
        # message.
        return next(iter(v2p.values()))

    def get_image(self, image_id: str) -> TestImage:
        """Get a test image by its ID."""
        if image_id not in self._images_by_id:
            self.fail(f'Unknown image id: {image_id}')
        return self._images_by_id[image_id]

    def get_adversarial_image(self, image_id: str) -> TestImage:
        """Get an adversarial test image, skipping if not found on disk."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def verify_image_hash(self, image: TestImage) -> Tuple[bool, Optional[str]]:
        """
        Verify the SHA256 hash of a test image matches the manifest.

        Args:
            image: The TestImage to verify

        Returns:
            tuple: (is_valid, actual_hash)
                - is_valid: True if hash matches or no hash specified
                - actual_hash: The computed hash, or None if file doesn't exist
        """
        # Check cache first
        if image.id in self._hash_verification_results:
            return self._hash_verification_results[image.id]

        # If no hash specified, consider it valid (backwards compatibility)
        if not image.sha256:
            result = (True, None)
            self._hash_verification_results[image.id] = result
            return result

        # If file doesn't exist, can't verify
        if not image.path.exists():
            result = (False, None)
            self._hash_verification_results[image.id] = result
            return result

        # Compute SHA256 hash
        sha256 = hashlib.sha256()
        with open(image.path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()

        is_valid = actual_hash == image.sha256
        result = (is_valid, actual_hash)
        self._hash_verification_results[image.id] = result
        return result

    def skip_if_hash_mismatch(self, image: TestImage) -> None:
        """
        Skip the test if the image hash doesn't match the manifest.

        This helps catch test data drift - when image files change but
        baselines haven't been regenerated.
        """
        is_valid, actual_hash = self.verify_image_hash(image)

        if not is_valid and actual_hash is not None:
            self.skipTest(
                f'Image {image.id} has changed since baselines were captured.\n'
                f'  Expected SHA256: {image.sha256}\n'
                f'  Actual SHA256:   {actual_hash}\n'
                f'Regenerate baselines in instar-testdata or update manifest hash.'
            )

    def get_instar_binary(self) -> Path:
        """Get path to the instar binary."""
        # Can be overridden by environment variable
        instar_env = os.environ.get('INSTAR_BINARY_PATH')
        if instar_env:
            return Path(instar_env)

        # Default location relative to tests directory
        tests_dir = Path(__file__).parent
        binary = tests_dir.parent / 'src' / 'target' / 'release' / 'instar'

        if not binary.exists():
            self.skipTest(
                f'instar binary not found at {binary}. Run "make instar" first.'
            )

        return binary

    def run_instar_info(
        self,
        image_path: Path,
        timeout: int = 30,
        qemu_version: Optional[str] = None,
        output_format: Optional[str] = None,
        unsafe_quirks: bool = False,
        chain: bool = False,
    ) -> tuple:
        """
        Run instar info on an image.

        Args:
            image_path: Path to the image file
            timeout: Timeout in seconds
            qemu_version: Optional qemu-img version to emulate (e.g., '7.2')
            output_format: Optional output format ('human' or 'json')
            unsafe_quirks: Enable unsafe qemu-img compatibility mode.
                           When True, accepts any file as RAW without requiring
                           a valid partition table. Required for testing images
                           marked with unsafe_quirks_required in the manifest.
            chain: Enable backing chain discovery (--chain)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        instar = self.get_instar_binary()

        cmd = [str(instar), 'info']
        if chain:
            cmd.append('--chain')
        if qemu_version:
            cmd.extend(['--qemu-version', qemu_version])
        if output_format:
            cmd.extend(['--output', output_format])
        if unsafe_quirks:
            cmd.append('--unsafe-quirks')
        cmd.append(str(image_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_info(
        self,
        image_path: Path,
        timeout: int = 30
    ) -> tuple:
        """
        Run qemu-img info on an image.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        try:
            result = subprocess.run(
                ['qemu-img', 'info', str(image_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_instar_check(
        self,
        image_path: Path,
        timeout: int = 30,
        qemu_version: Optional[str] = None,
        output_format: Optional[str] = None,
        unsafe_quirks: bool = False,
        chain: bool = False,
        repair: Optional[str] = None,
    ) -> tuple:
        """
        Run instar check on an image.

        Args:
            image_path: Path to the image file
            timeout: Timeout in seconds
            qemu_version: Optional qemu-img version to emulate
            output_format: Optional output format ('human' or 'json')
            unsafe_quirks: Enable unsafe qemu-img compatible mode.
            chain: Enable backing chain validation (--chain)
            repair: Optional repair tier. When set, appends
                `--repair={repair}` (e.g. 'leaks' or 'all'). Default
                None appends nothing, leaving existing callers unchanged.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        instar = self.get_instar_binary()

        cmd = [str(instar), 'check']
        if qemu_version:
            cmd.extend(['--qemu-version', qemu_version])
        if output_format:
            cmd.extend(['--output', output_format])
        if unsafe_quirks:
            cmd.append('--unsafe-quirks')
        if chain:
            cmd.append('--chain')
        if repair is not None:
            cmd.append(f'--repair={repair}')
        cmd.append(str(image_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_check(
        self,
        image_path: Path,
        timeout: int = 30,
        output_format: Optional[str] = None,
    ) -> tuple:
        """
        Run qemu-img check on an image.

        Args:
            image_path: Path to the image file
            timeout: Timeout in seconds
            output_format: Optional output format ('json' for JSON output)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        cmd = ['qemu-img', 'check']
        if output_format:
            cmd.extend([f'--output={output_format}'])
        cmd.append(str(image_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_instar_rebase(
        self,
        overlay_path: Path,
        *args: str,
        timeout: int = 60,
    ) -> tuple:
        """
        Run `instar rebase` on an overlay image.

        Mirrors `run_instar_check` / `run_instar_info` shape.
        Extra clap arguments (`-u`, `-q`, `-b <PATH>`, `-F <FMT>`,
        `--output json`, etc.) are passed through via *args.

        Args:
            overlay_path: Path to the overlay image (the file being
                rebased).
            *args: Additional rebase flags (e.g. `-u`, `-b`, `BACKING`).
            timeout: Timeout in seconds.

        Returns:
            tuple: (stdout, stderr, return_code).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'rebase', *[str(a) for a in args], str(overlay_path)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_instar_commit(
        self,
        overlay_path: Path,
        *args: str,
        timeout: int = 60,
    ) -> tuple:
        """
        Run `instar commit` on an overlay image.

        Mirrors `run_instar_rebase` shape. Extra clap arguments
        (`-b BASE`, `-f FMT`, `-q`, `--output json`) are passed
        through via *args.

        Args:
            overlay_path: Path to the overlay image (the file being
                committed).
            *args: Additional commit flags.
            timeout: Timeout in seconds.

        Returns:
            tuple: (stdout, stderr, return_code).
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'commit', *[str(a) for a in args], str(overlay_path)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_rebase(
        self,
        overlay_path: Path,
        backing_path,
        *args: str,
        timeout: int = 60,
    ) -> tuple:
        """
        Run `qemu-img rebase` on an overlay image.

        `backing_path` is the value passed to `-b`; pass `""` to
        detach. Extra flags (`-u`, `-q`, `-F <FMT>`) are passed
        through via *args.

        Args:
            overlay_path: Path to the overlay image.
            backing_path: New backing path or empty string for detach.
            *args: Additional rebase flags.
            timeout: Timeout in seconds.

        Returns:
            tuple: (stdout, stderr, return_code).
        """
        cmd = ['qemu-img', 'rebase', '-b', str(backing_path)]
        cmd.extend(str(a) for a in args)
        cmd.append(str(overlay_path))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_instar_compare(
        self,
        image1_path: Path,
        image2_path: Path,
        timeout: int = 30,
        output_format: Optional[str] = None,
        strict: bool = False,
        quiet: bool = False,
        luks_passphrase: str = None,
        sector_size: int = None,
    ) -> tuple:
        """
        Run instar compare on two images.

        Args:
            image1_path: Path to the first image file
            image2_path: Path to the second image file
            timeout: Timeout in seconds
            output_format: Optional output format ('human' or 'json')
            strict: Enable strict mode (fail on size differences)
            quiet: Enable quiet mode
            luks_passphrase: Passphrase for LUKS-encrypted images

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        instar = self.get_instar_binary()

        cmd = [str(instar), 'compare']
        if output_format:
            cmd.extend(['--output', output_format])
        if strict:
            cmd.append('--strict')
        if quiet:
            cmd.append('--quiet')
        if luks_passphrase is not None:
            cmd.extend(['--luks-passphrase', luks_passphrase])
        if sector_size is not None:
            cmd.extend(['--sector-size', str(sector_size)])
        cmd.extend([str(image1_path), str(image2_path)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_compare(
        self,
        image1_path: Path,
        image2_path: Path,
        timeout: int = 30,
        strict: bool = False,
    ) -> tuple:
        """
        Run qemu-img compare on two images.

        Args:
            image1_path: Path to the first image file
            image2_path: Path to the second image file
            timeout: Timeout in seconds
            strict: Enable strict mode (-s flag)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        cmd = ['qemu-img', 'compare']
        if strict:
            cmd.append('-s')
        cmd.extend([str(image1_path), str(image2_path)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_instar_snapshot(
        self,
        *args,
        timeout: int = 60,
        env_overrides: Optional[dict] = None,
    ) -> tuple:
        """Run `instar snapshot` with the given args.

        Accepts an ``env_overrides`` dict so callers can pin
        ``TZ=UTC`` explicitly — the snapshot-list baseline files
        were generated under UTC, so every list invocation that
        compares against a baseline must set TZ=UTC.

        Args:
            *args: Additional snapshot flags and the image path.
            timeout: Timeout in seconds.
            env_overrides: Optional dict of environment variables to
                add/override in the subprocess environment.

        Returns:
            tuple: (stdout, stderr, return_code).
        """
        import os as _os
        instar = self.get_instar_binary()
        cmd = [str(instar), 'snapshot', *[str(a) for a in args]]
        env = dict(_os.environ)
        if env_overrides:
            env.update(env_overrides)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_instar_convert(
        self,
        input_path: Path,
        output_path: Path,
        timeout: int = 60,
        output_format: str = 'raw',
        skip_zeros: bool = None,
        cluster_size: int = None,
        compress: bool = False,
        extended_l2: bool = False,
        luks_encrypt_passphrase: str = None,
        qcow2_password: str = None,
        luks_passphrase: str = None,
        snapshot: str = None,
        max_guest_memory: str = None,
        grain_size: int = None,
        block_size: int = None,
        subformat: str = None,
        sector_size: int = None,
    ) -> tuple:
        """
        Run instar convert on an image.

        Args:
            input_path: Path to the input image file
            output_path: Path to the output image file
            timeout: Timeout in seconds
            output_format: Output format (default: raw)
            skip_zeros: Skip writing zero-filled clusters
                (None=use CLI default which is true)
            cluster_size: Output cluster size (qcow2 only)
            compress: Compress data clusters (qcow2 only)
            qcow2_password: Password for AES-encrypted QCOW2
            luks_passphrase: Passphrase for LUKS-encrypted images
            snapshot: Snapshot ID or name to extract
            subformat: VMDK subformat (monolithicFlat, etc.)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        instar = self.get_instar_binary()

        cmd = [
            str(instar), 'convert',
            '-O', output_format,
        ]
        if skip_zeros is True:
            cmd.append('--skip-zeros')
        elif skip_zeros is False:
            cmd.append('--no-skip-zeros')
        if cluster_size is not None:
            cmd.extend(['--cluster-size', str(cluster_size)])
        if compress:
            cmd.append('--compress')
        if extended_l2:
            cmd.append('--extended-l2')
        if luks_encrypt_passphrase is not None:
            cmd.extend(
                ['--luks-encrypt-passphrase',
                 luks_encrypt_passphrase]
            )
        if qcow2_password is not None:
            cmd.extend(['--qcow2-password', qcow2_password])
        if luks_passphrase is not None:
            cmd.extend(
                ['--luks-passphrase', luks_passphrase]
            )
        if snapshot is not None:
            cmd.extend(['--snapshot', snapshot])
        if max_guest_memory is not None:
            cmd.extend(
                ['--max-guest-memory', max_guest_memory]
            )
        if grain_size is not None:
            cmd.extend(['--grain-size', str(grain_size)])
        if block_size is not None:
            cmd.extend(['--block-size', str(block_size)])
        if subformat is not None:
            cmd.extend(['--subformat', subformat])
        if sector_size is not None:
            cmd.extend(['--sector-size', str(sector_size)])
        cmd.extend([str(input_path), str(output_path)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def assert_size_roundtrip(
        self, image_id, output_format, expected_format,
        suffix, grain_size=None, block_size=None,
        compress=False, timeout=120
    ):
        """Round-trip conversion with a specific grain/block size.

        Converts image_id to output_format with the given
        grain_size or block_size, verifies qemu-img can read
        the result, converts back to raw, and compares against
        a qemu-img baseline.
        """
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )
        self.skip_if_hash_mismatch(image)

        size_label = (
            f'grain={grain_size}' if grain_size
            else f'block={block_size}'
        )

        with tempfile.NamedTemporaryFile(
                suffix=suffix) as fmt_out, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as rt_raw, \
                tempfile.NamedTemporaryFile(
                suffix='.raw') as qemu_raw:
            _, stderr, rc = self.run_instar_convert(
                image.path, Path(fmt_out.name),
                output_format=output_format,
                compress=compress,
                grain_size=grain_size,
                block_size=block_size,
                timeout=timeout
            )
            self.assertEqual(
                rc, 0,
                f'instar convert to {output_format} '
                f'({size_label}) failed for '
                f'{image_id}: {stderr}'
            )

            result = subprocess.run(
                [
                    'qemu-img', 'info', '--output=json',
                    fmt_out.name,
                ],
                capture_output=True, text=True,
                timeout=30
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img info failed ({size_label}): '
                f'{result.stderr}'
            )
            info = json.loads(result.stdout)
            self.assertEqual(
                info.get('format'), expected_format
            )

            _, rt_stderr, rt_rc = \
                self.run_instar_convert(
                    Path(fmt_out.name),
                    Path(rt_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                rt_rc, 0,
                f'Round-trip failed ({size_label}): '
                f'{rt_stderr}'
            )

            _, q_stderr, q_rc = \
                self.run_qemu_img_convert(
                    image.path, Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(q_rc, 0, q_stderr)

            cmp_out, _, cmp_rc = \
                self.run_instar_compare(
                    Path(rt_raw.name),
                    Path(qemu_raw.name),
                    timeout=timeout
                )
            self.assertEqual(
                cmp_rc, 0,
                f'Mismatch ({size_label}): {cmp_out}'
            )

    def assert_convert_rejects(
        self, output_format, suffix, grain_size=None,
        block_size=None
    ):
        """Assert that instar convert rejects invalid parameters."""
        image = self.get_image('raw-mbr-partitioned')
        if not image.path.exists():
            self.skipTest(
                f'Image not found: {image.path}'
            )

        with tempfile.NamedTemporaryFile(
                suffix=suffix) as out:
            _, stderr, rc = self.run_instar_convert(
                image.path, Path(out.name),
                output_format=output_format,
                grain_size=grain_size,
                block_size=block_size
            )
            self.assertNotEqual(
                rc, 0,
                f'Should have rejected '
                f'grain_size={grain_size} '
                f'block_size={block_size}'
            )

    def run_instar_dd(
        self,
        operands: list,
        input_format: Optional[str] = None,
        output_format: Optional[str] = None,
        timeout: int = 60,
    ) -> tuple:
        """
        Run instar dd with the given operands.

        Args:
            operands: List of dd-style operands, e.g. ['if=/path/in',
                'of=/path/out'].
            input_format: Optional input format override (-f flag).
            output_format: Optional output format override (-O flag).
            timeout: Timeout in seconds.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        instar = self.get_instar_binary()

        cmd = [str(instar), 'dd']
        if input_format:
            cmd.extend(['-f', input_format])
        if output_format:
            cmd.extend(['-O', output_format])
        cmd.extend(operands)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_dd(
        self,
        operands: list,
        output_format: Optional[str] = None,
        timeout: int = 60,
    ) -> tuple:
        """
        Run qemu-img dd with the given operands.

        Inserts a default bs=512 operand when the caller does not
        supply one, to match instar dd's default block size and
        ensure byte-identical output for whole-image copies.

        Args:
            operands: List of dd-style operands, e.g. ['if=/path/in',
                'of=/path/out'].
            output_format: Optional output format override (-O flag).
            timeout: Timeout in seconds.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        # Ensure a bs= is present so qemu-img dd uses the same
        # default as instar dd (512 bytes).
        if not any(op.startswith('bs=') for op in operands):
            operands = list(operands) + ['bs=512']

        cmd = ['qemu-img', 'dd']
        if output_format:
            cmd.extend(['-O', output_format])
        cmd.extend(operands)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_qemu_img_convert(
        self,
        input_path: Path,
        output_path: Path,
        timeout: int = 60,
        output_format: str = 'raw',
        input_format: str = None,
        compress: bool = False,
    ) -> tuple:
        """
        Run qemu-img convert on an image.

        Args:
            input_path: Path to the input image file
            output_path: Path to the output image file
            timeout: Timeout in seconds
            output_format: Output format (default: raw)
            input_format: Input format (default: auto-detect)
            compress: Compress data clusters (-c flag)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        cmd = ['qemu-img', 'convert']
        if compress:
            cmd.append('-c')
        if input_format:
            cmd.extend(['-f', input_format])
        cmd.extend([
            '-O', output_format,
            str(input_path),
            str(output_path),
        ])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timeout after {}s'.format(timeout), -1

    def run_adversarial(
        self,
        cmd: list,
        timeout: int = 30,
        max_memory_mb: int = 512
    ) -> tuple:
        """Run a command against an adversarial image with safety checks.

        Asserts that the process completes within the timeout (no hang)
        and exits normally without being killed by a signal (no crash).

        Args:
            cmd: Command and arguments to run
            timeout: Maximum seconds before declaring a hang
            max_memory_mb: Memory limit in MB (applied via RLIMIT_AS)

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        def set_limits():
            mem = max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                preexec_fn=set_limits
            )
        except subprocess.TimeoutExpired:
            self.fail(
                f'Process hung (>{timeout}s): {" ".join(cmd)}'
            )

        if result.returncode < 0:
            sig = -result.returncode
            self.fail(
                f'Process crashed with signal {sig}: '
                f'{result.stderr}'
            )

        return (result.stdout, result.stderr, result.returncode)

    def load_expected_override(self, override_path: str) -> Optional[str]:
        """
        Load expected output from an override file.

        Args:
            override_path: Path relative to tests/expected_outputs/

        Returns:
            The expected output string, or None if file not found.
        """
        tests_dir = Path(__file__).parent
        full_path = tests_dir / override_path

        if not full_path.exists():
            return None

        with open(full_path) as f:
            return f.read()

    def assert_outputs_match(
        self,
        image_id: str,
        instar_output: str,
        expected_output: str,
        image_path: Optional[Path] = None
    ):
        """
        Assert that instar output matches expected output exactly.

        If image_path is provided, the actual disk size is looked up from the
        filesystem and substituted into the expected output. This ensures that
        the "actual-size" (JSON) or "disk size" (human) field comparison uses
        the current filesystem's view of the file, not a potentially stale
        baseline value.

        Provides detailed diff output on failure with whitespace made visible.

        Args:
            image_id: The test image identifier (for error messages)
            instar_output: Output from running instar
            expected_output: Expected output (from baseline or qemu-img)
            image_path: Path to the image file (for disk size substitution)
        """
        # Substitute actual disk size if image path is provided
        if image_path is not None:
            disk_size = get_disk_size(str(image_path))
            expected_output = substitute_actual_size(expected_output, disk_size)

        matched, diff_text = compare_outputs(instar_output, expected_output)

        if not matched:
            msg = format_failure_message(
                image_id, instar_output, expected_output, diff_text
            )
            self.fail(msg)
