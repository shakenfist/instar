"""Base test class for imago integration tests."""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import testtools

from helpers.comparators import compare_outputs, format_failure_message
from helpers.types import TestImage


class ImagoTestBase(testtools.TestCase):
    """Base class for imago integration tests."""

    # Class-level cache for manifest and images
    _manifest = None
    _images_by_id = None
    _testdata_root = None

    @classmethod
    def setUpClass(cls):
        """Load manifest once for all tests in the class."""
        super().setUpClass()
        cls._load_manifest()

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
        testdata_env = os.environ.get('IMAGO_TESTDATA_PATH')
        if testdata_env:
            cls._testdata_root = Path(testdata_env)
        else:
            cls._testdata_root = tests_dir.parent.parent / 'imago-testdata'

        if not cls._testdata_root.exists():
            raise RuntimeError(
                f'Test data directory not found: {cls._testdata_root}\n'
                f'Set IMAGO_TESTDATA_PATH environment variable or ensure '
                f'imago-testdata is a sibling directory.'
            )

        # Build lookup by image id
        cls._images_by_id = {}
        for img_data in cls._manifest.get('images', []):
            image = TestImage.from_dict(img_data, cls._testdata_root)
            cls._images_by_id[image.id] = image

    def get_image(self, image_id: str) -> TestImage:
        """Get a test image by its ID."""
        if image_id not in self._images_by_id:
            self.fail(f'Unknown image id: {image_id}')
        return self._images_by_id[image_id]

    def get_imago_binary(self) -> Path:
        """Get path to the imago binary."""
        # Can be overridden by environment variable
        imago_env = os.environ.get('IMAGO_BINARY_PATH')
        if imago_env:
            return Path(imago_env)

        # Default location relative to tests directory
        tests_dir = Path(__file__).parent
        binary = tests_dir.parent / 'src' / 'target' / 'release' / 'imago'

        if not binary.exists():
            self.skipTest(
                f'imago binary not found at {binary}. Run "make imago" first.'
            )

        return binary

    def run_imago_info(
        self,
        image_path: Path,
        timeout: int = 30
    ) -> tuple:
        """
        Run imago info on an image.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        imago = self.get_imago_binary()

        try:
            result = subprocess.run(
                [str(imago), 'info', str(image_path)],
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
        imago_output: str,
        expected_output: str
    ):
        """
        Assert that imago output matches expected output exactly.

        Provides detailed diff output on failure with whitespace made visible.
        """
        matched, diff_text = compare_outputs(imago_output, expected_output)

        if not matched:
            msg = format_failure_message(
                image_id, imago_output, expected_output, diff_text
            )
            self.fail(msg)
