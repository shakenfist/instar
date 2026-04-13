# Test helper modules

import json
from pathlib import Path


def load_manifest_images():
    """Load raw image dicts from manifest.json.

    This is a module-level helper for use in scenario
    generation functions that run at import time (before
    any test class is instantiated). For TestImage objects
    inside test methods, use InstarTestBase.get_image().

    Returns:
        List of image dicts from the manifest, or [] if
        manifest.json does not exist.
    """
    tests_dir = Path(__file__).parent.parent
    manifest_path = tests_dir / 'manifest.json'
    if not manifest_path.exists():
        return []
    with open(manifest_path) as f:
        manifest = json.load(f)
    return manifest.get('images', [])
