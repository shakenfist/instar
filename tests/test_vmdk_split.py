"""Unit tests for the split-flat VMDK generator in helpers/vmdk_split.py.

These need a pinned qemu-img build from the testdata checkout, which is
why they are here rather than in test_helpers.py: that file's tests touch
neither the binary nor testdata, and keeping it that way is what lets it
run anywhere in a fraction of a second.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import qemu_pins
from helpers.vmdk_split import split_flat_image
from helpers.vmdk_structure import descriptor_extents, read_descriptor


def _testdata_root() -> Path:
    """The testdata checkout, resolved the way base.py resolves it.

    The environment variable wins, and otherwise the checkout is the
    sibling directory. `make test` sets no environment variable, so an
    env-only lookup would fail here while every other test in the suite
    found its data.
    """
    override = os.environ.get('INSTAR_TESTDATA_PATH')
    if override:
        return Path(override)
    return Path(__file__).parent.parent.parent / 'instar-testdata'


class TestSplitFlatImage(unittest.TestCase):
    """`split_flat_image` makes a split-flat VMDK with a pinned qemu-img, and cleans up."""

    def setUp(self):
        builds = qemu_pins.qemu_img_builds(_testdata_root() / 'qemu-img-binaries' / 'x86_64')
        self.assertIn('10.2.0', builds)
        self.qemu_img = builds['10.2.0']
        self.workdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    def test_five_gib_geometry(self):
        with split_flat_image(self.qemu_img, '5G', self.workdir) as image:
            self.assertEqual(len(image.extents), 3)
            text, _ = read_descriptor(image.descriptor)
            declared = descriptor_extents(text)
            self.assertEqual([one['sectors'] for one in declared], [4194304, 4194304, 2097152])
            self.assertEqual([os.path.getsize(path) for path in image.extents],
                             [2147483648, 2147483648, 1073741824])
            self.assertEqual([path.name for path in image.extents],
                             ['image-f001.vmdk', 'image-f002.vmdk', 'image-f003.vmdk'])

    def test_directory_is_removed(self):
        with split_flat_image(self.qemu_img, '5G', self.workdir) as image:
            directory = image.descriptor.parent
            self.assertTrue(directory.is_dir())
        self.assertFalse(directory.exists())
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_directory_is_removed_on_error(self):
        with self.assertRaises(ZeroDivisionError):
            with split_flat_image(self.qemu_img, '5G', self.workdir):
                1 / 0
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_missing_qemu_img_raises(self):
        with self.assertRaises(FileNotFoundError):
            with split_flat_image(self.workdir / 'no-such-qemu-img', '5G', self.workdir):
                pass

    def test_non_executable_qemu_img_raises(self):
        fake = self.workdir / 'qemu-img'
        fake.write_text('#!/bin/sh\n')
        fake.chmod(0o644)
        with self.assertRaises(FileNotFoundError):
            with split_flat_image(fake, '5G', self.workdir):
                pass

    def test_a_bare_name_is_not_looked_up_on_path(self):
        """A name with no directory must not resolve to the host's qemu-img.

        Which build made an image decides what it looks like, so the
        generator takes a path and checks it, rather than searching PATH
        and quietly accepting whatever the host happens to have.
        """
        with self.assertRaises(FileNotFoundError):
            with split_flat_image('qemu-img', '5G', self.workdir):
                pass

    def test_failed_create_raises(self):
        with self.assertRaises(RuntimeError):
            with split_flat_image(self.qemu_img, 'not-a-size', self.workdir):
                pass
        self.assertEqual(list(self.workdir.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
