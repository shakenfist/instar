"""`instar info` reads split-sparse VMDK images and reports the size they declare.

A `twoGbMaxExtentSparse` image is a descriptor naming sparse extent files,
each with its own header and grain directory. Its virtual size is the sum of
the extent lengths the descriptor declares, and qemu-img reports the same
figure. These images were once refused; a baseline comparison that skips
proves nothing about them being read, so this pins the capability directly,
including past the 15-extent ceiling on attached devices.
"""

import json
import subprocess

from base import InstarTestBase
from helpers import qemu_pins
from helpers.vmdk_structure import descriptor_extents, read_descriptor

IMAGES = [
    'vmdk-split-sparse-2049m',
    'vmdk-split-sparse-5g',
    'vmdk-split-sparse-5g-boundary',
    'vmdk-split-sparse-33g',
    'osboxes-vmdk-split-sparse',
]

SECTOR = 512


class TestInfoSplitSparse(InstarTestBase):

    def _image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image.path

    def _qemu_img(self):
        builds = qemu_pins.qemu_img_builds(self._testdata_root / 'qemu-img-binaries' / 'x86_64')
        if '10.2.0' not in builds:
            self.skipTest('pinned qemu-img 10.2.0 not available')
        return builds['10.2.0']

    def _instar_info(self, path):
        result = subprocess.run([str(self.get_instar_binary()), 'info', '--output', 'json', str(path)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def _declared_size(self, path):
        text, _ = read_descriptor(path)
        extents = descriptor_extents(text)
        self.assertTrue(extents, f'{path} declares no extents')
        return sum(extent['sectors'] for extent in extents) * SECTOR

    def test_is_read_as_vmdk(self):
        for image_id in IMAGES:
            with self.subTest(image=image_id):
                self.assertEqual('vmdk', self._instar_info(self._image(image_id))['format'])

    def test_reports_the_size_the_descriptor_declares(self):
        for image_id in IMAGES:
            with self.subTest(image=image_id):
                path = self._image(image_id)
                declared = self._declared_size(path)
                self.assertGreater(declared, 0)
                self.assertEqual(declared, self._instar_info(path)['virtual-size'])

    def test_agrees_with_qemu_img(self):
        for image_id in IMAGES:
            with self.subTest(image=image_id):
                path = self._image(image_id)
                result = subprocess.run([str(self._qemu_img()), 'info', '--output=json', str(path)],
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(json.loads(result.stdout)['virtual-size'], self._instar_info(path)['virtual-size'])
