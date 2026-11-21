"""`info --chain` reports a VMDK descriptor's allocation as the whole image's.

A descriptor is a few hundred bytes of text; the data lives in its extents.
qemu-img reports the sum over the descriptor and every extent as
`actual-size`, for each member of a chain, and `info --chain` must agree
with it and with the same tool's non-chain `info` on the same image.
"""

import json
import os
import subprocess

from base import InstarTestBase
from helpers import qemu_pins

IMAGES = [
    'vmdk-split-sparse-33g.vmdk',
    'vmdk-multi-flat.vmdk',
    'vmdk-flat-with-parent.vmdk',
]


class TestInfoChainSizes(InstarTestBase):

    def _image(self, name):
        path = self._testdata_root / 'custom' / 'format-coverage' / name
        if not path.exists():
            self.skipTest(f'Test image not found: {path}')
        return path

    def _qemu_img(self):
        builds = qemu_pins.qemu_img_builds(self._testdata_root / 'qemu-img-binaries' / 'x86_64')
        if '10.2.0' not in builds:
            self.skipTest('pinned qemu-img 10.2.0 not available')
        return builds['10.2.0']

    def _instar(self, image, *flags, chain=True):
        cmd = [str(self.get_instar_binary()), 'info']
        if chain:
            cmd.append('--chain')
        cmd.extend(flags)
        cmd.extend(['--output', 'json', str(image)])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def _qemu_chain(self, image):
        result = subprocess.run(
            [str(self._qemu_img()), 'info', '--backing-chain', '--output=json', str(image)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        return [(os.path.basename(m['filename']), m['actual-size']) for m in json.loads(result.stdout)]

    def _members(self, chain):
        return [(os.path.basename(m['filename']), m['actual-size']) for m in chain]

    def test_every_member_matches_qemu(self):
        for name in IMAGES:
            with self.subTest(image=name):
                image = self._image(name)
                self.assertEqual(self._qemu_chain(image), self._members(self._instar(image)))

    def test_chain_agrees_with_non_chain_info(self):
        for name in IMAGES:
            for flags in ((), ('--ignore-quirks',)):
                with self.subTest(image=name, flags=flags):
                    image = self._image(name)
                    top = self._instar(image, *flags)[0]['actual-size']
                    self.assertEqual(self._instar(image, *flags, chain=False)['actual-size'], top)

    def test_ignore_quirks_counts_file_lengths_for_every_member(self):
        # No qemu-img flag asks for apparent sizes, so the expectation is
        # measured: each descriptor's length plus its extents' lengths.
        image = self._image('vmdk-flat-with-parent.vmdk')
        directory = image.parent
        expected = [
            ('vmdk-flat-with-parent.vmdk',
             os.path.getsize(image) + os.path.getsize(directory / 'vmdk-flat-with-parent-flat.vmdk')),
        ]
        parent = directory / 'vmdk-flat-parent.vmdk'
        extent = [line.split('"')[1] for line in parent.read_text().splitlines()
                  if line.startswith(('RW', 'RDONLY')) and '"' in line]
        self.assertEqual(1, len(extent))
        expected.append((parent.name, os.path.getsize(parent) + os.path.getsize(directory / extent[0])))
        self.assertEqual(expected, self._members(self._instar(image, '--ignore-quirks')))

    def test_human_output_reports_the_same_figure(self):
        image = self._image('vmdk-flat-with-parent.vmdk')
        expected = self._members(self._instar(image))
        result = subprocess.run([str(self.get_instar_binary()), 'info', '--chain', str(image)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        sizes = [int(line.split('(')[1].split(' ')[0]) for line in result.stdout.splitlines()
                 if line.strip().startswith('disk size:')]
        self.assertEqual([size for _, size in expected], sizes)

    def test_extents_are_not_labelled_as_data_files(self):
        image = self._image('vmdk-multi-flat.vmdk')
        result = subprocess.run([str(self.get_instar_binary()), 'info', '--chain', str(image)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(3, result.stdout.count('VMDK extent: '))
        self.assertNotIn('External data file', result.stdout)
