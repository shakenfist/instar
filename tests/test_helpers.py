"""Unit tests for tests/helpers/ pure-Python utilities.

These tests don't touch the binary or testdata — they exercise
helper functions in isolation, mainly the info_json
normalisation that the info JSON comparisons rely on, and the pure
parts of the qemu-img create pins (grouping, the pin file's folded BAT
lists, the preallocation byte comparison, and the normalisers).
"""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from helpers import qemu_pins
from helpers.info_json import (
    FILENAME_PLACEHOLDER,
    assert_info_equivalent,
    normalise_info_json,
)


class TestNormaliseInfoJsonStripsDivergence(unittest.TestCase):
    """`normalise_info_json` removes divergent fields per target."""

    def test_universal_actual_size_stripped(self):
        obj = {'format': 'qcow2', 'virtual-size': 1024, 'actual-size': 200704}
        norm = normalise_info_json(obj, 'qcow2')
        self.assertNotIn('actual-size', norm)
        self.assertEqual(norm['virtual-size'], 1024)

    def test_vmdk_cid_stripped(self):
        obj = {
            'format': 'vmdk',
            'virtual-size': 1024,
            'format-specific': {
                'type': 'vmdk',
                'data': {
                    'cid': 3735928559,
                    'parent-cid': 4294967295,
                    'create-type': 'monolithicSparse',
                },
            },
        }
        norm = normalise_info_json(obj, 'vmdk')
        data = norm['format-specific']['data']
        self.assertNotIn('cid', data)
        self.assertNotIn('parent-cid', data)
        self.assertEqual(data['create-type'], 'monolithicSparse')

    def test_vhdx_log_size_stripped(self):
        obj = {
            'format': 'vhdx',
            'format-specific': {'data': {'log-size': 1048576, 'block-size': 33554432}},
        }
        norm = normalise_info_json(obj, 'vhdx')
        self.assertNotIn('log-size', norm['format-specific']['data'])
        self.assertEqual(norm['format-specific']['data']['block-size'], 33554432)

    def test_qcow2_keeps_format_specific(self):
        obj = {
            'format': 'qcow2',
            'format-specific': {
                'data': {
                    'compat': '1.1',
                    'lazy-refcounts': False,
                    'refcount-bits': 16,
                    'extended-l2': False,
                },
            },
            'actual-size': 200704,
        }
        norm = normalise_info_json(obj, 'qcow2')
        self.assertEqual(norm['format-specific']['data']['compat'], '1.1')
        self.assertEqual(norm['format-specific']['data']['refcount-bits'], 16)
        self.assertNotIn('actual-size', norm)

    def test_cache_hint_fields_stripped(self):
        obj = {
            'format': 'qcow2',
            'format-specific': {
                'data': {
                    'compat': '1.1',
                    'refcount-block-cache-size': 1048576,
                    'l2-cache-size': 1048576,
                },
            },
        }
        norm = normalise_info_json(obj, 'qcow2')
        data = norm['format-specific']['data']
        self.assertNotIn('refcount-block-cache-size', data)
        self.assertNotIn('l2-cache-size', data)
        self.assertEqual(data['compat'], '1.1')

    def test_nested_actual_size_stripped(self):
        """children[*].info.actual-size also gets stripped."""
        obj = {
            'format': 'qcow2',
            'children': [
                {'name': 'file', 'info': {'format': 'file', 'actual-size': 4096}},
            ],
            'actual-size': 200704,
        }
        norm = normalise_info_json(obj, 'qcow2')
        self.assertNotIn('actual-size', norm)
        self.assertNotIn('actual-size', norm['children'][0]['info'])

    def test_nested_virtual_size_stripped_but_top_preserved(self):
        """children[*].info.virtual-size (physical file size) stripped;
        top-level virtual-size (format virtual size) preserved.
        """
        obj = {
            'format': 'qcow2',
            'virtual-size': 1048576,
            'children': [
                {'name': 'file', 'info': {'format': 'file',
                                          'virtual-size': 262144}},
            ],
        }
        norm = normalise_info_json(obj, 'qcow2')
        self.assertEqual(norm['virtual-size'], 1048576)
        self.assertNotIn('virtual-size', norm['children'][0]['info'])

    def test_tmp_path_substitution(self):
        obj = {
            'format': 'qcow2',
            'filename': '/tmp/abc/foo.qcow2',
            'children': [
                {'name': 'file', 'info': {'filename': '/tmp/abc/foo.qcow2'}},
            ],
        }
        norm = normalise_info_json(obj, 'qcow2', tmp_path='/tmp/abc/foo.qcow2')
        self.assertEqual(norm['filename'], FILENAME_PLACEHOLDER)
        self.assertEqual(norm['children'][0]['info']['filename'],
                         FILENAME_PLACEHOLDER)

    def test_input_unchanged(self):
        """normalise_info_json must not mutate its input."""
        obj = {'format': 'qcow2', 'actual-size': 1234}
        normalise_info_json(obj, 'qcow2')
        self.assertEqual(obj['actual-size'], 1234)


class TestAssertInfoEquivalent(unittest.TestCase):
    """`assert_info_equivalent` passes on whitelist-only differences."""

    def test_pass_when_only_divergent_fields_differ(self):
        actual = json.dumps({
            'format': 'vmdk',
            'virtual-size': 1024,
            'actual-size': 999,
            'format-specific': {
                'data': {'cid': 11111111, 'create-type': 'monolithicSparse'},
            },
        })
        expected = json.dumps({
            'format': 'vmdk',
            'virtual-size': 1024,
            'actual-size': 200704,
            'format-specific': {
                'data': {'cid': 22222222, 'create-type': 'monolithicSparse'},
            },
        })
        assert_info_equivalent(self, actual, expected, 'vmdk')

    def test_fail_when_non_whitelist_field_differs(self):
        actual = json.dumps({'format': 'qcow2', 'virtual-size': 1024})
        expected = json.dumps({'format': 'qcow2', 'virtual-size': 2048})
        with self.assertRaises(AssertionError):
            assert_info_equivalent(self, actual, expected, 'qcow2')


def _run(first_index, count, kind, state, first_offset, stride):
    return [first_index, count, kind, state, first_offset, stride]


def _interleaved_bat(groups, chunk, state, data_start, block):
    """A summarise()-style BAT: `groups` payload runs of `chunk` entries, each followed by a bitmap slot."""
    runs = []
    index = 0
    for g in range(groups):
        offset = data_start + g * chunk * block if state == 6 else 0
        runs.append(_run(index, chunk, 'payload', state, offset, block if state == 6 else 0))
        runs.append(_run(index + chunk, 1, 'sector_bitmap', 0, 0, 0))
        index += chunk + 1
    runs.append(_run(index, 5, 'payload', state, 0, 0))
    runs.append(_run(index + 5, 100, 'padding', 0, 0, 0))
    return runs


def _pin(results_by_version):
    """A pin as load_pin returns it, built from `{version: {case: result}}`."""
    encoded = qemu_pins.encode_pin(list(results_by_version), qemu_pins.group_results(results_by_version))
    return qemu_pins.decode_pin(json.loads(qemu_pins.dump_pin(encoded)))


class TestQemuPinCases(unittest.TestCase):
    """The case table is well formed."""

    def test_names_unique_and_kinds_known(self):
        names = [case['name'] for case in qemu_pins.CASES]
        self.assertEqual(len(names), len(set(names)))
        for case in qemu_pins.CASES:
            self.assertIn(case['kind'], qemu_pins.RUNNERS, case['name'])

    def test_base_placeholder_only_with_base(self):
        for case in qemu_pins.CASES:
            uses = '{base}' in case.get('args', [])
            self.assertEqual(uses, bool(case.get('base')), case['name'])


class TestQemuPinVersions(unittest.TestCase):
    """Versions sort numerically, not as strings."""

    def test_version_key_numeric(self):
        versions = ['8.2.10', '10.0.0', '8.2.9', '6.0.0']
        self.assertEqual(sorted(versions, key=qemu_pins.version_key), ['6.0.0', '8.2.9', '8.2.10', '10.0.0'])

    def test_newest_pinned_at_or_below(self):
        pin = _pin({'6.0.0': {}, '8.2.9': {}, '8.2.10': {}, '10.2.0': {}})
        self.assertEqual(qemu_pins.newest_pinned_at_or_below('10.0.13', pin), '8.2.10')
        self.assertEqual(qemu_pins.newest_pinned_at_or_below('10.2.0', pin), '10.2.0')
        self.assertIsNone(qemu_pins.newest_pinned_at_or_below('5.2.0', pin))

    def test_qemu_img_version_drops_distro_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'qemu-img'
            fake.write_text('#!/bin/sh\necho "qemu-img version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)"\n')
            fake.chmod(0o755)
            self.assertEqual(qemu_pins.qemu_img_version(fake), '10.0.13')


class TestQemuPinGrouping(unittest.TestCase):
    """Versions with identical results share a group; `expected` refuses a boundary."""

    def setUp(self):
        same = {'rc': 0, 'stderr': ''}
        self.pin = _pin({
            '10.2.0': {'stable': same, 'moved': {'rc': 1, 'stderr': 'b'}},
            '6.0.0': {'stable': same, 'moved': {'rc': 1, 'stderr': 'a'}},
            '6.2.0': {'stable': same, 'moved': {'rc': 1, 'stderr': 'b'}},
        })

    def test_groups(self):
        self.assertEqual(self.pin['versions'], ['6.0.0', '6.2.0', '10.2.0'])
        self.assertEqual([g['versions'] for g in self.pin['cases']['stable']], [['6.0.0', '6.2.0', '10.2.0']])
        self.assertEqual([g['versions'] for g in self.pin['cases']['moved']], [['6.0.0'], ['6.2.0', '10.2.0']])

    def test_expected_single_group(self):
        self.assertEqual(qemu_pins.expected('stable', pin=self.pin), {'rc': 0, 'stderr': ''})

    def test_expected_raises_on_boundary(self):
        pattern = r'moved has 2 results .*6\.0\.0 to 6\.0\.0; 6\.2\.0 to 10\.2\.0'
        with self.assertRaisesRegex(qemu_pins.PinError, pattern):
            qemu_pins.expected('moved', pin=self.pin)

    def test_expected_by_version(self):
        self.assertEqual(qemu_pins.expected('moved', '6.2.0', pin=self.pin)['stderr'], 'b')
        self.assertEqual(qemu_pins.expected('moved', '6.0.0', pin=self.pin)['stderr'], 'a')

    def test_expected_unknown(self):
        with self.assertRaises(qemu_pins.PinError):
            qemu_pins.expected('moved', '7.0.0', pin=self.pin)
        with self.assertRaises(qemu_pins.PinError):
            qemu_pins.expected('absent', pin=self.pin)

    def test_expected_returns_a_copy(self):
        qemu_pins.expected('stable', pin=self.pin)['rc'] = 99
        self.assertEqual(qemu_pins.expected('stable', pin=self.pin)['rc'], 0)

    def test_load_pin_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pin.json'
            bat = _interleaved_bat(50, 128, 2, 0, 0)
            results = {'6.0.0': {'c': {'rc': 0, 'summary': {'file_length': 1, 'bat': bat}}}}
            encoded = qemu_pins.encode_pin(['6.0.0'], qemu_pins.group_results(results))
            path.write_text(qemu_pins.dump_pin(encoded))
            loaded = qemu_pins.load_pin(path)
            self.assertEqual(loaded['cases']['c'][0]['result']['summary']['bat'], bat)
            self.assertLess(len(json.loads(path.read_text())['cases']['c'][0]['result']['summary']['bat']), 5)


class TestQemuPinBatFolding(unittest.TestCase):
    """`compact_bat` folds periodic runs and `expand_bat` restores them exactly."""

    def test_zero_state_interleave(self):
        runs = _interleaved_bat(1000, 64, 2, 0, 0)
        folded = qemu_pins.compact_bat(runs)
        self.assertEqual(len(folded), 3)
        self.assertEqual(folded[0]['repeat'], 1000)
        self.assertEqual(folded[0]['index_step'], 65)
        self.assertEqual(qemu_pins.expand_bat(folded), runs)

    def test_fully_present_offsets_advance_per_run(self):
        runs = _interleaved_bat(31, 4096, 6, 8 << 20, 1 << 20)
        folded = qemu_pins.compact_bat(runs)
        self.assertEqual(folded[0]['offset_steps'], [4096 << 20, 0])
        self.assertEqual(qemu_pins.expand_bat(folded), runs)

    def test_short_lists_unchanged(self):
        runs = [_run(0, 8, 'payload', 2, 0, 0), _run(8, 131064, 'padding', 0, 0, 0)]
        self.assertEqual(qemu_pins.compact_bat(runs), runs)
        irregular = [_run(0, 1, 'payload', 2, 0, 0), _run(1, 1, 'payload', 6, 75497472, 0),
                     _run(2, 1, 'payload', 2, 0, 0), _run(3, 1, 'payload', 6, 83886080, 0),
                     _run(4, 2, 'payload', 2, 0, 0), _run(6, 1, 'payload', 6, 92274688, 0)]
        self.assertEqual(qemu_pins.expand_bat(qemu_pins.compact_bat(irregular)), irregular)


class TestQemuPinNormalisers(unittest.TestCase):
    """What a result keeps of stderr and of a VMDK descriptor."""

    def test_stderr_directory_replaced(self):
        self.assertEqual(
            qemu_pins.normalise_stderr('qemu-img: /tmp/x/case-abc/image.vhdx: Image size too large\n',
                                       Path('/tmp/x/case-abc')),
            'qemu-img: $DIR/image.vhdx: Image size too large\n')

    def test_descriptor(self):
        text = ('version=1\nCID=8432577\nparentCID=ffffffff\n'
                'RW 131072 FLAT "image-flat.vmdk" 0\nRW 131072 SPARSE "image.vmdk"\n')
        self.assertEqual(qemu_pins.normalise_descriptor(text),
                         'version=1\nCID=$CID\nparentCID=ffffffff\n'
                         'RW 131072 FLAT "$EXTENT" 0\nRW 131072 SPARSE "$EXTENT"\n')


class TestQemuPinVolatileMask(unittest.TestCase):
    """The preallocation comparison ignores volatile bytes and nothing else."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def _offs(self):
        # 200 KiB so the comparison spans several chunks; bytes 10-13 and
        # 140000 vary between runs, as a timestamp and a GUID byte would.
        paths = []
        for i in range(4):
            data = bytearray(b'\x11' * (200 * 1024))
            data[10:14] = struct.pack('<I', 1000 + i)
            data[140000] = i
            paths.append(self._write(f'off{i}', bytes(data)))
        return paths

    def test_mask_is_the_varying_bytes(self):
        mask = qemu_pins.volatile_mask(self._offs())
        self.assertEqual(mask, {10, 140000})

    def test_same_outside_mask(self):
        offs = self._offs()
        mask = qemu_pins.volatile_mask(offs)
        mode = bytearray(offs[0].read_bytes())
        mode[10] = 0xFF
        mode[140000] = 0xFF
        self.assertTrue(qemu_pins.same_content(offs[0], self._write('mode', bytes(mode)), mask))

    def test_unmasked_difference(self):
        offs = self._offs()
        mask = qemu_pins.volatile_mask(offs)
        mode = bytearray(offs[0].read_bytes())
        mode[150000] = 0
        self.assertFalse(qemu_pins.same_content(offs[0], self._write('mode', bytes(mode)), mask))

    def test_length_difference(self):
        offs = self._offs()
        mask = qemu_pins.volatile_mask(offs)
        self.assertFalse(qemu_pins.same_content(offs[0], self._write('mode', offs[0].read_bytes() + b'\0'), mask))

    def _vmdk(self, name, descriptor):
        header = b'KDMV' + struct.pack('<IIQQQQ', 1, 3, 131072, 128, 1, 20)
        data = bytearray(64 * 1024)
        data[:len(header)] = header
        data[512:512 + len(descriptor)] = descriptor
        return self._write(name, bytes(data))

    def test_vmdk_descriptor_compared_as_text(self):
        a = self._vmdk('a', b'CID=45edb770\nparentCID=ffffffff\ncreateType="monolithicSparse"\n')
        b = self._vmdk('b', b'CID=8432577\nparentCID=ffffffff\ncreateType="monolithicSparse"\n')
        c = self._vmdk('c', b'CID=8432577\nparentCID=ffffffff\ncreateType="streamOptimized"\n')
        self.assertEqual(qemu_pins.text_regions(a), [(512, 20 * 512)])
        self.assertTrue(qemu_pins.same_content(a, b, set()))
        self.assertFalse(qemu_pins.same_content(a, c, set()))


class TestQemuPinResultDiff(unittest.TestCase):
    """`result_diff` names the field, the pinned value and the measured one."""

    def test_nested_field(self):
        pinned = {'modes': {'full': {'rc': 0, 'same_bytes_as_off': True}}}
        measured = {'modes': {'full': {'rc': 0, 'same_bytes_as_off': False}}}
        self.assertEqual(qemu_pins.result_diff(pinned, measured), ['modes.full.same_bytes_as_off: True != False'])

    def test_summary_uses_structural_diff(self):
        pinned = {'rc': 0, 'summary': {'file_length': 75497472, 'bat': [_run(0, 8, 'payload', 2, 0, 0)]}}
        measured = {'rc': 0, 'summary': {'file_length': 75497472, 'bat': [_run(0, 8, 'payload', 6, 8388608, 8388608)]}}
        self.assertEqual(qemu_pins.result_diff(pinned, measured), [
            'summary: bat run 0: 8 x payload ZERO from entry 0, offset 0 stride 0 != '
            '8 x payload FULLY_PRESENT from entry 0, offset 8388608 stride 8388608'])

    def test_equal(self):
        self.assertEqual(qemu_pins.result_diff({'rc': 1, 'stderr': 'x'}, {'rc': 1, 'stderr': 'x'}), [])


if __name__ == '__main__':
    unittest.main()
