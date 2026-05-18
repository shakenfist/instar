"""Unit tests for tests/helpers/ pure-Python utilities.

These tests don't touch the binary or testdata — they exercise
helper functions in isolation, mainly the info_json
normalisation that phase 8 relies on.
"""

import json
import unittest

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


if __name__ == '__main__':
    unittest.main()
