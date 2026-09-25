#!/usr/bin/env python3
"""Unit tests for the fuzz corpus seed builders.

Runs with plain `python3 -m unittest` (stdlib only, no venv), like
`test_check_test_partition.py` next to it.

The seed builders in `scripts/extract-fuzz-corpus.py` are the only thing
standing between an adversarial testdata fixture and the nightly
`Seed corpus from testdata` step, and they run unattended: a fixture
that makes one of them raise takes the whole run down, seeding nothing
for any of the 42 targets, and a fixture whose defect is silently
normalised away costs coverage nobody will notice missing. Both of those
have happened, so both are asserted here.

The fixtures are synthesised rather than read from instar-testdata: this
file has to run in the `ci-tooling` job, which has no testdata checkout.
"""

import os
import re
import shutil
import tempfile
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_EFC_PATH = os.path.join(_HERE, '..', '..', 'scripts', 'extract-fuzz-corpus.py')


def _load(path, name):
    """Execute a hyphenated script as a module, compiling from source.

    Deliberately not `importlib.util.spec_from_file_location`: that goes
    through the bytecode cache, whose freshness check is the source's
    size plus an mtime at one-second resolution. An edit that preserves
    the file size and lands in the same second as the previous run --
    which is exactly what breaking a constant to check that a test
    notices looks like -- is served from `__pycache__` instead, and the
    test then passes against code that is no longer on disk. Compiling
    the text every time costs milliseconds and cannot go stale.
    """
    module = types.ModuleType(name)
    module.__file__ = path
    with open(path, encoding='utf-8') as f:
        source = f.read()
    exec(compile(source, path, 'exec'), module.__dict__)
    return module


efc = _load(_EFC_PATH, 'extract_fuzz_corpus')


def rust_const_bytes(name):
    """The byte values of a `pub const NAME: [u8; N]` in the vhdx crate."""
    path = os.path.join(_HERE, '..', '..', 'src', 'crates', 'vhdx', 'src', 'lib.rs')
    with open(path, encoding='utf-8') as f:
        source = f.read()
    match = re.search(
        r'pub const ' + re.escape(name) + r': \[u8; \d+\] = \[(.*?)\];',
        source, re.DOTALL)
    if match is None:
        raise AssertionError('%s is no longer declared in %s' % (name, path))
    return [int(v, 0) for v in match.group(1).replace('\n', ' ').split(',') if v.strip()]


def build_differencing_vhd(locators, size=1024 * 1024, data_offset=512):
    """A synthetic differencing VHD carrying the given locator entries.

    `locators` is a list of (platform_code, data_offset, data_length)
    triples, assigned to consecutive slots. Returns the image bytes; the
    caller decides what, if anything, lives at those offsets.
    """
    img = bytearray(size)

    header = bytearray(efc.DYNAMIC_HEADER_SIZE)
    header[0:8] = b'cxsparse'
    for slot, (code, data_off, data_length) in enumerate(locators):
        off = efc.VHD_DYN_PARENT_LOCATORS_OFFSET + slot * efc.VHD_PARENT_LOCATOR_ENTRY_SIZE
        header[off:off + 4] = code
        header[off + efc.VHD_LOC_DATA_SPACE_OFFSET:off + efc.VHD_LOC_DATA_SPACE_OFFSET + 4] = \
            (data_length).to_bytes(4, 'big')
        header[off + efc.VHD_LOC_DATA_LENGTH_OFFSET:off + efc.VHD_LOC_DATA_LENGTH_OFFSET + 4] = \
            (data_length).to_bytes(4, 'big')
        header[off + efc.VHD_LOC_DATA_OFFSET_OFFSET:off + efc.VHD_LOC_DATA_OFFSET_OFFSET + 8] = \
            (data_off).to_bytes(8, 'big')
    img[data_offset:data_offset + efc.DYNAMIC_HEADER_SIZE] = header

    footer = bytearray(efc.FOOTER_SIZE)
    footer[0:8] = b'conectix'
    footer[16:24] = (data_offset).to_bytes(8, 'big')
    footer[60:64] = (4).to_bytes(4, 'big')  # DISK_TYPE_DIFFERENCING
    img[size - efc.FOOTER_SIZE:] = footer

    return bytes(img)


def locator_offset(seed, slot):
    """Read slot `slot`'s platform_data_offset back out of a seed."""
    off = efc.VHD_DYN_PARENT_LOCATORS_OFFSET + slot * efc.VHD_PARENT_LOCATOR_ENTRY_SIZE
    field = off + efc.VHD_LOC_DATA_OFFSET_OFFSET
    return int.from_bytes(seed[field:field + 8], 'big')


class SeedBuilderTestCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work)

    def write_image(self, name, content):
        path = os.path.join(self.work, name)
        with open(path, 'wb') as f:
            f.write(content)
        return path

    def extract(self, image):
        """Run the extractor and return the single seed it wrote."""
        dest = os.path.join(self.work, 'corpus')
        wrote = efc.extract_vhd_parent_seed(image, dest)
        if not wrote:
            return None
        names = os.listdir(dest)
        self.assertEqual(len(names), 1, 'expected exactly one seed, got %r' % names)
        with open(os.path.join(dest, names[0]), 'rb') as f:
            return f.read()


class TestHostileOffsets(SeedBuilderTestCase):
    """An offset the fixture chose, not one the extractor can trust."""

    def test_offset_above_seek_limit_does_not_raise(self):
        # 2**64-8 makes f.seek raise ValueError, not OSError: before the
        # guard this escaped the handler and aborted the whole run.
        img = build_differencing_vhd([(b'W2ru', 2 ** 64 - 8, 16)])
        seed = self.extract(self.write_image('hostile.vhd', img))
        self.assertIsNotNone(seed, 'a hostile offset should still yield a seed')

    def test_offset_past_end_of_file_is_preserved(self):
        # The defect is the point of the fixture. Relocating it would
        # rewrite it to a valid in-window offset and the seed would
        # exercise the success path instead of locator_defect.
        hostile = 2 ** 63 + 4096
        img = build_differencing_vhd([(b'W2ru', hostile, 16)])
        seed = self.extract(self.write_image('past-end.vhd', img))
        self.assertEqual(locator_offset(seed, 0), hostile)

    def test_all_entries_out_of_range_still_seeds(self):
        img = build_differencing_vhd([(b'W2ru', 2 ** 64 - 8, 16),
                                      (b'W2ku', 2 ** 63, 32)])
        seed = self.extract(self.write_image('all-hostile.vhd', img))
        self.assertIsNotNone(seed)
        # Header plus the bare control prefix, no platform data carried.
        self.assertEqual(len(seed), efc.DYNAMIC_HEADER_SIZE + efc.VHD_PARENT_TAIL_RESERVED)

    def test_length_overflowing_the_file_is_preserved(self):
        # The offset is in the file but the extent is not, which is a
        # distinct defect class from an offset past the end.
        img = build_differencing_vhd([(b'W2ru', 4096, 0xFFFFFFFF)])
        seed = self.extract(self.write_image('long.vhd', img))
        self.assertEqual(locator_offset(seed, 0), 4096)


class TestRelocation(SeedBuilderTestCase):
    """In-range entries move together and keep their relative spacing."""

    def test_in_range_entry_is_relocated_and_data_follows(self):
        payload = b'./parent-disk.vhd\x00'
        img = bytearray(build_differencing_vhd([(b'W2ru', 4096, len(payload))]))
        img[4096:4096 + len(payload)] = payload
        seed = self.extract(self.write_image('good.vhd', bytes(img)))

        new_off = locator_offset(seed, 0)
        window_file_offset = efc.FOOTER_SIZE + efc.DYNAMIC_HEADER_SIZE
        self.assertEqual(new_off, window_file_offset + efc.VHD_PARENT_TAIL_RESERVED)

        # The target synthesises a window whose file_offset is 1536 and
        # whose bytes are the tail after the reserved prefix, so the
        # relocated offset has to index the seed at new_off - 1536.
        at = new_off - window_file_offset + efc.DYNAMIC_HEADER_SIZE
        self.assertEqual(seed[at:at + len(payload)], payload)

    def test_mixed_entries_relocate_only_the_reachable_one(self):
        payload = b'parent.vhd\x00'
        img = bytearray(build_differencing_vhd([(b'W2ru', 2 ** 64 - 8, 16),
                                                (b'W2ku', 8192, len(payload))]))
        img[8192:8192 + len(payload)] = payload
        seed = self.extract(self.write_image('mixed.vhd', bytes(img)))

        self.assertEqual(locator_offset(seed, 0), 2 ** 64 - 8)
        window_file_offset = efc.FOOTER_SIZE + efc.DYNAMIC_HEADER_SIZE
        self.assertEqual(locator_offset(seed, 1),
                         window_file_offset + efc.VHD_PARENT_TAIL_RESERVED)

    def test_two_entries_keep_their_relative_spacing(self):
        img = bytearray(build_differencing_vhd([(b'W2ru', 4096, 8),
                                                (b'W2ku', 4200, 8)]))
        img[4096:4104] = b'AAAAAAAA'
        img[4200:4208] = b'BBBBBBBB'
        seed = self.extract(self.write_image('two.vhd', bytes(img)))
        self.assertEqual(locator_offset(seed, 1) - locator_offset(seed, 0), 4200 - 4096)

    def test_entry_beyond_the_region_clamp_is_left_alone(self):
        # region_len is clamped to 65536, so an entry further out than
        # that is in the file but not in the bytes carried. Relocating
        # it would point into the middle of another entry's data.
        far = 4096 + 65536 + 512
        img = bytearray(build_differencing_vhd([(b'W2ru', 4096, 8),
                                                (b'W2ku', far, 8)],
                                               size=4 * 1024 * 1024))
        seed = self.extract(self.write_image('clamped.vhd', bytes(img)))
        self.assertEqual(locator_offset(seed, 1), far)


class TestRefusals(SeedBuilderTestCase):
    """Shapes the extractor must decline rather than mangle."""

    def test_non_differencing_image_is_declined(self):
        img = bytearray(build_differencing_vhd([(b'W2ru', 4096, 8)]))
        img[len(img) - efc.FOOTER_SIZE + 60:len(img) - efc.FOOTER_SIZE + 64] = (3).to_bytes(4, 'big')
        self.assertIsNone(self.extract(self.write_image('dynamic.vhd', bytes(img))))

    def test_image_with_no_populated_locators_is_declined(self):
        img = build_differencing_vhd([])
        self.assertIsNone(self.extract(self.write_image('empty.vhd', img)))

    def test_zero_length_entry_is_not_a_populated_locator(self):
        img = build_differencing_vhd([(b'W2ru', 4096, 0)])
        self.assertIsNone(self.extract(self.write_image('zerolen.vhd', img)))

    def test_truncated_file_is_declined(self):
        self.assertIsNone(self.extract(self.write_image('tiny.vhd', b'conectix')))

    def test_missing_file_is_declined(self):
        self.assertIsNone(self.extract(os.path.join(self.work, 'absent.vhd')))


class TestMinimalSeeds(unittest.TestCase):
    """The hand-built seeds must be in the shape their target accepts.

    Neither target reaches anything if its seed is refused at the first
    check, and a seed that is refused looks exactly like a target that
    found no bug.
    """

    def test_vhd_parent_seed_is_accepted_by_its_target(self):
        seed = efc.build_minimal_vhd_parent_seed()
        # fuzz_vhd_parent returns early below DYNAMIC_HEADER_SIZE, then
        # VhdParentInfo::parse refuses anything without the cookie at 0.
        self.assertGreater(len(seed), efc.DYNAMIC_HEADER_SIZE)
        self.assertEqual(seed[0:8], b'cxsparse')
        # tail[0] is the selector; 0x00 picks the realistic arms.
        self.assertEqual(seed[efc.DYNAMIC_HEADER_SIZE], 0x00)
        # At least one populated locator, or the target parses a table
        # with nothing in it and asserts nothing interesting.
        populated = [
            slot for slot in range(efc.VHD_PARENT_LOCATOR_COUNT)
            if seed[efc.VHD_DYN_PARENT_LOCATORS_OFFSET
                    + slot * efc.VHD_PARENT_LOCATOR_ENTRY_SIZE:
                    efc.VHD_DYN_PARENT_LOCATORS_OFFSET
                    + slot * efc.VHD_PARENT_LOCATOR_ENTRY_SIZE + 4] != b'\x00\x00\x00\x00'
        ]
        self.assertTrue(populated, 'the minimal seed carries no populated locator')

    def test_vhdx_parent_seed_carries_the_locator_type_guid(self):
        seed = efc.build_minimal_vhdx_parent_seed()
        # fuzz_vhdx_parent hands the item straight to
        # vhdx::parse_parent_locator, which refuses anything whose first
        # 16 bytes are not the parent-locator type GUID. The expected
        # bytes are read out of the crate rather than restated here: the
        # crate declares a second, adjacent PARENT_LOCATOR_GUID and its
        # own docstring says the two are easy to confuse, so a copy in
        # this file would assert only that the copy had not changed.
        self.assertGreaterEqual(len(seed), 20)
        self.assertEqual(list(seed[0:16]), rust_const_bytes('VHDX_PARENT_LOCATOR_TYPE_GUID'))

    def test_the_parent_targets_are_not_in_format_to_targets(self):
        # A whole-image seed is refused at the cookie or GUID check on
        # every run, while still setting libFuzzer's unit size from its
        # multi-megabyte length.
        for fmt in ('vpc', 'vhd'):
            self.assertNotIn('fuzz_vhd_parent', efc.FORMAT_TO_TARGETS[fmt])
        self.assertNotIn('fuzz_vhdx_parent', efc.FORMAT_TO_TARGETS['vhdx'])


if __name__ == '__main__':
    unittest.main()
