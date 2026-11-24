"""Guard the hand-copied split VMDK descriptors in the vmdk crate against the qemu pin.

The vmdk crate's tests hold twelve qemu-written split descriptors as Rust
string literals, because the Rust workspace has no JSON parser and so cannot
read `tests/golden/qemu-create-pins.json`. Nothing in Rust can check that
copy: an emitter and its expectations written from the same misreading agree
with each other. These tests read the pin and the Rust source as text and
check the copy here, so they are the one check an emitter bug cannot satisfy.

Source-only: no testdata is needed except for the fixture comparison, which
fails rather than skips when the clone is absent, as `InstarTestBase` does for
every other test in the suite. The fixture is the only committed witness past
sixteen extents and past 65535 cylinders, so a skip there would read as a pass
on the one check an emitter bug cannot satisfy.
"""

import difflib
import os
import re
import unittest
from pathlib import Path

from helpers import qemu_pins

REPIN_HINT = 're-run tools/sweep-qemu-create.py --write tests/golden/qemu-create-pins.json'

RUST_SOURCE = Path(__file__).resolve().parent.parent / 'src' / 'crates' / 'vmdk' / 'src' / 'lib.rs'

# The qemu builds from which the split descriptors are stable.
LAST_GROUP_FIRST_VERSION = '6.2.0'
LAST_GROUP_LAST_VERSION = '10.2.0'

# What the emitter writes for CID, and so what the literals hold.
CID = 'fffffffe'
STEM = 'image'

FIXTURE = Path('custom') / 'format-coverage' / 'vmdk-split-sparse-33g.vmdk'
FIXTURE_CONSTANT = 'QEMU_SPLIT_SPARSE_33G'

DESCRIPTOR_START = '# Disk DescriptorFile\n'
DESCRIPTOR_END = 'ddb.toolsVersion = "2147483647"\n'


def _multi_cases():
    return [name for name in qemu_pins.load_pin()['cases'] if name.startswith('vmdk-multi-')]


def _last_group(case_name):
    group = qemu_pins.load_pin()['cases'][case_name][-1]
    versions = group['versions']
    if versions[0] != LAST_GROUP_FIRST_VERSION or versions[-1] != LAST_GROUP_LAST_VERSION:
        raise AssertionError(
            f'{case_name}: the last pin group covers {versions[0]} to {versions[-1]}, not '
            f'{LAST_GROUP_FIRST_VERSION} to {LAST_GROUP_LAST_VERSION}; the literals were copied from the '
            f'latter, so check what changed before trusting them; {REPIN_HINT}')
    return group['result']


def _rebuild(result):
    """The real descriptor text a pin result records, with its placeholders filled in."""
    text = result['descriptor'].replace(qemu_pins.CID_PLACEHOLDER, CID)
    names = result['extent_names']
    # Highest index first: `$EXTENT1` is a prefix of `$EXTENT10` and `$EXTENT11`, so substituting in
    # ascending order would corrupt the eleven-extent case.
    for index in range(len(names), 0, -1):
        text = text.replace(f'{qemu_pins.EXTENT_PLACEHOLDER_PREFIX}{index}',
                            names[index - 1].replace(qemu_pins.STEM_PLACEHOLDER, STEM))
    text = text.replace(qemu_pins.STEM_PLACEHOLDER, STEM)
    if '$' in text:
        raise AssertionError(f'unsubstituted placeholder left in descriptor:\n{text}')
    return text


def _rust_source():
    return RUST_SOURCE.read_text(encoding='utf-8')


def _unescape(rust_text):
    # The literals use real newlines at column zero, not `\n` escapes, so the only escape in them is
    # `\"`. That is the only one undone; do not grow this into a general Rust string unescaper.
    return rust_text.replace('\\"', '"')


def _candidates(text):
    """Every descriptor-shaped block in `text`."""
    blocks = []
    start = 0
    while True:
        begin = text.find(DESCRIPTOR_START, start)
        if begin < 0:
            return blocks
        end = text.find(DESCRIPTOR_END, begin)
        if end < 0:
            return blocks
        end += len(DESCRIPTOR_END)
        blocks.append(text[begin:end])
        start = end


def _diff_against_nearest(want, source):
    blocks = _candidates(source)
    if not blocks:
        return 'no descriptor literal is present in the Rust file at all'
    nearest = max(blocks, key=lambda b: difflib.SequenceMatcher(None, want, b, autojunk=False).ratio())
    diff = difflib.unified_diff(want.splitlines(keepends=True), nearest.splitlines(keepends=True),
                                'pin (expected)', 'lib.rs (nearest literal)')
    return ''.join(diff) or '(the nearest literal differs only in trailing text)'


class TestSplitDescriptorLiterals(unittest.TestCase):
    """Each pinned multi-extent descriptor appears verbatim in the vmdk crate's tests."""

    def test_pin_has_the_fourteen_cases(self):
        self.assertEqual(14, len(_multi_cases()), _multi_cases())

    def test_every_pin_descriptor_is_in_the_rust_source(self):
        source = _unescape(_rust_source())
        for case_name in _multi_cases():
            with self.subTest(case=case_name):
                want = _rebuild(_last_group(case_name))
                if want in source:
                    continue
                self.fail(f'{case_name}: the pinned descriptor is not in {RUST_SOURCE.name}.\n'
                          f'{_diff_against_nearest(want, source)}\n'
                          f'Either re-copy the literal from the pin, or if qemu is what changed, {REPIN_HINT}.')

    def test_existing_extent_cases_match_the_plain_ones(self):
        # The Rust constants for these rows are one constant, so only the pin can say the sharing is true.
        for subformat in ('sparse', 'flat'):
            plain = f'vmdk-multi-{subformat}-5G'
            existing = f'{plain}-existing-extent'
            with self.subTest(case=existing):
                want = _rebuild(_last_group(plain))
                got = _rebuild(_last_group(existing))
                if want == got:
                    continue
                diff = ''.join(difflib.unified_diff(want.splitlines(keepends=True), got.splitlines(keepends=True),
                                                    plain, existing))
                self.fail(f'{existing}: qemu now writes a different descriptor when a file is in the way, '
                          f'but the Rust tests share one literal for it and {plain}.\n{diff}\n'
                          f'Give the existing-extent row its own literal, or if qemu is what changed, {REPIN_HINT}.')


class TestSplitFixtureLiteral(unittest.TestCase):
    """The hand-copied 33 GiB descriptor matches the qemu-written fixture in instar-testdata."""

    @staticmethod
    def _testdata_root():
        env = os.environ.get('INSTAR_TESTDATA_PATH')
        if env:
            return Path(env)
        return Path(__file__).resolve().parent.parent.parent / 'instar-testdata'

    def test_fixture_literal_matches(self):
        root = self._testdata_root()
        fixture = root / FIXTURE
        if not fixture.exists():
            # Not a skip. This is the only check on the hand copy of the
            # 33 GiB descriptor, and the suite treats testdata as a hard
            # dependency everywhere else (tests/base.py raises when the
            # root is missing), so a missing fixture is a failure here too.
            missing = 'the testdata clone' if not root.exists() else 'the fixture'
            self.fail(f'{missing} is absent, so {FIXTURE_CONSTANT} is unchecked: {fixture}\n'
                      f'Set INSTAR_TESTDATA_PATH, or clone instar-testdata beside this repository.')
        want = re.sub(r'^CID=[0-9a-f]+$', f'CID={CID}', fixture.read_text(encoding='utf-8'), flags=re.M)
        source = _unescape(_rust_source())
        match = re.search(rf'const {FIXTURE_CONSTANT}: &str = "\\\n(.*?)";\n', source, re.S)
        if not match:
            self.fail(f'{FIXTURE_CONSTANT} is absent from {RUST_SOURCE.name} entirely')
        got = match.group(1)
        if want == got:
            return
        diff = ''.join(difflib.unified_diff(want.splitlines(keepends=True), got.splitlines(keepends=True),
                                            f'{FIXTURE} (CID normalised)', f'lib.rs {FIXTURE_CONSTANT}'))
        self.fail(f'{FIXTURE_CONSTANT} differs from the fixture.\n{diff}\n'
                  f'Re-copy the literal from the fixture; if the fixture was regenerated, regenerate it knowingly.')


if __name__ == '__main__':
    unittest.main()
