#!/usr/bin/env python3
"""Check the split VMDK descriptor literals in the vmdk crate against the qemu pin.

The vmdk crate's tests hold twelve qemu-written split descriptors as Rust
string literals, because the Rust workspace has no JSON parser and so cannot
read `tests/golden/qemu-create-pins.json`. Nothing in Rust can check that
copy: an emitter and its expectations written from the same misreading agree
with each other. This reads the pin, the Rust source and the committed 33 GiB
fixture as text and checks the copy, so it is the one check an emitter bug
cannot satisfy.

It is a source-level guard rather than a test under `tests/`, because the
suite's tree is relocatable. `tools/test-package-functional.sh` copies
`tests/` alone to `/tmp/instar-tests` and runs it against an installed
package, where `src/crates/vmdk/src/lib.rs` does not exist; a test here that
read the Rust source passed every pull request and failed all seven merge
queue legs. These checks read the repository, so they belong beside the other
`tools/ci` guards, which run on every pull request with the whole tree
present. `tools/ci/check-tests-relocatable.sh` now stops a test reaching out
of `tests/` again.

usage: check-vmdk-split-pins.py [--source PATH] [--testdata PATH] [--no-fixture]
Exits 0 with a one-line summary when the literals agree, 1 naming every
difference otherwise, and 2 when the pin or the Rust source cannot be read.
"""

import argparse
import difflib
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TESTS_DIR = REPO_ROOT / 'tests'
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))
from helpers import qemu_pins  # noqa: E402

REPIN_HINT = 're-run tools/sweep-qemu-create.py --write tests/golden/qemu-create-pins.json'

DEFAULT_SOURCE = REPO_ROOT / 'src' / 'crates' / 'vmdk' / 'src' / 'lib.rs'

# The qemu builds from which the split descriptors are stable.
LAST_GROUP_FIRST_VERSION = '6.2.0'
LAST_GROUP_LAST_VERSION = '10.2.0'

# How many multi-extent cases the pin is expected to carry.
EXPECTED_MULTI_CASES = 14

# What the emitter writes for CID, and so what the literals hold.
CID = 'fffffffe'
STEM = 'image'

FIXTURE = Path('custom') / 'format-coverage' / 'vmdk-split-sparse-33g.vmdk'
FIXTURE_CONSTANT = 'QEMU_SPLIT_SPARSE_33G'

DESCRIPTOR_START = '# Disk DescriptorFile\n'
DESCRIPTOR_END = 'ddb.toolsVersion = "2147483647"\n'


def multi_cases():
    return [name for name in qemu_pins.load_pin()['cases'] if name.startswith('vmdk-multi-')]


def last_group(case_name):
    group = qemu_pins.load_pin()['cases'][case_name][-1]
    versions = group['versions']
    if versions[0] != LAST_GROUP_FIRST_VERSION or versions[-1] != LAST_GROUP_LAST_VERSION:
        raise SystemExit(
            f'ERROR: {case_name}: the last pin group covers {versions[0]} to {versions[-1]}, not '
            f'{LAST_GROUP_FIRST_VERSION} to {LAST_GROUP_LAST_VERSION}; the literals were copied from '
            f'the latter, so check what changed before trusting them; {REPIN_HINT}')
    return group['result']


def rebuild(result):
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
        raise SystemExit(f'ERROR: unsubstituted placeholder left in descriptor:\n{text}')
    return text


def unescape(rust_text):
    # The literals use real newlines at column zero, not `\n` escapes, so the only escape in them is
    # `\"`. That is the only one undone; do not grow this into a general Rust string unescaper.
    return rust_text.replace('\\"', '"')


def candidates(text):
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


def diff_against_nearest(want, source):
    blocks = candidates(source)
    if not blocks:
        return 'no descriptor literal is present in the Rust file at all'
    nearest = max(blocks, key=lambda b: difflib.SequenceMatcher(None, want, b, autojunk=False).ratio())
    diff = difflib.unified_diff(want.splitlines(keepends=True), nearest.splitlines(keepends=True),
                                'pin (expected)', 'lib.rs (nearest literal)')
    return ''.join(diff) or '(the nearest literal differs only in trailing text)'


def check_case_count(problems):
    """The pin carries the number of multi-extent cases the literals were copied from."""
    found = multi_cases()
    if len(found) != EXPECTED_MULTI_CASES:
        problems.append(f'the pin has {len(found)} multi-extent cases, not {EXPECTED_MULTI_CASES}: '
                        f'{found}\nIf a case was added deliberately, copy its literal and raise '
                        f'EXPECTED_MULTI_CASES here.')


def check_descriptors_in_source(problems, source):
    """Every pinned multi-extent descriptor appears verbatim in the vmdk crate's tests."""
    for case_name in multi_cases():
        want = rebuild(last_group(case_name))
        if want in source:
            continue
        problems.append(f'{case_name}: the pinned descriptor is not in the Rust source.\n'
                        f'{diff_against_nearest(want, source)}\n'
                        f'Either re-copy the literal from the pin, or if qemu is what changed, {REPIN_HINT}.')


def check_existing_extent_cases(problems):
    """The Rust constants for these rows are one constant, so only the pin can say the sharing is true."""
    for subformat in ('sparse', 'flat'):
        plain = f'vmdk-multi-{subformat}-5G'
        existing = f'{plain}-existing-extent'
        want = rebuild(last_group(plain))
        got = rebuild(last_group(existing))
        if want == got:
            continue
        diff = ''.join(difflib.unified_diff(want.splitlines(keepends=True), got.splitlines(keepends=True),
                                            plain, existing))
        problems.append(f'{existing}: qemu now writes a different descriptor when a file is in the way, '
                        f'but the Rust tests share one literal for it and {plain}.\n{diff}\n'
                        f'Give the existing-extent row its own literal, or if qemu is what changed, {REPIN_HINT}.')


def check_fixture_literal(problems, source, testdata_root):
    """The hand-copied 33 GiB descriptor matches the qemu-written fixture in instar-testdata."""
    fixture = testdata_root / FIXTURE
    if not fixture.exists():
        # Not a soft pass. This is the only check on the hand copy of the
        # 33 GiB descriptor -- the only committed witness past sixteen
        # extents and past 65535 cylinders -- so letting it through unread
        # would read as a pass on the one check an emitter bug cannot
        # satisfy. Pass --no-fixture to say so deliberately.
        missing = 'the testdata clone' if not testdata_root.exists() else 'the fixture'
        problems.append(f'{missing} is absent, so {FIXTURE_CONSTANT} is unchecked: {fixture}\n'
                        f'Set INSTAR_TESTDATA_PATH, clone instar-testdata beside this repository, or '
                        f'pass --no-fixture to skip this one check knowingly.')
        return
    want = re.sub(r'^CID=[0-9a-f]+$', f'CID={CID}', fixture.read_text(encoding='utf-8'), flags=re.M)
    match = re.search(rf'const {FIXTURE_CONSTANT}: &str = "\\\n(.*?)";\n', source, re.S)
    if not match:
        problems.append(f'{FIXTURE_CONSTANT} is absent from the Rust source entirely')
        return
    got = match.group(1)
    if want == got:
        return
    diff = ''.join(difflib.unified_diff(want.splitlines(keepends=True), got.splitlines(keepends=True),
                                        f'{FIXTURE} (CID normalised)', f'lib.rs {FIXTURE_CONSTANT}'))
    problems.append(f'{FIXTURE_CONSTANT} differs from the fixture.\n{diff}\n'
                    f'Re-copy the literal from the fixture; if the fixture was regenerated, regenerate '
                    f'it knowingly.')


def default_testdata_root():
    env = os.environ.get('INSTAR_TESTDATA_PATH')
    if env:
        return Path(env)
    return REPO_ROOT.parent / 'instar-testdata'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE,
                        help='the Rust file holding the literals (default: %(default)s)')
    parser.add_argument('--testdata', type=Path, default=None,
                        help='the instar-testdata clone (default: $INSTAR_TESTDATA_PATH, else a sibling)')
    parser.add_argument('--no-fixture', action='store_true',
                        help='skip the fixture comparison, for a job with no testdata clone')
    args = parser.parse_args()

    if not args.source.exists():
        print(f'ERROR: the Rust source is absent: {args.source}', file=sys.stderr)
        return 2
    source = unescape(args.source.read_text(encoding='utf-8'))

    problems = []
    check_case_count(problems)
    check_descriptors_in_source(problems, source)
    check_existing_extent_cases(problems)
    if args.no_fixture:
        fixture_note = f'{FIXTURE_CONSTANT} not checked (--no-fixture)'
    else:
        check_fixture_literal(problems, source, args.testdata or default_testdata_root())
        fixture_note = f'{FIXTURE_CONSTANT} checked against the fixture'

    if problems:
        for problem in problems:
            print(f'ERROR: {problem}', file=sys.stderr)
        print(f'check-vmdk-split-pins: {len(problems)} problem(s) found.', file=sys.stderr)
        return 1

    print(f'check-vmdk-split-pins: {EXPECTED_MULTI_CASES} pinned descriptors match the Rust '
          f'literals; {fixture_note}.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
