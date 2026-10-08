#!/usr/bin/env python3
"""Fail if anything in the tree claims instar cannot read or compose a
differencing image.

Five operations compose one, so that claim is false wherever it is
made. It is checked rather than trusted because the sentences wrap
mid-phrase: a line-granular grep missed one in
`src/shared/src/lib.rs` that read "Instar cannot / compose a parent
yet" across a line break, and a comment-granular version of this
script missed a second one in a `tests/` assertion message, which is
why prose, comments and string literals are all read now.

Paragraphs -- runs of non-blank lines -- are flattened and matched,
which both reunites a wrapped sentence and keeps a line number to
report. Rust block comments, Python docstrings, assertion messages and
Markdown prose therefore all fall out of one pass.

The pattern is anchored on what a claim says instar cannot act *on*,
not on the verb, because that is what decides whether the claim is
false. "instar cannot compose a parent" is false; "a chain instar
cannot compose" -- said of a differencing image whose own parent is
differencing -- is true and stays unflagged, as does "a source instar
cannot read", which is true of any unsupported format. A sentence that
forbids or disclaims the claim rather than making it ("must not imply
that instar cannot compose at all") is cleared by the negation test.

Two trees are deliberately not read. `docs/plans/` records what was
true when each phase was planned, and prescribes the sweeps that made
it false; `CHANGELOG.md` entries were true for the release they
describe. Editing either to satisfy this script would falsify a
record.
"""
import argparse
import pathlib
import re
import sys

CLAIM = re.compile(
    r'(?i)instar cannot (?:read|compose|open) (?:a |an |the )?'
    r'(?:differencing|parent)'
    r'|cannot compose a parent'
    r'|instar cannot compose (?:a chain )?at all'
)
NEGATED = re.compile(
    r'(?i)(?:not|never|neither)\s+(?:\w+\s+){0,3}'
    r'(?:claim|say|assert|state|impl|imply|mean)\w*\s+(?:that\s+)?$'
)

GLOBS = ('src/**/*.rs', 'tests/**/*.py', 'docs/*.md')
# This file quotes the pattern it searches for, so it would always
# match itself.
EXCLUDED = ('tools/check-no-capability-claims.py',)


def paragraphs(text):
    """Yield (line number, flattened text) for each run of non-blank lines."""
    block, start = [], 0
    for lineno, line in enumerate(text.split('\n') + [''], 1):
        if line.strip():
            if not block:
                start = lineno
            block.append(line.strip().lstrip('/!#').strip())
            continue
        if block:
            yield start, re.sub(r'\s+', ' ', ' '.join(block))
            block = []


def claims_in(text):
    """Yield (line number, matched text) for each unnegated claim."""
    for start, flat in paragraphs(text):
        for match in CLAIM.finditer(flat):
            if NEGATED.search(flat[:match.start()]):
                continue
            yield start, match.group(0)


SELF_TEST_CASES = (
    # (must be flagged, description, text)
    (True, 'the wrapped claim a line-granular grep missed',
     '// Backing image is a differencing VHD or VHDX. Instar cannot\n'
     '// compose a parent yet, so the overlay would be unreadable.\n'),
    (True, 'a claim in an assertion message rather than a comment',
     "    self.assertIn(\n"
     "        'Chain: 1 image(s)', stdout,\n"
     "        f'{image_id}: the chain must stop at the child -- '\n"
     "        f'instar cannot compose a parent, and these locators '\n"
     "        f'must never be followed'\n"
     "    )\n"),
    (True, 'a claim in a Rust block comment',
     '/* check refuses because instar cannot read a differencing\n'
     '   image at all. */\n'),
    (True, 'a claim in Markdown prose',
     'The operation refuses a differencing source because instar\n'
     'cannot compose a parent.\n'),
    (False, 'a prohibition on making the claim',
     '// The refusal message must name its operation and must not\n'
     '// imply that instar cannot compose at all.\n'),
    (False, 'a disclaimer that the refusal is not the claim',
     'This refusal is `create`\'s own restriction on what it will\n'
     'build, not a statement that instar cannot read the result.\n'),
    (False, 'the true scoped claim about a differencing grandparent',
     '# A structurally valid differencing image naming a parent that\n'
     '# is itself differencing -- a chain instar cannot compose.\n'),
    (False, 'a true statement about an unsupported source',
     '# A source instar cannot read is not a version-parity fact.\n'),
    (False, 'a per-operation statement, true of check and measure',
     '// This operation does not compose a differencing chain.\n'),
)


def self_test():
    """Check the pattern pair against the forms it must and must not catch.

    Written because a checker that has only ever been run against a
    clean tree has not been shown to catch anything. Each case is a
    form that actually appeared in this repository.
    """
    bad = 0
    for expected, description, text in SELF_TEST_CASES:
        got = bool(list(claims_in(text)))
        if got != expected:
            verb = 'missed' if expected else 'wrongly flagged'
            print(f'FAIL {verb}: {description}')
            bad += 1
        else:
            print(f'ok   {"flags" if expected else "clears"}: {description}')
    if bad:
        print(f'{bad} of {len(SELF_TEST_CASES)} self-test cases failed')
        return 1
    print(f'{len(SELF_TEST_CASES)} self-test cases pass')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--self-test', action='store_true',
        help='check the pattern against the forms it must and must not catch'
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    hits = []
    for glob in GLOBS:
        for path in sorted(pathlib.Path('.').glob(glob)):
            if str(path) in EXCLUDED:
                continue
            for lineno, claim in claims_in(path.read_text()):
                hits.append(f'{path}:{lineno}: {claim!r}')
    for hit in hits:
        print(hit)
    if hits:
        print(f'{len(hits)} claim(s) that instar cannot read or compose a '
              f'differencing image')
        return 1
    print('nothing claims instar cannot read or compose a differencing image')
    return 0


if __name__ == '__main__':
    sys.exit(main())
