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
# Resolved from this file rather than the working directory. Globbed
# relative to `.`, every pattern matched nothing when the script was
# run from anywhere but the repository root -- from `tools/`, or from
# CI with a different cwd -- and it reported a clean tree having read
# no files at all. A checker that is trusted without being read must
# not have a silent pass in it.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# The floor below which an empty scan is a broken checker rather than a
# clean tree. Deliberately far under the real count (hundreds) so it
# needs no maintenance, while still catching a glob that has stopped
# matching.
MIN_FILES_SCANNED = 20


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
    # The pattern cases above are all this used to check, and a pattern
    # that works proves nothing if the scan never reaches a file. Run
    # the real glob from a directory that is not the repository root,
    # which is exactly the shape that made this script report a clean
    # tree having read nothing.
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as elsewhere:
        here = os.getcwd()
        try:
            os.chdir(elsewhere)
            found = sum(
                1
                for glob in GLOBS
                for path in REPO_ROOT.glob(glob)
                if path.relative_to(REPO_ROOT).as_posix() not in EXCLUDED
            )
        finally:
            os.chdir(here)
    if found < MIN_FILES_SCANNED:
        print(f'FAIL the scan reads only {found} file(s) from a working '
              f'directory other than the repository root')
        bad += 1
    else:
        print(f'ok   reads {found} files regardless of working directory')

    if bad:
        print(f'{bad} of {len(SELF_TEST_CASES) + 1} self-test checks failed')
        return 1
    print(f'{len(SELF_TEST_CASES) + 1} self-test checks pass')
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
    scanned = 0
    for glob in GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative in EXCLUDED:
                continue
            scanned += 1
            for lineno, claim in claims_in(path.read_text()):
                hits.append(f'{relative}:{lineno}: {claim!r}')
    for hit in hits:
        print(hit)
    if hits:
        print(f'{len(hits)} claim(s) that instar cannot read or compose a '
              f'differencing image')
        return 1
    if scanned < MIN_FILES_SCANNED:
        print(f'only {scanned} file(s) matched {GLOBS} under {REPO_ROOT}; '
              f'refusing to report a clean tree on a scan that read nothing')
        return 2
    print(f'nothing in {scanned} files claims instar cannot read or compose '
          f'a differencing image')
    return 0


if __name__ == '__main__':
    sys.exit(main())
