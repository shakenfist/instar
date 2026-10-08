#!/usr/bin/env python3
"""Fail if a comment in src/ claims instar cannot read or compose a
differencing image.

Five operations compose one, so that claim is false wherever it is
made. It is checked rather than trusted because the sentences wrap
mid-phrase: a line-granular grep missed one in
`src/shared/src/lib.rs` that read "Instar cannot / compose a parent
yet" across a line break.

Two things this deliberately does not flag. Comment blocks are read
rather than whole files, so a test asserting that a *message* must
not contain the claim is code and never matches. And a comment that
forbids the claim rather than making it -- "neither may claim instar
cannot compose such a chain" -- is a prohibition, so a negation
immediately before the match clears it. A per-operation statement
("this operation does not compose a differencing chain") is true of
`check`, `measure` and `commit` and is not what this looks for.
"""
import pathlib
import re
import sys

CLAIM = re.compile(r'(?i)instar cannot (?:read|compose)|cannot compose a parent')
NEGATED = re.compile(r'(?i)(?:not|never|neither)\s+(?:\w+\s+){0,2}(?:claim|say|assert|state)\w*\s*$')


def comment_blocks(text):
    """Yield (line number, flattened text) for each run of comment lines."""
    block, start = [], 0
    for lineno, line in enumerate(text.split('\n') + [''], 1):
        stripped = line.strip()
        if stripped.startswith('//'):
            if not block:
                start = lineno
            block.append(stripped.lstrip('/!').strip())
            continue
        if block:
            yield start, re.sub(r'\s+', ' ', ' '.join(block))
            block = []


def main():
    hits = []
    for path in sorted(pathlib.Path('src').rglob('*.rs')):
        for start, flat in comment_blocks(path.read_text()):
            for match in CLAIM.finditer(flat):
                if NEGATED.search(flat[:match.start()]):
                    continue
                hits.append(f'{path}:{start}: {match.group(0)!r}')
    for hit in hits:
        print(hit)
    if hits:
        print(f'{len(hits)} comment(s) claim instar cannot read or compose a differencing image')
        return 1
    print('no comment claims instar cannot read or compose a differencing image')
    return 0


if __name__ == '__main__':
    sys.exit(main())
