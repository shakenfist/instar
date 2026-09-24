#!/usr/bin/env python3
"""Literal find-and-replace that refuses to do anything ambiguous.

Written for `tools/mutate-differencing.sh`, which needs to edit one
line of Rust and then assert a test notices. The whole value of a
mutation harness rests on the mutation actually landing: a substitution
that matches nothing leaves the code unchanged, the test then passes
for the ordinary reason, and the harness scores a pass it has not
earned. Two rounds of hand-rolled `sed` harnesses did exactly that
before this script existed.

So the contract is deliberately narrow:

* the search string is matched **literally** -- no regular expressions,
  no escaping rules, no `sed` address syntax to get wrong;
* it must occur **exactly once** in the file. Zero occurrences means
  the pattern has drifted away from the code; more than one means the
  edit is not the edit the caller described. Both exit non-zero;
* nothing is written unless the match count is exactly one.

Exit status:

* 0 -- replaced exactly one occurrence.
* 2 -- the search string did not occur exactly once, or search and
  replacement are identical (a no-op mutation is a broken mutation).
* 3 -- the file could not be read or written, or was not valid UTF-8.

Usage: ``replace-once.py FILE SEARCH REPLACE``
"""

import sys


def fail(message, status):
    """Report `message` on stderr and return `status`."""
    print(f'replace-once: {message}', file=sys.stderr)
    return status


def replace_once(path, search, replace):
    """Replace the single occurrence of `search` in `path`.

    Returns a process exit status; see the module docstring.
    """
    if search == replace:
        return fail('the search and replacement strings are identical', 2)
    if not search:
        return fail('the search string is empty', 2)
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            original = handle.read()
    except OSError as err:
        return fail(f'{path}: cannot read: {err}', 3)
    except UnicodeDecodeError as err:
        return fail(f'{path}: not valid UTF-8: {err}', 3)

    count = original.count(search)
    if count != 1:
        return fail(
            f'{path}: the search string occurs {count} times, expected exactly 1; '
            f'searched for {search!r}', 2)

    try:
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(original.replace(search, replace))
    except OSError as err:
        return fail(f'{path}: cannot write: {err}', 3)
    return 0


def main(argv):
    """Command line entry point."""
    if len(argv) != 4:
        return fail('usage: replace-once.py FILE SEARCH REPLACE', 2)
    return replace_once(argv[1], argv[2], argv[3])


if __name__ == '__main__':
    sys.exit(main(sys.argv))
