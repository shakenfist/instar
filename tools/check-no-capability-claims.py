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
record. `docs/plans/` is skipped by an explicit prefix: it used to be
skipped only as a side effect of a non-recursive `docs/*.md` glob,
which also meant the 36 pages under `docs/commentary/`,
`docs/crates/`, `docs/qcow2/` and the rest were never read at all,
while the docstring presented the plans exclusion as the deliberate
part.
"""
import argparse
import pathlib
import re
import subprocess
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

GLOBS = (
    'src/**/*.rs',
    'tests/**/*.py',
    'docs/**/*.md',
    'tools/**/*.py',
    'scripts/**/*.py',
)
# This file quotes the pattern it searches for, so it would always
# match itself. The exclusion was unreachable until `tools/**/*.py`
# joined GLOBS, because no glob reached `tools/`.
EXCLUDED = ('tools/check-no-capability-claims.py',)
# Trees whose records were true when written: see the module
# docstring. A prefix rather than a glob that happens to miss them.
EXCLUDED_PREFIXES = ('docs/plans/',)
# Build trees are excluded for a different reason, and by asking git
# rather than by listing them: `src/**/*.rs` and `tests/**/*.py` reach
# generated and vendored code once a tree has been built, and pathlib's
# globs match dotted directories, so a developer with src/target/ and
# tests/.venv/ present scanned 1199 files where CI's fresh checkout
# scans 277. Those 922 files are not this repository's claims, a
# vendored crate's comment would be reported against a path nobody can
# edit, and the two counts disagreeing makes the number this prints
# useless as evidence.
#
# The first version of that exclusion was a hardcoded prefix tuple, and
# it had already drifted: .gitignore is `**/target/` and src/fuzz
# carries its own, so src/fuzz/target/ -- where the cargo-fuzz crate
# builds, outside the main workspace -- was ignored by git and scanned
# here. Asking git instead means the scan and the self-test share one
# definition of generated, and the next build directory needs
# remembering in neither.
#
# These are the fallback for a tree git cannot be asked about: an
# exported source drop or a release tarball is not a repository.
GENERATED_PREFIXES = ('src/target/', 'src/fuzz/target/', 'tests/.venv/')
# Resolved from this file rather than the working directory. Globbed
# relative to `.`, every pattern matched nothing when the script was
# run from anywhere but the repository root -- from `tools/`, or from
# CI with a different cwd -- and it reported a clean tree having read
# no files at all. A checker that is trusted without being read must
# not have a silent pass in it.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# The floor below which an empty scan is a broken checker rather than a
# clean tree. Deliberately far under the real count (hundreds) so it
# needs no maintenance.
#
# It is the weaker of the two floors, and only a backstop against a
# total collapse. It was sized for three globs and cannot catch one
# glob going quiet now that there are five: any one of them could stop
# matching -- the precise failure a floor exists to catch -- while the
# other four keep the total in the thousands. So every glob must also
# match at least one file it is allowed to read, which is a floor that
# needs no number at all.
MIN_FILES_SCANNED = 20


def excluded(relative):
    """Whether *relative* (a repo-relative posix path) is not scanned."""
    return (relative in EXCLUDED
            or relative.startswith(EXCLUDED_PREFIXES))


def git_ignored(candidates):
    """Which of *candidates* git ignores, or None when git cannot say.

    None is "could not be asked" and not "nothing is ignored", so the
    caller falls back to GENERATED_PREFIXES rather than scanning a
    build tree. `check-ignore` exits 0 when something matched, 1 when
    nothing did, and 128 outside a working tree -- which an exported
    source drop or a release tarball really is, so that is a fallback
    and not an error.
    """
    if not candidates:
        return set()
    try:
        asked = subprocess.run(
            ['git', '-C', str(REPO_ROOT), 'check-ignore', '--stdin'],
            input='\n'.join(sorted(candidates)), capture_output=True,
            text=True, check=False)
    except OSError:
        return None
    if asked.returncode not in (0, 1):
        return None
    return {line.strip() for line in asked.stdout.split('\n') if line.strip()}


def generated_by_prefix(candidates):
    """Which of *candidates* the build-tree prefixes account for.

    What the scan falls back to when git cannot be asked -- an exported
    source drop, a tarball. A function rather than a set comprehension
    inside scan_paths so that the self-test can check the fallback
    itself: in a real checkout git always answers, so the fallback is
    the half that is never exercised, and it is also the half that has
    already rotted once (.gitignore covered src/fuzz/target/ and this
    tuple did not).
    """
    return {path for path in candidates
            if path.startswith(GENERATED_PREFIXES)}


def scan_paths():
    """Return {glob: [repo-relative posix path, ...]} for every glob.

    One implementation for the real scan and for the self-test, so the
    self-test cannot pass against a set of files the scan does not read.
    """
    candidates = {}
    for glob in GLOBS:
        candidates[glob] = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in sorted(REPO_ROOT.glob(glob))
            if not excluded(path.relative_to(REPO_ROOT).as_posix())
        ]
    every = {path for paths in candidates.values() for path in paths}
    ignored = git_ignored(every)
    if ignored is None:
        ignored = generated_by_prefix(every)
    return {glob: [path for path in paths if path not in ignored]
            for glob, paths in candidates.items()}


def empty_globs(found):
    """Which globs matched no file they are allowed to read."""
    return [glob for glob, paths in found.items() if not paths]


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
    checks = len(SELF_TEST_CASES)

    def check(ok, passed, failed):
        nonlocal bad, checks
        checks += 1
        if ok:
            print(f'ok   {passed}')
        else:
            print(f'FAIL {failed}')
            bad += 1

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
            found = scan_paths()
        finally:
            os.chdir(here)
    total = sum(len(paths) for paths in found.values())
    check(total >= MIN_FILES_SCANNED,
          f'reads {total} files regardless of working directory',
          f'the scan reads only {total} file(s) from a working directory '
          f'other than the repository root')

    empty = empty_globs(found)
    check(not empty,
          'every glob matches at least one file it may read',
          f'these globs match nothing: {", ".join(empty)}')

    # The two halves of the widening that the pattern cases cannot see:
    # a docs tree below the top level is read, and docs/plans/ is not.
    # Without these, a later edit that put back the non-recursive
    # `docs/*.md` glob -- the blind spot that hid 36 pages, including
    # every commentary page -- would self-test clean.
    scanned = {path for paths in found.values() for path in paths}
    nested_docs = sorted(p for p in scanned
                         if p.startswith('docs/') and p.count('/') >= 2)
    check(bool(nested_docs),
          f'reads nested docs pages ({len(nested_docs)}, e.g. '
          f'{nested_docs[0] if nested_docs else ""})',
          'no docs page below docs/ itself is scanned, so the glob is '
          'back to the non-recursive form')

    plans = sorted(p for p in scanned if p.startswith('docs/plans/'))
    check(not plans,
          'reads nothing under docs/plans/',
          f'{len(plans)} file(s) under docs/plans/ are scanned, e.g. '
          f'{plans[0] if plans else ""}')

    # Asserted on this file's own path rather than on EXCLUDED, which
    # would make the check vacuous: `not any(p in EXCLUDED ...)` passes
    # trivially the moment EXCLUDED is empty, which is the edit it is
    # supposed to catch. This script quotes the pattern it searches
    # for, so a scan that reads it reports itself.
    myself = pathlib.Path(__file__).resolve().relative_to(
        REPO_ROOT).as_posix()
    check(myself not in scanned,
          'does not scan itself',
          f'{myself} scans itself, so it will report its own specimens')

    # The ignore filter, asserted on paths rather than on the tree.
    # Observing the real scan cannot check this: the scan filters
    # through git, so "nothing scanned is ignored" is now true by
    # construction, and in CI's fresh checkout no build tree exists to
    # be excluded in the first place -- the same vacuity as asserting
    # `not any(p in EXCLUDED ...)`. So the filter is asked directly,
    # about the two build trees that matter and about a tracked file. A
    # filter that excluded nothing, excluded everything, or missed
    # src/fuzz/target/ -- as the hardcoded prefixes did, while
    # .gitignore always covered it -- fails all three at once.
    probes = ['src/target/debug/probe.rs', 'src/fuzz/target/probe.rs',
              'tools/check-no-capability-claims.py']
    ignored = git_ignored(probes)
    if ignored is None:
        print('skip git cannot be asked what it ignores here, so the scan '
              f'falls back to {GENERATED_PREFIXES}')
    else:
        check(ignored == set(probes[:2]),
              'excludes the build trees git ignores, and only those',
              f'the ignore filter answered {sorted(ignored)}, not the two '
              f'build trees alone')

    # The fallback, against the same three paths and the same
    # expectation. Asked directly because git answers in every
    # checkout, so the branch that runs when it cannot be asked is the
    # one nobody ever reaches -- and it is where the exclusion had
    # already drifted once. One expectation over both halves means a
    # prefix tuple that stops covering a build tree git ignores fails
    # here rather than in an exported source drop nobody is testing.
    check(generated_by_prefix(probes) == set(probes[:2]),
          'falls back to prefixes that cover the same build trees',
          f'the prefix fallback answered {sorted(generated_by_prefix(probes))}, '
          f'not the two build trees alone')

    if bad:
        print(f'{bad} of {checks} self-test checks failed')
        return 1
    print(f'{checks} self-test checks pass')
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

    found = scan_paths()
    empty = empty_globs(found)
    if empty:
        print('ERROR: these globs match no file they are allowed to read, '
              'so whatever they cover is not being checked: '
              + ', '.join(empty))
        return 1

    hits = []
    scanned = 0
    for paths in found.values():
        for relative in paths:
            scanned += 1
            # UTF-8 explicitly, as the rest of the repo's tooling
            # reads files: the default is the locale's, and the globs
            # now cover docs/**/*.md, which is full of em dashes. An
            # interpreter whose preferred encoding resolved to ASCII
            # would fail the lint with a UnicodeDecodeError traceback
            # rather than a claim. errors='replace' because a file that
            # is not text is not a capability claim either way, and a
            # stray binary in a glob must not be able to fail this for
            # a reason unrelated to what it checks.
            for lineno, claim in claims_in(
                    (REPO_ROOT / relative).read_text(
                        encoding='utf-8', errors='replace')):
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
