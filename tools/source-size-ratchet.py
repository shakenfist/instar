#!/usr/bin/env -S python3 -I

"""Stop source files that are already too long from growing silently.

A ratchet on source size, copied verbatim from shakenfist/development's
templates/source-size-ratchet/ into tools/source-size-ratchet.py. It
never forces a file to be split. A file over the threshold may stay
exactly as long as it is for ever; what it may not do is grow, or a new
file cross the threshold, without a pull request saying so in a place a
reviewer cannot scroll past -- a one-line edit to the baseline.

What is counted. Every file `git ls-files` reports whose name ends in
one of SOURCE_EXTENSIONS, so untracked trees (target/, .cargo-cache/,
virtualenvs) are never seen. A path that is not a regular file in the
working tree -- deleted but still tracked, a symlink, a submodule -- is
skipped. Lines are what `wc -l` reports, plus one for a non-empty file
whose last line has no newline. A path holding a line break is counted
like any other, but cannot be written to the baseline, so if it is over
the threshold the tool fails (exit 2) and asks for it to be renamed or
excluded.

What is not counted. BUILTIN_EXCLUDES, the handful of generated shapes
that are nobody's review unit anywhere, and then the repository's own
optional tools/source-size-exclude: one glob per line, matched against
the repository-relative path with fnmatch (so `*` crosses `/`), with
whole-line `#` comments and blank lines ignored. A pattern that matches
a leading directory of a path excludes the whole tree beneath it, with
or without a trailing `/`; with one, it only ever matches a directory.
Patterns are anchored at the repository root, unlike .gitignore:
`vendor/` matches vendor/x.py but not sub/vendor/x.py, for which write
`*/vendor/` or the full path. Give every line a comment saying why that
tree is not reviewed here.

The baseline. tools/source-size-baseline holds one `<lines> <path>`
per file over THRESHOLD, sorted by path, under a header this tool
writes. `#` lines and blank lines are ignored when it is read, and are
not preserved when it is rewritten: the reason for an entry belongs in
the pull request that changed it. A missing baseline is an empty one.

Hostile checkouts. The tree is pull request content, so the baseline,
the exclude file and tools/ itself must each be absent or a real file
or directory: a symlink, FIFO or device in their place is a tool
failure, never followed. The baseline is written through a temporary
file renamed into place. Paths and patterns are printed escaped when
they hold anything unprintable or begin with `::`, after any leading
whitespace, so a file name cannot write control sequences or workflow
commands into a CI log. Run
it with `python3 -I`, as the shebang and the pre-commit hook do, so a
module planted beside it in tools/ cannot shadow the standard library.

Modes:

  (default)  Exit 1 if a file over the threshold is not in the
             baseline or is longer than its entry. An entry higher
             than its file, or for a file that is gone or now under the
             threshold, is not a failure; it is noted, and --update
             tightens it.
  --update   Rewrite the baseline downwards only: lower entries that
             shrank, drop files now at or under the threshold, gone, or
             excluded. It never raises an entry or adds a file, because
             that hand edit is the decision a reviewer is meant to see,
             and leaves the file untouched when there is nothing to
             tighten. It still exits 1 if anything grew.
  --init     Write the baseline from scratch from the current tree. For
             adopting the tool, not for making a failure go away.

Exit status: 0 clean, 1 a file grew past the baseline, 2 the tool could
not do its job (not a git repository, git failed, a malformed baseline,
a baseline or exclude file that is not a regular file).
A tool failure is never reported as a size violation.

THRESHOLD is a constant rather than a flag on purpose: every copy of
this file is meant to be byte-identical to the template, so that one
review of it covers the fleet.
"""

import argparse
import fnmatch
import os
import re
import stat
import subprocess
import sys
import tempfile

#: A file longer than this many lines is oversize. 1,500 is the line
#: above which the source-file-size shared block says a file wants a
#: stated reason to stay whole, so the baseline is exactly the list of
#: files that owe one.
THRESHOLD = 1500

#: Hand-written source in the languages the fleet uses. Anything else
#: -- markdown, data, lock files, configuration -- is not counted, and
#: neither is a file with no extension, such as a script known only by
#: its shebang: telling those from data would mean reading every
#: tracked file. Widen this when a repository adopts another language;
#: every copy is the template, so the whole fleet gets it at once.
SOURCE_EXTENSIONS = ('.c', '.cc', '.cjs', '.cpp', '.css', '.cts', '.cxx', '.go', '.h', '.hh', '.hpp', '.js',
                     '.jsx', '.mjs', '.mts', '.py', '.rs', '.sh', '.ts', '.tsx')

#: Generated shapes that are never a review unit in any repository.
#: Lock files need no entry: no lock file has a source extension.
BUILTIN_EXCLUDES = (
    # protoc's Python output; reviewed as the .proto it came from.
    '*_pb2.py',
    # protoc's gRPC stubs for Python; same reason.
    '*_pb2_grpc.py',
    # protoc's Go output; same reason.
    '*.pb.go',
    # Minified bundles; machine output, one enormous line or many.
    '*.min.js',
    # Minified stylesheets; same reason.
    '*.min.css',
)

BASELINE = os.path.join('tools', 'source-size-baseline')
EXCLUDE = os.path.join('tools', 'source-size-exclude')
SELF = os.path.join('tools', 'source-size-ratchet.py')

HEADER = f"""\
# Source files over the {THRESHOLD:,}-line threshold, one "<lines> <path>"
# per line, sorted by path. Written by {SELF}, which fails
# when a file over the threshold is missing from this list or is longer
# than its entry here.
#
# Shrinking a file needs no edit by hand: `{SELF} --update`
# lowers entries and drops files that fell under the threshold, and never
# raises one. Raising an entry or adding a file is a deliberate hand edit:
# make it in the pull request that grows the file, and say in the
# pull request description why the file should grow rather than split.
# Comments here are not preserved when the tool rewrites this file.

"""

ENTRY_RE = re.compile(r'^([0-9]+) (.+)$')

#: How much of a malformed baseline line an error message quotes.
EXCERPT = 80


class ToolError(Exception):
    """The tool could not do its job, as opposed to finding a file too long."""


def shown(text):
    """Text safe to print: as it is if printable, else escaped with ascii().

    Paths are pull request content. A name with a control character, an
    undecodable byte (which os.fsdecode leaves as a lone surrogate that
    cannot be encoded for output) or a leading `::` (a workflow command
    in a GitHub Actions log) is shown as a quoted escape instead. The
    runner trims leading whitespace before it looks for a command, and
    paths are printed indented, so `::` after spaces counts as leading.
    """
    if text.isprintable() and not text.lstrip().startswith('::'):
        return text
    return ascii(text)


def git(*args):
    """Run git and return its stdout as bytes, raising ToolError on failure."""
    try:
        result = subprocess.run(['git', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise ToolError(f'could not run git: {e}')
    if result.returncode != 0:
        err = shown(result.stderr.decode('utf-8', 'replace').strip())
        raise ToolError(f'git {" ".join(args)} failed ({result.returncode}): {err}')
    return result.stdout


def count_lines(path):
    """Lines as wc -l counts them, plus one for an unterminated last line.

    Read in chunks, so a huge tracked file costs time but not memory.
    """
    lines = 0
    last = b'\n'
    with open(path, 'rb') as f:
        while chunk := f.read(1 << 20):
            lines += chunk.count(b'\n')
            last = chunk[-1:]
    if last != b'\n':
        lines += 1
    return lines


def is_regular(path):
    """True for a regular file, False if absent, ToolError for anything else.

    path is tools/<name>, relative to the repository top level, and both
    components are pull request content, so both are lstat'd: a symlink
    in place of either is refused rather than followed out of the tree,
    and a FIFO or device is refused rather than read until it hangs or
    exhausts memory. Checking each component is simpler and stricter
    than resolving the path and asking whether it stayed in the tree,
    which would still have to reject special files separately.
    """
    for name, wanted, kind in ((os.path.dirname(path), stat.S_ISDIR, 'a directory'),
                               (path, stat.S_ISREG, 'a regular file')):
        try:
            mode = os.lstat(name).st_mode
        except FileNotFoundError:
            return False
        except OSError as e:
            raise ToolError(f'could not inspect {name}: {e}')
        if not wanted(mode):
            raise ToolError(f'{name} must be {kind}, not a symlink or other special file; refusing to use it')
    return True


def read_text(path):
    """The contents of tools/<name>, or None if it is absent."""
    if not is_regular(path):
        return None
    try:
        with open(path, encoding='utf-8', errors='surrogateescape', newline='') as f:
            return f.read()
    except OSError as e:
        raise ToolError(f'could not read {path}: {e}')


def read_excludes():
    """The repository's own exclusion patterns, in file order."""
    text = read_text(EXCLUDE)
    if text is None:
        return []
    patterns = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        patterns.append(line)
    return patterns


def pattern_matches(pattern, path):
    """Whether one exclusion pattern covers a repository-relative path.

    The whole path is tried, then each leading directory, so that a
    pattern naming a directory excludes everything beneath it. A
    trailing `/` restricts the pattern to directories. Every candidate
    starts at the repository root, so patterns are root-anchored.
    """
    if pattern.startswith('./'):
        pattern = pattern[2:]
    pattern = pattern.lstrip('/')
    directory_only = pattern.endswith('/')
    pattern = pattern.rstrip('/')
    if not pattern:
        return False
    parts = path.split('/')
    candidates = ['/'.join(parts[:i]) for i in range(1, len(parts))]
    if not directory_only:
        candidates.append(path)
    return any(fnmatch.fnmatchcase(c, pattern) for c in candidates)


def measure():
    """Count every tracked source file, and note unused exclusions.

    Returns ({path: lines} for every counted file, [patterns from the
    exclude file that matched no tracked source file]).
    """
    excludes = read_excludes()
    used = set()
    counts = {}
    listed = git('ls-files', '-z').split(b'\0')
    for path in sorted({os.fsdecode(p) for p in listed if p}):
        if not path.endswith(SOURCE_EXTENSIONS):
            continue
        # The repository's patterns are tried first so that one covering
        # only generated files still counts as used, rather than being
        # reported as matching nothing.
        hits = [p for p in excludes if pattern_matches(p, path)]
        if hits:
            used.update(hits)
            continue
        if any(fnmatch.fnmatchcase(path, p) for p in BUILTIN_EXCLUDES):
            continue
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(mode):
            continue
        try:
            counts[path] = count_lines(path)
        except OSError as e:
            raise ToolError(f'could not read {shown(path)}: {e}')
        # Only an oversize file ever reaches the baseline, so only one
        # of those with a line break in its name is a problem.
        if counts[path] > THRESHOLD and ('\n' in path or '\r' in path):
            raise ToolError(f'tracked path {shown(path)} is over the threshold and contains a line break, '
                            f'which the baseline cannot hold; rename it or exclude it in {EXCLUDE}')
    return counts, [p for p in excludes if p not in used]


def read_baseline():
    """The baseline as {path: lines}; an absent file is an empty baseline."""
    text = read_text(BASELINE)
    if text is None:
        return {}
    baseline = {}
    for number, line in enumerate(text.split('\n'), start=1):
        if line.endswith('\r'):
            line = line[:-1]
        if not line.strip() or line.startswith('#'):
            continue
        match = ENTRY_RE.match(line)
        if not match:
            excerpt = shown(line[:EXCERPT]) + ('...' if len(line) > EXCERPT else '')
            raise ToolError(f'{BASELINE}:{number}: expected "<lines> <path>", got: {excerpt}')
        path = match.group(2)
        if path in baseline:
            raise ToolError(f'{BASELINE}:{number}: {shown(path)} is listed twice')
        baseline[path] = int(match.group(1))
    return baseline


def write_baseline(entries):
    """Write {path: lines} under the fixed header, sorted by path.

    A symlink or special file at the destination, or in place of tools/,
    is refused by is_regular. The write then goes to a temporary file
    beside the baseline, renamed over it, so that even a destination
    swapped for a symlink in between is replaced rather than followed.
    """
    body = ''.join(f'{lines} {path}\n' for path, lines in sorted(entries.items()))
    # Called for its ToolError alone: absent or regular are both fine to
    # write, but a symlink or special file must stop the write here.
    is_regular(BASELINE)
    directory = os.path.dirname(BASELINE)
    try:
        os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=directory, prefix='.source-size-baseline.')
        try:
            # mkstemp creates the file 0600; give it what open() would.
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(temporary, 0o666 & ~umask)
            with open(fd, 'w', encoding='utf-8', errors='surrogateescape', newline='') as f:
                f.write(HEADER + body)
            os.replace(temporary, BASELINE)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError as e:
        raise ToolError(f'could not write {BASELINE}: {e}')


def oversize(counts):
    return {path: lines for path, lines in counts.items() if lines > THRESHOLD}


def growth(current, baseline):
    """[(path, lines, baseline entry or None)] for every file that grew past the baseline."""
    grown = []
    for path, lines in sorted(current.items()):
        allowed = baseline.get(path)
        if allowed is None or lines > allowed:
            grown.append((path, lines, allowed))
    return grown


def slack(current, baseline):
    """[(path, entry, lines or None)] for every entry --update would lower or drop."""
    loose = []
    for path, allowed in sorted(baseline.items()):
        lines = current.get(path)
        if lines is None or lines < allowed:
            loose.append((path, allowed, lines))
    return loose


def report_growth(grown):
    print(f'source-size-ratchet: {len(grown)} file(s) over the {THRESHOLD:,}-line threshold '
          f'grew past {BASELINE}:')
    for path, lines, allowed in grown:
        if allowed is None:
            print(f'  {shown(path)}: {lines:,} lines, not in the baseline')
        else:
            print(f'  {shown(path)}: {lines:,} lines, baseline {allowed:,}')
    print('Each needs one of:')
    print(f'  * shrink it back to its baseline entry, or to {THRESHOLD:,} lines or fewer; or')
    print(f'  * raise or add its entry in {BASELINE} in this pull request, and say in the')
    print('    pull request description why the file should grow rather than split.')
    print('Shrinking by deleting comments is not a fix: rationale is worth more than the line count.')
    if not os.path.lexists(BASELINE):
        print(f'There is no {BASELINE}. When adopting this tool, write one with {SELF} --init.')


def report_slack(loose):
    print(f'source-size-ratchet: note: {len(loose)} baseline entr{"y is" if len(loose) == 1 else "ies are"} '
          f'looser than the tree (not a failure):')
    for path, allowed, lines in loose:
        if lines is None:
            print(f'  {shown(path)}: baseline {allowed:,}, now excluded, gone, or {THRESHOLD:,} lines or fewer')
        else:
            print(f'  {shown(path)}: baseline {allowed:,}, now {lines:,}')
    print(f'Run {SELF} --update to tighten them.')


def report_unused(unused):
    print(f'source-size-ratchet: note: {len(unused)} pattern(s) in {EXCLUDE} match no tracked source file:')
    for pattern in unused:
        print(f'  {shown(pattern)}')


def run(mode):
    counts, unused = measure()
    current = oversize(counts)

    if mode == 'init':
        write_baseline(current)
        print(f'source-size-ratchet: wrote {len(current)} entr{"y" if len(current) == 1 else "ies"} to {BASELINE}')
        if unused:
            report_unused(unused)
        return 0

    baseline = read_baseline()
    grown = growth(current, baseline)

    if mode == 'update':
        tightened = {}
        for path, allowed in baseline.items():
            if path in current:
                tightened[path] = min(allowed, current[path])
        if tightened != baseline:
            write_baseline(tightened)
        loose = slack(current, baseline)
        if loose:
            print(f'source-size-ratchet: tightened {len(loose)} entr{"y" if len(loose) == 1 else "ies"} '
                  f'in {BASELINE}')
        else:
            print(f'source-size-ratchet: nothing to tighten in {BASELINE}')
    else:
        loose = slack(current, baseline)
        if loose:
            report_slack(loose)

    if unused:
        report_unused(unused)
    if grown:
        report_growth(grown)
        if mode == 'update':
            print('--update never raises an entry or adds a file; that edit is made by hand.')
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='source-size-ratchet.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f'Fail when a tracked source file over {THRESHOLD:,} lines is missing from {BASELINE}\n'
            'or longer than its entry there. Files already over the threshold may stay as long as\n'
            'they are; growing one is a hand edit to its baseline entry, explained in the pull\n'
            f'request. Generated trees are excluded by glob in {EXCLUDE}.'),
        epilog='Exit status: 0 clean, 1 a file grew past the baseline, 2 the tool itself failed.')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        '--update', dest='mode', action='store_const', const='update',
        help='rewrite the baseline downwards only: lower entries that shrank and drop files at or under '
             'the threshold, gone or excluded; never raise or add one (exits 1 if anything grew)')
    modes.add_argument(
        '--init', dest='mode', action='store_const', const='init',
        help='write the baseline from scratch from the current tree, when adopting the tool')
    args = parser.parse_args(argv)

    try:
        top = os.fsdecode(git('rev-parse', '--show-toplevel')).rstrip('\n')
        os.chdir(top)
        return run(args.mode or 'check')
    except (ToolError, OSError) as e:
        print(f'source-size-ratchet: error: {e}', file=sys.stderr)
        return 2
    except (UnicodeError, ValueError) as e:
        # A backstop: an unexpected name or byte is still the tool
        # failing, not a file growing, so it must not exit 1.
        print(f'source-size-ratchet: error: {e!r}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
