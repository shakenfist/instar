#!/usr/bin/env python3
"""Decide whether a freshly measured stestr timing file is worth publishing.

tests/stestr-timing.txt is a scheduling hint and nothing else:
tools/ci/seed-stestr-timing.sh loads it into stestr's repository before a
run so the scheduler can bin-pack workers by measured duration instead of
splitting the suite round-robin. A stale hint degrades packing gradually
and can never make a run wrong, which sets the bias for this script --
stay silent on a night when nothing meaningful changed, rather than open
a pull request every morning against a file nobody needs to look at.

So the nightly measurement leg re-derives the file and this decides
whether the difference is worth a human's attention. "Materially moved"
is defined on the only property the scheduler actually consumes, and the
definition matters more than the numbers:

**Bin packing is scale-free.** Multiply every duration by 1.3 and stestr
produces exactly the same partition. A contended runner, a slower runner
generation or a faster qemu therefore changes the file's numbers without
changing a single scheduling decision, and that is the commonest night-
to-night difference by far. Both tests below are expressed in each test's
*share of the suite's total weight*, so a uniform shift of any size is
invisible to them.

A refresh is published when either holds:

1. **One test's share moved by at least SINGLE_TEST_SHARE_PP percentage
   points**, counting a test absent from one side as zero. On this tree a
   percentage point is about 50 seconds, so two points is roughly 100
   seconds against a worker's quarter-share of 25 points -- about 8% of
   one worker's load, enough to change which worker a test lands on and
   to show up in the leg's wall time. It also catches the case
   seeding exists to make visible: a newly added test that is minutes
   long arrives with a share well over two points, where round-robin
   would have hidden it until someone wondered why the leg got slower.
   The 3,400-odd sub-second cases cannot reach this test at all, which is
   the point -- their durations jitter by milliseconds every run.

2. **At least TOTAL_VARIATION_PP percentage points of the suite's weight
   moved between tests.** Half the sum of the absolute share changes,
   which is the fraction of the suite's weight that relocated. This is
   the broad-recomposition case that no single test shows: a distro's
   qemu-img getting much faster at one format, or a few dozen tests
   changing together. A tenth is a large recomposition for a file whose
   22 heaviest tests carry 74% of the weight.

Anything smaller is noise, and noise is what a quiet default is for.

usage: compare-stestr-timing.py OLD_FILE NEW_FILE

Writes a Markdown report to stdout -- the verdict, the totals and the
largest movers -- which tools/ci/publish-stestr-timing.sh uses as the
body of the pull request it opens. Because that report names test ids
read out of a file another job produced, the ids are checked against
TEST_ID_RE here and anything else stops the refresh; see the note on
that constant.

Exit codes, so the caller branches on a status rather than parsing prose:

  0   material: publish the refreshed file
  10  immaterial: stay quiet
  1   error (bad usage, unreadable or malformed input)

A missing OLD_FILE is material rather than an error: it means nothing is
committed yet, and the first measurement is always worth having.

tools/ci/test_compare_stestr_timing.py exercises each rule, and pins the
scale invariance above as its own case -- that property is the whole
reason this script is not a diff.
"""

import os
import re
import sys

# Both thresholds are in percentage points of the suite's total measured
# weight. See the module docstring for where the numbers come from; they
# are deliberately in one place so a later tuning is one edit and the
# tests move with it.
SINGLE_TEST_SHARE_PP = 2.0
TOTAL_VARIATION_PP = 10.0

# How many movers the report lists. Enough to show what changed without
# pasting a 3,675-line file into a pull request body.
REPORT_MOVERS = 15

# What a test id is allowed to look like on this path: a dotted
# module.Class.method, optionally carrying a testscenarios suffix in
# parentheses. Every one of the 3,675 ids in the committed file matches
# it, and the characters it admits -- letters, digits, underscore, dot,
# hyphen, plus -- are the ones those ids actually use.
#
# This is a security boundary rather than a tidiness check, and it is
# here because this is the publication path. The ids arrive in a file
# derived by the one job that runs the whole suite over 7.5 GiB of
# deliberately malformed images, and from here they travel into a
# Markdown report, into the body of a pull request opened unattended,
# and into the committed scheduling hint. An id carrying a backtick, a
# pipe, a fenced block, an `@name` or an HTML comment would be rendering
# as Markdown in a pull request nobody wrote. Constraining the id is
# what makes every code span and table cell below safe, so nothing
# downstream has to escape them one at a time.
#
# It fails closed: an id outside this shape raises, the publisher exits
# non-zero and the nightly files an issue about the refresh. That is the
# right direction for the path that WRITES the committed file --
# tools/ci/seed-stestr-timing.sh, which only reads it before a run,
# deliberately fails open instead, because one bad line there would take
# out every testdata job. The cost here is that a test id in some new
# shape -- a scenario name with a space or a comma in it -- stops the
# refresh until someone widens this. That is a visible issue rather than
# a silent publish, which is the trade this whole script is built on.
TEST_ID_RE = re.compile(r'^[A-Za-z0-9_.+-]+(\([A-Za-z0-9_.+-]+\))?$')


class TimingError(Exception):
    """A timing file could not be read or parsed."""


def read_timings(path):
    """Read a "<test id><TAB><duration>" timing file.

    :param str path: path to the file, in the format
        tools/ci/generate-stestr-timing.py writes.
    :return: a dict mapping test id (str) to duration (float seconds).
    :raises TimingError: if the file cannot be read, holds a line that is
        not an id and a duration, or holds an id outside TEST_ID_RE. A
        malformed file is an error rather than something to work around:
        this decides whether to open a pull request, and guessing at a
        half-written measurement is how a wrong hint gets committed.
    """
    durations = {}
    try:
        with open(path) as fh:
            for number, line in enumerate(fh, start=1):
                line = line.rstrip('\n')
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) != 2:
                    raise TimingError(f'{path}:{number}: expected "<test id><TAB><duration>", got {line!r}')
                if not TEST_ID_RE.match(parts[0]):
                    # Quoted with !r so the rejected bytes cannot break
                    # the line they are reported on either.
                    raise TimingError(f'{path}:{number}: {parts[0]!r} is not a test id')
                try:
                    durations[parts[0]] = float(parts[1])
                except ValueError:
                    raise TimingError(f'{path}:{number}: {parts[1]!r} is not a duration')
    except OSError as exc:
        raise TimingError(f'could not read {path}: {exc}')
    if not durations:
        raise TimingError(f'{path} holds no test durations')
    return durations


def shares(durations):
    """Convert durations to each test's share of the total, in percentage points.

    Shares rather than seconds because stestr's bin packing is
    scale-free: a run that was uniformly 30% slower produces the same
    partition, so comparing seconds would report a change the scheduler
    cannot see.

    :param dict durations: test id (str) -> duration (float seconds).
    :return: a dict mapping test id (str) to share (float percentage points).
    """
    total = sum(durations.values())
    if total <= 0:
        raise TimingError('timing file totals zero seconds, so it has no shares to compare')
    return {test_id: 100.0 * duration / total for test_id, duration in durations.items()}


def compare(old, new):
    """Compare two sets of durations and decide whether the change is material.

    :param dict old: committed test id -> duration (float seconds).
    :param dict new: freshly measured test id -> duration (float seconds).
    :return: a dict with keys 'material' (bool), 'reasons' (list of str),
        'movers' (list of (share_delta_pp, test_id, old_seconds,
        new_seconds), largest absolute share delta first),
        'weight_moved_pp' (float), 'old_total', 'new_total',
        'added' and 'removed' (lists of test ids).
    """
    old_share = shares(old)
    new_share = shares(new)

    movers = []
    for test_id in set(old) | set(new):
        delta = new_share.get(test_id, 0.0) - old_share.get(test_id, 0.0)
        movers.append((delta, test_id, old.get(test_id), new.get(test_id)))
    movers.sort(key=lambda row: (-abs(row[0]), row[1]))

    # Half the L1 distance between the two share distributions: both sum
    # to 100 points, so halving turns "every point counted at both ends"
    # into the fraction of the suite's weight that actually relocated.
    weight_moved_pp = sum(abs(row[0]) for row in movers) / 2.0

    reasons = []
    biggest = movers[0] if movers else (0.0, None, None, None)
    if abs(biggest[0]) >= SINGLE_TEST_SHARE_PP:
        reasons.append(
            f'`{biggest[1]}` moved {biggest[0]:+.2f} points of the suite\'s weight '
            f'(threshold {SINGLE_TEST_SHARE_PP:.2f})')
    if weight_moved_pp >= TOTAL_VARIATION_PP:
        reasons.append(
            f'{weight_moved_pp:.2f} points of the suite\'s weight moved between tests '
            f'(threshold {TOTAL_VARIATION_PP:.2f})')

    return {
        'material': bool(reasons),
        'reasons': reasons,
        'movers': movers,
        'weight_moved_pp': weight_moved_pp,
        'old_total': sum(old.values()),
        'new_total': sum(new.values()),
        'old_count': len(old),
        'new_count': len(new),
        'added': sorted(set(new) - set(old)),
        'removed': sorted(set(old) - set(new)),
    }


def format_report(result, old_path, new_path):
    """Render a comparison as the Markdown a pull request body wants.

    :param dict result: the return value of compare().
    :param str old_path: path the committed timings were read from.
    :param str new_path: path the measured timings were read from.
    :return: a Markdown report (str).
    """
    lines = []
    if result['material']:
        lines.append('The measured test timings have moved enough to be worth committing.')
    else:
        lines.append('The measured test timings have not moved enough to be worth committing.')
    lines.append('')
    lines.append(f'- committed: `{old_path}`, {result["old_total"]:.0f}s over {result["old_count"]} tests')
    lines.append(f'- measured: `{new_path}`, {result["new_total"]:.0f}s over {result["new_count"]} tests')
    lines.append(f'- weight moved between tests: {result["weight_moved_pp"]:.2f} points '
                 f'(threshold {TOTAL_VARIATION_PP:.2f})')
    lines.append(f'- largest single-test move: {result["movers"][0][0]:+.2f} points '
                 f'(threshold {SINGLE_TEST_SHARE_PP:.2f})')
    if result['added']:
        lines.append(f'- tests measured for the first time: {len(result["added"])}')
    if result['removed']:
        lines.append(f'- tests no longer measured: {len(result["removed"])}')
    lines.append('')

    if result['reasons']:
        lines.append('Why this is material:')
        lines.append('')
        for reason in result['reasons']:
            lines.append(f'- {reason}')
        lines.append('')

    lines.append(f'Largest movers (share of the suite\'s total weight, {REPORT_MOVERS} shown):')
    lines.append('')
    lines.append('| Test | Committed | Measured | Share change |')
    lines.append('| ---- | --------- | -------- | ------------ |')
    for delta, test_id, old_seconds, new_seconds in result['movers'][:REPORT_MOVERS]:
        old_text = '--' if old_seconds is None else f'{old_seconds:.2f}s'
        new_text = '--' if new_seconds is None else f'{new_seconds:.2f}s'
        lines.append(f'| `{test_id}` | {old_text} | {new_text} | {delta:+.2f} pp |')
    lines.append('')
    return '\n'.join(lines)


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        print('usage: compare-stestr-timing.py OLD_FILE NEW_FILE', file=sys.stderr)
        return 1

    old_path, new_path = argv[1], argv[2]

    try:
        new = read_timings(new_path)
    except TimingError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    if not os.path.exists(old_path):
        # Nothing committed yet. The first measurement is always worth
        # having, and there is no baseline to call it immaterial against.
        print(f'No committed timing data at `{old_path}`, so this first measurement is worth committing: '
              f'{sum(new.values()):.0f}s over {len(new)} tests.')
        return 0

    try:
        old = read_timings(old_path)
        result = compare(old, new)
    except TimingError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    print(format_report(result, old_path, new_path))
    return 0 if result['material'] else 10


if __name__ == '__main__':
    sys.exit(main(sys.argv))
