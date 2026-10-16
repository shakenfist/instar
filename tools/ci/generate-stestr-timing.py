#!/usr/bin/env python3
"""Derive tests/stestr-timing.txt from a real stestr run.

tools/ci/seed-stestr-timing.sh converts that file into a subunit v2
stream and loads it into a fresh stestr repository before "stestr
run", so the scheduler can bin-pack workers by measured duration
instead of splitting every test round-robin across them. That file
must be *derived*, not hand-maintained: this repository has already
been bitten by hand-maintained figures drifting (the mutation
harness's case counts drifted three review rounds running, and are
now computed instead).

This script is the derivation. stestr's own repository already
records a per-test duration for every test a run executed (read by
stestr.scheduler.partition_tests via repository.get_test_times() --
see tools/ci/seed-stestr-timing.sh for the mechanism this feeds). This
reads those durations straight out of the repository's on-disk
'times' store and re-emits them as plain text: one
"<test id><TAB><duration>" line per test, sorted by test id, duration
rounded to 0.01 seconds.

Text rather than the subunit v2 stream it used to be, and the rounding,
are both deliberate: this repository tracks no binary files today (its
largest tracked file of any kind is 828 KB), a nightly job refreshes
this file, and most test durations do not move from one run to the
next. A sorted, rounded text file keeps that refresh a small diff; a
binary stream with full timestamp precision would instead make every
refresh a whole new ~700 KB blob, because almost nothing about it
would byte-match the last one. Generating twice from the same
repository must therefore produce byte-identical output -- see
tools/ci/test-generate-stestr-timing.sh, which asserts exactly that.

Regenerate the committed file with:

    cd tests && ../tests/.venv/bin/stestr run --exclude-regex test_info_malicious
    cd ..
    tests/.venv/bin/python3 tools/ci/generate-stestr-timing.py \\
        tests/.stestr tests/stestr-timing.txt

usage: generate-stestr-timing.py REPO_DIR OUTPUT_FILE

  REPO_DIR     path to a stestr repository that already holds at least
               one completed run (e.g. tests/.stestr right after
               "stestr run"). Its on-disk format is stestr's own
               (stestr.repository.file.Repository), not a public API --
               if a future stestr release changes it, this script is
               the one place that needs updating, not every consumer.
  OUTPUT_FILE  path to write the derived "<test id><TAB><duration>"
               text to.
"""

import dbm.dumb as dumbdbm
import sys


def read_durations(repo_dir):
    """Read every (test_id -> duration seconds) pair stestr recorded.

    :param str repo_dir: path to a stestr repository directory.
    :return: a dict mapping test id (str) to duration (float seconds).
    """
    db = dumbdbm.open(f'{repo_dir}/times.dbm', 'r')
    try:
        durations = {}
        for key in db.keys():
            test_id = key.decode('utf-8') if isinstance(key, bytes) else key
            durations[test_id] = float(db[key])
        return durations
    finally:
        db.close()


def write_timing_text(durations, out_path):
    """Write "<test id><TAB><duration>" lines, sorted, rounded to 0.01s.

    Sorting and rounding are both what keep a nightly refresh a small
    diff rather than a new file every time: an unsorted dict iteration
    order, or full float precision, would change nearly every line even
    when the measured durations barely moved.

    :param dict durations: test id (str) -> duration (float seconds).
    :param str out_path: path to write the text to.
    """
    with open(out_path, 'w') as fh:
        for test_id in sorted(durations):
            fh.write(f'{test_id}\t{durations[test_id]:.2f}\n')


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        print('usage: generate-stestr-timing.py REPO_DIR OUTPUT_FILE', file=sys.stderr)
        return 1

    repo_dir, out_path = argv[1], argv[2]

    try:
        durations = read_durations(repo_dir)
    except OSError as exc:
        print(f'error: could not open stestr repository at {repo_dir}: {exc}', file=sys.stderr)
        return 1

    if not durations:
        print(f'error: {repo_dir} has no recorded test durations -- run "stestr run" there first',
              file=sys.stderr)
        return 1

    write_timing_text(durations, out_path)
    print(f'wrote {len(durations)} test durations from {repo_dir} to {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
