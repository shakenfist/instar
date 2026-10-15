#!/usr/bin/env bash
#
# Seed a stestr repository with committed per-test timing data before
# the first "stestr run", so the scheduler can bin-pack workers by
# measured duration instead of distributing every test round-robin.
#
# stestr partitions a run across workers using durations held in its own
# repository (stestr.scheduler.partition_tests calls
# repository.get_test_times()); a repository created fresh for every CI
# container starts with none, so any test that takes minutes rather than
# seconds lands on whichever worker round-robin assigns it, and that
# worker becomes the run's wall time. Measured on one matrix leg: three
# VirtualPC conversion tests alone cost 1424s of a 5967s total execute
# time, round-robin put all three on one worker, and that worker ran
# 2197s wall against 913s for the lightest -- the leg's wall time is
# its slowest worker's wall time.
#
# "stestr load --force-init FILE" loads a subunit v2 stream's per-test
# start/stop timestamps into a repository, creating the repository
# first if it does not already exist. That is the only mechanism stestr
# offers for this without a hand-written worker-assignment file (see
# stestr/scheduler.py:generate_worker_partitions, which requires one and
# is for manual grouping, not derived timing). The committed TIMING_FILE
# is plain "<test id><TAB><duration>" text, not a subunit stream -- this
# script does that conversion itself, into a throwaway temp file, right
# before loading it. Text stays the committed format (see
# tools/ci/generate-stestr-timing.py for why) because this repository
# tracks no binary files today and a nightly job refreshes this file;
# a sorted, rounded text file keeps that refresh a small diff instead of
# a new ~700 KB blob every time.
#
# usage: seed-stestr-timing.sh STESTR_BIN TIMING_FILE
#
#   STESTR_BIN    path to the stestr executable to invoke, inside a venv
#                 that also has a "python3" alongside it (every venv
#                 this is run against does, since stestr itself needs
#                 one) -- that sibling python3 is what converts
#                 TIMING_FILE to subunit.
#   TIMING_FILE   path to a committed "<test id><TAB><duration>" text
#                 file, one line per test, sorted by test id. A missing
#                 file is NOT an error -- a developer checkout, or a
#                 tree where this data has not yet been generated, must
#                 still be able to run the suite; the scheduler simply
#                 partitions blind, as it always has.
#
# Must be run from the directory that will hold .stestr/ -- i.e. the
# same cwd "stestr run" is about to be invoked from -- since stestr
# resolves its repository relative to the process cwd.
#
# TIMING_FILE is derived, not hand-maintained: tools/ci/generate-
# stestr-timing.py reads the per-test durations a real "stestr run"
# already recorded in its own repository and re-emits them as this
# sorted, rounded text. Regenerate the committed tests/stestr-timing.txt
# with:
#
#   cd tests && ../tests/.venv/bin/stestr run --exclude-regex test_info_malicious
#   cd ..
#   tests/.venv/bin/python3 tools/ci/generate-stestr-timing.py \
#       tests/.stestr tests/stestr-timing.txt

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 STESTR_BIN TIMING_FILE" >&2
    exit 1
fi

STESTR_BIN="$1"
TIMING_FILE="$2"

if [ ! -f "${TIMING_FILE}" ]; then
    echo "no committed stestr timing data at ${TIMING_FILE};" \
        "the scheduler will partition this run blind"
    exit 0
fi

PYTHON_BIN="$(dirname "${STESTR_BIN}")/python3"
SUBUNIT_FILE="$(mktemp)"
trap 'rm -f "${SUBUNIT_FILE}"' EXIT

# Turn the committed text into the subunit v2 stream "stestr load" needs:
# one synthetic inprogress/success pair per line, on an arbitrary
# timeline -- only the gap between the two timestamps is read back out
# for scheduling (stestr.scheduler.partition_tests via
# repository.get_test_times()), so neither the timeline nor the status
# is meaningful beyond that.
"${PYTHON_BIN}" - "${TIMING_FILE}" "${SUBUNIT_FILE}" <<'PY'
import datetime
import sys

import subunit.v2

in_path, out_path = sys.argv[1], sys.argv[2]
epoch = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
with open(in_path) as in_fh, open(out_path, 'wb') as out_fh:
    stream = subunit.v2.StreamResultToBytes(out_fh)
    stream.startTestRun()
    offset = 0.0
    for line in in_fh:
        line = line.rstrip('\n')
        if not line:
            continue
        test_id, duration_text = line.split('\t')
        duration = float(duration_text)
        start = epoch + datetime.timedelta(seconds=offset)
        stop = epoch + datetime.timedelta(seconds=offset + duration)
        stream.status(test_id=test_id, test_status='inprogress', timestamp=start)
        stream.status(test_id=test_id, test_status='success', timestamp=stop)
        offset += duration
    stream.stopTestRun()
PY

echo "seeding stestr repository timing data from ${TIMING_FILE}"
"${STESTR_BIN}" load --force-init "${SUBUNIT_FILE}"
