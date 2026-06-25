#!/usr/bin/env python3
'''Assert every integration test is claimed by at least one CI job.

The Python integration suite (tests/test_*.py) is split across several
CI jobs in .github/workflows/functional-tests.yml, each selecting a
subset with stestr regex filters defined in the Makefile
(test-container-* targets). The split is currently:

  - integration-core         -> make test-container-core
                                (exclude convert/compare/malicious;
                                 the catch-all)
  - integration-convert-qcow2 -> make test-container-convert-qcow2
  - integration-convert-vhd   -> make test-container-convert-vhd

Because integration-core is exclude-based it silently absorbs any new
test file -- which is safe today, but means a future refactor (e.g.
turning it into an include-list like the convert jobs) could drop a
whole test module from CI with no failure. The convert split is also
class-level, so a stray test_convert class could fall between the
qcow2 and vhd selectors. This guard makes either kind of gap a hard
CI failure instead of a silent loss of coverage.

How it stays honest (no duplicated source of truth):

  - The set of active jobs is DISCOVERED from the workflow (every
    `make test-container-*` invocation, plus any inline `stestr run`).
  - Each job's selectors are READ from the Makefile target (or the
    inline workflow command). We never keep a second copy of the
    regexes, so the guard always validates what CI actually runs.
  - The full test-ID universe comes from `stestr list` (fed on stdin),
    i.e. stestr's own discovery -- not a reimplementation.

The only hand-maintained input is INTENTIONAL_EXCLUSIONS: tests that
are deliberately not run by any pull-request job. Each entry needs a
documented reason. That is the human-judgment part and is meant to be
reviewed when it changes.
'''

import argparse
import re
import sys


# Tests deliberately excluded from every pull-request job. Each pattern
# is an re.search() over the full stestr test id. Keep this list short
# and justified -- an unjustified entry here defeats the whole guard.
INTENTIONAL_EXCLUSIONS = [
    # Malicious-image tests run only via `make test-malicious` (explicit
    # opt-in); they are excluded from PR CI by every test-container-*
    # target's --exclude-regex. See Makefile test-malicious.
    (r'^test_info_malicious\.', 'malicious images; opt-in via make test-malicious only'),
]


class JobSelector:
    '''A CI job's stestr selection: OR of `includes`, minus `excludes`.'''

    def __init__(self, name, includes, excludes):
        self.name = name
        # Empty includes == match everything (the exclude-based catch-all).
        self.includes = [re.compile(p) for p in includes]
        self.excludes = [re.compile(p) for p in excludes]
        self.include_src = list(includes)
        self.exclude_src = list(excludes)

    def selects(self, test_id):
        if self.includes and not any(p.search(test_id) for p in self.includes):
            return False
        if any(p.search(test_id) for p in self.excludes):
            return False
        return True

    def describe(self):
        inc = ' | '.join(self.include_src) if self.include_src else '(all)'
        exc = ' | '.join(self.exclude_src) if self.exclude_src else '(none)'
        return 'include=%s  exclude=%s' % (inc, exc)


def _quoted_tokens(text):
    '''Yield (token, preceding_flag) for every "double-quoted" string,
    where preceding_flag is the immediately preceding bare word (so we
    can tell a --exclude-regex argument from a positional selector).'''
    out = []
    # Match either a flag word or a quoted string, in order.
    for m in re.finditer(r'(--[a-z-]+)|"([^"]*)"', text):
        out.append(m)
    results = []
    for i, m in enumerate(out):
        if m.group(2) is None:
            continue  # this match is a flag, not a quoted token
        prev = out[i - 1].group(1) if i > 0 else None
        results.append((m.group(2), prev))
    return results


def parse_makefile_target(makefile_text, target):
    '''Extract (includes, excludes) for a Makefile test-container target
    by reading the stestr invocation in its recipe.'''
    # Recipe runs from the target line to the next top-level target or a
    # blank-line-separated stanza. We scan until the closing single quote
    # of the `bash -c '...'` block, or the next `^<word>:` target line.
    lines = makefile_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith('%s:' % target):
            start = i
            break
    if start is None:
        raise LookupError('Makefile target not found: %s' % target)

    recipe = []
    for line in lines[start + 1:]:
        # Stop at the next target definition (a non-indented `name:` line).
        if re.match(r'^[A-Za-z0-9_.-]+:', line):
            break
        recipe.append(line)
    recipe_text = '\n'.join(recipe)

    # Only consider the stestr run invocation.
    m = re.search(r'stestr\s+run\b(.*?)(?:\n\s*\'|\Z)', recipe_text, re.DOTALL)
    if not m:
        raise LookupError('no `stestr run` found in target %s' % target)
    invocation = m.group(1)

    includes, excludes = [], []
    for token, prev in _quoted_tokens(invocation):
        if prev == '--exclude-regex':
            excludes.append(token)
        else:
            includes.append(token)
    return includes, excludes


def parse_inline_stestr(command):
    '''Parse selectors from an inline `stestr run ...` workflow command.'''
    m = re.search(r'stestr\s+run\b(.*)', command)
    invocation = m.group(1) if m else ''
    includes, excludes = [], []
    # Quoted tokens first.
    for token, prev in _quoted_tokens(invocation):
        (excludes if prev == '--exclude-regex' else includes).append(token)
    # Then bare positional words (e.g. `stestr run test_oslo_crossval`),
    # skipping flags and their values.
    bare = re.sub(r'"[^"]*"', ' ', invocation)
    words = bare.split()
    skip_next = False
    for w in words:
        if skip_next:
            skip_next = False
            continue
        if w.startswith('--'):
            # --concurrency takes a value; --serial does not. Be lenient:
            # only --exclude-regex/--concurrency consume a following word.
            if w in ('--exclude-regex', '--concurrency'):
                skip_next = True
            continue
        if re.match(r'^[A-Za-z_]', w):
            includes.append(re.escape(w) if '\\' not in w else w)
    return includes, excludes


def discover_jobs(makefile_text, workflow_text):
    '''Build the list of JobSelectors actually exercised on pull requests,
    by reading the workflow for `make test-container-*` invocations and
    inline `stestr run` commands, then resolving selectors.'''
    jobs = []

    targets = sorted(set(re.findall(r'make\s+(test-container-[a-z0-9-]+)', workflow_text)))
    for target in targets:
        includes, excludes = parse_makefile_target(makefile_text, target)
        jobs.append(JobSelector(target, includes, excludes))

    # Inline `stestr run` in the workflow (e.g. the oslo-crossval job).
    # The Makefile is parsed separately above; here we only want the
    # workflow's own direct invocations.
    for m in re.finditer(r'(/[^\s]*/)?stestr\s+run\b[^\n]*', workflow_text):
        includes, excludes = parse_inline_stestr(m.group(0))
        if includes or excludes:
            jobs.append(JobSelector('workflow-inline:%s' % '+'.join(includes) or 'inline',
                                    includes, excludes))
    return jobs


def is_intentionally_excluded(test_id):
    for pattern, _reason in INTENTIONAL_EXCLUSIONS:
        if re.search(pattern, test_id):
            return True
    return False


def read_test_ids(stream):
    ids = []
    for raw in stream:
        line = raw.strip()
        # A stestr test id looks like module.Class.method (>= 2 dots,
        # starts with test_). Ignore any stray output.
        if re.match(r'^test_[\w]+\.[\w]+', line):
            ids.append(line)
    return ids


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--makefile', required=True, help='path to the Makefile')
    ap.add_argument('--workflow', required=True,
                    help='path to functional-tests.yml')
    ap.add_argument('--test-ids', default='-',
                    help='file with stestr ids (one per line); default stdin')
    args = ap.parse_args(argv)

    with open(args.makefile, encoding='utf-8') as f:
        makefile_text = f.read()
    with open(args.workflow, encoding='utf-8') as f:
        workflow_text = f.read()

    if args.test_ids == '-':
        test_ids = read_test_ids(sys.stdin)
    else:
        with open(args.test_ids, encoding='utf-8') as f:
            test_ids = read_test_ids(f)

    if not test_ids:
        print('ERROR: no test ids on input -- did `stestr list` run?', file=sys.stderr)
        return 2

    try:
        jobs = discover_jobs(makefile_text, workflow_text)
    except LookupError as exc:
        print('ERROR parsing CI selectors: %s' % exc, file=sys.stderr)
        print('The Makefile/workflow format changed; update '
              'tools/ci/check-test-partition.py to match.', file=sys.stderr)
        return 2

    coverage = {tid: [] for tid in test_ids}
    for job in jobs:
        for tid in test_ids:
            if job.selects(tid):
                coverage[tid].append(job.name)

    orphans = []
    for tid in test_ids:
        if coverage[tid]:
            continue
        if is_intentionally_excluded(tid):
            continue
        orphans.append(tid)

    overlaps = {tid: js for tid, js in coverage.items() if len(js) > 1}

    print('=== CI test-partition check ===')
    print('test ids discovered : %d' % len(test_ids))
    print('coverage-contributing jobs:')
    for job in jobs:
        n = sum(1 for tid in test_ids if job.name in coverage[tid])
        print('  - %-30s %5d tests   [%s]' % (job.name, n, job.describe()))

    intentionally = sum(1 for tid in test_ids if not coverage[tid]
                        and is_intentionally_excluded(tid))
    if intentionally:
        print('intentionally excluded (allowlisted): %d' % intentionally)

    if overlaps:
        # Overlap wastes runner time but is not a coverage failure (e.g.
        # oslo-crossval re-runs a core test against a different dep set).
        print()
        print('NOTE: %d test(s) run in more than one job (wasted runner '
              'time, not a failure):' % len(overlaps))
        shown = sorted(overlaps.items())[:10]
        for tid, js in shown:
            print('  %s  -> %s' % (tid, ', '.join(js)))
        if len(overlaps) > 10:
            print('  ... and %d more' % (len(overlaps) - 10))

    if orphans:
        print()
        print('FAIL: %d test(s) are run by NO pull-request job '
              '(silent coverage loss):' % len(orphans))
        by_module = {}
        for tid in orphans:
            by_module.setdefault(tid.split('.', 1)[0], []).append(tid)
        for module in sorted(by_module):
            print('  %s  (%d):' % (module, len(by_module[module])))
            for tid in by_module[module][:5]:
                print('    %s' % tid)
            if len(by_module[module]) > 5:
                print('    ... and %d more' % (len(by_module[module]) - 5))
        print()
        print('Fix: add these to a CI job (a Makefile test-container-* '
              'selector) or, if deliberately excluded, add a justified '
              'entry to INTENTIONAL_EXCLUSIONS in this script.')
        return 1

    print()
    print('PASS: every discovered test is claimed by at least one '
          'pull-request job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
