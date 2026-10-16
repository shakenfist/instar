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

The merge-queue distro matrix is a second partition over the same
suite, and it is checked separately because it does not run on pull
requests. Six heavy VHD conversion tests moved off the merge gate to a
nightly cross-distro run, so what used to be one selection is now two
halves that must still add up:

  - the merge-queue matrix -> make target for MATRIX_SET=queue
  - the nightly matrix     -> make target for MATRIX_SET=nightly

Losing a test from both halves is this guard's worst case and the one
with no symptom at all: nothing fails, CI simply goes green faster. So
the halves are asserted to cover, between them, everything an
unselected matrix entry ran before the split, and to not overlap --
an overlap means the gate is still paying for a test the nightly
claims to have taken off it.

How it stays honest (no duplicated source of truth):

  - The set of active jobs is DISCOVERED from the workflows (every
    `make test-container-*` invocation, plus any inline `stestr run`).
  - The matrix jobs are discovered through the same indirection the
    workflows actually use. A matrix leg does not invoke a Makefile
    target: it calls tools/ci/run-matrix-entry.sh, which maps a
    MATRIX_SET value to a Makefile target name. So the guard reads the
    MATRIX_SET value (or its absence, which means the script's own
    default) out of each workflow job, reads the set-to-target mapping
    and that default out of run-matrix-entry.sh, and reads the selector
    out of the named Makefile target. Nothing in the chain is restated
    here, which is why a renamed target or a typo'd MATRIX_SET is a
    parse failure rather than a quietly different selection.
  - Each job's selectors are READ from the Makefile target (or the
    inline workflow command). We never keep a second copy of the
    regexes, so the guard always validates what CI actually runs.
  - What an unselected matrix entry runs -- the baseline the two halves
    must cover -- is the suite minus the exclusions in
    tools/test-package-functional.sh, read from that script.
  - The distro lists of every matrix job that has a distro axis are
    compared with each other. The merge-queue list and the nightly list
    are deliberately copies rather than a shared JSON file, because
    their entries carry a Debian 12 end-of-life rationale and an audit
    marker that JSON cannot hold, so this is the thing that keeps them
    in step. A distro present in one list and not the other is reported
    by name. Reading those lists is a text scan, so a list that reads as
    no distros at all, or a run with fewer than two readable lists while
    more than one leg selects tests, is a failure in its own right --
    otherwise a reformatted list would leave the comparison with nothing
    to compare and the run would still be green.
  - A leg running the selector-free set must exist too. It contributes no
    coverage, so no other assertion here needs it, but it is the only run
    that measures a duration for every test and so the only thing
    tests/stestr-timing.txt can be derived from.
  - The full test-ID universe comes from `stestr list` (fed on stdin),
    i.e. stestr's own discovery -- not a reimplementation.

What `stestr list` does NOT give us, because it matters to how far the
conclusions reach. A listing collapses a parameterised test to its bare
id: test_info_safe.TestInfoSafe.test_output_matches_baseline is one
line in a listing and several hundred ids in a run, because the cases
are built at load time. Measured on this tree, a listing enumerates
2378 ids where a run reports 3675. The conclusions still hold for a
prefix-style selector, which is what every selector here is bar one:
a variant's id begins with its bare id, so a job claiming the bare id
claims every variant of it.

The exception is an anchored selector -- the nightly's selection is
`^(?:...)$` over six literal ids -- which does not match a
parameterised variant of one of those ids at all. If one of the six
ever gained variants, the nightly would claim only the bare id and the
queue's negated complement (also `$`-anchored, so its lookahead fails
to fire on a variant) would claim the variants: they would stay on the
merge gate. That is the safe direction -- the coverage assertion cannot
be fooled by it, only the time saving is smaller than it looks -- and
it is recorded here so nobody has to rediscover it from a confusing
Worker Balance block.

The only hand-maintained input is INTENTIONAL_EXCLUSIONS: tests that
are deliberately not run by any pull-request job. Each entry needs a
documented reason. That is the human-judgment part and is meant to be
reviewed when it changes.
'''

import argparse
import os
import re
import sys


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
        # A recipe writes a literal dollar as "$$" so make passes one
        # through; the matrix selectors anchor each test id with "$", so
        # undo the doubling to get the regex stestr actually sees.
        # tools/ci/run-matrix-entry.sh does the same thing for the same
        # reason, and the two must agree or the guard would be checking
        # a regex no run ever uses.
        token = token.replace('$$', '$')
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


def _in_yaml_comment(text, offset):
    '''True if `offset` falls inside a YAML comment on its line.

    Not cosmetic. The workflow explains the selectors in prose, and a
    comment saying `before "stestr run", so ...` was being discovered as
    a job whose selector was the bare word `so` -- which matches a large
    part of the suite and would have masked a real orphan. A match is
    only a command if nothing before it on the line is a `#`.'''
    line_start = text.rfind('\n', 0, offset) + 1
    return '#' in text[line_start:offset]


def discover_jobs(makefile_text, workflow_text):
    '''Build the list of JobSelectors actually exercised on pull requests,
    by reading the workflow for `make test-container-*` invocations and
    inline `stestr run` commands, then resolving selectors.'''
    jobs = []

    targets = []
    for m in re.finditer(r'make\s+(test-container-[a-z0-9-]+)', workflow_text):
        if _in_yaml_comment(workflow_text, m.start()):
            continue
        if m.group(1) not in targets:
            targets.append(m.group(1))
    for target in sorted(targets):
        includes, excludes = parse_makefile_target(makefile_text, target)
        jobs.append(JobSelector(target, includes, excludes))

    # Inline `stestr run` in the workflow (e.g. the oslo-crossval job).
    # The Makefile is parsed separately above; here we only want the
    # workflow's own direct invocations.
    for m in re.finditer(r'(/[^\s]*/)?stestr\s+run\b[^\n]*', workflow_text):
        if _in_yaml_comment(workflow_text, m.start()):
            continue
        includes, excludes = parse_inline_stestr(m.group(0))
        if includes or excludes:
            jobs.append(JobSelector('workflow-inline:%s' % '+'.join(includes) or 'inline',
                                    includes, excludes))
    return jobs


class MatrixJob:
    '''A distro-matrix leg: which half of the split it runs, through which
    Makefile target, and which distros it runs on.

    `selector` is None for the set that passes no selector at all (the
    whole suite as a matrix entry ran it before the split). Such a leg
    measures rather than gates, so it contributes no coverage and is
    reported but not counted.'''

    def __init__(self, label, matrix_set, target, selector, distros):
        self.label = label
        self.matrix_set = matrix_set
        self.target = target
        self.selector = selector
        self.distros = distros

    def describe_target(self):
        if not self.target:
            return '(no selector -- the whole suite)'
        return self.target


def parse_matrix_sets(entry_runner_text):
    '''Read tools/ci/run-matrix-entry.sh's MATRIX_SET handling.

    Returns (default_set, {set_name: makefile_target}), where the target
    is the empty string for a set that runs with no selector. Both come
    out of the script because the script is what CI runs: a workflow job
    that sets no MATRIX_SET gets whatever default is written there, and
    the set-to-target mapping is the indirection a matrix leg reaches
    the Makefile through.'''
    m = re.search(r'MATRIX_SET:-([a-z][a-z0-9]*)', entry_runner_text)
    if not m:
        raise LookupError('no MATRIX_SET default found in the matrix entry runner')
    default_set = m.group(1)

    targets = {}
    for arm in re.finditer(r'^\s*([a-z][a-z0-9|]*)\)\s*SELECT_TARGET=\'?([A-Za-z0-9_.-]*)\'?',
                           entry_runner_text, re.MULTILINE):
        for name in arm.group(1).split('|'):
            targets[name] = arm.group(2)
    if not targets:
        raise LookupError('no MATRIX_SET case arms found in the matrix entry runner')
    if default_set not in targets:
        raise LookupError('the matrix entry runner defaults MATRIX_SET to %r, which is '
                          'not one of its own case arms (%s)'
                          % (default_set, ', '.join(sorted(targets))))
    return default_set, targets


def split_workflow_jobs(workflow_text):
    '''Yield (job_key, job_text) for every job in a workflow file.

    Text-based on purpose: this guard is stdlib-only so it can run
    without a venv, and the enclosing job is all the structure the
    MATRIX_SET lookup needs.'''
    lines = workflow_text.splitlines()
    starts = []
    in_jobs = False
    for i, line in enumerate(lines):
        if re.match(r'^jobs:\s*$', line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if re.match(r'^[A-Za-z]', line):
            # A new top-level key ends the jobs mapping.
            starts.append((None, i))
            break
        m = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if m:
            starts.append((m.group(1), i))
    out = []
    for idx, (key, start) in enumerate(starts):
        if key is None:
            continue
        end = starts[idx + 1][1] if idx + 1 < len(starts) else len(lines)
        out.append((key, '\n'.join(lines[start:end])))
    return out


def parse_distro_matrix(job_text):
    '''Return the [(name, image, pkg_kind)] of a job's `distro:` matrix
    axis, or None if it has no distro axis.

    The entries are read rather than named, so the comments and audit
    markers that live between them -- which is why the two lists are
    copies rather than a shared file -- do not have to be understood
    here.

    An entry begins at its `-` and its keys are read in whatever order
    they appear, with comment lines between two keys of one entry
    tolerated (the Debian 12 end-of-life marker is exactly that). The
    key order matters because this is a text scan over indentation
    rather than a YAML parse: an earlier version keyed each entry on
    `- name:` being its first line, so a YAML-equivalent reformat
    putting `image:` first would have returned a shorter list -- and a
    shorter list is how the comparison in check_matrix_partition goes
    quiet rather than loud.'''
    lines = job_text.splitlines()
    start = None
    indent = 0
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)distro:\s*$', line)
        if m:
            start = i + 1
            indent = len(m.group(1))
            break
    if start is None:
        return None

    entries = []
    current = None
    for line in lines[start:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        m = re.match(r'^\s*-\s*(.*)$', line)
        if m:
            current = {}
            entries.append(current)
            rest = m.group(1)
        else:
            if current is None:
                continue
            rest = line.strip()
        m = re.match(r'^([a-z_]+):\s*\'?([^\'\n]*?)\'?\s*$', rest)
        if m:
            current[m.group(1)] = m.group(2)
    return [(e.get('name', ''), e.get('image', ''), e.get('pkg_kind', '')) for e in entries]


def discover_matrix_jobs(makefile_text, workflows, entry_runner_text):
    '''Discover the distro-matrix legs across every workflow file.

    `workflows` is a list of (label, text). A leg is any workflow job
    that runs tools/ci/run-matrix-entry.sh; its half of the split is the
    nearest MATRIX_SET assignment above the invocation in the same job,
    or the runner script's own default when the job sets none (which is
    how the merge-queue matrix selects the queue half).

    Returns (jobs, errors, set_targets): `errors` holds MATRIX_SET values
    the runner script does not implement, which would fail the leg at
    runtime, and `set_targets` is the runner's own set-to-target mapping
    so a caller can tell which halves exist at all.'''
    default_set, set_targets = parse_matrix_sets(entry_runner_text)
    jobs, errors = [], []
    for label, text in workflows:
        for key, job_text in split_workflow_jobs(text):
            invocations = [m for m in re.finditer(r'run-matrix-entry\.sh', job_text)
                           if not _in_yaml_comment(job_text, m.start())]
            if not invocations:
                continue
            assignments = [m for m in re.finditer(r'MATRIX_SET:\s*\'?([A-Za-z0-9_]+)\'?', job_text)
                           if m.start() < invocations[0].start()
                           and not _in_yaml_comment(job_text, m.start())]
            matrix_set = assignments[-1].group(1) if assignments else default_set
            job_label = '%s:%s' % (label, key)
            if matrix_set not in set_targets:
                errors.append('%s sets MATRIX_SET=%s, which tools/ci/run-matrix-entry.sh '
                              'does not implement (it accepts %s)'
                              % (job_label, matrix_set, ', '.join(sorted(set_targets))))
                continue
            target = set_targets[matrix_set]
            selector = None
            if target:
                includes, excludes = parse_makefile_target(makefile_text, target)
                selector = JobSelector(target, includes, excludes)
            jobs.append(MatrixJob(job_label, matrix_set, target, selector,
                                  parse_distro_matrix(job_text)))
    return jobs, errors, set_targets


def parse_runner_exclusions(functional_runner_text):
    '''Read the exclude regex tools/test-package-functional.sh applies to
    every matrix run, which is what makes the "whole suite" of an
    unselected matrix entry smaller than the stestr listing.'''
    m = re.search(r'^EXCLUDE_RE=\'([^\']*)\'', functional_runner_text, re.MULTILINE)
    if not m:
        raise LookupError('no EXCLUDE_RE assignment found in the functional runner')
    return m.group(1)


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


def _lines_by_module(test_ids, per_module=5):
    '''Render test ids grouped by module, so a whole module dropping out
    of a selector reads as one line with a count rather than as a wall
    of ids the reader has to spot the pattern in.'''
    by_module = {}
    for tid in test_ids:
        by_module.setdefault(tid.split('.', 1)[0], []).append(tid)
    lines = []
    for module in sorted(by_module):
        lines.append('  %s  (%d):' % (module, len(by_module[module])))
        for tid in by_module[module][:per_module]:
            lines.append('    %s' % tid)
        if len(by_module[module]) > per_module:
            lines.append('    ... and %d more' % (len(by_module[module]) - per_module))
    return lines


def check_matrix_partition(makefile_text, workflows, entry_runner_text,
                           functional_runner_text, test_ids):
    '''Check the merge-queue / nightly split of the distro matrix.

    Returns (rc, lines): rc is 0 when the split holds, 1 for a coverage
    or consistency failure, 2 when the chain from workflow to Makefile
    could not be followed at all.'''
    out = []
    try:
        jobs, set_errors, set_targets = discover_matrix_jobs(
            makefile_text, workflows, entry_runner_text)
        exclude_re = parse_runner_exclusions(functional_runner_text)
    except LookupError as exc:
        out.append('ERROR following the matrix selectors: %s' % exc)
        out.append('A matrix leg reaches the Makefile through MATRIX_SET in '
                   'tools/ci/run-matrix-entry.sh; that chain no longer parses, '
                   'so update tools/ci/check-test-partition.py to match it.')
        return 2, out

    exclude = re.compile(exclude_re)
    baseline = [tid for tid in test_ids if not exclude.search(tid)]

    out.append('=== Distro-matrix partition check ===')
    out.append('baseline (what an unselected matrix entry runs): %d of %d test ids'
               % (len(baseline), len(test_ids)))
    out.append('  excluded by the functional runner: %s' % exclude_re)
    out.append('matrix legs discovered:')
    for job in jobs:
        n = sum(1 for tid in baseline if job.selector.selects(tid)) if job.selector else len(baseline)
        distros = 'no distro axis' if job.distros is None else '%d distros' % len(job.distros)
        out.append('  - %-34s set=%-8s %5d tests   %s   [%s]'
                   % (job.label, job.matrix_set, n, distros, job.describe_target()))

    rc = 0

    if set_errors:
        out.append('')
        out.append('FAIL: a matrix leg asks for a selection that does not exist:')
        for err in set_errors:
            out.append('  %s' % err)
        rc = 1

    # A leg of every selecting set must actually exist in a workflow. If
    # one stops being invoked the assertions below would still pass --
    # against a half of the split that nothing runs any more, which is
    # exactly the silent loss this guard exists to make loud.
    exercised = {job.matrix_set for job in jobs}
    unexercised = sorted(name for name, target in set_targets.items()
                         if target and name not in exercised)
    if unexercised:
        out.append('')
        out.append('FAIL: no workflow job runs the matrix with MATRIX_SET=%s, so that '
                   'half of the split is defined but never executed:' % ', '.join(unexercised))
        for name in unexercised:
            out.append('  %s -> %s (Makefile target exists; no caller does)'
                       % (name, set_targets[name]))
        rc = 1

    # The set that passes no selector is checked separately, because the
    # assertion above deliberately skips it: it contributes no coverage,
    # so every arithmetic check here would still pass with no leg running
    # it. It is nonetheless the only run that measures a duration for
    # every test, and so the only place tests/stestr-timing.txt can be
    # derived from. Losing the leg would stop that refresh with nothing
    # going red, which is the same shape of silent loss as a dropped
    # test.
    measuring = sorted(name for name, target in set_targets.items() if not target)
    if measuring and not any(job.matrix_set in measuring for job in jobs):
        out.append('')
        out.append('FAIL: no workflow job runs the matrix with MATRIX_SET=%s, the '
                   'selector-free set that measures every test:' % ', '.join(measuring))
        out.append('  tests/stestr-timing.txt can only be derived from a run that '
                   'executes the whole suite in one stestr repository, so without such '
                   'a leg the committed timings stop being refreshed and nothing says so.')
        out.append('  Restore the measurement job, or delete the set from '
                   'tools/ci/run-matrix-entry.sh if the refresh is genuinely gone.')
        rc = 1

    selecting = [job for job in jobs if job.selector]
    if selecting:
        claims = {tid: [job.matrix_set for job in selecting if job.selector.selects(tid)]
                  for tid in baseline}

        dropped = [tid for tid in baseline if not claims[tid]]
        if dropped:
            out.append('')
            out.append('FAIL: %d test(s) ran in the distro matrix before the split and are '
                       'now claimed by NO half of it:' % len(dropped))
            out.extend(_lines_by_module(dropped))
            out.append('')
            out.append('This is a silent loss of the merge gate: nothing fails, the matrix '
                       'just runs less. Fix the selector in the Makefile target that should '
                       'claim them.')
            rc = 1

        both = sorted(tid for tid in baseline if len(claims[tid]) > 1)
        if both:
            out.append('')
            out.append('FAIL: %d test(s) are claimed by more than one half of the split '
                       '(%s):' % (len(both), ' and '.join(sorted(set(
                           m for tid in both for m in claims[tid])))))
            out.extend(_lines_by_module(both))
            out.append('')
            out.append('The halves must be complements. An overlap means the merge gate is '
                       'still paying for a test the nightly says it took off the gate, so '
                       'the saving is not what it looks like.')
            rc = 1

        outside = sorted(tid for tid in test_ids
                         if exclude.search(tid)
                         and any(job.selector.selects(tid) for job in selecting))
        if outside:
            out.append('')
            out.append('FAIL: %d test(s) are selected by a half of the split but excluded '
                       'from every matrix run by the functional runner:' % len(outside))
            out.extend(_lines_by_module(outside))
            out.append('')
            out.append('A selector that reaches past %s claims tests no matrix entry can '
                       'run, so the split no longer describes what CI does.' % exclude_re)
            rc = 1

    # The distro lists are copies rather than a shared file because their
    # entries carry comments and audit markers a shared file could not,
    # so comparing them here is what keeps them in step. A distro present
    # in one and not the other loses a whole distro's coverage with no
    # symptom.
    #
    # A leg whose axis is present but reads as no distros at all is a
    # failure rather than a leg to leave out of the comparison.
    # parse_distro_matrix is a text scan, so an unreadable list and a
    # deliberately emptied one look identical to it -- and dropping such
    # a leg would leave one list with nothing to compare against, which
    # is this check going quiet while still reporting PASS.
    empty_axis = [job for job in jobs if job.distros is not None and not job.distros]
    if empty_axis:
        out.append('')
        out.append('FAIL: %d matrix leg(s) have a distro axis that reads as no distros:'
                   % len(empty_axis))
        for job in empty_axis:
            out.append('  %s (set=%s)' % (job.label, job.matrix_set))
        out.append('')
        out.append('Either the axis really is empty -- in which case that leg runs nothing '
                   '-- or its entries no longer parse, and the two cannot be told apart '
                   'from here. If the entries were reformatted, teach parse_distro_matrix '
                   'in tools/ci/check-test-partition.py the new shape; an unparsed list '
                   'silently removes the leg from the comparison below.')
        rc = 1

    with_distros = [job for job in jobs if job.distros]
    if len(with_distros) < 2 and len(selecting) > 1:
        # More than one leg selects tests, so there is more than one list
        # that has to stay in step, and fewer than two of them could be
        # read. Nothing below would compare anything, and the run would
        # still be green.
        out.append('')
        out.append('FAIL: %d matrix legs select tests but only %d distro list could be '
                   'read, so nothing checked the lists against each other:'
                   % (len(selecting), len(with_distros)))
        for job in jobs:
            out.append('  %-34s set=%-8s %s'
                       % (job.label, job.matrix_set,
                          'no distro axis' if job.distros is None
                          else '%d distros' % len(job.distros)))
        out.append('')
        out.append('The lists are deliberately copies of each other, so this comparison is '
                   'the only thing that keeps them in step. With one list there is nothing '
                   'to compare, and a distro dropped from the other side would not be '
                   'reported by anything.')
        rc = 1
    elif len(with_distros) > 1:
        reference = with_distros[0]
        ref_set = set(reference.distros)
        for job in with_distros[1:]:
            job_set = set(job.distros)
            if job_set == ref_set:
                continue
            out.append('')
            out.append('FAIL: the distro lists of %s and %s disagree:'
                       % (reference.label, job.label))
            for entry in sorted(ref_set - job_set):
                out.append('  only in %s: %s (%s, %s)'
                           % (reference.label, entry[0], entry[1], entry[2]))
            for entry in sorted(job_set - ref_set):
                out.append('  only in %s: %s (%s, %s)'
                           % (job.label, entry[0], entry[1], entry[2]))
            out.append('')
            out.append('The two lists are deliberately copies, so nothing but this check '
                       'keeps them in step. A distro dropped from one side stops being '
                       'tested there and nothing goes red to say so.')
            rc = 1

    if rc == 0:
        out.append('')
        out.append('PASS: the matrix halves cover the baseline exactly and do not overlap.')
        if len(with_distros) > 1:
            out.append('      %d distro lists agree on %d distros.'
                       % (len(with_distros), len(with_distros[0].distros)))
        else:
            # Reachable only when at most one leg selects tests, because
            # more than one selecting leg with fewer than two readable
            # lists is a failure above. It still says so rather than
            # staying silent, so a run can never look like a comparison
            # that happened.
            out.append('      only %d distro list found; nothing to compare it with '
                       '(at most one matrix leg selects tests).' % len(with_distros))
    return rc, out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--makefile', required=True, help='path to the Makefile')
    ap.add_argument('--workflow', required=True, action='append', metavar='PATH',
                    help='path to a workflow file; repeat for each one that runs '
                         'tests (functional-tests.yml, nightly-matrix.yml)')
    ap.add_argument('--entry-runner',
                    default=os.path.join(_REPO_ROOT, 'tools', 'ci', 'run-matrix-entry.sh'),
                    help='path to the matrix entry runner, which maps MATRIX_SET to a '
                         'Makefile target')
    ap.add_argument('--functional-runner',
                    default=os.path.join(_REPO_ROOT, 'tools', 'test-package-functional.sh'),
                    help='path to the functional runner, which defines what every matrix '
                         'run excludes')
    ap.add_argument('--test-ids', default='-',
                    help='file with stestr ids (one per line); default stdin')
    args = ap.parse_args(argv)

    with open(args.makefile, encoding='utf-8') as f:
        makefile_text = f.read()
    workflows = []
    for path in args.workflow:
        with open(path, encoding='utf-8') as f:
            workflows.append((os.path.basename(path), f.read()))
    workflow_text = '\n'.join(text for _label, text in workflows)
    with open(args.entry_runner, encoding='utf-8') as f:
        entry_runner_text = f.read()
    with open(args.functional_runner, encoding='utf-8') as f:
        functional_runner_text = f.read()

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

    rc = 0
    if orphans:
        print()
        print('FAIL: %d test(s) are run by NO pull-request job '
              '(silent coverage loss):' % len(orphans))
        for line in _lines_by_module(orphans):
            print(line)
        print()
        print('Fix: add these to a CI job (a Makefile test-container-* '
              'selector) or, if deliberately excluded, add a justified '
              'entry to INTENTIONAL_EXCLUSIONS in this script.')
        rc = 1
    else:
        print()
        print('PASS: every discovered test is claimed by at least one '
              'pull-request job.')

    # The merge-queue matrix and the nightly are a second partition over
    # the same suite and are checked whatever the pull-request verdict
    # was, so one run reports every gap rather than the first one.
    print()
    matrix_rc, lines = check_matrix_partition(makefile_text, workflows, entry_runner_text,
                                             functional_runner_text, test_ids)
    for line in lines:
        print(line)
    return max(rc, matrix_rc)


if __name__ == '__main__':
    sys.exit(main())
