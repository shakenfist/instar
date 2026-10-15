#!/usr/bin/env python3
'''Unit tests for the CI test-partition guard.

Runs with plain `python3 -m unittest` (stdlib only, no venv). These
tests prove the guard is not a tautology: it must PASS a complete
partition and FAIL when a test is orphaned, including the specific
drift scenario it exists to catch (a catch-all job refactored into an
include-list that drops a module).

The same standard applies to the merge-queue / nightly split of the
distro matrix: every assertion about it has a test that breaks the
fixtures in one way and demands a non-zero exit naming the specific
thing that broke. An assertion with only a passing test is worth
nothing here, because the failure these guard against -- a test, a
module or a distro quietly leaving the merge gate -- has no symptom of
its own. Nothing goes red; CI just gets faster.

This file lives under tools/ci/ (outside tests/), so stestr -- whose
test_path is the tests/ directory -- never discovers it, and it is not
itself part of the partition it checks.
'''

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'check_test_partition', os.path.join(_HERE, 'check-test-partition.py'))
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


# A Makefile fragment mirroring the real test-container-* targets.
MAKEFILE = '''\
test-container-core: instar-devcontainer instar
\tdocker run --rm "$(INSTAR_IMAGE)" bash -c '\\
\t\tcd tests && \\
\t\tstestr run \\
\t\t\t--exclude-regex "(test_convert\\.|test_compare\\.|test_info_malicious)" \\
\t\t\t--concurrency 4 \\
\t'

test-container-convert-qcow2: instar-devcontainer instar
\tdocker run --rm "$(INSTAR_IMAGE)" bash -c '\\
\t\tcd tests && \\
\t\tstestr run \\
\t\t\t--exclude-regex "Vhd" \\
\t\t\t--concurrency 4 \\
\t\t\t"(test_convert\\.|test_compare\\.)" \\
\t'

test-container-convert-vhd: instar-devcontainer instar
\tdocker run --rm "$(INSTAR_IMAGE)" bash -c '\\
\t\tcd tests && \\
\t\tstestr run \\
\t\t\t--concurrency 4 \\
\t\t\t"test_convert\\.TestConvert.*Vhd" \\
\t'

test-container-matrix-queue: instar-devcontainer instar
\tdocker run --rm "$(INSTAR_IMAGE)" bash -c '\\
\t\tcd tests && \\
\t\tstestr run \\
\t\t\t--exclude-regex "(test_info_malicious|test_bench)" \\
\t\t\t--concurrency 4 \\
\t\t\t"^(?!(?:%s)$$)" \\
\t'

test-container-matrix-nightly: instar-devcontainer instar
\tdocker run --rm "$(INSTAR_IMAGE)" bash -c '\\
\t\tcd tests && \\
\t\tstestr run \\
\t\t\t--concurrency 4 \\
\t\t\t"^(?:%s)$$" \\
\t'

some-other-target:
\techo unrelated
'''

# The two tests the fixture moves off the merge gate. Two rather than the
# real six: the arithmetic the guard does is the same, and a shorter list
# keeps the mutations in the failure tests readable.
MOVED = ('test_convert\\.TestConvertVhdToRaw\\.test_convert_virtualpc_vhd'
         '|test_convert\\.TestConvertVhdCompare\\.test_compare_virtualpc_vhd_vs_raw')

MAKEFILE = MAKEFILE % (MOVED, MOVED)

# A distro list in the shape of the real ones, comments and all -- those
# comments are the reason the two lists are copies rather than a shared
# file, and so the reason the guard compares them.
DISTROS = '''\
    strategy:
      matrix:
        distro:
          # Debian 12 is a supported target, not a build platform.
          - name: 'Debian 12'
            # audit-ok: eol-distro -- supported target, see the note above
            image: 'debian:12'
            pkg_kind: 'deb'
            allow_failure: false
          - name: 'Ubuntu 22.04'
            image: 'ubuntu:22.04'
            pkg_kind: 'deb'
            allow_failure: false
          - name: 'Rocky 10'
            image: 'rockylinux/rockylinux:10'
            pkg_kind: 'rpm'
            allow_failure: false
'''

WORKFLOW = '''\
jobs:
  integration-core:
    steps:
      - run: make test-container-core
  integration-convert-qcow2:
    steps:
      - run: make test-container-convert-qcow2
  integration-convert-vhd:
    steps:
      - run: make test-container-convert-vhd
  oslo-crossval-master:
    steps:
      - run: |
          /build/test-venv/bin/stestr run test_oslo_crossval
  # A prose comment of the kind the real workflow carries, mentioning a
  # committed timing file loaded before "stestr run", so that the
  # comment-stripping in discovery is exercised rather than assumed.
  package-matrix:
%s    steps:
      # No MATRIX_SET here: the merge queue takes the entry runner's
      # own default, which is the half of the split that gates.
      - name: Run the suite
        env:
          PACKAGE_DIR: packages
        run: tools/ci/run-matrix-entry.sh "Debian 13" "debian:13" "deb"
''' % DISTROS

NIGHTLY_WORKFLOW = '''\
jobs:
  package-build:
    steps:
      - run: make package
  nightly-legs:
%s    steps:
      - name: Run the nightly selection
        env:
          MATRIX_SET: nightly
        run: tools/ci/run-matrix-entry.sh "Debian 13" "debian:13" "deb"
  measure:
    steps:
      # MATRIX_SET: queue would be wrong here, and a comment saying so
      # must not be read as the setting.
      - name: Run the whole suite and measure it
        env:
          MATRIX_SET: all
        run: tools/ci/run-matrix-entry.sh "Debian 13 (full suite)" "debian:13" "deb"
''' % DISTROS

# The MATRIX_SET indirection, in the shape run-matrix-entry.sh writes it.
ENTRY_RUNNER = '''\
#!/bin/bash
case "${MATRIX_SET:-queue}" in
    queue) SELECT_TARGET=test-container-matrix-queue ;;
    nightly) SELECT_TARGET=test-container-matrix-nightly ;;
    all) SELECT_TARGET='' ;;
    *)
        echo "Error: MATRIX_SET must be 'queue', 'nightly' or 'all'." >&2
        exit 2
        ;;
esac
'''

FUNCTIONAL_RUNNER = '''\
#!/bin/bash
EXCLUDE_RE='(test_info_malicious|test_bench)'
SELECT_RE=''
'''

# Covers the fixture partition end to end: two tests on the nightly half,
# one same-class sibling and three unrelated modules on the queue half,
# and two ids the functional runner excludes from every matrix run.
MATRIX_IDS = [
    'test_info_safe.TestInfo.test_a',
    'test_dd.TestDd.test_window',
    'test_convert.TestConvertQcow.test_c',
    'test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd',
    'test_convert.TestConvertVhdCompare.test_compare_virtualpc_vhd_vs_raw',
    'test_convert.TestConvertVhdToRaw.test_convert_vhd_fixed',
    'test_compare.TestCompare.test_e',
    'test_info_malicious.TestMal.test_bomb',
    'test_bench.TestBench.test_speed',
]


def run_guard(test_ids, makefile=None, workflow=None, nightly=None,
              entry_runner=None, functional_runner=None, with_nightly=True):
    '''Invoke the guard's main() with synthetic inputs; return (rc, out).

    Every input is overridable so a test can break exactly one link in
    the workflow -> MATRIX_SET -> Makefile chain and prove the guard
    notices. `with_nightly=False` drops the nightly workflow from the
    invocation altogether.'''
    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for name, text in (('Makefile', makefile if makefile is not None else MAKEFILE),
                           ('functional-tests.yml', workflow if workflow is not None else WORKFLOW),
                           ('nightly-matrix.yml', nightly if nightly is not None else NIGHTLY_WORKFLOW),
                           ('run-matrix-entry.sh',
                            entry_runner if entry_runner is not None else ENTRY_RUNNER),
                           ('test-package-functional.sh',
                            functional_runner if functional_runner is not None else FUNCTIONAL_RUNNER)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], 'w') as f:
                f.write(text)
        ids = os.path.join(d, 'ids.txt')
        with open(ids, 'w') as f:
            f.write('\n'.join(test_ids) + '\n')
        argv = ['--makefile', paths['Makefile'], '--workflow', paths['functional-tests.yml']]
        if with_nightly:
            argv += ['--workflow', paths['nightly-matrix.yml']]
        argv += ['--entry-runner', paths['run-matrix-entry.sh'],
                 '--functional-runner', paths['test-package-functional.sh'],
                 '--test-ids', ids]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = guard.main(argv)
        return rc, buf.getvalue()


class TestMakefileParsing(unittest.TestCase):
    def test_core_is_exclude_only(self):
        inc, exc = guard.parse_makefile_target(MAKEFILE, 'test-container-core')
        self.assertEqual(inc, [])
        self.assertEqual(exc, ['(test_convert\\.|test_compare\\.|test_info_malicious)'])

    def test_qcow2_has_include_and_exclude(self):
        inc, exc = guard.parse_makefile_target(MAKEFILE, 'test-container-convert-qcow2')
        self.assertEqual(inc, ['(test_convert\\.|test_compare\\.)'])
        self.assertEqual(exc, ['Vhd'])

    def test_vhd_is_include_only(self):
        inc, exc = guard.parse_makefile_target(MAKEFILE, 'test-container-convert-vhd')
        self.assertEqual(inc, ['test_convert\\.TestConvert.*Vhd'])
        self.assertEqual(exc, [])

    def test_missing_target_raises(self):
        with self.assertRaises(LookupError):
            guard.parse_makefile_target(MAKEFILE, 'test-container-nope')


class TestJobDiscovery(unittest.TestCase):
    def test_discovers_make_targets_and_inline(self):
        jobs = guard.discover_jobs(MAKEFILE, WORKFLOW)
        names = {j.name for j in jobs}
        self.assertIn('test-container-core', names)
        self.assertIn('test-container-convert-qcow2', names)
        self.assertIn('test-container-convert-vhd', names)
        # The oslo inline stestr run is discovered too.
        self.assertTrue(any('oslo' in n for n in names))


class TestPartition(unittest.TestCase):
    def test_complete_partition_passes(self):
        ids = [
            'test_info_safe.TestInfo.test_a',          # -> core
            'test_create.TestCreate.test_b',           # -> core
            'test_convert.TestConvertQcow.test_c',     # -> qcow2
            'test_convert.TestConvertVhd.test_d',      # -> vhd
            'test_compare.TestCompare.test_e',         # -> qcow2
            'test_oslo_crossval.TestOslo.test_f',      # -> core + oslo (overlap)
        ]
        rc, out = run_guard(ids)
        self.assertEqual(rc, 0, out)
        self.assertIn('PASS', out)

    def test_orphan_module_fails(self):
        # A brand-new module that no selector mentions. The catch-all
        # core would normally grab it -- but see the refactor test below
        # for when it cannot. Here we simulate a module that core's
        # exclude wrongly swallows is not possible; instead test a module
        # excluded by every job by construction.
        ids = [
            'test_info_safe.TestInfo.test_a',
            # This one matches the core exclude (looks convert-ish) but is
            # NOT a real convert/compare test, so qcow2/vhd ignore it too:
            'test_convert.TestVhdFooter.test_parse',   # has 'Vhd' but not
            # 'TestConvert.*Vhd' -> excluded by qcow2 (Vhd) AND not matched
            # by vhd selector -> ORPHAN. This is the real convert-split gap.
        ]
        rc, out = run_guard(ids)
        self.assertEqual(rc, 1, out)
        self.assertIn('FAIL', out)
        self.assertIn('test_convert.TestVhdFooter.test_parse', out)

    def test_allowlisted_malicious_is_not_orphan(self):
        ids = [
            'test_info_safe.TestInfo.test_a',
            'test_info_malicious.TestMal.test_bomb',   # excluded everywhere
        ]
        rc, out = run_guard(ids)
        self.assertEqual(rc, 0, out)
        self.assertIn('allowlisted', out)

    def test_catchall_refactored_to_include_drops_module(self):
        # The key drift scenario: someone turns core's exclude-list into
        # an include-list that forgets a module (here: test_dd). The guard
        # must catch the dropped module.
        broken_makefile = MAKEFILE.replace(
            '--exclude-regex "(test_convert\\.|test_compare\\.|test_info_malicious)" \\\n',
            '"(test_info_safe\\.|test_create\\.)" \\\n')
        ids = [
            'test_info_safe.TestInfo.test_a',          # still included
            'test_dd.TestDd.test_window',              # DROPPED by refactor
        ]
        rc, out = run_guard(ids, makefile=broken_makefile)
        self.assertEqual(rc, 1, out)
        self.assertIn('test_dd.TestDd.test_window', out)

    def test_empty_input_is_error(self):
        rc, out = run_guard([])
        # read_test_ids filters everything -> rc 2 (no ids).
        self.assertEqual(rc, 2)


class TestMatrixDiscovery(unittest.TestCase):
    '''The workflow -> MATRIX_SET -> Makefile indirection.'''

    def test_set_mapping_and_default_come_from_the_entry_runner(self):
        default, targets = guard.parse_matrix_sets(ENTRY_RUNNER)
        self.assertEqual(default, 'queue')
        self.assertEqual(targets, {'queue': 'test-container-matrix-queue',
                                   'nightly': 'test-container-matrix-nightly',
                                   'all': ''})

    def test_legs_resolve_through_both_workflow_files(self):
        jobs, errors, _targets = guard.discover_matrix_jobs(
            MAKEFILE, [('functional-tests.yml', WORKFLOW),
                       ('nightly-matrix.yml', NIGHTLY_WORKFLOW)], ENTRY_RUNNER)
        self.assertEqual(errors, [])
        resolved = {job.label: (job.matrix_set, job.target) for job in jobs}
        self.assertEqual(resolved, {
            # No MATRIX_SET in the queue's job: the default is followed.
            'functional-tests.yml:package-matrix': ('queue', 'test-container-matrix-queue'),
            'nightly-matrix.yml:nightly-legs': ('nightly', 'test-container-matrix-nightly'),
            # The measurement leg selects nothing, so it has no target.
            'nightly-matrix.yml:measure': ('all', ''),
        })

    def test_dollar_doubling_is_undone(self):
        # A recipe writes "$$" for a literal "$". If the guard kept the
        # doubling it would be checking a regex no run ever uses.
        inc, _exc = guard.parse_makefile_target(MAKEFILE, 'test-container-matrix-nightly')
        self.assertTrue(inc[0].endswith(')$'), inc[0])
        self.assertNotIn('$$', inc[0])

    def test_distro_axis_is_read_with_its_comments(self):
        jobs, _errors, _targets = guard.discover_matrix_jobs(
            MAKEFILE, [('nightly-matrix.yml', NIGHTLY_WORKFLOW)], ENTRY_RUNNER)
        legs = {job.label: job.distros for job in jobs}
        self.assertEqual(legs['nightly-matrix.yml:nightly-legs'], [
            ('Debian 12', 'debian:12', 'deb'),
            ('Ubuntu 22.04', 'ubuntu:22.04', 'deb'),
            ('Rocky 10', 'rockylinux/rockylinux:10', 'rpm'),
        ])
        # The measurement leg runs one distro inline and has no axis at
        # all, which must read as "nothing to compare" and not as "no
        # distros", or every run would report a mismatch.
        self.assertIsNone(legs['nightly-matrix.yml:measure'])

    def test_prose_about_stestr_run_is_not_a_job(self):
        # The workflow's own comments mention `stestr run` while
        # explaining the timing file. One of them was being discovered as
        # a job whose selector was the bare word `so`, which matches much
        # of the suite and would mask a real orphan.
        jobs = guard.discover_jobs(MAKEFILE, WORKFLOW)
        self.assertEqual([j.name for j in jobs if j.include_src == ['so']], [])
        self.assertTrue(any('oslo' in j.name for j in jobs))


class TestMatrixPartition(unittest.TestCase):
    '''The merge-queue / nightly split. Every assertion here has a test
    that breaks the fixtures and demands the guard say what broke.'''

    def test_complete_split_passes(self):
        rc, out = run_guard(MATRIX_IDS)
        self.assertEqual(rc, 0, out)
        self.assertIn('PASS: the matrix halves cover the baseline exactly', out)
        self.assertIn('agree on 3 distros', out)

    def test_baseline_excludes_what_the_functional_runner_excludes(self):
        rc, out = run_guard(MATRIX_IDS)
        self.assertEqual(rc, 0, out)
        # Nine ids, less the malicious and benchmark ones no matrix entry
        # runs: the two halves are compared against seven, not nine.
        self.assertIn('baseline (what an unselected matrix entry runs): 7 of 9 test ids', out)

    def test_test_claimed_by_neither_half_fails(self):
        # The realistic mistake: a seventh test is taken off the gate and
        # nobody adds it to the nightly. Nothing goes red without this.
        dropped = 'test_convert\\.TestConvertVhdToRaw\\.test_convert_vhd_fixed'
        broken = MAKEFILE.replace('"^(?!(?:%s)$$)"' % MOVED,
                                  '"^(?!(?:%s|%s)$$)"' % (MOVED, dropped))
        self.assertNotEqual(broken, MAKEFILE)
        rc, out = run_guard(MATRIX_IDS, makefile=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('claimed by NO half of it', out)
        self.assertIn('test_convert.TestConvertVhdToRaw.test_convert_vhd_fixed', out)

    def test_matrix_selector_dropping_a_whole_module_fails(self):
        # The same gap at module scale: a module added to the queue's
        # exclude-regex, which is how a whole module leaves the gate.
        broken = MAKEFILE.replace('--exclude-regex "(test_info_malicious|test_bench)"',
                                  '--exclude-regex "(test_info_malicious|test_bench|test_dd\\.)"')
        self.assertNotEqual(broken, MAKEFILE)
        rc, out = run_guard(MATRIX_IDS, makefile=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('claimed by NO half of it', out)
        self.assertIn('test_dd  (1)', out)
        self.assertIn('test_dd.TestDd.test_window', out)

    def test_nightly_overlapping_the_queue_fails(self):
        # An overlap is silent in the other direction: the nightly says it
        # took a test off the gate while the gate still runs it.
        broken = MAKEFILE.replace('"^(?:%s)$$"' % MOVED,
                                  '"^(?:%s|test_dd\\.TestDd\\.test_window)$$"' % MOVED)
        self.assertNotEqual(broken, MAKEFILE)
        rc, out = run_guard(MATRIX_IDS, makefile=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('claimed by more than one half of the split', out)
        self.assertIn('nightly and queue', out)
        self.assertIn('test_dd.TestDd.test_window', out)

    def test_selector_reaching_past_the_runner_exclusions_fails(self):
        # A half that claims a test no matrix entry can run: the split
        # stops describing what CI does, and the arithmetic above it
        # stops meaning anything.
        broken = MAKEFILE.replace('"^(?:%s)$$"' % MOVED,
                                  '"^(?:%s|test_info_malicious\\.TestMal\\.test_bomb)$$"' % MOVED)
        self.assertNotEqual(broken, MAKEFILE)
        rc, out = run_guard(MATRIX_IDS, makefile=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('excluded from every matrix run by the functional runner', out)
        self.assertIn('test_info_malicious.TestMal.test_bomb', out)

    def test_distro_dropped_from_one_list_fails(self):
        # The failure mode with no symptom at all: the nightly quietly
        # stops covering a distro the merge queue covers.
        broken = NIGHTLY_WORKFLOW.replace('''\
          - name: 'Rocky 10'
            image: 'rockylinux/rockylinux:10'
            pkg_kind: 'rpm'
            allow_failure: false
''', '', 1)
        self.assertNotEqual(broken, NIGHTLY_WORKFLOW)
        rc, out = run_guard(MATRIX_IDS, nightly=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('distro lists of', out)
        self.assertIn('only in functional-tests.yml:package-matrix: Rocky 10', out)

    def test_distro_image_drifting_between_lists_fails(self):
        # Same list length, one image changed: the nightly would test a
        # distro the queue does not, and report it under the other's name.
        broken = NIGHTLY_WORKFLOW.replace("image: 'ubuntu:22.04'", "image: 'ubuntu:22.10'")
        self.assertNotEqual(broken, NIGHTLY_WORKFLOW)
        rc, out = run_guard(MATRIX_IDS, nightly=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('ubuntu:22.04', out)
        self.assertIn('ubuntu:22.10', out)

    def test_half_defined_but_never_run_fails(self):
        # Dropping the nightly workflow from the invocation, or renaming
        # the job that runs it, must fail rather than leave the
        # assertions above comparing the queue half against itself.
        rc, out = run_guard(MATRIX_IDS, with_nightly=False)
        self.assertEqual(rc, 1, out)
        self.assertIn('no workflow job runs the matrix with MATRIX_SET=nightly', out)

    def test_unknown_matrix_set_fails(self):
        # A typo'd MATRIX_SET makes run-matrix-entry.sh exit 2 at
        # runtime; the guard says so at pull-request time instead.
        broken = NIGHTLY_WORKFLOW.replace('MATRIX_SET: nightly', 'MATRIX_SET: nighlty')
        self.assertNotEqual(broken, NIGHTLY_WORKFLOW)
        rc, out = run_guard(MATRIX_IDS, nightly=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('MATRIX_SET=nighlty', out)
        self.assertIn('does not implement', out)

    def test_unfollowable_indirection_is_a_parse_error(self):
        # The chain must break loudly. A renamed Makefile target, or a
        # rewritten case statement, is rc 2 and a message pointing at the
        # chain -- never a quietly smaller selection.
        broken = ENTRY_RUNNER.replace('test-container-matrix-queue',
                                      'test-container-matrix-gate')
        rc, out = run_guard(MATRIX_IDS, entry_runner=broken)
        self.assertEqual(rc, 2, out)
        self.assertIn('ERROR following the matrix selectors', out)
        self.assertIn('test-container-matrix-gate', out)

    def test_missing_runner_exclusions_is_a_parse_error(self):
        broken = FUNCTIONAL_RUNNER.replace("EXCLUDE_RE='(test_info_malicious|test_bench)'",
                                           'EXCLUDE_PATTERNS=()')
        rc, out = run_guard(MATRIX_IDS, functional_runner=broken)
        self.assertEqual(rc, 2, out)
        self.assertIn('no EXCLUDE_RE assignment found', out)

    def test_pull_request_and_matrix_verdicts_are_both_reported(self):
        # One run reports every gap. A pull-request orphan must not stop
        # the matrix check from running, or fixing one failure would
        # reveal the next only on the following push.
        ids = MATRIX_IDS + ['test_convert.TestVhdFooter.test_parse']
        broken = MAKEFILE.replace('--exclude-regex "(test_info_malicious|test_bench)"',
                                  '--exclude-regex "(test_info_malicious|test_bench|test_dd\\.)"')
        rc, out = run_guard(ids, makefile=broken)
        self.assertEqual(rc, 1, out)
        self.assertIn('are run by NO pull-request job', out)
        self.assertIn('claimed by NO half of it', out)


if __name__ == '__main__':
    unittest.main()
