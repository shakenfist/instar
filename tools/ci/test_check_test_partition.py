#!/usr/bin/env python3
'''Unit tests for the CI test-partition guard.

Runs with plain `python3 -m unittest` (stdlib only, no venv). These
tests prove the guard is not a tautology: it must PASS a complete
partition and FAIL when a test is orphaned, including the specific
drift scenario it exists to catch (a catch-all job refactored into an
include-list that drops a module).

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

some-other-target:
\techo unrelated
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
'''


def run_guard(test_ids):
    '''Invoke the guard's main() with synthetic inputs; return (rc, out).'''
    with tempfile.TemporaryDirectory() as d:
        mk = os.path.join(d, 'Makefile')
        wf = os.path.join(d, 'functional-tests.yml')
        ids = os.path.join(d, 'ids.txt')
        with open(mk, 'w') as f:
            f.write(MAKEFILE)
        with open(wf, 'w') as f:
            f.write(WORKFLOW)
        with open(ids, 'w') as f:
            f.write('\n'.join(test_ids) + '\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = guard.main(['--makefile', mk, '--workflow', wf, '--test-ids', ids])
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
        with tempfile.TemporaryDirectory() as d:
            mk = os.path.join(d, 'Makefile')
            wf = os.path.join(d, 'functional-tests.yml')
            with open(mk, 'w') as f:
                f.write(broken_makefile)
            with open(wf, 'w') as f:
                f.write(WORKFLOW)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = guard.main(['--makefile', mk, '--workflow', wf,
                                 '--test-ids', _write_ids(d, ids)])
            out = buf.getvalue()
        self.assertEqual(rc, 1, out)
        self.assertIn('test_dd.TestDd.test_window', out)

    def test_empty_input_is_error(self):
        rc, out = run_guard([])
        # read_test_ids filters everything -> rc 2 (no ids).
        self.assertEqual(rc, 2)


def _write_ids(d, ids):
    p = os.path.join(d, 'ids.txt')
    with open(p, 'w') as f:
        f.write('\n'.join(ids) + '\n')
    return p


if __name__ == '__main__':
    unittest.main()
