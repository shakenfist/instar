#!/usr/bin/env python3
"""Tests for tools/ci/compare-stestr-timing.py.

The script decides, unattended, whether a nightly measurement opens a
pull request. Both failure directions are silent: too twitchy and it
files a pull request every morning until someone turns the nightly off,
too deaf and the committed scheduling hint quietly rots. So every rule is
pinned here, and so is the property the whole design rests on -- that a
uniformly slower or faster run is NOT a change, because stestr's bin
packing is scale-free.

Discovered by the "Test the fuzz corpus seed builders" step of the
ci-tooling job, which runs "python3 -m unittest discover -s tools/ci -t
tools/ci" over this directory. Pure arithmetic: no stestr, no venv, no
testdata.
"""

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location('compare_stestr_timing',
                                               os.path.join(_HERE, 'compare-stestr-timing.py'))
compare_stestr_timing = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(compare_stestr_timing)


# A miniature of the real file's shape, which is what makes the
# thresholds meaningful: a handful of heavy conversion tests carrying
# most of the weight, and a long tail of sub-second cases. Measured on
# the committed tests/stestr-timing.txt, the 22 tests of 30s or more
# carry 74% of 4,960 seconds across 3,675 ids.
def _baseline():
    durations = {
        'test_convert.TestConvertVhdToQcow2Roundtrip.test_virtualpc_vhd_qcow2_roundtrip': 530.0,
        'test_convert.TestConvertVhdToQcow2Roundtrip.test_hyperv_vhd_qcow2_roundtrip': 520.0,
        'test_convert.TestConvertVhdToRaw.test_convert_hyperv_dynamic_vhd': 455.0,
        'test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd': 445.0,
        'test_convert.TestConvertVhdCompare.test_compare_hyperv_vhd_vs_raw': 200.0,
        'test_convert.TestConvertVhdCompare.test_compare_virtualpc_vhd_vs_raw': 200.0,
    }
    for index in range(1000):
        durations[f'test_info.TestInfo.test_case_{index:04d}'] = 0.5
    return durations


class TimingFileTestCase(unittest.TestCase):

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)

    def write(self, name, durations):
        path = os.path.join(self.work.name, name)
        with open(path, 'w') as fh:
            for test_id in sorted(durations):
                fh.write(f'{test_id}\t{durations[test_id]:.2f}\n')
        return path

    def verdict(self, old, new):
        """Run the script's main() over two duration dicts, return its exit code.

        The report goes to a buffer rather than to the test runner's
        output: these cases print a movers table each, and 17 of them
        would bury the ci-tooling job's log in Markdown.
        """
        old_path = self.write('old.txt', old)
        new_path = self.write('new.txt', new)
        self.report = io.StringIO()
        with contextlib.redirect_stdout(self.report):
            return compare_stestr_timing.main(['compare-stestr-timing.py', old_path, new_path])


class TestMateriality(TimingFileTestCase):

    def test_identical_files_are_immaterial(self):
        durations = _baseline()
        self.assertEqual(10, self.verdict(durations, dict(durations)))

    def test_uniform_slowdown_is_immaterial(self):
        """The property the whole script exists for.

        Every duration 1.4x larger -- a contended runner, a slower runner
        generation -- produces exactly the same stestr partition, so it
        must not open a pull request. A seconds-based comparison would
        report a 40% change here, which is why this is not a diff.
        """
        old = _baseline()
        new = {test_id: duration * 1.4 for test_id, duration in old.items()}
        self.assertEqual(10, self.verdict(old, new))

    def test_small_jitter_on_every_test_is_immaterial(self):
        """Alternating +/-8% jitter, the shape of a real re-measurement."""
        old = _baseline()
        new = {}
        for index, (test_id, duration) in enumerate(sorted(old.items())):
            new[test_id] = duration * (1.08 if index % 2 else 0.92)
        self.assertEqual(10, self.verdict(old, new))

    def test_one_heavy_test_halving_is_material(self):
        old = _baseline()
        new = dict(old)
        new['test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd'] = 222.0
        self.assertEqual(0, self.verdict(old, new))

    def test_a_new_heavy_test_is_material(self):
        """The case seeding exists to make visible.

        A newly added test of several minutes is exactly what round-robin
        hides until a leg mysteriously slows down, so the hint has to
        learn about it.
        """
        old = _baseline()
        new = dict(old)
        new['test_convert.TestConvertNew.test_enormous'] = 300.0
        self.assertEqual(0, self.verdict(old, new))

    def test_a_new_cheap_test_is_immaterial(self):
        old = _baseline()
        new = dict(old)
        new['test_info.TestInfo.test_one_more'] = 0.5
        self.assertEqual(10, self.verdict(old, new))

    def test_a_deleted_heavy_test_is_material(self):
        old = _baseline()
        new = dict(old)
        del new['test_convert.TestConvertVhdCompare.test_compare_hyperv_vhd_vs_raw']
        self.assertEqual(0, self.verdict(old, new))

    def test_broad_recomposition_is_material(self):
        """The aggregate rule on its own: no single test moves 2 points.

        The fixture is a flat suite rather than the heavy-tailed real
        one, and deliberately so. In the committed file six tests carry
        82% of the weight, so any recomposition large enough to reach the
        aggregate threshold also moves one of those six by more than two
        points -- which means that on the real distribution the aggregate
        rule is a safety net for a shape of change this suite does not
        currently have, and isolating it needs a flatter suite. Here 80
        of 200 equal tests trade their weight: a fifth of the suite
        relocates while every single test moves half a point.
        """
        old = {f'test_flat.TestFlat.test_case_{index:04d}': 10.0 for index in range(200)}
        new = dict(old)
        for index in range(40):
            new[f'test_flat.TestFlat.test_case_{index:04d}'] = 0.01
            new[f'test_flat.TestFlat.test_case_{index + 100:04d}'] = 20.0
        result = compare_stestr_timing.compare(old, new)
        biggest = max(abs(row[0]) for row in result['movers'])
        self.assertLess(biggest, compare_stestr_timing.SINGLE_TEST_SHARE_PP,
                        'fixture should not trip the single-test rule')
        self.assertGreaterEqual(result['weight_moved_pp'], compare_stestr_timing.TOTAL_VARIATION_PP)
        self.assertEqual(0, self.verdict(old, new))

    def test_missing_committed_file_is_material(self):
        new_path = self.write('new.txt', _baseline())
        missing = os.path.join(self.work.name, 'not-there.txt')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, compare_stestr_timing.main(['compare-stestr-timing.py', missing, new_path]))


class TestThresholdArithmetic(TimingFileTestCase):
    """The thresholds in share points, checked against their own definitions.

    These are the cases a tuning of either constant has to be reconciled
    with, which is why they are stated as "just under" and "just over"
    rather than as magic numbers.
    """

    def test_single_test_rule_boundary(self):
        # A suite of exactly 1000s, so one point of share is 10s and the
        # threshold is 20s of share -- held fixed by keeping the total
        # constant, with the moved weight absorbed by a filler test.
        old = {'heavy': 500.0, 'filler': 500.0}
        pp = compare_stestr_timing.SINGLE_TEST_SHARE_PP
        just_under = (pp - 0.2) * 10.0
        just_over = (pp + 0.2) * 10.0
        self.assertEqual(10, self.verdict(old, {'heavy': 500.0 - just_under, 'filler': 500.0 + just_under}))
        self.assertEqual(0, self.verdict(old, {'heavy': 500.0 - just_over, 'filler': 500.0 + just_over}))

    def test_weight_moved_is_half_the_absolute_share_change(self):
        """Weight moved is reported as the fraction that relocated, not twice it."""
        old = {'a': 50.0, 'b': 50.0}
        new = {'a': 60.0, 'b': 40.0}
        result = compare_stestr_timing.compare(old, new)
        self.assertAlmostEqual(10.0, result['weight_moved_pp'], places=6)


class TestMalformedInput(TimingFileTestCase):

    def test_missing_tab_is_an_error(self):
        path = os.path.join(self.work.name, 'bad.txt')
        with open(path, 'w') as fh:
            fh.write('test_info.TestInfo.test_a 1.00\n')
        good = self.write('good.txt', _baseline())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, compare_stestr_timing.main(['compare-stestr-timing.py', good, path]))

    def test_non_numeric_duration_is_an_error(self):
        path = os.path.join(self.work.name, 'bad.txt')
        with open(path, 'w') as fh:
            fh.write('test_info.TestInfo.test_a\tquick\n')
        good = self.write('good.txt', _baseline())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, compare_stestr_timing.main(['compare-stestr-timing.py', good, path]))

    def test_empty_measurement_is_an_error(self):
        """A run that measured nothing must not be published as a refresh."""
        path = os.path.join(self.work.name, 'empty.txt')
        open(path, 'w').close()
        good = self.write('good.txt', _baseline())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, compare_stestr_timing.main(['compare-stestr-timing.py', good, path]))

    def test_bad_usage_is_an_error(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, compare_stestr_timing.main(['compare-stestr-timing.py', 'only-one']))


class TestReport(TimingFileTestCase):

    def test_report_names_the_mover_and_the_rule(self):
        old = _baseline()
        new = dict(old)
        new['test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd'] = 222.0
        result = compare_stestr_timing.compare(old, new)
        report = compare_stestr_timing.format_report(result, 'committed.txt', 'measured.txt')
        self.assertIn('test_convert.TestConvertVhdToRaw.test_convert_virtualpc_vhd', report)
        self.assertIn('weight moved between tests', report)
        self.assertIn('Why this is material', report)

    def test_report_of_an_immaterial_change_says_so(self):
        durations = _baseline()
        result = compare_stestr_timing.compare(durations, dict(durations))
        report = compare_stestr_timing.format_report(result, 'committed.txt', 'measured.txt')
        self.assertIn('not moved enough', report)
        self.assertNotIn('Why this is material', report)


if __name__ == '__main__':
    unittest.main()
