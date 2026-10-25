#!/usr/bin/env python3
"""Unit tests for the differential fuzzer's issue filing.

Runs with plain `python3 -m unittest` (stdlib only, no venv), like the
other `test_*.py` files next to it, in the `ci-tooling` job.

On 2026-10-17 one 100-iteration run of `scripts/differential-fuzz.py`
filed 98 issues for a single kernel fault, one per iteration, because
nothing grouped or capped them (#787). These tests hold the two things
that stop that: a run files one issue per divergence shape, and no more
than its limit. `gh` is never run; the filer's issue and comment
callables are replaced with recorders.
"""

import os
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DF_PATH = os.path.join(_HERE, '..', '..', 'scripts', 'differential-fuzz.py')


def _load(path, name):
    """Execute a hyphenated script as a module, compiling from source.

    Compiled from the text every time rather than imported, for the
    reason test_extract_fuzz_corpus.py gives: the bytecode cache can
    serve a same-size edit made within the same second, which is what a
    mutation check of this file looks like.
    """
    module = types.ModuleType(name)
    module.__file__ = path
    with open(path, encoding='utf-8') as f:
        source = f.read()
    exec(compile(source, path, 'exec'), module.__dict__)
    return module


df = _load(_DF_PATH, 'differential_fuzz')
# The filer warns when it stops filing, which is right in a run and only
# noise in a test.
df.logger.disabled = True


def exit_code(operation, stderr):
    """An exit_code_divergence in the shape the fuzzer records one."""
    return {
        'type': 'exit_code_divergence',
        'operation': operation,
        'instar_rc': 1,
        'qemu_rc': 0,
        'context': {'instar_stderr': stderr, 'qemu_stderr': ''},
    }


class Recorder:
    """Stands in for gh: records issues filed and comments made."""

    def __init__(self, fail=False):
        self.issues = []
        self.comments = []
        self.fail = fail

    def file_issue(self, seed, iteration, attrs, div, workflow_url):
        if self.fail:
            return None
        self.issues.append((iteration, div))
        return f'https://example.invalid/issues/{len(self.issues)}'

    def comment(self, url, body):
        self.comments.append((url, body))


def filer(recorder, max_issues=5):
    return df.IssueFiler(1234, None, max_issues,
                         file_issue=recorder.file_issue, comment=recorder.comment)


class DivergenceKeyTestCase(unittest.TestCase):
    def test_paths_and_offsets_do_not_distinguish(self):
        a = exit_code('bitmap', 'Error: read failed at offset 1048576 in /tmp/instar-fuzz-ab12/img0.qcow2\n')
        b = exit_code('bitmap', 'Error: read failed at offset 2097152 in /tmp/instar-fuzz-cd34/img7.qcow2\n')
        self.assertEqual(df.divergence_key(a), df.divergence_key(b))

    def test_an_errno_does_distinguish(self):
        a = exit_code('info', 'Error: Error(22)\n')
        b = exit_code('info', 'Error: Error(5)\n')
        self.assertNotEqual(df.divergence_key(a), df.divergence_key(b))

    def test_operation_and_type_distinguish(self):
        a = exit_code('info', 'Error: Error(22)\n')
        b = exit_code('resize', 'Error: Error(22)\n')
        c = dict(a, type='info_output_divergence')
        self.assertEqual(3, len({df.divergence_key(a), df.divergence_key(b), df.divergence_key(c)}))

    def test_only_the_first_line_of_stderr_counts(self):
        a = exit_code('info', '\nError: Error(22)\ncaused by: something long and variable 1\n')
        b = exit_code('info', 'Error: Error(22)\ncaused by: something else entirely\n')
        self.assertEqual(df.divergence_key(a), df.divergence_key(b))

    def test_a_divergence_with_no_stderr_still_has_a_key(self):
        self.assertEqual(('snapshot_byte_divergence', '', ''),
                         df.divergence_key({'type': 'snapshot_byte_divergence'}))


class IssueFilerTestCase(unittest.TestCase):
    def test_one_fault_in_every_iteration_files_one_issue(self):
        # The #787 storm: every iteration of a 100-iteration run diverged
        # because the kernel refused the guest, on 98 of them.
        rec = Recorder()
        issues = filer(rec)
        for i in range(98):
            issues.divergence(i, {}, exit_code('bitmap', 'Error: Error(22)\n'))
        summary = issues.finish()

        self.assertEqual(1, len(rec.issues))
        self.assertEqual(0, rec.issues[0][0])
        # The repeats are noted on that issue, once.
        self.assertEqual(1, len(rec.comments))
        self.assertEqual('https://example.invalid/issues/1', rec.comments[0][0])
        self.assertIn('97 more iteration(s)', rec.comments[0][1])
        self.assertEqual({'issues_filed': 1, 'issues_failed': 0, 'issue_shapes_suppressed': 0,
                          'divergence_shapes': 1}, summary)

    def test_filing_stops_at_the_limit(self):
        rec = Recorder()
        issues = filer(rec, max_issues=3)
        for i, op in enumerate(['info', 'map', 'measure', 'resize', 'commit', 'rebase']):
            issues.divergence(i, {}, exit_code(op, 'Error: Error(22)\n'))
        summary = issues.finish()

        self.assertEqual([0, 1, 2], [i for i, _ in rec.issues])
        self.assertEqual(3, summary['issues_filed'])
        self.assertEqual(3, summary['issue_shapes_suppressed'])
        self.assertEqual(6, summary['divergence_shapes'])

    def test_a_repeat_of_a_filed_shape_does_not_count_against_the_limit(self):
        rec = Recorder()
        issues = filer(rec, max_issues=2)
        issues.divergence(0, {}, exit_code('info', 'Error: Error(22)\n'))
        issues.divergence(1, {}, exit_code('info', 'Error: Error(22)\n'))
        issues.divergence(2, {}, exit_code('map', 'Error: Error(22)\n'))
        issues.finish()

        self.assertEqual([0, 2], [i for i, _ in rec.issues])

    def test_a_shape_seen_once_gets_no_comment(self):
        rec = Recorder()
        issues = filer(rec)
        issues.divergence(0, {}, exit_code('info', 'Error: Error(22)\n'))
        issues.divergence(1, {}, exit_code('map', 'Error: Error(22)\n'))
        issues.finish()

        self.assertEqual([], rec.comments)

    def test_an_issue_that_could_not_be_filed_gets_no_comment(self):
        rec = Recorder(fail=True)
        issues = filer(rec)
        for i in range(3):
            issues.divergence(i, {}, exit_code('info', 'Error: Error(22)\n'))
        issues.finish()

        self.assertEqual([], rec.comments)

    def test_a_filing_that_failed_is_not_reported_as_filed(self):
        rec = Recorder(fail=True)
        attempts = []
        original = rec.file_issue

        def counting(*args):
            attempts.append(args[1])
            return original(*args)

        issues = df.IssueFiler(1234, None, 3, file_issue=counting, comment=rec.comment)
        for i, op in enumerate(['info', 'map', 'measure', 'resize', 'commit']):
            issues.divergence(i, {}, exit_code(op, 'Error: Error(22)\n'))
        summary = issues.finish()

        self.assertEqual(0, summary['issues_filed'])
        self.assertEqual(3, summary['issues_failed'])
        # A broken gh is tried no more often than a working one would be.
        self.assertEqual([0, 1, 2], attempts)
        self.assertEqual(2, summary['issue_shapes_suppressed'])


if __name__ == '__main__':
    unittest.main()
