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

import ast
import os
import re
import types
import unittest
from unittest import mock

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
        self.assertEqual(('snapshot_byte_divergence', '', (), ''),
                         df.divergence_key({'type': 'snapshot_byte_divergence'}))

    def test_a_hex_offset_does_not_distinguish(self):
        a = exit_code('map', 'Error: bad L2 entry at 0xab12cd\n')
        b = exit_code('map', 'Error: bad L2 entry at 0x3f00\n')
        self.assertEqual(df.divergence_key(a), df.divergence_key(b))

    def test_a_slash_inside_a_word_is_not_a_path(self):
        a = exit_code('info', 'Error: read/write not permitted\n')
        b = exit_code('info', 'Error: read/only not permitted\n')
        self.assertNotEqual(df.divergence_key(a), df.divergence_key(b))

    def test_a_quoted_path_is_still_a_path(self):
        a = exit_code('info', 'Error: cannot open "/tmp/instar-fuzz-ab12/img0.qcow2"\n')
        b = exit_code('info', 'Error: cannot open "/tmp/instar-fuzz-cd34/img9.qcow2"\n')
        self.assertEqual(df.divergence_key(a), df.divergence_key(b))


class ContentDivergenceKeyTestCase(unittest.TestCase):
    """Most divergence types carry no stderr, so their fields are the shape."""

    def convert(self, target_format, sha, compress=False):
        return {'type': 'convert_content_divergence', 'target_format': target_format,
                'compress': compress, 'instar_sha256': sha, 'qemu_sha256': 'f' * 64}

    def test_the_target_format_distinguishes(self):
        self.assertNotEqual(df.divergence_key(self.convert('qcow2', 'a' * 64)),
                            df.divergence_key(self.convert('vmdk', 'a' * 64)))

    def test_compression_distinguishes(self):
        self.assertNotEqual(df.divergence_key(self.convert('qcow2', 'a' * 64)),
                            df.divergence_key(self.convert('qcow2', 'a' * 64, compress=True)))

    def test_a_hash_does_not_distinguish(self):
        self.assertEqual(df.divergence_key(self.convert('qcow2', 'a' * 64)),
                         df.divergence_key(self.convert('qcow2', 'b' * 64)))

    def test_the_measure_field_distinguishes_and_its_values_do_not(self):
        def measure(field, value):
            return {'type': 'measure_numeric_divergence', 'target_format': 'qcow2', 'field': field,
                    'instar_value': value, 'qemu_value': 0, 'instar_stdout': str(value)}
        self.assertEqual(df.divergence_key(measure('required', 1)), df.divergence_key(measure('required', 2)))
        self.assertNotEqual(df.divergence_key(measure('required', 1)),
                            df.divergence_key(measure('fully-allocated', 1)))

    def test_the_libyal_fields_that_differ_distinguish(self):
        def libyal(fields):
            return {'type': 'libyal_info_divergence', 'tool': 'vhdiinfo', 'format': 'vhd',
                    'field_divergences': {f: {'instar': 1, 'libyal': 2} for f in fields}}
        self.assertNotEqual(df.divergence_key(libyal(['virtual_size'])),
                            df.divergence_key(libyal(['identifier'])))
        self.assertEqual(df.divergence_key(libyal(['identifier', 'virtual_size'])),
                         df.divergence_key(libyal(['virtual_size', 'identifier'])))

    def test_a_bench_recipe_format_distinguishes(self):
        def bench(fmt):
            return {'type': 'bench_write_divergence', 'operation': 'bench',
                    'recipe': {'fmt': fmt, 'size': 123}, 'argv': ['x'], 'reason': 'differ'}
        self.assertNotEqual(df.divergence_key(bench('raw')), df.divergence_key(bench('qcow2')))


# Every dict the fuzzer builds with a literal `type` is one of its
# records, so the scan matches on having a type at all rather than on a
# list of suffixes. The 66 types in the file end in nine different words
# -- _divergence, _failure, _failed, _timeout, _unparseable, _error,
# _crash, _bound, _conservative -- and an allowlist of those is stale
# the moment a tenth is written, which is how the fields below went
# unclassified in the first place.
#
# The one kind of record that is not a divergence is excluded by the
# same prefix the fuzzer itself routes it by: an `inconclusive_` record
# is logged and never reaches `divergence_key` or the issue filer. A
# crash record does reach both, so it is in.
_NOT_A_DIVERGENCE_PREFIX = 'inconclusive_'

# The fuzzer's name for a variable holding a divergence. A field added by
# subscript assignment (div['x'] = y) cannot be tied to a dict by reading
# alone, so the scan goes by this convention and
# test_every_divergence_variable_follows_the_naming_convention keeps the
# convention true.
_DIVERGENCE_NAME = re.compile(r'(^|_)div(ergence)?$')


def _type_text(node):
    """The literal tail of a divergence `type` expression, or None.

    A plain string is itself; an f-string is its last piece, which is
    where the fuzzer puts the part that names the comparison.
    """
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.JoinedStr) and node.values:
        tail = node.values[-1]
        if isinstance(tail, ast.Constant):
            return str(tail.value)
    return None


def _is_divergence_type(node):
    """Whether a `type` expression names a record that can file an issue.

    Only the literal tail of an interpolated type is knowable here, so an
    `inconclusive_` type built by interpolation would read as a
    divergence. Every one in the file is a plain literal today, and the
    error is in the safe direction: a field classified that is never
    keyed costs nothing, while an unclassified one fails CI.
    """
    text = _type_text(node)
    return bool(text) and not text.startswith(_NOT_A_DIVERGENCE_PREFIX)


class ShapeFieldsTestCase(unittest.TestCase):
    def divergence_fields(self):
        """Every field named in a divergence the fuzzer builds.

        Reads the source rather than running it. A divergence is built in
        one of four shapes, and all four have carried a field the lists
        below had to classify:

        * a dict literal whose 'type' is a divergence type;
        * `dict(ctx, type=..., ...)`, which spreads a context in by call
          rather than by `**`;
        * the context dicts spread in either way, found by name; and
        * `div['field'] = value` after the fact.
        """
        with open(_DF_PATH, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        spread = set()
        fields = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                keys = [k.value if isinstance(k, ast.Constant) else None for k in node.keys]
                types_ = [v for k, v in zip(keys, node.values) if k == 'type']
                if types_ and _is_divergence_type(types_[0]):
                    fields.update(k for k in keys if k and k != 'type')
                    spread.update(v.id for k, v in zip(keys, node.values)
                                  if k is None and isinstance(v, ast.Name))
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'dict'):
                types_ = [kw.value for kw in node.keywords if kw.arg == 'type']
                if types_ and _is_divergence_type(types_[0]):
                    fields.update(kw.arg for kw in node.keywords if kw.arg and kw.arg != 'type')
                    spread.update(a.id for a in node.args if isinstance(a, ast.Name))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if isinstance(node.value, ast.Dict) and any(
                    isinstance(t, ast.Name) and t.id in spread for t in node.targets):
                fields.update(k.value for k in node.value.keys if isinstance(k, ast.Constant))
            for target in node.targets:
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and _DIVERGENCE_NAME.search(target.value.id)
                        and isinstance(target.slice, ast.Constant)):
                    fields.add(str(target.slice.value))
        return fields

    def divergence_variables(self):
        """Every variable the fuzzer assigns a divergence it built inline."""
        with open(_DF_PATH, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        names = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if isinstance(value, ast.Dict):
                keys = [k.value if isinstance(k, ast.Constant) else None for k in value.keys]
                types_ = [v for k, v in zip(keys, value.values) if k == 'type']
            elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id == 'dict'):
                types_ = [kw.value for kw in value.keywords if kw.arg == 'type']
            else:
                continue
            if types_ and _is_divergence_type(types_[0]):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        return names

    def test_the_scan_finds_the_divergences(self):
        # A scan that matched nothing would pass the test below vacuously.
        fields = self.divergence_fields()
        for expected in ('target_format', 'field_divergences', 'corruption', 'shape'):
            self.assertIn(expected, fields)

    def test_the_scan_sees_every_shape_a_divergence_is_built_in(self):
        # One field per shape, so a scan that lost one of the four shapes
        # fails here rather than going quiet: a dict literal, a
        # dict(ctx, type=...) call with an interpolated type, a context
        # spread in by name, and a subscript assignment after the fact.
        fields = self.divergence_fields()
        for expected in ('corruption', 'vhdx_subformat', 'instar_stderr', 'structure_also_diverged',
                         'error'):
            self.assertIn(expected, fields)

    def test_the_scan_does_not_depend_on_how_a_type_is_spelled(self):
        # `cushion` is carried only by measure_above_fully_allocated_bound,
        # whose type ends in none of the words a suffix allowlist would
        # have held. Its presence is what says the scan matches on having
        # a type rather than on the type's last word.
        self.assertIn('cushion', self.divergence_fields())

    def test_inconclusive_records_are_not_divergences(self):
        # An inconclusive record is logged for visibility and never
        # reaches divergence_key or the issue filer, so its own fields are
        # deliberately out of the scan's scope. `timed_out` is carried by
        # nothing else.
        self.assertNotIn('timed_out', self.divergence_fields())

    def test_every_divergence_variable_follows_the_naming_convention(self):
        # The subscript half of the scan goes by variable name, so a
        # divergence held in a variable the pattern does not match would
        # take its later fields out of the scan's sight.
        stray = {name for name in self.divergence_variables()
                 if not _DIVERGENCE_NAME.search(name)}
        self.assertEqual(set(), stray,
                         'name a variable holding a divergence `div`, `..._div` or `divergence` '
                         'so fields assigned into it later are still scanned')

    def test_every_divergence_field_is_classified(self):
        unclassified = self.divergence_fields() - set(df.SHAPE_FIELDS) - df.PER_ITERATION_FIELDS
        self.assertEqual(set(), unclassified,
                         'add each to SHAPE_FIELDS if it says what diverged, or to '
                         'PER_ITERATION_FIELDS if it changes every iteration')

    def test_no_field_is_both(self):
        self.assertEqual(set(), set(df.SHAPE_FIELDS) & df.PER_ITERATION_FIELDS)


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


MiB = 1024 * 1024


class VhdxPinCaseSelectionTestCase(unittest.TestCase):
    """The cases the structural comparison referees are chosen by option, not by name."""

    def test_a_case_is_selected_whichever_order_its_options_are_in(self):
        # A pin case's name is built by joining option abbreviations in
        # the order the case lists them, so a selector that read the name
        # would drop this case the moment someone wrote its two options
        # the other way round.
        ordered = {
            'name': 'vhdx-fixed-64M-block-1M-bsz-off', 'kind': df.KIND_VHDX_CREATE, 'size': '64M',
            'args': ['-f', 'vhdx', '-o', 'subformat=fixed,block_size=1M,block_state_zero=off'],
        }
        swapped = dict(
            ordered, name='vhdx-fixed-64M-bsz-off-block-1M',
            args=['-f', 'vhdx', '-o', 'subformat=fixed,block_state_zero=off,block_size=1M'],
        )
        for case in (ordered, swapped):
            with self.subTest(name=case['name']):
                with mock.patch.object(df, 'CASES', [case]):
                    self.assertEqual({case['name']: 'fixed'}, df._vhdx_pin_case_subformats())

    def test_the_layouts_instar_does_not_write_are_refused(self):
        cases = [
            # Fixed without block_state_zero=off: not the layout instar's
            # writer copies.
            {'name': 'fixed-on', 'kind': df.KIND_VHDX_CREATE,
             'args': ['-f', 'vhdx', '-o', 'subformat=fixed']},
            # Dynamic with it: the default dynamic case stands in for
            # both, since a dynamic BAT is not compared.
            {'name': 'dynamic-off', 'kind': df.KIND_VHDX_CREATE,
             'args': ['-f', 'vhdx', '-o', 'block_state_zero=off']},
            # A differencing image's structure follows its parent.
            {'name': 'fixed-base', 'kind': df.KIND_VHDX_CREATE, 'base': 'vhdx',
             'args': ['-f', 'vhdx', '-o', 'subformat=fixed,block_state_zero=off']},
            # Another kind of pinned command entirely.
            {'name': 'prealloc', 'kind': 'prealloc', 'args': ['-f', 'vhdx']},
        ]
        with mock.patch.object(df, 'CASES', cases):
            self.assertEqual({}, df._vhdx_pin_case_subformats())

    def test_the_committed_cases_still_offer_both_subformats(self):
        # Vacuity guard: both tests above would pass against a selector
        # that matched nothing in the real case list.
        self.assertEqual({'fixed', 'dynamic'}, set(df._vhdx_pin_case_subformats().values()))


class VhdxStructureIssueShapeTestCase(unittest.TestCase):
    """A structural divergence files per subformat and geometry, not one issue for all of them."""

    @staticmethod
    def divergence(subformat, case, **overrides):
        return dict({
            'type': 'convert_vhdx_structure_divergence', 'operation': 'convert',
            'target_format': 'vhdx', 'compress': False,
            'vhdx_subformat': subformat, 'pin_case': case,
            'virtual_size': 64 * MiB, 'block_size': MiB,
            'differences': ['file_length: 1 != 2'],
        }, **overrides)

    def test_fixed_and_dynamic_are_separate_findings(self):
        # The distinction the structural arm exists to expose: without
        # the subformat in the shape these two share a type, an
        # operation, a target format and a compress flag, so one issue
        # would stand for both.
        self.assertNotEqual(
            df.divergence_key(self.divergence('fixed', 'vhdx-fixed-64M-bsz-off')),
            df.divergence_key(self.divergence('dynamic', 'vhdx-dynamic-64M')))

    def test_two_subformats_failing_to_parse_are_separate_findings(self):
        # A parse failure carries no pin case, because the geometry was
        # never established, so the subformat is the only thing telling a
        # fixed output that could not be read from a dynamic one. This is
        # what `vhdx_subformat` is in the shape for; `pin_case` carries
        # the distinction on its own whenever there is a pin case.
        def failure(subformat):
            return {'type': 'convert_vhdx_parse_failure', 'operation': 'convert',
                    'target_format': 'vhdx', 'compress': False,
                    'vhdx_subformat': subformat,
                    'parse_error': 'bat region at offset 2097152 lies outside the file'}
        self.assertNotEqual(df.divergence_key(failure('fixed')),
                            df.divergence_key(failure('dynamic')))

    def test_two_geometries_of_one_subformat_are_separate_findings(self):
        self.assertNotEqual(
            df.divergence_key(self.divergence('fixed', 'vhdx-fixed-64M-bsz-off')),
            df.divergence_key(self.divergence('fixed', 'vhdx-fixed-16M-bsz-off')))

    def test_the_values_compared_do_not_split_a_finding(self):
        # The other half of the classification: a run where every
        # iteration differs by a different amount must still file one
        # issue for the geometry, which is what SHAPE_FIELDS is for.
        self.assertEqual(
            df.divergence_key(self.divergence('fixed', 'vhdx-fixed-64M-bsz-off')),
            df.divergence_key(self.divergence('fixed', 'vhdx-fixed-64M-bsz-off',
                                              differences=['bat: 9 != 8'], block_size=8 * MiB)))


class VhdxStructureGeometryKeyTestCase(unittest.TestCase):
    """The pin lookup is keyed on the geometry asked for, not the one the output claims."""

    PIN = {'block_size': MiB, 'virtual_disk_size': 64 * MiB, 'bat_entry_count': 64}

    def compare(self, claimed_block_size, requested_block_size, extra=None):
        """`compare_vhdx_structure` against a pin, with the parse stubbed out."""
        summary = dict(self.PIN, block_size=claimed_block_size, **(extra or {}))
        with mock.patch.object(df, 'parse_vhdx', lambda path: None), \
                mock.patch.object(df, 'summarise', lambda parsed: summary), \
                mock.patch.object(df, '_vhdx_pin_geometries',
                                  lambda: {'fixed': {(64 * MiB, MiB): 'vhdx-fixed-64M-block-1M-bsz-off'}}), \
                mock.patch.object(df, 'expected', lambda case, pin=None: {'summary': dict(self.PIN)}):
            return df.compare_vhdx_structure('out.vhdx', 'fixed', 64 * MiB, 'convert', {},
                                             block_size=requested_block_size)

    def test_a_wrong_block_size_is_a_difference_not_a_silencer(self):
        # The defect this keying avoids: an output whose block size is
        # wrong must not move itself off the pinned geometry and skip the
        # comparison that would have reported it.
        divergence = self.compare(claimed_block_size=2 * MiB, requested_block_size=MiB)
        self.assertIsNotNone(divergence)
        self.assertEqual('convert_vhdx_structure_divergence', divergence['type'])
        self.assertEqual(['block_size: 2097152 != 1048576'], divergence['differences'])
        # The pin case names the geometry, which is what separates one
        # issue shape from another; the sizes travel per iteration.
        self.assertEqual('vhdx-fixed-64M-block-1M-bsz-off', divergence['pin_case'])

    def test_an_output_matching_the_pin_is_not_a_divergence(self):
        self.assertIsNone(self.compare(claimed_block_size=MiB, requested_block_size=MiB))

    def test_a_field_the_pin_predates_is_reported_not_dropped(self):
        # The comparison takes its field set from both sides, so a field
        # `summarise` gains after the pin was taken is reported as
        # present on one side only rather than quietly left out of the
        # comparison on both.
        divergence = self.compare(claimed_block_size=MiB, requested_block_size=MiB,
                                  extra={'log_offset': 1048576})
        self.assertIsNotNone(divergence)
        self.assertEqual(['log_offset: 1048576 != None'], divergence['differences'])

    def test_an_unset_block_size_is_keyed_on_what_the_tool_chose(self):
        # The one draw with nothing to compare against: the option was
        # left unset, so the value asked for is whatever the default
        # picked, and the read-back value is what finds the pin.
        self.assertIsNone(self.compare(claimed_block_size=MiB, requested_block_size=None))
        self.assertIsNone(self.compare(claimed_block_size=2 * MiB, requested_block_size=None))


if __name__ == '__main__':
    unittest.main()
