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
import random
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


def unreadable_record_types(source):
    """Line numbers in `source` of records whose `type` text cannot be read.

    A record is a dict or `dict()` call carrying a `type` key. When that
    key's text cannot be determined -- an f-string ending in an
    interpolation -- every field of the record leaves the field
    classification scan without a word, so the scan treats this as a
    hard failure rather than skipping the record.
    """
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            keys = [k.value if isinstance(k, ast.Constant) else None for k in node.keys]
            types_ = [v for k, v in zip(keys, node.values) if k == 'type']
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'dict'):
            types_ = [kw.value for kw in node.keywords if kw.arg == 'type']
        else:
            continue
        if types_ and _type_text(types_[0]) is None:
            lines.append(node.lineno)
    return lines


def _is_divergence_type(node):
    """Whether a `type` expression names a record that can file an issue.

    Only the literal tail of an interpolated type is knowable here, so an
    `inconclusive_` type built by interpolation would read as a
    divergence. Every one in the file is a plain literal today, and that
    error is in the safe direction: a field classified that is never
    keyed costs nothing, while an unclassified one fails CI.

    The unsafe direction is a `type` whose text cannot be read at all --
    an f-string ending in an interpolation, say -- because every field of
    that record would leave the scan silently.
    `test_every_record_type_can_be_read` refuses that rather than
    leaving the guard best-effort.
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
        * `div['field'] = value` after the fact, onto either the
          divergence or a context that is spread into one.
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
                if not (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and isinstance(target.slice, ast.Constant)):
                    continue
                # Onto the divergence, by the naming convention below, or
                # onto a context that is spread into one: `op_convert`
                # sets context['vhdx_subformat'] before building the
                # divergence that spreads it, so a field can reach a
                # divergence without ever being written on it.
                if _DIVERGENCE_NAME.search(target.value.id) or target.value.id in spread:
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

    # One field per way the fuzzer can name a field in a record, each
    # reachable by that way and no other, so losing any one path fails
    # this test rather than going quiet. Checked by construction: a
    # scan-path audit over the source found each of these in exactly one.
    SHAPES = {
        'dict literal, plain type': 'cushion',
        'dict literal, interpolated type': 'instar_sha',
        'dict(ctx, ...) call, plain type': 'compare_stdout',
        'dict(ctx, ...) call, interpolated type': 'parse_error',
        'a context dict spread in by name': 'corruption',
        'subscript onto the divergence': 'structure_also_diverged',
        'subscript onto a spread context': 'vhdx_block_size',
    }

    def test_the_scan_sees_every_shape_a_divergence_is_built_in(self):
        fields = self.divergence_fields()
        for shape, field in self.SHAPES.items():
            with self.subTest(shape=shape):
                self.assertIn(field, fields, f'{shape} is no longer scanned')

    def test_the_scan_does_not_depend_on_how_a_type_is_spelled(self):
        # `cushion` is carried only by measure_above_fully_allocated_bound,
        # whose type ends in none of the words a suffix allowlist would
        # have held. Its presence is what says the scan matches on having
        # a type rather than on the type's last word.
        self.assertIn('cushion', self.divergence_fields())

    def test_the_scan_sees_a_field_set_on_a_spread_context(self):
        # `op_convert` sets context['vhdx_block_size'] and then builds a
        # divergence that spreads that context, so the field reaches a
        # divergence without ever being written on one. A scan that only
        # followed subscripts on the divergence itself would miss it.
        # Named separately from the table above so a regression in this
        # one path is attributable.
        self.assertIn('vhdx_block_size', self.divergence_fields())

    def test_every_record_type_can_be_read(self):
        # The scan reads an interpolated type by its literal tail, so a
        # type that ends in an interpolation is unreadable and every
        # field of that record leaves the scan without a word. That is
        # the one way this guard fails unsafely, so it is refused here
        # rather than tolerated.
        with open(_DF_PATH, encoding='utf-8') as f:
            source = f.read()
        self.assertEqual([], unreadable_record_types(source),
                         'end an interpolated divergence `type` in a literal, so the field '
                         'classification guard can still read which record it is')

    def test_an_unreadable_type_is_detected(self):
        # The test above holds over a file that has none, so it would
        # pass against a detector that found nothing. These fixtures say
        # the detector works: a type ending in an interpolation is
        # caught, in both shapes a record is built in, and a type ending
        # in a literal is not.
        caught = (
            "d = {'type': f'{op}_{kind}', 'a': 1}\n"
            "e = dict(ctx, type=f'prefix_{suffix}')\n"
        )
        self.assertEqual([1, 2], unreadable_record_types(caught))
        self.assertEqual([], unreadable_record_types("d = {'type': f'{op}_divergence', 'a': 1}\n"))
        self.assertEqual([], unreadable_record_types("d = {'type': 'exit_code_divergence'}\n"))
        # A dict with no type at all is not a record.
        self.assertEqual([], unreadable_record_types("d = {'a': f'{x}'}\n"))

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


KiB = 1024
MiB = 1024 * KiB


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
                with mock.patch.object(df, 'PIN_CASES', [case]):
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
        with mock.patch.object(df, 'PIN_CASES', cases):
            self.assertEqual({}, df._vhdx_pin_case_subformats())

    def test_a_pin_case_whose_options_are_missing_does_not_crash(self):
        # The selector runs once at first use, so an IndexError here is a
        # startup crash in the fuzzer rather than a wrong comparison. A
        # case listing `-o` last is malformed, but it should drop out
        # rather than take the run with it.
        cases = [{'name': 'dangling-o', 'kind': df.KIND_VHDX_CREATE, 'args': ['-f', 'vhdx', '-o']}]
        with mock.patch.object(df, 'PIN_CASES', cases):
            self.assertEqual({'dangling-o': 'dynamic'}, df._vhdx_pin_case_subformats())

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


class NestedContextShapeTestCase(unittest.TestCase):
    """A divergence that nests its whole context is still shaped by it."""

    @staticmethod
    def exit_code(**context):
        return {'type': 'exit_code_divergence', 'operation': 'convert',
                'instar_rc': 1, 'qemu_rc': 0, 'context': context}

    def test_a_nested_shape_field_separates_two_findings(self):
        # exit_code_divergence puts every field of its own under
        # 'context', so without the fallback a fixed and a dynamic
        # `convert -O vhdx` refusal share every shape component and file
        # as one issue whenever their stderr normalises the same.
        self.assertNotEqual(
            df.divergence_key(self.exit_code(target_format='vhdx', vhdx_subformat='fixed')),
            df.divergence_key(self.exit_code(target_format='vhdx', vhdx_subformat='dynamic')))

    def test_a_nested_per_iteration_field_does_not(self):
        self.assertEqual(
            df.divergence_key(self.exit_code(target_format='vhdx', vhdx_block_size=1048576)),
            df.divergence_key(self.exit_code(target_format='vhdx', vhdx_block_size=8388608)))

    def test_a_top_level_field_still_wins_over_the_context(self):
        # The top level is the divergence's own answer; the context is
        # only consulted where it has none.
        divergence = dict(self.exit_code(target_format='qcow2'), target_format='vhdx')
        self.assertIn(('target_format', 'vhdx'), df.divergence_key(divergence)[2])


class KnownDefectSkipScopeTestCase(unittest.TestCase):
    """The #883 skip covers the subformat and operation the defect was measured on."""

    SHAPE = ('metadata', 4 * MiB, 3 * MiB + 128 * KiB)

    def compare(self, subformat, operation):
        """`compare_vhdx_structure` where the parse fails in the #883 shape."""
        def unparseable(path):
            raise df.VhdxParseError('metadata region at 3145728 lies outside the file')

        with mock.patch.object(df, 'parse_vhdx', unparseable), \
                mock.patch.object(df, 'truncated_inside_region', lambda path: self.SHAPE), \
                mock.patch.dict(df.KNOWN_DEFECT_SKIPS, {}, clear=True):
            result = df.compare_vhdx_structure('out.vhdx', subformat, 64 * MiB, operation, {})
            return result, dict(df.KNOWN_DEFECT_SKIPS)

    def test_a_dynamic_convert_output_is_skipped_and_counted(self):
        result, skips = self.compare('dynamic', 'convert')
        self.assertIsNone(result)
        self.assertEqual({'convert_vhdx_truncated_region_issue_883': 1}, skips)

    def test_a_fixed_output_of_the_same_shape_is_reported(self):
        # A fixed image carries a present entry for every block, so an
        # all-zero BAT region in one is a finding of its own, not #883.
        result, skips = self.compare('fixed', 'convert')
        self.assertEqual('convert_vhdx_parse_failure', result['type'])
        self.assertEqual('fixed', result['vhdx_subformat'])
        self.assertEqual({}, skips)

    def test_another_operation_reaching_the_same_shape_is_reported(self):
        # `dd` draws a vhdx target too. The same file shape from a caller
        # the defect was never measured on is a new defect, not this one.
        result, skips = self.compare('dynamic', 'dd')
        self.assertEqual('dd_vhdx_parse_failure', result['type'])
        self.assertEqual({}, skips)


class ArguableClassificationsTestCase(unittest.TestCase):
    """The field classifications whose call is a judgement, held by a test.

    Widening the scan surfaced two dozen fields that had never been
    classified, and most are obvious from their name. These three are
    not: mis-binning one is silent, and it goes wrong in both
    directions -- a shape field left per-iteration merges distinct
    findings into one issue, and the reverse splits one finding across
    many -- so the reasoning is pinned here rather than left to the
    comment beside the list.
    """

    @staticmethod
    def divergence(**fields):
        return dict({'type': 'amend_check_divergence', 'operation': 'amend'}, **fields)

    def test_note_separates_two_findings(self):
        # `note` is the fixed wording a check gives its finding, from a
        # small vocabulary, so two different notes are two findings.
        self.assertNotEqual(
            df.divergence_key(self.divergence(note='raw-flattened content differs')),
            df.divergence_key(self.divergence(note='qemu-img check could not parse image')))

    def test_error_does_not_separate_two_findings(self):
        # `error` is an exception's text, which carries paths and offsets
        # from the iteration that raised it. Shaping on it would file one
        # issue per iteration, which is the fault divergence_key exists
        # to prevent.
        self.assertEqual(
            df.divergence_key(self.divergence(error="can't open /tmp/fuzz-1/img.qcow2")),
            df.divergence_key(self.divergence(error="can't open /tmp/fuzz-2/img.qcow2")))

    def test_path_does_not_separate_two_findings(self):
        # Every iteration works in its own directory, so a path differs
        # every time by construction.
        self.assertEqual(
            df.divergence_key(self.divergence(path='/tmp/fuzz-1/out.vhdx')),
            df.divergence_key(self.divergence(path='/tmp/fuzz-2/out.vhdx')))


class StructuralOutcomeCountTestCase(unittest.TestCase):
    """Every structural comparison that did not happen is counted, not silent."""

    PIN = {'block_size': MiB, 'virtual_disk_size': 64 * MiB}

    def outcomes(self, virtual_size=64 * MiB, block_size=MiB, parse_error=None, shape=None,
                 subformat='fixed'):
        def parse(path):
            if parse_error:
                raise df.VhdxParseError(parse_error)
            return None

        with mock.patch.object(df, 'parse_vhdx', parse), \
                mock.patch.object(df, 'summarise', lambda parsed: dict(self.PIN)), \
                mock.patch.object(df, 'truncated_inside_region', lambda path: shape), \
                mock.patch.object(df, '_vhdx_pin_geometries',
                                  lambda: {subformat: {(64 * MiB, MiB): 'case'}}), \
                mock.patch.object(df, 'expected', lambda name, pin=None: {'summary': dict(self.PIN)}), \
                mock.patch.dict(df.STRUCTURAL_OUTCOMES, {}, clear=True), \
                mock.patch.dict(df.KNOWN_DEFECT_SKIPS, {}, clear=True):
            df.compare_vhdx_structure('out.vhdx', subformat, virtual_size, 'convert', {},
                                      block_size=block_size)
            return dict(df.STRUCTURAL_OUTCOMES)

    def test_a_comparison_that_happened_is_counted(self):
        self.assertEqual({'convert:compared': 1}, self.outcomes())

    def test_the_counters_are_emptied_per_run(self):
        # Both counters are module globals read only when a run reports,
        # so a second run in one process would otherwise report the
        # first run's counts as its own.
        with mock.patch.dict(df.STRUCTURAL_OUTCOMES, {'convert:compared': 7}, clear=True), \
                mock.patch.dict(df.KNOWN_DEFECT_SKIPS, {'convert_vhdx_x': 3}, clear=True):
            df.reset_run_counters()
            self.assertEqual({}, df.STRUCTURAL_OUTCOMES)
            self.assertEqual({}, df.KNOWN_DEFECT_SKIPS)

    def test_an_unpinned_geometry_is_counted_not_silent(self):
        # The failure this closes: an iteration that parsed its output
        # and found no pin returns no divergence, which reads exactly
        # like a clean comparison in the summary.
        self.assertEqual({'convert:no_pin_for_geometry': 1}, self.outcomes(block_size=8 * MiB))

    def test_an_unprobeable_source_is_counted_not_silent(self):
        self.assertEqual({'convert:no_virtual_size': 1}, self.outcomes(virtual_size=None))

    def test_a_parse_failure_is_counted(self):
        self.assertEqual({'convert:parse_failure': 1}, self.outcomes(parse_error='truncated'))

    def test_the_known_defect_skip_is_counted_under_its_own_name(self):
        # Dynamic, because the skip is scoped to the shape the defect was
        # measured on; a fixed output of the same shape counts as a parse
        # failure, which the case below holds.
        self.assertEqual({'convert:skipped_issue_883': 1},
                         self.outcomes(subformat='dynamic', parse_error='truncated',
                                       shape=('metadata', 4 * MiB, 3 * MiB)))

    def test_a_fixed_output_of_the_known_shape_counts_as_a_parse_failure(self):
        self.assertEqual({'convert:parse_failure': 1},
                         self.outcomes(subformat='fixed', parse_error='truncated',
                                       shape=('metadata', 4 * MiB, 3 * MiB)))


class ConvertShapePickerTestCase(unittest.TestCase):
    """What `_convert_vhdx_shape` can draw, over a stubbed pin and probe."""

    GEOMETRIES = {
        'fixed': {(64 * MiB, MiB): 'vhdx-fixed-64M-block-1M-bsz-off'},
        'dynamic': {(64 * MiB, 8 * MiB): 'vhdx-dynamic-64M'},
    }

    def draws(self, virtual_size=64 * MiB, count=400):
        rng = random.Random(1234)
        with mock.patch.object(df, '_vhdx_pin_geometries', lambda: self.GEOMETRIES), \
                mock.patch.object(df, '_map_probe_virtual_size', lambda source, timeout: virtual_size):
            return [df._convert_vhdx_shape(rng, 'src.qcow2', 30) for _ in range(count)]

    def test_both_subformats_are_reachable(self):
        # An arm that is never drawn is not coverage, and fixed VHDX is
        # the subject of the phase this picker was added for.
        self.assertEqual({'fixed', 'dynamic'}, {subformat for subformat, _, _ in self.draws()})

    def test_every_fixed_draw_names_its_block_size(self):
        # The pin is the oracle and there is no pinned structure for a
        # geometry the sweep never ran, so a fixed draw may not leave the
        # block size to the tool's default.
        for subformat, block_size, _ in self.draws():
            if subformat == 'fixed':
                self.assertIsNotNone(block_size)

    def test_every_fixed_draw_is_a_whole_number_of_blocks(self):
        # #879: `convert -O vhdx --subformat fixed` fails when the
        # partial last block holds data, so a geometry that is not a
        # whole multiple would report a known bug every run instead of
        # coverage.
        for subformat, block_size, virtual_size in self.draws():
            if subformat == 'fixed':
                self.assertEqual(0, virtual_size % block_size)

    def test_an_unpinned_source_size_only_draws_dynamic(self):
        shapes = self.draws(virtual_size=65 * MiB)
        self.assertEqual({'dynamic'}, {subformat for subformat, _, _ in shapes})

    def test_an_unprobeable_source_degrades_to_dynamic(self):
        # The probe is a qemu-img subprocess; when it cannot answer, the
        # iteration still runs and the comparison finds no pin for a
        # None virtual size.
        shapes = self.draws(virtual_size=None)
        self.assertEqual({'dynamic'}, {subformat for subformat, _, _ in shapes})
        self.assertEqual({None}, {virtual_size for _, _, virtual_size in shapes})


class VhdxStructureGeometryKeyTestCase(unittest.TestCase):
    """The pin lookup is keyed on the geometry asked for, not the one the output claims."""

    PIN = {'block_size': MiB, 'virtual_disk_size': 64 * MiB, 'bat_entry_count': 64}

    def compare(self, claimed_block_size, requested_block_size, extra=None, subformat='fixed'):
        """`compare_vhdx_structure` against a pin, with the parse stubbed out."""
        summary = dict(self.PIN, block_size=claimed_block_size, **(extra or {}))
        case = f'vhdx-{subformat}-64M-block-1M'
        with mock.patch.object(df, 'parse_vhdx', lambda path: None), \
                mock.patch.object(df, 'summarise', lambda parsed: summary), \
                mock.patch.object(df, '_vhdx_pin_geometries',
                                  lambda: {subformat: {(64 * MiB, MiB): case}}), \
                mock.patch.object(df, 'expected', lambda name, pin=None: {'summary': dict(self.PIN)}):
            return df.compare_vhdx_structure('out.vhdx', subformat, 64 * MiB, 'convert', {},
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
        self.assertEqual('vhdx-fixed-64M-block-1M', divergence['pin_case'])

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

    def test_a_dynamic_comparison_drops_exactly_the_data_dependent_fields(self):
        # A dynamic image's BAT and file length follow the source's data,
        # so they are excluded -- and nothing else is. Widening
        # _VHDX_DATA_DEPENDENT_FIELDS thins dynamic coverage with no
        # visible symptom, which is what this holds.
        wrong = {'file_length': 1, 'bat': [], 'log_offset': 7, 'chunk_ratio': 9}
        divergence = self.compare(claimed_block_size=MiB, requested_block_size=MiB,
                                  subformat='dynamic', extra=wrong)
        self.assertIsNotNone(divergence)
        self.assertEqual(['chunk_ratio: 9 != None', 'log_offset: 7 != None'],
                         sorted(divergence['differences']))

    def test_a_dynamic_comparison_with_only_data_differences_is_not_a_divergence(self):
        self.assertIsNone(self.compare(
            claimed_block_size=MiB, requested_block_size=MiB, subformat='dynamic',
            extra={'file_length': 1, 'bat': [{'index': 0, 'state': 6, 'offset': 0}]}))

    def test_an_unset_block_size_is_keyed_on_what_the_tool_chose(self):
        # The one draw with nothing to compare against: the option was
        # left unset, so the value asked for is whatever the default
        # picked, and the read-back value is what finds the pin.
        self.assertIsNone(self.compare(claimed_block_size=MiB, requested_block_size=None))
        self.assertIsNone(self.compare(claimed_block_size=2 * MiB, requested_block_size=None))


if __name__ == '__main__':
    unittest.main()
