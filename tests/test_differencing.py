"""Integration tests for PLAN-differencing phase 4's read-side refusal.

A differencing image is one whose content lives partly in a parent
file. instar cannot compose a parent yet -- composition is phases 11
to 16 of PLAN-differencing.md -- so every operation that would compose
sector data refuses a differencing VHD or VHDX by name instead of
returning a wrong answer.

These tests pin that refusal. They exist because two of the three
things they assert used to be defects:

* `instar convert -O raw` on a differencing VHD exited 0 and wrote a
  file composed as though the parent's sectors were zero (issue #547).
  The tests below assert both the non-zero exit *and* the absence of
  the output file, because "exits non-zero" alone would have passed
  while a partial file was still left on disk.
* `instar compare` on a differencing VHDX reported "Content mismatch
  at offset 0!" -- an undiagnosed generic failure with no hint that a
  parent was involved (issue #548). `test_compare_self_is_refused_not_
  mismatch` asserts that string never comes back.

Deliberately *not* asserted here: composition. The composed goldens
(`vhd-diff-aligned-composed.raw`, `vhd-diff-mixed-composed.raw`,
`vhdx-diff-composed.raw`) are phase 11-16 material; using them here
would assert behaviour that does not exist.

The classes are:

* `DifferencingTestBase` -- fixture table, the expected message, and
  the per-op runners this suite needs beyond the ones in `base.py`.
* `TestDifferencingRefusal` -- one test per composing operation
  (convert, dd, compare, bench, check, measure) over every
  differencing fixture.
* `TestDifferencingConvertLeavesNoOutput` -- issue #547's core.
* `TestDifferencingDdMatchesConvert` -- the only record in the tree
  that `dd` and `convert` share a guest binary.
* `TestDifferencingMapStillRefuses` -- regression guard on map's own,
  older refusal.
* `TestDifferencingInfoReports` -- `info` reports, it does not refuse.
* `TestDifferencingParentAbsent` -- the refusal does not depend on the
  parent file existing.
* `TestDifferencingNegativeControls` -- the plain dynamic parents of
  these chains must keep working, so the refusal is not over-broad.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# Every differencing fixture, with the format name that must appear in
# the refusal message. `vhd-differencing` is a dynamic VHD patched to
# disk type 4 whose parent name field is all zeroes, so `info` reports
# no backing file for it; it is still a differencing image and the
# composing operations must still refuse it. The two `*-diff-child-*`
# fixtures are real chains with a real parent beside them.
DIFFERENCING_FIXTURES = (
    ('vhd-diff-child-aligned', 'VHD'),
    ('vhd-differencing', 'VHD'),
    ('vhdx-diff-child', 'VHDX'),
)

# The subset with a real, resolvable parent. Used where the test needs
# `info` to report a parent name, which `vhd-differencing` cannot do.
DIFFERENCING_CHAIN_FIXTURES = (
    ('vhd-diff-child-aligned', 'vhd-diff-parent.vhd'),
    ('vhdx-diff-child', '.\\vhdx-diff-parent.vhdx'),
)

# The plain dynamic base disks of the two real chains. These are NOT
# differencing and must keep working normally.
NEGATIVE_CONTROL_FIXTURES = ('vhd-diff-parent', 'vhdx-diff-parent')

# `map` refuses with its own, older text and its own error code. It
# predates this phase for VHD; the VHDX arm was added in step 4b
# because removing `VhdxState::init`'s `has_parent` rejection would
# otherwise have let map emit a differencing VHDX's parent blocks as
# holes.
MAP_REFUSAL = (
    'map: source has a backing/parent reference; chain composition is '
    'deferred (see PLAN-map.md)'
)
MAP_ERROR_CODE = 'map: guest reported error code 3'


class DifferencingTestBase(InstarTestBase):
    """Shared fixture handling and runners for the differencing suite."""

    def expected_refusal(self, op: str, format_name: str) -> str:
        """The exact refusal sentence for one operation and format.

        Rendered by `differencing_refusal_error` in
        `src/vmm/src/main.rs`. The wording is user-visible and is
        asserted verbatim: a reworded message is a behaviour change
        that should surface here rather than pass silently.
        """
        return (
            f'{op}: source is a differencing {format_name} image whose '
            f'parent instar cannot yet compose; composition is deferred '
            f'(see PLAN-differencing.md phases 11-16)'
        )

    def differencing_image(self, image_id: str) -> Path:
        """Resolve a differencing fixture, skipping if it is absent."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        return image.path

    def run_instar_measure(self, *args, timeout=60):
        """Invoke `instar measure`. Returns (stdout, stderr, rc)."""
        return self._run_instar('measure', args, timeout)

    def run_instar_map(self, *args, timeout=60):
        """Invoke `instar map`. Returns (stdout, stderr, rc)."""
        return self._run_instar('map', args, timeout)

    def run_instar_bench(self, *args, timeout=120):
        """Invoke `instar bench`. Returns (stdout, stderr, rc).

        Timeout 120s because bench spins up the guest VMM, matching
        the runner in test_bench.py.
        """
        return self._run_instar('bench', args, timeout)

    def _run_instar(self, subcommand, args, timeout):
        """Run one instar subcommand and capture its output."""
        instar = self.get_instar_binary()
        cmd = [str(instar), subcommand, *[str(a) for a in args]]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def assert_refused(self, op, format_name, stdout, stderr, rc, context):
        """Assert one run refused with the phase 4 message.

        Exit code 1 is asserted exactly, not merely as non-zero. For
        `check` in particular that matters: exit 2 means corruption,
        and step 4b deliberately classified a differencing source away
        from corruption, so a future 2 here would be a regression even
        though it is non-zero.
        """
        expected = self.expected_refusal(op, format_name)
        self.assertEqual(
            1, rc,
            f'{context}: expected exit 1, got {rc}; '
            f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
        )
        self.assertIn(
            expected, stderr,
            f'{context}: expected refusal message on stderr; '
            f'stderr={stderr!r}'
        )


class TestDifferencingRefusal(DifferencingTestBase):
    """Every composing operation refuses every differencing fixture.

    One test per operation, each iterating the fixture table so a
    failure names the fixture that broke. The operation names in the
    assertions are the names the user typed, which is what the host
    formatter is handed.
    """

    def test_convert_refuses(self):
        """`convert -O raw` refuses and writes nothing."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'out.raw'
                stdout, stderr, rc = self.run_instar_convert(
                    source, out, output_format='raw'
                )
                self.assert_refused(
                    'convert', format_name, stdout, stderr, rc, image_id
                )
                self.assertFalse(
                    out.exists(),
                    f'{image_id}: convert must leave no output file, '
                    f'found one of {out.stat().st_size if out.exists() else 0}'
                    f' bytes'
                )

    def test_dd_refuses(self):
        """`dd` refuses and writes nothing."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'out.raw'
                stdout, stderr, rc = self.run_instar_dd(
                    [f'if={source}', f'of={out}']
                )
                self.assert_refused(
                    'dd', format_name, stdout, stderr, rc, image_id
                )
                self.assertFalse(
                    out.exists(),
                    f'{image_id}: dd must leave no output file'
                )

    def test_compare_refuses(self):
        """`compare` refuses a differencing source."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_compare(source, source)
            self.assert_refused(
                'compare', format_name, stdout, stderr, rc, image_id
            )

    def test_bench_refuses(self):
        """`bench` refuses a differencing source."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_bench('-c', '4', source)
            self.assert_refused(
                'bench', format_name, stdout, stderr, rc, image_id
            )

    def test_check_refuses(self):
        """`check` refuses a differencing source with exit 1, not 2.

        Exit 2 is check's corruption code. A differencing source is
        not corrupt -- it is incomplete -- so step 4b reports it as a
        refusal instead. `assert_refused` pins the 1.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_check(source)
            self.assert_refused(
                'check', format_name, stdout, stderr, rc, image_id
            )

    def test_measure_refuses(self):
        """`measure` refuses a differencing source."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_measure(source)
            self.assert_refused(
                'measure', format_name, stdout, stderr, rc, image_id
            )

    def test_compare_self_is_refused_not_mismatch(self):
        """Issue #548: an image compared with itself must not "differ".

        Before phase 4 a differencing source reached sector
        composition, read the parent's sectors as zeroes on both sides
        of the comparison for VHD and failed opaquely for VHDX. The
        VHDX case surfaced as "Content mismatch at offset 0!", which
        told the user nothing about the parent. That string must never
        come back, so its absence is asserted explicitly rather than
        merely implied by the refusal assertion above.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_compare(source, source)
            self.assert_refused(
                'compare', format_name, stdout, stderr, rc, image_id
            )
            combined = stdout + stderr
            self.assertNotIn(
                'Content mismatch', combined,
                f'{image_id}: issue #548 regression -- compare reported a '
                f'content mismatch instead of refusing; output={combined!r}'
            )
            self.assertNotIn(
                'Images are identical', combined,
                f'{image_id}: compare must refuse, not claim a verdict; '
                f'output={combined!r}'
            )


class TestDifferencingConvertLeavesNoOutput(DifferencingTestBase):
    """Issue #547: `convert -O raw` produced a wrong file and exited 0.

    `TestDifferencingRefusal.test_convert_refuses` already checks the
    output file, but this states the defect on its own so the reason
    the check exists survives any later refactor of that loop. The
    output path is inside a fresh temporary directory, so "the file
    does not exist" cannot be satisfied by a leftover from an earlier
    test.
    """

    def test_convert_raw_writes_no_file(self):
        """No output file survives a refused convert, for any fixture."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'issue-547.raw'
                stdout, stderr, rc = self.run_instar_convert(
                    source, out, output_format='raw'
                )
                self.assertEqual(
                    1, rc,
                    f'{image_id}: convert exited {rc}, expected 1; '
                    f'stderr={stderr!r}'
                )
                self.assertEqual(
                    [], list(Path(tmp).iterdir()),
                    f'{image_id}: convert left files behind in its output '
                    f'directory: {[p.name for p in Path(tmp).iterdir()]}'
                )
                self.assertIn(
                    self.expected_refusal('convert', format_name), stderr
                )

    def test_convert_to_qcow2_writes_no_file(self):
        """The refusal is not specific to a raw target.

        The defect was reported against `-O raw`, but the refusal
        lives at the source-reading entry point, so a qcow2 target
        must be refused identically. If this ever diverges from the
        raw case, the refusal has been attached to the writer rather
        than the reader.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'out.qcow2'
                stdout, stderr, rc = self.run_instar_convert(
                    source, out, output_format='qcow2'
                )
                self.assert_refused(
                    'convert', format_name, stdout, stderr, rc, image_id
                )
                self.assertEqual(
                    [], list(Path(tmp).iterdir()),
                    f'{image_id}: convert -O qcow2 left files behind'
                )


class TestDifferencingDdMatchesConvert(DifferencingTestBase):
    """`dd` and `convert` must refuse identically.

    This is the only thing in the tree recording that the two share an
    implementation. There is no `src/operations/dd`: `run_dd` in
    `src/vmm/src/main.rs` builds a convert execution and calls
    `execute_convert`, so `dd` inherits convert's guest binary and
    therefore convert's refusal. Nothing else -- no comment, no type,
    no test -- would catch the two diverging, which is exactly what
    would happen if someone gave `dd` its own read path and forgot the
    differencing check. Hence the assertion is on the messages being
    the same sentence rather than on each being separately correct.
    """

    def test_dd_and_convert_give_the_same_refusal(self):
        """Both refusals differ only in the leading operation name."""
        for image_id, _format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                convert_out = Path(tmp) / 'convert.raw'
                _, convert_err, convert_rc = self.run_instar_convert(
                    source, convert_out, output_format='raw'
                )
                dd_out = Path(tmp) / 'dd.raw'
                _, dd_err, dd_rc = self.run_instar_dd(
                    [f'if={source}', f'of={dd_out}']
                )

            self.assertEqual(
                convert_rc, dd_rc,
                f'{image_id}: convert exited {convert_rc} but dd exited '
                f'{dd_rc}; dd shares convert\'s guest binary and must '
                f'refuse identically'
            )
            convert_reason = self._refusal_reason('convert', convert_err)
            dd_reason = self._refusal_reason('dd', dd_err)
            self.assertEqual(
                convert_reason, dd_reason,
                f'{image_id}: dd and convert gave different refusals. '
                f'convert: {convert_err!r} dd: {dd_err!r}'
            )
            self.assertIn(
                'differencing', convert_reason,
                f'{image_id}: neither op refused for the expected reason; '
                f'convert stderr={convert_err!r}'
            )

    def _refusal_reason(self, op, stderr):
        """Strip the leading `<op>: ` from the refusal sentence.

        Returns the remainder of the first line mentioning the
        operation, so two operations' messages can be compared for the
        part that must agree.
        """
        marker = f'{op}: '
        index = stderr.find(marker)
        self.assertNotEqual(
            -1, index,
            f'expected a message beginning {marker!r} in {stderr!r}'
        )
        return stderr[index + len(marker):].strip().rstrip('"')


class TestDifferencingMapStillRefuses(DifferencingTestBase):
    """`map` keeps its own, older refusal.

    `map` was refusing a differencing VHD before this phase, with
    different wording and its own guest error code, and step 4b left
    that precedent in place rather than migrating it. Its VHDX arm,
    however, is new: map's VHDX safety came entirely from the
    `VhdxState::init` rejection that step 4b removed, so without the
    added arm map would have started emitting a differencing VHDX's
    parent blocks as holes -- a silent wrong answer of exactly the
    kind this phase exists to stop. Both arms are pinned here.
    """

    def test_map_refuses_with_its_own_message(self):
        """map refuses every differencing fixture, error code 3."""
        for image_id, _format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_map(source)
            self.assertEqual(
                1, rc,
                f'{image_id}: expected exit 1 from map, got {rc}; '
                f'stdout={stdout[:400]!r}'
            )
            self.assertIn(
                MAP_REFUSAL, stderr,
                f'{image_id}: map must keep its own refusal wording; '
                f'stderr={stderr!r}'
            )
            self.assertIn(
                MAP_ERROR_CODE, stderr,
                f'{image_id}: map must report guest error code 3 '
                f'(ERROR_HAS_BACKING); stderr={stderr!r}'
            )

    def test_map_emits_no_extents_for_a_differencing_source(self):
        """map prints its header but no extent rows before refusing.

        An extent row here would mean map had walked the child's block
        allocation table and reported parent-owned regions as holes.
        """
        for image_id, _format_name in DIFFERENCING_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, _stderr, _rc = self.run_instar_map(source)
            rows = [
                line for line in stdout.splitlines()
                if line.strip() and not line.startswith('Offset')
            ]
            self.assertEqual(
                [], rows,
                f'{image_id}: map emitted extent rows for a differencing '
                f'source: {rows}'
            )


class TestDifferencingInfoReports(DifferencingTestBase):
    """`info` reports the parent; it does not refuse.

    `info` composes nothing, so it has no wrong answer to give, and
    refusing would remove the only way to inspect an image the rest of
    the tool declines to read -- which is precisely when a user needs
    it. Decision 4 of the phase plan.
    """

    def test_info_human_reports_the_parent(self):
        """Human `info` exits 0 and names the backing file."""
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_info(source)
            self.assertEqual(
                0, rc,
                f'{image_id}: info must not refuse a differencing image; '
                f'stderr={stderr!r}'
            )
            self.assertIn(
                f'backing file: {parent_name}', stdout,
                f'{image_id}: info must report the parent; stdout={stdout!r}'
            )
            self.assertNotIn(
                'differencing', stdout + stderr,
                f'{image_id}: info must report, not refuse; '
                f'output={(stdout + stderr)!r}'
            )

    def test_info_json_reports_the_parent(self):
        """`info --output json` exits 0 and carries backing-filename."""
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_info(
                source, output_format='json'
            )
            self.assertEqual(
                0, rc,
                f'{image_id}: info --output json must not refuse; '
                f'stderr={stderr!r}'
            )
            parsed = json.loads(stdout)
            self.assertEqual(
                parent_name, parsed.get('backing-filename'),
                f'{image_id}: unexpected backing-filename in {stdout!r}'
            )
            self.assertIn(
                'full-backing-filename', parsed,
                f'{image_id}: expected a resolved parent path in {stdout!r}'
            )

    def test_info_reports_the_disk_type_4_fixture_without_a_parent(self):
        """`vhd-differencing` has an all-zero parent name.

        It is a dynamic VHD patched to disk type 4, so it is refused by
        the composing operations but has no parent name for `info` to
        report. `info` must still exit 0 and identify the format rather
        than treating the empty name as an error.
        """
        source = self.differencing_image('vhd-differencing')
        stdout, stderr, rc = self.run_instar_info(source)
        self.assertEqual(
            0, rc, f'info must not refuse vhd-differencing; stderr={stderr!r}'
        )
        self.assertIn('file format: vpc', stdout, f'stdout={stdout!r}')

    def test_info_chain_stops_at_a_vhd_parent(self):
        """`info --chain` reports a 1-image chain and exits 0.

        Host-side chain discovery stops at a VHD or VHDX parent --
        walking it is phase 11's business -- so the chain listing has
        one entry, annotated with the parent reference it did not
        follow. This pins the current boundary; phase 11 will change it
        and should have to change this test to do so.
        """
        for image_id, _parent_name in DIFFERENCING_CHAIN_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_info(source, chain=True)
            self.assertEqual(
                0, rc,
                f'{image_id}: info --chain must not error; stderr={stderr!r}'
            )
            self.assertIn(
                'Chain: 1 image(s)', stdout,
                f'{image_id}: expected a one-image chain; stdout={stdout!r}'
            )


class TestDifferencingParentAbsent(DifferencingTestBase):
    """The refusal does not depend on the parent file existing.

    The host walks the backing chain before the guest runs, so the
    natural failure for an orphaned child is "Backing file not found"
    -- a different, more alarming error that says nothing about
    composition being deferred. Step 4b changed `discover_backing_chain`
    so that a VHD or VHDX parent reference is recorded without being
    resolved, which makes the refusal unconditional. Copying the child
    alone into an empty directory is the only way to exercise that.
    """

    def _orphaned_copy(self, image_id):
        """Copy one child fixture, alone, into a fresh directory."""
        source = self.differencing_image(image_id)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        target = Path(tmp) / source.name
        shutil.copy2(source, target)
        self.assertEqual(
            [target.name], [p.name for p in Path(tmp).iterdir()],
            'the orphan directory must hold the child and nothing else'
        )
        return target

    def test_convert_refuses_an_orphaned_child(self):
        """convert refuses, and does not complain about a missing parent."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            orphan = self._orphaned_copy(image_id)
            out = orphan.parent / 'out.raw'
            stdout, stderr, rc = self.run_instar_convert(
                orphan, out, output_format='raw'
            )
            self.assert_refused(
                'convert', format_name, stdout, stderr, rc,
                f'{image_id} (orphaned)'
            )
            self.assertNotIn(
                'Backing file not found', stderr,
                f'{image_id}: the refusal must not be contingent on the '
                f'parent existing; stderr={stderr!r}'
            )
            self.assertFalse(
                out.exists(),
                f'{image_id}: orphaned convert left an output file'
            )

    def test_check_refuses_an_orphaned_child(self):
        """check refuses an orphaned child for the same reason."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            orphan = self._orphaned_copy(image_id)
            stdout, stderr, rc = self.run_instar_check(orphan)
            self.assert_refused(
                'check', format_name, stdout, stderr, rc,
                f'{image_id} (orphaned)'
            )
            self.assertNotIn(
                'Backing file not found', stderr,
                f'{image_id}: stderr={stderr!r}'
            )


class TestDifferencingNegativeControls(DifferencingTestBase):
    """The chains' plain dynamic base disks must keep working.

    `vhd-diff-parent.vhd` and `vhdx-diff-parent.vhdx` are the parents
    of the two real chains: ordinary dynamic images with no parent of
    their own. If the tests above pass but these fail, the refusal has
    been attached to the format or to the fixture directory rather
    than to the differencing flag, and every dynamic VHD and VHDX in
    the wild has just stopped working.
    """

    def test_convert_succeeds(self):
        """convert produces an output file and exits 0."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'out.raw'
                stdout, stderr, rc = self.run_instar_convert(
                    source, out, output_format='raw'
                )
                self.assertEqual(
                    0, rc,
                    f'{image_id}: convert must still succeed; '
                    f'stderr={stderr!r}'
                )
                self.assertTrue(
                    out.exists() and out.stat().st_size > 0,
                    f'{image_id}: convert produced no output'
                )

    def test_check_succeeds(self):
        """check reports a clean image and exits 0."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_check(source)
            self.assertEqual(
                0, rc,
                f'{image_id}: check must still succeed; stderr={stderr!r}'
            )
            self.assertIn(
                'No errors were found', stdout,
                f'{image_id}: stdout={stdout!r}'
            )

    def test_measure_succeeds(self):
        """measure reports sizes and exits 0."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_measure(source)
            self.assertEqual(
                0, rc,
                f'{image_id}: measure must still succeed; stderr={stderr!r}'
            )
            self.assertIn(
                'required size:', stdout, f'{image_id}: stdout={stdout!r}'
            )

    def test_compare_self_is_identical(self):
        """compare of the parent with itself reports identical images."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_compare(source, source)
            self.assertEqual(
                0, rc,
                f'{image_id}: compare must still succeed; stderr={stderr!r}'
            )
            self.assertIn(
                'Images are identical', stdout,
                f'{image_id}: stdout={stdout!r}'
            )

    def test_map_succeeds(self):
        """map emits extents and exits 0."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_map(source)
            self.assertEqual(
                0, rc,
                f'{image_id}: map must still succeed; stderr={stderr!r}'
            )
            rows = [
                line for line in stdout.splitlines()
                if line.strip() and not line.startswith('Offset')
            ]
            self.assertNotEqual(
                [], rows,
                f'{image_id}: map produced no extents; stdout={stdout!r}'
            )

    def test_info_reports_no_backing_file(self):
        """info shows no parent for a base disk."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            source = self.differencing_image(image_id)
            stdout, stderr, rc = self.run_instar_info(source)
            self.assertEqual(
                0, rc, f'{image_id}: info failed; stderr={stderr!r}'
            )
            self.assertNotIn(
                'backing file:', stdout,
                f'{image_id}: a base disk has no parent; stdout={stdout!r}'
            )
