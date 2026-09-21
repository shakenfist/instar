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
* `TestDifferencingAdversarialLocators` -- the six hostile
  parent-locator fixtures: refused by the composing ops, reported but
  never followed by `info`.
* `TestDifferencingInfoValidatesTheDynamicHeader` -- `info` will not
  decode a parent name out of a `data_offset` that does not point at a
  `cxsparse` header.
* `TestDifferencingCreateRefusesAsBacking` -- `create -b` fails closed
  on a differencing base, which is what the removed `VhdxState::init`
  rejection used to do for VHDX.
* `TestDifferencingLibvhdiOracle` -- the only place an independent
  parser reads a differencing child instar wrote and is asked whether
  it names the intended parent.
"""

import json
import re
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
    ('vhd-diff-child-mixed', 'VHD'),
    ('vhd-differencing', 'VHD'),
    ('vhdx-diff-child', 'VHDX'),
)

# Structurally valid differencing VHDs whose parent name and locator
# entries were built to be hostile: absolute POSIX paths, relative
# traversal, UNC, a URL, an unterminated 512-byte name, and eight
# mutually-contradictory locator entries. They live in
# `custom/audit/` rather than `custom/format-coverage/` because their
# point is what a reader must *not* do with a locator, not what a
# differencing image looks like.
#
# They matter to this suite for two reasons. The composing operations
# must refuse them like any other differencing image -- a hostile
# locator must not become a route to a read instar would otherwise
# decline. And `info`, which reports rather than refuses, now prints
# these strings: the refusal has moved the attacker-shaped path from
# "never seen" to "rendered in a user-facing field", so what is
# rendered needs pinning.
ADVERSARIAL_LOCATOR_FIXTURES = (
    ('vhd-diff-locator-etc-passwd', '/etc/passwd'),
    ('vhd-diff-locator-dotdot', '../../../etc/passwd'),
    ('vhd-diff-locator-unc', '\\\\attacker\\share\\probe'),
    ('vhd-diff-locator-url', 'http://attacker.example/probe'),
    ('vhd-diff-locator-overlong', '/overlong-'),
    ('vhd-diff-locator-conflicting', 'conflict-parent-name.vhd'),
)

# The subset with a real, resolvable parent. Used where the test needs
# `info` to report a parent name, which `vhd-differencing` cannot do.
#
# All three are bare POSIX names. The VHDX entry used to read
# `.\\vhdx-diff-parent.vhdx`, the raw contents of the locator's
# `relative_path` key -- a genuine Hyper-V child records its parent in
# the Windows convention, and `info` reported those bytes unchanged.
# This table was where the asymmetry showed: the same column held bare
# names for VHD, whose parent *unicode name* field keeps the path as
# typed, and a Windows path for VHDX, which has no such field. `info`
# now renders the relative key back into POSIX convention, so
# `full-backing-filename` resolves instead of yielding
# `<dir>/.\\vhdx-diff-parent.vhdx`, which opens nothing.
DIFFERENCING_CHAIN_FIXTURES = (
    ('vhd-diff-child-aligned', 'vhd-diff-parent.vhd'),
    ('vhd-diff-child-mixed', 'vhd-diff-parent.vhd'),
    ('vhdx-diff-child', 'vhdx-diff-parent.vhdx'),
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
            f'(see PLAN-differencing.md)'
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_compare(source, source)
                self.assert_refused(
                    'compare', format_name, stdout, stderr, rc, image_id
                )

    def test_bench_refuses(self):
        """`bench` refuses a differencing source."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_check(source)
                self.assert_refused(
                    'check', format_name, stdout, stderr, rc, image_id
                )

    def test_measure_refuses(self):
        """`measure` refuses a differencing source."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
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
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_info(source)
                self.assertEqual(
                    0, rc, f'{image_id}: info failed; stderr={stderr!r}'
                )
                self.assertNotIn(
                    'backing file:', stdout,
                    f'{image_id}: a base disk has no parent; stdout={stdout!r}'
                )


class TestDifferencingAdversarialLocators(DifferencingTestBase):
    """The six hostile parent-locator fixtures.

    These exist because the refusal changed what a hostile locator can
    reach. Before it, a differencing VHD's parent name was never
    decoded at all, so the content of these fields did not matter. Now
    `info` decodes and prints them, and the host resolves them into an
    "actual path" -- so the fixtures that were written to be nasty are
    the ones that need assertions.

    Two properties are pinned:

    * the composing operations refuse them exactly like any other
      differencing image, so a hostile locator is not a route to a read
      instar would otherwise decline; and
    * `info` *reports* the string without acting on it -- in particular
      `--chain` stops at the one image rather than following the
      locator to whatever it names.
    """

    def test_convert_refuses_every_locator_fixture(self):
        """A hostile locator does not change the refusal."""
        for image_id, _expected in ADVERSARIAL_LOCATOR_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'out.raw'
                    stdout, stderr, rc = self.run_instar_convert(
                        source, out, output_format='raw'
                    )
                    self.assert_refused(
                        'convert', 'VHD', stdout, stderr, rc, image_id
                    )
                    self.assertFalse(
                        out.exists(),
                        f'{image_id}: convert must leave no output file'
                    )

    def test_check_refuses_every_locator_fixture(self):
        """`check` refuses too, with exit 1 rather than 2."""
        for image_id, _expected in ADVERSARIAL_LOCATOR_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_check(source)
                self.assert_refused(
                    'check', 'VHD', stdout, stderr, rc, image_id
                )

    def test_info_reports_the_locator_without_following_it(self):
        """`info` prints the hostile string and opens nothing.

        `info --chain` is the assertion that matters. Every one of
        these fixtures names a parent that instar must not walk to;
        `vhd-diff-locator-etc-passwd` in particular names a path that
        really does exist on the machine running the test, so a reader
        that resolved-and-opened its locator would have something to
        find. The chain must still be one image long.
        """
        for image_id, expected in ADVERSARIAL_LOCATOR_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_info(source, chain=True)
                self.assertEqual(
                    0, rc,
                    f'{image_id}: info must not refuse; stderr={stderr!r}'
                )
                self.assertIn(
                    'Chain: 1 image(s)', stdout,
                    f'{image_id}: the chain must stop at the child -- '
                    f'instar cannot compose a parent, and these locators '
                    f'must never be followed; stdout={stdout!r}'
                )
                self.assertIn(
                    expected, stdout,
                    f'{image_id}: expected the locator to be reported '
                    f'verbatim; stdout={stdout!r}'
                )

    def test_info_json_names_the_parent_as_a_vhd(self):
        """`backing-filename-format` says vpc, not qcow2.

        `backing-filename-format` defaults to "qcow2" when no format is
        recorded, which is right for a qcow2 v2 image with no
        backing-format header extension. A differencing VHD has no such
        extension either, but its parent is a VHD by definition --
        SPEC(VHD) requires the parent to be the same format as the
        child -- so the default would put a false claim in a field
        callers parse.
        """
        for image_id, expected in ADVERSARIAL_LOCATOR_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, _stderr, rc = self.run_instar_info(
                    source, output_format='json'
                )
                self.assertEqual(0, rc, f'{image_id}: info must succeed')
                data = json.loads(stdout)
                self.assertEqual(
                    'vpc', data.get('backing-filename-format'),
                    f'{image_id}: a differencing VHD\'s parent is a VHD; '
                    f'got {data.get("backing-filename-format")!r}'
                )
                self.assertIn(
                    expected, data.get('backing-filename', ''),
                    f'{image_id}: expected the locator reported verbatim '
                    f'in JSON; got {data.get("backing-filename")!r}'
                )


class TestDifferencingInfoValidatesTheDynamicHeader(DifferencingTestBase):
    """`info` will not decode a parent name out of arbitrary bytes.

    A VHD footer's `disk_type` and `data_offset` are both image-
    controlled. Without a cookie check, an image can claim
    `disk_type = 4` and point `data_offset` at any offset in the file,
    and `info` would decode 512 bytes from there as UTF-16BE and print
    them as `backing file:` -- untrusted content promoted into a
    structured, user-facing field. `crates/vhd` guards its own reads of
    this structure with the `cxsparse` cookie, and `info` now calls
    that same parser rather than trusting the offset.

    The image is built here rather than shipped as a fixture: it is one
    field and two checksums away from `vhd-diff-child-aligned`, and
    building it in the test keeps the patch visible next to the
    assertion.
    """

    FOOTER_SIZE = 512
    FOOTER_DATA_OFFSET = 16
    FOOTER_CHECKSUM_OFFSET = 64

    def _repair_footer_checksum(self, data: bytearray, offset: int) -> None:
        """Recompute one VHD footer's ones-complement checksum in place."""
        data[offset + self.FOOTER_CHECKSUM_OFFSET:
             offset + self.FOOTER_CHECKSUM_OFFSET + 4] = b'\x00\x00\x00\x00'
        total = sum(data[offset:offset + self.FOOTER_SIZE]) & 0xffffffff
        checksum = (~total) & 0xffffffff
        data[offset + self.FOOTER_CHECKSUM_OFFSET:
             offset + self.FOOTER_CHECKSUM_OFFSET + 4] = \
            checksum.to_bytes(4, 'big')

    def _build_image_with_bogus_data_offset(
        self, destination: Path, data_offset: int, plant: bytes = b''
    ) -> None:
        """Copy the aligned child, repointing `data_offset` at `data_offset`.

        Both footers (the copy at offset 0 and the real one at the end
        of the file) are patched and re-checksummed, so the image stays
        structurally valid apart from the one field under test.
        """
        source = self.differencing_image('vhd-diff-child-aligned')
        data = bytearray(source.read_bytes())
        if plant:
            # `data_offset + 64` is where the parent unicode name lives.
            at = data_offset + 64
            data[at:at + len(plant)] = plant
        for offset in (0, len(data) - self.FOOTER_SIZE):
            data[offset + self.FOOTER_DATA_OFFSET:
                 offset + self.FOOTER_DATA_OFFSET + 8] = \
                data_offset.to_bytes(8, 'big')
            self._repair_footer_checksum(data, offset)
        destination.write_bytes(data)

    def test_info_ignores_a_parent_name_outside_a_dynamic_header(self):
        """Text reachable via a bogus `data_offset` is not a backing file."""
        planted = 'PWNED-SECRET.vhd'.encode('utf-16-be') + b'\x00\x00'
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'bogus-data-offset.vhd'
            # 0x1fffc0 + 64 == 0x200000, comfortably inside the image's
            # data region and nowhere near a `cxsparse` cookie.
            self._build_image_with_bogus_data_offset(
                image, 0x1fffc0, plant=planted
            )
            stdout, stderr, rc = self.run_instar_info(image)
            self.assertEqual(
                0, rc, f'info must still succeed; stderr={stderr!r}'
            )
            self.assertNotIn(
                'PWNED-SECRET', stdout,
                'info decoded image content as a parent name: the '
                'dynamic-header cookie check is not doing its job; '
                f'stdout={stdout!r}'
            )
            self.assertNotIn(
                'backing file', stdout,
                'no parent should be reported when `data_offset` does '
                f'not point at a dynamic header; stdout={stdout!r}'
            )

    def test_the_composing_ops_do_not_read_it(self):
        """The same image is not converted either -- it fails, and writes
        nothing.

        The message here is the *generic* "convert operation failed",
        not the differencing refusal, and that is correct rather than a
        gap: the differencing refusal in `init_chain_states` reads
        `VhdState`, and `VhdState::init` cannot build one without a
        valid `cxsparse` dynamic header. An image with a bogus
        `data_offset` is malformed, so it fails as malformed before its
        disk type is ever consulted.

        What matters is the property #547 was filed over, and it holds:
        no output file is produced and the exit code is non-zero. This
        test exists so that a future change that starts *reading* such
        an image -- composing it as though it had no parent, which is
        the original defect -- fails here.
        """
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'bogus-data-offset.vhd'
            self._build_image_with_bogus_data_offset(image, 0x1fffc0)
            out = Path(tmp) / 'out.raw'
            _stdout, stderr, rc = self.run_instar_convert(
                image, out, output_format='raw'
            )
            self.assertNotEqual(
                0, rc,
                f'a malformed differencing VHD must not convert; '
                f'stderr={stderr!r}'
            )
            # The typed refusal unlinks its output; a generic failure
            # leaves the stub `BackingStore::open` created. Either way
            # no sector was composed, which is the property that
            # matters -- so assert on the content, not the inode.
            self.assertEqual(
                0, out.stat().st_size if out.exists() else 0,
                'no image content may be written for an image instar '
                'could not read'
            )


class TestDifferencingCreateRefusesAsBacking(DifferencingTestBase):
    """`create -b <differencing image>` fails closed.

    Removing `VhdxState::init`'s blanket `has_parent` rejection (so the
    read entry points could refuse with a reason instead of failing
    anonymously) also removed the only thing stopping `create` from
    accepting a differencing VHDX as a backing file. An overlay on a
    base every read path refuses is a chain that can never be read
    back, so `create` now refuses both formats explicitly.

    The plain dynamic parents of the same chains must keep working --
    that is what separates "refuses a differencing base" from "refuses
    a VHD base".
    """

    EXPECTED = (
        'backing file is a differencing VHD or VHDX whose parent instar '
        'cannot yet compose'
    )

    BACKING_FORMAT = {'VHD': 'vpc', 'VHDX': 'vhdx'}

    # Extension per child format, so the overlay's name matches what it
    # actually is rather than always reading `overlay.qcow2`.
    CHILD_EXTENSION = {'qcow2': 'qcow2', 'vpc': 'vhd', 'vhdx': 'vhdx'}

    def _create_overlay(self, tmp, base, backing_format, child_format='qcow2'):
        """`instar create -f <child_format> -b <base> -F <fmt>` into a temp dir."""
        instar = self.get_instar_binary()
        overlay = Path(tmp) / f'overlay.{self.CHILD_EXTENSION[child_format]}'
        r = subprocess.run(
            [str(instar), 'create', '-f', child_format, '-b', str(base),
             '-F', backing_format, str(overlay)],
            capture_output=True, text=True, timeout=60
        )
        return overlay, r.stdout, r.stderr, r.returncode

    def test_create_refuses_a_differencing_backing_file(self):
        """Every differencing fixture is refused as `-b`."""
        for image_id, format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp) / source.name
                    shutil.copy(source, base)
                    overlay, stdout, stderr, rc = self._create_overlay(
                        tmp, base, self.BACKING_FORMAT[format_name]
                    )
                    self.assertNotEqual(
                        0, rc,
                        f'{image_id}: create -b must fail; '
                        f'stdout={stdout!r}'
                    )
                    self.assertIn(
                        self.EXPECTED, stderr,
                        f'{image_id}: expected the differencing reason, '
                        f'not a generic parse failure; stderr={stderr!r}'
                    )
                    self.assertFalse(
                        overlay.exists(),
                        f'{image_id}: no overlay should be left behind'
                    )

    # Format instar would give the child if it were foolish enough to
    # accept the same-format differencing parent above it. VHD's arm of
    # `probe_backing` (main.rs:313) and VHDX's (main.rs:343) are separate
    # code paths, and the test above always requests a qcow2 child, so
    # neither arm is exercised with a child in its own native format.
    SAME_FORMAT_CHILD = {'VHD': 'vpc', 'VHDX': 'vhdx'}

    def test_create_refuses_a_differencing_backing_file_for_a_same_format_child(self):
        """A same-format child is refused a differencing parent too.

        `test_create_refuses_a_differencing_backing_file` above proves the
        refusal fires, but only into a qcow2 child, for every fixture. That
        leaves a distinct, reachable input unexercised: a vpc child offered
        a differencing VHD parent, and a vhdx child offered a differencing
        VHDX parent. A child accepted here would itself be a structurally
        valid differencing image naming a parent that is itself
        differencing -- a chain instar cannot compose -- and nothing else
        in the suite looks at that shape.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            child_format = self.SAME_FORMAT_CHILD[format_name]
            with self.subTest(image=image_id, child_format=child_format):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp) / source.name
                    shutil.copy(source, base)
                    overlay, stdout, stderr, rc = self._create_overlay(
                        tmp, base, self.BACKING_FORMAT[format_name],
                        child_format=child_format,
                    )
                    self.assertNotEqual(
                        0, rc,
                        f'{image_id}: create -b must fail for a '
                        f'{child_format} child too; stdout={stdout!r}'
                    )
                    self.assertIn(
                        self.EXPECTED, stderr,
                        f'{image_id}: expected the differencing reason, '
                        f'not a generic parse failure; stderr={stderr!r}'
                    )
                    self.assertFalse(
                        overlay.exists(),
                        f'{image_id}: no {child_format} overlay should be '
                        f'left behind'
                    )

    def test_create_accepts_the_plain_parents(self):
        """The negative control: a dynamic VHD/VHDX base still works."""
        for image_id in NEGATIVE_CONTROL_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                fmt = 'vhdx' if image_id.startswith('vhdx') else 'vpc'
                with tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp) / source.name
                    shutil.copy(source, base)
                    overlay, stdout, stderr, rc = self._create_overlay(
                        tmp, base, fmt
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: a plain dynamic base must still be '
                        f'accepted; stderr={stderr!r}'
                    )
                    self.assertTrue(
                        overlay.exists(),
                        f'{image_id}: overlay was not created'
                    )


class TestDifferencingLibvhdiOracle(DifferencingTestBase):
    """An independent parser agrees a child instar wrote names its parent.

    Everything else in this suite and in `test_create.py` checks
    instar's differencing output with instar's own reader, or with
    hand-rolled struct reads written from the same understanding of the
    specification that produced the bytes. That is a closed loop: a
    field written into the wrong offset, or under the wrong key, is
    read back from the wrong offset and agrees with itself.

    libvhdi is the external oracle PLAN-differencing.md picked for
    exactly this, because qemu-img cannot serve: qemu-img reads a
    differencing child as though the parent were absent, so it has no
    opinion about which parent the child names. `vhdiinfo` does, and it
    resolves a VHD parent through the *parent unicode name* field and a
    VHDX parent through the parent identity, which are the two things
    the emitter has to get right.

    Scope, deliberately narrow (PLAN-differencing.md decision 1):
    **structure only**. Nothing here reads composed image content --
    whether instar assembles a chain the way libvhdi does is phase 15's
    question and cannot be asked before instar can compose at all. The
    split also falls on a real seam: the fields below never reach
    libvhdi's VHD sector-bitmap decoder, which is where the known
    oracle defect (defect A, see tests/manifest.json on
    `vhd-diff-child-mixed.vhd`) lives.

    Not used here: the `vhd-diff-locator-overlong.vhd` fixture, whose
    parent unicode name fills all 512 bytes with no NUL terminator.
    `vhdiinfo` over-reads two bytes past the field into the locator
    table and reports a 257th character (libvhdi defect C, recorded
    against that fixture in tests/manifest.json). That is an oracle
    defect, so the fixture is not a valid input for an oracle
    cross-check -- an assertion built on it would be asserting
    libvhdi's bug. It is exercised elsewhere in this file, where the
    reader under test is instar's.

    The parents are third-party fixtures rather than images instar
    wrote. Every image instar writes today carries the same constant
    identity (#566), so a child instar wrote against a parent instar
    wrote would satisfy an identity check by comparing zeros to zeros
    and would keep passing with the plumbing ripped out. The parent's
    expected identity is read back out of `vhdiinfo` on the parent
    rather than hardcoded, so these tests pin the emitter's behaviour
    and not the fixture's bytes.
    """

    # Field labels exactly as `vhdiinfo 20240509` prints them -- the
    # Debian 13 build (libvhdi-utils 20240509-2+b1) that
    # src/.devcontainer/Dockerfile installs, and so the build CI runs.
    # Measured, not remembered; the raw output is in the commit that
    # added this class.
    DISK_TYPE = 'Disk type'
    IDENTIFIER = 'Identifier'
    PARENT_IDENTIFIER = 'Parent identifier'
    PARENT_FILENAME = 'Parent filename'

    # The value `Disk type` takes for a differencing image of either
    # format. libvhdi calls it "Differential"; SPEC(VHD) calls the same
    # thing a differencing disk.
    DIFFERENTIAL = 'Differential'

    ZERO_GUID = '00000000-0000-0000-0000-000000000000'

    # `vhdiinfo` prints one field per line as a tab-indented label, a
    # colon, and the value. Lines at column zero are the version banner
    # and the "Virtual Hard Disk image information:" heading, which
    # carry no value and must not be parsed as fields.
    FIELD_RE = re.compile(r'^\s+(\S.*?)\s*:\s*(.*)$')

    def _vhdiinfo(self, path: Path) -> dict:
        """Parse `vhdiinfo PATH` into a {label: value} mapping."""
        r = subprocess.run(
            ['vhdiinfo', str(path)], capture_output=True, text=True, timeout=60
        )
        self.assertEqual(
            0, r.returncode,
            f'vhdiinfo failed on {path}: stdout={r.stdout!r} stderr={r.stderr!r}'
        )
        fields = {}
        for line in r.stdout.splitlines():
            match = self.FIELD_RE.match(line)
            if match:
                fields[match.group(1)] = match.group(2)
        # A parse that silently produced nothing would make every
        # assertion below vacuous, so prove the output was understood
        # before trusting any of it.
        self.assertIn(
            self.DISK_TYPE, fields,
            f'vhdiinfo output was not understood for {path}: {r.stdout!r}'
        )
        return fields

    def _stage_parent(self, image_id: str, workdir, subdirectory=None):
        """Copy a parent fixture under *workdir*; return (path, typed name).

        Copying rather than referencing in place keeps the emitted
        parent path short and relative, and keeps the test from writing
        beside the fixture. The typed name is what goes to `-b`, which
        for the VHD arm is also what `vhdiinfo` must read back.

        An absent fixture fails rather than skips: these are the only
        automated runs of the oracle against instar's own output, so a
        skip here would turn that coverage green while checking
        nothing. `InstarTestBase._load_manifest` already raises in
        `setUpClass` when there is no testdata checkout at all, so this
        covers only a checkout missing this one file.
        """
        source = self.get_image(image_id).path
        self.assertTrue(
            source.exists(),
            f'testdata is present but the parent fixture is not: {source}'
        )
        destination_dir = Path(workdir)
        if subdirectory is not None:
            destination_dir = destination_dir / subdirectory
            destination_dir.mkdir(parents=True)
        destination = destination_dir / source.name
        shutil.copyfile(source, destination)
        typed = source.name
        if subdirectory is not None:
            typed = f'{subdirectory}/{source.name}'
        return destination, typed

    def _create_child(self, workdir, fmt: str, typed_parent: str, child_name: str) -> Path:
        """`instar create -f FMT -b TYPED -F FMT CHILD`, run from *workdir*.

        `-F` is not optional: `create -b` refuses to guess a backing
        format and demands either `-F` or `-u`. Running from *workdir*
        makes the relative `-b` resolve the way a user's would, which
        is also what keeps the emitted parent path relative.
        """
        instar = self.get_instar_binary()
        r = subprocess.run(
            [str(instar), 'create', '-f', fmt, '-b', typed_parent, '-F', fmt,
             child_name],
            capture_output=True, text=True, timeout=60, cwd=str(workdir)
        )
        self.assertEqual(
            0, r.returncode,
            f'creating the {fmt} child failed: stdout={r.stdout!r} '
            f'stderr={r.stderr!r}'
        )
        child = Path(workdir) / child_name
        self.assertTrue(
            child.exists(), f'create -f {fmt} exited 0 but wrote no child'
        )
        return child

    def test_libvhdi_reads_a_vhd_child_as_naming_its_parent(self):
        """`vhdiinfo` on a VHD child reports the parent instar was given.

        Two path shapes, because the distinction between them is what
        phase 7 got wrong once and what round 4 of #581's review found.
        The `Parent filename` libvhdi reports comes from the dynamic
        header's *parent unicode name*, which keeps the path **as
        typed** -- it is emphatically not the `.\\`-prefixed, backslash
        separated rendering that goes into the parent locator table.
        A bare name cannot tell those two apart (`parent.vhd` renders
        to `.\\parent.vhd`, which merely gains a prefix); a name inside
        a subdirectory can, because `sub/parent.vhd` renders to
        `.\\sub\\parent.vhd` and the separator changes too.

        libvhdi never parses the VHD locator table at all, so nothing
        here asserts anything about it. The locator's own structure is
        pinned by `src/crates/create/tests/round_trip.rs`.
        """
        self._require_vhdiinfo()
        for subdirectory in (None, 'sub'):
            shape = 'bare' if subdirectory is None else 'subdirectory'
            with self.subTest(parent_path=shape):
                with tempfile.TemporaryDirectory() as td:
                    parent, typed = self._stage_parent(
                        'vhd-diff-parent', td, subdirectory)

                    # Derived from the parent, never hardcoded: a
                    # constant here would pin the fixture rather than
                    # the emitter, and would go stale the day the
                    # fixture is regenerated.
                    parent_fields = self._vhdiinfo(parent)
                    want_identity = parent_fields.get(self.IDENTIFIER)
                    self.assertNotEqual(
                        self.ZERO_GUID, want_identity,
                        'the parent fixture has a zero identifier, so this '
                        'test cannot tell a real identity from the '
                        'placeholder instar writes for #566'
                    )

                    child = self._create_child(td, 'vpc', typed, 'child.vhd')
                    fields = self._vhdiinfo(child)

                    self.assertEqual(
                        self.DIFFERENTIAL, fields.get(self.DISK_TYPE),
                        f'libvhdi does not read the child as differencing: '
                        f'{fields!r}'
                    )
                    self.assertEqual(
                        want_identity, fields.get(self.PARENT_IDENTIFIER),
                        f'libvhdi reads a parent identity that is not the '
                        f'parent\'s own: {fields!r}'
                    )
                    self.assertEqual(
                        typed, fields.get(self.PARENT_FILENAME),
                        f'libvhdi reads a parent filename that is not the '
                        f'path -b was given ({typed!r}): {fields!r}'
                    )

    def test_libvhdi_reads_a_vhdx_child_as_naming_its_parent(self):
        """`vhdiinfo` on a VHDX child reports the parent's linkage GUID.

        This is the assertion that replaces a much weaker one.
        `test_create.py:test_create_vhd_and_vhdx_differencing_round_trip`
        proves the VHDX linkage with a whole-file substring search for
        the GUID's UTF-16 bytes, which would pass with the GUID written
        under the wrong key, in a stray second locator item, or
        anywhere else in the file at all. A parser that has to locate
        the metadata region, find the parent locator item and read the
        entry cannot be satisfied that way. That test is left alone;
        this one is independent coverage beside it, not a rewrite of
        it.

        What libvhdi calls a VHDX's `Identifier` is the **active**
        header's `DataWriteGuid` -- the two headers carry different
        GUIDs and the one with the higher sequence number wins -- and
        the child's `Parent identifier` is its `parent_linkage`. Asking
        the oracle for the parent's own `Identifier` rather than
        reading the parent's header bytes here means this test does not
        contain a second implementation of "which header is active" to
        disagree with the first.

        Only one path shape, unlike the VHD arm above: `vhdiinfo`
        prints **no** `Parent filename` line for a VHDX, with or
        without `-v` -- measured against 20240509, which has no such
        field for this format. So there is no oracle-visible path to
        vary, and an assertion written against that line would be an
        assertion against a line that does not exist. The VHDX parent
        locator's path key is pinned structurally instead, by
        `src/crates/create/tests/round_trip.rs:vhdx_differencing_path_key_follows_the_path`.
        """
        self._require_vhdiinfo()
        with tempfile.TemporaryDirectory() as td:
            parent, typed = self._stage_parent('vhdx-diff-parent', td)

            parent_fields = self._vhdiinfo(parent)
            want_identity = parent_fields.get(self.IDENTIFIER)
            self.assertNotEqual(
                self.ZERO_GUID, want_identity,
                'the parent fixture has a zero DataWriteGuid, so this test '
                'cannot tell a real identity from the placeholder instar '
                'writes for #566'
            )

            child = self._create_child(td, 'vhdx', typed, 'child.vhdx')
            fields = self._vhdiinfo(child)

            # The File Parameters `HasParent` bit, seen from outside.
            # Nothing else in the Python suite asserts it: the round
            # trip test's VHDX arm never checks it, where its VHD arm
            # does assert disk_type == 4.
            self.assertEqual(
                self.DIFFERENTIAL, fields.get(self.DISK_TYPE),
                f'libvhdi does not read the child as differencing: {fields!r}'
            )
            self.assertEqual(
                want_identity, fields.get(self.PARENT_IDENTIFIER),
                f'libvhdi reads a parent linkage that is not the parent\'s '
                f'active-header DataWriteGuid: {fields!r}'
            )
