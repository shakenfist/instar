"""Integration tests for reading a differencing VHD or VHDX chain.

A differencing image is one whose content lives partly in a parent
file. instar composes such a chain for the operations that read
through the guest chain walker -- `convert`, `dd`, `compare`, `bench`
and `rebase` -- and declines it for the ones that do not: `map`,
`measure` and `check` read one image on its own and refuse a
differencing source by name rather than returning a wrong answer.

So this suite has two halves, and they are here together on purpose.
A user meets both in one session, and the policy only makes sense read
whole.

**What now composes.** `instar convert` of each real chain is compared
with the recorded composition of that chain, byte for byte over the
whole file. The expectation is not instar's: the three
`*-composed.raw` fixtures were written by
`scripts/create-vhd-testdata.sh` out of the same sector patterns it
wrote into the parents and children, so nothing in the read path under
test contributed a byte of them.

**What is still refused, and why that is narrower than it was.** The
guest refuses a differencing child only when its own chain holds no
device behind it, which is the case where the sectors the child leaves
to its parent have nowhere to come from. The fixtures with a parent
reference and a parent beside them compose; `vhd-differencing`, whose
disk type says differencing and whose parent name is empty, has no
parent to compose and is refused by name. So does a child whose chain
is one image long inside a device array holding two -- which is
exactly how `compare child.vhd other.raw` lays its arguments out, and
why composing against "the next device in the array" would read an
unrelated image as the parent (issue #614).

Two of the properties asserted here used to be defects, and the
assertions are shaped by them:

* `instar convert -O raw` on a differencing VHD exited 0 and wrote a
  file composed as though the parent's sectors were zero (issue #547).
  That is why the refusal tests assert the non-zero exit *and* the
  absence of the output file, and why the composition tests compare
  the whole file rather than a prefix: zeros in place of a parent's
  sectors are invisible to a spot check at offset 0.
* `instar compare` on a differencing VHDX reported "Content mismatch
  at offset 0!" -- an undiagnosed generic failure with no hint that a
  parent was involved (issue #548). `test_compare_self_is_refused_not_
  mismatch` asserts that string never comes back for a source that is
  refused.

The classes are:

* `DifferencingTestBase` -- fixture tables, the two expected refusal
  messages, and the per-op runners this suite needs beyond the ones in
  `base.py`.
* `TestDifferencingComposition` -- `convert` and `dd` read each real
  chain and produce the recorded composition exactly.
* `TestDifferencingDepthThree` -- the same, through a chain three
  images deep, so the composing arm descends past a device that is
  neither the top of the chain nor the bottom.
* `TestDifferencingBenchComposes` -- `bench` reads across the full
  declared virtual size of a real chain and across its validated
  parent- and child-owned probe sectors, since `bench` reports a
  throughput number regardless of whether the bytes underneath it
  were composed correctly.
* `TestDifferencingRebaseThroughChain` -- a differencing VHD or VHDX
  sitting in the backing chain of a qcow2 overlay `rebase` detaches,
  asserted against the detached overlay's own content, and the typed
  refusal `rebase` renders for a parentless differencing member of
  that chain.
* `TestDifferencingCompareTwoChains` -- the only operation that packs
  two chains into one device array, and the properties no single-chain
  test can be wrong about: a child composed against image2 rather than
  its own parent, a difference reported at a known offset, and a
  differencing child at the head of the *second* chain.
* `TestDifferencingRefusal` -- what each operation does with a
  differencing source it cannot compose.
* `TestDifferencingNonComposingRefusalPolicy` -- the boundary this phase
  draws, asserted on its own terms: `map`, `measure` and `check` must
  each still refuse, each naming itself rather than instar generally,
  and `check` must refuse the same way with or without `--chain`.
* `TestDifferencingConvertLeavesNoOutput` -- issue #547's core.
* `TestDifferencingDdMatchesConvert` -- the only record in the tree
  that `dd` and `convert` share a guest binary.
* `TestDifferencingMapStillRefuses` -- regression guard on map's own,
  older refusal.
* `TestDifferencingInfoReports` -- `info` reports, it does not refuse.
* `TestDifferencingParentAbsent` -- which operations depend on the
  parent file existing, and which are unchanged by it.
* `TestDifferencingNegativeControls` -- the plain dynamic parents of
  these chains must keep working, so the refusal is not over-broad.
* `TestDifferencingAdversarialLocators` -- the six hostile
  parent-locator fixtures: declined during chain discovery, reported
  but never followed by `info`.
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
# a refusal message naming it. `vhd-differencing` is a dynamic VHD
# patched to disk type 4 whose parent name field is all zeroes, so
# `info` reports no backing file for it and no walk can resolve one:
# it is the fixture every operation still refuses. The two
# `*-diff-child-*` fixtures are real chains with a real parent beside
# them, which the composing operations now read.
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

# The stderr reasons the reporting walk may give for each fixture above,
# from `UnresolvedParent::describe` (`src/vmm/src/main.rs`). A one-image
# chain alone cannot tell "the allowlist correctly rejected this" apart
# from "resolution silently failed", and these six fixtures do not all
# fail for the same reason -- measured directly against the built binary,
# not assumed:
#
# * `/etc/passwd` is an absolute POSIX path, so it is classified and
#   rejected as outside the allowlist -- the property this whole fixture
#   family exists to exercise.
# * the UNC path is classified as a Windows absolute path before the
#   allowlist is even consulted.
# * the URL, overlong and conflicting-name fixtures all name something
#   that plain path resolution never finds beside the child, so they end
#   at "was not found" rather than at the allowlist.
# * the traversal fixture gives either, and which one is a fact about the
#   host rather than about instar. `../../../` is resolved relative to the
#   fixture's own directory, so it reaches a real `/etc/passwd` -- and the
#   allowlist -- only where the testdata tree sits within three levels of
#   the root, as CI's `/testdata/` mount does. A deeper checkout, which is
#   every development clone, traverses to a path that does not exist and
#   stops at "was not found" first, because resolution canonicalises
#   before the allowlist is consulted. Both are refusals the walk
#   classified and named, which is the whole point of pinning them, so
#   the values here are tuples and the traversal fixture carries both.
ADVERSARIAL_LOCATOR_REASONS = {
    'vhd-diff-locator-etc-passwd': (
        "parent '/etc/passwd' is outside the backing file allowlist",
    ),
    'vhd-diff-locator-dotdot': (
        "parent '../../../etc/passwd' was not found",
        "parent '../../../etc/passwd' is outside the backing file allowlist",
    ),
    'vhd-diff-locator-unc': (
        "parent '\\\\attacker\\share\\probe' is a Windows absolute path and cannot be "
        "resolved on this host",
    ),
    'vhd-diff-locator-url': ("parent 'http://attacker.example/probe' was not found",),
    'vhd-diff-locator-overlong': ('was not found',),
    'vhd-diff-locator-conflicting': ("parent 'conflict-parent-name.vhd' was not found",),
}

# The errors the *composing* walk gives for the same six fixtures.
# `convert` resolves a differencing parent now, so a hostile locator is
# declined by `validate_backing_path` during chain discovery rather than
# by the guest -- one step earlier, before any device is attached. These
# strings are the allowlist's and the filesystem's, measured against the
# built binary rather than assumed.
#
# Only `/etc/passwd` reaches the allowlist: it is the one locator that
# names a path which really exists, and resolution canonicalises before
# the allowlist is consulted, so everything else stops at "not found"
# first. The traversal fixture carries both for exactly the reason the
# reporting table above explains -- whether `../../../etc/passwd` lands
# on a real file is a fact about where the testdata tree sits, not about
# instar. The UNC fixture is "not found" rather than classified: the
# Windows-absolute classifier belongs to the reporting walk, and a
# composing walk simply joins the reference to the child's directory and
# finds nothing, which refuses just as firmly.
COMPOSING_LOCATOR_REASONS = {
    'vhd-diff-locator-etc-passwd': (
        "Backing file '/etc/passwd' is outside allowed paths",
    ),
    'vhd-diff-locator-dotdot': (
        'Backing file not found',
        'is outside allowed paths',
    ),
    'vhd-diff-locator-unc': ('Backing file not found',),
    'vhd-diff-locator-url': ('Backing file not found',),
    'vhd-diff-locator-overlong': ('Backing file not found',),
    'vhd-diff-locator-conflicting': ('Backing file not found',),
}

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

# The differencing fixtures with no parent reference at all -- a disk
# type of 4 and an empty parent name. Derived from the two tables above
# rather than written out, so a fixture added to either cannot quietly
# fall out of both. These are the images for which the walk has nothing
# to resolve whatever an operation's composition capability says, so
# they are the ones that still get the typed refusal when they stand
# alone in an empty directory.
PARENTLESS_DIFFERENCING_FIXTURES = tuple(
    (image_id, format_name)
    for image_id, format_name in DIFFERENCING_FIXTURES
    if image_id not in {i for i, _ in DIFFERENCING_CHAIN_FIXTURES}
)

# The plain dynamic base disks of the two real chains. These are NOT
# differencing and must keep working normally.
NEGATIVE_CONTROL_FIXTURES = ('vhd-diff-parent', 'vhdx-diff-parent')

# The virtual size every image in these chains declares, and so the
# size of each recorded composition. Asserted against the golden
# wherever it is used rather than trusted, so a regenerated fixture of
# a different size fails loudly instead of yielding a short
# expectation.
IMAGE_VIRTUAL_SIZE = 16 * 1024 * 1024

# Each real chain and the raw image it composes to, as (child fixture,
# composed fixture, format name).
#
# The composed `.raw` fixtures are the expectation for every
# whole-file assertion below, and they are usable as one because
# nothing in instar produced them.
# `scripts/create-vhd-testdata.sh` writes the parents and children
# from per-sector byte patterns and writes the composition from the
# same patterns and the same ownership tables, in Python, in the same
# run. The libvhdi oracle did not contribute either, which matters
# most for `vhd-diff-child-mixed`: libvhdi decodes a VHD per-block
# sector bitmap with an unmasked shift, so its composition of that
# chain is wrong at sector 2, where a parent-owned and a child-owned
# sector share a bitmap byte. A recorded expectation is not exposed to
# that defect, and `vhd-diff-child-mixed` is the fixture that makes
# mixed-ownership bytes the interesting case rather than an untested
# one.
COMPOSED_CHAIN_FIXTURES = (
    ('vhd-diff-child-aligned', 'vhd-diff-aligned-composed', 'VHD'),
    ('vhd-diff-child-mixed', 'vhd-diff-mixed-composed', 'VHD'),
    ('vhdx-diff-child', 'vhdx-diff-composed', 'VHDX'),
)

# The format name `instar create`/`qemu-img` use for each child, keyed
# by the fixture id, for the places a test has to name it explicitly.
CHAIN_FIXTURE_FORMAT = {
    'vhd-diff-child-aligned': 'vpc',
    'vhd-diff-child-mixed': 'vpc',
    'vhdx-diff-child': 'vhdx',
}

# The parent each chain child resolves to, by fixture id. Derived from
# DIFFERENCING_CHAIN_FIXTURES so the two cannot disagree.
CHAIN_FIXTURE_PARENT = dict(DIFFERENCING_CHAIN_FIXTURES)

# Two probe sectors per chain, as (a sector the parent owns and the
# child leaves to it, a sector both own where the child must win).
#
# These are the sectors `TestDifferencingCompareTwoChains` alters, and
# they are what makes an altered byte attributable. A difference at the
# first says a parent-owned sector really was read from the parent; the
# absence of one at the second says the child's bitmap bit beat its
# parent's copy of the same sector. Every test that uses them first
# asserts the recorded composition says `PARENT-sector-NNNNNN` and
# `CHILD-sector-NNNNNN` at the two offsets, so a regenerated fixture
# with a different content plan fails loudly rather than quietly
# testing nothing.
#
# `vhd-diff-child-mixed`'s pair is the interesting one: sectors 1, 2
# and 3 share a single sector-bitmap byte, 1 and 3 belonging to the
# child and 2 to its parent, so a reader whose bit arithmetic is nearly
# right reports a difference at the wrong offset here rather than none
# at all.
CHAIN_PROBE_SECTORS = {
    'vhd-diff-child-aligned': (100, 8),
    'vhd-diff-child-mixed': (2, 1),
    'vhdx-diff-child': (2048, 5),
}

# `map` refuses with its own, older text and its own error code. It
# predates this phase for VHD; the VHDX arm was added in step 4b
# because removing `VhdxState::init`'s `has_parent` rejection would
# otherwise have let map emit a differencing VHDX's parent blocks as
# holes.
MAP_REFUSAL = (
    'map: source has a backing/parent reference; map reads an image '
    'on its own rather than composing a parent into it'
)
MAP_ERROR_CODE = 'map: guest reported error code 3'


class DifferencingTestBase(InstarTestBase):
    """Shared fixture handling and runners for the differencing suite."""

    #: Operation names that compose a differencing source today. Used by
    #: `assert_refusal_names_itself_not_instar` to check that a
    #: non-composing refusal never mentions one of these as though the
    #: limitation it describes were general rather than specific to the
    #: operation that refused.
    COMPOSING_OP_NAMES = ('convert', 'dd', 'compare', 'bench', 'rebase')

    def assert_refusal_names_itself_not_instar(self, op: str, message: str) -> None:
        """Assert `message` names `op` and never reads as a claim about
        every operation in the tool.

        Shared by every non-composing operation's refusal, including
        `map`'s own, older wording, so the two properties a refusal must
        keep -- naming its own operation, and never implying a blanket
        incapacity -- are defined once rather than once per operation.
        """
        self.assertTrue(
            message.startswith(f'{op}: '),
            f'{op}: message does not open by naming its own operation: '
            f'{message!r}'
        )
        self.assertNotIn(
            'instar', message.lower(),
            f'{op}: message generalises to instar rather than naming '
            f'{op}: {message!r}'
        )
        for other in self.COMPOSING_OP_NAMES:
            if other == op:
                continue
            self.assertIsNone(
                re.search(rf'\b{other}\b', message, re.IGNORECASE),
                f'{op}: message mentions {other!r}, which would make the '
                f'limitation sound general rather than specific to {op}: '
                f'{message!r}'
            )

    def expected_refusal(self, op: str, format_name: str) -> str:
        """The refusal sentence for an operation that does compose.

        Rendered by `differencing_refusal_error` in
        `src/vmm/src/main.rs`. An operation that reads a differencing
        child against its parent reaches this message only when the
        chain it was given held no parent to read, so the sentence
        says that rather than anything about instar's abilities. The
        wording is user-visible and is asserted verbatim: a reworded
        message is a behaviour change that should surface here rather
        than pass silently.
        """
        return (
            f'{op}: a differencing {format_name} image in the chain {op} '
            f'was given has no parent behind it, so the sectors it leaves '
            f'to its parent could not be composed'
        )

    def expected_non_composing_refusal(self, op: str, format_name: str) -> str:
        """The refusal sentence for an operation that composes nothing.

        `check` and `measure` decline a differencing source however
        complete its chain is, so their message must not blame the
        chain for a parent they were never going to resolve. A user
        whose `convert` of the same image has just succeeded would
        otherwise be told the parent is missing when it is sitting
        beside the child.
        """
        return (
            f'{op}: source is a differencing {format_name} image, and {op} '
            f'reads an image on its own rather than composing a parent into '
            f'it, so the sectors it leaves to its parent could not be '
            f'composed'
        )

    def assert_bytes_identical(self, produced, expected, context):
        """Compare two files in full, naming the first differing byte.

        The whole file, not a prefix and not a digest. A composition
        defect appears wherever one sector's ownership was decided
        wrongly, and zeros served in place of a parent's sectors are
        exactly what a spot check at offset 0 misses -- which is the
        shape issue #547 shipped in.
        """
        got = produced.read_bytes()
        want = expected.read_bytes()
        self.assertEqual(
            len(want), len(got),
            f'{context}: produced {len(got)} bytes, expected {len(want)}'
        )
        if got == want:
            return
        first = next(i for i in range(len(got)) if got[i] != want[i])
        differing = sum(1 for i in range(len(got)) if got[i] != want[i])
        self.fail(
            f'{context}: output differs from the recorded composition in '
            f'{differing} of {len(want)} bytes, first at offset {first} '
            f'(0x{first:x}): produced 0x{got[first]:02x}, expected '
            f'0x{want[first]:02x}'
        )

    def chain_copy(self, image_id, target_dir):
        """Copy one chain child and its parent into `target_dir`.

        Both keep their fixture basenames, which is what lets the host
        walk resolve the parent reference the child carries. Returns
        the copied child's path.
        """
        child = self.differencing_image(image_id)
        parent_name = CHAIN_FIXTURE_PARENT[image_id]
        parent = self.differencing_image(Path(parent_name).stem)
        self.assertEqual(
            parent_name, parent.name,
            f'{image_id}: the parent fixture id does not resolve to the '
            f'basename the child names'
        )
        target = Path(target_dir) / child.name
        shutil.copy2(child, target)
        shutil.copy2(parent, Path(target_dir) / parent.name)
        return target

    def differencing_image(self, image_id: str) -> Path:
        """Resolve a differencing fixture, skipping if it is absent."""
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        return image.path

    def composed_golden(self, golden_id: str) -> Path:
        """Resolve a `*-composed.raw` fixture, skipping if it is absent."""
        image = self.get_image(golden_id)
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

    def assert_refused(self, op, format_name, stdout, stderr, rc, context,
                       composing=True):
        """Assert one run refused with the message its half of the policy uses.

        `composing` picks the sentence: the composing operations say
        the chain held no parent, the non-composing ones say they read
        an image on its own. Asserting the wrong one is a real failure,
        not a cosmetic one -- the two messages send a user to different
        places.

        Exit code 1 is asserted exactly, not merely as non-zero. For
        `check` in particular that matters: exit 2 means corruption,
        and a differencing source was deliberately classified away
        from corruption, so a future 2 here would be a regression even
        though it is non-zero.
        """
        expected = (
            self.expected_refusal(op, format_name) if composing
            else self.expected_non_composing_refusal(op, format_name)
        )
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


class TestDifferencingComposition(DifferencingTestBase):
    """`convert` and `dd` read a real differencing chain correctly.

    The assertion is the whole output file against the chain's
    recorded composition, byte for byte. A digest would do as well for
    the pass case and much worse for the failure case, which is the
    one that matters here: a composition defect is a run of sectors
    taken from the wrong image, and a test that can say "first
    differing byte at 0x2a00" names the sector whose ownership was
    decided wrongly.

    Both formats and all three chains, including
    `vhd-diff-child-mixed`, whose sector bitmap deliberately puts
    parent-owned and child-owned sectors in the same bitmap byte. That
    is the chain a reader using an unmasked shift gets wrong, and the
    only one of the three where the bit arithmetic is load-bearing.

    `dd` is here beside `convert` because it has no guest binary of
    its own -- `run_dd` ends in `execute_convert` -- so composing is
    something it inherits rather than implements. Asserting it
    separately is what would catch the two being given different read
    paths.
    """

    def test_convert_matches_the_recorded_composition(self):
        """`convert -O raw` of each chain equals its recorded composition."""
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                golden = self.composed_golden(golden_id)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'composed.raw'
                    stdout, stderr, rc = self.run_instar_convert(
                        source, out, output_format='raw'
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: convert must compose a chain whose '
                        f'parent is beside it; stdout={stdout[:400]!r} '
                        f'stderr={stderr[:400]!r}'
                    )
                    self.assertTrue(
                        out.exists(),
                        f'{image_id}: convert exited 0 and wrote nothing'
                    )
                    self.assert_bytes_identical(out, golden, image_id)

    def test_dd_matches_the_recorded_composition(self):
        """`dd` composes identically to `convert`."""
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                golden = self.composed_golden(golden_id)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'composed.raw'
                    stdout, stderr, rc = self.run_instar_dd(
                        [f'if={source}', f'of={out}']
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: dd must compose a chain whose parent '
                        f'is beside it; stdout={stdout[:400]!r} '
                        f'stderr={stderr[:400]!r}'
                    )
                    self.assert_bytes_identical(out, golden, f'{image_id} (dd)')

    def test_convert_to_qcow2_composes_the_same_content(self):
        """The composition is the reader's, not the raw writer's.

        `convert -O raw` and `convert -O qcow2` share the source-side
        chain walk and differ only in what they write, so a qcow2
        target must carry the same virtual content. If this ever
        diverges from the raw case, composition has been attached to
        the writer rather than to the reader -- the same mistake the
        refused `-O qcow2` test was written to catch from the other
        side.

        The verdict comes from `instar compare` rather than from
        bytes, because a qcow2 file is not expected to be
        byte-identical to a raw one; what must be identical is the
        content, and `compare` reads both through the guest.
        """
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                golden = self.composed_golden(golden_id)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'composed.qcow2'
                    stdout, stderr, rc = self.run_instar_convert(
                        source, out, output_format='qcow2'
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: convert -O qcow2 must compose; '
                        f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                    )
                    c_stdout, c_stderr, c_rc = self.run_instar_compare(
                        out, golden
                    )
                self.assertEqual(
                    0, c_rc,
                    f'{image_id}: the qcow2 output does not match the '
                    f'recorded composition; stdout={c_stdout!r} '
                    f'stderr={c_stderr!r}'
                )
                self.assertIn(
                    'Images are identical', c_stdout,
                    f'{image_id}: stdout={c_stdout!r}'
                )

    def test_compare_against_the_recorded_composition_is_identical(self):
        """`compare` composes the child and finds no difference.

        The composing half of `compare`, stated against an expectation
        nothing in instar produced. A wrongly composed read can still
        report "identical" when both sides are wrong the same way, so
        the second side here is the recorded `.raw` rather than
        another copy of the chain.
        """
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                golden = self.composed_golden(golden_id)
                stdout, stderr, rc = self.run_instar_compare(source, golden)
                self.assertEqual(
                    0, rc,
                    f'{image_id}: compare against the recorded composition '
                    f'must report identical; stdout={stdout!r} '
                    f'stderr={stderr!r}'
                )
                self.assertIn(
                    'Images are identical', stdout,
                    f'{image_id}: stdout={stdout!r}'
                )


class TestDifferencingDepthThree(DifferencingTestBase):
    """A chain three images deep, with the differencing child in the middle.

    Both real fixtures are two images, so nothing else in the suite
    makes the chain reader descend twice: for a differencing child at
    index 0 whose parent is at index 1, "descend to the next device"
    and "descend to the last device" are the same instruction. Stacking
    a qcow2 overlay on the child moves the differencing device to index
    1 of a three-device chain, so the VHD and VHDX composing arms
    recurse with a chain-relative offset into a device that is neither
    the top of the chain nor the bottom of it.

    The overlay is built with `qemu-img`, not `instar create -b`, which
    refuses a differencing backing file (see
    `TestDifferencingCreateRefusesAsBacking`). It is created
    standalone, written into, and then given its backing reference with
    `qemu-img rebase -u` -- the `-u` matters, because qemu's own
    readers cannot open either child: its VHDX driver refuses a
    parent-referencing image outright and its VPC driver would read a
    differencing VHD as though it were dynamic. Neither contributes to
    the expectation: the overlay owns exactly one cluster, written with
    a single repeated byte, and the expected file is the recorded
    composition with that one cluster overwritten.

    The overlay owning a cluster is what makes this more than a
    pass-through test -- a reader that ignored the top of the chain
    would otherwise produce the recorded composition and pass.
    """

    # A cluster-aligned region of the overlay's own, well inside the
    # image and clear of offset 0, so that neither a reader starting
    # one device too low nor one that confuses "unallocated" with
    # "zero" at the start of the image can pass by coincidence.
    OVERLAY_OFFSET = 0x100000
    OVERLAY_LENGTH = 0x10000
    OVERLAY_BYTE = 0x5a

    def _require_qemu_tools(self):
        for tool in ('qemu-img', 'qemu-io'):
            if shutil.which(tool) is None:
                self.skipTest(f'{tool} is required to build a depth-3 chain')

    def _run(self, argv, context):
        """Run one qemu tool, failing the test if it does not exit 0."""
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.assertEqual(
            0, r.returncode,
            f'{context}: {argv[0]} exited {r.returncode}; '
            f'stdout={r.stdout!r} stderr={r.stderr!r}'
        )
        return r

    def _build_overlay(self, tmp, child, child_format, context):
        """Create a qcow2 overlay over `child` holding one cluster of its own."""
        overlay = Path(tmp) / 'overlay.qcow2'
        self._run(
            ['qemu-img', 'create', '-f', 'qcow2', str(overlay),
             str(IMAGE_VIRTUAL_SIZE)],
            f'{context}: creating the overlay'
        )
        self._run(
            ['qemu-io', '-c',
             f'write -P 0x{self.OVERLAY_BYTE:02x} '
             f'0x{self.OVERLAY_OFFSET:x} 0x{self.OVERLAY_LENGTH:x}',
             str(overlay)],
            f'{context}: writing the overlay\'s own cluster'
        )
        self._run(
            ['qemu-img', 'rebase', '-u', '-b', child.name,
             '-F', child_format, str(overlay)],
            f'{context}: attaching the overlay to the chain'
        )
        return overlay

    def _expected(self, tmp, golden):
        """The recorded composition with the overlay's own cluster patched in."""
        expected = Path(tmp) / 'expected.raw'
        data = bytearray(golden.read_bytes())
        self.assertEqual(
            IMAGE_VIRTUAL_SIZE, len(data),
            'the recorded composition is not the size this test assumes'
        )
        end = self.OVERLAY_OFFSET + self.OVERLAY_LENGTH
        data[self.OVERLAY_OFFSET:end] = bytes(
            [self.OVERLAY_BYTE] * self.OVERLAY_LENGTH
        )
        expected.write_bytes(bytes(data))
        return expected

    def test_convert_composes_a_three_image_chain(self):
        """A qcow2 over a differencing child over its parent, read in full."""
        self._require_qemu_tools()
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                golden = self.get_image(golden_id)
                if not golden.path.exists():
                    self.skipTest(f'fixture not available: {golden.path}')
                with tempfile.TemporaryDirectory() as tmp:
                    child = self.chain_copy(image_id, tmp)
                    overlay = self._build_overlay(
                        tmp, child, CHAIN_FIXTURE_FORMAT[image_id], image_id
                    )
                    chain_stdout, _, chain_rc = self.run_instar_info(
                        overlay, chain=True
                    )
                    self.assertEqual(0, chain_rc, chain_stdout)
                    self.assertIn(
                        'Chain: 3 image(s)', chain_stdout,
                        f'{image_id}: the fixture is not three images deep, '
                        f'so this test is not testing what it says; '
                        f'stdout={chain_stdout!r}'
                    )

                    out = Path(tmp) / 'composed.raw'
                    stdout, stderr, rc = self.run_instar_convert(
                        overlay, out, output_format='raw'
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: convert must compose a three-image '
                        f'chain; stdout={stdout[:400]!r} '
                        f'stderr={stderr[:400]!r}'
                    )
                    expected = self._expected(tmp, golden.path)
                    self.assert_bytes_identical(
                        out, expected, f'{image_id} (depth 3)'
                    )


class TestDifferencingBenchComposes(DifferencingTestBase):
    """`bench` reads a real differencing chain across its full extent.

    `bench` does not verify the content it reads -- it reports a
    throughput number whether the bytes it got back were composed
    correctly or were the child's own zeros served in their place.
    Exit code and a parsed JSON blob are therefore not enough: this
    class pins two properties the brief's own byte-count check
    reduces to, since `bench`'s JSON ``count`` / ``buffer-size`` are
    plain echoes of the arguments and prove nothing about the read
    underneath them.

    The first is range: `-o`/`-s`/`-c` are chosen so a single,
    non-wrapping request lands on the last byte of the chain's
    declared virtual size (`IMAGE_VIRTUAL_SIZE`, asserted elsewhere
    against the fixture table). If composing silently truncated the
    chain to something shorter -- the class of defect the guest-side
    bound already catches as a read error rather than wrong data --
    this request goes out of bounds and bench fails instead of
    quietly succeeding on a short chain.

    The second is that a request anchored exactly on one of
    `CHAIN_PROBE_SECTORS`'s validated parent-owned sectors succeeds.
    That is all it is: a successful read, not a correct one. A reader
    that ignored the sector bitmap would hand back the child's own
    bytes, or zeros for a block it never allocated, and report no
    error -- and `bench` would not notice, because it never looks at
    the content. Content correctness for `bench` rests on it sharing
    the chain walker that `TestDifferencingComposition`'s whole-file
    `convert` comparisons pin byte for byte; what this class adds is
    that `bench`'s own request path reaches that walker over the
    whole declared extent, including the parts only the parent owns.
    """

    BENCH_BUFSIZE = 4096

    def test_bench_reads_to_the_end_of_the_full_virtual_size(self):
        """A single request at (virtual_size - bufsize) must succeed."""
        for image_id, _golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                offset = IMAGE_VIRTUAL_SIZE - self.BENCH_BUFSIZE
                stdout, stderr, rc = self.run_instar_bench(
                    '-c', '1', '-s', str(self.BENCH_BUFSIZE),
                    '-o', str(offset), '--output', 'json', source
                )
                self.assertEqual(
                    0, rc,
                    f'{image_id}: bench must read the final '
                    f'{self.BENCH_BUFSIZE} bytes of the full composed '
                    f'chain; stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                )
                data = json.loads(stdout)
                self.assertEqual(data['count'], 1)
                self.assertEqual(data['buffer-size'], self.BENCH_BUFSIZE)
                self.assertEqual(data['offset'], offset)
                self.assertGreater(
                    data['bytes-per-second'], 0,
                    f'{image_id}: a completed read must report a positive rate'
                )

    def test_bench_reads_a_parent_owned_sector_without_error(self):
        """A probe read anchored on a validated parent-owned sector.

        Paired with the child-owned sector from the same table, so a
        failure here points specifically at the parent-descending
        half of composition rather than at reading the chain at all.
        """
        for image_id, _golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            parent_sector, child_sector = CHAIN_PROBE_SECTORS[image_id]
            for label, sector in (('parent', parent_sector), ('child', child_sector)):
                with self.subTest(image=image_id, owner=label):
                    source = self.differencing_image(image_id)
                    offset = sector * 512
                    stdout, stderr, rc = self.run_instar_bench(
                        '-c', '1', '-s', '512', '-o', str(offset),
                        '--output', 'json', source
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: bench must read the {label}-owned '
                        f'sector {sector} without error; '
                        f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                    )
                    data = json.loads(stdout)
                    self.assertEqual(data['offset'], offset)


class TestDifferencingRebaseThroughChain(DifferencingTestBase):
    """`rebase` composes a differencing VHD or VHDX in a backing chain.

    `rebase` itself only accepts a qcow2 or vmdk overlay as the file
    being rebased, so "rebasing a differencing VHD or VHDX child" is
    not a thing this tool does. What is testable, and what this class
    covers, is a differencing VHD or VHDX child sitting *behind* a
    qcow2 overlay in that overlay's own backing chain: a safe-mode
    detach reads the whole old chain and copies every byte the
    overlay does not already own into the overlay itself, so a
    wrongly composed differencing member shows up directly in the
    detached overlay's content.

    The overlay is built the way `TestDifferencingDepthThree` builds
    its three-image chain: created and written to standalone, then
    given its backing reference with `qemu-img rebase -u`, because
    `instar create -b` refuses a differencing backing file and
    because qemu's own VPC/VHDX readers cannot open either
    differencing fixture directly. Detaching (`-b ''`, safe mode, no
    `-u`) is the rebase target rather than a new backing: it is the
    one mode that reads the whole old chain and writes every sector
    back into the overlay, so the resulting, now-standalone overlay's
    content is the strongest assertion available here -- the same
    whole-file comparison `TestDifferencingComposition` uses for
    `convert`, with the overlay's own written cluster patched into
    the expectation the way `TestDifferencingDepthThree` does.
    """

    OVERLAY_OFFSET = 0x100000
    OVERLAY_LENGTH = 0x10000
    OVERLAY_BYTE = 0x5a

    def _require_qemu_tools(self):
        for tool in ('qemu-img', 'qemu-io'):
            if shutil.which(tool) is None:
                self.skipTest(f'{tool} is required to build the overlay chain')

    def _run(self, argv, context):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.assertEqual(
            0, r.returncode,
            f'{context}: {argv[0]} exited {r.returncode}; '
            f'stdout={r.stdout!r} stderr={r.stderr!r}'
        )
        return r

    def _build_overlay(self, tmp, child, child_format, context):
        """Create a qcow2 overlay holding one cluster of its own, backed
        by `child`."""
        overlay = Path(tmp) / 'overlay.qcow2'
        self._run(
            ['qemu-img', 'create', '-f', 'qcow2', str(overlay),
             str(IMAGE_VIRTUAL_SIZE)],
            f'{context}: creating the overlay'
        )
        self._run(
            ['qemu-io', '-c',
             f'write -P 0x{self.OVERLAY_BYTE:02x} '
             f'0x{self.OVERLAY_OFFSET:x} 0x{self.OVERLAY_LENGTH:x}',
             str(overlay)],
            f'{context}: writing the overlay\'s own cluster'
        )
        self._run(
            ['qemu-img', 'rebase', '-u', '-b', child.name,
             '-F', child_format, str(overlay)],
            f'{context}: attaching the differencing child as backing'
        )
        return overlay

    def _expected(self, tmp, golden):
        """The recorded composition with the overlay's own cluster patched in."""
        expected = Path(tmp) / 'expected.raw'
        data = bytearray(golden.read_bytes())
        self.assertEqual(
            IMAGE_VIRTUAL_SIZE, len(data),
            'the recorded composition is not the size this test assumes'
        )
        end = self.OVERLAY_OFFSET + self.OVERLAY_LENGTH
        data[self.OVERLAY_OFFSET:end] = bytes(
            [self.OVERLAY_BYTE] * self.OVERLAY_LENGTH
        )
        expected.write_bytes(bytes(data))
        return expected

    def test_rebase_detach_composes_the_differencing_backing_chain(self):
        """Detaching a qcow2 overlay copies the whole composed chain in."""
        self._require_qemu_tools()
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                golden = self.composed_golden(golden_id)
                with tempfile.TemporaryDirectory() as tmp:
                    child = self.chain_copy(image_id, tmp)
                    overlay = self._build_overlay(
                        tmp, child, CHAIN_FIXTURE_FORMAT[image_id], image_id
                    )
                    stdout, stderr, rc = self.run_instar_rebase(overlay, '-b', '')
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: rebase must compose the differencing '
                        f'backing chain when detaching; '
                        f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                    )

                    out = Path(tmp) / 'flattened.raw'
                    c_stdout, c_stderr, c_rc = self.run_instar_convert(
                        overlay, out, output_format='raw'
                    )
                    self.assertEqual(
                        0, c_rc,
                        f'{image_id}: reading the detached, now-standalone '
                        f'overlay back failed; stdout={c_stdout[:400]!r} '
                        f'stderr={c_stderr[:400]!r}'
                    )
                    expected = self._expected(tmp, golden)
                    self.assert_bytes_identical(
                        out, expected, f'{image_id} (rebase detach)'
                    )

    def test_rebase_onto_a_new_backing_keeps_the_two_chains_apart(self):
        """A rebase with both an old and a new chain writes two segments.

        Every other rebase test here detaches (`-b \'\'`), which leaves
        `run_rebase_guest` with one chain and so one `ChainSegment`.
        Giving `-b` a real target is the only way to reach the
        two-segment config: the old chain the overlay is being moved
        off and the new chain it is being moved onto are written into
        one device array, and the segments are what stop the guest
        reading the first device of the new chain as the parent of the
        last device of the old one.

        The old chain is the differencing child and its parent, so
        safe mode has to compose it to know what the overlay must keep.
        The new backing holds the recorded composition itself, which
        means a correct rebase finds the two chains already agree and
        writes nothing -- and a rebase that composed the old chain
        wrongly finds a difference that is not there and writes those
        wrong bytes into the overlay, where the content comparison
        catches them.

        The new backing is qcow2 rather than the raw file the golden
        already is, because safe-mode rebase onto a raw backing fails
        with the generic unparseable-header error regardless of what
        the old chain holds -- issue #632, which predates the
        composition rollout and is not what this test is about.
        """
        self._require_qemu_tools()
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                golden = self.composed_golden(golden_id)
                with tempfile.TemporaryDirectory() as tmp:
                    child = self.chain_copy(image_id, tmp)
                    overlay = self._build_overlay(
                        tmp, child, CHAIN_FIXTURE_FORMAT[image_id], image_id
                    )
                    # Named, not pathed, and deliberately shorter than
                    # either fixture's own filename: safe-mode rebase
                    # writes the new reference into the overlay's
                    # existing backing-filename slot and refuses a
                    # path that does not fit (`rebase` error 8), which
                    # an absolute path under a temporary directory
                    # never does.
                    new_backing = Path(tmp) / 'nb.qcow2'
                    self._run(
                        ['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
                         str(golden), str(new_backing)],
                        f'{image_id}: building the new backing'
                    )

                    stdout, stderr, rc = self.run_instar_rebase(
                        overlay, '-b', new_backing.name, '-F', 'qcow2'
                    )
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: rebase must accept an old chain and a '
                        f'new chain in one device array; '
                        f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                    )

                    out = Path(tmp) / 'rebased.raw'
                    c_stdout, c_stderr, c_rc = self.run_instar_convert(
                        overlay, out, output_format='raw'
                    )
                    self.assertEqual(
                        0, c_rc,
                        f'{image_id}: reading the rebased overlay back '
                        f'failed; stdout={c_stdout[:400]!r} '
                        f'stderr={c_stderr[:400]!r}'
                    )
                    expected = self._expected(tmp, golden)
                    self.assert_bytes_identical(
                        out, expected, f'{image_id} (rebase onto a new chain)'
                    )

    def test_rebase_old_chain_refusal_is_the_typed_message(self):
        """A parentless differencing VHD in the old chain names itself.

        `rebase` had no `differencing_refusal_error` call site: a
        refusal reaching it rendered as the generic
        ``the overlay's header could not be parsed`` instead of the
        typed sentence `convert`/`dd`/`compare`/`bench` already use.
        This pins the fixed rendering.
        """
        self._require_qemu_tools()
        source = self.differencing_image('vhd-differencing')
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / source.name
            shutil.copy2(source, target)
            overlay = Path(tmp) / 'overlay.qcow2'
            self._run(
                ['qemu-img', 'create', '-f', 'qcow2', str(overlay),
                 str(IMAGE_VIRTUAL_SIZE)],
                'building the refusal overlay'
            )
            self._run(
                ['qemu-img', 'rebase', '-u', '-b', target.name, '-F', 'vpc',
                 str(overlay)],
                'attaching the parentless differencing VHD'
            )
            stdout, stderr, rc = self.run_instar_rebase(overlay, '-b', '')
            self.assertEqual(
                1, rc,
                f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
            )
            self.assertIn(self.expected_refusal('rebase', 'VHD'), stderr)


class TestDifferencingCompareTwoChains(DifferencingTestBase):
    """`compare` composes two independent chains out of one device array.

    `compare` is the only operation that reads two images at once, and
    it does it by packing both backing chains into the single device
    array the guest is handed: `CompareConfig.image1_device_count` and
    `image2_device_count` say how long each chain is, the guest derives
    image2's first device by adding the two, and the host writes one
    `ChainSegment` per chain. Nothing in a single-chain test can be
    wrong about any of that, which is why these cases are here and not
    folded into `TestDifferencingComposition`.

    Three distinct ways to get it wrong, and the case that catches each:

    * Taking "a device follows in the array" for "a parent follows in
      my chain". The rule the guest used to be tempted by,
      `dev_idx + 1 >= device_count`, admits a differencing child at
      index 0 of a two-device array whose own chain is one image long,
      and composes it against image2 -- an unrelated file (issue #614).
      `test_compare_refuses_a_child_against_the_image2_that_would_look_
      identical` picks the one image2 for which that wrong read reports
      "Images are identical", so the test cannot pass by the wrong
      answer merely looking wrong.
    * Reading image2 from the wrong place in the array, or giving one
      chain the other's bounds. Every case here asserts a verdict, and
      the ones that expect a difference assert the offset of it, so a
      read served from the wrong device is a wrong offset rather than
      an exit code that happens to be non-zero.
    * Asking "is there a parent behind me" with an array-absolute
      offset instead of a chain-relative one. That is invisible for
      chain 1, whose segment begins at 0, and wrong for chain 2.
      `test_compare_two_differencing_chains_are_identical` is the case
      where image2 is itself a differencing child, so it is the only
      one that can see it.

    A verdict and not an exit code, throughout. A composition that is
    wrong on both sides in the same way still reports "identical", so
    the expectations here are the recorded `*-composed.raw` fixtures
    and offsets derived from the generator's own sector plan -- never
    another instar read of the same chain.
    """

    SECTOR = 512

    # The byte written over a probe sector. Not 0x00, which an
    # unallocated sector also reads as, and not 0xff, which is what an
    # all-ones sector bitmap byte would be: a difference reported for
    # this byte cannot be a hole or a bitmap read back as data.
    PATCH_BYTE = 0x7e

    def _require_qemu_io(self):
        if shutil.which('qemu-io') is None:
            self.skipTest('qemu-io is required to alter a parent in place')

    def _probe_offsets(self, image_id, golden):
        """The two probe offsets for a chain, checked against its golden.

        Returns (parent-owned offset, jointly-owned offset). The
        recorded composition names the owner of every sector it holds
        in the sector's own first bytes, so the table's claim about
        each probe is asserted here rather than trusted: a fixture
        regenerated from a different content plan fails with the
        offset it disagreed at.
        """
        parent_sector, child_sector = CHAIN_PROBE_SECTORS[image_id]
        data = golden.read_bytes()
        self.assertEqual(
            IMAGE_VIRTUAL_SIZE, len(data),
            f'{image_id}: the recorded composition is '
            f'{len(data)} bytes, not the size these probes assume'
        )
        probes = (
            (parent_sector, f'PARENT-sector-{parent_sector:06d}'.encode()),
            (child_sector, f'CHILD-sector-{child_sector:06d}'.encode()),
        )
        for sector, marker in probes:
            offset = sector * self.SECTOR
            self.assertEqual(
                marker, data[offset:offset + len(marker)],
                f'{image_id}: the recorded composition does not hold '
                f'{marker!r} at offset {offset}, so this probe sector no '
                f'longer means what CHAIN_PROBE_SECTORS says it does'
            )
        return parent_sector * self.SECTOR, child_sector * self.SECTOR

    def _patch_parent_sector(self, chain_dir, image_id, offset, context):
        """Overwrite one sector of the parent beside the child in `chain_dir`.

        Written through `qemu-io` rather than into the file's bytes
        because the parents are dynamic images: the sector's home has
        to be found through a BAT, and a block may have to be
        allocated for it. The parents are plain dynamic VHD and VHDX,
        which is the one thing in these chains qemu reads correctly --
        its VPC driver would read a differencing child as dynamic and
        its VHDX driver refuses one outright, so neither child is ever
        handed to it.
        """
        parent = Path(chain_dir) / CHAIN_FIXTURE_PARENT[image_id]
        parent_format = (
            'vhdx' if parent.suffix == '.vhdx' else 'vpc'
        )
        argv = [
            'qemu-io', '-f', parent_format, '-c',
            f'write -P 0x{self.PATCH_BYTE:02x} {offset} {self.SECTOR}',
            str(parent),
        ]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.assertEqual(
            0, r.returncode,
            f'{context}: qemu-io could not write offset {offset} of '
            f'{parent.name}; stdout={r.stdout!r} stderr={r.stderr!r}'
        )

    def assert_compare_identical(self, image1, image2, context):
        """`compare` reports the two images identical, and says so."""
        stdout, stderr, rc = self.run_instar_compare(image1, image2)
        self.assertEqual(
            0, rc,
            f'{context}: compare must report identical; '
            f'stdout={stdout!r} stderr={stderr!r}'
        )
        self.assertIn(
            'Images are identical', stdout,
            f'{context}: stdout={stdout!r}'
        )

    def assert_compare_differs_at(self, image1, image2, offset, context):
        """`compare` reports a first difference at exactly `offset`.

        Both output formats, because they are two renderings of the
        same number and a test that reads only one cannot tell a
        formatting change from a read served off the wrong device.
        """
        stdout, stderr, rc = self.run_instar_compare(image1, image2)
        self.assertEqual(
            1, rc,
            f'{context}: compare must report a difference; '
            f'stdout={stdout!r} stderr={stderr!r}'
        )
        self.assertIn(
            f'Content mismatch at offset {offset}!', stdout,
            f'{context}: compare reported a difference somewhere other '
            f'than offset {offset}; stdout={stdout!r}'
        )
        stdout, stderr, rc = self.run_instar_compare(
            image1, image2, output_format='json'
        )
        self.assertEqual(
            1, rc,
            f'{context} (json): stdout={stdout!r} stderr={stderr!r}'
        )
        report = json.loads(stdout)
        self.assertFalse(
            report['identical'],
            f'{context} (json): report={report!r}'
        )
        self.assertEqual(
            offset, report['first-mismatch-offset'],
            f'{context} (json): report={report!r}'
        )

    def assert_chain_is_two_images(self, image, context):
        """Pin that this side of the comparison really is a two-image chain.

        Without it the four-device claim these tests rest on is an
        assumption. A chain that silently resolved to one image would
        make the test below a two-device case asserting nothing new.
        """
        stdout, _stderr, rc = self.run_instar_info(image, chain=True)
        self.assertEqual(0, rc, f'{context}: stdout={stdout!r}')
        self.assertIn(
            'Chain: 2 image(s)', stdout,
            f'{context}: this side is not a two-image chain, so the '
            f'comparison is not the four-device case; stdout={stdout!r}'
        )

    def test_compare_refuses_a_child_against_the_image2_that_would_look_identical(self):
        """Issue #614, stated so that the wrong answer is "identical".

        A differencing child at index 0 of a two-device array whose own
        chain holds no parent. `device_count` says a device follows;
        the segmentation says nothing follows in this child's chain, and
        the segmentation is right -- the device that follows is image2.

        image2 here is not an arbitrary unrelated file. It is qemu's
        reading of the child itself, which its VPC driver decodes as a
        dynamic VHD: every allocated block's bytes verbatim, the sector
        bitmap ignored, holes elsewhere. That is precisely the file a
        reader composing this child against image2 would agree with at
        every byte -- child-owned sectors from the child, parent-owned
        sectors read out of image2, which holds the child's own bytes
        there, and holes from image2 for the unallocated blocks. So the
        wrong read does not merely produce a wrong verdict here, it
        produces the right-looking one, and the refusal is the only
        answer distinguishable from it.

        VHD only, and deliberately so: the construction needs a reader
        that will decode a parent-referencing child as though it had no
        parent, and qemu's VPC driver is the only one that does. Its
        VHDX driver refuses such an image outright, so there is no
        VHDX file to build this side of the comparison out of. The
        format-blind half of the property -- that every parentless
        differencing fixture is refused rather than composed against
        image2 -- is `TestDifferencingRefusal.test_compare_does_not_
        compose_a_child_against_an_unrelated_image`.
        """
        if shutil.which('qemu-img') is None:
            self.skipTest('qemu-img is required to build the adversarial image2')
        vhd_fixtures = [
            (image_id, format_name)
            for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES
            if format_name == 'VHD'
        ]
        self.assertTrue(
            vhd_fixtures,
            'no parentless differencing VHD fixture is left, so this test '
            'exercises nothing'
        )
        for image_id, format_name in vhd_fixtures:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    other = Path(tmp) / 'reads-back-as-the-child.raw'
                    r = subprocess.run(
                        ['qemu-img', 'convert', '-f', 'vpc', '-O', 'raw',
                         str(source), str(other)],
                        capture_output=True, text=True, timeout=120
                    )
                    self.assertEqual(
                        0, r.returncode,
                        f'{image_id}: qemu-img could not flatten the child; '
                        f'stdout={r.stdout!r} stderr={r.stderr!r}'
                    )
                    flattened = other.read_bytes()
                    self.assertNotEqual(
                        bytes(len(flattened)), flattened,
                        f'{image_id}: the adversarial image2 is all zeros, so '
                        f'a wrong composition would no longer match it and '
                        f'this test proves nothing'
                    )
                    stdout, stderr, rc = self.run_instar_compare(source, other)
                self.assert_refused(
                    'compare', format_name, stdout, stderr, rc,
                    f'{image_id} against an image2 a wrong composition '
                    f'would match'
                )
                combined = stdout + stderr
                self.assertNotIn(
                    'Images are identical', combined,
                    f'{image_id}: compare composed the child against image2 '
                    f'and reported the wrong answer as success; '
                    f'output={combined!r}'
                )
                self.assertNotIn(
                    'Content mismatch', combined,
                    f'{image_id}: compare reached a verdict against an '
                    f'image it should not have read; output={combined!r}'
                )

    def test_compare_reports_the_offset_of_one_altered_parent_owned_sector(self):
        """A difference at a known offset, not merely a difference.

        The second side is the recorded composition with a single
        parent-owned sector overwritten, so the offset `compare`
        reports is the offset of a sector whose content the chain can
        only have taken from the parent. An exit code cannot say that;
        a reader that served the child's zeros for its parent's sectors
        would differ from the golden somewhere too, just not here.

        For `vhd-diff-child-mixed` the sector is 2, which shares its
        sector-bitmap byte with the child's own sectors 1 and 3, so the
        offset reported here is the one a nearly-correct bit shift gets
        wrong.
        """
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                golden = self.composed_golden(golden_id)
                parent_offset, _child_offset = self._probe_offsets(
                    image_id, golden
                )
                with tempfile.TemporaryDirectory() as tmp:
                    altered = Path(tmp) / 'altered.raw'
                    data = bytearray(golden.read_bytes())
                    end = parent_offset + self.SECTOR
                    data[parent_offset:end] = bytes(
                        [self.PATCH_BYTE] * self.SECTOR
                    )
                    altered.write_bytes(bytes(data))
                    self.assert_compare_differs_at(
                        source, altered, parent_offset,
                        f'{image_id} against its composition with the '
                        f'parent-owned sector at {parent_offset} overwritten'
                    )

    def test_compare_two_differencing_chains_are_identical(self):
        """Four devices, two chains, both of them differencing.

        Each child is copied beside its own copy of the parent in a
        directory of its own, so the host resolves two independent
        two-image chains and writes a segment for each. Nothing else in
        this suite puts a differencing child at the head of a *second*
        chain, and a chain beginning at index 0 is the one position at
        which an array-absolute device offset and a chain-relative one
        agree, so this is the only case that can tell them apart.

        The two chains hold the same content, so the verdict must be
        identical -- and the two cases below, which alter one parent,
        are what stop that verdict being reachable by a read that
        served neither chain's data.
        """
        for image_id, _golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                with tempfile.TemporaryDirectory() as tmp:
                    first_dir = Path(tmp) / 'chain-one'
                    second_dir = Path(tmp) / 'chain-two'
                    first_dir.mkdir()
                    second_dir.mkdir()
                    first = self.chain_copy(image_id, first_dir)
                    second = self.chain_copy(image_id, second_dir)
                    self.assert_chain_is_two_images(
                        first, f'{image_id}: image1'
                    )
                    self.assert_chain_is_two_images(
                        second, f'{image_id}: image2'
                    )
                    self.assert_compare_identical(
                        first, second,
                        f'{image_id} against a separate copy of the same '
                        f'chain'
                    )

    def test_compare_reads_each_chain_against_its_own_parent(self):
        """Two differencing children of genuinely different parents.

        The two chains start as copies of one another and then one
        parent -- image2's -- has a single parent-owned sector
        overwritten. The children are untouched and byte-identical, so
        the only thing that can make the comparison differ is each
        chain descending into its own parent file, and the offset of
        the difference says which sector it descended for.

        This is the case that fails if image2's chain is read from the
        wrong index in the device array: reading image2 from image1's
        chain start compares a chain with itself and reports identical,
        and reading it one device low compares the composition against a
        parent alone, which differs at a different offset.
        """
        self._require_qemu_io()
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                golden = self.composed_golden(golden_id)
                parent_offset, _child_offset = self._probe_offsets(
                    image_id, golden
                )
                with tempfile.TemporaryDirectory() as tmp:
                    first_dir = Path(tmp) / 'chain-one'
                    second_dir = Path(tmp) / 'chain-two'
                    first_dir.mkdir()
                    second_dir.mkdir()
                    first = self.chain_copy(image_id, first_dir)
                    second = self.chain_copy(image_id, second_dir)
                    self._patch_parent_sector(
                        second_dir, image_id, parent_offset, image_id
                    )
                    self.assert_chain_is_two_images(
                        second, f'{image_id}: image2 after its parent changed'
                    )
                    self.assert_compare_differs_at(
                        first, second, parent_offset,
                        f'{image_id} against the same chain over a parent '
                        f'altered at {parent_offset}'
                    )

    def test_compare_two_chains_let_each_child_outrank_its_own_parent(self):
        """The same four devices, altered where the child wins instead.

        The altered sector is one both the child and its parent hold.
        The child's sector bitmap claims it, so the parent's copy is
        never read and overwriting it must change nothing -- which is
        the complement of the case above: there the parent's byte was
        the answer, here it is unreachable.

        For `vhd-diff-child-mixed` that sector is 1, in the same
        sector-bitmap byte as the parent-owned sector 2 the previous
        test alters. One byte of bitmap, two sectors, two opposite
        verdicts, and a reader that resolves the byte with an unmasked
        shift gets one of them wrong.
        """
        self._require_qemu_io()
        for image_id, golden_id, _format_name in COMPOSED_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                golden = self.composed_golden(golden_id)
                _parent_offset, child_offset = self._probe_offsets(
                    image_id, golden
                )
                with tempfile.TemporaryDirectory() as tmp:
                    first_dir = Path(tmp) / 'chain-one'
                    second_dir = Path(tmp) / 'chain-two'
                    first_dir.mkdir()
                    second_dir.mkdir()
                    first = self.chain_copy(image_id, first_dir)
                    second = self.chain_copy(image_id, second_dir)
                    self._patch_parent_sector(
                        second_dir, image_id, child_offset, image_id
                    )
                    self.assert_compare_identical(
                        first, second,
                        f'{image_id} against the same chain over a parent '
                        f'altered at {child_offset}, which the child owns'
                    )


class TestDifferencingRefusal(DifferencingTestBase):
    """What each operation does with a differencing source.

    One test per operation, each iterating the fixture table that
    applies to it so a failure names the fixture that broke. The
    operation names in the assertions are the names the user typed,
    which is what the host formatter is handed.

    The composing operations iterate
    `PARENTLESS_DIFFERENCING_FIXTURES` -- the differencing images with
    no parent reference for a walk to resolve, and so the only ones
    they still refuse. Their behaviour on the real chains is
    `TestDifferencingComposition`'s, and the two tables together cover
    `DIFFERENCING_FIXTURES` exactly, by construction rather than by
    hand.

    `check` and `measure` iterate the whole table, because they refuse
    every differencing source whatever its chain holds.
    """

    def test_convert_refuses_a_source_with_no_parent_to_compose(self):
        """`convert -O raw` refuses and writes nothing."""
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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

    def test_dd_refuses_a_source_with_no_parent_to_compose(self):
        """`dd` refuses and writes nothing."""
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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

    def test_compare_refuses_a_source_with_no_parent_to_compose(self):
        """`compare` refuses a differencing source it cannot compose."""
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_compare(source, source)
                self.assert_refused(
                    'compare', format_name, stdout, stderr, rc, image_id
                )

    def test_bench_refuses_a_source_with_no_parent_to_compose(self):
        """`bench` refuses a differencing source it cannot compose."""
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_bench('-c', '4', source)
                self.assert_refused(
                    'bench', format_name, stdout, stderr, rc, image_id
                )

    def test_check_refuses_every_differencing_source(self):
        """`check` refuses a differencing source with exit 1, not 2.

        Every fixture, including the two with their parents beside
        them: `check` validates chain members independently and
        composes nothing, so a complete chain makes no difference to
        it. Its message says so, which is what
        `composing=False` pins.

        Exit 2 is check's corruption code. A differencing source is
        not corrupt -- it is incomplete -- so it is reported as a
        refusal instead. `assert_refused` pins the 1.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_check(source)
                self.assert_refused(
                    'check', format_name, stdout, stderr, rc, image_id,
                    composing=False
                )

    def test_measure_refuses_every_differencing_source(self):
        """`measure` refuses a differencing source.

        Every fixture, for the same reason as `check`: `measure` has
        no chain plumbing at all, so there is no chain for a parent to
        be missing from.
        """
        for image_id, format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_measure(source)
                self.assert_refused(
                    'measure', format_name, stdout, stderr, rc, image_id,
                    composing=False
                )

    def test_compare_does_not_compose_a_child_against_an_unrelated_image(self):
        """Issue #614: a second image is not a parent.

        `compare` packs two independent chains into one device array,
        so a differencing child at index 0 of a two-device array may
        have nothing behind it in its own chain. The rule the guest
        used to be tempted by -- "a parent follows if another device
        follows" -- would admit this and read every parent-owned
        sector out of `image2`, reporting a verdict on data that came
        from the wrong file. No single-chain test can fail that way,
        which is why this one exists.

        The source is the fixture with no parent reference, because it
        is the only differencing image whose chain the host walk
        genuinely leaves one device long: a child with a resolvable
        parent gets a two-device chain of its own and composes.
        """
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    other = Path(tmp) / 'unrelated.raw'
                    other.write_bytes(b'\xa5' * (2 * 1024 * 1024))
                    stdout, stderr, rc = self.run_instar_compare(
                        source, other
                    )
                self.assert_refused(
                    'compare', format_name, stdout, stderr, rc,
                    f'{image_id} against an unrelated second image'
                )
                combined = stdout + stderr
                self.assertNotIn(
                    'Images are identical', combined,
                    f'{image_id}: compare reached a verdict against an '
                    f'unrelated image; output={combined!r}'
                )
                self.assertNotIn(
                    'Content mismatch', combined,
                    f'{image_id}: compare reached a verdict against an '
                    f'unrelated image; output={combined!r}'
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
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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


class TestDifferencingNonComposingRefusalPolicy(DifferencingTestBase):
    """The boundary this suite exists to hold: `map`, `measure` and `check`
    still refuse a differencing source, and their messages hold up both
    halves of the policy at once.

    `test_check_refuses_every_differencing_source` and
    `test_measure_refuses_every_differencing_source` above already pin the
    exact sentence `expected_non_composing_refusal` renders, so the tests
    here are not duplicating that: they name the two properties that
    sentence has to keep -- naming its own operation, and never reading as
    a claim about every operation -- independently of its exact wording.
    `map` keeps its own, separate sentence rather than the one
    `expected_non_composing_refusal` renders, and that sentence is pinned
    verbatim in `TestDifferencingMapStillRefuses` below. Its test here
    checks the same two properties rather than the wording, so a
    rewording of `map`'s sentence cannot quietly drop one of them.

    A reader told only "composition is not supported" has no way to tell
    whether that is true of the command they just typed or of every
    command in the tool. That is exactly the contradiction a user who has
    just run a successful `convert` would meet in a refused `map`, so every
    message here must name its own operation and must not use `instar`'s
    own name, or another operation's name, as though the limitation
    applied generally.
    """

    def test_check_and_measure_name_themselves_rather_than_instar(self):
        """`check` and `measure` each refuse by their own name, not instar's."""
        self.assertTrue(
            DIFFERENCING_FIXTURES, 'DIFFERENCING_FIXTURES must not be empty'
        )
        runners = {
            'check': self.run_instar_check,
            'measure': self.run_instar_measure,
        }
        for op, runner in runners.items():
            for image_id, format_name in DIFFERENCING_FIXTURES:
                with self.subTest(op=op, image=image_id):
                    source = self.differencing_image(image_id)
                    _stdout, stderr, rc = runner(source)
                    self.assertEqual(
                        1, rc,
                        f'{op}/{image_id}: expected exit 1, got {rc}; '
                        f'stderr={stderr!r}'
                    )
                    message = self.expected_non_composing_refusal(op, format_name)
                    self.assertIn(
                        message, stderr,
                        f'{op}/{image_id}: refusal message not found; '
                        f'stderr={stderr!r}'
                    )
                    self.assert_refusal_names_itself_not_instar(op, message)

    def test_check_refuses_identically_with_and_without_the_chain_flag(self):
        """`--chain` must not change what `check` decides.

        `check`'s own chain-discovery call states that it cannot compose a
        differencing parent, so passing `--chain` must not let the host
        resolve one it is never going to validate. Every chain fixture
        here has its real parent sitting beside it, which is the one case
        where chain discovery has something to resolve, so a gate that
        only behaved differently with `--chain` present would be invisible
        without this comparison.
        """
        self.assertTrue(
            DIFFERENCING_CHAIN_FIXTURES, 'DIFFERENCING_CHAIN_FIXTURES must not be empty'
        )
        for image_id, _parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                plain = self.run_instar_check(source, chain=False)
                chained = self.run_instar_check(source, chain=True)
                self.assertEqual(
                    plain, chained,
                    f'{image_id}: check --chain disagreed with check without '
                    f'it; plain={plain!r} chained={chained!r}'
                )
                _stdout, stderr, rc = plain
                self.assertEqual(
                    1, rc,
                    f'{image_id}: expected exit 1, got {rc}; stderr={stderr!r}'
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
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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
        for image_id, _format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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
        """The refusal sentence with every mention of the operation masked.

        The message names the operation more than once -- it leads
        with it and then says what that operation did -- so stripping
        only the leading `<op>: ` would leave two sentences that
        differ in the body and compare unequal for a reason that is
        not a divergence. Masking every occurrence keeps this an
        assertion about the reason the two gave rather than about
        their names.
        """
        marker = f'{op}: '
        index = stderr.find(marker)
        self.assertNotEqual(
            -1, index,
            f'expected a message beginning {marker!r} in {stderr!r}'
        )
        sentence = stderr[index + len(marker):].strip().rstrip('"')
        return sentence.replace(op, '<op>')


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

    def test_map_refusal_names_itself_rather_than_instar(self):
        """map's own wording still names map and does not read as a claim
        about every operation in the tool.

        `test_map_refuses_with_its_own_message` above pins `MAP_REFUSAL`
        verbatim. This test is written against the two properties that
        sentence has to keep rather than against the sentence itself, so
        a rewording -- a wording change, not a policy change -- passes
        here and fails only if it drops one of the two properties.

        That separation earned its keep when `map`'s sentence was
        reworded to stop citing a planning document: the verbatim pin
        above had to be updated and this test did not.
        """
        self.assertTrue(DIFFERENCING_FIXTURES, 'DIFFERENCING_FIXTURES must not be empty')
        for image_id, _format_name in DIFFERENCING_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                _stdout, stderr, rc = self.run_instar_map(source)
                self.assertEqual(
                    1, rc,
                    f'{image_id}: expected exit 1 from map, got {rc}; '
                    f'stderr={stderr!r}'
                )
                self.assert_refusal_names_itself_not_instar('map', stderr)


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

    def test_info_chain_walks_a_resolvable_vhd_or_vhdx_parent(self):
        """`info --chain` walks a resolvable VHD or VHDX parent.

        Host-side chain discovery used to stop at any VHD or VHDX parent,
        annotated but never opened. That gate is now a walk
        policy (`ChainUse`, `src/vmm/src/main.rs`): only `run_info`'s
        `--chain` branch passes `ChainUse::Report`, so it is the sole
        caller that resolves a differencing parent, while every composing
        operation still passes `ChainUse::Compose` and refuses identically
        -- see `TestDifferencingParentAbsent` for that half of the
        invariant. All three fixtures below name a parent that sits beside
        them, so the chain now has two entries, and `[1]` must be the
        parent resolved to an absolute path: a relative path there would
        mean the walk happened to find the file rather than resolving it
        against a known directory, which is not the guarantee this test
        exists to pin.
        """
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                stdout, stderr, rc = self.run_instar_info(source, chain=True)
                self.assertEqual(
                    0, rc,
                    f'{image_id}: info --chain must not error; stderr={stderr!r}'
                )
                self.assertIn(
                    'Chain: 2 image(s)', stdout,
                    f'{image_id}: expected a two-image chain now the parent '
                    f'is resolved; stdout={stdout!r}'
                )
                parent_lines = [
                    line for line in stdout.splitlines()
                    if line.startswith('  [1] ')
                ]
                self.assertEqual(
                    1, len(parent_lines),
                    f'{image_id}: expected exactly one [1] chain entry; '
                    f'stdout={stdout!r}'
                )
                match = re.match(r'^  \[1\] (\S+) ', parent_lines[0])
                self.assertIsNotNone(
                    match,
                    f'{image_id}: could not parse the [1] entry path from '
                    f'{parent_lines[0]!r}'
                )
                parent_path = Path(match.group(1))
                self.assertTrue(
                    parent_path.is_absolute(),
                    f'{image_id}: expected [1] to be an absolute path, got '
                    f'{parent_path}; stdout={stdout!r}'
                )
                self.assertEqual(
                    parent_name, parent_path.name,
                    f'{image_id}: expected [1] to resolve to {parent_name!r}, '
                    f'got {parent_path}'
                )


class TestDifferencingParentAbsent(DifferencingTestBase):
    """What each operation does when the parent is not beside the child.

    The host walks the backing chain before the guest runs, and whether
    that walk resolves a differencing parent is a capability each call
    site states for itself rather than a property of every composing
    caller. So there are two halves to pin here, and the whole value of
    this class is that they are pinned against the same fixture.

    An operation that is going to refuse a differencing source by name
    must not resolve the parent: `check`, `measure` and `map` behave
    byte-for-byte identically whether the parent is there or not,
    because resolving a file they will never read could only replace
    one error with a different, more alarming one -- and would make
    their refusal contingent on a file's presence, which is the one
    thing a refusal must not be.

    An operation that is going to read the parent must resolve it, and
    an absent parent is then a real error that has to be named:
    `convert`, `dd`, `compare` and `bench` report "Backing file not
    found" and the parent's name. That is not the invariant weakening;
    it is the invariant applying to a different set of operations.

    Copying the child alone into an empty directory is the only way to
    exercise either half.
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

    def test_convert_names_an_absent_parent_it_meant_to_read(self):
        """convert reports the missing parent, and writes nothing.

        `convert` resolves a differencing parent because it is going to
        read it, so an orphaned child fails in the host chain walk with
        the parent named. The alarming-sounding error is the correct one
        here: the file convert needed really is missing, and the only
        alternative -- declining the source by name and saying nothing
        about the parent -- would hide which file the user has to go and
        find.
        """
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                orphan = self._orphaned_copy(image_id)
                out = orphan.parent / 'out.raw'
                stdout, stderr, rc = self.run_instar_convert(
                    orphan, out, output_format='raw'
                )
                self.assertEqual(
                    1, rc,
                    f'{image_id}: expected exit 1 for an orphaned child; '
                    f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                )
                self.assertIn(
                    'Backing file not found', stderr,
                    f'{image_id}: convert must say the parent is missing '
                    f'rather than decline the source by name; '
                    f'stderr={stderr!r}'
                )
                self.assertIn(
                    parent_name, stderr,
                    f'{image_id}: the error must name the parent the user '
                    f'has to find; stderr={stderr!r}'
                )
                self.assertFalse(
                    out.exists(),
                    f'{image_id}: orphaned convert left an output file'
                )

    def test_convert_refuses_a_child_with_no_parent_reference(self):
        """A differencing flag with no parent name is still refused by name.

        The complement of the test above, and the part of the original
        unconditional-refusal assertion that survives unchanged: there
        is no reference here for the walk to resolve, so the capability
        never comes into it and the typed refusal is the only possible
        answer whether the child stands alone or not.
        """
        for image_id, format_name in PARENTLESS_DIFFERENCING_FIXTURES:
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
                    f'{image_id}: there is no parent reference to miss; '
                    f'stderr={stderr!r}'
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
                    f'{image_id} (orphaned)', composing=False
                )
                self.assertNotIn(
                    'Backing file not found', stderr,
                    f'{image_id}: stderr={stderr!r}'
                )

    def test_info_chain_reports_one_image_for_an_orphaned_child(self):
        """`info --chain` on an orphaned child stays a one-image chain, rc 0.

        This is the walking caller's half of the same invariant the two
        tests above pin for the refusing callers: the reporting walk
        (`ChainUse::Report`) must not depend on the parent existing either.
        An unresolvable parent -- for whatever reason --
        ends the listing without erroring, so an orphaned child's own
        directory listing is empty of everything but the child, and the
        walk stops with a "was not found" reason rather than failing the
        command. Both real chains are covered, VHD and VHDX.
        """
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                orphan = self._orphaned_copy(image_id)
                stdout, stderr, rc = self.run_instar_info(orphan, chain=True)
                self.assertEqual(
                    0, rc,
                    f'{image_id}: info --chain on an orphaned child must '
                    f'not error; stderr={stderr!r}'
                )
                self.assertIn(
                    'Chain: 1 image(s)', stdout,
                    f'{image_id}: expected a one-image chain once the '
                    f'parent is gone; stdout={stdout!r}'
                )
                expected_reason = f"parent '{parent_name}' was not found"
                self.assertIn(
                    expected_reason, stderr,
                    f'{image_id}: expected {expected_reason!r} on stderr; '
                    f'stderr={stderr!r}'
                )

    def _run_op(self, op, source, tmp_dir):
        """Run one chain-walking operation against `source`.

        Returns (stdout, stderr, rc). `tmp_dir` is scratch space for the
        two operations that write an output file (`convert`, `dd`); the
        others ignore it.
        """
        out = Path(tmp_dir) / 'out.raw'
        if op == 'convert':
            return self.run_instar_convert(source, out, output_format='raw')
        if op == 'dd':
            return self.run_instar_dd([f'if={source}', f'of={out}'])
        if op == 'compare':
            return self.run_instar_compare(source, source)
        if op == 'bench':
            return self.run_instar_bench('-c', '4', source)
        if op == 'check':
            return self.run_instar_check(source)
        if op == 'measure':
            return self.run_instar_measure(source)
        if op == 'map':
            return self.run_instar_map(source)
        raise ValueError(f'unknown composing op {op!r}')

    def test_refusing_operations_are_unchanged_by_parent_presence(self):
        """`check`, `measure` and `map` are byte-for-byte unchanged either way.

        This is the surviving half of the walk policy's central
        invariant, and the half that still carries the whole argument.
        These three refuse a differencing source by name before any
        parent matters, so their `discover_backing_chain` calls state
        that they cannot compose one and the parent is recorded without
        being resolved. If that ever changed, the same image would give
        the typed refusal when its parent happened to sit beside it and
        a path error when it did not -- a refusal contingent on a file
        instar was never going to read, which is no refusal at all.

        `TestDifferencingRefusal` and the orphan tests above only assert
        that both runs contain the same fixed refusal sentence, which
        would still pass if a path leaked into some *other* part of the
        output. Diffing stdout, stderr and exit code exactly, against
        the same fixture with and without its real parent, is the test
        that would actually fail if the boundary were crossed. The four
        operations that now resolve the parent on purpose are covered by
        the test below instead; `measure` and `map` are here because
        they refuse without walking a chain at all, so the invariant is
        trivially true for them and a future chain-aware `measure` would
        be caught by it.
        """
        refusing_ops = ('check', 'measure', 'map')
        for image_id, _parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                present = self.differencing_image(image_id)
                orphan = self._orphaned_copy(image_id)

                def anonymise(text, source, workdir):
                    """Mask the paths that differ by construction, not by behaviour.

                    The two runs necessarily read a different file and
                    write into a different scratch directory, so an
                    operation that named either would differ here for a
                    reason that has nothing to do with the parent. Nothing
                    prints them today, which is why this started as a raw
                    comparison; masking keeps the diff strict about the
                    invariant rather than about paths, so an operation that
                    later names its input or its output does not turn this
                    into a false failure. Both are masked, not just the
                    input, because the output directory has exactly the
                    same property.
                    """
                    return text.replace(str(source), '<SRC>').replace(str(workdir), '<WORKDIR>')
                for op in refusing_ops:
                    with self.subTest(image=image_id, op=op):
                        with tempfile.TemporaryDirectory() as tmp_present:
                            with tempfile.TemporaryDirectory() as tmp_orphan:
                                p_stdout, p_stderr, p_rc = self._run_op(
                                    op, present, tmp_present
                                )
                                a_stdout, a_stderr, a_rc = self._run_op(
                                    op, orphan, tmp_orphan
                                )
                                self.assertEqual(
                                    p_rc, a_rc,
                                    f'{image_id}/{op}: exit code changed when '
                                    f'the parent went missing: {p_rc} -> {a_rc}'
                                )
                                self.assertEqual(
                                    anonymise(p_stdout, present, tmp_present),
                                    anonymise(a_stdout, orphan, tmp_orphan),
                                    f'{image_id}/{op}: stdout changed when '
                                    f'the parent went missing; present='
                                    f'{p_stdout!r} absent={a_stdout!r}'
                                )
                                self.assertEqual(
                                    anonymise(p_stderr, present, tmp_present),
                                    anonymise(a_stderr, orphan, tmp_orphan),
                                    f'{image_id}/{op}: stderr changed when '
                                    f'the parent went missing; present='
                                    f'{p_stderr!r} absent={a_stderr!r}'
                                )

    def test_resolving_operations_report_the_absent_parent(self):
        """`convert`, `dd`, `compare` and `bench` do depend on the parent.

        The other half of the policy, and the assertion that the host
        now resolves a differencing parent for the operations that read
        through the guest chain walker. Each of these four states that
        it can compose a differencing chain, so the walk resolves the
        parent for them exactly as it does for a qcow2 backing file:
        with the parent beside the child the walk succeeds and so does
        the operation, composing the chain rather than refusing it;
        with the parent gone the walk itself fails and names the file
        it could not find.

        Asserting both directions is what makes this a test of the gate
        rather than of an error string. An operation that still refused
        to resolve would produce the same output in both runs, which is
        what the test above *requires* of `check` -- so the two tests
        fail in opposite directions if a capability is ever set the
        wrong way round at a call site.
        """
        resolving_ops = ('convert', 'dd', 'compare', 'bench')
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                present = self.differencing_image(image_id)
                orphan = self._orphaned_copy(image_id)
                for op in resolving_ops:
                    with self.subTest(image=image_id, op=op):
                        with tempfile.TemporaryDirectory() as tmp_present:
                            with tempfile.TemporaryDirectory() as tmp_orphan:
                                p_stdout, p_stderr, p_rc = self._run_op(
                                    op, present, tmp_present
                                )
                                a_stdout, a_stderr, a_rc = self._run_op(
                                    op, orphan, tmp_orphan
                                )
                        self.assertEqual(
                            1, a_rc,
                            f'{image_id}/{op}: expected exit 1 with the '
                            f'parent absent; stdout={a_stdout[:400]!r} '
                            f'stderr={a_stderr[:400]!r}'
                        )
                        self.assertIn(
                            'Backing file not found', a_stderr,
                            f'{image_id}/{op}: the walk must report the '
                            f'parent it could not resolve; '
                            f'stderr={a_stderr!r}'
                        )
                        self.assertIn(
                            parent_name, a_stderr,
                            f'{image_id}/{op}: the error must name the '
                            f'parent; stderr={a_stderr!r}'
                        )
                        self.assertEqual(
                            0, p_rc,
                            f'{image_id}/{op}: with the parent present '
                            f'the operation must compose the chain and '
                            f'succeed; stdout={p_stdout[:400]!r} '
                            f'stderr={p_stderr[:400]!r}'
                        )
                        self.assertNotIn(
                            'Backing file not found', p_stderr,
                            f'{image_id}/{op}: with the parent present '
                            f'the walk must resolve it rather than '
                            f'reporting it missing; stderr={p_stderr!r}'
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

    * every operation declines them, so a hostile locator is not a
      route to a read instar would otherwise decline -- `check`
      declines the source by name without the locator being resolved
      at all, and `convert`, which does resolve a differencing parent,
      has the locator declined by the allowlist or the filesystem
      during chain discovery, one step before any device is attached;
      and
    * `info` *reports* the string without acting on it -- in particular
      `--chain` stops at the one image rather than following the
      locator to whatever it names.
    """

    def test_convert_refuses_every_locator_fixture(self):
        """A hostile locator is declined by the walk, never followed.

        `convert` resolves a differencing parent now, so these six are
        refused one step earlier than they used to be: by
        `validate_backing_path` during chain discovery, before a device
        is attached and before the guest runs. What the fixtures exist
        to prove is unchanged -- none of them becomes a route to a read
        instar would otherwise decline -- but the message is the walk's
        rather than the guest's, so the reason is pinned per fixture
        the way the reporting walk's already is. A one-line "it failed"
        assertion would not distinguish the allowlist rejecting
        `/etc/passwd` from resolution quietly going wrong, which is the
        same shape of bug either way.
        """
        for image_id, _expected in ADVERSARIAL_LOCATOR_FIXTURES:
            with self.subTest(image=image_id):
                source = self.differencing_image(image_id)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'out.raw'
                    stdout, stderr, rc = self.run_instar_convert(
                        source, out, output_format='raw'
                    )
                    self.assertEqual(
                        1, rc,
                        f'{image_id}: expected exit 1; '
                        f'stdout={stdout[:400]!r} stderr={stderr[:400]!r}'
                    )
                    expected_reasons = COMPOSING_LOCATOR_REASONS[image_id]
                    self.assertTrue(
                        any(reason in stderr for reason in expected_reasons),
                        f'{image_id}: expected one of the reasons '
                        f'{expected_reasons!r} on stderr -- a bare failure '
                        f'cannot show the allowlist (or plain path '
                        f'resolution) did the declining rather than '
                        f'something going wrong later; stderr={stderr!r}'
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
                    'check', 'VHD', stdout, stderr, rc, image_id,
                    composing=False
                )

    def test_info_reports_the_locator_without_following_it(self):
        """`info` prints the hostile string and opens nothing.

        `info --chain` is the assertion that matters. Every one of
        these fixtures names a parent that instar must not walk to;
        `vhd-diff-locator-etc-passwd` in particular names a path that
        really does exist on the machine running the test, so a reader
        that resolved-and-opened its locator would have something to
        find. The chain must still be one image long -- that is the
        security property and the walk must not weaken it -- but a
        one-image chain by itself does not distinguish "the allowlist
        correctly rejected this" from "resolution silently failed", which
        is exactly the same shape of bug either way. So this test also
        pins the stderr reason the reporting walk gives for each fixture
        against `ADVERSARIAL_LOCATOR_REASONS`, whose comment explains why
        one of the six admits two reasons: the chain stays one image long
        *for the right reason*, not by accident.
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
                expected_reasons = ADVERSARIAL_LOCATOR_REASONS[image_id]
                self.assertTrue(
                    any(reason in stderr for reason in expected_reasons),
                    f'{image_id}: expected one of the reasons '
                    f'{expected_reasons!r} on stderr -- a one-image chain '
                    f'alone cannot show the allowlist (or the classifier) '
                    f'did the rejecting rather than resolution silently '
                    f'failing; stderr={stderr!r}'
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
        'backing file is a differencing VHD or VHDX; create does not '
        'support stacking a backing file on one'
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

    def _vhdiinfo(self, path: Path, required=()) -> dict:
        """Parse `vhdiinfo PATH` into a {label: value} mapping.

        *required* names labels the caller is about to assert on. They
        are checked here rather than at the call site because
        `fields.get(MISSING)` is `None`, and `None` compares equal to
        `None`: a libvhdi release that renamed `Parent identifier`
        would turn both identity assertions into a comparison of two
        absent values and keep passing. An oracle whose whole claim is
        that it is not a closed loop cannot afford to go vacuous
        quietly.
        """
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
            if not match:
                continue
            label, value = match.group(1), match.group(2)
            # Plain assignment would let a repeated label overwrite an
            # earlier one with no signal, so a second section or a new
            # field under an indented sub-heading would quietly change
            # what every assertion below reads. The vacuous-parse guard
            # underneath is the same concern approached from the other
            # end: there, nothing was understood; here, two things were
            # and the parser cannot say which one counts.
            self.assertNotIn(
                label, fields,
                f'vhdiinfo printed {label!r} more than once for {path}, so '
                f'the parser cannot tell which value to assert on: {r.stdout!r}'
            )
            fields[label] = value
        # A parse that silently produced nothing would make every
        # assertion below vacuous, so prove the output was understood
        # before trusting any of it.
        for label in (self.DISK_TYPE, *required):
            self.assertIn(
                label, fields,
                f'vhdiinfo did not report {label!r} for {path}, so an '
                f'assertion on it would compare None with None: {r.stdout!r}'
            )
        return fields

    # libvhdi 20240509 prints GUIDs bare, lowercase and hyphenated.
    # A release that rendered them braced or uppercase would silently
    # disable the placeholder guard below, because an assertNotEqual
    # against a literal it can never match always passes -- so the
    # shape is asserted rather than assumed, and the comparison is
    # made on a normalised form.
    GUID_RE = re.compile(
        r'^\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$')

    def _guid(self, value, label: str) -> str:
        """Normalise a GUID `vhdiinfo` printed, asserting it is one."""
        self.assertIsNotNone(
            value, f'vhdiinfo reported no {label}, so there is nothing to compare')
        self.assertRegex(
            value, self.GUID_RE,
            f'vhdiinfo rendered {label} as {value!r}, which is not a GUID this '
            f'test knows how to compare; the zero-identity guard would not fire'
        )
        return value.strip('{}').lower()

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

        The third shape is absolute, which takes the other branch of
        the rendering entirely: an absolute path keeps its POSIX bytes
        and never gains the `.\\` prefix. `test_create.py` covers that
        shape today with a whole-file substring search and an `instar
        info` round-trip -- but the round-trip is instar reading what
        instar wrote, which is the assertion strength this oracle
        exists to improve on.

        libvhdi never parses the VHD locator table at all, so nothing
        here asserts anything about it. The locator's own structure is
        pinned by `src/crates/create/tests/round_trip.rs`.
        """
        self._require_vhdiinfo()
        for shape in ('bare', 'subdirectory', 'absolute'):
            subdirectory = 'sub' if shape == 'subdirectory' else None
            with self.subTest(parent_path=shape):
                with tempfile.TemporaryDirectory() as td:
                    parent, typed = self._stage_parent(
                        'vhd-diff-parent', td, subdirectory)
                    if shape == 'absolute':
                        # What -b is given, and so what the parent
                        # unicode name must hold verbatim. FIELD_RE
                        # splits on the first colon, which a POSIX
                        # absolute path does not contain, so the value
                        # comes back whole.
                        typed = str(parent)

                    # Derived from the parent, never hardcoded: a
                    # constant here would pin the fixture rather than
                    # the emitter, and would go stale the day the
                    # fixture is regenerated.
                    parent_fields = self._vhdiinfo(
                        parent, required=(self.IDENTIFIER,))
                    want_identity = self._guid(
                        parent_fields.get(self.IDENTIFIER), self.IDENTIFIER)
                    self.assertNotEqual(
                        self.ZERO_GUID, want_identity,
                        'the parent fixture has a zero identifier, so this '
                        'test cannot tell a real identity from the '
                        'placeholder instar writes for #566'
                    )

                    child = self._create_child(td, 'vpc', typed, 'child.vhd')
                    fields = self._vhdiinfo(
                        child,
                        required=(self.PARENT_IDENTIFIER, self.PARENT_FILENAME))

                    self.assertEqual(
                        self.DIFFERENTIAL, fields.get(self.DISK_TYPE),
                        f'libvhdi does not read the child as differencing: '
                        f'{fields!r}'
                    )
                    self.assertEqual(
                        want_identity,
                        self._guid(fields.get(self.PARENT_IDENTIFIER),
                                   self.PARENT_IDENTIFIER),
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

            parent_fields = self._vhdiinfo(
                parent, required=(self.IDENTIFIER,))
            want_identity = self._guid(
                parent_fields.get(self.IDENTIFIER), self.IDENTIFIER)
            self.assertNotEqual(
                self.ZERO_GUID, want_identity,
                'the parent fixture has a zero DataWriteGuid, so this test '
                'cannot tell a real identity from the placeholder instar '
                'writes for #566'
            )

            child = self._create_child(td, 'vhdx', typed, 'child.vhdx')
            fields = self._vhdiinfo(
                child, required=(self.PARENT_IDENTIFIER,))

            # The File Parameters `HasParent` bit, seen from outside.
            # Nothing else in the Python suite asserts it: the round
            # trip test's VHDX arm never checks it, where its VHD arm
            # does assert disk_type == 4.
            self.assertEqual(
                self.DIFFERENTIAL, fields.get(self.DISK_TYPE),
                f'libvhdi does not read the child as differencing: {fields!r}'
            )
            self.assertEqual(
                want_identity,
                self._guid(fields.get(self.PARENT_IDENTIFIER),
                           self.PARENT_IDENTIFIER),
                f'libvhdi reads a parent linkage that is not the parent\'s '
                f'active-header DataWriteGuid: {fields!r}'
            )
