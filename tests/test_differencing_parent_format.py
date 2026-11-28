"""Integration tests for a differencing parent that is the wrong format.

A sibling of `test_differencing.py`, split out of it along the seam
between a parent that is absent and a parent that resolved but cannot
be used. `test_differencing.py`'s `TestDifferencingParentAbsent` pins
the first; this module pins the second (issue #608), and shares that
module's fixture table and base class rather than restating them. The
substitute parents it writes, and what each is called, are the table
in docs/chain-discovery.md.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from helpers.headerless import headerless_bytes
from test_differencing import CHAIN_FIXTURE_PARENT, DIFFERENCING_CHAIN_FIXTURES, DifferencingTestBase


class TestDifferencingParentWrongFormat(DifferencingTestBase):
    """The parent resolved, and is not the format the child requires.

    Both specifications require a differencing child's parent to be the
    same format as the child. The walk never checked, so a child whose
    parent file had been replaced by a qcow2 was listed as having a
    qcow2 parent and `convert` of that chain exited 0 -- a chain no
    reader should accept, read through the parent arm of a different
    format (issue #608).

    `TestDifferencingParentAbsent` pins what happens when the parent is
    not there; this pins the step after it, where the parent resolved
    and then turned out to be unusable. The two halves split the same
    way: a reporting walk ends its listing with the reason on stderr and
    still exits 0, because `info` must not turn a listing into a failure,
    while an operation that was going to read the parent refuses and
    names both images.
    """

    def _substituted_copy(self, image_id, write_parent):
        """Copy a child alone, then write `write_parent(path)` at its parent."""
        source = self.differencing_image(image_id)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        child = Path(tmp) / source.name
        shutil.copy2(source, child)
        write_parent(Path(tmp) / CHAIN_FIXTURE_PARENT[image_id])
        return child

    def _qemu_img_parent(self, path, *args):
        r = subprocess.run(
            ['qemu-img', 'create', *args, str(path), '16M'],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f'qemu-img create: {r.stderr!r}')

    def _qcow2_parent(self, path):
        self._qemu_img_parent(path, '-f', 'qcow2')

    def _unidentified_parent(self, path):
        # Random bytes match no magic and carry no partition table, so
        # `info` names this `unknown`. It is the row that interacts with
        # the chain reader reading an `unknown` member as raw: the
        # format check has to see the name discovery gave it, not the
        # one the guest would be told to read it as. The seed is fixed
        # so a failure replays with the same bytes.
        path.write_bytes(headerless_bytes(16 * 1024 * 1024))

    def _qed_parent(self, path):
        self._qemu_img_parent(path, '-f', 'qed')

    def _qcow2_parent_missing_its_backing(self, path):
        # The format check must come before the qcow2's own backing is
        # chased, or this is reported as a missing file rather than as
        # the wrong format.
        self._qemu_img_parent(
            path, '-f', 'qcow2', '-u', '-b', 'gone.qcow2', '-F', 'qcow2')

    # Each row of the table in docs/chain-discovery.md: the parent
    # written, what the listing's reason names it, and what an
    # operation that reads the parent says when it refuses. A qed
    # parent is refused as qed is at any chain position, not by the
    # differencing rule, which is why its refusal reads differently.
    SUBSTITUTES = (
        ('qcow2', '_qcow2_parent', 'is qcow2', 'its parent must be'),
        ('unknown', '_unidentified_parent', 'is unknown', 'its parent must be'),
        ('qcow2-missing-backing', '_qcow2_parent_missing_its_backing',
         'is qcow2', 'its parent must be'),
        ('qed', '_qed_parent', 'is qed', 'not supported for reading'),
    )

    def _substitutes(self):
        """The SUBSTITUTES rows this host's qemu-img can write.

        RHEL-family qemu-img has no qed driver, so the qed parent cannot
        be written there. The row is dropped rather than skipped inside
        its subTest, which subunit does not report cleanly.
        """
        if self.qemu_img_supports_format('qed'):
            return self.SUBSTITUTES
        return tuple(row for row in self.SUBSTITUTES if row[0] != 'qed')

    def test_info_chain_ends_the_listing_at_a_wrong_format_parent(self):
        """The listing stops at the child, exits 0, and says why."""
        self._require_qemu_img()
        for image_id, parent_name in DIFFERENCING_CHAIN_FIXTURES:
            for label, writer, named, _refusal in self._substitutes():
                with self.subTest(image=image_id, parent=label):
                    child = self._substituted_copy(
                        image_id, getattr(self, writer))
                    stdout, stderr, rc = self.run_instar_info(
                        child, chain=True)
                    # Every excerpt below is bounded. A subTest that
                    # embeds a whole chain listing in each of four
                    # messages, many subTests over, bursts subunit's
                    # packet limit and takes the stestr worker with it
                    # -- which reports as a partial run rather than as
                    # this failure.
                    self.assertEqual(
                        0, rc,
                        f'{image_id}/{label}: info --chain must not fail on '
                        f'a chain it can only report; stdout={stdout[:200]!r} '
                        f'stderr={stderr[:200]!r}'
                    )
                    self.assertIn(
                        'Chain: 1 image(s)', stdout,
                        f'{image_id}/{label}: the file standing in for the '
                        f'parent must not be listed; stdout={stdout[:200]!r}'
                    )
                    self.assertIn(
                        named, stderr,
                        f'{image_id}/{label}: the reason must name what the '
                        f'parent turned out to be; stderr={stderr[:200]!r}'
                    )
                    self.assertIn(
                        parent_name, stdout,
                        f'{image_id}/{label}: the child line must still '
                        f'print the reference it names; '
                        f'stdout={stdout[:200]!r}'
                    )

    def test_convert_refuses_a_wrong_format_parent(self):
        """convert refuses, says why, and writes nothing."""
        self._require_qemu_img()
        for image_id, _parent_name in DIFFERENCING_CHAIN_FIXTURES:
            for label, writer, named, refusal in self._substitutes():
                with self.subTest(image=image_id, parent=label):
                    child = self._substituted_copy(
                        image_id, getattr(self, writer))
                    out = child.parent / 'out.raw'
                    stdout, stderr, rc = self.run_instar_convert(
                        child, out, output_format='raw')
                    self.assertEqual(
                        1, rc,
                        f'{image_id}/{label}: convert exited {rc} on a '
                        f'chain it cannot read; stdout={stdout[:400]!r} '
                        f'stderr={stderr[:400]!r}'
                    )
                    self.assertIn(
                        refusal, stderr,
                        f'{image_id}/{label}: the refusal must say why; '
                        f'stderr={stderr[:200]!r}'
                    )
                    if refusal == 'its parent must be':
                        self.assertIn(
                            named, stderr,
                            f'{image_id}/{label}: the refusal must say what '
                            f'the parent is instead; stderr={stderr[:200]!r}'
                        )
                    self.assertFalse(
                        out.exists(),
                        f'{image_id}/{label}: a refused convert must leave '
                        f'no output'
                    )

    def test_the_real_parent_still_composes(self):
        """The control: the same child over its own parent reads.

        Without this, every assertion above would also pass if the walk
        had simply stopped resolving differencing parents at all.
        """
        for image_id, _parent_name in DIFFERENCING_CHAIN_FIXTURES:
            with self.subTest(image=image_id):
                with tempfile.TemporaryDirectory() as tmp:
                    child = self.chain_copy(image_id, tmp)
                    stdout, stderr, rc = self.run_instar_info(
                        child, chain=True)
                    self.assertEqual(0, rc, f'{image_id}: {stderr!r}')
                    self.assertIn(
                        'Chain: 2 image(s)', stdout,
                        f'{image_id}: the real parent must still be '
                        f'listed; stdout={stdout[:200]!r}'
                    )
                    out = Path(tmp) / 'out.raw'
                    _, stderr, rc = self.run_instar_convert(
                        child, out, output_format='raw')
                    self.assertEqual(
                        0, rc,
                        f'{image_id}: convert of the real chain failed: '
                        f'{stderr!r}'
                    )

