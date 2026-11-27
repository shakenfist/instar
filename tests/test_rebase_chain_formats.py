"""Integration tests for `instar rebase` over chains of more than one format.

A sibling of `test_rebase.py`, split out of it along the seam this
module tests: what a rebase does when the chains either side of it are
not all qcow2. `test_rebase.py` pins rebase's own contracts -- the
host pre-checks, the success paths, qemu parity and the overlay shapes
safe mode can write into -- and every chain there is qcow2 over qcow2,
or vmdk over vmdk. These are the cases that only appear when a member
is something else:

- ``TestRebaseUnreadableChainMember`` pins the guest-side refusal of
  a chain member whose format the chain reader cannot serve, and that
  the refusal comes before the overlay is written to (issue #632).
- ``TestRebaseRecordsBackingFormat`` pins the backing-format header
  extension a rebase rewrites (issue #972).
- ``TestRebaseUnidentifiedChainMember`` pins the chains that hold a
  raw image with no partition table -- the shape secure-mode ``info``
  names ``unknown`` -- in the old chain and as the new backing
  (issues #629 and #632).

Tests run on the host's installed `instar` binary, and need
``/dev/kvm`` access and the qemu tools.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from helpers.headerless import headerless_bytes
from test_rebase import TestRebaseSmoke


# ----------------------------------------------------------------------
# A chain member the guest's chain reader cannot serve.
# ----------------------------------------------------------------------


class TestRebaseUnreadableChainMember(TestRebaseSmoke):
    """A chain member in a format the chain reader cannot read is refused by name."""

    def test_unreadable_chain_member_names_its_own_reason(self):
        """A VMDK backing is refused as a chain member it cannot read.

        Safe mode reads the old and new chains through the guest's
        chain reader, which serves qcow2, raw, VHD and VHDX
        members. A VMDK member is genuinely outside that set, so
        refusing is right -- but the refusal came out of the
        per-cluster reader, which could say no more than that a
        read had failed, and the runner reported it as
        `ERROR_PARSE_FAILED`: "the overlay's header could not be
        parsed" (issue #632).

        The control rebases an identically-shaped overlay over a
        qcow2 backing, which is what makes the claim "the overlay
        parses fine" a measurement rather than an assertion.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            for args in (['-f', 'vmdk', 'base.vmdk', '1M'],
                         ['-f', 'qcow2', 'qbase.qcow2', '1M'],
                         ['-f', 'qcow2', 'nb.qcow2', '1M']):
                r = subprocess.run(['qemu-img', 'create', *args],
                                   capture_output=True, text=True,
                                   timeout=30, cwd=str(td))
                self.assertEqual(r.returncode, 0, r.stderr)
            for backing, fmt, name in (('base.vmdk', 'vmdk', 'vmdk.qcow2'),
                                       ('qbase.qcow2', 'qcow2', 'qc.qcow2')):
                r = subprocess.run(
                    ['qemu-img', 'create', '-f', 'qcow2', '-b', backing,
                     '-F', fmt, name, '1M'],
                    capture_output=True, text=True, timeout=30, cwd=str(td))
                self.assertEqual(r.returncode, 0, r.stderr)

            _, stderr, rc = self.run_instar_rebase(
                td / 'vmdk.qcow2', '-b', 'nb.qcow2', '-F', 'qcow2')
            self.assertNotEqual(rc, 0, 'expected the vmdk member to be refused')
            self.assertIn('a backing chain member is a format this build '
                          'cannot read', stderr, f'unexpected stderr: {stderr}')
            self.assertNotIn("overlay's header could not be parsed", stderr,
                             f'refusal still blames the overlay: {stderr}')

            # Same overlay shape, readable member: rebases.
            _, stderr, rc = self.run_instar_rebase(
                td / 'qc.qcow2', '-b', 'nb.qcow2', '-F', 'qcow2')
            self.assertEqual(rc, 0, f'control rebase failed: {stderr!r}')

    def test_unreadable_chain_member_refusal_leaves_a_snapshot_overlay_alone(self):
        """The chain is refused before the overlay is written to.

        A snapshot-bearing overlay is the case where a safe rebase
        writes before it copies anything: it grows the refcount
        structures for the worst-case copy-on-write first. The
        refusal of a chain member the reader cannot serve has to
        come before that, or the overlay is refused and changed at
        once. 512-byte clusters make the worst case outgrow the
        existing refblocks, so growth really does write here.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            for args in (['create', '-f', 'vmdk', 'base.vmdk', '1M'],
                         ['create', '-f', 'qcow2', 'nb.qcow2', '1M'],
                         ['create', '-f', 'qcow2', '-o', 'cluster_size=512',
                          '-b', 'base.vmdk', '-F', 'vmdk', 'snap.qcow2', '1M'],
                         ['snapshot', '-c', 's1', 'snap.qcow2']):
                r = subprocess.run(['qemu-img', *args],
                                   capture_output=True, text=True,
                                   timeout=30, cwd=str(td))
                self.assertEqual(r.returncode, 0, r.stderr)

            overlay = td / 'snap.qcow2'
            before = overlay.read_bytes()
            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'nb.qcow2', '-F', 'qcow2')
            self.assertNotEqual(rc, 0, 'expected the vmdk member to be refused')
            self.assertIn('a backing chain member is a format this build '
                          'cannot read', stderr, f'unexpected stderr: {stderr}')
            self.assert_bytes_identical(
                overlay.read_bytes(), before,
                'a refused rebase must not touch the snapshot-bearing overlay')


# ----------------------------------------------------------------------
# The backing format the overlay records.
# ----------------------------------------------------------------------


class TestRebaseRecordsBackingFormat(TestRebaseSmoke):
    """A rebase that changes format updates what the overlay records.

    A qcow2 overlay names its backing's format in a header
    extension and a reader trusts it, so an overlay rebased from a
    qcow2 backing onto a raw one while still recording `qcow2` is
    one `qemu-img` refuses to open at all -- issue #972. instar
    kept reading such an overlay, because chain discovery probes
    each member instead of trusting the record, which is why the
    suite did not notice: every round-trip fixture rebases qcow2
    onto qcow2, where the stale record is accidentally right.

    `-u` is the mode that reaches this most widely: it rewrites the
    reference without reading either chain's data, so it accepts a
    new backing in a format rebase cannot read. It still opens the
    new backing to discover what it is, and what discovery found is
    what gets recorded.
    """

    def test_unsafe_rebase_records_the_new_backing_format(self):
        self._require_qemu_img()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(td / 'base.qcow2'), '1M')
            self.assertEqual(rc, 0, stderr)
            # Headerless, so there is no signature to probe: the
            # recorded format is the only thing that says what this
            # file is.
            (td / 'nb.raw').write_bytes(headerless_bytes(1 << 20))
            overlay = td / 'ovl.qcow2'
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', '-b', 'base.qcow2', '-F', 'qcow2',
                str(overlay), '1M')
            self.assertEqual(rc, 0, stderr)

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', 'nb.raw', '-F', 'raw')
            self.assertEqual(rc, 0, f'rebase failed: stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img could not open the rebased overlay: {r.stderr!r}')
            info = json.loads(r.stdout)
            self.assertEqual(info.get('backing-filename'), 'nb.raw')
            self.assertEqual(
                info.get('backing-filename-format'), 'raw',
                'the overlay still records its old backing\'s format')

            # And the whole overlay opens, not just its header: a
            # record that disagreed with its own length word would
            # pass the assertion above and fail here.
            r = subprocess.run(['qemu-img', 'check', str(overlay)],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0,
                             f'qemu-img check: {r.stdout!r} {r.stderr!r}')

    def test_v2_overlay_records_the_new_backing_format(self):
        """A compat=0.10 overlay's record is rewritten as well.

        qemu writes the backing-format extension into a v2 header too,
        at offset 72, and the extension parser rebase used to locate
        it reads nothing from a v2 header. So a v2 overlay kept naming
        its old backing's format, which is #972 for every overlay
        `qemu-img create -o compat=0.10 -F` made. instar's own create
        only writes v3, so qemu-img makes this fixture.
        """
        self._require_qemu_img()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(td / 'base.qcow2'), '1M')
            self.assertEqual(rc, 0, stderr)
            (td / 'nb.raw').write_bytes(headerless_bytes(1 << 20))
            overlay = td / 'ovl.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', '-o', 'compat=0.10',
                 '-b', 'base.qcow2', '-F', 'qcow2', 'ovl.qcow2', '1M'],
                capture_output=True, text=True, timeout=30, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-u', '-b', 'nb.raw', '-F', 'raw')
            self.assertEqual(rc, 0, f'rebase failed: stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img could not open the rebased overlay: {r.stderr!r}')
            info = json.loads(r.stdout)
            self.assertEqual(info['format-specific']['data']['compat'], '0.10')
            self.assertEqual(info.get('backing-filename'), 'nb.raw')
            self.assertEqual(
                info.get('backing-filename-format'), 'raw',
                'the v2 overlay still records its old backing\'s format')
            r = subprocess.run(['qemu-img', 'check', str(overlay)],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0,
                             f'qemu-img check: {r.stdout!r} {r.stderr!r}')

    def test_safe_rebase_without_f_records_the_discovered_format(self):
        """With no `-F`, the record is the format discovery found.

        The `-F`-less invocation is the common one, and the only one
        the host has to answer for itself: with no hint it states the
        format chain discovery found for the new backing. Passing the
        auto-detect code instead would leave the overlay recording its
        old backing's format, which is #972 reached by another route --
        and the mutation check for that line is what showed nothing
        covered it.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(td / 'base.qcow2'), '1M')
            self.assertEqual(rc, 0, stderr)
            r = subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x42 0 64k',
                 str(td / 'base.qcow2')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            # Headerless: discovery names it `unknown`, and the format
            # the guest is told to read it as is what gets recorded.
            (td / 'nb.raw').write_bytes(headerless_bytes(1 << 20))
            overlay = td / 'ovl.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', '-b', 'base.qcow2',
                 '-F', 'qcow2', 'ovl.qcow2', '1M'],
                capture_output=True, text=True, timeout=30, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)

            _, stderr, rc = self.run_instar_rebase(overlay, '-b', 'nb.raw')
            self.assertEqual(rc, 0, f'rebase failed: stderr={stderr!r}')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(overlay)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img could not open the rebased overlay: {r.stderr!r}')
            self.assertEqual(
                json.loads(r.stdout).get('backing-filename-format'), 'raw',
                'without -F the overlay must record what discovery found')

    def test_rebase_onto_a_vhd_family_backing_records_its_driver_name(self):
        """A VHD or VHDX backing is recorded as `vpc` or `vhdx`.

        The name written is the *driver's*, which is not instar's enum
        name for VHD, and a format the record table does not name is
        left alone -- so an unnamed format means the overlay goes on
        recording its old backing's format, which is #972 again. VHD
        and VHDX are reachable without `-F` (which only spells qcow2,
        vmdk and raw): chain discovery identifies both, and rebase's
        chain reader can serve both, so this is a rebase that succeeds
        and used to leave the record saying `qcow2`.
        """
        self._require_qemu_tools()
        for create_format, recorded in (('vpc', 'vpc'), ('vhdx', 'vhdx')):
            with self.subTest(format=create_format):
                with tempfile.TemporaryDirectory() as td:
                    td = Path(td)
                    r = subprocess.run(
                        ['qemu-img', 'create', '-f', 'qcow2', 'base.qcow2', '4M'],
                        capture_output=True, text=True, timeout=30, cwd=str(td))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    backing = f'nb.{create_format}'
                    r = subprocess.run(
                        ['qemu-img', 'create', '-f', create_format, backing, '4M'],
                        capture_output=True, text=True, timeout=30, cwd=str(td))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    overlay = td / 'ovl.qcow2'
                    r = subprocess.run(
                        ['qemu-img', 'create', '-f', 'qcow2', '-b', 'base.qcow2',
                         '-F', 'qcow2', 'ovl.qcow2', '4M'],
                        capture_output=True, text=True, timeout=30, cwd=str(td))
                    self.assertEqual(r.returncode, 0, r.stderr)

                    _, stderr, rc = self.run_instar_rebase(overlay, '-b', backing)
                    self.assertEqual(rc, 0, f'rebase failed: stderr={stderr!r}')

                    r = subprocess.run(
                        ['qemu-img', 'info', '--output=json', str(overlay)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(
                        r.returncode, 0,
                        f'qemu-img could not open the rebased overlay: {r.stderr!r}')
                    info = json.loads(r.stdout)
                    self.assertEqual(info.get('backing-filename'), backing)
                    self.assertEqual(
                        info.get('backing-filename-format'), recorded,
                        'the overlay still records its old backing\'s format')

                    # The whole overlay opens, backing and all: a record
                    # naming a format qemu cannot match to the file it
                    # points at fails here rather than above.
                    r = subprocess.run(['qemu-img', 'check', str(overlay)],
                                       capture_output=True, text=True, timeout=60)
                    self.assertEqual(r.returncode, 0,
                                     f'qemu-img check: {r.stdout!r} {r.stderr!r}')

    def test_unsafe_rebase_names_a_format_rebase_cannot_read(self):
        """`-u` onto a VDI, VMDK descriptor or qcow records its driver.

        These are backings safe mode refuses to read and `-u` accepts,
        and `-F` cannot spell any of them, so the host's discovered
        format is the only statement of what they are. Each used to
        have no driver name in the record table and left the overlay
        recording `qcow2` -- a header `qemu-img` then refuses to open,
        after an instar rebase that exited 0.
        """
        self._require_qemu_tools()
        cases = (
            ('vdi', [], 'vdi'),
            ('vmdk', ['-o', 'subformat=monolithicFlat'], 'vmdk'),
            ('qcow', [], 'qcow'),
        )
        for create_format, options, recorded in cases:
            with self.subTest(format=create_format):
                with tempfile.TemporaryDirectory() as td:
                    td = Path(td)
                    overlay = self._overlay_over_qcow2(td)
                    backing = f'nb.{create_format}'
                    r = subprocess.run(
                        ['qemu-img', 'create', '-f', create_format, *options,
                         backing, '4M'],
                        capture_output=True, text=True, timeout=30, cwd=str(td))
                    self.assertEqual(r.returncode, 0, r.stderr)

                    _, stderr, rc = self.run_instar_rebase(
                        overlay, '-u', '-b', backing)
                    self.assertEqual(rc, 0, f'rebase failed: stderr={stderr!r}')

                    r = subprocess.run(
                        ['qemu-img', 'info', '--output=json', str(overlay)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(
                        r.returncode, 0,
                        f'qemu-img could not open the rebased overlay: {r.stderr!r}')
                    info = json.loads(r.stdout)
                    self.assertEqual(info.get('backing-filename'), backing)
                    self.assertEqual(
                        info.get('backing-filename-format'), recorded,
                        'the overlay still records its old backing\'s format')

    def test_a_record_that_cannot_change_width_is_refused(self):
        """Onto a Parallels backing, the rebase refuses and writes nothing.

        `parallels` is the one driver name that pads its record to 16
        bytes rather than 8, and the record is rewritten in place, so
        an overlay recording `qcow2` cannot be made to record it
        without moving every header extension behind it. Leaving the
        record alone would be the stale `qcow2` again; the refusal is
        typed, and the overlay is left as it was, reference included.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            overlay = self._overlay_over_qcow2(td)
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'parallels', 'nb.hdd', '4M'],
                capture_output=True, text=True, timeout=30, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)
            before = overlay.read_bytes()

            _, stderr, rc = self.run_instar_rebase(overlay, '-u', '-b', 'nb.hdd')
            self.assertNotEqual(rc, 0, 'a width-changing record must be refused')
            self.assertIn('cannot be updated in place', stderr)
            self.assertEqual(before, overlay.read_bytes(),
                             'a refused rebase must leave the overlay untouched')

    def _overlay_over_qcow2(self, td):
        """A qcow2 overlay recording a `qcow2` backing, in `td`."""
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', 'base.qcow2', '4M'],
            capture_output=True, text=True, timeout=30, cwd=str(td))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', '-b', 'base.qcow2',
             '-F', 'qcow2', 'ovl.qcow2', '4M'],
            capture_output=True, text=True, timeout=30, cwd=str(td))
        self.assertEqual(r.returncode, 0, r.stderr)
        return td / 'ovl.qcow2'


# ----------------------------------------------------------------------
# Chains holding a member the info gate could not identify.
# ----------------------------------------------------------------------


class TestRebaseUnidentifiedChainMember(TestRebaseSmoke):
    """Rebase over, and onto, a raw image with no partition table.

    Secure-mode `info` names such a file `unknown` rather than
    `raw` -- the gate that stops an arbitrary file being accepted
    as a disk image -- and chain discovery kept that name for the
    guest. Rebase's chain reader allowlists the formats it can
    read and `unknown` was not among them, so it refused the whole
    run before reading a byte, with the generic
    unparseable-overlay-header message: issue #629 for a member of
    the old chain, issue #632 for the new backing.

    Each asserts what the overlay then holds, not exit 0 alone. A
    chain member read through the wrong arm returns wrong bytes
    under a success exit, which is the failure the allowlist was
    there to prevent and is exactly what a passing exit code would
    hide.
    """

    def _headerless_raw(self, path, size=1 << 20):
        """A raw image with no partition table and no magic.

        Pseudo-random bytes rather than a pattern: a file of
        repeated bytes could match a format probe by accident, and
        the point of the fixture is that nothing identifies it. The
        seed is fixed so a failure replays with the same bytes.
        """
        path.write_bytes(headerless_bytes(size))

    def _overlay_over(self, td, name, backing_name, backing_format):
        """A qcow2 overlay with one written cluster of its own."""
        overlay = td / name
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-b', backing_name, '-F', backing_format,
             str(overlay), '1M'],
            capture_output=True, text=True, timeout=30, cwd=str(td))
        self.assertEqual(r.returncode, 0, f'create overlay: {r.stderr!r}')
        r = subprocess.run(
            ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x77 128k 64k',
             str(overlay)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, f'qemu-io write: {r.stderr!r}')
        return overlay

    def _composed(self, image):
        """The image's visible content, read back through instar."""
        out = image.parent / (image.name + '.flat')
        _, stderr, rc = self.run_instar_convert(image, out)
        self.assertEqual(rc, 0, f'convert: stderr={stderr!r}')
        return out.read_bytes()

    def test_safe_rebase_reads_an_unidentified_old_chain_member(self):
        """Issue #629: the old chain's raw backing is readable.

        The new backing is given the old chain's exact content, so
        a correct rebase finds the two chains agree and copies
        nothing; a rebase that misread the raw member finds a
        difference that is not there and writes those wrong bytes
        into the overlay, where the content comparison catches it.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self._headerless_raw(td / 'base.raw')
            # Same bytes, qcow2 instead of raw: the chains agree.
            r = subprocess.run(
                ['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
                 'base.raw', 'nb.qcow2'],
                capture_output=True, text=True, timeout=60, cwd=str(td))
            self.assertEqual(r.returncode, 0, r.stderr)

            overlay = self._overlay_over(td, 'a.qcow2', 'base.raw', 'raw')
            before = self._composed(overlay)

            _, stderr, rc = self.run_instar_rebase(
                overlay, '-b', 'nb.qcow2', '-F', 'qcow2')
            self.assertEqual(rc, 0, f'rebase refused: stderr={stderr!r}')
            self.assertEqual(
                before, self._composed(overlay),
                'rebase changed the overlay\'s visible content')

            r = subprocess.run(['qemu-img', 'check', str(overlay)],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0,
                             f'qemu-img check: {r.stdout!r} {r.stderr!r}')

    def test_safe_rebase_onto_an_unidentified_new_backing(self):
        """Issue #632: a raw new backing is readable, and recorded.

        Run against `qemu-img rebase` on an identical overlay: the
        two must agree on the overlay's visible content, and the
        rebased overlay must record `raw` as its backing format.
        Recording the old backing's format instead leaves an
        overlay qemu-img refuses to open at all, which is how that
        half of this was found.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _, stderr, rc = self.run_instar_create(
                '-f', 'qcow2', str(td / 'base.qcow2'), '1M')
            self.assertEqual(rc, 0, stderr)
            r = subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x42 0 64k',
                 str(td / 'base.qcow2')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self._headerless_raw(td / 'nb.raw')

            mine = self._overlay_over(td, 'mine.qcow2', 'base.qcow2', 'qcow2')
            theirs = self._overlay_over(td, 'thrs.qcow2', 'base.qcow2', 'qcow2')

            _, stderr, rc = self.run_instar_rebase(
                mine, '-b', 'nb.raw', '-F', 'raw')
            self.assertEqual(rc, 0, f'rebase refused: stderr={stderr!r}')
            r = subprocess.run(
                ['qemu-img', 'rebase', '-b', 'nb.raw', '-F', 'raw',
                 str(theirs)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, f'qemu-img rebase: {r.stderr!r}')

            self.assertEqual(
                self._composed(mine), self._composed(theirs),
                'instar and qemu-img rebased to different content')

            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(mine)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img could not open the rebased overlay: {r.stderr!r}')
            self.assertEqual(
                json.loads(r.stdout).get('backing-filename-format'), 'raw',
                'the rebased overlay records the wrong backing format')

    def test_detach_from_an_unidentified_backing(self):
        """A raw old chain is read for a detach too.

        Detach keeps every cluster the chain served, so the
        overlay's content after it must be what the chain showed
        before -- which means reading the unidentified member.
        """
        self._require_qemu_tools()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self._headerless_raw(td / 'base.raw')
            overlay = self._overlay_over(td, 'a.qcow2', 'base.raw', 'raw')
            before = self._composed(overlay)

            _, stderr, rc = self.run_instar_rebase(overlay, '-b', '')
            self.assertEqual(rc, 0, f'detach refused: stderr={stderr!r}')
            self.assertEqual(
                before, self._composed(overlay),
                'detach lost content the raw backing was serving')
