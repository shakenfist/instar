"""`create -f vmdk -o subformat=twoGbMaxExtentFlat`, against qemu-img's own output.

A split-flat VMDK is a descriptor plus one sparse extent file per 2 GiB of
virtual size, and instar writes all of it on the host: there is no format to
emit inside a flat extent, so no guest runs. What makes that checkable rather
than merely plausible is that qemu-img's output for the same commands is
already committed. `tests/golden/qemu-create-pins.json` records, for every
static qemu-img build in instar-testdata, the descriptor (with its random CID
and its extent filenames masked), the extent names as a naming scheme, and
each extent's apparent length. `helpers.qemu_pins.run_case` reduces a create
to exactly that shape, and it takes any binary -- so running it with instar in
place of qemu-img gives two results that can be compared field by field.

Six pinned sizes have instar and qemu agreeing. The seventh is where they
part: a create whose second extent file already exists. qemu truncates that
file in place and succeeds; instar refuses, because it derived that path
rather than being given it. The refusal is deliberate, and
`TestCreateVmdkSplitFlatPins.test_a_pre_existing_extent_is_refused_where_qemu_truncates_it`
asserts the divergence against the measurement rather than against an
opinion.

Lengths here are always apparent lengths. The extents are holes -- 64 of them
for the largest image these tests write -- and what a filesystem does with a
hole is a property of the filesystem, not of instar.
"""

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers import qemu_pins
from helpers.vmdk_structure import descriptor_extents, read_descriptor

SPLIT_FLAT = ('-f', 'vmdk', '-o', 'subformat=twoGbMaxExtentFlat')

GIB = 1024 * 1024 * 1024
SECTOR = 512

# qemu's split size, constant across every pinned build: no extent of a
# twoGbMaxExtentFlat image is longer than this, and all but the last are
# exactly this long.
EXTENT_BYTES = 2 * GIB
# The guest's extent table is a fixed array of this many entries, which is
# what instar refuses to write past. It is instar's limit, not qemu's.
MAX_EXTENTS = 64
CEILING_BYTES = MAX_EXTENTS * EXTENT_BYTES

# The pinned cases instar is expected to reproduce byte for byte. Their
# names carry their units: 1 MiB and 2 GiB are one extent each, 2049 MiB and
# 4 GiB two, 5 GiB three, 21 GiB eleven. Every one of them is inside the
# 64-extent ceiling, so all six are comparable.
PINNED_CASES = (
    'vmdk-multi-flat-1M',
    'vmdk-multi-flat-2G',
    'vmdk-multi-flat-2049M',
    'vmdk-multi-flat-4G',
    'vmdk-multi-flat-5G',
    'vmdk-multi-flat-21G',
)

# The case that places a file where the second of three extents goes.
EXISTING_EXTENT_CASE = 'vmdk-multi-flat-5G-existing-extent'

# Words a refusal must not use. A message that names a plan phase, a plan
# file or a date promises the reader something about when the gap closes,
# which landed code does not get to do.
FORBIDDEN_IN_REFUSALS = (
    re.compile(r'\bphase\b', re.IGNORECASE),
    re.compile(r'\bPLAN-'),
    re.compile(r'\.md\b'),
    re.compile(r'\byet\b', re.IGNORECASE),
    re.compile(r'\b20\d\d\b'),
)


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class _SplitFlatBase(InstarTestBase):

    def run_instar_create(self, *args, cwd=None, timeout=300):
        cmd = [str(self.get_instar_binary()), 'create', *[str(one) for one in args]]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return result.stdout, result.stderr, result.returncode

    def create_split_flat(self, path, size, *extra, cwd=None, timeout=300):
        stdout, stderr, rc = self.run_instar_create(*SPLIT_FLAT, *extra, path, size, cwd=cwd, timeout=timeout)
        self.assertEqual(0, rc, f'create of a {size} split-flat VMDK failed: {stderr}')
        return stdout

    def files_in(self, directory):
        return sorted(one.name for one in Path(directory).iterdir())

    def declared_extents(self, descriptor):
        """The extent lines of a descriptor, as the shared parser reads them."""
        text, _ = read_descriptor(descriptor)
        extents = descriptor_extents(text)
        self.assertTrue(extents, f'{descriptor} declares no extents')
        return extents

    def extent_lengths(self, descriptor):
        """Each extent's apparent length, in descriptor order."""
        directory = Path(descriptor).parent
        return [(directory / one['filename']).stat().st_size for one in self.declared_extents(descriptor)]

    def expected_lengths(self, virtual_size):
        """The lengths qemu's 2 GiB split size implies for `virtual_size`."""
        whole, remainder = divmod(virtual_size, EXTENT_BYTES)
        return [EXTENT_BYTES] * whole + ([remainder] if remainder else [])


class TestCreateVmdkSplitFlatPins(_SplitFlatBase):
    """instar's create against the committed record of what qemu-img writes."""

    def _newest_pinned_version(self):
        pin = qemu_pins.load_pin()
        return max(pin['versions'], key=qemu_pins.version_key)

    def _run_case_with_instar(self, case_name, workdir):
        return qemu_pins.run_case(self.get_instar_binary(), case_name, Path(workdir))

    def test_descriptor_extent_names_and_lengths_match_the_pin(self):
        """Every comparable pinned size reproduces qemu's descriptor, names and extent lengths.

        The comparison is the whole reduced result: the return code, stderr,
        the descriptor text with the CID and the extent filenames masked, the
        extent names as a naming scheme, and each extent's apparent length.
        The CID mask is what lets this pass at all -- qemu writes a random
        CID and instar writes a fixed one by design -- and the filename mask
        turns the extent lines into the order and count of the extents rather
        than a list of paths.

        The pin holds two answers for these cases, qemu 6.0.0 to 6.1.1 and
        6.2.0 onwards, which differ by a `ddb.toolsVersion` line qemu started
        writing in 6.2.0. instar writes the modern form, so the comparison is
        against the newest pinned build.
        """
        version = self._newest_pinned_version()
        for case_name in PINNED_CASES:
            with self.subTest(case=case_name), tempfile.TemporaryDirectory() as workdir:
                want = qemu_pins.expected(case_name, version=version)
                got = self._run_case_with_instar(case_name, workdir)
                self.assertEqual(0, got['rc'], got['stderr'])
                differences = qemu_pins.result_diff(want, got)
                self.assertEqual([], differences,
                                 f'{case_name}: instar differs from qemu-img {version} '
                                 f'(pinned != measured):\n' + '\n'.join(differences))

    def test_the_pin_says_qemu_truncates_a_pre_existing_extent_in_place(self):
        """The measurement decision 1 diverges from, read out of the pin.

        The case drops a 1 MiB file at `image-f002.vmdk`, where the second of
        three extents goes, and keeps a second hard link to it under a name
        no extent uses. The link is what makes the result legible: the file
        at the extent's name says only what is there when the command
        finished, while the kept link says what became of the file that was
        there before. A kept link still holding 1 MiB would mean qemu
        unlinked what it found and created its own file. A kept link holding
        an extent's length means qemu truncated the file that was already
        there, in place.

        It holds 2 GiB, in both of the case's pinned answers and so across
        all 80 builds. qemu also returns 0 and writes the same descriptor it
        writes when nothing is in the way.
        """
        pin = qemu_pins.load_pin()
        groups = pin['cases'][EXISTING_EXTENT_CASE]
        self.assertTrue(groups)
        plain = {version: qemu_pins.expected('vmdk-multi-flat-5G', version=version, pin=pin)
                 for version in pin['versions']}
        for group in groups:
            for version in group['versions']:
                with self.subTest(qemu=version):
                    want = qemu_pins.expected(EXISTING_EXTENT_CASE, version=version, pin=pin)
                    self.assertEqual(0, want['rc'])
                    self.assertEqual([EXTENT_BYTES, EXTENT_BYTES, GIB], want['extent_lengths'])
                    self.assertEqual([EXTENT_BYTES], want['existing_kept_lengths'],
                                     'the kept link holds an extent length, so qemu truncated the '
                                     'pre-existing file in place rather than unlinking it')
                    self.assertNotEqual([qemu_pins.EXISTING_EXTENT_SIZE], want['existing_kept_lengths'])
                    self.assertEqual(plain[version]['descriptor'], want['descriptor'],
                                     'qemu writes the same descriptor whether or not an extent was there')

    def test_a_pre_existing_extent_is_refused_where_qemu_truncates_it(self):
        """instar refuses the create qemu-img completes, and leaves the file alone.

        Run against the same case, with the same pre-existing 1 MiB file and
        the same kept link. instar fails, writes neither the descriptor nor
        any extent, and leaves the kept link holding the 1 MiB it started
        with -- where every pinned qemu build returns 0 and leaves it holding
        2 GiB. The extents are instar's own invention, derived from the one
        path the user named, and truncating sixty-four files nobody asked for
        is not something to do silently; the cost is that re-running a failed
        create means removing them by hand.
        """
        want = qemu_pins.expected(EXISTING_EXTENT_CASE, version=self._newest_pinned_version())
        with tempfile.TemporaryDirectory() as workdir:
            got = self._run_case_with_instar(EXISTING_EXTENT_CASE, workdir)

        self.assertEqual(0, want['rc'])
        self.assertEqual([EXTENT_BYTES], want['existing_kept_lengths'])

        self.assertNotEqual(0, got['rc'], 'instar is expected to refuse what qemu-img accepts here')
        self.assertIsNone(got['descriptor'], 'no descriptor is written')
        self.assertIsNone(got['extent_lengths'], 'no extent is written')
        self.assertEqual([qemu_pins.EXISTING_EXTENT_SIZE], got['existing_kept_lengths'],
                         'the pre-existing file keeps its length, so instar neither truncated nor '
                         'unlinked it')
        self.assertIn('image-f002.vmdk', got['stderr'], 'the refusal names the offending extent')
        self.assertIn('already exists', got['stderr'])


class TestCreateVmdkSplitFlat(_SplitFlatBase):
    """The command itself: what it writes, what it reads back, and what it refuses."""

    def test_five_gib_writes_three_extents_of_the_pinned_lengths(self):
        """2 GiB, 2 GiB then 1 GiB beside the descriptor, by apparent length."""
        with tempfile.TemporaryDirectory() as workdir:
            descriptor = Path(workdir) / 'out.vmdk'
            self.create_split_flat(descriptor, '5G')
            self.assertEqual(['out-f001.vmdk', 'out-f002.vmdk', 'out-f003.vmdk', 'out.vmdk'],
                             self.files_in(workdir))
            self.assertEqual([EXTENT_BYTES, EXTENT_BYTES, GIB], self.extent_lengths(descriptor))
            self.assertEqual([4194304, 4194304, 2097152],
                             [one['sectors'] for one in self.declared_extents(descriptor)])

    def test_instar_info_reads_back_what_create_wrote(self):
        """info reports the virtual size create was asked for, and names the extents it made."""
        for size, virtual_size in (('1M', 1024 * 1024), ('5G', 5 * GIB), ('21G', 21 * GIB)):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as workdir:
                descriptor = Path(workdir) / 'out.vmdk'
                self.create_split_flat(descriptor, size)
                stdout, stderr, rc = self.run_instar_info(descriptor, output_format='json', timeout=120)
                self.assertEqual(0, rc, stderr)
                info = json.loads(stdout)
                self.assertEqual('vmdk', info['format'])
                self.assertEqual(virtual_size, info['virtual-size'])
                self.assertEqual('twoGbMaxExtentFlat', info['format-specific']['data']['create-type'])
                self.assertEqual([one['filename'] for one in self.declared_extents(descriptor)],
                                 [Path(one['filename']).name
                                  for one in info['format-specific']['data']['extents']])

    def test_the_largest_accepted_size_writes_sixty_four_extents(self):
        """128 GiB is 64 extents exactly, and is accepted and readable back.

        The 64 files are holes of 2 GiB apparent length each, so this writes
        no real bytes. Nothing asserts what the filesystem allocated for
        them, which is the filesystem's business; the lengths are what the
        descriptor declares the image to be.
        """
        with tempfile.TemporaryDirectory() as workdir:
            descriptor = Path(workdir) / 'out.vmdk'
            self.create_split_flat(descriptor, str(CEILING_BYTES))
            declared = self.declared_extents(descriptor)
            self.assertEqual(MAX_EXTENTS, len(declared))
            self.assertEqual([f'out-f{index:03d}.vmdk' for index in range(1, MAX_EXTENTS + 1)],
                             [one['filename'] for one in declared])
            self.assertEqual([EXTENT_BYTES] * MAX_EXTENTS, self.extent_lengths(descriptor))
            stdout, stderr, rc = self.run_instar_info(descriptor, output_format='json', timeout=120)
            self.assertEqual(0, rc, stderr)
            self.assertEqual(CEILING_BYTES, json.loads(stdout)['virtual-size'])

    def test_one_byte_past_the_ceiling_is_refused_and_writes_nothing(self):
        """128 GiB + 1 needs 65 extents, so it is refused before anything is opened.

        The message names the limit and the size that reached it, and says
        the limit is instar's own rather than qemu's -- qemu-img writes a
        split image of any size it can express, and the pinned builds show no
        ceiling at all. instar's exists because the guest's extent table is a
        fixed array: an image past it is one instar's own reader declines, and
        output instar cannot read back is not worth writing.
        """
        with tempfile.TemporaryDirectory() as workdir:
            size = CEILING_BYTES + 1
            _, stderr, rc = self.run_instar_create(*SPLIT_FLAT, Path(workdir) / 'out.vmdk', str(size))
            self.assertEqual(1, rc, stderr)
            self.assertIn('65 extents', stderr)
            self.assertIn(str(MAX_EXTENTS), stderr)
            self.assertIn(str(size), stderr)
            self.assertIn("not qemu's", stderr)
            self.assertEqual([], self.files_in(workdir), 'neither descriptor nor extent is left behind')

    def test_a_zero_size_is_refused_and_writes_nothing(self):
        """A zero virtual size is refused before any file is opened.

        Zero bytes lays out no extents at all, and a descriptor with no
        extent lines is one instar's own reader declines. The split writer
        refuses it on that ground, but create's generic size check gets there
        first and refuses the argument itself, which is why the message here
        is the generic one. The subformat's own refusal stays as the inner
        guard for a caller that does not come through the command line.
        """
        with tempfile.TemporaryDirectory() as workdir:
            _, stderr, rc = self.run_instar_create(*SPLIT_FLAT, Path(workdir) / 'out.vmdk', '0')
            self.assertEqual(1, rc, stderr)
            self.assertIn('SIZE must be greater than zero', stderr)
            self.assertEqual([], self.files_in(workdir))

    def test_a_pre_existing_derived_extent_is_refused_byte_for_byte(self):
        """The file in the way is named in the refusal and is not touched.

        The pinned case proves the length is unchanged. This proves the
        contents are: the file holds a pattern no extent would, and its
        digest is the same afterwards. Each of the three derived names is
        tried in turn, so the refusal is not merely the first one.
        """
        pattern = bytes(range(256)) * 97
        for index in (1, 2, 3):
            name = f'out-f{index:03d}.vmdk'
            with self.subTest(extent=name), tempfile.TemporaryDirectory() as workdir:
                existing = Path(workdir) / name
                existing.write_bytes(pattern)
                before = _hash(existing)
                _, stderr, rc = self.run_instar_create(*SPLIT_FLAT, Path(workdir) / 'out.vmdk', '5G')
                self.assertEqual(1, rc, stderr)
                self.assertIn(name, stderr)
                self.assertIn('already exists', stderr)
                self.assertEqual([name], self.files_in(workdir), 'nothing else was written')
                self.assertEqual(len(pattern), existing.stat().st_size)
                self.assertEqual(before, _hash(existing))

    def test_a_pre_existing_descriptor_is_still_overwritten(self):
        """The one path the user named keeps create's documented contract.

        `CreateArgs::filename` promises the output is overwritten if it
        already exists, matching qemu-img, and the split subformat is not an
        exception to it: only the extent paths instar derived are protected.
        """
        with tempfile.TemporaryDirectory() as workdir:
            descriptor = Path(workdir) / 'out.vmdk'
            descriptor.write_bytes(b'this is not a descriptor\n' * 100)
            self.create_split_flat(descriptor, '5G')
            text, _ = read_descriptor(descriptor)
            self.assertIn('createType="twoGbMaxExtentFlat"', text)
            self.assertNotIn('this is not a descriptor', text)
            self.assertEqual([EXTENT_BYTES, EXTENT_BYTES, GIB], self.extent_lengths(descriptor))

    def test_the_sparse_split_subformat_is_refused_with_what_is_supported(self):
        """twoGbMaxExtentSparse needs format emission in the guest, and create says so plainly.

        The message names the subformat it will not write and lists the ones
        it will, and promises nothing about when that changes: no plan phase,
        no file name, no date.
        """
        with tempfile.TemporaryDirectory() as workdir:
            _, stderr, rc = self.run_instar_create('-f', 'vmdk', '-o', 'subformat=twoGbMaxExtentSparse',
                                                   Path(workdir) / 'out.vmdk', '5G')
            self.assertEqual(1, rc, stderr)
            self.assertIn('twoGbMaxExtentSparse', stderr)
            self.assertIn('not supported for create', stderr)
            for supported in ('monolithicSparse', 'streamOptimized', 'monolithicFlat', 'twoGbMaxExtentFlat'):
                self.assertIn(supported, stderr)
            for pattern in FORBIDDEN_IN_REFUSALS:
                self.assertIsNone(pattern.search(stderr), f'the refusal must not say {pattern.pattern!r}: {stderr}')
            self.assertEqual([], self.files_in(workdir))

    def test_grain_size_is_refused_as_qemu_refuses_it(self):
        """A grain size is refused, which is what qemu-img does too -- for its own reason.

        Measured against the static builds: qemu-img has no grain-size create
        option for vmdk at any subformat, so it refuses `grain_size` as an
        invalid parameter whatever the subformat. instar accepts a grain size
        for the sparse subformats as an extension of its own, and refuses it
        here because a flat extent has no grains. Both refuse; the test
        asserts instar's half, and the qemu half is what makes it a match
        rather than a guess.
        """
        for args in (('-o', 'grain_size=65536'), ('--grain-size', '65536')):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as workdir:
                _, stderr, rc = self.run_instar_create(*SPLIT_FLAT, *args, Path(workdir) / 'out.vmdk', '5G')
                self.assertEqual(1, rc, stderr)
                self.assertIn('twoGbMaxExtentFlat has no grains', stderr)
                self.assertEqual([], self.files_in(workdir))

    def test_the_extent_lengths_follow_the_split_size_at_every_pinned_size(self):
        """Each pinned size's extents are 2 GiB apiece with the remainder last.

        The arithmetic is stated here independently of the pin, so a change
        that moved every length consistently -- in instar and in the pinned
        descriptor's sector counts alike -- would still be caught.
        """
        for size, virtual_size in (('1M', 1024 * 1024), ('2G', 2 * GIB), ('2049M', 2049 * 1024 * 1024),
                                   ('4G', 4 * GIB), ('5G', 5 * GIB), ('21G', 21 * GIB)):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as workdir:
                descriptor = Path(workdir) / 'out.vmdk'
                self.create_split_flat(descriptor, size)
                lengths = self.extent_lengths(descriptor)
                self.assertEqual(self.expected_lengths(virtual_size), lengths)
                self.assertEqual(virtual_size, sum(lengths))
                self.assertEqual(virtual_size,
                                 sum(one['sectors'] for one in self.declared_extents(descriptor)) * SECTOR)


class TestSplitFlatIsCreateOnly(_SplitFlatBase):
    """Only `create` knows this subformat; the sibling subcommands still refuse it.

    `create`'s `--subformat` value list gained twoGbMaxExtentFlat, and convert
    and measure keep their own lists and their own `-o` parsers. Nothing shares
    a list between them, which is exactly why a later widening could leak into
    one of them unnoticed: a subformat convert accepted but could not emit
    would write a descriptor naming extents it never made.
    """

    def run_instar(self, *args, timeout=300):
        cmd = [str(self.get_instar_binary()), *[str(one) for one in args]]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode

    def test_convert_and_measure_refuse_the_split_flat_subformat(self):
        """Each refuses it by name, before writing anything, and says what it does take."""
        cases = (
            ('convert --subformat', ('convert', '-O', 'vmdk', '--subformat', 'twoGbMaxExtentFlat'), 1),
            ('measure -o subformat', ('measure', '-O', 'vmdk', '-o', 'subformat=twoGbMaxExtentFlat'), 1),
            # Refused by the argument parser rather than by instar's own
            # validation, which is why the exit code differs.
            ('measure --subformat', ('measure', '-O', 'vmdk', '--subformat', 'twoGbMaxExtentFlat'), 2),
        )
        with tempfile.TemporaryDirectory() as workdir:
            source = Path(workdir) / 'in.raw'
            self.run_instar('create', '-q', '-f', 'raw', source, '1M')
            for name, args, expected_rc in cases:
                with self.subTest(case=name):
                    out = Path(workdir) / 'out.vmdk'
                    extra = (out,) if args[0] == 'convert' else ()
                    _, stderr, rc = self.run_instar(*args, source, *extra)
                    self.assertEqual(expected_rc, rc, stderr)
                    self.assertIn('twoGbMaxExtentFlat', stderr)
                    self.assertIn('monolithicFlat', stderr)
                    self.assertFalse(out.exists(), f'{name} wrote an output it had refused')
            self.assertEqual(['in.raw'], self.files_in(workdir))
