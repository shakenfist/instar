"""What qemu's fixed VHDX images are, and what instar reads from them.

instar-testdata holds four small fixed VHDX images written by `qemu-img`
(two whole 8 MiB blocks, and two blocks plus a 1 MiB partial one, each in
both `block_state_zero` modes, the `off` pair carrying data) and a dynamic
image at the geometry where the BAT exactly fills its 1 MiB region, the
geometry #626 was about, in 8 MiB. `scripts/create-vhd-testdata.sh` writes
them.

`TestVhdxFixedFixturePins` checks that each committed file has the
structure every pinned `qemu-img` build writes for its command
(`helpers.qemu_pins`), so the fixture stands for all of them rather than
for the one build that generated it, and that each fixed fixture holds
exactly the data the generator wrote, read through its BAT. That needs no
qemu, so it also catches a fixture whose data never landed, which the
reads below would not: instar and qemu-img agree on an all-zero image.

`TestVhdxFixedReads` runs instar's read operations on those fixtures and
on five images built here with the host `qemu-img`: the two convert-to-fixed
images, whose data blocks qemu appends past the preallocated area (a layout
no committed fixture has), fixed images at the #626 geometry, which as
128 GiB files are too large to commit, and a fixed image whose partial last
block lies past the first chunk, which qemu writes but cannot open again.
Every image built by `qemu-img create`, and the committed dynamic image at
the #626 geometry, gets only the operations that do not read the data region
(`info`, `check`, `map`, `measure`); the BAT walk #626 broke is in those,
and a convert or compare of a 128 GiB virtual disk would read all of it. The
committed dynamic image is also converted to qcow2: every one of its BAT
entries is ZERO, so the convert walks the BAT without reading any data.

`TestVhdxFixedReads` also pins how `check` treats a FULLY_PRESENT partial
last block (#797): whole, it is clean and ends the image, and cut short in
the file, or cut off at its start, it is a corruption.

`KNOWN_READ_FAILURES` lists what instar would still get wrong. It is empty
while instar reads every image here as qemu-img does; a listed pair must
still fail, with the message recorded there, and once instar reads it
correctly the test fails and asks for the entry to be removed, so a fix
shows up here rather than going unnoticed.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import QEMU_TOOL_TIMEOUT, InstarTestBase
from helpers import qemu_pins
from helpers.vhdx_structure import KIND_PAYLOAD, parse_vhdx, structural_diff, summarise

KiB = 1024
MiB = 1024 * KiB

# Each committed fixture's manifest id, and the pin case for the
# `qemu-img create` that wrote it. The data written into the `off` images
# afterwards lands in blocks the BAT already marks FULLY_PRESENT, so it
# leaves their structure equal to the empty image's.
FIXTURE_PIN_CASES = {
    'vhdx-fixed-16M': 'vhdx-fixed-16M',
    'vhdx-fixed-16M-bsz-off-data': 'vhdx-fixed-16M-bsz-off',
    'vhdx-fixed-17M': 'vhdx-fixed-17M',
    'vhdx-fixed-17M-bsz-off-data': 'vhdx-fixed-17M-bsz-off',
    'vhdx-dynamic-131041M-block-1M': 'vhdx-dynamic-131041M-block-1M',
}

# What `scripts/create-vhd-testdata.sh` writes into each fixed fixture with
# qemu-io, as (offset, length, byte); every other byte of the virtual disk
# is zero. The last write in the 17M image lands in its partial final
# block, the block #797 is about.
FIXTURE_DATA = {
    'vhdx-fixed-16M': (),
    'vhdx-fixed-16M-bsz-off-data': ((0, 64 * KiB, 0x11), (12 * MiB, 64 * KiB, 0x22)),
    'vhdx-fixed-17M': (),
    'vhdx-fixed-17M-bsz-off-data': ((0, 64 * KiB, 0x33), (17344 * KiB, 64 * KiB, 0x44)),
}

# BAT payload states (SPEC(VHDX) 2.5.1): those that read as zeros, and the
# one whose block is read from the file.
ZERO_STATES = (0, 1, 2, 3)
FULLY_PRESENT = 6

# Images built at test time by `qemu-img convert -f raw -O vhdx` of
# `qemu_pins.write_convert_source`, named for the pin case whose `-o`
# options they use.
RUNTIME_CONVERT_IMAGES = ('vhdx-convert-fixed', 'vhdx-convert-fixed-bsz-off')

# Images built at test time by `qemu-img create -f vhdx`: name to `-o`
# options and size. 131041 one-MiB payload blocks and their 31 sector
# bitmap slots fill a 1 MiB BAT region exactly (SPEC(VHDX) 2.5), the
# geometry #626 miscounted. At 4608.5M with 1 MiB blocks the last payload
# block, number 4608, holds 512 KiB and lies past the first 4096-block
# chunk, so its BAT index (4609) is not its payload index; with
# block_state_zero off it is FULLY_PRESENT, and qemu allocates it only as
# far as the end of the virtual disk. The files are sparse.
PARTIAL_PAST_FIRST_CHUNK = 'vhdx-fixed-4608.5M-block-1M-bsz-off'
RUNTIME_CREATE_IMAGES = {
    'vhdx-fixed-131041M-block-1M': ('subformat=fixed,block_size=1M', '131041M'),
    'vhdx-fixed-131041M-block-1M-bsz-off': ('subformat=fixed,block_size=1M,block_state_zero=off', '131041M'),
    PARTIAL_PAST_FIRST_CHUNK: ('subformat=fixed,block_size=1M,block_state_zero=off', '4608.5M'),
}

# Images qemu-img writes but cannot open again, and the virtual size each
# was created with, which stands in for `qemu-img info` as the oracle. qemu
# checks every FULLY_PRESENT block against the end of the file on open, and
# sizes a partial last block by its BAT index rather than its payload index,
# so past the first chunk it demands a whole block the file does not hold.
# See "VHDX partial last block past the first chunk" in docs/quirks.md.
QEMU_CANNOT_OPEN = {
    PARTIAL_PAST_FIRST_CHUNK: 4608 * MiB + 512 * KiB,
}

OP_INFO = 'info'
OP_CHECK = 'check'
OP_MAP = 'map'
OP_MEASURE = 'measure'
OP_CONVERT = 'convert'
OP_COMPARE = 'compare'
# The operations that read only the headers, metadata and BAT.
METADATA_OPS = (OP_INFO, OP_CHECK, OP_MAP, OP_MEASURE)
ALL_OPS = METADATA_OPS + (OP_CONVERT, OP_COMPARE)

# The committed image at the #626 geometry whose BAT is all ZERO entries,
# so that converting it walks the whole BAT and reads no data.
DYNAMIC_131041M = 'vhdx-dynamic-131041M-block-1M'

# Which operations run on which image. The 131041 MiB images get only the
# metadata operations, since a convert or compare would read 128 GiB;
# `test_dynamic_131041m_converts_to_qcow2` converts the one that holds no
# data.
READ_MATRIX = {name: ALL_OPS for name in list(FIXTURE_PIN_CASES) + list(RUNTIME_CONVERT_IMAGES)}
READ_MATRIX.update({name: METADATA_OPS for name in [DYNAMIC_131041M, *RUNTIME_CREATE_IMAGES]})

# Reads instar is known to get wrong: (image, operation) to (issue,
# message). It is empty because instar reads every image in the matrix as
# qemu-img does. It stays so that a regression found later, with an issue
# filed for it, can be recorded here before its fix lands: a listed pair
# must still fail, its output must contain the message, and once it passes
# the test asks for the entry to be removed. `check` reports why only on its
# verbose output, so it is run with `-v` here. A map failure would match
# loosely: the map guest reports no reason, even with -v, so any failure to
# lay out the BAT reads as an unrecognised format.
KNOWN_READ_FAILURES = {}

# The committed fixture whose last payload block is partial and
# FULLY_PRESENT: data starts at 8 MiB, the two whole 8 MiB blocks sit at 8
# and 16 MiB, and the third block starts at 24 MiB and holds the 1 MiB the
# 17 MiB virtual disk needs, which is where the file ends.
PARTIAL_LAST_BLOCK = 'vhdx-fixed-17M-bsz-off-data'
PARTIAL_LAST_BLOCK_START = 24 * MiB
PARTIAL_LAST_BLOCK_FILE_END = 25 * MiB

COMPARE_CHUNK = 1024 * 1024


def _test_name(image_name, op=None):
    suffix = f'_{op}' if op else ''
    return 'test_' + image_name.replace('-', '_').replace('.', '_') + suffix


def _failure_line(op, stdout, stderr):
    """Why `instar op` failed, in a line.

    That is the last message the guest operation printed before finishing,
    when verbose output carries one, and otherwise the first line of output
    that is not a tagged log line.
    """
    marker = f'[GUEST] {op}: '
    messages = [line.split(marker, 1)[1].strip() for line in stderr.splitlines() if marker in line]
    messages = [message for message in messages if message != 'done']
    if messages:
        return messages[-1]
    for line in (stderr + stdout).splitlines():
        if line.strip() and not line.startswith('['):
            return line.strip()
    return '(no output)'


def _first_difference(a: Path, b: Path):
    """The first byte offset at which two files differ, or None if they are identical."""
    offset = 0
    with open(a, 'rb') as fa, open(b, 'rb') as fb:
        while True:
            chunk_a = fa.read(COMPARE_CHUNK)
            chunk_b = fb.read(COMPARE_CHUNK)
            if chunk_a != chunk_b:
                for i in range(min(len(chunk_a), len(chunk_b))):
                    if chunk_a[i] != chunk_b[i]:
                        return offset + i
                return offset + min(len(chunk_a), len(chunk_b))
            if not chunk_a:
                return None
            offset += len(chunk_a)


def _virtual_disk(path: Path) -> bytes:
    """The virtual disk of a VHDX with no parent, read through its BAT without qemu or instar."""
    structure = parse_vhdx(path)
    size = structure.virtual_disk_size
    disk = bytearray(size)
    payload_blocks = (entry for entry in structure.bat_entries() if entry[1] == KIND_PAYLOAD)
    with open(path, 'rb') as handle:
        for block, (index, _kind, state, offset) in enumerate(payload_blocks):
            if state in ZERO_STATES:
                continue
            if state != FULLY_PRESENT:
                raise ValueError(f'BAT entry {index} has state {state}, which this reader does not handle')
            start = block * structure.block_size
            length = min(structure.block_size, size - start)
            handle.seek(offset)
            chunk = handle.read(length)
            if len(chunk) != length:
                raise ValueError(f'BAT entry {index} at file offset {offset} runs past the end of the file')
            disk[start:start + length] = chunk
    return bytes(disk)


def _map_coverage_problems(extents, virtual_size):
    """Why `extents` do not tile `[0, virtual_size)` exactly, or nothing if they do."""
    position = 0
    for extent in sorted(extents, key=lambda e: e['start']):
        if extent['start'] != position:
            kind = 'a gap' if extent['start'] > position else 'an overlap'
            return [f'map extents have {kind} at {position}: the next extent starts at {extent["start"]}']
        position = extent['start'] + extent['length']
    if position != virtual_size:
        return [f'map extents end at {position}, not at the virtual size {virtual_size}']
    return []


class TestVhdxFixedFixturePins(InstarTestBase):
    """Each committed fixture has the structure every pinned qemu-img build writes, and its data."""


def _make_pin_test(image_id, case_name):
    def test(self):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        want = qemu_pins.expected(case_name)['summary']
        differences = structural_diff(summarise(parse_vhdx(image.path)), want)
        self.assertEqual([], differences,
                         f'{image_id} does not have the structure qemu-img writes for pin case {case_name} '
                         f'(fixture != pin):\n' + '\n'.join(differences))

    test.__doc__ = f'{image_id} has the structure of pin case {case_name}.'
    return test


def _make_data_test(image_id, writes):
    def test(self):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        got = _virtual_disk(image.path)
        want = bytearray(len(got))
        for offset, length, byte in writes:
            want[offset:offset + length] = bytes([byte]) * length
        if got != want:
            first = next(i for i in range(len(got)) if got[i] != want[i])
            self.fail(f'{image_id} holds 0x{got[first]:02x} at virtual offset {first} where the generator wrote '
                      f'0x{want[first]:02x}; regenerate it with scripts/create-vhd-testdata.sh')

    test.__doc__ = f'{image_id} holds exactly the data the generator wrote.'
    return test


for _image_id, _case_name in FIXTURE_PIN_CASES.items():
    setattr(TestVhdxFixedFixturePins, _test_name(_image_id), _make_pin_test(_image_id, _case_name))
for _image_id, _writes in FIXTURE_DATA.items():
    setattr(TestVhdxFixedFixturePins, _test_name(_image_id, 'data'), _make_data_test(_image_id, _writes))


class TestVhdxFixedReads(InstarTestBase):
    """instar reads qemu's fixed VHDX images as qemu-img does, except where KNOWN_READ_FAILURES says."""

    def _require_qemu_vhdx(self):
        self._require_qemu_img()
        self.skip_unless_qemu_supports('vhdx')

    def _image(self, name, workdir: Path) -> Path:
        """The image called `name`: a committed fixture, or one built in `workdir` with the host qemu-img."""
        if name in FIXTURE_PIN_CASES:
            image = self.get_image(name)
            if not image.path.exists():
                self.skipTest(f'fixture not available: {image.path}')
            return image.path

        self._require_qemu_vhdx()
        path = workdir / f'{name}.vhdx'
        if name in RUNTIME_CONVERT_IMAGES:
            source = workdir / 'source.raw'
            qemu_pins.write_convert_source(source)
            options = qemu_pins.CASES_BY_NAME[name]['options']
            self._run_tool(['qemu-img', 'convert', '-f', 'raw', '-O', 'vhdx', '-o', options, str(source), str(path)],
                           workdir)
        else:
            options, size = RUNTIME_CREATE_IMAGES[name]
            self._run_tool(['qemu-img', 'create', '-q', '-f', 'vhdx', '-o', options, str(path), size], workdir)
        return path

    def _instar(self, *args):
        """Run instar; return (stdout, stderr, returncode)."""
        cmd = [str(self.get_instar_binary())] + [str(arg) for arg in args]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=QEMU_TOOL_TIMEOUT)
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {QEMU_TOOL_TIMEOUT}s', -1
        return r.stdout, r.stderr, r.returncode

    def _qemu_raw(self, image: Path, workdir: Path) -> Path:
        reference = workdir / 'qemu.raw'
        self._run_tool(['qemu-img', 'convert', '-f', 'vhdx', '-O', 'raw', str(image), str(reference)], workdir)
        return reference

    # Each operation returns (problems, output): what instar did that
    # qemu-img does not, empty when it read the image correctly, and its
    # combined output for matching a known failure's message. Each is given
    # the image's name as well as its path, because for an image in
    # QEMU_CANNOT_OPEN the oracle is not qemu-img's reading of the file.

    def _op_info(self, name, image: Path, workdir: Path):
        self._require_qemu_vhdx()
        stdout, stderr, rc = self._instar('info', '--output', 'json', image)
        if rc != 0:
            return [f'instar info exited {rc}: {_failure_line(OP_INFO, stdout, stderr)}'], stdout + stderr
        if name in QEMU_CANNOT_OPEN:
            want = QEMU_CANNOT_OPEN[name]
        else:
            qemu = self._run_tool(['qemu-img', 'info', '-f', 'vhdx', '--output=json', str(image)], workdir)
            want = json.loads(qemu.stdout)['virtual-size']
        got = json.loads(stdout)['virtual-size']
        problems = [] if got == want else [f'instar info virtual-size {got} != qemu-img {want}']
        return problems, stdout + stderr

    def _op_check(self, name, image: Path, workdir: Path):
        stdout, stderr, rc = self._instar('check', '-v', image)
        problems = [] if rc == 0 else [f'instar check exited {rc}: {_failure_line(OP_CHECK, stdout, stderr)}']
        return problems, stdout + stderr

    def _op_map(self, name, image: Path, workdir: Path):
        # instar reports BAT-level extents where qemu-img merges them into
        # one, so the output is not compared with qemu's; it must tile the
        # virtual disk, whose size comes from the image's own metadata.
        stdout, stderr, rc = self._instar('map', '--output', 'json', image)
        if rc != 0:
            return [f'instar map exited {rc}: {_failure_line(OP_MAP, stdout, stderr)}'], stdout + stderr
        try:
            extents = json.loads(stdout)
        except json.JSONDecodeError as e:
            return [f'instar map --output json is not JSON: {e}'], stdout + stderr
        return _map_coverage_problems(extents, parse_vhdx(image).virtual_disk_size), stdout + stderr

    def _op_measure(self, name, image: Path, workdir: Path):
        """instar measure -O qcow2 must succeed and agree with qemu-img on `fully-allocated`.

        `required` is not compared. For a VHDX source the two tools count
        allocation differently: qemu's vhdx driver reports no block status,
        so `qemu-img measure` counts every block as data, while instar walks
        the BAT and counts no ZERO block. On an all-ZERO fixed image qemu's
        `required` is the whole disk and instar's is metadata only, and
        neither is a misread of the image. `fully-allocated` depends only on
        the virtual size, which both must read the same. For an image qemu
        cannot open, qemu-img measures that virtual size with `--size`.
        """
        self._require_qemu_vhdx()
        stdout, stderr, rc = self._instar('measure', '-O', 'qcow2', '--output', 'json', image)
        if rc != 0:
            return [f'instar measure exited {rc}: {_failure_line(OP_MEASURE, stdout, stderr)}'], stdout + stderr
        if name in QEMU_CANNOT_OPEN:
            source = ['--size', str(QEMU_CANNOT_OPEN[name])]
        else:
            source = ['-f', 'vhdx', str(image)]
        qemu = self._run_tool(['qemu-img', 'measure', '-O', 'qcow2', '--output=json', *source], workdir)
        want = json.loads(qemu.stdout)['fully-allocated']
        try:
            got = json.loads(stdout)['fully-allocated']
        except (json.JSONDecodeError, KeyError) as e:
            return [f'instar measure --output json has no fully-allocated: {e!r}'], stdout + stderr
        problems = [] if got == want else [f'instar measure fully-allocated {got} != qemu-img {want}']
        return problems, stdout + stderr

    def _op_convert(self, name, image: Path, workdir: Path):
        self._require_qemu_vhdx()
        output = workdir / 'instar.raw'
        stdout, stderr, rc = self._instar('convert', '-O', 'raw', image, output)
        if rc != 0:
            return [f'instar convert exited {rc}: {_failure_line(OP_CONVERT, stdout, stderr)}'], stdout + stderr
        reference = self._qemu_raw(image, workdir)
        offset = _first_difference(output, reference)
        problems = []
        if offset is not None:
            problems.append(f'instar convert -O raw differs from qemu-img convert -O raw at byte {offset} '
                            f'(sizes {output.stat().st_size} and {reference.stat().st_size})')
        return problems, stdout + stderr

    def _op_compare(self, name, image: Path, workdir: Path):
        self._require_qemu_vhdx()
        reference = self._qemu_raw(image, workdir)
        stdout, stderr, rc = self._instar('compare', image, reference)
        problems = [] if rc == 0 else [f'instar compare with qemu-img\'s raw conversion exited {rc}: '
                                       f'{_failure_line(OP_COMPARE, stdout, stderr)}']
        return problems, stdout + stderr

    def _check_read(self, image_name, op):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            image = self._image(image_name, workdir)
            problems, output = getattr(self, f'_op_{op}')(image_name, image, workdir)

        known = KNOWN_READ_FAILURES.get((image_name, op))
        if known is None:
            self.assertEqual([], problems, f'instar {op} misreads {image_name}')
            return
        issue, message = known
        if not problems:
            self.fail(f'instar {op} now reads {image_name} correctly, so #{issue} looks fixed: remove this entry, '
                      f'({image_name!r}, {op!r}), from KNOWN_READ_FAILURES')
        if message not in output:
            self.fail(f'instar {op} on {image_name} fails, but not with the message KNOWN_READ_FAILURES records for '
                      f'#{issue} ({message!r}): {problems}')

    def test_map_coverage_finds_gaps_overlaps_and_short_ends(self):
        """The map oracle accepts only extents that tile the virtual disk exactly."""
        def extents(*spans):
            return [{'start': start, 'length': length} for start, length in spans]

        self.assertEqual([], _map_coverage_problems(extents((4, 6), (0, 4)), 10))
        self.assertEqual(['map extents have a gap at 4: the next extent starts at 5'],
                         _map_coverage_problems(extents((0, 4), (5, 5)), 10))
        self.assertEqual(['map extents have an overlap at 4: the next extent starts at 3'],
                         _map_coverage_problems(extents((0, 4), (3, 7)), 10))
        self.assertEqual(['map extents end at 8, not at the virtual size 10'],
                         _map_coverage_problems(extents((0, 4), (4, 4)), 10))
        self.assertEqual(['map extents end at 0, not at the virtual size 10'], _map_coverage_problems([], 10))

    def test_dynamic_131041m_converts_to_qcow2(self):
        """instar converts the dynamic image at the #626 geometry to qcow2, keeping its virtual size.

        Every BAT entry of the fixture is ZERO, so the convert walks the
        whole 131072-entry BAT, which #626 miscounted, and reads no data.
        """
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            image = self._image(DYNAMIC_131041M, workdir)
            self._require_qemu_vhdx()
            output = workdir / 'out.qcow2'
            stdout, stderr, rc = self._instar('convert', '-O', 'qcow2', image, output)
            self.assertEqual(0, rc, f'instar convert -O qcow2 exited {rc}: '
                                    f'{_failure_line(OP_CONVERT, stdout, stderr)}')
            converted = self._run_tool(['qemu-img', 'info', '-f', 'qcow2', '--output=json', str(output)], workdir)
            source = self._run_tool(['qemu-img', 'info', '-f', 'vhdx', '--output=json', str(image)], workdir)
            self.assertEqual(json.loads(source.stdout)['virtual-size'], json.loads(converted.stdout)['virtual-size'])

    def test_qemu_cannot_open_its_partial_block_past_the_first_chunk(self):
        """The host qemu-img check calls its own fixed image truncated, where instar check passes it.

        This pins the qemu defect recorded in docs/quirks.md, "VHDX partial
        last block past the first chunk": qemu sizes a partial last block by
        its BAT index, so past the first chunk it requires a whole block.
        `test_vhdx_fixed_4608_5M_block_1M_bsz_off_check` requires instar to
        pass the same image. If this test fails, the host qemu has fixed the
        defect, and the quirk text needs revisiting.
        """
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            image = self._image(PARTIAL_PAST_FIRST_CHUNK, workdir)
            r = subprocess.run(['qemu-img', 'check', '-f', 'vhdx', str(image)], capture_output=True, text=True,
                               timeout=QEMU_TOOL_TIMEOUT)
        self.assertEqual(2, r.returncode, f'qemu-img check exited {r.returncode}, not 2 (see docs/quirks.md, '
                                          f'"VHDX partial last block past the first chunk"): {r.stderr!r}')

    def _truncated_partial_fixture(self, workdir: Path, length):
        """A copy of the 17M fixture, whose last block is partial and present, cut to `length` bytes."""
        image = self._image(PARTIAL_LAST_BLOCK, workdir)
        self.assertEqual(PARTIAL_LAST_BLOCK_FILE_END, image.stat().st_size,
                         f'{PARTIAL_LAST_BLOCK} is not the file these tests were written against')
        copy = workdir / 'truncated.vhdx'
        shutil.copyfile(image, copy)
        os.truncate(copy, length)
        return copy

    def _assert_check_finds_block_out_of_bounds(self, length):
        with tempfile.TemporaryDirectory() as tmp:
            image = self._truncated_partial_fixture(Path(tmp), length)
            stdout, stderr, rc = self._instar('check', '-v', image)
        self.assertEqual(2, rc, f'instar check exited {rc} on {PARTIAL_LAST_BLOCK} cut to {length} bytes: '
                                f'{_failure_line(OP_CHECK, stdout, stderr)}')
        self.assertIn('VHDX block offset out of bounds', stdout + stderr)

    def test_partial_last_block_cut_short_is_a_corruption(self):
        """A partial last block the file holds only half of is out of bounds.

        The block starts at 24 MiB and the virtual disk needs 1 MiB of it;
        the file is cut 512 KiB in.
        """
        self._assert_check_finds_block_out_of_bounds(PARTIAL_LAST_BLOCK_START + 512 * KiB)

    def test_partial_last_block_starting_at_end_of_file_is_a_corruption(self):
        """A partial last block whose start is the end of the file is out of bounds."""
        self._assert_check_finds_block_out_of_bounds(PARTIAL_LAST_BLOCK_START)

    def test_partial_last_block_ends_the_image(self):
        """instar check reports the image as ending where the partial last block, and the file, end.

        Measuring the block as a whole one would put the end 7 MiB past the
        end of the file; leaving it out would put it 1 MiB short.
        """
        with tempfile.TemporaryDirectory() as tmp:
            image = self._image(PARTIAL_LAST_BLOCK, Path(tmp))
            stdout, stderr, rc = self._instar('check', '--output', 'json', image)
            size = image.stat().st_size
        self.assertEqual(0, rc, f'instar check exited {rc}: {_failure_line(OP_CHECK, stdout, stderr)}')
        self.assertEqual(PARTIAL_LAST_BLOCK_FILE_END, size)
        self.assertEqual(size, json.loads(stdout)['image-end-offset'])

    def test_known_failures_are_in_the_matrix(self):
        """Every KNOWN_READ_FAILURES entry names a pair the matrix runs, so none is silently unchecked."""
        unrun = sorted(pair for pair in KNOWN_READ_FAILURES if pair[1] not in READ_MATRIX.get(pair[0], ()))
        self.assertEqual([], unrun)


def _make_read_test(image_name, op):
    def test(self):
        self._check_read(image_name, op)

    test.__doc__ = f'instar {op} reads {image_name} as qemu-img does, or fails as KNOWN_READ_FAILURES records.'
    return test


for _image_name, _ops in READ_MATRIX.items():
    for _op in _ops:
        setattr(TestVhdxFixedReads, _test_name(_image_name, _op), _make_read_test(_image_name, _op))
