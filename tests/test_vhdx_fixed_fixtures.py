"""What qemu's fixed VHDX images are, and what instar reads from them.

instar-testdata holds four small fixed VHDX images written by `qemu-img`
(two whole 8 MiB blocks, and two blocks plus a 1 MiB partial one, each in
both `block_state_zero` modes, the `off` pair carrying data) and a dynamic
image at the geometry where the BAT exactly fills its 1 MiB region, which
reproduces #626 in 8 MiB. `scripts/create-vhd-testdata.sh` writes them.

`TestVhdxFixedFixturePins` checks that each committed file has the
structure every pinned `qemu-img` build writes for its command
(`helpers.qemu_pins`), so the fixture stands for all of them rather than
for the one build that generated it. That needs no qemu.

`TestVhdxFixedReads` runs instar's read operations on those fixtures and
on four images built here with the host `qemu-img`: the two convert-to-fixed
images, whose data blocks qemu appends past the preallocated area (a layout
no committed fixture has), and fixed images at the #626 geometry, which as
128 GiB files are too large to commit. Every image at the #626 geometry,
committed or built here, gets only the operations that do not read the data
region (`info`, `check`, `map`); the BAT walk #626 breaks is in those, and
a convert or compare of a 128 GiB virtual disk would read all of it.

What instar gets wrong today is listed in `KNOWN_READ_FAILURES`. A listed
pair must still fail, with the message recorded there; once instar reads
it correctly the test fails and asks for the entry to be removed, so a fix
for #626 or #797 shows up here rather than going unnoticed.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import QEMU_TOOL_TIMEOUT, InstarTestBase
from helpers import qemu_pins
from helpers.vhdx_structure import parse_vhdx, structural_diff, summarise

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

# Images built at test time by `qemu-img convert -f raw -O vhdx` of
# `qemu_pins.write_convert_source`, named for the pin case whose `-o`
# options they use.
RUNTIME_CONVERT_IMAGES = ('vhdx-convert-fixed', 'vhdx-convert-fixed-bsz-off')

# Images built at test time by `qemu-img create -f vhdx`: name to `-o`
# options and size. 131041 one-MiB payload blocks and their 31 sector
# bitmap slots fill a 1 MiB BAT region exactly (SPEC(VHDX) 2.5), the
# geometry #626 miscounts. The files are sparse.
RUNTIME_CREATE_IMAGES = {
    'vhdx-fixed-131041M-block-1M': ('subformat=fixed,block_size=1M', '131041M'),
    'vhdx-fixed-131041M-block-1M-bsz-off': ('subformat=fixed,block_size=1M,block_state_zero=off', '131041M'),
}

OP_INFO = 'info'
OP_CHECK = 'check'
OP_MAP = 'map'
OP_CONVERT = 'convert'
OP_COMPARE = 'compare'
ALL_OPS = (OP_INFO, OP_CHECK, OP_MAP, OP_CONVERT, OP_COMPARE)
# The operations that read only the headers, metadata and BAT.
METADATA_OPS = (OP_INFO, OP_CHECK, OP_MAP)

# Which operations run on which image. The 131041 MiB images get only the
# metadata operations, since a convert or compare would read 128 GiB.
READ_MATRIX = {name: ALL_OPS for name in list(FIXTURE_PIN_CASES) + list(RUNTIME_CONVERT_IMAGES)}
READ_MATRIX.update({name: METADATA_OPS for name in ['vhdx-dynamic-131041M-block-1M', *RUNTIME_CREATE_IMAGES]})

# What instar cannot read today: (image, operation) to (issue, message).
# Each listed pair must still fail, and its output must contain the
# message. `check` reports why only on its verbose output, so it is run
# with `-v` here; `map` refuses a VHDX whose BAT it cannot lay out as an
# unrecognised format.
#
# #626: instar counts one sector bitmap slot more than the BAT holds, a
# trailing one after the last payload entry. That only matters when the
# BAT exactly fills its region, which is then judged too small for it.
# `info` does not walk the BAT and passes.
#
# #797: `check` requires the whole of every FULLY_PRESENT block to lie
# inside the file, but qemu allocates the partial final block of a fixed
# image only as far as the end of the virtual disk, so `check` fails on any
# image whose last block is partial and present.
BAT_REGION_TOO_SMALL = 'VHDX BAT region too small'
MAP_UNRECOGNISED = 'source format unrecognised'
KNOWN_READ_FAILURES = {
    ('vhdx-fixed-17M-bsz-off-data', OP_CHECK): (797, 'VHDX block offset out of bounds'),
    ('vhdx-dynamic-131041M-block-1M', OP_CHECK): (626, BAT_REGION_TOO_SMALL),
    ('vhdx-dynamic-131041M-block-1M', OP_MAP): (626, MAP_UNRECOGNISED),
    ('vhdx-fixed-131041M-block-1M', OP_CHECK): (626, BAT_REGION_TOO_SMALL),
    ('vhdx-fixed-131041M-block-1M', OP_MAP): (626, MAP_UNRECOGNISED),
    ('vhdx-fixed-131041M-block-1M-bsz-off', OP_CHECK): (626, BAT_REGION_TOO_SMALL),
    ('vhdx-fixed-131041M-block-1M-bsz-off', OP_MAP): (626, MAP_UNRECOGNISED),
}

COMPARE_CHUNK = 1024 * 1024


def _test_name(image_name, op=None):
    suffix = f'_{op}' if op else ''
    return 'test_' + image_name.replace('-', '_') + suffix


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
    """Each committed fixture has the structure every pinned qemu-img build writes."""


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


for _image_id, _case_name in FIXTURE_PIN_CASES.items():
    setattr(TestVhdxFixedFixturePins, _test_name(_image_id), _make_pin_test(_image_id, _case_name))


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
    # combined output for matching a known failure's message.

    def _op_info(self, image: Path, workdir: Path):
        self._require_qemu_vhdx()
        stdout, stderr, rc = self._instar('info', '--output', 'json', image)
        if rc != 0:
            return [f'instar info exited {rc}: {_failure_line(OP_INFO, stdout, stderr)}'], stdout + stderr
        qemu = self._run_tool(['qemu-img', 'info', '-f', 'vhdx', '--output=json', str(image)], workdir)
        want = json.loads(qemu.stdout)['virtual-size']
        got = json.loads(stdout)['virtual-size']
        problems = [] if got == want else [f'instar info virtual-size {got} != qemu-img {want}']
        return problems, stdout + stderr

    def _op_check(self, image: Path, workdir: Path):
        stdout, stderr, rc = self._instar('check', '-v', image)
        problems = [] if rc == 0 else [f'instar check exited {rc}: {_failure_line(OP_CHECK, stdout, stderr)}']
        return problems, stdout + stderr

    def _op_map(self, image: Path, workdir: Path):
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

    def _op_convert(self, image: Path, workdir: Path):
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

    def _op_compare(self, image: Path, workdir: Path):
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
            problems, output = getattr(self, f'_op_{op}')(image, workdir)

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
