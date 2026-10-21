"""What `qemu-img` writes for the create and convert commands instar copies.

instar's VHDX, VPC and VMDK writers are meant to produce what `qemu-img`
produces, and `qemu-img info` is too coarse to say whether they do: it
cannot tell a fixed VHDX from a dynamic one, or a BAT of zero-state entries
from one of fully present entries. This module defines the commands whose
output instar copies (`CASES`), runs one of them against a given `qemu-img`
and reduces what it wrote to a JSON-able result (`run_case`), and reads the
committed pin file that records those results for every static `qemu-img`
build in instar-testdata (`load_pin`, `expected`).

The pin is written and re-checked by `tools/sweep-qemu-create.py`, and
checked in CI on a few versions and on the host `qemu-img`. A test that
asks "does instar's fixed VHDX have the structure qemu writes?" compares
against `expected(case_name)['summary']` with
`helpers.vhdx_structure.structural_diff`, rather than running qemu.

The pin file is `{"versions": [...], "cases": {name: [group, ...]}}`, one
group per distinct result, each `{"versions": [...], "result": {...}}`; a
case on which every version agrees has one group. In the file, long BAT
run lists are stored with their periodic structure folded (see
`compact_bat`); `load_pin` unfolds them, so callers only ever see the
lists `summarise` produces.

Stdlib only, and nothing from `tests/base.py`, so that
`scripts/differential-fuzz.py` and the sweep tool can import it with only
`tests/` on `sys.path`.
"""

import contextlib
import copy
import difflib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

from helpers.vhdx_structure import VhdxParseError, allocated_bytes, parse_vhdx, structural_diff, summarise

PIN_PATH = Path(__file__).resolve().parent.parent / 'golden' / 'qemu-create-pins.json'

KIND_VHDX_CREATE = 'vhdx-create'
KIND_VHDX_CONVERT = 'vhdx-convert'
KIND_PREALLOC = 'prealloc'
KIND_VMDK_FLAT = 'vmdk-flat'

PREALLOC_MODES = ('off', 'falloc', 'full', 'metadata')

# Placeholders for the parts of a result that differ between runs of one
# command. `$DIR` stands for the directory the case ran in, wherever it
# appears in stderr.
DIR_PLACEHOLDER = '$DIR'
CID_PLACEHOLDER = '$CID'
EXTENT_PLACEHOLDER = '$EXTENT'

# Where `run_case` puts things inside its per-case directory. `{base}` in a
# case's `args` is replaced by the path of a base image it creates first.
IMAGE_STEM = 'image'
BASE_STEM = 'base'
SOURCE_NAME = 'source.raw'

# The convert source: 64 MiB of raw, zero except for three whole 8 MiB
# blocks of a non-zero byte. 8 MiB is qemu's default VHDX block size below
# 1 GiB (qemu 7.0.0 block/vhdx.c:1962-1974), so each data block lands in
# exactly one BAT entry, and the zero blocks between them show whether the
# writer allocates what it was never given.
CONVERT_SOURCE_SIZE = 64 * 1024 * 1024
CONVERT_SOURCE_BLOCK = 8 * 1024 * 1024
CONVERT_SOURCE_DATA_BLOCKS = (1, 3, 6)
CONVERT_SOURCE_FILL = 0x5A

# Every qemu-img invocation gets this long before it counts as a hang. The
# largest case writes an 8 MiB BAT; nothing should take more than seconds.
COMMAND_TIMEOUT = 300

# The preallocation comparison makes four `off` images and sleeps this long
# after the first, so that a field holding the creation time in seconds
# (the VPC footer's timestamp, qemu 7.0.0 block/vpc.c:1056) differs between
# them and is masked rather than mistaken for a mode-dependent byte.
TIMESTAMP_SLEEP = 1.1
OFF_IMAGE_COUNT = 4
COMPARE_CHUNK = 64 * 1024

VMDK4_MAGIC = b'KDMV'
VMDK4_HEADER_READ = 44
SECTOR_SIZE = 512

# A run of BAT runs is folded into one repeat entry in the pin file only
# when the pattern repeats at least this often; the pattern is at most
# this many runs long.
COMPACT_MIN_REPEATS = 3
COMPACT_MAX_PERIOD = 4


class PinError(Exception):
    """The pin does not hold the answer asked for."""


def _vhdx_create(name, args, size, base=None):
    case = {'name': name, 'kind': KIND_VHDX_CREATE, 'args': ['-f', 'vhdx'] + args, 'size': size}
    if base:
        case['base'] = base
    return case


def _fixed(options, size):
    return _vhdx_create(f'vhdx-fixed-{size}' + _suffix(options), ['-o', ','.join(['subformat=fixed'] + options)], size)


def _dynamic(options, size):
    args = ['-o', ','.join(options)] if options else []
    return _vhdx_create(f'vhdx-dynamic-{size}' + _suffix(options), args, size)


def _suffix(options):
    names = {'block_state_zero=off': 'bsz-off', 'block_size=1M': 'block-1M'}
    return ''.join(f'-{names[option]}' for option in options)


def _prealloc(name, fmt, options, suffix, measure=None):
    case = {'name': name, 'kind': KIND_PREALLOC, 'format': fmt, 'options': options, 'suffix': suffix,
            'size': '64M'}
    if measure:
        case['measure'] = measure
    return case


# The commands whose results are pinned. Each is a dict with a unique
# `name`, a `kind` (which decides what `run_case` measures), and the
# arguments: for `vhdx-create` and `vmdk-flat` the argv between `create`
# and the image path, plus the size; for `vhdx-convert` the `-o` value; for
# `prealloc` the format, its other options and the image suffix. Adding a
# case is a row here and a re-run of tools/sweep-qemu-create.py --write.
CASES = [
    # Fixed VHDX in both BAT modes, on a size that fills its last block and
    # one that does not, and at the smallest block size, where the BAT
    # holds sector bitmap slots between its payload entries.
    _fixed([], '64M'),
    _fixed(['block_state_zero=off'], '64M'),
    _fixed([], '65M'),
    _fixed(['block_state_zero=off'], '65M'),
    _fixed(['block_size=1M'], '64M'),
    _fixed(['block_size=1M', 'block_state_zero=off'], '64M'),
    # 131041 one-MiB payload blocks plus their 31 sector bitmap slots fill
    # a 1 MiB BAT region exactly (SPEC(VHDX) 2.5: 131041 + floor(131040 /
    # 4096) = 131072 entries). The fixed image is a 128 GiB sparse file.
    _fixed(['block_size=1M', 'block_state_zero=off'], '131041M'),
    _dynamic([], '64M'),
    _dynamic(['block_state_zero=off'], '64M'),
    _dynamic(['block_size=1M'], '131041M'),
    # At the default 32 MiB block size (above 100 GiB), 130056 payload
    # blocks and 1016 sector bitmap slots are also exactly 131072 entries.
    _dynamic([], '4161792M'),
    # Each side of every default block size threshold (qemu 7.0.0
    # block/vhdx.c:1962-1974: above 1 GiB, 100 GiB and 32 TiB).
    _dynamic([], '1024M'),
    _dynamic([], '1025M'),
    _dynamic([], '102400M'),
    _dynamic([], '102401M'),
    _dynamic([], '33554432M'),
    _dynamic([], '33554433M'),
    # The size limit, 64 TiB inclusive (qemu 7.0.0 block/vhdx.h:289,
    # block/vhdx.c:1920-1921).
    _dynamic([], '64T'),
    _dynamic([], '65T'),
    # Refusals. A backing file is refused by the generic create path
    # (qemu 7.0.0 block.c:7054-7058), because the vhdx driver's create
    # options have no backing_file (block/vhdx.c:2195-2232); metadata
    # preallocation by the file protocol underneath
    # (block/file-posix.c:2024-2026).
    _vhdx_create('vhdx-fixed-backing', ['-o', 'subformat=fixed', '-b', '{base}', '-F', 'vhdx'], '64M', base='vhdx'),
    _vhdx_create('vhdx-fixed-prealloc-metadata', ['-o', 'subformat=fixed,preallocation=metadata'], '64M'),

    {'name': 'vhdx-convert-fixed', 'kind': KIND_VHDX_CONVERT, 'options': 'subformat=fixed'},
    {'name': 'vhdx-convert-fixed-bsz-off', 'kind': KIND_VHDX_CONVERT,
     'options': 'subformat=fixed,block_state_zero=off'},

    _prealloc('prealloc-vpc', 'vpc', [], 'vhd'),
    _prealloc('prealloc-vmdk', 'vmdk', [], 'vmdk'),
    _prealloc('prealloc-vhdx', 'vhdx', [], 'vhdx'),
    _prealloc('prealloc-vpc-fixed', 'vpc', ['subformat=fixed'], 'vhd'),
    _prealloc('prealloc-vhdx-fixed', 'vhdx', ['subformat=fixed'], 'vhdx'),
    _prealloc('prealloc-vmdk-monolithicFlat', 'vmdk', ['subformat=monolithicFlat'], 'vmdk', measure='flat-extent'),

    {'name': 'vmdk-flat-64M', 'kind': KIND_VMDK_FLAT, 'args': ['-f', 'vmdk', '-o', 'subformat=monolithicFlat'],
     'size': '64M'},
    # qemu 7.0.0 block/vmdk.c:2428-2429: "Flat image can't have backing file".
    {'name': 'vmdk-flat-backing', 'kind': KIND_VMDK_FLAT,
     'args': ['-f', 'vmdk', '-o', 'subformat=monolithicFlat', '-b', '{base}', '-F', 'vmdk'], 'size': '64M',
     'base': 'vmdk'},
]

CASES_BY_NAME = {case['name']: case for case in CASES}
if len(CASES_BY_NAME) != len(CASES):
    raise RuntimeError('qemu pin case names are not unique')


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

def version_key(version: str) -> tuple:
    """Sort key for a dotted qemu version such as `8.2.10`."""
    return tuple(int(part) for part in version.split('.'))


def qemu_img_builds(root: Path) -> dict:
    """Return {version: qemu-img path} for every executable build under `root`, oldest first.

    `root` is instar-testdata's `qemu-img-binaries/x86_64`. A version
    directory whose `qemu-img` is missing or not executable (an LFS
    checkout can drop the bit) is not a build, for the sweep and the CI
    check alike. A build in a directory not named for a release, such as
    `latest` or `10.2.0-rc1`, raises PinError: the pin is keyed by
    release, so it has nowhere to put one.
    """
    builds = {}
    for entry in root.iterdir():
        binary = entry / 'qemu-img'
        if binary.is_file() and os.access(binary, os.X_OK):
            if not re.fullmatch(r'\d+\.\d+\.\d+', entry.name):
                raise PinError(f'qemu-img build directory {entry} is not named for a qemu release (such as 10.2.0)')
            builds[entry.name] = binary
    return dict(sorted(builds.items(), key=lambda item: version_key(item[0])))


def qemu_img_version(qemu_img) -> str:
    """The `major.minor.patch` a `qemu-img` binary reports.

    Distribution suffixes are dropped: Debian's `10.0.13 (Debian
    1:10.0.13+ds-0+deb13u1)` is `10.0.13`.
    """
    out = subprocess.run([str(qemu_img), '--version'], capture_output=True, text=True, check=True,
                         timeout=COMMAND_TIMEOUT).stdout
    match = re.search(r'version (\d+)\.(\d+)\.(\d+)', out)
    if not match:
        raise PinError(f'cannot find a version in the output of {qemu_img} --version: {out!r}')
    return '.'.join(match.groups())


# ---------------------------------------------------------------------------
# Running a case
# ---------------------------------------------------------------------------

def _run(argv, workdir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, LC_ALL='C')
    try:
        return subprocess.run([str(arg) for arg in argv], capture_output=True, text=True, cwd=workdir, env=env,
                              timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f'{" ".join(str(arg) for arg in argv)} did not finish in {COMMAND_TIMEOUT} s') from e


def normalise_stderr(stderr: str, workdir) -> str:
    """Replace the case directory in `stderr` with `$DIR`."""
    return stderr.replace(str(workdir), DIR_PLACEHOLDER)


def _create_base(qemu_img, fmt: str, workdir: Path) -> Path:
    base = workdir / f'{BASE_STEM}.{fmt}'
    proc = _run([qemu_img, 'create', '-f', fmt, base, '64M'], workdir)
    if proc.returncode != 0:
        raise RuntimeError(f'creating the {fmt} base image failed: {proc.stderr.strip()}')
    return base


def _create(qemu_img, case: dict, image: Path, workdir: Path) -> subprocess.CompletedProcess:
    base = _create_base(qemu_img, case['base'], workdir) if case.get('base') else None
    args = [str(base) if arg == '{base}' else arg for arg in case['args']]
    return _run([qemu_img, 'create'] + args + [image, case['size']], workdir)


def _check_rc(qemu_img, fmt: str, image: Path, workdir: Path) -> int:
    return _run([qemu_img, 'check', '-f', fmt, image], workdir).returncode


def _vhdx_summary(image: Path) -> dict:
    try:
        return summarise(parse_vhdx(image))
    except VhdxParseError as e:
        # A qemu image this parser cannot read is a result to pin and look
        # at, not a reason to abandon the sweep.
        return {'parse_error': str(e)}


def _run_vhdx_create(qemu_img, case: dict, workdir: Path) -> dict:
    image = workdir / f'{IMAGE_STEM}.vhdx'
    proc = _create(qemu_img, case, image, workdir)
    result = {'rc': proc.returncode, 'stderr': normalise_stderr(proc.stderr, workdir), 'summary': None,
              'check_rc': None}
    if proc.returncode == 0:
        result['summary'] = _vhdx_summary(image)
        result['check_rc'] = _check_rc(qemu_img, 'vhdx', image, workdir)
    return result


def write_convert_source(path: Path) -> None:
    """Write the sparse raw source the convert cases read."""
    fill = bytes([CONVERT_SOURCE_FILL]) * CONVERT_SOURCE_BLOCK
    with open(path, 'wb') as f:
        f.truncate(CONVERT_SOURCE_SIZE)
        for block in CONVERT_SOURCE_DATA_BLOCKS:
            f.seek(block * CONVERT_SOURCE_BLOCK)
            f.write(fill)


def _run_vhdx_convert(qemu_img, case: dict, workdir: Path) -> dict:
    source = workdir / SOURCE_NAME
    write_convert_source(source)
    image = workdir / f'{IMAGE_STEM}.vhdx'
    proc = _run([qemu_img, 'convert', '-f', 'raw', '-O', 'vhdx', '-o', case['options'], source, image], workdir)
    result = {'rc': proc.returncode, 'stderr': normalise_stderr(proc.stderr, workdir), 'summary': None,
              'check_rc': None, 'compare_rc': None}
    if proc.returncode == 0:
        result['summary'] = _vhdx_summary(image)
        result['check_rc'] = _check_rc(qemu_img, 'vhdx', image, workdir)
        result['compare_rc'] = _run([qemu_img, 'compare', '-f', 'raw', '-F', 'vhdx', source, image],
                                    workdir).returncode
    return result


def _differing_positions(chunks: List[bytes], base_offset: int) -> set:
    """Offsets at which any two of `chunks` differ, over their common length."""
    length = min(len(chunk) for chunk in chunks)
    first = chunks[0]
    positions = set()
    for other in chunks[1:]:
        if other[:length] == first[:length]:
            continue
        for i in range(length):
            if other[i] != first[i]:
                positions.add(base_offset + i)
    return positions


def volatile_mask(paths: List[Path]) -> set:
    """Every byte offset at which any two of the files at `paths` differ.

    The files are runs of the same command, so what differs between them is
    what the command does not determine: random GUIDs and CIDs, creation
    timestamps, and the checksums over them. Offsets past the shortest
    file are not in the mask; a length difference is reported separately.
    """
    mask = set()
    with contextlib.ExitStack() as stack:
        handles = [stack.enter_context(open(path, 'rb')) for path in paths]
        offset = 0
        while True:
            chunks = [handle.read(COMPARE_CHUNK) for handle in handles]
            if not any(chunks):
                return mask
            if any(chunk != chunks[0] for chunk in chunks[1:]):
                mask |= _differing_positions(chunks, offset)
            if min(len(chunk) for chunk in chunks) < COMPARE_CHUNK:
                return mask
            offset += COMPARE_CHUNK


def text_regions(path: Path) -> List[Tuple[int, int]]:
    """The `(offset, length)` ranges of `path` compared as text, not bytes.

    A monolithicSparse VMDK embeds its descriptor, and the descriptor's CID
    is random and printed in hex without padding (qemu 7.0.0
    block/vmdk.c:2375, :2525-2526), so one run in sixteen writes a CID a
    digit shorter and every byte after it in the descriptor moves. No byte
    mask survives that; the descriptor is compared after
    `normalise_descriptor` instead. The VMDK4 header after the 4-byte
    `KDMV` magic holds the descriptor's offset and size in sectors at +28
    and +36 (`VMDK4Header`, block/vmdk.c:79-94).
    """
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        header = f.read(VMDK4_HEADER_READ)
    if len(header) < VMDK4_HEADER_READ or header[:4] != VMDK4_MAGIC:
        return []
    desc_offset, desc_size = struct.unpack_from('<QQ', header, 28)
    start = min(desc_offset * SECTOR_SIZE, size)
    return [(start, min(desc_size * SECTOR_SIZE, size - start))]


def _region_text(handle, offset: int, length: int) -> str:
    handle.seek(offset)
    return normalise_descriptor(handle.read(length).rstrip(b'\0').decode('utf-8', errors='replace'))


def same_content(a: Path, b: Path, mask: set) -> bool:
    """Whether `a` and `b` are the same file but for volatile content.

    Equal lengths; equal bytes at every offset outside `mask` and outside
    their `text_regions`; and equal normalised text in those regions.
    """
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    regions = text_regions(a)
    if text_regions(b) != regions:
        return False

    def ignored(position):
        return position in mask or any(start <= position < start + length for start, length in regions)

    with open(a, 'rb') as fa, open(b, 'rb') as fb:
        offset = 0
        while True:
            chunk_a = fa.read(COMPARE_CHUNK)
            chunk_b = fb.read(COMPARE_CHUNK)
            if not chunk_a:
                break
            if chunk_a != chunk_b:
                if any(not ignored(position) for position in _differing_positions([chunk_a, chunk_b], offset)):
                    return False
            offset += COMPARE_CHUNK
        return all(_region_text(fa, start, length) == _region_text(fb, start, length) for start, length in regions)


def _prealloc_measured_file(case: dict, image: Path) -> Path:
    if case.get('measure') == 'flat-extent':
        # The data of a monolithicFlat image is in the extent beside the
        # descriptor, named after it (qemu 7.0.0 block/vmdk.c:2337-2340
        # writes the extent's basename into the descriptor).
        return image.with_name(f'{image.stem}-flat{image.suffix}')
    return image


def _prealloc_create(qemu_img, case: dict, mode: str, label: str, workdir: Path):
    # Every image gets the same name, in a directory of its own, because a
    # sparse VMDK records its own filename in its descriptor.
    imagedir = workdir / label
    imagedir.mkdir()
    image = imagedir / f'{IMAGE_STEM}.{case["suffix"]}'
    options = ','.join(case['options'] + [f'preallocation={mode}'])
    proc = _run([qemu_img, 'create', '-f', case['format'], '-o', options, image, case['size']], imagedir)
    return proc, normalise_stderr(proc.stderr, imagedir), _prealloc_measured_file(case, image)


def _prealloc_measure(qemu_img, case: dict, workdir: Path) -> dict:
    offs = []
    for i in range(OFF_IMAGE_COUNT):
        offs.append(_prealloc_create(qemu_img, case, 'off', f'off{i}', workdir))
        if i == 0:
            time.sleep(TIMESTAMP_SLEEP)
    for proc, stderr, _ in offs:
        if proc.returncode != 0:
            raise RuntimeError(f'{case["name"]}: preallocation=off failed: {stderr.strip()}')
    reference = offs[0][2]
    mask = volatile_mask([path for _, _, path in offs])

    modes = {}
    for mode in PREALLOC_MODES:
        if mode == 'off':
            # The second off image stands for the mode: its bytes match the
            # first by construction of the mask, but its allocation need not.
            proc, stderr, path = offs[1]
        else:
            proc, stderr, path = _prealloc_create(qemu_img, case, mode, mode, workdir)
        entry = {'rc': proc.returncode, 'stderr': stderr,
                 'file_length': os.path.getsize(path) if path.exists() else None,
                 'same_bytes_as_off': None, 'same_allocation_as_off': None}
        if proc.returncode == 0:
            entry['same_bytes_as_off'] = same_content(reference, path, mask)
            entry['same_allocation_as_off'] = allocated_bytes(path) == allocated_bytes(reference)
        modes[mode] = entry
    return {'modes': modes}


def _run_prealloc(qemu_img, case: dict, workdir: Path) -> dict:
    result = _prealloc_measure(qemu_img, case, workdir)
    if any(entry[field] is False for entry in result['modes'].values()
           for field in ('same_bytes_as_off', 'same_allocation_as_off')):
        # A mismatch can be a byte that happened to agree across the four
        # off images (and so escaped the mask) or allocation that the
        # filesystem had not settled; build everything again once and
        # believe the second answer.
        for child in workdir.iterdir():
            shutil.rmtree(child)
        result = _prealloc_measure(qemu_img, case, workdir)
    return result


def normalise_descriptor(text: str) -> str:
    """A VMDK descriptor with its random CID and its extent filenames replaced.

    The CID is random at create (qemu 7.0.0 block/vmdk.c:2525-2526); an
    extent's filename follows the image's name.
    """
    text = re.sub(r'^CID=[0-9a-fA-F]+$', f'CID={CID_PLACEHOLDER}', text, flags=re.MULTILINE)
    return re.sub(r'^(RW \d+ [A-Z]+ )"[^"]*"', rf'\1"{EXTENT_PLACEHOLDER}"', text, flags=re.MULTILINE)


def _run_vmdk_flat(qemu_img, case: dict, workdir: Path) -> dict:
    image = workdir / f'{IMAGE_STEM}.vmdk'
    proc = _create(qemu_img, case, image, workdir)
    result = {'rc': proc.returncode, 'stderr': normalise_stderr(proc.stderr, workdir), 'descriptor': None,
              'extent_length': None}
    if proc.returncode == 0:
        result['descriptor'] = normalise_descriptor(image.read_text(encoding='utf-8', errors='replace'))
        extent = _prealloc_measured_file({'measure': 'flat-extent'}, image)
        result['extent_length'] = os.path.getsize(extent) if extent.exists() else None
    return result


RUNNERS = {
    KIND_VHDX_CREATE: _run_vhdx_create,
    KIND_VHDX_CONVERT: _run_vhdx_convert,
    KIND_PREALLOC: _run_prealloc,
    KIND_VMDK_FLAT: _run_vmdk_flat,
}


def run_case(qemu_img, case, workdir) -> dict:
    """Run `case` (a `CASES` entry or its name) with `qemu_img`, and return its result.

    Everything is created in a fresh directory under `workdir` that is
    removed before returning, so a 128 GiB sparse fixed image does not
    outlive its measurement. The result is JSON-able and contains nothing
    that differs between two runs of the same `qemu-img` on any
    filesystem, so it can be compared for equality with a pinned one.
    """
    if isinstance(case, str):
        case = CASES_BY_NAME[case]
    # A bare name such as 'qemu-img' is looked up on PATH; the commands run
    # with the case directory as their working directory.
    resolved = shutil.which(str(qemu_img))
    if resolved is None:
        raise FileNotFoundError(f'no executable qemu-img at {qemu_img}')
    casedir = Path(tempfile.mkdtemp(prefix=f'{case["name"]}-', dir=workdir))
    try:
        return RUNNERS[case['kind']](Path(resolved).resolve(), case, casedir)
    finally:
        shutil.rmtree(casedir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Comparing results
# ---------------------------------------------------------------------------

def canonical(result) -> str:
    """The canonical JSON text of a result, for grouping and equality."""
    return json.dumps(result, sort_keys=True, separators=(',', ':'))


def result_diff(expected: dict, actual: dict, path: str = '') -> List[str]:
    """Human-readable differences between a pinned and a measured result.

    Each message names the field, then the pinned value, then the measured
    one. VHDX summaries are compared with `structural_diff`, so a BAT
    difference reads as runs rather than as two long lists.
    """
    differences = []
    for key in sorted(set(expected) | set(actual), key=str):
        field = f'{path}{key}'
        want = expected.get(key)
        got = actual.get(key)
        if want == got:
            continue
        if key == 'summary' and isinstance(want, dict) and isinstance(got, dict):
            if 'parse_error' in want or 'parse_error' in got:
                differences.append(f'{field}: {want.get("parse_error", "parsed")!r} != '
                                   f'{got.get("parse_error", "parsed")!r}')
            else:
                differences.extend(f'{field}: {message}' for message in structural_diff(want, got))
        elif isinstance(want, dict) and isinstance(got, dict):
            differences.extend(result_diff(want, got, f'{field}.'))
        elif isinstance(want, str) and isinstance(got, str) and '\n' in want + got:
            lines = difflib.unified_diff(want.splitlines(), got.splitlines(), 'pinned', 'measured', n=0, lineterm='')
            differences.append(f'{field}:\n    ' + '\n    '.join(lines))
        else:
            differences.append(f'{field}: {want!r} != {got!r}')
    return differences


def group_results(results_by_version: dict) -> dict:
    """Turn `{version: {case: result}}` into the pin's `cases` mapping.

    Versions whose results for a case are identical (canonical JSON) share
    a group; groups are ordered by their oldest version, and versions
    within a group numerically.
    """
    measured = {name for results in results_by_version.values() for name in results}
    # Case table order, so the pin reads in the order the cases are defined.
    names = [case['name'] for case in CASES if case['name'] in measured]
    names += sorted(measured - set(names))
    cases = {}
    for name in names:
        groups = {}
        for version in sorted(results_by_version, key=version_key):
            result = results_by_version[version].get(name)
            if result is None:
                continue
            groups.setdefault(canonical(result), {'versions': [], 'result': result})['versions'].append(version)
        cases[name] = sorted(groups.values(), key=lambda group: version_key(group['versions'][0]))
    return cases


# ---------------------------------------------------------------------------
# The pin file's folded BAT lists
# ---------------------------------------------------------------------------

def _shifted(run: list, index_step: int, offset_step: int, times: int) -> list:
    first_index, count, kind, state, first_offset, stride = run
    return [first_index + times * index_step, count, kind, state, first_offset + times * offset_step, stride]


def _repeats(runs: list, start: int, period: int):
    """How often `runs[start:start + period]` repeats from `start`, and its steps."""
    if start + 2 * period > len(runs):
        return 1, 0, []
    pattern = runs[start:start + period]
    index_step = runs[start + period][0] - pattern[0][0]
    offset_steps = [runs[start + period + j][4] - pattern[j][4] for j in range(period)]
    times = 1
    while start + (times + 1) * period <= len(runs):
        block = runs[start + times * period:start + (times + 1) * period]
        if any(block[j] != _shifted(pattern[j], index_step, offset_steps[j], times) for j in range(period)):
            break
        times += 1
    return times, index_step, offset_steps


def compact_bat(runs: list) -> list:
    """Fold the periodic part of a `summarise()` BAT run list.

    A large BAT alternates a run of payload entries with one sector bitmap
    slot, thousands of times: 32 TiB at 32 MiB blocks is 16384 runs. Where
    a pattern of up to `COMPACT_MAX_PERIOD` runs repeats at least
    `COMPACT_MIN_REPEATS` times, each run advancing its first index by the
    same step and its first offset by a step of its own, the repeats become
    one `{"repeat": n, "index_step": i, "offset_steps": [...], "runs":
    [...]}` entry. `expand_bat` reverses it exactly.
    """
    out = []
    i = 0
    while i < len(runs):
        best = (1, 1, 0, [])
        for period in range(1, COMPACT_MAX_PERIOD + 1):
            times, index_step, offset_steps = _repeats(runs, i, period)
            if times >= COMPACT_MIN_REPEATS and times * period > best[0] * best[1]:
                best = (times, period, index_step, offset_steps)
        times, period, index_step, offset_steps = best
        if times >= COMPACT_MIN_REPEATS:
            out.append({'repeat': times, 'index_step': index_step, 'offset_steps': offset_steps,
                        'runs': [list(run) for run in runs[i:i + period]]})
            i += times * period
        else:
            out.append(list(runs[i]))
            i += 1
    return out


def expand_bat(entries: list) -> list:
    """Undo `compact_bat`."""
    runs = []
    for entry in entries:
        if isinstance(entry, dict):
            for times in range(entry['repeat']):
                for run, offset_step in zip(entry['runs'], entry['offset_steps']):
                    runs.append(_shifted(run, entry['index_step'], offset_step, times))
        else:
            runs.append(list(entry))
    return runs


def _map_summaries(result: dict, transform) -> dict:
    result = copy.deepcopy(result)
    summary = result.get('summary')
    if isinstance(summary, dict) and isinstance(summary.get('bat'), list):
        summary['bat'] = transform(summary['bat'])
    return result


def encode_pin(versions: list, cases: dict) -> dict:
    """The pin file's content for `versions` and a `group_results` mapping."""
    return {
        'versions': sorted(versions, key=version_key),
        'cases': {name: [{'versions': group['versions'], 'result': _map_summaries(group['result'], compact_bat)}
                         for group in groups]
                  for name, groups in cases.items()},
    }


def decode_pin(data: dict) -> dict:
    """The inverse of `encode_pin`: BAT run lists unfolded."""
    return {
        'versions': list(data['versions']),
        'cases': {name: [{'versions': list(group['versions']),
                          'result': _map_summaries(group['result'], expand_bat)}
                         for group in groups]
                  for name, groups in data['cases'].items()},
    }


def _dump(value, indent: int, width: int, lead: int = 0) -> str:
    """JSON with containers indented, and with flat containers kept on one line where they fit.

    `lead` is how many characters precede the value on its first line (its
    key), beyond the indent.
    """
    pad = ' ' * indent
    inner = ' ' * (indent + 2)
    items = value.values() if isinstance(value, dict) else value
    if isinstance(value, (dict, list)) and all(not isinstance(item, (dict, list)) for item in items):
        text = json.dumps(value)
        if indent + lead + len(text) <= width:
            return text
    if isinstance(value, dict):
        rendered = []
        for key, item in value.items():
            name = json.dumps(key) + ': '
            rendered.append(inner + name + _dump(item, indent + 2, width, len(name)))
        return '{\n' + ',\n'.join(rendered) + '\n' + pad + '}'
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            # A long list of scalars: as many to a line as fit.
            lines = []
            line = ''
            for item in value:
                piece = json.dumps(item)
                if line and len(inner) + len(line) + len(piece) + 2 > width:
                    lines.append(line + ',')
                    line = ''
                line = f'{line}, {piece}' if line else piece
            lines.append(line)
            return '[\n' + '\n'.join(inner + text for text in lines) + '\n' + pad + ']'
        rendered = [inner + _dump(item, indent + 2, width) for item in value]
        return '[\n' + ',\n'.join(rendered) + '\n' + pad + ']'
    return json.dumps(value)


def dump_pin(data: dict) -> str:
    """Serialise encoded pin content as reviewable JSON text."""
    return _dump(data, 0, 120) + '\n'


# ---------------------------------------------------------------------------
# Reading the pin
# ---------------------------------------------------------------------------

_PIN_CACHE = {}


def load_pin(path=None) -> dict:
    """The pin at `path` (default `PIN_PATH`), with its BAT lists unfolded.

    Returns a fresh copy each call; the parsed file is cached.
    """
    path = Path(path) if path else PIN_PATH
    key = str(path.resolve())
    if key not in _PIN_CACHE:
        with open(path, encoding='utf-8') as f:
            _PIN_CACHE[key] = decode_pin(json.load(f))
    return copy.deepcopy(_PIN_CACHE[key])


def find_group(pin: dict, case_name: str, version: str) -> Optional[dict]:
    """The group of `case_name` listing `version`, or None."""
    for group in pin['cases'].get(case_name, []):
        if version in group['versions']:
            return group
    return None


def expected(case_name: str, version: Optional[str] = None, pin=None) -> dict:
    """The pinned result of `case_name`.

    With a version, the result of that version's group. Without one, the
    result every pinned version agrees on: a case whose behaviour changed
    between versions raises `PinError` naming the boundary, so a caller
    that assumes "qemu always does this" learns when that stops being true.
    `pin` is a `load_pin` result, or None for the committed pin.
    """
    if pin is None:
        pin = load_pin()
    groups = pin['cases'].get(case_name)
    if not groups:
        raise PinError(f'case {case_name} is not in the pin')
    if version is None:
        if len(groups) != 1:
            spans = '; '.join(f'{group["versions"][0]} to {group["versions"][-1]}' for group in groups)
            raise PinError(f'case {case_name} has {len(groups)} results across qemu versions ({spans}); '
                           f'ask for a version')
        return copy.deepcopy(groups[0]['result'])
    group = find_group(pin, case_name, version)
    if group is None:
        raise PinError(f'version {version} is not pinned for case {case_name}')
    return copy.deepcopy(group['result'])


def newest_pinned_at_or_below(version: str, pin=None) -> Optional[str]:
    """The newest pinned version not newer than `version`, or None."""
    if pin is None:
        pin = load_pin()
    candidates = [v for v in pin['versions'] if version_key(v) <= version_key(version)]
    return max(candidates, key=version_key) if candidates else None
