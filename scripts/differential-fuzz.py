#!/usr/bin/env python3
"""Differential fuzzing: compare instar vs qemu-img on random images.

For each iteration this script:
  1. Picks a random seed (logged for reproducibility).
  2. Generates a random disk image with qemu-img create.
  3. Runs a random set of operations (info, check, convert)
     independently against both instar and qemu-img on separate
     copies of the same input image.
  4. Compares outputs at each stage; exits with details on the
     first unexplained divergence.

Usage:
    python3 scripts/differential-fuzz.py \
        --instar src/target/release/instar \
        --iterations 1000 \
        [--seed 42] \
        [--workdir /tmp/fuzz] \
        [--timeout 30] \
        [--log-dir ./fuzz-logs]
"""

import argparse
import hashlib
import json
import logging
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORMATS = ['qcow2', 'raw', 'vmdk', 'vpc']
OUTPUT_FORMATS = ['qcow2', 'raw', 'vmdk', 'vpc']
VIRTUAL_SIZES = ['1M', '4M', '16M', '64M', '256M', '1G']
QCOW2_CLUSTER_SIZES = [512, 4096, 65536, 262144, 2097152]
DATA_PATTERNS = ['zeros', 'random', 'sparse', 'mbr']

# Operations that the fuzzer can chain together
OPERATIONS = ['info', 'check', 'convert', 'convert_compressed', 'measure',
              'create']

# Known divergence categories to skip (unsafe quirks)
# See docs/quirks.md for rationale
KNOWN_DIVERGENCE_FIELDS = {
    # disk size varies by filesystem allocation
    'actual-size',
    'disk size',
    # instar uses consistent JSON schema; qemu-img omits zero fields
    'image-clusters',
    'fragmented-clusters',
    'allocated-clusters',
}

logger = logging.getLogger('differential-fuzz')


# ---------------------------------------------------------------------------
# Image generation
# ---------------------------------------------------------------------------

def write_mbr_header(path):
    """Write a minimal MBR partition table to a raw file."""
    with open(path, 'r+b') as f:
        # MBR signature at bytes 510-511
        f.seek(510)
        f.write(b'\x55\xAA')
        # One partition entry at offset 446 (16 bytes)
        f.seek(446)
        # Status=0x80 (active), CHS start, type=0x83 (Linux),
        # CHS end, LBA start=2048, LBA size=rest
        f.write(struct.pack(
            '<BBBBBBBBII',
            0x80,        # status (active)
            0, 1, 0,     # CHS start
            0x83,        # partition type (Linux)
            0, 0, 0,     # CHS end
            2048,        # LBA start
            0,           # LBA size (placeholder)
        ))


def generate_image(rng, workdir, iteration):
    """Generate a random disk image using qemu-img.

    Returns (image_path, format, attributes_dict) or raises on failure.
    """
    fmt = rng.choice(FORMATS)
    vsize = rng.choice(VIRTUAL_SIZES)
    pattern = rng.choice(DATA_PATTERNS)

    attrs = {
        'format': fmt,
        'virtual_size': vsize,
        'pattern': pattern,
    }

    image_name = f'fuzz-{iteration:06d}.{fmt}'
    image_path = workdir / image_name

    # Build qemu-img create command
    cmd = ['qemu-img', 'create', '-f', fmt]

    if fmt == 'qcow2':
        cluster_size = rng.choice(QCOW2_CLUSTER_SIZES)
        attrs['cluster_size'] = cluster_size
        cmd.extend(['-o', f'cluster_size={cluster_size}'])

    if fmt == 'vmdk':
        # VMDK only supports specific sub-formats; use monolithicSparse
        cmd.extend(['-o', 'subformat=monolithicSparse'])

    cmd.extend([str(image_path), vsize])

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError(
            f'qemu-img create failed: {result.stderr}'
        )

    # Write data pattern
    if pattern == 'random':
        _write_random_data(rng, image_path, fmt)
    elif pattern == 'mbr' and fmt == 'raw':
        write_mbr_header(image_path)
    elif pattern == 'sparse':
        # Leave as-is (all zeros, sparse allocation)
        pass

    return image_path, fmt, attrs


def _write_random_data(rng, image_path, fmt):
    """Write a small amount of random data into the image via qemu-io."""
    # Write 1-4 random blocks at random offsets
    num_writes = rng.randint(1, 4)
    for _ in range(num_writes):
        offset = rng.choice([0, 4096, 8192, 65536, 131072])
        size = rng.choice([512, 4096])
        byte_val = rng.randint(0, 255)
        cmd = [
            'qemu-io', '-f', fmt, '-c',
            f'write -P {byte_val} {offset} {size}',
            str(image_path),
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # qemu-io not available or hung; skip data writes
            break


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

def run_instar(instar_bin, subcmd, args, timeout=30):
    """Run an instar subcommand. Returns (stdout, stderr, rc)."""
    cmd = [str(instar_bin)] + subcmd + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1


def run_qemu_img(subcmd, args, timeout=30):
    """Run a qemu-img subcommand. Returns (stdout, stderr, rc)."""
    cmd = ['qemu-img'] + subcmd + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1


# ---------------------------------------------------------------------------
# libyal tool detection and parsing
# ---------------------------------------------------------------------------

# Maps format names to their libyal info tool
LIBYAL_TOOLS = {
    'vmdk': 'vmdkinfo',
    'vpc': 'vhdiinfo',
    'vhdx': 'vhdiinfo',
    'qcow2': 'qcowinfo',
}


def detect_libyal_tools():
    """Detect which libyal tools are available on PATH.

    Returns a dict mapping tool name to its absolute path, or
    an empty dict entry is omitted when unavailable.
    """
    available = {}
    for tool in ('vmdkinfo', 'vhdiinfo', 'qcowinfo'):
        path = shutil.which(tool)
        if path:
            available[tool] = path
            logger.info('  libyal:     %s found at %s', tool, path)
        else:
            logger.warning(
                '  libyal:     %s not found, skipping %s comparisons',
                tool, tool,
            )
    return available


def run_libyal_tool(tool_path, image_path, timeout=30):
    """Run a libyal info tool. Returns (stdout, stderr, rc)."""
    cmd = [tool_path, str(image_path)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1


def parse_libyal_kv(output):
    """Parse libyal colon-separated key-value text output.

    libyal tools output lines like:
        Media size:             1048576
        Format version:         3

    Returns a dict of {key: value} with keys lowercased and
    stripped, values stripped. Skips section headers (lines
    without a colon) and empty values.
    """
    result = {}
    for line in output.splitlines():
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


def _extract_libyal_fields(kv, field_specs):
    """Extract fields from parsed libyal key-value output.

    Each spec in field_specs is (source_key, target_key, type)
    where type is 'str' or 'int'. Integer fields that fail to
    parse are silently skipped.
    """
    result = {}
    for source_key, target_key, value_type in field_specs:
        if source_key not in kv:
            continue
        if value_type == 'int':
            try:
                result[target_key] = int(kv[source_key])
            except ValueError:
                # Silently skip fields that cannot be parsed as integers.
                logger.debug(
                    "Skipping non-integer libyal field %r with value %r",
                    source_key,
                    kv[source_key],
                )
        else:
            result[target_key] = kv[source_key]
    return result


# Field mappings per libyal tool: (libyal_key, instar_key, type)
_VMDKINFO_FIELDS = [
    ('media size', 'virtual-size', 'int'),
    ('format version', 'format-version', 'str'),
    ('disk type', 'disk-type', 'str'),
    ('compression method', 'compression', 'str'),
]

_VHDIINFO_FIELDS = [
    ('media size', 'virtual-size', 'int'),
    ('disk type', 'disk-type', 'str'),
    ('format version', 'format-version', 'str'),
]

_QCOWINFO_FIELDS = [
    ('media size', 'virtual-size', 'int'),
    ('format version', 'format-version', 'str'),
    ('cluster block size', 'cluster-size', 'int'),
    ('compression method', 'compression', 'str'),
    ('encryption method', 'encryption', 'str'),
]


def parse_vmdkinfo(output):
    """Parse vmdkinfo output into comparable fields."""
    return _extract_libyal_fields(parse_libyal_kv(output), _VMDKINFO_FIELDS)


def parse_vhdiinfo(output):
    """Parse vhdiinfo output into comparable fields (VHD and VHDX)."""
    return _extract_libyal_fields(parse_libyal_kv(output), _VHDIINFO_FIELDS)


def parse_qcowinfo(output):
    """Parse qcowinfo output into comparable fields (QCOW v1/v2/v3)."""
    return _extract_libyal_fields(parse_libyal_kv(output), _QCOWINFO_FIELDS)


# Map tool names to their output parsers
LIBYAL_PARSERS = {
    'vmdkinfo': parse_vmdkinfo,
    'vhdiinfo': parse_vhdiinfo,
    'qcowinfo': parse_qcowinfo,
}


def compare_libyal_info(instar_json, libyal_fields, fmt, tool_name):
    """Compare instar info JSON against libyal parsed fields.

    Only compares fields that both tools report. Returns a
    divergence dict or None.
    """
    try:
        instar_data = json.loads(instar_json)
    except (json.JSONDecodeError, ValueError):
        return None

    divergences = {}
    for field, libyal_val in libyal_fields.items():
        if field not in instar_data:
            continue

        instar_val = instar_data[field]

        # Numeric comparison with tolerance
        if isinstance(instar_val, (int, float)) and isinstance(libyal_val, (int, float)):
            if instar_val != libyal_val:
                divergences[field] = {
                    'instar': instar_val,
                    'libyal': libyal_val,
                }
        else:
            # String comparison (case-insensitive for text fields)
            if str(instar_val).lower() != str(libyal_val).lower():
                divergences[field] = {
                    'instar': str(instar_val),
                    'libyal': str(libyal_val),
                }

    if not divergences:
        return None

    return {
        'type': 'libyal_info_divergence',
        'tool': tool_name,
        'format': fmt,
        'field_divergences': divergences,
    }


def check_libyal_parse_consistency(
    instar_rc, libyal_rc, fmt, tool_name, image_path,
    instar_stderr='', libyal_stderr='',
):
    """Compare parse-success consistency between instar and a libyal tool.

    Returns a divergence dict if the tools disagree on whether
    the image is valid, or None if they agree.
    """
    instar_ok = (instar_rc == 0)
    libyal_ok = (libyal_rc == 0)

    if instar_ok == libyal_ok:
        return None

    return {
        'type': 'libyal_check_divergence',
        'tool': tool_name,
        'format': fmt,
        'instar_rc': instar_rc,
        'libyal_rc': libyal_rc,
        'instar_ok': instar_ok,
        'libyal_ok': libyal_ok,
        'note': (
            'libyal parsed OK but instar found errors'
            if libyal_ok
            else 'instar found no errors but libyal failed to parse'
        ),
        'instar_stderr': instar_stderr[:500],
        'libyal_stderr': libyal_stderr[:500],
    }


# ---------------------------------------------------------------------------
# Output comparison
# ---------------------------------------------------------------------------

def _strip_divergent_fields(obj):
    """Recursively strip known-divergent fields from a JSON object.

    Handles nested structures like the 'children' array in info
    JSON output, where each child has its own 'info' dict with
    filename, actual-size, etc.
    """
    if isinstance(obj, dict):
        # Fields that differ because instar and qemu-img operate
        # on separate copies with different paths
        for field in ('filename',):
            obj.pop(field, None)
        # Fields that vary by filesystem allocation or are
        # format-implementation-specific
        for field in KNOWN_DIVERGENCE_FIELDS:
            obj.pop(field, None)
        obj.pop('format-specific', None)
        obj.pop('dirty-flag', None)
        # Recurse into remaining values
        for key in list(obj.keys()):
            obj[key] = _strip_divergent_fields(obj[key])
    elif isinstance(obj, list):
        obj = [_strip_divergent_fields(item) for item in obj]
    return obj


def normalize_info_json(raw_json):
    """Parse and normalize info JSON for comparison.

    Removes fields known to differ between instar and qemu-img
    (filenames, disk size, allocation details) and sorts keys
    for stable comparison. Handles nested children objects.
    """
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return raw_json.strip()

    _strip_divergent_fields(data)

    return json.dumps(data, sort_keys=True, indent=2)


def compare_exit_codes(instar_rc, qemu_rc, operation, context):
    """Compare exit codes, returning a divergence dict or None."""
    # Both succeed or both fail = OK
    instar_ok = (instar_rc == 0)
    qemu_ok = (qemu_rc == 0)

    if instar_ok == qemu_ok:
        return None

    return {
        'type': 'exit_code_divergence',
        'operation': operation,
        'instar_rc': instar_rc,
        'qemu_rc': qemu_rc,
        'context': context,
    }


def compare_info_outputs(instar_stdout, qemu_stdout):
    """Compare info JSON outputs after normalisation.

    Returns a divergence dict or None.
    """
    instar_norm = normalize_info_json(instar_stdout)
    qemu_norm = normalize_info_json(qemu_stdout)

    if instar_norm == qemu_norm:
        return None

    return {
        'type': 'info_output_divergence',
        'instar_normalized': instar_norm[:2000],
        'qemu_normalized': qemu_norm[:2000],
    }


def files_match(path_a, path_b):
    """Return True if two files have identical content."""
    hash_a = _file_sha256(path_a)
    hash_b = _file_sha256(path_b)
    return hash_a == hash_b


def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Operation executors
# ---------------------------------------------------------------------------

def op_info(instar_bin, instar_copy, qemu_copy, fmt, timeout,
            libyal_tools=None):
    """Run info on both copies and compare JSON output.

    When libyal tools are available, also runs the corresponding
    libyal info tool and compares extracted fields against instar.
    """
    # Raw images created by the fuzzer have no partition table,
    # so instar intentionally rejects them as "unknown format"
    # while qemu-img reports "raw".  This is a documented
    # unsafe quirk (see docs/quirks.md), not a bug.
    if fmt == 'raw':
        return None

    i_out, i_err, i_rc = run_instar(
        instar_bin, ['info'], ['--output', 'json', str(instar_copy)],
        timeout=timeout,
    )
    q_out, q_err, q_rc = run_qemu_img(
        ['info'], ['--output=json', str(qemu_copy)],
        timeout=timeout,
    )

    div = compare_exit_codes(i_rc, q_rc, 'info', {
        'instar_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
    })
    if div:
        return div

    # Only compare output when both succeeded
    if i_rc == 0 and q_rc == 0:
        div = compare_info_outputs(i_out, q_out)
        if div:
            return div

    # libyal cross-check: compare instar info against libyal parser
    if libyal_tools and i_rc == 0:
        tool_name = LIBYAL_TOOLS.get(fmt)
        if tool_name and tool_name in libyal_tools:
            parser = LIBYAL_PARSERS[tool_name]
            l_out, l_err, l_rc = run_libyal_tool(
                libyal_tools[tool_name], instar_copy, timeout=timeout,
            )
            if l_rc == 0:
                libyal_fields = parser(l_out)
                if libyal_fields:
                    div = compare_libyal_info(
                        i_out, libyal_fields, fmt, tool_name,
                    )
                    if div:
                        return div

    return None


def op_check(instar_bin, instar_copy, qemu_copy, fmt, timeout,
             libyal_tools=None):
    """Run check on both copies and compare exit codes.

    For QCOW2, compares instar vs qemu-img exit codes. For all
    formats with an available libyal tool, also checks
    parse-success consistency between instar check and the libyal
    info tool (which fails on structurally broken images).
    """
    i_out, i_err, i_rc = run_instar(
        instar_bin, ['check'], [str(instar_copy)],
        timeout=timeout,
    )

    # qemu-img check only works on qcow2
    if fmt == 'qcow2':
        q_out, q_err, q_rc = run_qemu_img(
            ['check'], [str(qemu_copy)],
            timeout=timeout,
        )

        div = compare_exit_codes(i_rc, q_rc, 'check', {
            'instar_stderr': i_err[:500],
            'qemu_stderr': q_err[:500],
            'instar_stdout': i_out[:500],
            'qemu_stdout': q_out[:500],
        })
        if div:
            return div

    # libyal parse-success consistency: if a libyal tool can
    # parse the image, it should be structurally valid; if it
    # can't, instar check should also report errors.
    if libyal_tools:
        tool_name = LIBYAL_TOOLS.get(fmt)
        if tool_name and tool_name in libyal_tools:
            l_out, l_err, l_rc = run_libyal_tool(
                libyal_tools[tool_name], instar_copy, timeout=timeout,
            )
            div = check_libyal_parse_consistency(
                i_rc, l_rc, fmt, tool_name, instar_copy,
                instar_stderr=i_err, libyal_stderr=l_err,
            )
            if div:
                return div

    return None


def op_convert(instar_bin, instar_copy, qemu_copy, fmt,
               timeout, rng, compress=False):
    """Convert both copies to a random output format; compare results.

    Converts both to raw and then SHA-compares the raw outputs to
    ensure data content is identical.
    """
    # Pick a target format for the convert
    target_fmt = rng.choice(['raw', 'qcow2'])

    instar_out = instar_copy.parent / f'{instar_copy.stem}-conv.{target_fmt}'
    qemu_out = qemu_copy.parent / f'{qemu_copy.stem}-conv.{target_fmt}'

    # Convert with instar
    instar_args = ['-O', target_fmt]
    if compress and target_fmt == 'qcow2':
        instar_args.append('--compress')
    instar_args.extend([str(instar_copy), str(instar_out)])

    i_out, i_err, i_rc = run_instar(
        instar_bin, ['convert'], instar_args, timeout=timeout,
    )

    # Convert with qemu-img
    qemu_args = ['-O', target_fmt]
    if compress and target_fmt == 'qcow2':
        qemu_args.append('-c')
    qemu_args.extend([str(qemu_copy), str(qemu_out)])

    q_out, q_err, q_rc = run_qemu_img(
        ['convert'], qemu_args, timeout=timeout,
    )

    div = compare_exit_codes(i_rc, q_rc, 'convert', {
        'target_format': target_fmt,
        'compress': compress,
        'instar_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
    })
    if div:
        return div

    if i_rc != 0:
        # Both failed; no further comparison needed
        return None

    # Compare content: convert both outputs to raw and hash
    if target_fmt == 'raw':
        if not files_match(instar_out, qemu_out):
            return {
                'type': 'convert_content_divergence',
                'target_format': target_fmt,
                'compress': compress,
                'instar_sha256': _file_sha256(instar_out),
                'qemu_sha256': _file_sha256(qemu_out),
            }
    else:
        # For non-raw targets, convert both to raw and compare
        instar_raw = instar_copy.parent / f'{instar_copy.stem}-verify.raw'
        qemu_raw = qemu_copy.parent / f'{qemu_copy.stem}-verify.raw'

        # Use qemu-img to flatten both to raw for comparison
        # (neutral ground — neither tool is favoured)
        subprocess.run(
            ['qemu-img', 'convert', '-O', 'raw',
             str(instar_out), str(instar_raw)],
            capture_output=True, timeout=timeout,
        )
        subprocess.run(
            ['qemu-img', 'convert', '-O', 'raw',
             str(qemu_out), str(qemu_raw)],
            capture_output=True, timeout=timeout,
        )

        if instar_raw.exists() and qemu_raw.exists():
            if not files_match(instar_raw, qemu_raw):
                return {
                    'type': 'convert_content_divergence',
                    'target_format': target_fmt,
                    'compress': compress,
                    'note': 'raw-flattened content differs',
                    'instar_sha256': _file_sha256(instar_raw),
                    'qemu_sha256': _file_sha256(qemu_raw),
                }

    return None


def op_measure(instar_bin, instar_copy, qemu_copy, fmt,
               timeout, rng):
    """Run instar measure and compare to qemu-img measure (raw/qcow2)
    or instar convert's actual output size (vmdk/vpc/vhdx).
    """
    # Pick a target format.
    target_fmt = rng.choice(['raw', 'qcow2', 'vmdk', 'vpc', 'vhdx'])

    instar_args = ['-O', target_fmt, '--output', 'json',
                   str(instar_copy)]
    i_out, i_err, i_rc = run_instar(
        instar_bin, ['measure'], instar_args, timeout=timeout,
    )

    if target_fmt in ('raw', 'qcow2'):
        # qemu-img supports these targets — numeric comparison.
        qemu_args = ['-O', target_fmt, '--output=json',
                     str(qemu_copy)]
        q_out, q_err, q_rc = run_qemu_img(
            ['measure'], qemu_args, timeout=timeout,
        )

        div = compare_exit_codes(
            i_rc, q_rc, 'measure',
            {'target_format': target_fmt,
             'instar_stderr': i_err[:500],
             'qemu_stderr': q_err[:500]},
        )
        if div:
            return div
        if i_rc != 0:
            return None  # both failed, nothing to compare

        # Parse JSON, compare numeric fields.
        try:
            i_json = json.loads(i_out)
            q_json = json.loads(q_out)
        except json.JSONDecodeError as e:
            return {
                'type': 'measure_json_parse_failure',
                'target_format': target_fmt,
                'error': str(e),
                'instar_stdout': i_out[:500],
                'qemu_stdout': q_out[:500],
            }

        # `bitmaps` field comparison: both sides should agree on
        # presence (instar emits "bitmaps": 0 only for qcow2 v3
        # sources targeting qcow2; phase 7c verified parity).
        # required / fully-allocated must match exactly.
        for key in ('required', 'fully-allocated'):
            if i_json.get(key) != q_json.get(key):
                return {
                    'type': 'measure_numeric_divergence',
                    'target_format': target_fmt,
                    'field': key,
                    'instar_value': i_json.get(key),
                    'qemu_value': q_json.get(key),
                    'instar_stdout': i_out,
                    'qemu_stdout': q_out,
                }

        # Check the bitmaps field is consistent: emitted on
        # both sides or neither.
        i_has_bitmaps = 'bitmaps' in i_json
        q_has_bitmaps = 'bitmaps' in q_json
        if i_has_bitmaps != q_has_bitmaps:
            return {
                'type': 'measure_bitmaps_presence_divergence',
                'target_format': target_fmt,
                'instar_has_bitmaps': i_has_bitmaps,
                'qemu_has_bitmaps': q_has_bitmaps,
                'instar_stdout': i_out,
                'qemu_stdout': q_out,
            }

        return None

    # vmdk / vpc / vhdx: qemu-img can't measure, so self-consistency
    # against instar convert.
    if i_rc != 0:
        # measure failed; can't compare bounds. Not necessarily a
        # bug (e.g. unsupported source format).
        return None

    try:
        i_json = json.loads(i_out)
        required = i_json['required']
        fully_allocated = i_json['fully-allocated']
    except (json.JSONDecodeError, KeyError) as e:
        return {
            'type': 'measure_json_parse_failure',
            'target_format': target_fmt,
            'error': str(e),
            'instar_stdout': i_out[:500],
        }

    # Convert the instar copy to the target format.
    out_path = instar_copy.parent / f'{instar_copy.stem}-meas.{target_fmt}'
    conv_args = ['-O', target_fmt, str(instar_copy), str(out_path)]
    c_out, c_err, c_rc = run_instar(
        instar_bin, ['convert'], conv_args, timeout=timeout,
    )

    if c_rc != 0:
        # convert failed. Skip the bound check; some inputs are
        # genuinely unconvertible. measure-side success doesn't
        # imply convert-side success.
        return None

    actual = out_path.stat().st_size

    # Cushion absorbs writer-side alignment artefacts that measure
    # doesn't model. The dominant sources are:
    #
    # 1. Per-block sector alignment in the convert writer — each
    #    allocated block plus its metadata region is padded to the
    #    output sector size (typically 64 KiB).
    # 2. VHDX's 1 MiB block-region alignment — every payload block
    #    starts on a 1 MiB boundary, so the absolute slack on a
    #    ~MB-scale image can be a full MiB even when relative
    #    overhead is small. This is why the floor is 1 MiB rather
    #    than 64 KiB.
    #
    # tests/test_measure.py::TestMeasureRoundTrip uses tighter
    # per-target floors (vmdk/vpc 64 KiB, vhdx 1 MiB) on a curated
    # fixture set. The fuzzer's floor is deliberately the looser
    # of the three so that random small images don't produce
    # false-positive divergences from format-level alignment alone
    # — its purpose is to find *large* disagreements, with the
    # round-trip integration suite catching the smaller ones.
    cushion = max(1 << 20, fully_allocated >> 4)

    # Only the upper bound is a hard invariant.
    #
    # `required` is an *upper bound* on what convert produces for an
    # image with the given source-side AllocationSummary — not a
    # lower bound. instar's parser scanners can over-report
    # allocated_bytes (known phase 7c scanner divergences: raw lacks
    # SEEK_HOLE detection, vhdx scanner treats every block as fully
    # allocated, etc.), which inflates `required`. convert's
    # zero-skipping then produces a smaller-than-`required` output
    # that is still semantically correct. So we only assert
    # `actual <= fully_allocated + cushion` here; the
    # `actual >= required` direction is permissive.
    if actual > fully_allocated + cushion:
        return {
            'type': 'measure_above_fully_allocated_bound',
            'target_format': target_fmt,
            'measured_required': required,
            'measured_fully_allocated': fully_allocated,
            'convert_actual_size': actual,
            'cushion': cushion,
        }

    return None


# ---------------------------------------------------------------------------
# op_create: instar create vs qemu-img create
# ---------------------------------------------------------------------------
#
# Mirrors tests/helpers/info_json.py — keep in sync by hand. A divergence
# whitelist change in either copy should also land in the other.
_CREATE_UNIVERSAL_STRIP = {
    'actual-size', 'dirty-flag',
    'refcount-block-cache-size', 'l2-cache-size',
    'l2-cache-entry-size', 'cache-clean-interval',
}
_CREATE_TARGET_STRIP = {
    'qcow2': set(),
    'vmdk': {'cid', 'parent-cid'},
    'vhd': set(),
    'vhdx': {'log-size'},
    'raw': set(),
}
_CREATE_NESTED_INFO_STRIP = {'virtual-size'}


def _create_strip_keys(obj, keys):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in keys:
                del obj[k]
            else:
                _create_strip_keys(obj[k], keys)
    elif isinstance(obj, list):
        for item in obj:
            _create_strip_keys(item, keys)


def _create_substitute_filename(obj, tmp_path):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == 'filename' and isinstance(v, str) and v == tmp_path:
                obj[k] = '$FILENAME'
            else:
                _create_substitute_filename(v, tmp_path)
    elif isinstance(obj, list):
        for item in obj:
            _create_substitute_filename(item, tmp_path)


def _normalise_create_info(obj, target, tmp_path):
    """Strip divergence-whitelist fields and substitute $FILENAME.

    Returns a normalised deep copy ready for dict-equality comparison
    against another normalised side.
    """
    import copy as _copy
    result = _copy.deepcopy(obj)
    strip = set(_CREATE_UNIVERSAL_STRIP)
    strip.update(_CREATE_TARGET_STRIP.get(target, set()))
    _create_strip_keys(result, strip)
    # Nested children[*].info: strip the wrapping-file physical size
    # (writer-layout artefact; the top-level virtual-size is the
    # contract field and stays).
    if isinstance(result, dict):
        children = result.get('children')
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    info = child.get('info')
                    if isinstance(info, dict):
                        for k in _CREATE_NESTED_INFO_STRIP:
                            info.pop(k, None)
    _create_substitute_filename(result, tmp_path)
    return result


def _create_option_picker(rng):
    """Pick a (target, size_str, options_list) triple biased to avoid
    instar/qemu writer divergences documented in phase 8b's
    KNOWN_WRITER_DIVERGENCES.

    Excludes:
        vhd target entirely        (CHS-geometry rounding divergence)
        qcow2 refcount_bits != 16  (instar hardcodes refcount_order=4)
        qcow2 compat=0.10          (instar hardcodes compat=1.1)
        compression_type=zstd      (instar accept-ignores; emits zlib)
        vhdx default block_size    (instar 8 MiB vs qemu 32 MiB at <= 1 GiB)
    """
    target = rng.choice(['qcow2', 'vmdk', 'vhdx', 'raw'])

    if target == 'qcow2':
        options = []
        cs = rng.choice(QCOW2_CLUSTER_SIZES)
        options.append(f'cluster_size={cs}')
        extended_l2 = rng.random() < 0.3 and cs >= 16384
        if extended_l2:
            # extended_l2 requires cluster_size >= 16 KiB.
            options.append('extended_l2=on')
        if rng.random() < 0.3:
            options.append('lazy_refcounts=on')
        # qcow2 compute_layout in crates/qcow2::create rejects
        # extended_l2 + non-Off preallocation with
        # PreallocationUnsupported (deferred to a future phase). Mirror
        # that constraint in the picker so the differential fuzzer
        # doesn't flag a documented gap as a divergence.
        if extended_l2:
            prealloc = None
        else:
            prealloc = rng.choice([None, 'metadata', 'falloc', 'full'])
        if prealloc is not None:
            options.append(f'preallocation={prealloc}')
            if prealloc in ('metadata', 'falloc', 'full'):
                # All non-Off preallocation modes scale runtime with
                # virtual_size / cluster_size. falloc/full write real
                # blocks; metadata writes L1/L2 entries proportional
                # to the cluster count and is slow under qemu-img at
                # the minimum cluster_size (=512) — a 64 MiB image
                # populates ~1 MiB of L2 tables and qemu-img times
                # out at the fuzzer's 30s budget. Cap virtual_size
                # at 1 MiB so the worst-case combination
                # (cluster_size=512 + 1 MiB) is at most ~16 KiB of
                # L2, which fits comfortably in the budget.
                return target, '1M', options
        size = rng.choice(['1M', '16M', '64M'])
        return target, size, options

    if target == 'vmdk':
        subformat = rng.choice(['monolithicSparse', 'streamOptimized'])
        size = rng.choice(['1M', '16M', '64M', '256M'])
        return target, size, [f'subformat={subformat}']

    if target == 'vhdx':
        # block_size always explicit — instar's default diverges from
        # qemu's at virtual sizes <= 1 GiB.
        bs = rng.choice(['16M', '32M'])
        size = rng.choice(['64M', '256M', '1G'])
        return target, size, [f'block_size={bs}']

    # raw
    size = rng.choice(['1M', '16M', '64M', '256M'])
    return target, size, []


def op_create(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Create the same image via instar create and the system qemu-img
    create, compare via qemu-img info JSON.

    instar_copy / qemu_copy / fmt are part of the standard op_* signature
    but unused here — `create` produces new files from a synthetic
    (target, options, size) triple rather than reading the iteration's
    source image. The fuzz loop dispatches uniformly across ops, so the
    signature must match.
    """
    target, size_str, options_list = _create_option_picker(rng)

    iter_dir = instar_copy.parent
    ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk', 'vhdx': 'vhdx',
           'raw': 'raw'}[target]
    inst_path = iter_dir / f'create-instar.{ext}'
    qemu_path = iter_dir / f'create-qemu.{ext}'

    inst_args = ['-f', target]
    qemu_args = ['-f', target]
    for opt in options_list:
        inst_args.extend(['-o', opt])
        qemu_args.extend(['-o', opt])
    inst_args.extend([str(inst_path), size_str])
    qemu_args.extend([str(qemu_path), size_str])

    i_out, i_err, i_rc = run_instar(
        instar_bin, ['create'], inst_args, timeout=timeout)
    q_out, q_err, q_rc = run_qemu_img(
        ['create'], qemu_args, timeout=timeout)

    div = compare_exit_codes(
        i_rc, q_rc, 'create',
        {'target_format': target,
         'size': size_str,
         'options': options_list,
         'instar_stderr': i_err[:500],
         'qemu_stderr': q_err[:500]},
    )
    if div:
        return div
    if i_rc != 0:
        return None  # both failed, nothing to compare

    inst_info_out, _, inst_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(inst_path)], timeout=timeout)
    qemu_info_out, _, qemu_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(qemu_path)], timeout=timeout)
    if inst_info_rc != 0 or qemu_info_rc != 0:
        return {
            'type': 'create_info_readback_failure',
            'target_format': target,
            'size': size_str,
            'options': options_list,
            'instar_info_rc': inst_info_rc,
            'qemu_info_rc': qemu_info_rc,
            'instar_info_stdout': inst_info_out[:500],
            'qemu_info_stdout': qemu_info_out[:500],
        }

    try:
        inst_json = json.loads(inst_info_out)
        qemu_json = json.loads(qemu_info_out)
    except json.JSONDecodeError as e:
        return {
            'type': 'create_info_json_parse_failure',
            'target_format': target,
            'size': size_str,
            'options': options_list,
            'error': str(e),
            'instar_info_stdout': inst_info_out[:500],
            'qemu_info_stdout': qemu_info_out[:500],
        }

    inst_norm = _normalise_create_info(inst_json, target, str(inst_path))
    qemu_norm = _normalise_create_info(qemu_json, target, str(qemu_path))

    if inst_norm != qemu_norm:
        return {
            'type': 'create_info_divergence',
            'target_format': target,
            'size': size_str,
            'options': options_list,
            'instar_normalised': inst_norm,
            'qemu_normalised': qemu_norm,
        }
    return None


# ---------------------------------------------------------------------------
# Single iteration
# ---------------------------------------------------------------------------

def run_iteration(instar_bin, workdir, rng, iteration, timeout,
                   libyal_tools=None):
    """Run one fuzzing iteration. Returns (divergence_dict, attrs) or
    (None, attrs) on success.
    """
    iter_dir = workdir / f'iter-{iteration:06d}'
    iter_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Generate a random image
        image_path, fmt, attrs = generate_image(rng, iter_dir, iteration)

        # Create separate copies for instar and qemu-img
        instar_copy = iter_dir / f'instar-{image_path.name}'
        qemu_copy = iter_dir / f'qemu-{image_path.name}'
        shutil.copy2(image_path, instar_copy)
        shutil.copy2(image_path, qemu_copy)

        # Pick a random set of 2-4 operations to run independently
        # on the same input image
        num_ops = rng.randint(2, 4)
        ops = [rng.choice(OPERATIONS) for _ in range(num_ops)]
        attrs['operations'] = ops

        for op in ops:
            if op == 'info':
                div = op_info(
                    instar_bin, instar_copy, qemu_copy, fmt, timeout,
                    libyal_tools=libyal_tools,
                )
            elif op == 'check':
                div = op_check(
                    instar_bin, instar_copy, qemu_copy, fmt, timeout,
                    libyal_tools=libyal_tools,
                )
            elif op == 'convert':
                div = op_convert(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng, compress=False,
                )
            elif op == 'convert_compressed':
                div = op_convert(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng, compress=True,
                )
            elif op == 'measure':
                div = op_measure(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'create':
                div = op_create(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            else:
                continue

            if div:
                div['operation_in_chain'] = op
                div['iteration'] = iteration
                return div, attrs

        return None, attrs

    finally:
        # Clean up iteration directory to avoid filling disk
        shutil.rmtree(iter_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_dir, seed):
    """Configure logging to file and stderr."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f'fuzz-{seed}.log'

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    logger.addHandler(sh)

    return log_file


def write_divergence_report(log_dir, seed, iteration, attrs, divergence):
    """Write a JSON report for a divergence finding."""
    report = {
        'seed': seed,
        'iteration': iteration,
        'attributes': attrs,
        'divergence': divergence,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    report_path = log_dir / f'divergence-{seed}-{iteration:06d}.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    return report_path


def file_github_issue(seed, iteration, attrs, divergence, workflow_url):
    """File a GitHub issue for a divergence immediately.

    Requires the `gh` CLI to be installed and GH_TOKEN to be set.
    Logs a warning and continues if issue creation fails.
    """
    div_type = divergence.get('type', 'unknown')
    attrs_json = json.dumps(attrs, indent=2)
    details_json = json.dumps(divergence, indent=2)

    title = (
        f'Differential fuzz: {div_type}'
        f' (seed {seed}, iter {iteration})'
    )
    run_line = ''
    if workflow_url:
        run_line = f'**Workflow run:** {workflow_url}\n'

    body = (
        f'## Differential fuzzing divergence\n\n'
        f'**Type:** `{div_type}`\n'
        f'**Seed:** `{seed}`\n'
        f'**Iteration:** `{iteration}`\n'
        f'{run_line}\n'
        f'### Image attributes\n'
        f'```json\n{attrs_json}\n```\n\n'
        f'### Divergence details\n'
        f'```json\n{details_json}\n```\n\n'
        f'### Reproduction\n'
        f'```bash\n'
        f'python3 scripts/differential-fuzz.py \\\n'
        f'  --instar src/target/release/instar \\\n'
        f'  --iterations {iteration + 1} \\\n'
        f'  --seed {seed} \\\n'
        f'  --fail-fast\n'
        f'```\n'
    )

    try:
        result = subprocess.run(
            [
                'gh', 'issue', 'create',
                '--label', 'security-audit',
                '--title', title,
                '--body', body,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            issue_url = result.stdout.strip()
            logger.info(
                'Filed issue for iteration %d: %s',
                iteration, issue_url,
            )
        else:
            logger.warning(
                'Failed to file issue for iteration %d: %s',
                iteration, result.stderr.strip(),
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning(
            'Could not file issue for iteration %d: %s',
            iteration, exc,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Differential fuzzing: instar vs qemu-img',
    )
    parser.add_argument(
        '--instar', required=True,
        help='Path to instar binary',
    )
    parser.add_argument(
        '--iterations', type=int, default=1000,
        help='Number of fuzzing iterations (default: 1000)',
    )
    parser.add_argument(
        '--seed', type=int, default=None,
        help='Random seed (default: random)',
    )
    parser.add_argument(
        '--workdir', type=str, default=None,
        help='Working directory for temp images (default: tempdir)',
    )
    parser.add_argument(
        '--timeout', type=int, default=30,
        help='Per-operation timeout in seconds (default: 30)',
    )
    parser.add_argument(
        '--log-dir', type=str, default='./fuzz-logs',
        help='Directory for logs and reports (default: ./fuzz-logs)',
    )
    parser.add_argument(
        '--fail-fast', action='store_true',
        help='Exit on first divergence (default: continue and report)',
    )
    parser.add_argument(
        '--create-issues', action='store_true',
        help='File GitHub issues immediately as divergences are found '
             '(requires gh CLI and GH_TOKEN)',
    )
    parser.add_argument(
        '--workflow-url', type=str, default=None,
        help='URL of the CI workflow run (included in filed issues)',
    )
    args = parser.parse_args()

    # Resolve paths
    instar_bin = Path(args.instar).resolve()
    if not instar_bin.exists():
        print(f'Error: instar binary not found: {instar_bin}', file=sys.stderr)
        sys.exit(1)

    log_dir = Path(args.log_dir).resolve()
    seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)

    # Verify qemu-img is available
    try:
        subprocess.run(
            ['qemu-img', '--version'],
            capture_output=True, timeout=5,
        )
    except FileNotFoundError:
        print('Error: qemu-img not found in PATH', file=sys.stderr)
        sys.exit(1)

    log_file = setup_logging(log_dir, seed)
    logger.info('Differential fuzzing started')
    logger.info('  seed:       %d', seed)
    logger.info('  iterations: %d', args.iterations)
    logger.info('  instar:      %s', instar_bin)
    logger.info('  timeout:    %ds', args.timeout)
    logger.info('  log file:   %s', log_file)

    # Detect libyal tools (optional — graceful degradation)
    libyal_tools = detect_libyal_tools()

    # Create or use workdir
    if args.workdir:
        workdir = Path(args.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        cleanup_workdir = False
    else:
        workdir = Path(tempfile.mkdtemp(prefix='instar-fuzz-'))
        cleanup_workdir = True

    logger.info('  workdir:    %s', workdir)

    rng = random.Random(seed)
    divergences = []
    start_time = time.time()

    try:
        for i in range(args.iterations):
            # Derive a per-iteration seed so individual failures
            # are independently reproducible
            iter_seed = rng.randint(0, 2**32 - 1)
            iter_rng = random.Random(iter_seed)

            if (i + 1) % 50 == 0 or i == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                logger.info(
                    'Iteration %d/%d (%.1f iter/s, %d divergences)',
                    i + 1, args.iterations, rate, len(divergences),
                )

            try:
                div, attrs = run_iteration(
                    instar_bin, workdir, iter_rng, i, args.timeout,
                    libyal_tools=libyal_tools,
                )
            except Exception as exc:
                logger.warning(
                    'Iteration %d crashed: %s', i, exc,
                )
                attrs = {'error': str(exc)}
                div = {
                    'type': 'iteration_crash',
                    'error': str(exc),
                    'iteration': i,
                }

            if div:
                attrs['iter_seed'] = iter_seed
                report_path = write_divergence_report(
                    log_dir, seed, i, attrs, div,
                )
                divergences.append((i, div))
                logger.warning(
                    'DIVERGENCE at iteration %d: %s (report: %s)',
                    i, div.get('type', 'unknown'), report_path,
                )

                if args.create_issues:
                    file_github_issue(
                        seed, i, attrs, div,
                        args.workflow_url,
                    )

                if args.fail_fast:
                    logger.error(
                        'Exiting on first divergence (--fail-fast)'
                    )
                    sys.exit(1)

    finally:
        elapsed = time.time() - start_time
        iterations_done = i + 1 if 'i' in dir() else 0
        logger.info(
            'Fuzzing complete: %d iterations in %.1fs (%.1f iter/s)',
            iterations_done, elapsed,
            iterations_done / elapsed if elapsed > 0 else 0,
        )
        logger.info('Divergences found: %d', len(divergences))

        # Write summary (including in --fail-fast mode)
        summary = {
            'seed': seed,
            'iterations': args.iterations,
            'iterations_completed': iterations_done,
            'elapsed_seconds': round(elapsed, 1),
            'divergences_found': len(divergences),
            'divergence_iterations': [d[0] for d in divergences],
        }
        summary_path = log_dir / f'summary-{seed}.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info('Summary written to %s', summary_path)

        if cleanup_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    if divergences:
        print(
            f'\nFAILED: {len(divergences)} divergence(s) found. '
            f'See {log_dir} for details.',
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(
            f'\nPASSED: {args.iterations} iterations, '
            f'0 divergences. Seed: {seed}',
        )
        sys.exit(0)


if __name__ == '__main__':
    main()
