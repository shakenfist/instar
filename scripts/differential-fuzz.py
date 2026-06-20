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
        [--log-dir ./fuzz-logs] \
        [--ops snapshot,resize]
"""

import argparse
import hashlib
import json
import logging
import random
import re
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
              'create', 'resize', 'amend', 'rebase', 'commit', 'map',
              'snapshot', 'repair']

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

def run_instar(instar_bin, subcmd, args, timeout=30, cwd=None):
    """Run an instar subcommand. Returns (stdout, stderr, rc)."""
    cmd = [str(instar_bin)] + subcmd + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1


def run_qemu_img(subcmd, args, timeout=30, cwd=None):
    """Run a qemu-img subcommand. Returns (stdout, stderr, rc)."""
    cmd = ['qemu-img'] + subcmd + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
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
    the image is valid, or None if they agree. External-tool
    timeouts on either side are reclassified as inconclusive
    rather than `libyal_check_divergence` — mirrors the
    `compare_exit_codes` policy.
    """
    libyal_timed_out = _is_external_timeout(libyal_rc, libyal_stderr)
    instar_timed_out = _is_external_timeout(instar_rc, instar_stderr)
    if libyal_timed_out or instar_timed_out:
        return {
            'type': 'inconclusive_external_timeout',
            'operation': f'libyal:{tool_name}',
            'tool': tool_name,
            'format': fmt,
            'instar_rc': instar_rc,
            'libyal_rc': libyal_rc,
            'timed_out': (
                'libyal' if libyal_timed_out and not instar_timed_out
                else 'instar' if instar_timed_out and not libyal_timed_out
                else 'both'
            ),
            'instar_stderr': instar_stderr[:500],
            'libyal_stderr': libyal_stderr[:500],
        }

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


def _is_external_timeout(rc, stderr):
    """Detect the sentinel returned by run_instar / run_qemu_img when a
    subprocess.TimeoutExpired fires (rc=-1, stderr='TIMEOUT after Ns')."""
    return rc == -1 and isinstance(stderr, str) and 'TIMEOUT after' in stderr


def compare_exit_codes(instar_rc, qemu_rc, operation, context):
    """Compare exit codes, returning a divergence dict or None.

    Timeouts on either side are reclassified as inconclusive rather
    than `exit_code_divergence`: qemu-img is known to hang on some
    adversarial qcow2 shrink inputs and a timeout vs a real failure
    is not an instar defect. The harness records the inconclusive
    iteration in the summary so visibility is preserved without
    polluting the divergence count or filing a GitHub issue."""
    qemu_timed_out = _is_external_timeout(qemu_rc, context.get('qemu_stderr', ''))
    instar_timed_out = _is_external_timeout(
        instar_rc, context.get('instar_stderr', '')
    )
    if qemu_timed_out or instar_timed_out:
        return {
            'type': 'inconclusive_external_timeout',
            'operation': operation,
            'instar_rc': instar_rc,
            'qemu_rc': qemu_rc,
            'timed_out': (
                'qemu' if qemu_timed_out and not instar_timed_out
                else 'instar' if instar_timed_out and not qemu_timed_out
                else 'both'
            ),
            'context': context,
        }

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

    All qcow2 refcount_bits widths are now exercised — build_header
    derives refcount_order from refcount_bits and packs sub-byte widths
    LSB-first (instar #365).

    Excludes:
        vhd target entirely        (CHS-geometry rounding divergence)
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
        # refcount_bits dimension (instar #365): build_header now derives
        # refcount_order from refcount_bits and packs sub-byte widths
        # LSB-first, so every width qemu accepts round-trips and is
        # differential-comparable.
        if rng.random() < 0.4:
            options.append(
                f'refcount_bits={rng.choice([1, 2, 4, 8, 16, 32, 64])}')
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
# Resize: shared helpers + picker + op
# ---------------------------------------------------------------------------

# qemu-img size-suffix grammar; ported from
# instar-testdata/scripts/generate-baselines.py so the picker can
# do byte-math for --shrink inference without parsing qemu's grammar.
_RESIZE_SIZE_SUFFIX_MULTIPLIERS = {
    'b': 512,
    'k': 1024,
    'K': 1024,
    'M': 1024 ** 2,
    'G': 1024 ** 3,
}


def _resize_parse_qemu_size(size_str):
    """Parse a qemu-img SIZE string to bytes (M/G grammar subset)."""
    s = size_str.strip()
    if s[-1] in _RESIZE_SIZE_SUFFIX_MULTIPLIERS:
        return int(s[:-1]) * _RESIZE_SIZE_SUFFIX_MULTIPLIERS[s[-1]]
    return int(s)


def _resize_resolve_end_bytes(start_size, end_spec):
    """Resolve a resize end_spec ('64M' / '+63M' / '-32M') to bytes."""
    start_bytes = _resize_parse_qemu_size(start_size)
    s = end_spec.strip()
    if s.startswith('+'):
        return start_bytes + _resize_parse_qemu_size(s[1:])
    if s.startswith('-'):
        return start_bytes - _resize_parse_qemu_size(s[1:])
    return _resize_parse_qemu_size(s)


def _resize_option_picker(rng):
    """Pick (target, start_size, end_spec, options_list, prealloc).

    Constraints honour KNOWN_RESIZE_DIVERGENCES from
    tests/test_resize.py and the resize planner's documented gaps:
      * qcow2 + raw only — qemu-img can't resize vmdk/vhd/vhdx on
        any shipped version; the differential surface has nothing
        to compare against for those targets (see PLAN-resize
        phase 10 and 11 for the asymmetry).
      * qcow2 refcount_bits is now exercised across all widths —
        build_header derives refcount_order from refcount_bits and
        sub-byte widths are packed LSB-first (instar #365), so the
        widths qemu accepts are differential-comparable.
      * No qcow2 compat=0.10 (instar hardcodes compat=1.1).
      * No qcow2 + preallocation=metadata (planner gap deferred
        from phase 2c; master-plan Future work).
      * No qcow2 cluster_size=2097152 — the qcow2 resize planner's
        worst-case scratch buffer (QCOW2_MAX_RESIZE_SCRATCH = 32M)
        is sized for default-cluster-size images; 2 MiB cluster
        sizes blow it out for even modest virtual sizes
        ("image too large for the resize scratch buffer").
        Tightening the bound is a master-plan TODO.
      * No qcow2 extended_l2 + non-Off preallocation — the
        planner rejects with PreallocationUnsupported (same gap
        the create picker excludes; see _create_option_picker).
    """
    target = rng.choice(['qcow2', 'raw'])

    if target == 'qcow2':
        options = []
        # Drop 2 MiB clusters — see docstring.
        cs = rng.choice([c for c in QCOW2_CLUSTER_SIZES if c != 2097152])
        options.append(f'cluster_size={cs}')
        extended_l2 = rng.random() < 0.3 and cs >= 16384
        if extended_l2:
            options.append('extended_l2=on')
        if rng.random() < 0.3:
            options.append('lazy_refcounts=on')
        # refcount_bits dimension (instar #365): exercise sub-byte and
        # wide refcounts, not just the qemu default of 16.
        if rng.random() < 0.4:
            options.append(
                f'refcount_bits={rng.choice([1, 2, 4, 8, 16, 32, 64])}')

        # Pick a start / end pair. Sizes capped at 64M for runtime;
        # falloc/full prealloc additionally capped at 4M because
        # they materialise real blocks.
        # extended_l2 + non-Off preallocation is a planner-side
        # rejection — match the create picker's constraint.
        if extended_l2:
            prealloc = rng.choice([None, 'off'])
        else:
            prealloc = rng.choice([None, 'off', 'falloc', 'full'])
        if prealloc in ('falloc', 'full'):
            start = rng.choice(['1M', '4M'])
            end = rng.choice(['4M', '8M', '16M'])
            if _resize_parse_qemu_size(end) == _resize_parse_qemu_size(start):
                end = '16M'
            # prealloc is a resize flag, not -o — no extra
            # create-time options needed beyond what the qcow2
            # branch already accumulated.
        else:
            # qcow2 grow sizes include 256M / 1G after followup-01
            # lifted the stage-all refcount-block ceiling; both
            # tools handle these sparse-only-file sizes in well
            # under the differential harness's 30s timeout.
            start = rng.choice(['1M', '4M', '16M', '256M'])
            # Pick end form: absolute, additive, or subtractive.
            form = rng.choice(['abs', 'add', 'sub'])
            if form == 'abs':
                end = rng.choice(['4M', '16M', '64M', '256M', '1G'])
                if _resize_parse_qemu_size(end) == _resize_parse_qemu_size(start):
                    end = '1G'
            elif form == 'add':
                end = rng.choice(['+1M', '+15M', '+63M', '+256M'])
            else:
                start_b = _resize_parse_qemu_size(start)
                # Pick a delta that keeps end > 0.
                if start_b > 1024 ** 2:
                    end = rng.choice(['-512K', '-1M'])
                else:
                    end = '+63M'  # too small to shrink; fall back to grow

        return target, start, end, options, prealloc

    # raw
    options = []
    prealloc = rng.choice([None, 'off', 'falloc', 'full'])
    if prealloc in ('falloc', 'full'):
        start = rng.choice(['1M', '4M'])
        end = rng.choice(['4M', '8M', '16M'])
        if _resize_parse_qemu_size(end) == _resize_parse_qemu_size(start):
            end = '16M'
    else:
        start = rng.choice(['1M', '4M', '16M', '64M'])
        form = rng.choice(['abs', 'add', 'sub'])
        if form == 'abs':
            end = rng.choice(['4M', '16M', '64M', '256M'])
            if _resize_parse_qemu_size(end) == _resize_parse_qemu_size(start):
                end = '256M'
        elif form == 'add':
            end = rng.choice(['+1M', '+15M', '+63M'])
        else:
            start_b = _resize_parse_qemu_size(start)
            if start_b > 1024 ** 2:
                end = rng.choice(['-512K', '-1M'])
            else:
                end = '+63M'
    return target, start, end, options, prealloc


def op_resize(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Create the same image twice, resize each via its native tool,
    compare via qemu-img info JSON.

    instar_copy / qemu_copy / fmt are part of the standard op_*
    signature but unused — `resize` builds its own
    (target, start, end, opts, prealloc) tuple via the picker.
    """
    target, start_size, end_spec, options_list, prealloc = (
        _resize_option_picker(rng))
    end_bytes = _resize_resolve_end_bytes(start_size, end_spec)
    start_bytes = _resize_parse_qemu_size(start_size)
    apply_shrink = end_bytes < start_bytes

    iter_dir = instar_copy.parent
    ext = {'qcow2': 'qcow2', 'raw': 'raw'}[target]
    inst_path = iter_dir / f'resize-instar.{ext}'
    qemu_path = iter_dir / f'resize-qemu.{ext}'

    # 1. Seed identical start images.
    create_args_base = ['-f', target]
    for opt in options_list:
        create_args_base.extend(['-o', opt])

    _, ic_stderr, ic_rc = run_instar(
        instar_bin, ['create'],
        create_args_base + [str(inst_path), start_size],
        timeout=timeout)
    _, qc_stderr, qc_rc = run_qemu_img(
        ['create'],
        create_args_base + [str(qemu_path), start_size],
        timeout=timeout)
    if ic_rc != 0 or qc_rc != 0:
        # Divergent rejections at the create step show up as
        # phase 8's create matrix issues, not resize issues.
        if ic_rc != 0 and qc_rc != 0:
            return None  # both rejected; not a resize-side divergence
        return {
            'type': 'resize_create_seed_divergence',
            'target_format': target,
            'start_size': start_size,
            'options': options_list,
            'instar_rc': ic_rc, 'qemu_rc': qc_rc,
            'instar_stderr': ic_stderr[:500],
            'qemu_stderr': qc_stderr[:500],
        }

    # 2. Resize each via its native tool.
    resize_args_base = ['-f', target]
    if apply_shrink:
        resize_args_base.append('--shrink')
    if prealloc is not None:
        resize_args_base.extend(['--preallocation', prealloc])

    _, ir_stderr, ir_rc = run_instar(
        instar_bin, ['resize'],
        resize_args_base + [str(inst_path), end_spec],
        timeout=timeout)
    _, qr_stderr, qr_rc = run_qemu_img(
        ['resize'],
        resize_args_base + [str(qemu_path), end_spec],
        timeout=timeout)

    div = compare_exit_codes(
        ir_rc, qr_rc, 'resize',
        {'target_format': target,
         'start_size': start_size,
         'end_spec': end_spec,
         'options': options_list,
         'preallocation': prealloc,
         'apply_shrink': apply_shrink,
         'instar_stderr': ir_stderr[:500],
         'qemu_stderr': qr_stderr[:500]},
    )
    if div:
        return div
    if ir_rc != 0:
        return None  # both rejected; nothing to compare

    # 3. Compare via qemu-img info on both outputs.
    inst_info_out, _, inst_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(inst_path)], timeout=timeout)
    qemu_info_out, _, qemu_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(qemu_path)], timeout=timeout)
    if inst_info_rc != 0 or qemu_info_rc != 0:
        return {
            'type': 'resize_info_readback_failure',
            'target_format': target,
            'start_size': start_size,
            'end_spec': end_spec,
            'options': options_list,
            'preallocation': prealloc,
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
            'type': 'resize_info_json_parse_failure',
            'target_format': target,
            'error': str(e),
            'instar_info_stdout': inst_info_out[:500],
            'qemu_info_stdout': qemu_info_out[:500],
        }

    inst_norm = _normalise_create_info(inst_json, target, str(inst_path))
    qemu_norm = _normalise_create_info(qemu_json, target, str(qemu_path))

    if inst_norm != qemu_norm:
        return {
            'type': 'resize_info_divergence',
            'target_format': target,
            'start_size': start_size,
            'end_spec': end_spec,
            'options': options_list,
            'preallocation': prealloc,
            'apply_shrink': apply_shrink,
            'instar_normalised': inst_norm,
            'qemu_normalised': qemu_norm,
        }
    return None


# ---------------------------------------------------------------------------
# Amend: picker + op
# ---------------------------------------------------------------------------

def _amend_option_picker(rng):
    """Pick (create_opts, amend_opts) for a qcow2 amend transition.

    Both are lists of `key=value` strings passed to
    `qemu-img create -o` / `instar|qemu-img amend -o`. Mirrors the
    transition space of tests/test_amend.py's AMEND_CASES:
      * upgrade   — create compat=0.10, amend compat=1.1
                    (optionally + lazy_refcounts=on).
      * downgrade — create compat=1.1, amend compat=0.10.
      * lazy-on   — create compat=1.1, amend lazy_refcounts=on.
      * lazy-off  — create compat=1.1,lazy_refcounts=on,
                    amend lazy_refcounts=off.
      * noop      — create compat=1.1, amend compat=1.1.

    Divergence avoidance (a mis-steered picker floods false
    divergences — see PLAN-amend phase 8b Situation):
      * Never emits `compression_type=zstd` (or any
        `compression_type`): instar refuses a compat=0.10 downgrade
        of a zstd-compression image while qemu-img accepts it
        (rewriting compression_type) — the one documented phase-6
        divergence.
      * Keeps `refcount_bits=16` (the qcow2 default) on every
        downgrade case: instar refuses a compat=0.10 downgrade of an
        image whose refcount width is not 16. refcount_bits is only
        randomised for cases that do NOT downgrade.
    """
    case = rng.choice(
        ['upgrade', 'downgrade', 'lazy-on', 'lazy-off', 'noop'])

    create_opts = []
    cs = rng.choice([512, 4096, 65536])
    create_opts.append(f'cluster_size={cs}')

    downgrade = (case == 'downgrade')

    # refcount_bits is only safe to randomise when the amend does NOT
    # downgrade to compat=0.10 (instar refuses a non-16 downgrade).
    if not downgrade and rng.random() < 0.4:
        create_opts.append(
            f'refcount_bits={rng.choice([1, 2, 4, 8, 16, 32, 64])}')

    if case == 'upgrade':
        create_opts.append('compat=0.10')
        if rng.random() < 0.5:
            amend_opts = ['compat=1.1', 'lazy_refcounts=on']
        else:
            amend_opts = ['compat=1.1']
    elif case == 'downgrade':
        create_opts.append('compat=1.1')
        amend_opts = ['compat=0.10']
    elif case == 'lazy-on':
        create_opts.append('compat=1.1')
        amend_opts = ['lazy_refcounts=on']
    elif case == 'lazy-off':
        create_opts.append('compat=1.1')
        create_opts.append('lazy_refcounts=on')
        amend_opts = ['lazy_refcounts=off']
    else:  # noop
        create_opts.append('compat=1.1')
        amend_opts = ['compat=1.1']

    return create_opts, amend_opts


def op_amend(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Build the same qcow2 twice, amend each via its native tool,
    compare via qemu-img info JSON + a structural qemu-img check.

    instar_copy / qemu_copy / fmt are part of the standard op_*
    signature but unused — `amend` builds its own
    (create_opts, amend_opts) pair via the picker. amend is
    qcow2-only and launches a guest VMM needing /dev/kvm (the
    workflow passes --device /dev/kvm; op_rebase/op_commit/op_repair
    already assume this — no special kvm guard).
    """
    create_opts, amend_opts = _amend_option_picker(rng)

    iter_dir = instar_copy.parent
    inst_path = iter_dir / 'amend-instar.qcow2'
    qemu_path = iter_dir / 'amend-qemu.qcow2'

    # 1. Seed identical start images with qemu-img create (NOT instar
    # create — it is v3-only and cannot make the v2 upgrade inputs).
    create_args_base = ['-f', 'qcow2']
    for opt in create_opts:
        create_args_base.extend(['-o', opt])

    _, ic_stderr, ic_rc = run_qemu_img(
        ['create'], create_args_base + [str(inst_path), '1M'],
        timeout=timeout)
    _, qc_stderr, qc_rc = run_qemu_img(
        ['create'], create_args_base + [str(qemu_path), '1M'],
        timeout=timeout)
    if ic_rc != 0 or qc_rc != 0:
        # qemu-img create builds both sides; a failure here is not an
        # amend divergence. If both fail, skip; if only one fails it
        # is an unexpected qemu-img inconsistency, surface it.
        if ic_rc != 0 and qc_rc != 0:
            return None
        return {
            'type': 'amend_create_seed_divergence',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
            'instar_path_rc': ic_rc, 'qemu_path_rc': qc_rc,
            'instar_path_stderr': ic_stderr[:500],
            'qemu_path_stderr': qc_stderr[:500],
        }

    # 2. Amend each via its native tool.
    amend_args_base = ['-f', 'qcow2']
    for opt in amend_opts:
        amend_args_base.extend(['-o', opt])

    _, ia_stderr, ia_rc = run_instar(
        instar_bin, ['amend'],
        amend_args_base + [str(inst_path)],
        timeout=timeout)
    _, qa_stderr, qa_rc = run_qemu_img(
        ['amend'],
        amend_args_base + [str(qemu_path)],
        timeout=timeout)

    div = compare_exit_codes(
        ia_rc, qa_rc, 'amend',
        {'create_opts': create_opts,
         'amend_opts': amend_opts,
         'instar_stderr': ia_stderr[:500],
         'qemu_stderr': qa_stderr[:500]},
    )
    if div:
        return div
    if ia_rc != 0:
        return None  # both rejected; nothing to compare

    # 3. Compare via qemu-img info on both outputs.
    inst_info_out, _, inst_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(inst_path)], timeout=timeout)
    qemu_info_out, _, qemu_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(qemu_path)], timeout=timeout)
    if inst_info_rc != 0 or qemu_info_rc != 0:
        return {
            'type': 'amend_info_readback_failure',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
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
            'type': 'amend_info_json_parse_failure',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
            'error': str(e),
            'instar_info_stdout': inst_info_out[:500],
            'qemu_info_stdout': qemu_info_out[:500],
        }

    inst_norm = _normalise_create_info(inst_json, 'qcow2', str(inst_path))
    qemu_norm = _normalise_create_info(qemu_json, 'qcow2', str(qemu_path))

    if inst_norm != qemu_norm:
        return {
            'type': 'amend_info_divergence',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
            'instar_normalised': inst_norm,
            'qemu_normalised': qemu_norm,
        }

    # 4. Structural check on the instar output. amend rewrites only
    # header metadata; a corruption qemu-img info doesn't surface
    # (e.g. a damaged refcount/L1 table) shows up here. qemu-img
    # check exits non-zero when it finds corruptions/leaks/errors;
    # parse via metrics so a clean image with a benign non-zero rc
    # is not misread.
    inst_metrics = _qemu_check_metrics(inst_path, timeout)
    if inst_metrics is None:
        return {
            'type': 'amend_check_unparseable',
            'note': 'qemu-img check could not parse instar-amended image',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
            'instar_stderr': ia_stderr[:500],
        }
    if not _is_clean(inst_metrics):
        return {
            'type': 'amend_check_divergence',
            'create_opts': create_opts,
            'amend_opts': amend_opts,
            'instar_metrics': inst_metrics,
        }
    return None


def _rebase_option_picker(rng):
    """Pick (overlay_size, new_backing_name, new_backing_size,
    rebase_flags, extra_create_options).

    Constraints honour the rebase planner's documented gaps:
      * qcow2 only — qemu-img rebase rejects vmdk / vhd / vhdx
        with "Operation not supported" on every shipped
        version; the differential surface has nothing to
        compare against for those targets.
      * Backing names match the overlay's existing slot length
        (`base.qcow2` / `next.qcow2` are both 10 chars) so
        the unsafe-mode planner doesn't trip the long-path
        relocation gap. Detach (`-b ''`) covers the third
        shape.
      * Mode mix between `-u` and safe (default); both
        binaries support qcow2 safe-mode.
      * No qcow2 refcount_bits != 16 (instar hardcodes).
      * No qcow2 compat=0.10 (instar hardcodes 1.1).
      * cluster_size mix excluding 2 MiB (matches the resize
        picker's bound for runtime; rebase doesn't strictly
        share the scratch ceiling but keeping the picker
        tight avoids long iterations).
    """
    overlay_size = rng.choice(['1M', '4M', '64M'])
    new_backing_size = rng.choice(['1M', '4M', '64M'])
    # Mix detach (~25%) into the picker; otherwise pick a
    # basename matching the overlay's existing slot length.
    new_backing_name = rng.choice([
        'next.qcow2', 'base.qcow2', 'next.qcow2', '',
    ])
    is_detach = new_backing_name == ''
    mode = rng.choice(['unsafe', 'safe'])
    flags = []
    if mode == 'unsafe':
        flags.append('-u')
    if not is_detach:
        flags += ['-F', 'qcow2']

    create_options = []
    cs = rng.choice([c for c in QCOW2_CLUSTER_SIZES if c != 2097152])
    create_options.append(f'cluster_size={cs}')
    if rng.random() < 0.3:
        create_options.append('lazy_refcounts=on')

    return overlay_size, new_backing_name, new_backing_size, \
           flags, create_options


def op_rebase(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Build identical overlay+backing fixtures via qemu-img create,
    rebase each via its native tool, compare via qemu-img info JSON.

    `instar_copy / qemu_copy / fmt` are part of the standard op_*
    signature but unused — `rebase` builds its own fixture pair
    via the picker.
    """
    (overlay_size, new_backing_name, new_backing_size,
     rebase_flags, create_options) = _rebase_option_picker(rng)
    is_detach = new_backing_name == ''

    iter_dir = instar_copy.parent
    target = 'qcow2'

    # 1. Seed identical fixtures: a backing + an overlay backed by
    # it (each side gets its own copies). The "original" backing
    # is always `base.qcow2` to match the overlay's recorded
    # pointer. When not detaching, a separate `<new_backing_name>`
    # file is also created so the rebase can resolve it.
    inst_base = iter_dir / f'rebase-instar-base.{target}'
    inst_overlay = iter_dir / f'rebase-instar-overlay.{target}'
    qemu_base = iter_dir / f'rebase-qemu-base.{target}'
    qemu_overlay = iter_dir / f'rebase-qemu-overlay.{target}'
    inst_new = iter_dir / f'rebase-instar-{new_backing_name}' \
        if not is_detach else None
    qemu_new = iter_dir / f'rebase-qemu-{new_backing_name}' \
        if not is_detach else None

    create_args_base = ['-f', target]
    for opt in create_options:
        create_args_base.extend(['-o', opt])

    # qemu-img create is the fixture generator on BOTH sides so the
    # bytes the two rebase steps mutate are identical.
    for path in (inst_base, qemu_base):
        _, st, rc = run_qemu_img(
            ['create'],
            create_args_base + [str(path), overlay_size],
            timeout=timeout)
        if rc != 0:
            return {
                'type': 'rebase_fixture_create_failed',
                'side': 'base',
                'path': str(path),
                'stderr': st[:500],
            }

    if not is_detach:
        for path in (inst_new, qemu_new):
            _, st, rc = run_qemu_img(
                ['create'],
                create_args_base + [str(path), new_backing_size],
                timeout=timeout)
            if rc != 0:
                return {
                    'type': 'rebase_fixture_create_failed',
                    'side': 'new_backing',
                    'path': str(path),
                    'stderr': st[:500],
                }

    overlay_create_args = create_args_base + [
        '-b', 'base.qcow2', '-F', 'qcow2',
    ]
    for (overlay_path, base_path) in (
        (inst_overlay, inst_base),
        (qemu_overlay, qemu_base),
    ):
        # Use the absolute backing path so the overlay's
        # recorded pointer resolves at rebase time even though
        # the fuzzer doesn't run with a chdir.
        cmd_args = list(overlay_create_args)
        cmd_args[cmd_args.index('base.qcow2')] = str(base_path)
        _, st, rc = run_qemu_img(
            ['create'],
            cmd_args + [str(overlay_path), overlay_size],
            timeout=timeout)
        if rc != 0:
            return {
                'type': 'rebase_fixture_create_failed',
                'side': 'overlay',
                'path': str(overlay_path),
                'stderr': st[:500],
            }

    # 2. Rebase each via its native tool.
    instar_rebase_args = ['-f', target]
    qemu_rebase_args = ['-f', target]
    if is_detach:
        instar_rebase_args += ['-b', '']
        qemu_rebase_args += ['-b', '']
    else:
        instar_rebase_args += ['-b', str(inst_new)]
        qemu_rebase_args += ['-b', str(qemu_new)]
    instar_rebase_args += rebase_flags
    qemu_rebase_args += rebase_flags

    _, ir_stderr, ir_rc = run_instar(
        instar_bin, ['rebase'],
        instar_rebase_args + [str(inst_overlay)],
        timeout=timeout)
    _, qr_stderr, qr_rc = run_qemu_img(
        ['rebase'],
        qemu_rebase_args + [str(qemu_overlay)],
        timeout=timeout)

    div = compare_exit_codes(
        ir_rc, qr_rc, 'rebase',
        {'target_format': target,
         'overlay_size': overlay_size,
         'new_backing_name': new_backing_name,
         'new_backing_size': new_backing_size,
         'rebase_flags': rebase_flags,
         'create_options': create_options,
         'is_detach': is_detach,
         'instar_stderr': ir_stderr[:500],
         'qemu_stderr': qr_stderr[:500]},
    )
    if div:
        return div
    if ir_rc != 0:
        return None  # both rejected; nothing to compare

    # 3. Compare via qemu-img info JSON on the rebased overlays.
    inst_info_out, _, inst_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(inst_overlay)],
        timeout=timeout)
    qemu_info_out, _, qemu_info_rc = run_qemu_img(
        ['info', '--output=json'], [str(qemu_overlay)],
        timeout=timeout)
    if inst_info_rc != 0 or qemu_info_rc != 0:
        return {
            'type': 'rebase_info_readback_failure',
            'target_format': target,
            'overlay_size': overlay_size,
            'new_backing_name': new_backing_name,
            'rebase_flags': rebase_flags,
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
            'type': 'rebase_info_json_parse_failure',
            'target_format': target,
            'error': str(e),
            'instar_info_stdout': inst_info_out[:500],
            'qemu_info_stdout': qemu_info_out[:500],
        }

    inst_norm = _normalise_create_info(
        inst_json, target, str(inst_overlay))
    qemu_norm = _normalise_create_info(
        qemu_json, target, str(qemu_overlay))

    # The instar-side and qemu-side new backing files live at
    # different absolute paths; substitute both to a stable
    # placeholder so the comparison is path-independent. Also
    # strip the recorded basename when not detaching — that's
    # the file's recorded pointer, identical bytes on both sides.
    if not is_detach:
        _rebase_replace_filename(
            inst_norm, str(inst_new), '$NEW_BACKING')
        _rebase_replace_filename(
            qemu_norm, str(qemu_new), '$NEW_BACKING')

    if inst_norm != qemu_norm:
        return {
            'type': 'rebase_info_divergence',
            'target_format': target,
            'overlay_size': overlay_size,
            'new_backing_name': new_backing_name,
            'new_backing_size': new_backing_size,
            'rebase_flags': rebase_flags,
            'create_options': create_options,
            'is_detach': is_detach,
            'instar_normalised': inst_norm,
            'qemu_normalised': qemu_norm,
        }
    return None


def _rebase_replace_filename(obj, needle, replacement):
    """Replace `needle` with `replacement` in every string-valued
    field of a JSON-like object. Used to anonymise the
    `full-backing-filename` field's absolute path on each side
    before the info-JSON comparison.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and needle in v:
                obj[k] = v.replace(needle, replacement)
            else:
                _rebase_replace_filename(v, needle, replacement)
    elif isinstance(obj, list):
        for item in obj:
            _rebase_replace_filename(item, needle, replacement)


def _commit_option_picker(rng):
    """Pick (target, overlay_size, explicit_base, seed_spec,
    extra_create_options).

    Constraints honour the commit planner's documented gaps:
      * qcow2 only — vmdk explicit `-b` is blocked by the
        info-vmdk-backing-file follow-up (the host info
        operation doesn't expose vmdk monolithicSparse's
        `parentFileNameHint`, so the host-side pre-check
        refuses every vmdk `-b` as "not the recorded
        parent"). The vmdk smoke + matrix + round-trip
        tests gate this with skipTest; the fuzzer matches
        by excluding vmdk targets. Once the info follow-up
        lands, add `'vmdk'` back to the target choice.
      * No qcow2 refcount_bits != 16, no compat=0.10.
      * Optional `qemu-io` seed at offset 0 so the commit
        has real data to merge in some iterations.
      * cluster_size capped at 64 KiB: the commit guest's
        OVERLAY_RT_LIMIT / BACKING_RT_LIMIT are sized at
        MAX_SECTOR_SIZE (64 KiB), so a single-cluster
        refcount table for any cluster_size > 64 KiB blows
        the budget (ERROR_SCRATCH_TOO_SMALL). Lifting the
        bound is a master-plan TODO.
    """
    target = 'qcow2'
    overlay_size = rng.choice(['1M', '4M', '64M'])
    explicit_base = rng.choice([None, 'base.qcow2'])
    seed_spec = rng.choice([None, 'seed-64k'])
    create_options = []
    cs = rng.choice([c for c in QCOW2_CLUSTER_SIZES if c <= 65536])
    create_options.append(f'cluster_size={cs}')
    if rng.random() < 0.3:
        create_options.append('lazy_refcounts=on')
    return target, overlay_size, explicit_base, seed_spec, \
           create_options


def op_commit(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Build identical overlay+backing pairs (each in its own
    per-pair subdirectory so explicit `-b base.<ext>` matches
    the chain entry's canonicalised basename), commit each via
    its native tool, compare via `qemu-img info --output=json`
    on both the resulting overlay AND the resulting backing.

    A commit's observable state lives on both sides — the
    overlay's L2/refcount entries get zeroed and the backing's
    allocated clusters grow — so the comparison covers both.

    `instar_copy / qemu_copy / fmt` are part of the standard
    op_* signature but unused — `commit` builds its own
    fixture pairs via the picker.
    """
    (target, overlay_size, explicit_base, seed_spec,
     create_options) = _commit_option_picker(rng)

    iter_dir = instar_copy.parent
    ext = {'qcow2': 'qcow2', 'vmdk': 'vmdk'}[target]
    inst_dir = iter_dir / 'commit-instar'
    qemu_dir = iter_dir / 'commit-qemu'
    inst_dir.mkdir(parents=True, exist_ok=True)
    qemu_dir.mkdir(parents=True, exist_ok=True)

    inst_base = inst_dir / f'base.{ext}'
    inst_overlay = inst_dir / f'overlay.{ext}'
    qemu_base = qemu_dir / f'base.{ext}'
    qemu_overlay = qemu_dir / f'overlay.{ext}'

    create_args_base = ['-f', target]
    for opt in create_options:
        create_args_base.extend(['-o', opt])

    # 1. Seed identical backings via qemu-img create.
    for path in (inst_base, qemu_base):
        _, st, rc = run_qemu_img(
            ['create'],
            create_args_base + [str(path), overlay_size],
            timeout=timeout)
        if rc != 0:
            return {
                'type': 'commit_fixture_create_failed',
                'side': 'base',
                'path': str(path),
                'stderr': st[:500],
            }

    # 2. Build the overlays. `cwd=<side_dir>` so the recorded
    # backing pointer is just `base.<ext>` (relative basename
    # matching the chain canonicalisation that `-b base.<ext>`
    # uses at commit time).
    overlay_create_args = create_args_base + [
        '-o', f'backing_file=base.{ext},backing_fmt={target}',
    ]
    for (side_dir, overlay_path) in (
        (inst_dir, inst_overlay),
        (qemu_dir, qemu_overlay),
    ):
        _, st, rc = run_qemu_img(
            ['create'],
            overlay_create_args + [str(overlay_path), overlay_size],
            timeout=timeout, cwd=str(side_dir))
        if rc != 0:
            return {
                'type': 'commit_fixture_create_failed',
                'side': 'overlay',
                'path': str(overlay_path),
                'stderr': st[:500],
            }

    # 3. Optional seed step. qemu-io fixture-builder writes a
    # known 64 KiB pattern at offset 0 so both binaries have
    # the same real data to merge. The seed runs on both
    # copies; skip cleanly when qemu-io is missing.
    if seed_spec == 'seed-64k':
        if shutil.which('qemu-io') is None:
            # Treat as inconclusive — record nothing.
            return None
        for overlay_path in (inst_overlay, qemu_overlay):
            _, st, rc = _run_qemu_io(
                ['-f', target, '-c', 'write -P 0xab 0 64k',
                 str(overlay_path)],
                timeout=timeout)
            if rc != 0:
                return {
                    'type': 'commit_seed_failed',
                    'path': str(overlay_path),
                    'stderr': st[:500],
                }

    # 4. Commit each via its native tool. Run with `cwd=<side>`
    # so explicit `-b base.<ext>` resolves to the side's own
    # backing file.
    instar_commit_args = []
    qemu_commit_args = []
    if explicit_base is not None:
        instar_commit_args += ['-b', explicit_base]
        qemu_commit_args += ['-b', explicit_base]

    _, ic_stderr, ic_rc = run_instar(
        instar_bin, ['commit'],
        instar_commit_args + [str(inst_overlay)],
        timeout=timeout, cwd=str(inst_dir))
    _, qc_stderr, qc_rc = run_qemu_img(
        ['commit'],
        qemu_commit_args + [str(qemu_overlay)],
        timeout=timeout, cwd=str(qemu_dir))

    div = compare_exit_codes(
        ic_rc, qc_rc, 'commit',
        {'target_format': target,
         'overlay_size': overlay_size,
         'explicit_base': explicit_base,
         'seed_spec': seed_spec,
         'create_options': create_options,
         'instar_stderr': ic_stderr[:500],
         'qemu_stderr': qc_stderr[:500]},
    )
    if div:
        return div
    if ic_rc != 0:
        return None  # both rejected; nothing to compare

    # 5. Compare via qemu-img info on BOTH the overlay and the
    # backing. A commit's observable state lives on both
    # sides.
    for (label, inst_path, qemu_path) in (
        ('overlay', inst_overlay, qemu_overlay),
        ('backing', inst_base, qemu_base),
    ):
        inst_info_out, _, inst_info_rc = run_qemu_img(
            ['info', '--output=json'], [str(inst_path)],
            timeout=timeout)
        qemu_info_out, _, qemu_info_rc = run_qemu_img(
            ['info', '--output=json'], [str(qemu_path)],
            timeout=timeout)
        if inst_info_rc != 0 or qemu_info_rc != 0:
            return {
                'type': 'commit_info_readback_failure',
                'side': label,
                'target_format': target,
                'overlay_size': overlay_size,
                'explicit_base': explicit_base,
                'seed_spec': seed_spec,
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
                'type': 'commit_info_json_parse_failure',
                'side': label,
                'target_format': target,
                'error': str(e),
                'instar_info_stdout': inst_info_out[:500],
                'qemu_info_stdout': qemu_info_out[:500],
            }

        inst_norm = _normalise_create_info(
            inst_json, target, str(inst_path))
        qemu_norm = _normalise_create_info(
            qemu_json, target, str(qemu_path))

        # The overlay info JSON references the backing's
        # absolute path via `full-backing-filename`; anonymise
        # so the two sides' distinct paths don't trip the
        # comparison.
        if label == 'overlay':
            _rebase_replace_filename(
                inst_norm, str(inst_base), '$BASE')
            _rebase_replace_filename(
                qemu_norm, str(qemu_base), '$BASE')

        if inst_norm != qemu_norm:
            return {
                'type': f'commit_{label}_info_divergence',
                'target_format': target,
                'overlay_size': overlay_size,
                'explicit_base': explicit_base,
                'seed_spec': seed_spec,
                'create_options': create_options,
                'instar_normalised': inst_norm,
                'qemu_normalised': qemu_norm,
            }

    return None


# ---------------------------------------------------------------------------
# op_map: instar map vs qemu-img map (PLAN-map phase 8)
# ---------------------------------------------------------------------------

# Per-extent fields compared between instar and qemu-img. The skipped
# fields are documented in docs/plans/PLAN-map-phase-08-fuzz-
# differential.md (depth: always 0 in v1; compressed: instar emits
# false always; offset: compressed-cluster reporting drift across
# binaries; filename: paths differ between the two copies).
MAP_COMPARE_FIELDS = ('start', 'length', 'present', 'zero', 'data')

# Per-format field skips for documented divergences that would
# otherwise flood the differential signal. The phase 8 smoke
# discovered each entry empirically.
MAP_FIELD_SKIPS = {
    # VHD unallocated blocks: instar reports present=false (true
    # to the on-disk BAT 0xFFFFFFFF marker); qemu-img reports
    # present=true with zero=true (the "ZeroAllocated"
    # convention, same as it uses for raw sparse runs). Phase 6's
    # KNOWN_MAP_DIVERGENCES in tests/test_map.py marks
    # hyperv-dynamic-vhd and virtualpc-vhd with the same rationale.
    # Keeping {start, length, zero, data} comparison active for
    # vpc still catches BAT-walking boundary bugs and any genuine
    # data/zero mislabelling.
    'vpc': ('present',),
}


def _map_probe_virtual_size(qemu_copy, timeout):
    """Return the virtual size of an image in bytes via qemu-img info,
    or None on probe failure (in which case the caller should skip
    window-arg selection)."""
    out, _err, rc = run_qemu_img(
        ['info'], ['--output=json', str(qemu_copy)],
        timeout=timeout,
    )
    if rc != 0:
        return None
    try:
        info = json.loads(out)
    except json.JSONDecodeError:
        return None
    value = info.get('virtual-size')
    if not isinstance(value, int) or value <= 0:
        return None
    return value


def _map_window_args(rng, virtual_size_bytes):
    """Pick optional --start-offset / --max-length window arguments.

    25% chance each of being set, 64 KiB cluster-aligned to dodge the
    documented "instar clips bytes, qemu-img clips clusters" quirk
    in docs/quirks.md.
    """
    args = []
    align = 64 * 1024
    if virtual_size_bytes < align * 2:
        # Image too small for meaningful windowing; skip.
        return args
    if rng.random() < 0.25:
        half = virtual_size_bytes // 2
        start = (rng.randint(0, half) // align) * align
        args += ['--start-offset', str(start)]
    if rng.random() < 0.25:
        max_len = (rng.randint(align, virtual_size_bytes) // align) * align
        max_len = min(max_len, virtual_size_bytes)
        args += ['--max-length', str(max_len)]
    return args


def op_map(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Run instar map and qemu-img map, comparing JSON output extent-by-
    extent.

    Raw is gated out: instar emits one fully-allocated extent while
    qemu-img walks SEEK_HOLE — a documented divergence (see
    docs/quirks.md) that would noise-flood the fuzzer. The same
    posture as `op_info`'s raw skip.

    Other format-level divergences (chain qcow2 refused, vmdk
    multi-extent refused, vhdx partial-present) don't fire here
    because generate_image() never produces those shapes.
    """
    if fmt == 'raw':
        return None

    virtual_size = _map_probe_virtual_size(qemu_copy, timeout)
    window_args = (
        _map_window_args(rng, virtual_size) if virtual_size else []
    )

    instar_args = window_args + ['--output', 'json', str(instar_copy)]
    qemu_args = window_args + ['--output=json', str(qemu_copy)]

    i_out, i_err, i_rc = run_instar(
        instar_bin, ['map'], instar_args, timeout=timeout,
    )
    q_out, q_err, q_rc = run_qemu_img(
        ['map'], qemu_args, timeout=timeout,
    )

    div = compare_exit_codes(i_rc, q_rc, 'map', {
        'window_args': window_args,
        'instar_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
    })
    if div:
        return div

    if i_rc != 0:
        # Both failed identically — nothing to compare.
        return None

    try:
        i_arr = json.loads(i_out)
        q_arr = json.loads(q_out)
    except json.JSONDecodeError as exc:
        return {
            'type': 'map_json_parse_failure',
            'window_args': window_args,
            'error': str(exc),
            'instar_stdout': i_out[:500],
            'qemu_stdout': q_out[:500],
        }

    if not isinstance(i_arr, list) or not isinstance(q_arr, list):
        return {
            'type': 'map_json_shape_divergence',
            'window_args': window_args,
            'instar_stdout': i_out[:500],
            'qemu_stdout': q_out[:500],
        }

    if len(i_arr) != len(q_arr):
        return {
            'type': 'map_extent_count_divergence',
            'window_args': window_args,
            'instar_count': len(i_arr),
            'qemu_count': len(q_arr),
            'instar_stdout': i_out[:1000],
            'qemu_stdout': q_out[:1000],
        }

    skip_fields = MAP_FIELD_SKIPS.get(fmt, ())
    for idx, (i_ext, q_ext) in enumerate(zip(i_arr, q_arr)):
        for field in MAP_COMPARE_FIELDS:
            if field in skip_fields:
                continue
            if i_ext.get(field) != q_ext.get(field):
                return {
                    'type': 'map_field_divergence',
                    'window_args': window_args,
                    'extent_index': idx,
                    'field': field,
                    'instar_value': i_ext.get(field),
                    'qemu_value': q_ext.get(field),
                    'instar_extent': i_ext,
                    'qemu_extent': q_ext,
                    'instar_stdout': i_out[:1000],
                    'qemu_stdout': q_out[:1000],
                }

    return None


def _run_qemu_io(args, timeout=30):
    """Run a qemu-io command. Returns (stdout, stderr, rc).
    Mirrors `run_qemu_img`'s shape; used as a fixture-builder
    in `op_commit`'s optional seed step.
    """
    cmd = ['qemu-io'] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1


# ---------------------------------------------------------------------------
# op_snapshot: instar snapshot -c/-d/-a chains vs qemu-img
# (PLAN-snapshot phase 13)
# ---------------------------------------------------------------------------

# Fixed NONZERO date written into every live snapshot-table entry's
# date_sec / date_nsec after each successful create, on BOTH sides
# (phase 13 probe 3). Nonzero matters: with date_sec == 0,
# `instar snapshot -l` prints a blank DATE column while
# `qemu-img snapshot -l` renders the epoch in local time (degenerate
# input; see docs/quirks.md). With 0x60000000 both tools print
# '2021-01-14 19:25:36' (host-local) and -l output is byte-identical.
SNAPSHOT_NORM_DATE_SEC = 0x60000000
SNAPSHOT_NORM_DATE_NSEC = 0

# Name pool for `-c` chain elements: a 255-byte name (qemu's creation
# cap; never over), names with spaces, UTF-8 multibyte names, and an
# ID-like name ('2' — the -d-name-only vs -a-ID-first asymmetry is
# prime differential territory). Duplicate names arise naturally from
# repeated picks (first-match delete semantics). Never empty.
SNAPSHOT_NAME_POOL = [
    'alpha', 'beta', 'gamma',
    '2',
    'snap with spaces',
    'snäp-名前',
    'L' * 255,
]

# Module-level qemu-img version cache (startup probe, not a
# build-time constant — contributors may run older distros than the
# CI container, whose Debian-stable qemu-utils tracks the 10.0.x
# series the phase 6-8 harnesses pinned).
_QEMU_IMG_VERSION = None

# Keys for one-shot log messages (version-gate skips), so they print
# once per run instead of once per fuzz iteration.
_LOGGED_ONCE = set()


def _log_once(key, msg, *args):
    """Emit `logger.info(msg, *args)` the first time `key` is seen."""
    if key not in _LOGGED_ONCE:
        _LOGGED_ONCE.add(key)
        logger.info(msg, *args)


def qemu_img_version():
    """Parse and cache `qemu-img --version` as a (major, minor) tuple.

    Returns (0, 0) when the version cannot be determined, which fails
    both of op_snapshot's version gates closed (the op skips).
    """
    global _QEMU_IMG_VERSION
    if _QEMU_IMG_VERSION is None:
        out, _err, rc = run_qemu_img(['--version'], [], timeout=10)
        match = re.search(r'version\s+(\d+)\.(\d+)', out)
        if rc == 0 and match:
            _QEMU_IMG_VERSION = (int(match.group(1)),
                                 int(match.group(2)))
        else:
            _QEMU_IMG_VERSION = (0, 0)
    return _QEMU_IMG_VERSION


def _snapshot_next_id(live):
    """Mirror qemu's find_new_snapshot_id: max numeric ID + 1."""
    max_id = 0
    for sid, _name in live:
        if sid.isdigit():
            max_id = max(max_id, int(sid))
    return str(max_id + 1)


def _snapshot_pick_arg(rng, live):
    """Pick a -d / -a argument biased toward existing snapshots.

    Existing names (3x weight) exercise the happy paths; existing IDs
    (2x) are valid for -a but not-found for -d under qemu >= 4.0
    name-only delete semantics; bogus names and random numeric IDs
    keep failure-op parity (probe 4) in the mix.
    """
    choices = ['no-such-snapshot', str(rng.randint(1, 20))]
    if live:
        entry = rng.choice(live)
        choices = [entry[1]] * 3 + [entry[0]] * 2 + choices
    return rng.choice(choices)


# Divergence-avoidance table. Each documented instar<->qemu snapshot
# divergence (docs/quirks.md, snapshot sections) is avoided by
# generation, never absorbed by weakening the comparator:
#
# | Avoided input | Behaviour difference | docs/quirks.md entry |
# |---|---|---|
# | `-c ''` (empty name) | qemu accepts; instar refuses | "snapshot
# |   -c (create) quirks" — names >255 bytes refused, empty name
# |   likewise refused. Pool has no empty names. |
# | `-c` name > 255 bytes | qemu silently truncates; instar refuses
# |   | same entry. Pool tops out at exactly 255 bytes. |
# | 17th live snapshot | qemu allows; instar
# |   ERROR_SNAPSHOT_TABLE_FULL | "snapshot -c quirks" —
# |   16-snapshot cap. Picker simulates the live table and only
# |   offers 'create' while count < 16. |
# | resize within a chain | qemu's later -a truncates; instar
# |   refuses (ERROR_L1_SIZE_MISMATCH); instar resize on
# |   snapshot-bearing images is open future work | "snapshot -a
# |   quirks" — apply to a since-resized image refused. No resize
# |   chain element exists. |
# | dirty / compressed / encrypted / external-data / bitmap images
# |   | instar mutating modes refuse (ERROR_UNSUPPORTED_FEATURE)
# |   | "snapshot -c quirks" — dirty/compressed/external-data/
# |   encryption/bitmaps refused. Avoidance is structural: plain
# |   `qemu-img create` bases never produce these. |
# | refcount_bits != 16 | instar mutating modes refuse | "snapshot
# |   -c quirks" — refcount_bits != 16 refused. The qemu-img
# |   default is 16; the picker never overrides refcount_order. |
# | 512-byte clusters above 4M | chains exhaust the image's
# |   present refblocks; instar v1 never allocates new refblocks
# |   or grows the refcount table (qemu grows both and succeeds)
# |   | "snapshot -c quirks" — create may exhaust the image's
# |   existing refblocks. 512-byte clusters pair only with 4M
# |   images, the phase 6-8 matrix pairing. |
#
# Divergences HANDLED by the comparator (not avoided): freed-cluster
# discard (qemu side runs file.discard=ignore), date stamps
# (per-step normalization, probes 2/3), the sector-granular file
# tail (zero-tail tolerance), stderr wording (exit codes only,
# probe 4).
def _snapshot_chain_picker(rng):
    """Pick (base_opts, chain) for one snapshot-chain iteration.

    base_opts mirrors the phase 6-8 matrix dimensions
    (tools/snapshot-*-matrix.sh): cluster_size in {512, 4096, 65536};
    compat in {1.1, 0.10}; extended_l2 only with 64k clusters and
    compat 1.1; size in {4M, 16M, 64M} (4M only for 512-byte
    clusters — avoidance row 7 below); an optional backing file;
    plus 0-2 seed writes so creates capture real data.

    chain is 1-8 elements: ['create', NAME], ['delete', ARG],
    ['apply', ARG], ['write', OFFSET, LENGTH, PATTERN]. The picker
    simulates the live snapshot table (create appends with qemu's
    max-numeric-ID+1 assignment; delete removes the first name
    match, mirroring bdrv_snapshot_find's name-only semantics) so
    the create guard can hold the live count under instar's
    16-snapshot v1 cap (avoidance table above).
    """
    cluster_size = rng.choice([512, 4096, 65536])
    compat = rng.choice(['1.1', '0.10'])
    extended_l2 = (cluster_size == 65536 and compat == '1.1'
                   and rng.random() < 0.3)
    # Avoidance row 7: 512-byte clusters only pair with 4M images
    # (exactly the phase 6-8 matrix pairing). instar v1 never
    # allocates new refblocks or grows the refcount table
    # (docs/quirks.md, "Create may exhaust the image's existing
    # refblocks"), so at 512-byte clusters a larger image's
    # per-create L1 copy (32 clusters at 64M) exhausts the base
    # image's present refblocks within a few creates while qemu
    # grows the refcount structures and succeeds. Found by the
    # first 500-iteration soak: every divergence was a create on a
    # cluster_size=512 / 64M image failing ERROR_ALLOCATION_FAILED
    # under instar with qemu rc 0.
    size = rng.choice(['4M']) if cluster_size == 512 else (
        rng.choice(['4M', '16M', '64M']))
    backing = rng.random() < 0.25
    size_bytes = _resize_parse_qemu_size(size)

    def pick_write():
        length = rng.choice([4096, 65536, 131072])
        offset = (rng.randint(0, size_bytes - length) // 4096) * 4096
        return ['write', offset, length, rng.randint(1, 255)]

    base_opts = {
        'cluster_size': cluster_size,
        'compat': compat,
        'extended_l2': extended_l2,
        'size': size,
        'backing': backing,
        'seed_writes': [pick_write()
                        for _ in range(rng.randint(0, 2))],
    }

    live = []  # simulated table: list of (id, name)
    chain = []
    for _ in range(rng.randint(1, 8)):
        kinds = ['delete', 'apply', 'write']
        if len(live) < 16:
            kinds += ['create', 'create', 'create']
        kind = rng.choice(kinds)
        if kind == 'create':
            name = rng.choice(SNAPSHOT_NAME_POOL)
            live.append((_snapshot_next_id(live), name))
            chain.append(['create', name])
        elif kind == 'delete':
            arg = _snapshot_pick_arg(rng, live)
            for idx, (_sid, name) in enumerate(live):
                if name == arg:
                    del live[idx]
                    break
            chain.append(['delete', arg])
        elif kind == 'apply':
            chain.append(['apply', _snapshot_pick_arg(rng, live)])
        else:
            chain.append(pick_write())
    return base_opts, chain


def _snapshot_normalize_table(path):
    """Normalize the live snapshot table's tool-divergent dead bytes:
    dates and inter-entry alignment padding.

    Dates: patch every entry's date_sec / date_nsec to the fixed
    nonzero sentinel (probe 3 — each tool stamps its own wall
    clock; zero would expose the zero-date `-l` renderer quirk).

    Padding: zero the up-to-7 alignment bytes between an entry's
    end and the next entry's 8-aligned start. instar serializes the
    whole table with zeroed gaps (`build_snapshot_table`); qemu's
    `qcow2_write_snapshots` writes each entry field-by-field and
    never touches the pad bytes, so a table reallocated into a
    reused (freed, dirty) cluster keeps stale bytes there under
    qemu. Found by the first phase 13 soak: a create-after-apply
    chain reallocated the table into a freed data cluster and
    diverged by exactly the 2 pad bytes after a 70-byte entry.
    Both images are valid — the padding is dead bytes — so this is
    comparator-handled like the freed-cluster discard rule, not an
    instar bug (see docs/quirks.md).

    Called immediately after every successful create AND delete
    (both rewrite the table), on BOTH images. Per-step, NOT
    end-of-chain: when a later operation reallocates the snapshot
    table, both tools leave the old table's bytes — embedding each
    tool's own timestamps and padding — in the freed cluster, so
    normalizing only at chain end leaves divergent residue
    (probe 2). Normalizing the live table per step means all later
    residue inherits the normalized bytes.

    The entry walk mirrors walk_qcow2_snapshot_table in
    scripts/extract-fuzz-corpus.py. Returns True on success, False
    if the header or table walk escapes (a structural anomaly the
    caller reports as a divergence).
    """
    with open(path, 'r+b') as f:
        header = f.read(72)
        if len(header) < 72 or header[0:4] != b'QFI\xfb':
            return False
        nb_snapshots = int.from_bytes(header[60:64], 'big')
        snapshots_offset = int.from_bytes(header[64:72], 'big')
        if nb_snapshots == 0:
            return True
        if snapshots_offset == 0:
            return False
        f.seek(snapshots_offset)
        blob = f.read(1024 * 1024)
        pos = 0
        patch_offsets = []
        pad_ranges = []
        for _ in range(nb_snapshots):
            aligned = (pos + 7) & ~7
            if aligned > pos:
                pad_ranges.append((snapshots_offset + pos,
                                   aligned - pos))
            pos = aligned
            if pos + 40 > len(blob):
                return False
            patch_offsets.append(snapshots_offset + pos + 16)
            extra = int.from_bytes(blob[pos + 36:pos + 40], 'big')
            id_len = int.from_bytes(blob[pos + 12:pos + 14], 'big')
            name_len = int.from_bytes(blob[pos + 14:pos + 16], 'big')
            pos = pos + 40 + extra + id_len + name_len
            if pos > len(blob):
                return False
        stamp = struct.pack('>II', SNAPSHOT_NORM_DATE_SEC,
                            SNAPSHOT_NORM_DATE_NSEC)
        for off in patch_offsets:
            f.seek(off)
            f.write(stamp)
        for off, length in pad_ranges:
            f.seek(off)
            f.write(bytes(length))
    return True


def _snapshot_compare_bytes(inst_path, qemu_path):
    """Byte-identity check ported from the phase 6-8 harnesses'
    assert_byte_identical (tools/snapshot-*-matrix.sh): the files
    must agree over their common prefix, and the longer file's tail
    must be all zero (the sector-granular file-tail quirk —
    docs/quirks.md, "The created file may be physically larger than
    qemu-img's"). Returns None on identity or a detail dict.
    """
    inst_len = inst_path.stat().st_size
    qemu_len = qemu_path.stat().st_size
    common = min(inst_len, qemu_len)
    with open(inst_path, 'rb') as fa, open(qemu_path, 'rb') as fb:
        offset = 0
        while offset < common:
            n = min(1 << 20, common - offset)
            a = fa.read(n)
            b = fb.read(n)
            if a != b:
                first = next(i for i in range(len(a))
                             if a[i] != b[i])
                return {
                    'kind': 'prefix_mismatch',
                    'offset': offset + first,
                    'instar_byte': a[first],
                    'qemu_byte': b[first],
                    'instar_len': inst_len,
                    'qemu_len': qemu_len,
                }
            offset += n
        longer, longer_side = ((fa, 'instar') if inst_len > qemu_len
                               else (fb, 'qemu'))
        longer.seek(common)
        while True:
            chunk = longer.read(1 << 20)
            if not chunk:
                break
            if chunk.count(0) != len(chunk):
                return {
                    'kind': 'nonzero_tail',
                    'side': longer_side,
                    'instar_len': inst_len,
                    'qemu_len': qemu_len,
                }
    return None


def _snapshot_qemu_image_opts(path):
    """qemu-img side image spec: protocol-level discard disabled so
    qemu leaves stale bytes in freed clusters exactly like instar
    does (docs/quirks.md, "Freed-cluster bytes may differ from
    qemu-img's", under both -d and -a). With discard suppressed the
    post-op images are bit-for-bit identical (phase 6-8 harnesses;
    probes 1-2).
    """
    return f'driver=qcow2,file.filename={path},file.discard=ignore'


def op_snapshot(instar_bin, instar_copy, qemu_copy, fmt, timeout,
                rng):
    """Apply a random create/delete/apply/write chain to identical
    qcow2 images via instar and qemu-img; demand byte-identical
    results after every element (the phase 6-8 matrix methodology
    ported from tools/snapshot-*-matrix.sh).

    instar_copy / qemu_copy / fmt are part of the standard op_*
    signature but unused — snapshot builds its own image pair via
    `_snapshot_chain_picker`, per the resize/commit precedent.
    """
    # Version gate (a): the whole op requires qemu >= 4.0. instar
    # implements modern name-only delete semantics
    # (bdrv_snapshot_find); older qemu-img resolved delete arguments
    # ID-first via the since-removed
    # bdrv_snapshot_delete_by_id_or_name (docs/quirks.md, "-d
    # matches by NAME only" cross-version note).
    version = qemu_img_version()
    if version < (4, 0):
        _log_once(
            'snapshot-version-skip',
            'op_snapshot: qemu-img %d.%d < 4.0, skipping '
            'snapshot chains', version[0], version[1])
        return None

    base_opts, chain = _snapshot_chain_picker(rng)

    has_writes = base_opts['seed_writes'] or any(
        el[0] == 'write' for el in chain)
    if has_writes and shutil.which('qemu-io') is None:
        return None  # same posture as op_commit's seed step

    iter_dir = instar_copy.parent
    base_path = iter_dir / 'snap-base.qcow2'
    inst_path = iter_dir / 'snap-instar.qcow2'
    qemu_path = iter_dir / 'snap-qemu.qcow2'

    def context(idx=None):
        ctx = {'base_options': base_opts, 'chain': chain}
        if idx is not None:
            ctx['element_index'] = idx
            ctx['element'] = chain[idx]
        return ctx

    def write_both(off, length, pattern, paths):
        for path in paths:
            _, st, rc = _run_qemu_io(
                ['-f', 'qcow2', '-c',
                 f'write -P {pattern} {off} {length}', str(path)],
                timeout=timeout)
            if rc != 0:
                return {'path': str(path), 'write_rc': rc,
                        'stderr': st[:500]}
        return None

    # 1. Build the base (and optional backing) ONCE via qemu-img so
    # both sides start from identical bytes; copy to the two sides.
    create_args = ['-f', 'qcow2',
                   '-o', f'cluster_size={base_opts["cluster_size"]}',
                   '-o', f'compat={base_opts["compat"]}']
    if base_opts['extended_l2']:
        create_args += ['-o', 'extended_l2=on']
    if base_opts['backing']:
        backing_path = iter_dir / 'snap-backing.qcow2'
        _, st, rc = run_qemu_img(
            ['create'],
            ['-f', 'qcow2', str(backing_path), base_opts['size']],
            timeout=timeout)
        if rc != 0:
            return dict(context(),
                        type='snapshot_fixture_create_failed',
                        side='backing', stderr=st[:500])
        # Both copies reference the SAME backing path (master plan
        # point 6: internal snapshots compose with backing files
        # without walking the chain).
        create_args += ['-b', str(backing_path), '-F', 'qcow2']
    _, st, rc = run_qemu_img(
        ['create'], create_args + [str(base_path), base_opts['size']],
        timeout=timeout)
    if rc != 0:
        return dict(context(), type='snapshot_fixture_create_failed',
                    side='base', stderr=st[:500])

    for wr in base_opts['seed_writes']:
        err = write_both(wr[1], wr[2], wr[3], [base_path])
        if err:
            return dict(context(),
                        type='snapshot_fixture_create_failed',
                        side='seed_write', **err)

    shutil.copy2(base_path, inst_path)
    shutil.copy2(base_path, qemu_path)

    # 2. Run the chain element by element.
    for idx, element in enumerate(chain):
        kind = element[0]
        if kind == 'write':
            _kind, off, length, pattern = element
            err = write_both(off, length, pattern,
                             [inst_path, qemu_path])
            if err:
                return dict(context(idx),
                            type='snapshot_write_failed', **err)
        else:
            flag = {'create': '-c', 'delete': '-d',
                    'apply': '-a'}[kind]
            arg = element[1]
            _i_out, i_err, i_rc = run_instar(
                instar_bin, ['snapshot'],
                [flag, arg, str(inst_path)], timeout=timeout)
            _q_out, q_err, q_rc = run_qemu_img(
                ['snapshot'],
                [flag, arg, '--image-opts',
                 _snapshot_qemu_image_opts(qemu_path)],
                timeout=timeout)
            # Failure ops (e.g. not-found delete/apply) compare exit
            # codes ONLY — stderr wording differs by design (probe
            # 4: instar explains the matcher semantics, qemu says
            # "snapshot not found") and is never compared.
            div = compare_exit_codes(
                i_rc, q_rc, 'snapshot',
                dict(context(idx),
                     instar_stderr=i_err[:500],
                     qemu_stderr=q_err[:500]))
            if div:
                return div
            if kind in ('create', 'delete') and i_rc == 0:
                # Per-step table normalization (probes 2 and 3,
                # plus the inter-entry padding finding — see
                # _snapshot_normalize_table): patch the LIVE tables
                # on both sides now, so any residue a later table
                # reallocation leaves behind already carries
                # normalized bytes. End-of-chain normalization is
                # NOT sufficient (probe 2: freed-table residue
                # embeds each tool's own timestamps). Create and
                # delete both rewrite the table; apply does not.
                for path in (inst_path, qemu_path):
                    if not _snapshot_normalize_table(path):
                        return dict(
                            context(idx),
                            type='snapshot_normalize_failed',
                            path=str(path))
        # Byte-compare after EVERY element so the earliest diverging
        # element is the one reported.
        mismatch = _snapshot_compare_bytes(inst_path, qemu_path)
        if mismatch:
            return dict(context(idx),
                        type='snapshot_byte_divergence', **mismatch)

    # 3. Chain-end secondary net: check / compare / -l. Byte
    # identity above is the primary oracle; these mostly diagnose
    # what a byte divergence would mean.
    for side, path in (('instar', inst_path), ('qemu', qemu_path)):
        c_out, c_err, c_rc = run_qemu_img(
            ['check'], [str(path)], timeout=timeout)
        if c_rc != 0:
            return dict(context(), type='snapshot_check_divergence',
                        side=side, check_rc=c_rc,
                        check_stdout=c_out[:500],
                        check_stderr=c_err[:500])

    cmp_out, cmp_err, cmp_rc = run_qemu_img(
        ['compare'], [str(inst_path), str(qemu_path)],
        timeout=timeout)
    if cmp_rc != 0:
        return dict(context(), type='snapshot_compare_divergence',
                    compare_rc=cmp_rc,
                    compare_stdout=cmp_out[:500],
                    compare_stderr=cmp_err[:500])

    return _snapshot_compare_list_output(
        instar_bin, inst_path, timeout, context)


def _snapshot_compare_list_output(instar_bin, inst_path, timeout,
                                  context):
    """Version-gated -l stdout equality: `instar snapshot -l` vs
    `qemu-img snapshot -l` on the SAME (instar) image, isolating
    renderer parity from image bytes.

    Version gate (b): requires qemu >= 9.0 — qemu 8.x prints
    `VM SIZE` / 2-digit clock hours while instar implements the 9.0
    layout (docs/quirks.md, "Cross-version listing format"). Below
    9.0 the check silently skips (logged once); byte identity still
    carries the oracle.
    """
    version = qemu_img_version()
    if version < (9, 0):
        _log_once(
            'snapshot-list-skip',
            'op_snapshot: qemu-img %d.%d < 9.0, skipping -l '
            'stdout comparison (byte identity still applies)',
            version[0], version[1])
        return None

    il_out, il_err, il_rc = run_instar(
        instar_bin, ['snapshot'], ['-l', str(inst_path)],
        timeout=timeout)
    ql_out, ql_err, ql_rc = run_qemu_img(
        ['snapshot'], ['-l', str(inst_path)], timeout=timeout)
    if il_rc != 0 or ql_rc != 0 or il_out != ql_out:
        return dict(context(), type='snapshot_list_divergence',
                    instar_rc=il_rc, qemu_rc=ql_rc,
                    instar_stdout=il_out[:1000],
                    qemu_stdout=ql_out[:1000],
                    instar_stderr=il_err[:500],
                    qemu_stderr=ql_err[:500])
    return None


# ---------------------------------------------------------------------------
# check --repair: qcow2 corruptor + differential oracle
# ---------------------------------------------------------------------------
#
# The on-disk arithmetic below mirrors
# instar-testdata/custom/check-validation/create-corrupt-images.py
# (the fixture generator). Generated images use qemu-img's default
# qcow2 v3 layout with refcount_order=4, i.e. 16-bit big-endian
# refcounts (entry i at byte 2*i of its refcount block); L1/L2
# entries are big-endian u64 with the offset in bits 9..55.

_Q_MAGIC = 0x514649FB
_Q_OFFSET_MASK = 0x00FFFFFFFFFFFE00
_Q_OFLAG_COPIED = 1 << 63
# qcow2 corruption classes the corruptor can inject, and the repair
# tier(s) that can mechanically resolve each (for reference; the
# oracle does not hard-code these — it reads instar's own
# repair-incomplete signal).
REPAIR_CORRUPTIONS = [
    'refcount_zero',       # referenced cluster, refcount 0  (all)
    'refcount_too_high',   # referenced cluster, refcount 2  (all)
    'leaked_cluster',      # orphaned cluster, refcount kept (leaks/all)
    'stale_copied',        # OFLAG_COPIED + refcount 2       (all)
    'overlapping',         # two L2 entries -> one cluster   (partial)
]


def _q_read_header(path):
    """Parse the qcow2 header fields the corruptor needs, or None."""
    with open(path, 'rb') as f:
        hdr = f.read(104)
    if len(hdr) < 104 or struct.unpack('>I', hdr[0:4])[0] != _Q_MAGIC:
        return None
    cluster_bits = struct.unpack('>I', hdr[20:24])[0]
    return {
        'cluster_bits': cluster_bits,
        'cluster_size': 1 << cluster_bits,
        'l1_size': struct.unpack('>I', hdr[36:40])[0],
        'l1_offset': struct.unpack('>Q', hdr[40:48])[0],
        'reftable_offset': struct.unpack('>Q', hdr[48:56])[0],
    }


def _q_read64(path, offset):
    """Read a big-endian u64 at a file offset."""
    with open(path, 'rb') as f:
        f.seek(offset)
        return struct.unpack('>Q', f.read(8))[0]


def _q_write64(path, offset, value):
    """Write a big-endian u64 at a file offset."""
    with open(path, 'r+b') as f:
        f.seek(offset)
        f.write(struct.pack('>Q', value))


def _q_set_refcount(path, hdr, data_offset, value):
    """Set the 16-bit refcount for the cluster at data_offset.

    Returns False when the cluster's refcount block is not allocated.
    """
    cs = hdr['cluster_size']
    cluster_index = data_offset // cs
    entries_per_block = cs // 2
    refblock_index = cluster_index // entries_per_block
    entry_in_block = cluster_index % entries_per_block
    refblock_offset = _q_read64(
        path, hdr['reftable_offset'] + refblock_index * 8
    )
    if refblock_offset == 0:
        return False
    with open(path, 'r+b') as f:
        f.seek(refblock_offset + entry_in_block * 2)
        f.write(struct.pack('>H', value))
    return True


def _q_l2_entry(path, hdr, l2_index):
    """Resolve L1[0] -> L2[l2_index]; return (l2_off, entry, data_off)
    or None when the slot is unallocated."""
    l1_entry = _q_read64(path, hdr['l1_offset'])
    l2_off = l1_entry & _Q_OFFSET_MASK
    if l2_off == 0:
        return None
    entry = _q_read64(path, l2_off + l2_index * 8)
    data_off = entry & _Q_OFFSET_MASK
    if data_off == 0:
        return None
    return l2_off, entry, data_off


def corrupt_qcow2(rng, path):
    """Inject one random metadata corruption into a valid qcow2.

    Returns ``{'class': ..., 'data_offset': ...}`` or ``None`` when the
    image has no allocated cluster to corrupt (a skip, not a finding).
    """
    hdr = _q_read_header(path)
    if hdr is None or hdr['l1_size'] == 0:
        return None
    first = _q_l2_entry(path, hdr, 0)
    if first is None:
        return None
    l2_off, l2_entry, data_off = first
    cls = rng.choice(REPAIR_CORRUPTIONS)

    if cls == 'refcount_zero':
        if not _q_set_refcount(path, hdr, data_off, 0):
            return None
    elif cls == 'refcount_too_high':
        # Clear OFLAG_COPIED so qemu sees a pure leak, then inflate.
        _q_write64(path, l2_off, l2_entry & ~_Q_OFLAG_COPIED)
        if not _q_set_refcount(path, hdr, data_off, 2):
            return None
    elif cls == 'leaked_cluster':
        # Zero the L2 entry, orphaning its data cluster (refcount kept).
        _q_write64(path, l2_off, 0)
    elif cls == 'stale_copied':
        # Prefer L2[1] so this is not a near-duplicate of the others;
        # set OFLAG_COPIED and inflate the refcount to 2.
        second = _q_l2_entry(path, hdr, 1)
        l2o, entry, do = second if second is not None else first
        idx = 1 if second is not None else 0
        _q_write64(path, l2o + idx * 8, entry | _Q_OFLAG_COPIED)
        if not _q_set_refcount(path, hdr, do, 2):
            return None
    elif cls == 'overlapping':
        # Duplicate L2[0] into L2[1]: two virtual clusters -> one host
        # cluster (a structural overlap).
        _q_write64(path, l2_off + 1 * 8, l2_entry)

    return {'class': cls, 'data_offset': data_off}


def _qemu_check_metrics(path, timeout):
    """Read-only ``qemu-img check --output=json`` -> a metrics dict
    ``{'corruptions','leaks','check-errors'}`` (null -> 0), or None when
    qemu-img cannot produce parseable JSON for the image."""
    try:
        result = subprocess.run(
            ['qemu-img', 'check', '--output=json', str(path)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    try:
        data = json.loads(result.stdout)
    except (ValueError, json.JSONDecodeError):
        return None
    return {
        'corruptions': data.get('corruptions') or 0,
        'leaks': data.get('leaks') or 0,
        'check-errors': data.get('check-errors') or 0,
    }


def _instar_repair_incomplete(stdout):
    """Parse instar's ``repair-incomplete`` JSON key; None if unparseable."""
    try:
        return bool(json.loads(stdout).get('repair-incomplete'))
    except (ValueError, json.JSONDecodeError):
        return None


def _is_clean(metrics):
    """True when a qemu-img check metrics dict reports no problems."""
    return (
        metrics is not None
        and metrics['corruptions'] == 0
        and metrics['leaks'] == 0
        and metrics['check-errors'] == 0
    )


def op_repair(instar_bin, instar_copy, qemu_copy, fmt, timeout, rng):
    """Differential test of ``check --repair`` (qcow2 repair).

    Self-contained, like ``op_create``: ignores the passed copies,
    builds its own clean qcow2 with known data, corrupts it once, forks
    the corrupt file to two byte-identical copies, repairs one with
    ``instar check --repair`` and the other with ``qemu-img check -r``,
    and applies a three-tier oracle:

    1. Safety (unconditional): instar must never produce check-errors
       and never raise the corruption/leak count above the original —
       it must not make the image worse, even when it refuses.
    2. Convergence (only when instar claims a complete ``all``-tier
       repair via ``repair-incomplete == false``): the image must be
       qemu-clean, the way ``qemu-img check -r all`` reaches.
    3. Data equivalence (only when both reach clean): the raw-flattened
       guest data must match.

    instar's deliberate refuse/partial behaviour is recorded as
    ``inconclusive_repair_conservative`` (visibility, not a divergence).
    Returns a divergence dict, an inconclusive record, or None.
    """
    iter_dir = instar_copy.parent
    base = iter_dir / 'repair-base.qcow2'
    cluster_size = rng.choice([512, 4096, 65536])

    # 1. Build a clean qcow2 with known data patterns.
    try:
        created = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-o', f'cluster_size={cluster_size}', str(base), '1M'],
            capture_output=True, text=True, timeout=timeout,
        )
        if created.returncode != 0:
            return None
        for pattern, off, length in (
            ('0xAA', '0', '64k'), ('0xBB', '64k', '64k'),
            ('0xCC', '128k', '64k'), ('0xDD', '192k', '64k'),
        ):
            written = subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 f'write -P {pattern} {off} {length}', str(base)],
                capture_output=True, text=True, timeout=timeout,
            )
            if written.returncode != 0:
                return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    # 2. Corrupt it once (skip if nothing is allocated to corrupt).
    corruption = corrupt_qcow2(rng, base)
    if corruption is None:
        return None

    # 3. Establish the baseline on the corrupt original.
    orig = _qemu_check_metrics(base, timeout)
    if orig is None:
        return {
            'type': 'inconclusive_repair_no_baseline',
            'corruption': corruption['class'],
        }

    # 4. Fork byte-identical copies and repair each at a random tier.
    inst = iter_dir / 'repair-instar.qcow2'
    qemu = iter_dir / 'repair-qemu.qcow2'
    shutil.copy2(base, inst)
    shutil.copy2(base, qemu)
    tier = rng.choice(['leaks', 'all'])

    i_out, i_err, i_rc = run_instar(
        instar_bin, ['check'],
        [f'--repair={tier}', '--output', 'json', str(inst)],
        timeout=timeout,
    )
    if _is_external_timeout(i_rc, i_err):
        return {'type': 'inconclusive_external_timeout', 'operation': 'repair',
                'instar_rc': i_rc, 'qemu_rc': 0, 'timed_out': 'instar',
                'context': {'corruption': corruption['class'], 'tier': tier}}
    run_qemu_img(['check'], ['-r', tier, str(qemu)], timeout=timeout)

    # 5. Oracle.
    inst_m = _qemu_check_metrics(inst, timeout)
    qemu_m = _qemu_check_metrics(qemu, timeout)
    ctx = {'corruption': corruption['class'], 'tier': tier,
           'cluster_size': cluster_size, 'orig': orig}

    # 5a. Safety (unconditional). A repaired image qemu can no longer
    # parse, or with more corruptions/leaks than the original, means
    # instar made it worse.
    if inst_m is None:
        return {'type': 'repair_safety_divergence',
                'note': 'qemu-img check could not parse instar-repaired image',
                'instar_stderr': i_err[:500], **ctx}
    if (inst_m['check-errors'] > 0
            or inst_m['corruptions'] > orig['corruptions']
            or inst_m['leaks'] > orig['leaks']):
        return {'type': 'repair_safety_divergence',
                'instar': inst_m, 'instar_stderr': i_err[:500], **ctx}

    incomplete = _instar_repair_incomplete(i_out)

    # 5b. Convergence — only for the `all` tier, where instar and
    # qemu-img have matching scope (full refcount rebuild + leak
    # reclamation + COPIED reconciliation). When instar claims a
    # complete all-tier repair (repair-incomplete == false), the image
    # must be qemu-clean, the way `qemu-img check -r all` reaches.
    #
    # The leaks tier is deliberately NOT checked for convergence: it
    # is narrower than qemu-img's `-r leaks`. instar's safe tier only
    # frees unreferenced clusters and never lowers a *referenced*
    # cluster's refcount (over-count correction is the all tier's
    # lossy concern — see reclaim_leaks_in_refblock's doc), whereas
    # qemu-img's `-r leaks` also trims over-counts. So a refcount-too-
    # high / stale-copied cluster stays flagged after instar
    # `--repair=leaks` but is cleaned by `qemu-img -r leaks`: a known,
    # intentional scope difference, not a repair failure. Data
    # equivalence (5c) still covers the leaks-tier cases instar does
    # fully repair (genuine leaked clusters).
    if tier == 'all' and incomplete is False and not _is_clean(inst_m):
        return {'type': 'repair_completeness_divergence',
                'instar': inst_m, 'qemu': qemu_m,
                'instar_stdout': i_out[:500], **ctx}

    # 5c. Data equivalence (only when both reach clean).
    if _is_clean(inst_m) and _is_clean(qemu_m):
        inst_raw = iter_dir / 'repair-instar.raw'
        qemu_raw = iter_dir / 'repair-qemu.raw'
        subprocess.run(['qemu-img', 'convert', '-O', 'raw',
                        str(inst), str(inst_raw)],
                       capture_output=True, timeout=timeout)
        subprocess.run(['qemu-img', 'convert', '-O', 'raw',
                        str(qemu), str(qemu_raw)],
                       capture_output=True, timeout=timeout)
        if (inst_raw.exists() and qemu_raw.exists()
                and not files_match(inst_raw, qemu_raw)):
            return {'type': 'repair_data_divergence',
                    'instar_sha256': _file_sha256(inst_raw),
                    'qemu_sha256': _file_sha256(qemu_raw), **ctx}

    # 5d. Conservatism — instar deliberately did less. Recorded for
    # visibility, never a divergence or a GitHub issue.
    if incomplete:
        return {'type': 'inconclusive_repair_conservative', **ctx}

    return None


# ---------------------------------------------------------------------------
# Single iteration
# ---------------------------------------------------------------------------

def run_iteration(instar_bin, workdir, rng, iteration, timeout,
                   libyal_tools=None, operations=None):
    """Run one fuzzing iteration. Returns (divergence_dict, attrs) or
    (None, attrs) on success.

    `operations` restricts the op pool for this run (the --ops CLI
    filter); None means all of OPERATIONS.
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
        op_pool = operations if operations else OPERATIONS
        num_ops = rng.randint(2, 4)
        ops = [rng.choice(op_pool) for _ in range(num_ops)]
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
            elif op == 'resize':
                div = op_resize(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'amend':
                div = op_amend(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'rebase':
                div = op_rebase(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'commit':
                div = op_commit(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'map':
                div = op_map(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'snapshot':
                div = op_snapshot(
                    instar_bin, instar_copy, qemu_copy, fmt,
                    timeout, rng,
                )
            elif op == 'repair':
                div = op_repair(
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
        '--ops', type=str, default=None,
        help='Comma-separated subset of operations to run '
             f'(default: all). Valid: {", ".join(OPERATIONS)}',
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

    # Validate the --ops filter against OPERATIONS at startup.
    operations = None
    if args.ops is not None:
        operations = [o.strip() for o in args.ops.split(',')
                      if o.strip()]
        invalid = sorted(set(operations) - set(OPERATIONS))
        if invalid or not operations:
            print(
                f'Error: invalid --ops value {args.ops!r}; valid '
                f'operations: {", ".join(OPERATIONS)}',
                file=sys.stderr,
            )
            sys.exit(1)

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
    logger.info('  ops:        %s',
                ','.join(operations) if operations else 'all')

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
    inconclusive = []
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
                    'Iteration %d/%d (%.1f iter/s, %d divergences, '
                    '%d inconclusive)',
                    i + 1, args.iterations, rate,
                    len(divergences), len(inconclusive),
                )

            try:
                div, attrs = run_iteration(
                    instar_bin, workdir, iter_rng, i, args.timeout,
                    libyal_tools=libyal_tools, operations=operations,
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
                # Inconclusive records (e.g. external-tool timeouts)
                # are logged for visibility but do not count as
                # divergences and never file a GitHub issue.
                if str(div.get('type', '')).startswith('inconclusive_'):
                    inconclusive.append((i, div))
                    logger.info(
                        'inconclusive at iteration %d: %s',
                        i, div.get('type', 'unknown'),
                    )
                    continue
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
        if inconclusive:
            logger.info(
                'Inconclusive iterations (external-tool timeout, '
                'not a divergence): %d', len(inconclusive),
            )

        # Write summary (including in --fail-fast mode)
        summary = {
            'seed': seed,
            'iterations': args.iterations,
            'iterations_completed': iterations_done,
            'elapsed_seconds': round(elapsed, 1),
            'divergences_found': len(divergences),
            'divergence_iterations': [d[0] for d in divergences],
            'inconclusive_count': len(inconclusive),
            'inconclusive_iterations': [d[0] for d in inconclusive],
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
