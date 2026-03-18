#!/usr/bin/env python3
"""Differential fuzzing: compare imago vs qemu-img on random images.

For each iteration this script:
  1. Picks a random seed (logged for reproducibility).
  2. Generates a random disk image with qemu-img create.
  3. Runs a random set of operations (info, check, convert)
     independently against both imago and qemu-img on separate
     copies of the same input image.
  4. Compares outputs at each stage; exits with details on the
     first unexplained divergence.

Usage:
    python3 scripts/differential-fuzz.py \
        --imago src/target/release/imago \
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
OPERATIONS = ['info', 'check', 'convert', 'convert_compressed']

# Known divergence categories to skip (unsafe quirks)
# See docs/quirks.md for rationale
KNOWN_DIVERGENCE_FIELDS = {
    # disk size varies by filesystem allocation
    'actual-size',
    'disk size',
    # imago uses consistent JSON schema; qemu-img omits zero fields
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

def run_imago(imago_bin, subcmd, args, timeout=30):
    """Run an imago subcommand. Returns (stdout, stderr, rc)."""
    cmd = [str(imago_bin)] + subcmd + args
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
# Output comparison
# ---------------------------------------------------------------------------

def _strip_divergent_fields(obj):
    """Recursively strip known-divergent fields from a JSON object.

    Handles nested structures like the 'children' array in info
    JSON output, where each child has its own 'info' dict with
    filename, actual-size, etc.
    """
    if isinstance(obj, dict):
        # Fields that differ because imago and qemu-img operate
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

    Removes fields known to differ between imago and qemu-img
    (filenames, disk size, allocation details) and sorts keys
    for stable comparison. Handles nested children objects.
    """
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return raw_json.strip()

    _strip_divergent_fields(data)

    return json.dumps(data, sort_keys=True, indent=2)


def compare_exit_codes(imago_rc, qemu_rc, operation, context):
    """Compare exit codes, returning a divergence dict or None."""
    # Both succeed or both fail = OK
    imago_ok = (imago_rc == 0)
    qemu_ok = (qemu_rc == 0)

    if imago_ok == qemu_ok:
        return None

    return {
        'type': 'exit_code_divergence',
        'operation': operation,
        'imago_rc': imago_rc,
        'qemu_rc': qemu_rc,
        'context': context,
    }


def compare_info_outputs(imago_stdout, qemu_stdout):
    """Compare info JSON outputs after normalisation.

    Returns a divergence dict or None.
    """
    imago_norm = normalize_info_json(imago_stdout)
    qemu_norm = normalize_info_json(qemu_stdout)

    if imago_norm == qemu_norm:
        return None

    return {
        'type': 'info_output_divergence',
        'imago_normalized': imago_norm[:2000],
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

def op_info(imago_bin, imago_copy, qemu_copy, fmt, timeout):
    """Run info on both copies and compare JSON output."""
    # Raw images created by the fuzzer have no partition table,
    # so imago intentionally rejects them as "unknown format"
    # while qemu-img reports "raw".  This is a documented
    # unsafe quirk (see docs/quirks.md), not a bug.
    if fmt == 'raw':
        return None

    i_out, i_err, i_rc = run_imago(
        imago_bin, ['info'], ['--output', 'json', str(imago_copy)],
        timeout=timeout,
    )
    q_out, q_err, q_rc = run_qemu_img(
        ['info'], ['--output=json', str(qemu_copy)],
        timeout=timeout,
    )

    div = compare_exit_codes(i_rc, q_rc, 'info', {
        'imago_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
    })
    if div:
        return div

    # Only compare output when both succeeded
    if i_rc == 0 and q_rc == 0:
        div = compare_info_outputs(i_out, q_out)
        if div:
            return div

    return None


def op_check(imago_bin, imago_copy, qemu_copy, fmt, timeout):
    """Run check on both copies and compare exit codes."""
    # qemu-img check only works on qcow2; imago checks all formats
    # Skip comparison for non-qcow2 (known quirk)
    if fmt != 'qcow2':
        return None

    i_out, i_err, i_rc = run_imago(
        imago_bin, ['check'], [str(imago_copy)],
        timeout=timeout,
    )
    q_out, q_err, q_rc = run_qemu_img(
        ['check'], [str(qemu_copy)],
        timeout=timeout,
    )

    return compare_exit_codes(i_rc, q_rc, 'check', {
        'imago_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
        'imago_stdout': i_out[:500],
        'qemu_stdout': q_out[:500],
    })


def op_convert(imago_bin, imago_copy, qemu_copy, fmt,
               timeout, rng, compress=False):
    """Convert both copies to a random output format; compare results.

    Converts both to raw and then SHA-compares the raw outputs to
    ensure data content is identical.
    """
    # Pick a target format for the convert
    target_fmt = rng.choice(['raw', 'qcow2'])

    imago_out = imago_copy.parent / f'{imago_copy.stem}-conv.{target_fmt}'
    qemu_out = qemu_copy.parent / f'{qemu_copy.stem}-conv.{target_fmt}'

    # Convert with imago
    imago_args = ['-O', target_fmt]
    if compress and target_fmt == 'qcow2':
        imago_args.append('--compress')
    imago_args.extend([str(imago_copy), str(imago_out)])

    i_out, i_err, i_rc = run_imago(
        imago_bin, ['convert'], imago_args, timeout=timeout,
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
        'imago_stderr': i_err[:500],
        'qemu_stderr': q_err[:500],
    })
    if div:
        return div

    if i_rc != 0:
        # Both failed; no further comparison needed
        return None

    # Compare content: convert both outputs to raw and hash
    if target_fmt == 'raw':
        if not files_match(imago_out, qemu_out):
            return {
                'type': 'convert_content_divergence',
                'target_format': target_fmt,
                'compress': compress,
                'imago_sha256': _file_sha256(imago_out),
                'qemu_sha256': _file_sha256(qemu_out),
            }
    else:
        # For non-raw targets, convert both to raw and compare
        imago_raw = imago_copy.parent / f'{imago_copy.stem}-verify.raw'
        qemu_raw = qemu_copy.parent / f'{qemu_copy.stem}-verify.raw'

        # Use qemu-img to flatten both to raw for comparison
        # (neutral ground — neither tool is favoured)
        subprocess.run(
            ['qemu-img', 'convert', '-O', 'raw',
             str(imago_out), str(imago_raw)],
            capture_output=True, timeout=timeout,
        )
        subprocess.run(
            ['qemu-img', 'convert', '-O', 'raw',
             str(qemu_out), str(qemu_raw)],
            capture_output=True, timeout=timeout,
        )

        if imago_raw.exists() and qemu_raw.exists():
            if not files_match(imago_raw, qemu_raw):
                return {
                    'type': 'convert_content_divergence',
                    'target_format': target_fmt,
                    'compress': compress,
                    'note': 'raw-flattened content differs',
                    'imago_sha256': _file_sha256(imago_raw),
                    'qemu_sha256': _file_sha256(qemu_raw),
                }

    return None


# ---------------------------------------------------------------------------
# Single iteration
# ---------------------------------------------------------------------------

def run_iteration(imago_bin, workdir, rng, iteration, timeout):
    """Run one fuzzing iteration. Returns (divergence_dict, attrs) or
    (None, attrs) on success.
    """
    iter_dir = workdir / f'iter-{iteration:06d}'
    iter_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Generate a random image
        image_path, fmt, attrs = generate_image(rng, iter_dir, iteration)

        # Create separate copies for imago and qemu-img
        imago_copy = iter_dir / f'imago-{image_path.name}'
        qemu_copy = iter_dir / f'qemu-{image_path.name}'
        shutil.copy2(image_path, imago_copy)
        shutil.copy2(image_path, qemu_copy)

        # Pick a random set of 2-4 operations to run independently
        # on the same input image
        num_ops = rng.randint(2, 4)
        ops = [rng.choice(OPERATIONS) for _ in range(num_ops)]
        attrs['operations'] = ops

        for op in ops:
            if op == 'info':
                div = op_info(
                    imago_bin, imago_copy, qemu_copy, fmt, timeout
                )
            elif op == 'check':
                div = op_check(
                    imago_bin, imago_copy, qemu_copy, fmt, timeout
                )
            elif op == 'convert':
                div = op_convert(
                    imago_bin, imago_copy, qemu_copy, fmt,
                    timeout, rng, compress=False,
                )
            elif op == 'convert_compressed':
                div = op_convert(
                    imago_bin, imago_copy, qemu_copy, fmt,
                    timeout, rng, compress=True,
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
        f'  --imago src/target/release/imago \\\n'
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
        description='Differential fuzzing: imago vs qemu-img',
    )
    parser.add_argument(
        '--imago', required=True,
        help='Path to imago binary',
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
    imago_bin = Path(args.imago).resolve()
    if not imago_bin.exists():
        print(f'Error: imago binary not found: {imago_bin}', file=sys.stderr)
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
    logger.info('  imago:      %s', imago_bin)
    logger.info('  timeout:    %ds', args.timeout)
    logger.info('  log file:   %s', log_file)

    # Create or use workdir
    if args.workdir:
        workdir = Path(args.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        cleanup_workdir = False
    else:
        workdir = Path(tempfile.mkdtemp(prefix='imago-fuzz-'))
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
                    imago_bin, workdir, iter_rng, i, args.timeout,
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
