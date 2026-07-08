"""Integration tests for `instar bench`.

Phase 6 of PLAN-bench.md. Converts the 4c/5c smoke matrices (captured
in PLAN-bench-phase-01-crate.md's "Captured qemu-img 10.0.8 message
contract" + "Supplement 2", PLAN-bench-phase-04-host-cli.md's
"Captured smoke results (step 4c)", and PLAN-bench-phase-05-write.md's
"Captured write verification (step 5c)") into a live differential
suite against the locally-installed `qemu-img` (10.0.8), and
formalises `KNOWN_BENCH_DIVERGENCES` so the contract survives future
changes.

Scope contract (the OQ13 decisions, recorded):

* Timing values are NEVER asserted. The completion line is checked
  against the shape `^Run completed in \\d+\\.\\d{3} seconds\\.$`
  (`COMPLETION_RE`) only; `--output json`'s `elapsed-seconds` is
  checked for presence/type/positivity only, never for a specific
  value.
* **No cross-version baselines** (OQ13 resolved): the deterministic
  header depends only on arguments, so a baseline matrix would record
  only the uncomparable timing line. There is deliberately no
  `test_bench_baselines.py` and no `expected-outputs/bench-*` tree;
  parity is asserted **live** against the host's installed `qemu-img`
  instead, on fixtures synthesised per-test.
* Divergences are asserted, not silenced (the `test_map.py` contract):
  a failing cross-validation NOT registered in
  `KNOWN_BENCH_DIVERGENCES` is a real regression; a registered
  divergence that stops diverging fails `TestBenchDivergenceRegression`
  loudly, forcing a registry update rather than a silent pass.

Seven test classes, all inheriting from `BenchTestBase`:

* `TestBenchHeaderParity` — the 4c header-byte-parity rows.
* `TestBenchValidation` — the corrected §2 message-contract table
  (phase-04 Mission section 2), host-side, no guest launch.
* `TestBenchReadBehaviour` — EOF/wrap/chain read-path behaviour.
* `TestBenchWrite` — the 5c write-verification matrix, thinned.
* `TestBenchWriteRefusals` — the write-path gate contracts.
* `TestBenchJson` — the `--output json` schema.
* `TestBenchDivergenceRegression` — re-verifies every testable
  `KNOWN_BENCH_DIVERGENCES` entry still diverges.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# Shape-only match for the completion line -- the timing value itself
# is never asserted anywhere in this file (OQ13, module docstring).
COMPLETION_RE = re.compile(r'^Run completed in \d+\.\d{3} seconds\.$')


# ----------------------------------------------------------------------
# KNOWN_BENCH_DIVERGENCES -- registry of intentional instar-vs-qemu-img
# differences for `instar bench`. Mirrors `KNOWN_MAP_DIVERGENCES`
# (test_map.py:168): `dict[key, (scope, reason)]`. A cross-validation
# failure NOT registered here is a real regression to investigate, not
# to silence; `TestBenchDivergenceRegression` asserts each testable
# entry (2-7, 9-11) still diverges, so an accidental fix surfaces as a
# registry-cleanup prompt instead of a silent pass.
#
# `scope` is a short tag for where the divergence is observable:
# 'read', 'write', 'validation', or 'json'.
# ----------------------------------------------------------------------
KNOWN_BENCH_DIVERGENCES = {
    'depth-serialized': (
        'json',
        "-d is echoed in the header for parity but bench executes "
        'serially in v1 (master plan OQ1); --output json always '
        'reports "effective-depth": 1 regardless of the requested '
        'depth. No live regression test -- this is a semantic '
        'property verified directly by TestBenchJson.'
    ),
    'wrap-rule-10-0-8': (
        'read+write',
        'instar adopts qemu master\'s fixed wrap rule '
        '(offset %= image_size - bufsize) so a wrapped request never '
        'overruns EOF; qemu-img 10.0.8 still ships the buggy '
        '`% image_size` rule and can EIO near EOF on a request that '
        'wraps past the last full buffer. Captured live in phase 1 '
        '(read, the 10240-byte vector) and phase 5\'s 5c raw x (d) '
        'row (write).'
    ),
    'cache-modes-refused': (
        'validation',
        "-t with any cache mode other than the default 'writeback' is "
        "refused (`bench: cache mode '<v>' is not yet supported`); "
        'qemu-img runs every valid cache mode (e.g. -t none) '
        'successfully.'
    ),
    'aio-refused': (
        'validation',
        "-i <anything> is refused (`bench: aio backend '<v>' is not "
        'yet supported`); qemu-img runs with any recognised aio '
        'backend.'
    ),
    'native-aio-refused': (
        'validation',
        '-n is refused (`bench: native AIO (-n) is not yet '
        'supported`); qemu-img also fails for -n alone, but for an '
        'unrelated host requirement (`aio=native ... requires '
        'cache.direct=on`) -- both fail, for different reasons, not '
        'a "qemu succeeds" divergence.'
    ),
    'image-opts-refused': (
        'validation',
        '--image-opts alone is refused (`bench: --image-opts is not '
        'yet supported`); qemu-img runs it. (--image-opts combined '
        'with -f/--format is qemu parity: both refuse with the same '
        'mutual-exclusion text.)'
    ),
    'bufsize-cap-2mib': (
        'validation',
        "-s values inside qemu's [1, 2147483647] range but above "
        'BENCH_MAX_BUFSIZE (2 MiB) are refused (`bench: buffer sizes '
        'above 2 MiB are not yet supported`); qemu-img runs them '
        '(confirmed live with -s 3M).'
    ),
    'help-hint-names-instar': (
        'validation',
        'The filename-count error\'s second line names instar, not '
        "qemu-img: `Try 'instar bench --help' for more info` vs "
        "qemu's `Try 'qemu-img bench --help' for more info`."
    ),
    'zero-byte-early-failure': (
        'read',
        'instar fails during backing-chain discovery for a zero-byte '
        'image, before any header ever prints (`error discovering '
        'backing chain for <file>: ...`); qemu-img prints the header '
        'unconditionally then fails the first request (`Failed '
        'request: Input/output error`). Both exit 1, but the failure '
        'point and text are unrelated -- a stronger divergence than a '
        'plain format-classification difference.'
    ),
    'write-formats-limited': (
        'write',
        '-w is refused on vmdk/vhd/vhdx (`bench: write tests are not '
        'yet supported for <fmt>`); qemu-img writes all of them. '
        'instar v1 only supports write tests on raw and qcow2.'
    ),
    'secure-raw-detection': (
        'read+write',
        'A headerless raw image (no MBR/known signature) is refused '
        'as an unsupported format -- instar-wide security posture '
        'requires a recognisable signature before a file is treated '
        'as raw; qemu-img benches it happily. This is why every raw '
        'fixture in this suite carries the 55AA MBR signature '
        '(`make_raw_mbr`).'
    ),
}


class BenchTestBase(InstarTestBase):
    """Shared helpers for the `instar bench` test families.

    Owns the `instar bench` / `qemu-img bench` runners, the
    `/dev/kvm` skip guard, and the fixture builders (Mission
    section 3): `make_raw_mbr`, `make_qcow2`, `make_populated_qcow2`,
    `make_overlay`, `make_compressed_qcow2`, `make_vmdk`, `make_vhd`,
    `make_vhdx`, plus `sha256` and `header_line`.
    """

    def run_instar_bench(self, *args, timeout=120):
        """Invoke `instar bench` with the given args.

        Returns (stdout, stderr, returncode). Timeout 120s because
        bench spins up the guest VMM.
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'bench', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def run_qemu_bench(self, *args, timeout=120):
        """Invoke `qemu-img bench` (the oracle side).

        Returns (stdout, stderr, returncode).
        """
        cmd = ['qemu-img', 'bench', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _require_kvm(self):
        """Skip the test when `/dev/kvm` is not readable+writable.

        bench launches a guest VM; mirrors amend/bitmap's
        guest-needs-kvm skip so the suite degrades gracefully where
        kvm is unavailable. (On this host /dev/kvm is available, so
        no skips are expected in practice.)
        """
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            self.skipTest('/dev/kvm not readable+writable')

    def _qemu_io(self, img, cmd, fmt=None, timeout=30):
        """Run a single `qemu-io -c CMD IMG` command; assert rc 0."""
        argv = ['qemu-io']
        if fmt is not None:
            argv += ['-f', fmt]
        argv += ['-c', cmd, str(img)]
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-io -c {cmd!r} failed for {img}: {r.stderr!r}')
        return r

    # ------------------------------------------------------------------
    # Fixture builders (Mission section 3).
    # ------------------------------------------------------------------

    def make_raw_mbr(self, path, size='10M'):
        """Create a raw image carrying the 55AA MBR boot signature.

        instar's secure format detection refuses headerless raw
        files (KNOWN_BENCH_DIVERGENCES['secure-raw-detection']), so
        every raw fixture that is meant to be BENCHED (not used to
        exercise that refusal) needs this signature. No Python helper
        exists for this trick anywhere in the suite; replicated here
        from `scripts/create-external-data-testdata.sh:46-49`:
        create/truncate the file, then two `qemu-io` pattern writes at
        bytes 510/511.
        """
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', str(path), size],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create raw failed: {r.stderr!r}')
        r = subprocess.run(
            ['qemu-io', '-f', 'raw',
             '-c', 'write -P 0x55 510 1',
             '-c', 'write -P 0xaa 511 1',
             str(path)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0,
            f'MBR signature write failed for {path}: {r.stderr!r}')

    def make_qcow2(self, path, size='16M', cluster_size=None):
        """Create a fresh, empty qcow2 fixture."""
        cmd = ['qemu-img', 'create', '-f', 'qcow2']
        if cluster_size is not None:
            cmd += ['-o', f'cluster_size={cluster_size}']
        cmd += [str(path), size]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create qcow2 failed: {r.stderr!r}')

    def make_populated_qcow2(self, path, size='16M', fill_size='8M'):
        """A qcow2 fixture with `[0, fill_size)` pre-filled with 0xbb.

        Mirrors the 5c capture's "populated qcow2" base image: writes
        land on already-allocated clusters, exercising the write
        path's fast overwrite-in-place branch.
        """
        self.make_qcow2(path, size=size)
        self._qemu_io(path, f'write -P 0xbb 0 {fill_size}')

    def make_overlay(self, td, size='16M', fill_size='8M',
                      backing_name='backing.qcow2',
                      overlay_name='overlay.qcow2'):
        """A qcow2 overlay over a populated (0xbb) backing image.

        `td` is the directory both files are created in -- instar's
        default `SecurityConfig` restricts backing references to the
        top image's own directory, so the backing file MUST live
        alongside the overlay (5c capture note). Returns
        `(backing_path, overlay_path)`. The backing reference is
        written as the bare relative filename so a copy of the
        overlay into any other directory containing a same-named
        backing file still resolves.
        """
        backing = td / backing_name
        self.make_populated_qcow2(backing, size=size, fill_size=fill_size)
        overlay = td / overlay_name
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2',
             '-b', backing_name, '-F', 'qcow2', str(overlay)],
            cwd=str(td), capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create overlay failed: {r.stderr!r}')
        return backing, overlay

    def make_compressed_qcow2(self, td, size='4M'):
        """A compressed qcow2 fixture (`convert -c` of compressible data).

        Writes a single-byte-repeated (highly compressible) pattern
        into a raw source, then `qemu-img convert -c` to qcow2, then
        asserts via `qemu-img check --output=json`'s
        `compressed-clusters` field that the result actually carries
        compressed clusters (not just that convert -c was requested).
        """
        src = td / 'compressible_src.raw'
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', str(src), size],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create raw src failed: {r.stderr!r}')
        self._qemu_io(src, f'write -P 0x41 0 {size}', fmt='raw')
        dst = td / 'compressed.qcow2'
        r = subprocess.run(
            ['qemu-img', 'convert', '-c', '-f', 'raw', '-O', 'qcow2',
             str(src), str(dst)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img convert -c failed: {r.stderr!r}')
        chk = subprocess.run(
            ['qemu-img', 'check', '--output=json', str(dst)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            chk.returncode, 0, f'qemu-img check failed: {chk.stderr!r}')
        data = json.loads(chk.stdout)
        self.assertGreater(
            data.get('compressed-clusters', 0), 0,
            'compressed qcow2 fixture unexpectedly has no compressed '
            'clusters')
        return dst

    def make_vmdk(self, path, size='10M'):
        """A monolithicSparse vmdk fixture (single-file, embedded
        descriptor -- mirrors the 4c/5c capture's `test.vmdk`)."""
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'vmdk',
             '-o', 'subformat=monolithicSparse', str(path), size],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create vmdk failed: {r.stderr!r}')

    def make_vhd(self, path, size='10M'):
        """A dynamic VHD fixture (qemu-img driver name `vpc`)."""
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'vpc', str(path), size],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create vpc failed: {r.stderr!r}')

    def make_vhdx(self, path, size='10M'):
        """A VHDX fixture."""
        r = subprocess.run(
            ['qemu-img', 'create', '-f', 'vhdx', str(path), size],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0, f'qemu-img create vhdx failed: {r.stderr!r}')

    @staticmethod
    def sha256(path):
        """Return the sha256 hex digest of a file's full contents."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def header_line(stdout):
        """Return the first line of `stdout`, or '' if empty."""
        lines = stdout.splitlines()
        return lines[0] if lines else ''


class TestBenchHeaderParity(BenchTestBase):
    """The 4c header-byte-parity rows.

    Identical args on identical fixtures, instar vs qemu-img: the
    first stdout line (the header) must be byte-EQUAL between tools,
    the last stdout line (the completion line) must match
    `COMPLETION_RE` on both (never compared for its timing value), and
    both must exit 0. Read-only, so both tools can safely bench the
    SAME fixture file without an A/B copy.
    """

    def _assert_header_parity(self, args):
        """Run `args` (a full argv incl. the trailing path) through
        both tools; assert exit 0/0, header byte-equality, and
        completion-line shape on both. Returns `(i_out, q_out)`."""
        i_out, i_err, i_rc = self.run_instar_bench(*args)
        self.assertEqual(
            i_rc, 0, f'instar bench {args} failed: {i_err!r}')
        q_out, q_err, q_rc = self.run_qemu_bench(*args)
        self.assertEqual(
            q_rc, 0, f'qemu-img bench {args} failed: {q_err!r}')

        i_header = self.header_line(i_out)
        q_header = self.header_line(q_out)
        self.assertEqual(
            i_header, q_header,
            f'header mismatch:\n  instar: {i_header!r}\n'
            f'  qemu:   {q_header!r}')

        i_completion = i_out.splitlines()[-1]
        q_completion = q_out.splitlines()[-1]
        self.assertRegex(i_completion, COMPLETION_RE)
        self.assertRegex(q_completion, COMPLETION_RE)
        return i_out, q_out

    def test_raw_defaults(self):
        """raw, `-c 100` defaults: header byte-identical."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img)
            self._assert_header_parity(['-c', '100', '-f', 'raw', str(img)])

    def test_raw_offset_1k(self):
        """raw, `-o 1k`: offset renders as decimal 1024 on both."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img)
            self._assert_header_parity(
                ['-c', '100', '-o', '1k', '-f', 'raw', str(img)])

    def test_raw_step_zero(self):
        """raw, `-S 0`: effective step renders as bufsize (4096)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img)
            self._assert_header_parity(
                ['-c', '100', '-S', '0', '-f', 'raw', str(img)])

    def test_raw_multi_transfer(self):
        """raw, `-s 65537`: bufsize above the 64 KiB transfer cap."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img)
            self._assert_header_parity(
                ['-c', '100', '-s', '65537', '-f', 'raw', str(img)])

    def test_raw_depth_1(self):
        """raw, `-d 1`: depth is echoed in the header verbatim."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img)
            self._assert_header_parity(
                ['-c', '100', '-d', '1', '-f', 'raw', str(img)])

    def test_qcow2_plain(self):
        """A fresh, empty qcow2 image."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'plain.qcow2'
            self.make_qcow2(img)
            self._assert_header_parity(['-c', '100', '-f', 'qcow2', str(img)])

    def test_qcow2_backing(self):
        """A qcow2 image with a raw backing file (chain discovery)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            backing = td / 'backing.raw'
            self.make_raw_mbr(backing)
            overlay = td / 'withbacking.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', 'backing.raw', '-F', 'raw', str(overlay)],
                cwd=str(td), capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0, f'create overlay failed: {r.stderr!r}')
            self._assert_header_parity(
                ['-c', '100', '-f', 'qcow2', str(overlay)])

    def test_qcow2_compressed(self):
        """A compressed qcow2 image (compressed clusters, read path)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            img = self.make_compressed_qcow2(td)
            self._assert_header_parity(['-c', '100', '-f', 'qcow2', str(img)])

    def test_vmdk(self):
        """A monolithicSparse vmdk image."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'test.vmdk'
            self.make_vmdk(img)
            self._assert_header_parity(['-c', '100', '-f', 'vmdk', str(img)])

    def test_vhd(self):
        """A dynamic VHD image (driver name `vpc`)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'test.vhd'
            self.make_vhd(img)
            self._assert_header_parity(['-c', '100', '-f', 'vpc', str(img)])

    def test_vhdx(self):
        """A VHDX image."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'test.vhdx'
            self.make_vhdx(img)
            self._assert_header_parity(['-c', '100', '-f', 'vhdx', str(img)])


class TestBenchValidation(BenchTestBase):
    """The corrected §2 message-contract table (phase-04 Mission §2).

    Host-side validation failures only -- these fail inside
    `validate_bench_args`, BEFORE any guest launches, so (with one
    documented exception) they need no `/dev/kvm` guard. Every
    numeric option has two failure forms (Supplement 2 of the phase-1
    1e capture): an unparseable value gets the value-echoing
    `Invalid <name> specified: '<v>'.` text, an out-of-range *number*
    gets the `Must be between` text. Where instar and qemu-img share
    the exact same message (a parity row), both sides are run and
    compared; the 2 MiB buffer-size cap is instar-only (a registered
    divergence) so only instar's side is asserted here.
    """

    def _assert_failure_and_parity(self, flag, value, expected_core,
                                    extra_args=()):
        """`args = ['-c', '100', flag, value, *extra_args, '-f', 'raw',
        <fixture>]` must fail on BOTH tools with rc == 1 and stderr
        containing `expected_core`. clap refuses a repeated single-value
        option outright (`cannot be used multiple times`), so the
        default `-c 100` is omitted when `flag` is itself `-c`."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='1M')
            base = [] if flag == '-c' else ['-c', '100']
            args = [*base, flag, value, *extra_args, '-f', 'raw', str(img)]
            i_out, i_err, i_rc = self.run_instar_bench(*args)
            self.assertEqual(
                i_rc, 1,
                f'instar {flag} {value}: expected rc 1, stdout={i_out!r} '
                f'stderr={i_err!r}')
            self.assertIn(
                expected_core, i_err,
                f'instar {flag} {value}: unexpected stderr {i_err!r}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args)
            self.assertEqual(
                q_rc, 1,
                f'qemu-img {flag} {value}: expected rc 1, stdout={q_out!r} '
                f'stderr={q_err!r}')
            self.assertIn(
                expected_core, q_err,
                f'qemu-img {flag} {value}: unexpected stderr {q_err!r}')

    # ---- Echo forms (unparseable values), x7 ----

    def test_echo_count(self):
        self._assert_failure_and_parity(
            '-c', 'abc', "Invalid request count specified: 'abc'.")

    def test_echo_depth(self):
        self._assert_failure_and_parity(
            '-d', 'abc', "Invalid queue depth specified: 'abc'.")

    def test_echo_bufsize(self):
        self._assert_failure_and_parity(
            '-s', 'abc', "Invalid buffer size specified: 'abc'.")

    def test_echo_step(self):
        self._assert_failure_and_parity(
            '-S', 'abc', "Invalid step size specified: 'abc'.")

    def test_echo_offset(self):
        self._assert_failure_and_parity(
            '-o', 'abc', "Invalid offset specified: 'abc'.")

    def test_echo_pattern(self):
        self._assert_failure_and_parity(
            '--pattern', 'abc', "Invalid pattern byte specified: 'abc'.")

    def test_echo_flush_interval(self):
        self._assert_failure_and_parity(
            '--flush-interval', 'abc',
            "Invalid flush interval specified: 'abc'.")

    # ---- Range forms (out-of-range numbers), x7 ----

    def test_range_count(self):
        self._assert_failure_and_parity(
            '-c', '-1',
            'Invalid request count specified. Must be between 1 and '
            '2147483647.')

    def test_range_depth(self):
        self._assert_failure_and_parity(
            '-d', '0',
            'Invalid queue depth specified. Must be between 1 and '
            '2147483647.')

    def test_range_bufsize(self):
        """Includes the suffix-multiply overflow route (Supplement 2):
        a suffix multiply that overflows u64 takes the range form, not
        the echo form."""
        core = ('Invalid buffer size specified. Must be between 1 and '
                '2147483647.')
        self._assert_failure_and_parity('-s', '3G', core)
        self._assert_failure_and_parity('-s', '200000000000000G', core)

    def test_range_step(self):
        core = ('Invalid step size specified. Must be between 0 and '
                '2147483647.')
        self._assert_failure_and_parity('-S', '-1', core)
        self._assert_failure_and_parity('-S', '2147483648', core)

    def test_range_offset(self):
        """Includes the suffix-multiply overflow route for -o."""
        core = ('Invalid offset specified. Must be between 0 and '
                '9223372036854775807.')
        self._assert_failure_and_parity('-o', '-1', core)
        self._assert_failure_and_parity('-o', '200000000000000G', core)

    def test_range_pattern(self):
        core = ('Invalid pattern byte specified. Must be between 0 and '
                '255.')
        self._assert_failure_and_parity('--pattern', '256', core)
        self._assert_failure_and_parity('--pattern', '-1', core)

    def test_range_flush_interval(self):
        core = ('Invalid flush interval specified. Must be between 0 '
                'and 2147483647.')
        self._assert_failure_and_parity('--flush-interval', '-1', core)
        self._assert_failure_and_parity(
            '--flush-interval', '2147483648', core)

    # ---- The 2 MiB instar-only cap (divergence, instar side only) ----

    def test_bufsize_cap_2mib(self):
        """-s inside qemu's range but above the 2 MiB instar cap."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='4M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '3', '-s', '3M', '-f', 'raw', str(img))
            self.assertEqual(
                i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn(
                'bench: buffer sizes above 2 MiB are not yet supported',
                i_err)

    # ---- The two cross-option rules ----

    def test_cross_option_flush_requires_write(self):
        """A NONZERO --flush-interval without -w is refused on both."""
        self._assert_failure_and_parity(
            '--flush-interval', '50',
            '--flush-interval is only available in write tests')

    def test_cross_option_flush_smaller_than_depth(self):
        """`-w -d 64 --flush-interval 32` (interval < depth) refused."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='1M')
            args = ['-c', '100', '-w', '-d', '64', '--flush-interval', '32',
                    '-f', 'raw', str(img)]
            i_out, i_err, i_rc = self.run_instar_bench(*args)
            self.assertEqual(
                i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn(
                "Flush interval can't be smaller than depth", i_err)
            q_out, q_err, q_rc = self.run_qemu_bench(*args)
            self.assertEqual(
                q_rc, 1, f'stdout={q_out!r} stderr={q_err!r}')
            self.assertIn(
                "Flush interval can't be smaller than depth", q_err)

    # ---- --flush-interval 0 without -w: accepted, exit 0 ----
    # (Actually runs the guest to completion, so this ONE validation
    # row needs /dev/kvm despite the class's general "no KVM" grouping.)

    def test_flush_interval_zero_without_write_accepted(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='4M')
            args = ['-c', '100', '--flush-interval', '0', '-f', 'raw',
                    str(img)]
            i_out, i_err, i_rc = self.run_instar_bench(*args)
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args)
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')
            self.assertEqual(self.header_line(i_out), self.header_line(q_out))

    # ---- Filename count: 0 and 2 filenames, both lines ----

    def test_filename_count(self):
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='1M')

            for extra_paths in ([], [str(img), str(img)]):
                args = ['-c', '100', '-f', 'raw', *extra_paths]
                i_out, i_err, i_rc = self.run_instar_bench(*args)
                self.assertEqual(
                    i_rc, 1,
                    f'filenames={extra_paths}: stdout={i_out!r} '
                    f'stderr={i_err!r}')
                self.assertIn('Expecting one image file name', i_err)
                self.assertIn(
                    "Try 'instar bench --help' for more info", i_err)

                q_out, q_err, q_rc = self.run_qemu_bench(*args)
                self.assertEqual(
                    q_rc, 1,
                    f'filenames={extra_paths}: stdout={q_out!r} '
                    f'stderr={q_err!r}')
                self.assertIn('Expecting one image file name', q_err)
                self.assertIn(
                    "Try 'qemu-img bench --help' for more info", q_err)

    # ---- --image-opts + -f mutual exclusion (qemu parity) ----

    def test_image_opts_format_mutual_exclusion(self):
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'x.raw'
            self.make_raw_mbr(img, size='1M')
            args = ['--image-opts', '-f', 'raw', '-c', '100', str(img)]
            i_out, i_err, i_rc = self.run_instar_bench(*args)
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn(
                '--image-opts and --format are mutually exclusive', i_err)
            q_out, q_err, q_rc = self.run_qemu_bench(*args)
            self.assertEqual(q_rc, 1, f'stdout={q_out!r} stderr={q_err!r}')
            self.assertIn(
                '--image-opts and --format are mutually exclusive', q_err)


class TestBenchReadBehaviour(BenchTestBase):
    """EOF, wrap, and chain read-path behaviour (KVM; ~4 tests)."""

    def test_offset_past_eof_both_fail(self):
        """`-o` near EOF: header prints, then a read I/O failure --
        both tools, same mechanism (the raw first offset is never
        wrapped, so both fail identically on request 1)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='10M')
            size = 10 * 1024 * 1024
            offset = size - 100  # default bufsize 4096 overruns EOF.
            args = ['-c', '100', '-o', str(offset), '-f', 'raw', str(img)]

            i_out, i_err, i_rc = self.run_instar_bench(*args)
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn('Failed request: Input/output error', i_err)
            self.assertTrue(i_out.strip(), 'header should have printed')

            q_out, q_err, q_rc = self.run_qemu_bench(*args)
            self.assertEqual(q_rc, 1, f'stdout={q_out!r} stderr={q_err!r}')
            self.assertIn('Failed request: Input/output error', q_err)
            self.assertTrue(q_out.strip(), 'header should have printed')

            self.assertEqual(self.header_line(i_out), self.header_line(q_out))

    def test_wrap_window_master_rule_succeeds(self):
        """The phase-1 10240-byte wrap vector: instar's master wrap
        rule keeps every wrapped request in-bounds, so the run
        succeeds. Paired with
        `TestBenchDivergenceRegression.test_wrap_rule_10_0_8_still_diverges`,
        which asserts qemu-img 10.0.8 still EIOs on the identical
        vector."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'wrap.raw'
            self.make_raw_mbr(img, size='10240')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '5', '-s', '4096', '-S', '4096', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')

    def test_overlay_reads_succeed(self):
        """Reads through a populated backing chain (overlay) succeed
        -- the content path (not just structural chain discovery) is
        exercised."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _backing, overlay = self.make_overlay(td)
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '100', '-f', 'qcow2', str(overlay))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')

    def test_compressed_qcow2_reads_succeed(self):
        """Reads on a compressed qcow2 succeed (decompression path)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            img = self.make_compressed_qcow2(td)
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '100', '-f', 'qcow2', str(img))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')


class TestBenchWrite(BenchTestBase):
    """The 5c write-verification matrix, thinned (KVM).

    Every scenario uses a fresh pristine copy per tool
    (`shutil.copy2`) so instar's and qemu-img's runs never share a
    mutated file. Virtual-content parity is asserted via
    `qemu-img compare` (allocator placement may legitimately differ
    between the two implementations; see PLAN-bench-phase-05-write.md
    step 5b) plus `qemu-img check` clean; raw is additionally
    byte-comparable (sha256) since there is no allocator involved.
    """

    def test_raw_write_byte_identical(self):
        """raw `-w`: instar's output is byte-identical to qemu-img's."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.raw'
            self.make_raw_mbr(pristine, size='10M')
            a = td / 'a.raw'
            b = td / 'b.raw'
            shutil.copy2(pristine, a)
            shutil.copy2(pristine, b)
            args = ['-w', '-c', '100', '--pattern', '65', '-f', 'raw']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            self.assertEqual(self.header_line(i_out), self.header_line(q_out))
            self.assertEqual(
                self.sha256(a), self.sha256(b),
                'raw write output diverges from the qemu-img twin')

    def test_qcow2_fresh_write_compare_check_growth(self):
        """Fresh qcow2 `-w`: compare identical, check clean, disk grows."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_qcow2(pristine, size='64M')
            pre_size = pristine.stat().st_size
            a = td / 'a.qcow2'
            b = td / 'b.qcow2'
            shutil.copy2(pristine, a)
            shutil.copy2(pristine, b)
            args = ['-w', '-c', '100', '--pattern', '65', '-f', 'qcow2']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            cmp_out, cmp_err, cmp_rc = self.run_qemu_img_compare(a, b)
            self.assertEqual(cmp_rc, 0, f'compare mismatch: {cmp_out}{cmp_err}')
            chk_out, chk_err, chk_rc = self.run_qemu_img_check(a)
            self.assertEqual(chk_rc, 0, f'check failed: {chk_out}{chk_err}')
            self.assertGreater(
                a.stat().st_size, pre_size,
                'fresh qcow2 should grow after an allocating write')

    def test_qcow2_populated_write_fast_path_no_growth(self):
        """Populated qcow2 `-w`: overwrite-in-place, no disk growth."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_populated_qcow2(pristine, size='64M', fill_size='8M')
            pre_size = pristine.stat().st_size
            a = td / 'a.qcow2'
            b = td / 'b.qcow2'
            shutil.copy2(pristine, a)
            shutil.copy2(pristine, b)
            args = ['-w', '-c', '100', '--pattern', '65', '-f', 'qcow2']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            cmp_out, cmp_err, cmp_rc = self.run_qemu_img_compare(a, b)
            self.assertEqual(cmp_rc, 0, f'compare mismatch: {cmp_out}{cmp_err}')
            chk_out, chk_err, chk_rc = self.run_qemu_img_check(a)
            self.assertEqual(chk_rc, 0, f'check failed: {chk_out}{chk_err}')
            self.assertEqual(
                a.stat().st_size, pre_size,
                'populated qcow2 fast-path overwrite should not grow')

    def test_qcow2_overlay_write_cow_spot(self):
        """Overlay `-w`: compare + check + the COW spot-byte via
        `qemu-io read -P`.

        The 100 default-sized (4096-byte) writes fully cover
        `[0, 409600)`; the last touched cluster (default 65536-byte
        clusters) is `[393216, 458752)`, so byte 420000 lies inside
        the newly-allocated cluster but OUTSIDE the pattern window --
        it must still read the backing file's 0xbb content, proving
        the allocating path's chain-read COW fill preserved the rest
        of the cluster.
        """
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _backing, overlay = self.make_overlay(td)
            a = td / 'a.qcow2'
            b = td / 'b.qcow2'
            shutil.copy2(overlay, a)
            shutil.copy2(overlay, b)
            args = ['-w', '-c', '100', '--pattern', '65', '-f', 'qcow2']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            cmp_out, cmp_err, cmp_rc = self.run_qemu_img_compare(a, b)
            self.assertEqual(cmp_rc, 0, f'compare mismatch: {cmp_out}{cmp_err}')
            chk_out, chk_err, chk_rc = self.run_qemu_img_check(a)
            self.assertEqual(chk_rc, 0, f'check failed: {chk_out}{chk_err}')

            r = subprocess.run(
                ['qemu-io', '-c', 'read -P 0xbb 420000 16', str(a)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0,
                f'COW fill spot-check failed: {r.stdout}{r.stderr}')

    def test_qcow2_cluster_straddling_write(self):
        """`-s 131072 -o 32768` on a fresh qcow2: every request
        straddles two clusters. Compare + check only."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_qcow2(pristine, size='64M')
            a = td / 'a.qcow2'
            b = td / 'b.qcow2'
            shutil.copy2(pristine, a)
            shutil.copy2(pristine, b)
            args = ['-w', '-c', '200', '-s', '131072', '-o', '32768',
                    '--pattern', '66', '-f', 'qcow2']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            cmp_out, cmp_err, cmp_rc = self.run_qemu_img_compare(a, b)
            self.assertEqual(cmp_rc, 0, f'compare mismatch: {cmp_out}{cmp_err}')
            chk_out, chk_err, chk_rc = self.run_qemu_img_check(a)
            self.assertEqual(chk_rc, 0, f'check failed: {chk_out}{chk_err}')

    def test_flush_interval_line_parity(self):
        """`--flush-interval 50 -d 1`: the "Sending flush every 50
        requests" line is present on both tools' stdout."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_qcow2(pristine, size='16M')
            a = td / 'a.qcow2'
            b = td / 'b.qcow2'
            shutil.copy2(pristine, a)
            shutil.copy2(pristine, b)
            args = ['-w', '-c', '100', '--pattern', '65',
                    '--flush-interval', '50', '-d', '1', '-f', 'qcow2']

            i_out, i_err, i_rc = self.run_instar_bench(*args, str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')
            q_out, q_err, q_rc = self.run_qemu_bench(*args, str(b))
            self.assertEqual(q_rc, 0, f'qemu: {q_err}')

            self.assertIn('Sending flush every 50 requests', i_out)
            self.assertIn('Sending flush every 50 requests', q_out)

    def test_flush_interval_json_count(self):
        """`--flush-interval 50 -c 100`: `flushes-issued` == 2, matching
        `crates/bench::total_flushes(100, 50)`."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_qcow2(pristine, size='16M')
            a = td / 'a.qcow2'
            shutil.copy2(pristine, a)
            j_out, j_err, j_rc = self.run_instar_bench(
                '-w', '-c', '100', '--pattern', '65',
                '--flush-interval', '50', '-d', '1', '-f', 'qcow2',
                '--output', 'json', str(a))
            self.assertEqual(j_rc, 0, f'instar: {j_err}')
            data = json.loads(j_out)
            self.assertEqual(data['flushes-issued'], 2)

    def test_no_drain_accepted(self):
        """`--no-drain` is an accepted no-op alongside a real flush run."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pristine = td / 'src.qcow2'
            self.make_qcow2(pristine, size='16M')
            a = td / 'a.qcow2'
            shutil.copy2(pristine, a)
            i_out, i_err, i_rc = self.run_instar_bench(
                '-w', '--no-drain', '--flush-interval', '50', '-d', '1',
                '-c', '100', '--pattern', '65', '-f', 'qcow2', str(a))
            self.assertEqual(i_rc, 0, f'instar: {i_err}')


class TestBenchWriteRefusals(BenchTestBase):
    """Write-path gate contracts (Mission §3; ~10 tests).

    vmdk/vhd/vhdx are refused HOST-SIDE (Mission §3's "-w host-side
    format gate", `run_bench`, before the header prints or the guest
    launches) so those three need no `/dev/kvm` guard; internal
    snapshots, refcount_bits=1, compression, LUKS encryption,
    extended L2, an external data file, and the dirty bit are all
    refused GUEST-SIDE (the qcow2 write envelope gates checked before
    `send_bench_start`), so those seven launch the guest and need the
    guard. Every case additionally asserts the image's sha256 is
    unchanged -- a refused write must not touch the file.
    """

    def _assert_write_refused(self, path, fmt_hint, expected_substr):
        before = self.sha256(path)
        args = ['-w', '-c', '100', '--pattern', '65']
        if fmt_hint is not None:
            args += ['-f', fmt_hint]
        out, err, rc = self.run_instar_bench(*args, str(path))
        self.assertEqual(rc, 1, f'stdout={out!r} stderr={err!r}')
        self.assertIn(expected_substr, err, f'unexpected stderr: {err!r}')
        self.assertEqual(
            self.sha256(path), before,
            'a refused write must not touch the image')

    def test_refuse_internal_snapshot(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'snap.qcow2'
            self.make_qcow2(img, size='16M')
            r = subprocess.run(
                ['qemu-img', 'snapshot', '-c', 'snap1', str(img)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'snapshot -c failed: {r.stderr}')
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(internal snapshots)')

    def test_refuse_refcount_bits_1(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'rc1.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=1.1,refcount_bits=1', str(img), '16M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'create failed: {r.stderr}')
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(refcount_bits != 16)')

    def test_refuse_compressed(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            img = self.make_compressed_qcow2(td)
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(compression)')

    def test_refuse_luks(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'luks.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '--object', 'secret,id=sec0,data=test-passphrase',
                 '-o', 'encrypt.format=luks,encrypt.key-secret=sec0,encrypt.iter-time=10',
                 str(img), '16M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'create luks failed: {r.stderr}')
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(encryption)')

    def test_refuse_extended_l2(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'el2.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=1.1,extended_l2=on', str(img), '64M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'create failed: {r.stderr}')
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(extended L2)')

    def test_refuse_external_data_file(self):
        """External data file (`-o data_file=`): verified live that
        `discover_backing_chain` does NOT refuse an external-data
        qcow2 host-side for bench (unlike commit/rebase, which refuse
        it explicitly) -- the image is opened read-only, resolved,
        and passed through to the guest, where the write-envelope
        gate (id 4, "external data file") fires instead. No host-side
        chain-discovery refusal pre-empts it.
        """
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', 'ext.raw', '64M'],
                cwd=str(td), capture_output=True, text=True, timeout=30)
            self.assertEqual(
                r.returncode, 0, f'create raw data file failed: {r.stderr}')
            img = td / 'extdata.qcow2'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-o', 'compat=1.1,data_file=ext.raw', 'extdata.qcow2', '64M'],
                cwd=str(td), capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'create failed: {r.stderr}')
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(external data file)')

    def test_refuse_dirty(self):
        """Dirty bit set via in-test header surgery: flip
        incompatible_features bit 0 (the big-endian u64 at header
        offset 72) on a copy of a fresh qcow2. The guest's
        write-envelope gate (id 6, "dirty or corrupt") fires. sha256
        is captured AFTER the surgery, so the assertion is that the
        already-dirty image is untouched by the refused write.
        """
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / 'clean.qcow2'
            self.make_qcow2(src, size='64M')
            img = Path(td) / 'dirty.qcow2'
            shutil.copyfile(src, img)
            with open(img, 'r+b') as f:
                f.seek(72)
                current = int.from_bytes(f.read(8), 'big')
                f.seek(72)
                f.write((current | 1).to_bytes(8, 'big'))
            self._assert_write_refused(
                img, 'qcow2',
                'bench: write tests are not supported for this image '
                '(dirty or corrupt)')

    def test_refuse_vmdk(self):
        """Host-side format gate; no guest launch, no /dev/kvm needed."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 't.vmdk'
            self.make_vmdk(img)
            self._assert_write_refused(
                img, None,
                'bench: write tests are not yet supported for vmdk')

    def test_refuse_vhd(self):
        """Host-side format gate; discovered format name is `vpc`."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 't.vhd'
            self.make_vhd(img)
            self._assert_write_refused(
                img, None,
                'bench: write tests are not yet supported for vpc')

    def test_refuse_vhdx(self):
        """Host-side format gate; no guest launch, no /dev/kvm needed."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 't.vhdx'
            self.make_vhdx(img)
            self._assert_write_refused(
                img, None,
                'bench: write tests are not yet supported for vhdx')


class TestBenchJson(BenchTestBase):
    """The `--output json` schema (KVM; ~3 tests).

    Key-set presence is exact; key order is irrelevant (parsed via
    `json.loads`). Timing is never asserted for a value, only for
    type/positivity -- `elapsed-seconds` is a float > 0.
    """

    EXPECTED_KEYS = {
        'filename', 'format', 'count', 'depth', 'effective-depth',
        'buffer-size', 'step-size', 'offset', 'write', 'pattern',
        'flush-interval', 'no-drain', 'flushes-issued', 'elapsed-seconds',
        'requests-per-second', 'bytes-per-second',
    }

    def _run_json(self, *args):
        out, err, rc = self.run_instar_bench(*args, '--output', 'json')
        self.assertEqual(rc, 0, f'instar: {err}')
        return json.loads(out)

    def test_json_schema_keys_present(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            data = self._run_json('-c', '100', '-f', 'raw', str(img))
            self.assertEqual(set(data.keys()), self.EXPECTED_KEYS)

    def test_json_effective_depth_and_args_reflect(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)

            # Read test: depth echoed, effective-depth pinned at 1,
            # pattern/no-drain reflect args even without -w.
            img = td / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            data = self._run_json(
                '-c', '100', '-d', '5', '--pattern', '200', '--no-drain',
                '-f', 'raw', str(img))
            self.assertEqual(data['depth'], 5)
            self.assertEqual(data['effective-depth'], 1)
            self.assertEqual(data['write'], False)
            self.assertEqual(data['pattern'], 200)
            self.assertEqual(data['no-drain'], True)

            # Write test: write:true, pattern reflects the write value.
            wimg = td / 'w.qcow2'
            self.make_qcow2(wimg, size='16M')
            wdata = self._run_json(
                '-w', '-c', '100', '--pattern', '66', '-f', 'qcow2',
                str(wimg))
            self.assertEqual(wdata['write'], True)
            self.assertEqual(wdata['pattern'], 66)

    def test_json_elapsed_and_rates_positive(self):
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            data = self._run_json('-c', '100', '-f', 'raw', str(img))
            self.assertIsInstance(data['elapsed-seconds'], float)
            self.assertGreater(data['elapsed-seconds'], 0)
            self.assertIsInstance(data['requests-per-second'], (int, float))
            self.assertGreater(data['requests-per-second'], 0)
            self.assertIsInstance(data['bytes-per-second'], (int, float))
            self.assertGreater(data['bytes-per-second'], 0)


class TestBenchDivergenceRegression(BenchTestBase):
    """Assert each testable `KNOWN_BENCH_DIVERGENCES` entry still
    diverges (entries 2-7, 9-11 per Mission §2; 1 and 8 have no live
    regression test -- see their registry entries).

    Every test opens with `self.assertIn(key, KNOWN_BENCH_DIVERGENCES)`
    (the bitmap/map idiom) so the registry and the tests stay linked:
    removing an entry without removing its test fails loudly.
    """

    def test_wrap_rule_10_0_8_still_diverges(self):
        self.assertIn('wrap-rule-10-0-8', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'wrap.raw'
            self.make_raw_mbr(img, size='10240')
            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '5', '-s', '4096', '-S', '4096', '-f', 'raw', str(img))
            self.assertEqual(
                q_rc, 1,
                f'qemu-img 10.0.8 no longer EIOs on the wrap vector '
                f'(the divergence premise no longer holds): '
                f'stdout={q_out!r} stderr={q_err!r}')
            self.assertIn('Failed request: Input/output error', q_err)

    def test_cache_modes_refused_still_diverges(self):
        self.assertIn('cache-modes-refused', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '-t', 'none', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn("cache mode 'none' is not yet supported", i_err)

            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '-t', 'none', '-f', 'raw', str(img))
            self.assertEqual(
                q_rc, 0,
                f'qemu-img unexpectedly refused -t none (the divergence '
                f'premise no longer holds): stderr={q_err!r}')

    def test_aio_refused_still_diverges(self):
        self.assertIn('aio-refused', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '-i', 'threads', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn("aio backend 'threads' is not yet supported", i_err)

            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '-i', 'threads', '-f', 'raw', str(img))
            self.assertEqual(
                q_rc, 0,
                f'qemu-img unexpectedly refused -i threads (the '
                f'divergence premise no longer holds): stderr={q_err!r}')

    def test_native_aio_refused_still_diverges(self):
        self.assertIn('native-aio-refused', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '-n', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn('native AIO (-n) is not yet supported', i_err)

            # qemu also fails for -n alone, but for a different, unrelated
            # reason -- both fail, differently, not "qemu succeeds".
            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '-n', '-f', 'raw', str(img))
            self.assertNotEqual(
                q_rc, 0,
                f'qemu-img unexpectedly accepted -n (the divergence '
                f'premise changed): stdout={q_out!r}')
            self.assertNotIn('native AIO (-n) is not yet supported', q_err)

    def test_image_opts_refused_still_diverges(self):
        self.assertIn('image-opts-refused', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='4M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '--image-opts', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn('--image-opts is not yet supported', i_err)

            image_opts = f'driver=raw,file.filename={img}'
            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '--image-opts', image_opts)
            self.assertEqual(
                q_rc, 0,
                f'qemu-img unexpectedly refused --image-opts alone (the '
                f'divergence premise no longer holds): stderr={q_err!r}')

    def test_bufsize_cap_2mib_still_diverges(self):
        self.assertIn('bufsize-cap-2mib', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'raw.img'
            self.make_raw_mbr(img, size='10M')
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '3', '-s', '3M', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn(
                'bench: buffer sizes above 2 MiB are not yet supported',
                i_err)

            # -c 3 (not 100) keeps every request in-bounds on the 10 MiB
            # fixture, per the 4c capture's note on this exact row: with
            # more requests qemu's OWN `% image_size` wrap bug would EIO
            # first, masking the divergence this test targets.
            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '3', '-s', '3M', '-f', 'raw', str(img))
            self.assertEqual(
                q_rc, 0,
                f'qemu-img unexpectedly refused -s 3M (the divergence '
                f'premise no longer holds): stderr={q_err!r}')

    def test_zero_byte_early_failure_still_diverges(self):
        self.assertIn('zero-byte-early-failure', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'empty.raw'
            with open(img, 'wb'):
                pass
            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertEqual(
                i_out, '', 'instar must not print a header before '
                           'discovery fails')
            self.assertIn('error discovering backing chain', i_err)

            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '-f', 'raw', str(img))
            self.assertEqual(q_rc, 1, f'stdout={q_out!r} stderr={q_err!r}')
            self.assertNotEqual(
                q_out.strip(), '',
                'qemu-img is expected to print the header unconditionally')
            self.assertIn('Failed request: Input/output error', q_err)

    def test_write_formats_limited_still_diverges(self):
        self.assertIn('write-formats-limited', KNOWN_BENCH_DIVERGENCES)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cases = (
                ('vmdk', self.make_vmdk, 'vmdk'),
                ('vhd', self.make_vhd, 'vpc'),
                ('vhdx', self.make_vhdx, 'vhdx'),
            )
            for label, maker, fmt_name in cases:
                img = td / f'w.{label}'
                maker(img)
                i_out, i_err, i_rc = self.run_instar_bench(
                    '-w', '-c', '10', '--pattern', '65', str(img))
                self.assertEqual(
                    i_rc, 1, f'{label}: stdout={i_out!r} stderr={i_err!r}')
                self.assertIn(
                    f'bench: write tests are not yet supported for '
                    f'{fmt_name}',
                    i_err)

                qimg = td / f'q.{label}'
                shutil.copy2(img, qimg)
                q_out, q_err, q_rc = self.run_qemu_bench(
                    '-w', '-c', '10', '--pattern', '65', str(qimg))
                self.assertEqual(
                    q_rc, 0,
                    f'qemu-img unexpectedly refused a {label} write (the '
                    f'divergence premise no longer holds): '
                    f'stderr={q_err!r}')

    def test_secure_raw_detection_still_diverges(self):
        self.assertIn('secure-raw-detection', KNOWN_BENCH_DIVERGENCES)
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'nomagic.raw'
            r = subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', str(img), '4M'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f'create failed: {r.stderr}')

            i_out, i_err, i_rc = self.run_instar_bench(
                '-c', '10', '-f', 'raw', str(img))
            self.assertEqual(i_rc, 1, f'stdout={i_out!r} stderr={i_err!r}')
            self.assertIn('bench: unsupported input format', i_err)

            q_out, q_err, q_rc = self.run_qemu_bench(
                '-c', '10', '-f', 'raw', str(img))
            self.assertEqual(
                q_rc, 0,
                f'qemu-img unexpectedly refused the headerless raw file '
                f'(the divergence premise no longer holds): '
                f'stderr={q_err!r}')
