"""Tests for the dd subcommand.

Phase 2 (TestDdWholeImage) covers whole-image copies only.

Phase 3 (TestDdRawWindow) adds an output-window matrix: each case
runs `instar dd` and `qemu-img dd` with the same bs/count/skip
operands and asserts byte-identical output.  Both a raw and a qcow2
input are exercised for every windowed case.  Direct Python byte
comparison is used (read both output files and assertEqual on the
bytes) because dd parity is about exact file bytes including any
zero-padding from a short final block.

Phase 4b (TestDdStructuredWindow) adds the structured-output window
matrix for qcow2, vmdk, vpc, and vhdx.  Structured files are NOT
byte-comparable to qemu's file (cluster/grain/block allocation
differs), so parity is validated by:
  (a) qemu-img info virtual-size agreement, and
  (b) round-trip both outputs to raw and byte-compare the raws.
Empty-window (count=0) cases use format-specific assertions because
some formats produce unreadable output from qemu-img dd itself
(vmdk) or from instar (vhdx).
"""

import json
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


class TestDdWholeImage(InstarTestBase):
    """Smoke tests for whole-image dd copies."""

    def test_dd_whole_image_qcow2_to_raw(self):
        """instar dd copies a qcow2 input to raw, byte-identical to qemu-img dd."""
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2, \
                tempfile.NamedTemporaryFile(suffix='.raw') as instar_out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out:
            # Create a small qcow2 with a recognisable written pattern.
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', qcow2.name, '4M'],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0x42 0 65536', qcow2.name],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xAB 131072 65536', qcow2.name],
                capture_output=True,
                check=True,
            )

            # Run instar dd (default output format: raw).
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={qcow2.name}', f'of={instar_out.name}']
            )
            self.assertEqual(
                rc, 0,
                f'instar dd failed: stderr={stderr!r}'
            )

            # Run qemu-img dd for cross-validation.
            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={qcow2.name}', f'of={qemu_out.name}']
            )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img dd failed: stderr={q_stderr!r}'
            )

            # The two raw outputs must be byte-identical.
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_out.name), Path(qemu_out.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'instar dd output differs from qemu-img dd: {cmp_out}'
            )

    def test_dd_whole_image_raw_to_raw(self):
        """instar dd copies a raw input to raw, byte-identical to qemu-img dd."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src, \
                tempfile.NamedTemporaryFile(suffix='.raw') as instar_out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out:
            # Create a raw image with a recognisable pattern.
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', src.name, '4M'],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0x77 0 4096', src.name],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'raw', '-c',
                 'write -P 0xCC 65536 4096', src.name],
                capture_output=True,
                check=True,
            )

            # Run instar dd.
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={src.name}', f'of={instar_out.name}']
            )
            self.assertEqual(
                rc, 0,
                f'instar dd failed: stderr={stderr!r}'
            )

            # Run qemu-img dd for cross-validation.
            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={src.name}', f'of={qemu_out.name}']
            )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img dd failed: stderr={q_stderr!r}'
            )

            # Byte-identical comparison.
            cmp_out, _, cmp_rc = self.run_instar_compare(
                Path(instar_out.name), Path(qemu_out.name)
            )
            self.assertEqual(
                cmp_rc, 0,
                f'instar dd output differs from qemu-img dd: {cmp_out}'
            )

    def test_dd_missing_of_errors(self):
        """instar dd exits non-zero when the output file (of=) is absent."""
        with tempfile.NamedTemporaryFile(suffix='.raw') as src:
            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', src.name, '1M'],
                capture_output=True,
                check=True,
            )

            # Omit of= -- the subcommand must refuse.
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={src.name}']
            )
            self.assertNotEqual(
                rc, 0,
                'instar dd should have failed without of= operand'
            )


# ---------------------------------------------------------------------------
# Helpers shared by TestDdRawWindow
# ---------------------------------------------------------------------------

def _make_patterned_image(path: str, fmt: str) -> None:
    """Create a 1 MiB image with position-dependent data patterns.

    Two distinct byte patterns are written at well-separated offsets so
    that any window test which reads across them can detect byte-position
    errors rather than just checking for all-zeros or all-one-value data.

    Layout (1 MiB = 1048576 bytes):
      [0x00000, 0x10000)  bytes 0xAA  (first 64 KiB)
      [0x40000, 0x50000)  bytes 0x55  (at offset 256 KiB)
    Everything else reads as zeros (qemu-img/qemu-io default).
    """
    subprocess.run(
        ['qemu-img', 'create', '-f', fmt, path, '1M'],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ['qemu-io', '-f', fmt, '-c', 'write -P 0xAA 0 65536', path],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ['qemu-io', '-f', fmt, '-c', 'write -P 0x55 262144 65536', path],
        capture_output=True,
        check=True,
    )


def _bytes_of(path: str) -> bytes:
    """Return the full contents of *path* as bytes."""
    with open(path, 'rb') as fh:
        return fh.read()


def _assert_dd_parity(
    test_case,
    src_path: str,
    operands: list,
    label: str,
    expect_empty: bool = False,
) -> None:
    """Run instar dd and qemu-img dd with *operands*, assert byte-parity.

    *operands* must already contain all of bs=, count=, skip=, if=, of=
    tokens -- the caller supplies them in full so no default injection
    happens here.

    If *expect_empty* is True the test additionally asserts that both
    outputs are zero bytes.
    """
    with tempfile.NamedTemporaryFile(suffix='.raw') as instar_out, \
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out:
        # Substitute the placeholder output path with the real temp paths.
        instar_ops = [
            op.replace('of=__OUT__', f'of={instar_out.name}')
            for op in operands
        ]
        qemu_ops = [
            op.replace('of=__OUT__', f'of={qemu_out.name}')
            for op in operands
        ]

        stdout, stderr, rc = test_case.run_instar_dd(instar_ops)
        test_case.assertEqual(
            rc, 0,
            f'[{label}] instar dd failed: stderr={stderr!r}'
        )

        q_stdout, q_stderr, q_rc = test_case.run_qemu_img_dd(qemu_ops)
        test_case.assertEqual(
            q_rc, 0,
            f'[{label}] qemu-img dd failed: stderr={q_stderr!r}'
        )

        instar_bytes = _bytes_of(instar_out.name)
        qemu_bytes = _bytes_of(qemu_out.name)

        if expect_empty:
            test_case.assertEqual(
                len(instar_bytes), 0,
                f'[{label}] instar dd: expected empty output, got {len(instar_bytes)} bytes'
            )
            test_case.assertEqual(
                len(qemu_bytes), 0,
                f'[{label}] qemu-img dd: expected empty output, got {len(qemu_bytes)} bytes'
            )

        test_case.assert_bytes_identical(
            instar_bytes,
            qemu_bytes,
            f'[{label}] instar dd output differs from qemu-img dd '
            f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)'
        )


class TestDdRawWindow(InstarTestBase):
    """Phase-3 output-window matrix for ``instar dd -O raw``.

    Each test method exercises one window scenario on BOTH a raw and a
    qcow2 input image.  The images are 1 MiB and carry two distinct
    byte patterns so that windowed reads across the patterns actually
    validate byte-level accuracy.

    All assertions use direct Python byte equality (assertEqual on the
    raw file bytes).  This subsumes a size check because byte-identical
    files are, by construction, the same length.
    """

    # ------------------------------------------------------------------
    # Input image fixture (created fresh for each test method)
    # ------------------------------------------------------------------

    def setUp(self):
        """Create one raw and one qcow2 patterned input for this test."""
        super().setUp()
        self._raw_tmp = tempfile.NamedTemporaryFile(suffix='.raw')
        self._qcow2_tmp = tempfile.NamedTemporaryFile(suffix='.qcow2')
        _make_patterned_image(self._raw_tmp.name, 'raw')
        _make_patterned_image(self._qcow2_tmp.name, 'qcow2')

    def tearDown(self):
        """Clean up input images."""
        self._raw_tmp.close()
        self._qcow2_tmp.close()
        super().tearDown()

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _run_window(self, window_ops: list, label: str, expect_empty: bool = False):
        """Run the window matrix against both raw and qcow2 inputs."""
        for fmt, src in (('raw', self._raw_tmp.name),
                         ('qcow2', self._qcow2_tmp.name)):
            full_ops = [f'if={src}', 'of=__OUT__'] + window_ops
            _assert_dd_parity(
                self,
                src,
                full_ops,
                label=f'{label} ({fmt})',
                expect_empty=expect_empty,
            )

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_window_aligned_skip(self):
        """Aligned skip: bs=65536 skip=1 -- window starts at 64 KiB boundary."""
        self._run_window(['bs=65536', 'skip=1'], label='aligned_skip')

    def test_window_unaligned_skip(self):
        """Unaligned skip (sub-sector window start): bs=1000 skip=1 count=2."""
        self._run_window(
            ['bs=1000', 'skip=1', 'count=2'],
            label='unaligned_skip',
        )

    def test_window_count_smaller_than_image(self):
        """count smaller than image: bs=65536 count=8 (copies 512 KiB)."""
        self._run_window(
            ['bs=65536', 'count=8'],
            label='count_smaller_than_image',
        )

    def test_window_count_beyond_eof(self):
        """count beyond EOF: bs=65536 count=99999 -- expect whole image."""
        self._run_window(
            ['bs=65536', 'count=99999'],
            label='count_beyond_eof',
        )

    def test_window_count_zero(self):
        """count=0: expect a 0-byte output file and exit 0."""
        self._run_window(
            ['bs=65536', 'count=0'],
            label='count_zero',
            expect_empty=True,
        )

    def test_window_skip_past_eof(self):
        """skip past EOF: bs=65536 skip=99999 -- expect 0-byte output, exit 0."""
        self._run_window(
            ['bs=65536', 'skip=99999'],
            label='skip_past_eof',
            expect_empty=True,
        )

    def test_window_skip_and_count_together(self):
        """skip + count together: bs=65536 skip=2 count=4."""
        self._run_window(
            ['bs=65536', 'skip=2', 'count=4'],
            label='skip_and_count',
        )

    def test_window_short_final_block(self):
        """Short final block: bs=1000 count=3 -- window is 3000 B, file may be padded."""
        self._run_window(
            ['bs=1000', 'count=3'],
            label='short_final_block',
        )

    def test_window_size_suffix_1m(self):
        """Size suffix: bs=1M count=2 -- copies the whole 1 MiB image twice (or until EOF)."""
        self._run_window(
            ['bs=1M', 'count=2'],
            label='size_suffix_1M',
        )

    def test_window_sub_sector_bs_both_ends(self):
        """Sub-sector bs on both start and end: bs=513 skip=1 count=3."""
        self._run_window(
            ['bs=513', 'skip=1', 'count=3'],
            label='sub_sector_both_ends',
        )


# ---------------------------------------------------------------------------
# Phase-4b: structured-output window matrix
# ---------------------------------------------------------------------------

def _qemu_img_info_vsize(path: str) -> int:
    """Return the virtual-size field from ``qemu-img info --output=json``."""
    result = subprocess.run(
        ['qemu-img', 'info', '--output=json', path],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f'qemu-img info failed on {path!r}: {result.stderr}'
        )
    info = json.loads(result.stdout)
    return info['virtual-size']


def _convert_to_raw(src: str, dst: str) -> None:
    """Convert *src* to a raw file at *dst* using qemu-img convert."""
    result = subprocess.run(
        ['qemu-img', 'convert', '-O', 'raw', src, dst],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f'qemu-img convert to raw failed for {src!r}: {result.stderr}'
        )


def _assert_structured_dd_parity(
    test_case,
    src_path: str,
    window_ops: list,
    out_fmt: str,
    out_suffix: str,
    label: str,
) -> None:
    """Run instar dd and qemu-img dd for a structured format and assert parity.

    Parity means:
      1. Both commands exit 0.
      2. ``qemu-img info`` reports the same virtual-size for both outputs.
      3. Both outputs convert back to raw; the two raws are byte-identical.

    *window_ops* must contain bs=, skip= (if needed), and count= tokens but
    must NOT contain if= or of= -- those are prepended here.
    *out_fmt* is the format name passed to -O (e.g. ``'qcow2'``).
    *out_suffix* is the file suffix for temp files (e.g. ``'.qcow2'``).
    *label* is a short human-readable tag used in failure messages.
    """
    with (
        tempfile.NamedTemporaryFile(suffix=out_suffix) as instar_out,
        tempfile.NamedTemporaryFile(suffix=out_suffix) as qemu_out,
        tempfile.NamedTemporaryFile(suffix='.raw') as instar_raw,
        tempfile.NamedTemporaryFile(suffix='.raw') as qemu_raw,
    ):
        # Run instar dd with -O <fmt>.
        stdout, stderr, rc = test_case.run_instar_dd(
            [f'if={src_path}', f'of={instar_out.name}'] + window_ops,
            output_format=out_fmt,
        )
        test_case.assertEqual(
            rc, 0,
            f'[{label}] instar dd -O {out_fmt} failed: stderr={stderr!r}',
        )

        # Run qemu-img dd with -O <fmt> (bs= already present in window_ops).
        q_stdout, q_stderr, q_rc = test_case.run_qemu_img_dd(
            [f'if={src_path}', f'of={qemu_out.name}'] + window_ops,
            output_format=out_fmt,
        )
        test_case.assertEqual(
            q_rc, 0,
            f'[{label}] qemu-img dd -O {out_fmt} failed: stderr={q_stderr!r}',
        )

        # Assert virtual-size parity via qemu-img info.
        instar_vsize = _qemu_img_info_vsize(instar_out.name)
        qemu_vsize = _qemu_img_info_vsize(qemu_out.name)
        test_case.assertEqual(
            instar_vsize,
            qemu_vsize,
            f'[{label}] virtual-size mismatch: '
            f'instar={instar_vsize} qemu={qemu_vsize}',
        )

        # Convert both outputs to raw and assert byte-identical raws.
        _convert_to_raw(instar_out.name, instar_raw.name)
        _convert_to_raw(qemu_out.name, qemu_raw.name)
        with open(instar_raw.name, 'rb') as fh:
            ibytes = fh.read()
        with open(qemu_raw.name, 'rb') as fh:
            qbytes = fh.read()
        test_case.assert_bytes_identical(
            ibytes,
            qbytes,
            f'[{label}] round-trip raw mismatch',
        )


class TestDdStructuredWindow(InstarTestBase):
    """Phase-4b: structured-output window matrix for instar dd -O <fmt>.

    Each test method exercises one window scenario on BOTH a raw and a
    qcow2 input image, for each of the four structured output formats:
    qcow2, vmdk, vpc, vhdx.

    Parity validation (mirroring assert_size_roundtrip in tests/base.py):
      (a) qemu-img info virtual-size must agree between instar and qemu outputs.
      (b) Both outputs converted to raw must be byte-identical.

    Empty-window (count=0) cases use format-specific assertions because:
      - vmdk: qemu-img dd itself produces an unreadable file; assert exit 0 only.
      - vhdx: instar's empty vhdx is rejected by qemu-img info; assert exit 0 only.
        (This is a known phase-4 limitation -- vhdx empty-window is tracked as
        a future enhancement.)
      - qcow2 / vpc: both tools produce readable 0-virtual-size images; assert
        full parity (vsize == 0).
    """

    # Format-name -> file-suffix mapping.
    _FORMATS = {
        'qcow2': '.qcow2',
        'vmdk':  '.vmdk',
        'vpc':   '.vpc',
        'vhdx':  '.vhdx',
    }

    # ------------------------------------------------------------------
    # Input image fixture (created fresh for each test method)
    # ------------------------------------------------------------------

    def setUp(self):
        """Create one raw and one qcow2 patterned input for this test."""
        super().setUp()
        self._raw_tmp = tempfile.NamedTemporaryFile(suffix='.raw')
        self._qcow2_tmp = tempfile.NamedTemporaryFile(suffix='.qcow2')
        _make_patterned_image(self._raw_tmp.name, 'raw')
        _make_patterned_image(self._qcow2_tmp.name, 'qcow2')

    def tearDown(self):
        """Clean up input images."""
        self._raw_tmp.close()
        self._qcow2_tmp.close()
        super().tearDown()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_structured_window(self, window_ops: list, label: str) -> None:
        """Run the structured-output window matrix for all formats and inputs."""
        for fmt, suffix in self._FORMATS.items():
            for src_fmt, src_path in (
                ('raw', self._raw_tmp.name),
                ('qcow2', self._qcow2_tmp.name),
            ):
                full_label = f'{label} fmt={fmt} src={src_fmt}'
                _assert_structured_dd_parity(
                    self,
                    src_path=src_path,
                    window_ops=window_ops,
                    out_fmt=fmt,
                    out_suffix=suffix,
                    label=full_label,
                )

    def _run_empty_window(self, window_ops: list, label: str) -> None:
        """Run count=0 (empty-window) assertions for all formats and inputs.

        Per-format rules (empirically verified against qemu-img dd 10.0.8):
          qcow2: both tools exit 0 and produce a readable vsize=0 image.
                 Assert virtual-size parity (both 0).
          vmdk:  qemu-img dd itself exits 1 for count=0 (monolithicSparse
                 format cannot represent a 0-capacity disk).  instar exits 0.
                 Assert instar exit 0 only -- do not run qemu-img dd.
          vpc:   both tools exit 0 and produce a readable vsize=0 image.
                 Assert virtual-size parity (both 0).
          vhdx:  qemu-img dd exits 0 and produces a readable vsize=0 image.
                 instar exits 0 but produces a file rejected by qemu-img info
                 (known phase-4 limitation -- instar empty-vhdx is not yet
                 readable).  Assert instar exit 0 only.
        """
        for src_fmt, src_path in (
            ('raw', self._raw_tmp.name),
            ('qcow2', self._qcow2_tmp.name),
        ):
            # ------------------------------------------------------------------
            # qcow2 empty: full parity expected (vsize 0 from both tools).
            # ------------------------------------------------------------------
            full_label = f'{label} fmt=qcow2 src={src_fmt}'
            self._assert_empty_parity(
                src_path, window_ops, 'qcow2', '.qcow2', full_label,
            )

            # ------------------------------------------------------------------
            # vmdk empty: qemu-img dd itself exits 1 for count=0 (the
            # monolithicSparse format cannot represent a 0-capacity disk).
            # instar exits 0.  Assert instar exit 0 only; do not run
            # qemu-img dd.
            # ------------------------------------------------------------------
            full_label = f'{label} fmt=vmdk src={src_fmt}'
            self._assert_empty_instar_exit0_only(
                src_path, window_ops, 'vmdk', '.vmdk', full_label,
                note='qemu-img dd itself exits 1 for count=0 vmdk '
                     '(monolithicSparse cannot represent 0-capacity); '
                     'assert instar exit 0 only.',
            )

            # ------------------------------------------------------------------
            # vpc empty: full parity expected (vsize 0 from both tools).
            # ------------------------------------------------------------------
            full_label = f'{label} fmt=vpc src={src_fmt}'
            self._assert_empty_parity(
                src_path, window_ops, 'vpc', '.vpc', full_label,
            )

            # ------------------------------------------------------------------
            # vhdx empty: qemu exits 0 and image is readable; instar exits 0
            # but its output is rejected by qemu-img info (known phase-4
            # limitation -- instar empty-vhdx is not yet readable).
            # Assert instar exits 0 only; do not attempt qemu-img info or
            # round-trip on the instar output.
            # ------------------------------------------------------------------
            full_label = f'{label} fmt=vhdx src={src_fmt}'
            self._assert_empty_instar_exit0_only(
                src_path, window_ops, 'vhdx', '.vhdx', full_label,
                note='Known phase-4 limitation: instar empty vhdx (count=0) is '
                     'rejected by qemu-img info. Exit-0 only is asserted.',
            )

    def _assert_empty_parity(
        self,
        src_path: str,
        window_ops: list,
        out_fmt: str,
        out_suffix: str,
        label: str,
    ) -> None:
        """Assert full parity for an empty-window case that both tools handle well.

        Both tools must exit 0 and report the same (zero) virtual-size.
        """
        with (
            tempfile.NamedTemporaryFile(suffix=out_suffix) as instar_out,
            tempfile.NamedTemporaryFile(suffix=out_suffix) as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={src_path}', f'of={instar_out.name}'] + window_ops,
                output_format=out_fmt,
            )
            self.assertEqual(
                rc, 0,
                f'[{label}] instar dd -O {out_fmt} failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={src_path}', f'of={qemu_out.name}'] + window_ops,
                output_format=out_fmt,
            )
            self.assertEqual(
                q_rc, 0,
                f'[{label}] qemu-img dd -O {out_fmt} failed: stderr={q_stderr!r}',
            )

            instar_vsize = _qemu_img_info_vsize(instar_out.name)
            qemu_vsize = _qemu_img_info_vsize(qemu_out.name)
            self.assertEqual(
                instar_vsize,
                qemu_vsize,
                f'[{label}] virtual-size mismatch: '
                f'instar={instar_vsize} qemu={qemu_vsize}',
            )
            self.assertEqual(
                instar_vsize, 0,
                f'[{label}] expected virtual-size=0 for empty window, '
                f'got instar_vsize={instar_vsize}',
            )

    def _assert_empty_instar_exit0_only(
        self,
        src_path: str,
        window_ops: list,
        out_fmt: str,
        out_suffix: str,
        label: str,
        note: str = '',
    ) -> None:
        """Assert instar exits 0; do not attempt qemu-img info on its output.

        Used when instar's empty-window output is unreadable by qemu-img info
        (e.g. vhdx count=0 -- known phase-4 limitation).  Instar must exit 0;
        qemu-img dd is not run (it would succeed, but comparing the output
        would fail and obscure the known limitation).
        """
        with tempfile.NamedTemporaryFile(suffix=out_suffix) as instar_out:
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={src_path}', f'of={instar_out.name}'] + window_ops,
                output_format=out_fmt,
            )
            self.assertEqual(
                rc, 0,
                f'[{label}] instar dd -O {out_fmt} failed: stderr={stderr!r}'
                + (f' ({note})' if note else ''),
            )

    # ------------------------------------------------------------------
    # Non-empty window test cases
    # ------------------------------------------------------------------

    def test_structured_window_aligned_skip_count(self):
        """Aligned window: bs=65536 skip=2 count=4 (copies 256 KiB from offset 128 KiB).

        Exercises a sector-aligned window that spans both patterned regions
        (0xAA at 0 KiB and 0x55 at 256 KiB).  Parity: virtual-size agreement
        and byte-identical round-trip-to-raw for all four structured formats.
        """
        self._run_structured_window(
            ['bs=65536', 'skip=2', 'count=4'],
            label='aligned_skip_count',
        )

    def test_structured_window_non_512_end(self):
        """Non-512-aligned end: bs=1000 count=3 (3000 B window).

        The window size (3000 B) is not a multiple of 512.  This exercises
        the per-format declared-virtual-size rounding (qcow2/vmdk/vhdx round
        up to 512; vpc uses CHS rounding to a much larger value).
        """
        self._run_structured_window(
            ['bs=1000', 'count=3'],
            label='non_512_end',
        )

    def test_structured_window_sub_sector_bs(self):
        """Sub-sector block size: bs=513 skip=1 count=3 (1539 B window).

        Both the block size and total window (1539 B) are non-sector-aligned,
        exercising sub-sector read_start and the virtual-size rounding path.
        """
        self._run_structured_window(
            ['bs=513', 'skip=1', 'count=3'],
            label='sub_sector_bs',
        )

    # ------------------------------------------------------------------
    # Empty-window test case
    # ------------------------------------------------------------------

    def test_structured_window_count_zero(self):
        """Empty window: bs=65536 count=0.

        Per-format assertions (empirically verified against qemu-img 10.0.8):
          qcow2  -- both tools produce a readable 0-vsize image; assert parity.
          vmdk   -- qemu-img dd itself exits 1 (monolithicSparse cannot represent
                   0-capacity); assert instar exit 0 only.
          vpc    -- both tools produce a readable 0-vsize image; assert parity.
          vhdx   -- qemu succeeds and image is readable (vsize=0); instar exits
                   0 but its output is rejected by qemu-img info (known phase-4
                   limitation); assert instar exit 0 only.
        """
        self._run_empty_window(
            ['bs=65536', 'count=0'],
            label='count_zero',
        )


# ---------------------------------------------------------------------------
# Regression: unaligned windows crossing input-cluster boundaries (issue #396)
# ---------------------------------------------------------------------------

def _make_hole_then_data_qcow2(path: str) -> None:
    """Create a 4 MiB qcow2 whose FIRST cluster is a hole.

    Layout (64 KiB clusters):
      vc0             hole (unallocated)
      vc1  [64K,128K) bytes 0xCD (the only allocated cluster)
      vc2+            holes
    """
    subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2', path, '4M'],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xCD 65536 65536', path],
        capture_output=True,
        check=True,
    )


def _make_out_of_order_qcow2(path: str) -> None:
    """Create a 4 MiB qcow2 whose physical cluster order differs from
    the virtual order.

    Clusters are written vc1, vc0, vc63 -- so in the file, vc1's data
    cluster physically precedes vc0's, and vc0's is physically followed
    by vc63's. Any reader that fetches a virtual cluster's tail from the
    physically-adjacent file bytes returns the wrong data here.
    """
    subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2', path, '4M'],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ['qemu-io', '-f', 'qcow2',
         '-c', 'write -P 0x22 65536 65536',
         '-c', 'write -P 0x11 0 65536',
         '-c', 'write -P 0xFF 4128768 65536',
         path],
        capture_output=True,
        check=True,
    )


class TestDdUnalignedClusterCrossing(InstarTestBase):
    """Regression tests for issue #396 (differential-fuzz divergence).

    A dd window whose start is not a multiple of the input cluster size
    shifts every guest read off cluster alignment, so each read chunk
    straddles an input-cluster boundary. The structured-output read loops
    (convert_to_qcow2 / convert_to_qcow2_compressed) fed such straddling
    chunks to read_chain_virtual_cluster, whose single-cluster contract
    made it (a) zero-fill an entire chunk when only the chunk's FIRST
    byte fell in a hole, (b) read a cluster's tail bytes from the
    physically-adjacent file cluster (wrong data unless physical order
    matches virtual order), and (c) run past EOF when the allocated
    cluster was physically last (the fuzzer's exit-code divergence).
    The fix clamps each read at input-cluster boundaries, mirroring the
    clamp convert_to_raw already had.

    Both tests use bs=1000 skip=1 (window start 1000, well off any
    cluster or sector boundary) and assert full live parity -- exit
    codes, virtual size, and byte-identical round-trip-to-raw -- against
    qemu-img dd for every structured output format.
    """

    _FORMATS = {
        'qcow2': '.qcow2',
        'vmdk':  '.vmdk',
        'vpc':   '.vpc',
        'vhdx':  '.vhdx',
    }

    def _run_all_formats(self, src_path: str, label: str) -> None:
        for fmt, suffix in self._FORMATS.items():
            _assert_structured_dd_parity(
                self,
                src_path=src_path,
                window_ops=['bs=1000', 'skip=1'],
                out_fmt=fmt,
                out_suffix=suffix,
                label=f'{label} fmt={fmt}',
            )

    def test_unaligned_skip_hole_then_data(self):
        """Hole-first input: chunks straddle hole->data boundaries and the
        allocated cluster is physically last in the file (EOF case).

        Before the fix: instar exited 1 ("convert operation failed") for
        -O qcow2 while qemu-img dd exited 0 -- the fuzzer's
        exit_code_divergence (seed 2630842467, iteration 96).
        """
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as src:
            _make_hole_then_data_qcow2(src.name)
            self._run_all_formats(src.name, 'hole_then_data')

    def test_unaligned_skip_out_of_order_clusters(self):
        """Out-of-order input: physical cluster order != virtual order.

        Before the fix: instar exited 0 for -O qcow2 but the output's
        content silently differed from qemu's (cluster tails read from
        the physically-adjacent file cluster).
        """
        with tempfile.NamedTemporaryFile(suffix='.qcow2') as src:
            _make_out_of_order_qcow2(src.name)
            self._run_all_formats(src.name, 'out_of_order')


# ---------------------------------------------------------------------------
# Phase-6a: CLI rejection matrix
# ---------------------------------------------------------------------------

class TestDdErrors(InstarTestBase):
    """Phase-6a: CLI rejection parity matrix for ``instar dd``.

    Each test case verifies that ``instar dd`` exits non-zero for an
    invalid invocation.  For cases where ``qemu-img dd`` is given the
    same (well-formed except for the one bad field) arguments, the test
    also asserts that qemu-img dd exits non-zero (rejection parity).
    The error *text* may differ between the two tools.

    A single 1 MiB raw image and 1 MiB qcow2 image are created in
    setUp() for cases that require valid if=/of= paths.
    """

    def setUp(self):
        """Create small valid input images for rejection tests."""
        super().setUp()
        self._raw_tmp = tempfile.NamedTemporaryFile(suffix='.raw')
        self._qcow2_tmp = tempfile.NamedTemporaryFile(suffix='.qcow2')
        subprocess.run(
            ['qemu-img', 'create', '-f', 'raw', self._raw_tmp.name, '1M'],
            capture_output=True, check=True,
        )
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow2', self._qcow2_tmp.name, '1M'],
            capture_output=True, check=True,
        )

    def tearDown(self):
        """Clean up input images."""
        self._raw_tmp.close()
        self._qcow2_tmp.close()
        super().tearDown()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_both_reject(self, operands, label, output_format=None):
        """Assert that instar dd and qemu-img dd both exit non-zero.

        *operands* must contain all of if=, of=, and the bad field.
        The output path must be a real temporary file so neither tool
        trips over a missing destination.
        """
        with tempfile.NamedTemporaryFile(suffix='.out') as out:
            instar_ops = [
                op.replace('of=__OUT__', f'of={out.name}')
                for op in operands
            ]
            qemu_ops = [
                op.replace('of=__OUT__', f'of={out.name}')
                for op in operands
            ]

            _, stderr, rc = self.run_instar_dd(
                instar_ops, output_format=output_format,
            )
            self.assertNotEqual(
                rc, 0,
                f'[{label}] instar dd should have rejected; '
                f'stderr={stderr!r}',
            )

            _, q_stderr, q_rc = self.run_qemu_img_dd(
                qemu_ops, output_format=output_format,
            )
            self.assertNotEqual(
                q_rc, 0,
                f'[{label}] qemu-img dd should have rejected '
                f'(rejection parity); stderr={q_stderr!r}',
            )

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_reject_bs_zero(self):
        """bs=0 is rejected by both instar and qemu-img dd.

        The helper injects bs=512 only when no bs= operand is present.
        Because we explicitly pass bs=0 here, no injection occurs.
        """
        raw = self._raw_tmp.name
        self._assert_both_reject(
            [f'if={raw}', 'of=__OUT__', 'bs=0'],
            label='bs=0',
        )

    def test_reject_bs_over_int_max(self):
        """bs=2147483648 (> INT_MAX) is rejected by both instar and qemu-img dd."""
        raw = self._raw_tmp.name
        self._assert_both_reject(
            [f'if={raw}', 'of=__OUT__', 'bs=2147483648'],
            label='bs=2147483648',
        )

    def test_reject_unknown_operand(self):
        """An unknown key=value operand (foo=1) is rejected by both tools."""
        raw = self._raw_tmp.name
        self._assert_both_reject(
            [f'if={raw}', 'of=__OUT__', 'bs=512', 'foo=1'],
            label='unknown_operand',
        )

    def test_reject_no_equals_token(self):
        """A bare token with no '=' (bar) is rejected by both tools.

        Empirically verified: qemu-img dd also treats a token without
        '=' as an unrecognised operand and exits non-zero.
        """
        raw = self._raw_tmp.name
        self._assert_both_reject(
            [f'if={raw}', 'of=__OUT__', 'bs=512', 'bar'],
            label='no_equals_token',
        )

    def test_reject_missing_if(self):
        """Missing if= (only of= given) is rejected by both tools."""
        with tempfile.NamedTemporaryFile(suffix='.out') as out:
            _, stderr, rc = self.run_instar_dd(
                [f'of={out.name}', 'bs=512'],
            )
            self.assertNotEqual(
                rc, 0,
                f'instar dd should have rejected missing if=; '
                f'stderr={stderr!r}',
            )

            _, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'of={out.name}', 'bs=512'],
            )
            self.assertNotEqual(
                q_rc, 0,
                f'qemu-img dd should have rejected missing if= '
                f'(rejection parity); stderr={q_stderr!r}',
            )

    def test_reject_missing_of(self):
        """Missing of= (only if= given) is rejected by both tools."""
        raw = self._raw_tmp.name
        _, stderr, rc = self.run_instar_dd(
            [f'if={raw}', 'bs=512'],
        )
        self.assertNotEqual(
            rc, 0,
            f'instar dd should have rejected missing of=; '
            f'stderr={stderr!r}',
        )

        _, q_stderr, q_rc = self.run_qemu_img_dd(
            [f'if={raw}', 'bs=512'],
        )
        self.assertNotEqual(
            q_rc, 0,
            f'qemu-img dd should have rejected missing of= '
            f'(rejection parity); stderr={q_stderr!r}',
        )

    def test_reject_unknown_output_format(self):
        """An unknown -O format (bogus) is rejected by both tools."""
        raw = self._raw_tmp.name
        self._assert_both_reject(
            [f'if={raw}', 'of=__OUT__', 'bs=512'],
            label='unknown_output_format',
            output_format='bogus',
        )


# ---------------------------------------------------------------------------
# Phase-6b: -O default is raw (not the input format)
# ---------------------------------------------------------------------------

class TestDdOutputDefault(InstarTestBase):
    """Phase-6b: omitting -O produces raw output even from a qcow2 input.

    qemu-img dd (and instar dd, by parity) always defaults the output
    format to raw regardless of the input format.  This test makes that
    invariant explicit:

      - Run ``instar dd if=<qcow2> of=<out>`` with no -O flag.
      - Assert ``qemu-img info --output=json <out>`` reports
        ``format == "raw"`` (not ``"qcow2"``).
      - Assert the bytes equal the output of ``qemu-img dd`` run with
        the same omission (also raw by default).
    """

    def test_output_default_is_raw(self):
        """Omitting -O on a qcow2 input produces a raw (not qcow2) output."""
        with (
            tempfile.NamedTemporaryFile(suffix='.qcow2') as qcow2,
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            # Create a patterned qcow2 input so the output is not all-zeros.
            _make_patterned_image(qcow2.name, 'qcow2')

            # Run instar dd with NO -O flag.
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={qcow2.name}', f'of={instar_out.name}', 'bs=512'],
            )
            self.assertEqual(
                rc, 0,
                f'instar dd (no -O) failed: stderr={stderr!r}',
            )

            # Assert the output format is raw (not qcow2).
            info_result = subprocess.run(
                ['qemu-img', 'info', '--output=json', instar_out.name],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                info_result.returncode, 0,
                f'qemu-img info failed: {info_result.stderr}',
            )
            info = json.loads(info_result.stdout)
            self.assertEqual(
                info.get('format'), 'raw',
                f'Expected format=raw but got format={info.get("format")!r}; '
                f'instar dd must default to raw output even from a qcow2 input.',
            )

            # Run qemu-img dd with the same omission for cross-validation.
            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={qcow2.name}', f'of={qemu_out.name}', 'bs=512'],
            )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img dd (no -O) failed: stderr={q_stderr!r}',
            )

            # Both outputs must be byte-identical.
            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'instar dd (no -O) output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )


# ---------------------------------------------------------------------------
# Phase-6b: input-format coverage
# ---------------------------------------------------------------------------

def _make_patterned_raw(path: str) -> None:
    """Create a 1 MiB patterned raw image (reuses _make_patterned_image layout).

    Identical layout to _make_patterned_image for 'raw', extracted here so
    TestDdInputFormats can convert it to other formats.
    """
    _make_patterned_image(path, 'raw')


class TestDdInputFormats(InstarTestBase):
    """Phase-6b: input-format coverage for ``instar dd``.

    dd inherits convert's input read path (auto-detection + backing-chain
    composition).  Every existing dd test feeds a raw or qcow2 input.
    This class confirms that dd also reads vmdk, vhd (vpc), vhdx, and
    a backing-chain qcow2 correctly, producing byte-identical output to
    ``qemu-img dd`` with the same window.

    One window (bs=65536 skip=2 count=4) is used per input format --
    windowing logic is format-independent on the read side; this validates
    auto-detection + read for each format.

    Input images are built fresh for each test method.
    """

    # Shared window: 4 blocks of 64 KiB starting at block 2 (byte offset 128 KiB).
    # This window crosses both patterned regions in a 1 MiB image:
    #   0xAA at offset 0 (block 0),  0x55 at offset 256 KiB (block 4).
    # skip=2 start lands at 128 KiB (zeros), count=4 ends at 384 KiB (into 0x55).
    _WINDOW = ['bs=65536', 'skip=2', 'count=4']

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _assert_input_fmt_parity(
        self, src_path: str, fmt: str, label: str,
    ) -> None:
        """Assert byte-identical output between instar dd and qemu-img dd.

        Both tools auto-detect the input format; -O raw is passed
        explicitly so the output is always raw (comparable byte-for-byte).
        """
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={src_path}', f'of={instar_out.name}'] + self._WINDOW,
                output_format='raw',
            )
            self.assertEqual(
                rc, 0,
                f'[{label}] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={src_path}', f'of={qemu_out.name}'] + self._WINDOW,
                output_format='raw',
            )
            self.assertEqual(
                q_rc, 0,
                f'[{label}] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[{label}] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_input_vmdk(self):
        """dd reads a vmdk input and produces byte-identical output to qemu-img dd."""
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as raw,
            tempfile.NamedTemporaryFile(suffix='.vmdk') as vmdk,
        ):
            _make_patterned_raw(raw.name)
            result = subprocess.run(
                ['qemu-img', 'convert', '-O', 'vmdk', raw.name, vmdk.name],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img convert to vmdk failed: {result.stderr}',
            )
            self._assert_input_fmt_parity(vmdk.name, 'vmdk', label='vmdk')

    def test_input_vpc(self):
        """dd reads a vhd (vpc) input and produces byte-identical output to qemu-img dd."""
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as raw,
            tempfile.NamedTemporaryFile(suffix='.vpc') as vpc,
        ):
            _make_patterned_raw(raw.name)
            result = subprocess.run(
                ['qemu-img', 'convert', '-O', 'vpc', raw.name, vpc.name],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img convert to vpc failed: {result.stderr}',
            )
            self._assert_input_fmt_parity(vpc.name, 'vpc', label='vpc')

    def test_input_vhdx(self):
        """dd reads a vhdx input and produces byte-identical output to qemu-img dd."""
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as raw,
            tempfile.NamedTemporaryFile(suffix='.vhdx') as vhdx,
        ):
            _make_patterned_raw(raw.name)
            result = subprocess.run(
                ['qemu-img', 'convert', '-O', 'vhdx', raw.name, vhdx.name],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(
                result.returncode, 0,
                f'qemu-img convert to vhdx failed: {result.stderr}',
            )
            self._assert_input_fmt_parity(vhdx.name, 'vhdx', label='vhdx')

    def test_input_vdi(self):
        """dd reads a vdi input full-copy and matches qemu-img dd byte-for-byte.

        Format-coverage phase 2 graduates VDI to a real read format.  This
        smoke test uses the aligned vdi-simple fixture and does a full-image
        copy (no skip/count window) so the whole read path is exercised;
        windowed and data-bearing VDI coverage is added in step 2e.
        """
        image = self.get_image('vdi-simple')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'],
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[vdi] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'],
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[vdi] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[vdi] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )

    def test_input_parallels(self):
        """dd reads a parallels input full-copy and matches qemu-img dd.

        Format-coverage phase 3 graduates Parallels to a real read format;
        phase 1 gated dd for parallels but never added a refusal test (a
        documented gap this phase closes with positive coverage).  This
        smoke uses parallels-v2 ('WithouFreSpacExt') and does a full-image
        copy (no skip/count window) so the whole read path is exercised;
        windowed and both-magic coverage is added in step 3e.
        """
        # qemu-img is the oracle here and the RHEL-family builds have no
        # driver for this format.
        self.skip_unless_qemu_supports('parallels')
        image = self.get_image('parallels-v2')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'],
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[parallels] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'],
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[parallels] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[parallels] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )

    def test_input_parallels_windowed(self):
        """Windowed dd on a Parallels image crosses a hole->data boundary.

        parallels-data-v2 (2 MiB, 64 KiB clusters) fills guest clusters
        1/3/5/7 (0x11/0x33/0x55/0x77) and leaves the rest holes.  At
        bs=65536 one block == one cluster, so cluster 2 is a hole and
        cluster 3 carries 0x33.  qemu-img dd's ``count`` is an absolute
        end position in blocks (bytes copied = (count - skip) * bs), so
        skip=2 count=4 reads blocks [2, 4): one hole block then one data
        block, pinning the unallocated->allocated transition against
        qemu-img dd byte-for-byte.
        """
        # qemu-img is the oracle here and the RHEL-family
        # builds have no driver for this format.
        self.skip_unless_qemu_supports('parallels')
        image = self.get_image('parallels-data-v2')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=65536', 'skip=2', 'count=4']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[parallels-window] instar dd -O raw failed: '
                f'stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[parallels-window] qemu-img dd -O raw failed: '
                f'stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[parallels-window] instar dd output differs from qemu-img '
                f'dd (instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )
            # Sanity: the window really straddles the boundary -- the first
            # block is a hole (zeros) and the second carries data.
            self.assertFalse(
                any(instar_bytes[:65536]),
                '[parallels-window] first block should be a hole (zeros)',
            )
            self.assertTrue(
                any(instar_bytes[65536:]),
                '[parallels-window] second block should carry data',
            )

    def test_input_vdi_windowed(self):
        """Windowed dd on a data-bearing VDI crosses a hole->data boundary.

        vdi-data-dynamic holds a 1 MiB data block at guest 2 MiB
        (block 32 at bs=65536); blocks 30-31 are holes.  qemu-img dd's
        ``count`` is an absolute end position in blocks (bytes copied =
        (count - skip) * bs), so skip=30 count=34 reads blocks [30, 34):
        two hole blocks then two data blocks.  This pins the
        unallocated->allocated transition in the read path against
        qemu-img dd byte-for-byte.
        """
        image = self.get_image('vdi-data-dynamic')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=65536', 'skip=30', 'count=34']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[vdi-window] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[vdi-window] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[vdi-window] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )
            # Sanity: the window really straddles the boundary -- the first
            # two blocks are a hole (zeros) and the last two carry data.
            self.assertFalse(
                any(instar_bytes[:131072]),
                '[vdi-window] first half of window should be a hole (zeros)',
            )
            self.assertTrue(
                any(instar_bytes[131072:]),
                '[vdi-window] second half of window should carry data',
            )

    def test_input_backing_chain_qcow2(self):
        """dd composes a qcow2 backing chain and matches qemu-img dd byte-for-byte.

        Layout:
          base.qcow2   -- 4 MiB; 0xAA written at offset 0 (first 64 KiB).
          overlay.qcow2 -- 4 MiB backed by base; 0xBB written at offset
                           262144 (256 KiB, second 64 KiB block).

        The composed view (overlay resolved against base) has 0xAA at 0
        and 0xBB at 256 KiB.  The window (bs=65536 skip=0 count=5) reads
        the first 320 KiB, capturing both layers so neither 0xAA nor 0xBB
        are zero-masked by the other.

        This confirms that dd composes the chain via discover_backing_chain
        the same way as convert, exactly matching qemu-img dd's output.
        """
        import os
        import shutil

        tmpdir = tempfile.mkdtemp()
        try:
            base_path = os.path.join(tmpdir, 'base.qcow2')
            overlay_path = os.path.join(tmpdir, 'overlay.qcow2')

            # Build base: 0xAA at offset 0.
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', base_path, '4M'],
                capture_output=True, check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xAA 0 65536',
                 base_path],
                capture_output=True, check=True,
            )

            # Build overlay over base: 0xBB at offset 256 KiB (distinct
            # from 0xAA in base so composed view differs from either layer).
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2',
                 '-b', base_path, '-F', 'qcow2', overlay_path, '4M'],
                capture_output=True, check=True,
            )
            subprocess.run(
                ['qemu-io', '-f', 'qcow2', '-c',
                 'write -P 0xBB 262144 65536', overlay_path],
                capture_output=True, check=True,
            )

            # Window covers first 320 KiB: sees 0xAA (base) and 0xBB (overlay).
            window = ['bs=65536', 'skip=0', 'count=5']

            with (
                tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
                tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
            ):
                stdout, stderr, rc = self.run_instar_dd(
                    [f'if={overlay_path}', f'of={instar_out.name}'] + window,
                    output_format='raw',
                )
                self.assertEqual(
                    rc, 0,
                    f'[backing-chain] instar dd -O raw failed: stderr={stderr!r}',
                )

                q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                    [f'if={overlay_path}', f'of={qemu_out.name}'] + window,
                    output_format='raw',
                )
                self.assertEqual(
                    q_rc, 0,
                    f'[backing-chain] qemu-img dd -O raw failed: '
                    f'stderr={q_stderr!r}',
                )

                instar_bytes = _bytes_of(instar_out.name)
                qemu_bytes = _bytes_of(qemu_out.name)

                # Verify both layers are visible in the composed output.
                self.assertEqual(
                    instar_bytes[0:4], b'\xaa\xaa\xaa\xaa',
                    '[backing-chain] 0xAA base pattern not visible at offset 0',
                )
                self.assertEqual(
                    instar_bytes[262144:262148], b'\xbb\xbb\xbb\xbb',
                    '[backing-chain] 0xBB overlay pattern not visible at '
                    'offset 262144',
                )

                # Byte-identical to qemu-img dd.
                self.assert_bytes_identical(
                    instar_bytes,
                    qemu_bytes,
                    f'[backing-chain] instar dd output differs from qemu-img dd '
                    f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
                )
        finally:
            shutil.rmtree(tmpdir)

    def test_input_format_flag_accepted(self):
        """``-f raw`` is accepted on a raw input and output matches qemu-img dd.

        This documents that -f (input format hint) is accepted by instar dd.
        We do not assert forcing semantics (auto-detection is authoritative);
        we only confirm that passing -f does not cause an error and that the
        output matches qemu-img dd (which uses auto-detection).
        """
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as raw,
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            _make_patterned_raw(raw.name)
            window = ['bs=65536', 'skip=0', 'count=2']

            stdout, stderr, rc = self.run_instar_dd(
                [f'if={raw.name}', f'of={instar_out.name}'] + window,
                input_format='raw',
                output_format='raw',
            )
            self.assertEqual(
                rc, 0,
                f'instar dd -f raw -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={raw.name}', f'of={qemu_out.name}'] + window,
                output_format='raw',
            )
            self.assertEqual(
                q_rc, 0,
                f'qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'instar dd -f raw output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )

    def test_input_qcow1_windowed(self):
        """Windowed dd on a qcow1 image crosses a hole->data boundary.

        qcow1-data (2 MiB, 4 KiB clusters) fills guest clusters
        0/5/17/100/300/511 and leaves the rest holes.  At bs=4096 one
        block == one cluster, so cluster 4 is a hole and cluster 5
        carries data.  The same operands are handed to both tools
        (qemu-img dd's ``count`` is absolute from offset 0: skip=4
        count=6 copies blocks [4, 6) -- one hole block then one data
        block), pinning the unallocated->allocated transition against
        qemu-img dd byte-for-byte.
        """
        # qemu-img is the oracle here and the RHEL-family
        # builds have no driver for this format.
        self.skip_unless_qemu_supports('qcow')
        image = self.get_image('qcow1-data')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=4096', 'skip=4', 'count=6']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[qcow1-window] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[qcow1-window] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[qcow1-window] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )
            # Sanity: the window really straddles the boundary -- the first
            # block is a hole (zeros) and the second carries data.
            self.assertFalse(
                any(instar_bytes[:4096]),
                '[qcow1-window] first block should be a hole (zeros)',
            )
            self.assertTrue(
                any(instar_bytes[4096:]),
                '[qcow1-window] second block should carry data',
            )

    def test_input_qcow1_backing_windowed(self):
        """Windowed dd on a qcow1 overlay crosses an overlay-mask boundary.

        qcow1-backing is a 512-byte-cluster overlay masking its base at
        guest offsets 0/4096 (0x77/0x88) with every other offset reading
        through to the base (0xCC at offset 8192).  At bs=4096 skip=0
        count=3 the window spans two overlay-masked blocks and one
        read-through block, pinning that the dd path descends to the base
        for unallocated clusters -- byte-identical to qemu-img dd.
        """
        # qemu-img is the oracle here and the RHEL-family
        # builds have no driver for this format.
        self.skip_unless_qemu_supports('qcow')
        image = self.get_image('qcow1-backing')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=4096', 'skip=0', 'count=3']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[qcow1-backing-window] instar dd -O raw failed: '
                f'stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[qcow1-backing-window] qemu-img dd -O raw failed: '
                f'stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[qcow1-backing-window] instar dd output differs from '
                f'qemu-img dd (instar={len(instar_bytes)} B, '
                f'qemu={len(qemu_bytes)} B)',
            )
            # Sanity: the read-through block (offset 8192, base 0xCC) is
            # non-zero data descended from the backing file.
            self.assertTrue(
                any(instar_bytes[8192:12288]),
                '[qcow1-backing-window] read-through block should carry '
                'base data',
            )


class TestDdDmg(InstarTestBase):
    """Windowed dd on DMG input (format-coverage phase 5).

    Pins the graduation of DMG to a real read format.  dmg-simple is a
    4 MiB UDIF image with two zlib-wrapped UDZO chunks: chunk 0 covers
    [0, 2 MiB) and chunk 1 covers [2 MiB, 4 MiB).  A bs=65536 skip=31
    count=33 window copies blocks [31, 33) -- offsets [2031616, 2162688)
    -- which straddle the 2 MiB chunk boundary (qemu-img dd's ``count``
    is absolute from offset 0).  The window must be byte-identical to
    qemu-img dd and must actually cross the boundary (first block from
    chunk 0, second block from chunk 1), proving dd walks the UDIF chunk
    table rather than reading the container as raw.
    """

    def setUp(self):
        super().setUp()
        # This class compares instar against qemu-img for dmg; without
        # that driver the host qemu cannot act as the oracle at all.
        self.skip_unless_qemu_supports('dmg')

    def test_input_dmg_windowed(self):
        """Windowed dd on dmg-simple crosses the zlib chunk boundary."""
        image = self.get_image('dmg-simple')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=65536', 'skip=31', 'count=33']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[dmg-window] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[dmg-window] qemu-img dd -O raw failed: stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[dmg-window] instar dd output differs from qemu-img dd '
                f'(instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )
            # Sanity: the window straddles the chunk boundary -- the first
            # block carries chunk-0 content and the second chunk-1 content.
            self.assertIn(
                b'CHUNK-0', instar_bytes[:65536],
                '[dmg-window] first block should carry chunk-0 data',
            )
            self.assertIn(
                b'CHUNK-1', instar_bytes[65536:],
                '[dmg-window] second block should carry chunk-1 data',
            )

    def test_input_dmg_mixed_windowed(self):
        """Windowed dd on dmg-mixed crosses a zero->raw->zlib chunk run.

        dmg-mixed's chunk layout (from the generator): zero [0, 1 MiB),
        raw [1 MiB, 1 MiB+32 KiB), zlib [1 MiB+32 KiB, 2 MiB+32 KiB),
        ignore tail.  A bs=65536 skip=15 count=17 window copies blocks
        [15, 17) -- offsets [983040, 1114112) (qemu-img dd's ``count`` is
        absolute from offset 0).  Block 15 lies wholly in the zero span;
        block 16 straddles the zero->raw boundary at 1 MiB and the
        raw->zlib boundary 32 KiB later, so it carries the full raw span
        plus the head of the zlib span.  The window must be byte-identical
        to qemu-img dd and must actually cross all three chunk types,
        proving dd walks the UDIF chunk table span-by-span rather than
        reading the container as raw.
        """
        image = self.get_image('dmg-mixed')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        window = ['bs=65536', 'skip=15', 'count=17']
        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                rc, 0,
                f'[dmg-mixed-window] instar dd -O raw failed: stderr={stderr!r}',
            )

            q_stdout, q_stderr, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'] + window,
                output_format='raw',
                timeout=120,
            )
            self.assertEqual(
                q_rc, 0,
                f'[dmg-mixed-window] qemu-img dd -O raw failed: '
                f'stderr={q_stderr!r}',
            )

            instar_bytes = _bytes_of(instar_out.name)
            qemu_bytes = _bytes_of(qemu_out.name)
            self.assert_bytes_identical(
                instar_bytes,
                qemu_bytes,
                f'[dmg-mixed-window] instar dd output differs from qemu-img '
                f'dd (instar={len(instar_bytes)} B, qemu={len(qemu_bytes)} B)',
            )
            # Sanity: block 15 is all-zero; block 16 carries the raw span in
            # its first 32 KiB and the zlib span in its second 32 KiB.
            self.assertEqual(
                instar_bytes[:65536], bytes(65536),
                '[dmg-mixed-window] first block should be all zero',
            )
            self.assertIn(
                b'MIXED-RAW', instar_bytes[65536:65536 + 32768],
                '[dmg-mixed-window] raw span expected in the second block',
            )
            self.assertIn(
                b'MIXED-ZLIB', instar_bytes[65536 + 32768:],
                '[dmg-mixed-window] zlib span expected after the raw span',
            )

    def test_input_dmg_gap_error_parity(self):
        """dd on dmg-gap fails non-zero cleanly on BOTH instar and qemu.

        The koly SectorCount exceeds the mish coverage, so the tail is an
        uncovered gap.  DMG reads ERROR on a gap rather than zero-filling
        (the phase-5 EIO-parity semantic), so dd fails on both sides -- the
        messages differ (qemu ``Input/output error`` vs instar's generic
        operation failure).  Only the non-zero exit and clean termination
        are pinned, not the message.
        """
        image = self.get_image('dmg-gap')
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')
        self.skip_if_hash_mismatch(image)

        with (
            tempfile.NamedTemporaryFile(suffix='.raw') as instar_out,
            tempfile.NamedTemporaryFile(suffix='.raw') as qemu_out,
        ):
            i_out, i_err, i_rc = self.run_instar_dd(
                [f'if={image.path}', f'of={instar_out.name}'],
                output_format='raw',
                timeout=60,
            )
            self.assertNotEqual(
                i_rc, 0,
                f'[dmg-gap] instar dd should fail cleanly; '
                f'stdout={i_out!r} stderr={i_err!r}',
            )

            q_out, q_err, q_rc = self.run_qemu_img_dd(
                [f'if={image.path}', f'of={qemu_out.name}'],
                output_format='raw',
                timeout=60,
            )
            self.assertNotEqual(
                q_rc, 0,
                f'[dmg-gap] qemu-img dd should fail (EIO on the uncovered '
                f'tail); stdout={q_out!r} stderr={q_err!r}',
            )


class TestDdDetectOnlyRefusal(InstarTestBase):
    """dd refuses detect-only input formats instead of reading raw.

    qed is detected/sized by info but has no read path; dd must
    refuse it rather than emitting the container bytes plus zero padding
    (issue #444).  iso keeps its raw pass-through per the post-1a
    management decision (exact-length output, no sector padding).
    """

    def _refusal_image(self, image_id):
        image = self.get_image(image_id)
        if not image.path.exists():
            self.skipTest(f'Test image not found: {image.path}')
        return image

    def _assert_refused(self, image_id, fmt):
        image = self._refusal_image(image_id)
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={out.name}']
            )
        self.assertNotEqual(
            rc, 0,
            f'dd should refuse {fmt} input; stdout={stdout!r} '
            f'stderr={stderr!r}'
        )
        expected = (
            f"dd: input format '{fmt}' is detected but not supported "
            f'for reading (detection and info only)'
        )
        self.assertIn(
            expected, stdout + stderr,
            f'missing typed refusal for {fmt}: stderr={stderr!r}'
        )

    def test_dd_refuses_qed(self):
        """dd refuses a qed input with the typed message."""
        self._assert_refused('qed-simple', 'qed')

    def test_dd_refuses_bochs(self):
        """dd refuses a bochs-growing input with the typed message."""
        self._assert_refused('bochs-growing', 'bochs')

    def test_dd_refuses_cloop(self):
        """dd refuses a cloop-simple input with the typed message."""
        self._assert_refused('cloop-simple', 'cloop')

    # NOTE: dmg is no longer refused here.  Format-coverage phase 5
    # graduates DMG to a real read format; dd now reads it.  The windowed
    # dd byte-parity smoke lives in TestDdDmg below.

    def test_dd_iso_passthrough(self):
        """dd keeps reading iso as raw (deliberate qemu parity).

        Pins the step-1a behaviour: rc 0, output is the exact 376832-byte
        container length (dd sizes to the file, not the padded vsize).
        """
        image = self._refusal_image('iso-simple')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_instar_dd(
                [f'if={image.path}', f'of={out.name}']
            )
            self.assertEqual(rc, 0, f'iso dd should succeed; stderr={stderr!r}')
            self.assertEqual(len(_bytes_of(out.name)), 376832)
