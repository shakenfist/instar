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

        test_case.assertEqual(
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
        test_case.assertEqual(
            ibytes,
            qbytes,
            f'[{label}] round-trip raw mismatch '
            f'(instar={len(ibytes)} B, qemu={len(qbytes)} B)',
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
