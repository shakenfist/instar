"""Tests for the dd subcommand.

Phase 2 (TestDdWholeImage) covers whole-image copies only.

Phase 3 (TestDdRawWindow) adds an output-window matrix: each case
runs `instar dd` and `qemu-img dd` with the same bs/count/skip
operands and asserts byte-identical output.  Both a raw and a qcow2
input are exercised for every windowed case.  Direct Python byte
comparison is used (read both output files and assertEqual on the
bytes) because dd parity is about exact file bytes including any
zero-padding from a short final block.
"""

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

            # Omit of= — the subcommand must refuse.
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
    tokens — the caller supplies them in full so no default injection
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
        """Aligned skip: bs=65536 skip=1 — window starts at 64 KiB boundary."""
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
        """count beyond EOF: bs=65536 count=99999 — expect whole image."""
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
        """skip past EOF: bs=65536 skip=99999 — expect 0-byte output, exit 0."""
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
        """Short final block: bs=1000 count=3 — window is 3000 B, file may be padded."""
        self._run_window(
            ['bs=1000', 'count=3'],
            label='short_final_block',
        )

    def test_window_size_suffix_1m(self):
        """Size suffix: bs=1M count=2 — copies the whole 1 MiB image twice (or until EOF)."""
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
