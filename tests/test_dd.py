"""Tests for the dd subcommand (whole-image case only).

skip=/count= operands are NOT honoured until phase 3; those tests
live in a future test file.  Only whole-image copies are validated
here, because that is the only correct path for the current
implementation.

For whole-image copies with default raw output, `instar dd
if=IN of=OUT` should produce byte-identical output to
`qemu-img dd if=IN of=OUT bs=512`.
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
