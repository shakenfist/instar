"""Phase 4c smoke pins for QCOW1 ("qcow" v1) read support.

These tests create their qcow images LOCALLY with the host `qemu-img`
(the 4d instar-side manifest entries do not exist yet), so they do not
depend on the instar-testdata fixture set.  They pin the behaviours the
detection graduation unlocks:

* convert / compare / dd read-path byte-parity vs qemu-img on a plain
  qcow image, including a compressed twin and a backing chain;
* the subcommand policy divergences that are deliberately NOT lifted for
  qcow (check rc-63; map/measure refusals — qemu supports both on qcow1,
  instar refuses by scope, see PLAN-format-coverage-phase-04);
* the encrypted (AES, crypt_method=1) posture: info succeeds and prints
  the encrypted line, data ops refuse cleanly;
* the misdetection-regression guard: a fresh qcow image now reports
  "file format: qcow" with its real virtual size (before phase 4c it was
  misdetected as qcow2 with virtual size 0).
"""

import struct
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase


# qcow1 header: crypt_method is a big-endian u32 at byte offset 36.
QCOW1_CRYPT_METHOD_OFFSET = 36


def _qemu_io(fmt, image, *cmds):
    """Run one or more `qemu-io -c` write commands against *image*."""
    args = ['qemu-io', '-f', fmt]
    for c in cmds:
        args.extend(['-c', c])
    args.append(str(image))
    subprocess.run(args, capture_output=True, check=True)


class Qcow1SmokeBase(InstarTestBase):
    """
    Common setup for the qcow1 smoke pins.

    Every test here builds its fixture with the host `qemu-img -f qcow`
    and compares instar against qemu-img, so the whole module needs a
    qemu that carries the qcow1 driver. RHEL-family qemu-kvm does not
    (Rocky/RHEL 9 and 10), which makes these tests unrunnable there
    rather than failing.
    """

    def setUp(self):
        super().setUp()
        self.skip_unless_qemu_supports('qcow')


class TestQcow1ConvertSmoke(Qcow1SmokeBase):
    """convert / compare read-path parity vs qemu-img on a plain qcow."""

    def test_convert_to_raw_byte_identical(self):
        """instar convert of a qcow source to raw matches qemu-img byte for byte."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / 'src.qcow'
            i_out = tmp / 'instar.raw'
            q_out = tmp / 'qemu.raw'

            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', str(src), '4M'],
                capture_output=True, check=True,
            )
            # Scattered allocation: a hole between the two written spans.
            _qemu_io('qcow', src,
                     'write -P 0x42 0 65536',
                     'write -P 0xAB 2097152 65536')

            _, stderr, rc = self.run_instar_convert(src, i_out)
            self.assertEqual(rc, 0, f'instar convert failed: {stderr!r}')

            self.run_qemu_img_convert(src, q_out)

            self.assert_bytes_identical(
                i_out.read_bytes(), q_out.read_bytes(),
                'instar convert-to-raw differs from qemu-img',
            )

    def test_compare_self_is_identical(self):
        """instar compare of a qcow against itself exits 0 (identical)."""
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src.qcow'
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', str(src), '2M'],
                capture_output=True, check=True,
            )
            _qemu_io('qcow', src, 'write -P 0x5a 0 131072')

            stdout, stderr, rc = self.run_instar_compare(src, src)
            self.assertEqual(
                rc, 0, f'compare of identical qcow images failed: '
                f'{stdout!r} {stderr!r}')

    def test_convert_compressed_twin_byte_identical(self):
        """A compressed qcow (raw-deflate clusters) converts to raw identically.

        `qemu-img convert -c -O qcow` writes a valid compressed image but
        exits 1 with empty stderr (a qemu quirk on all versions), so the
        return code is deliberately not asserted — the image is validated
        by the byte-parity of the subsequent read.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw = tmp / 'src.raw'
            comp = tmp / 'comp.qcow'
            i_out = tmp / 'instar.raw'
            q_out = tmp / 'qemu.raw'

            subprocess.run(
                ['qemu-img', 'create', '-f', 'raw', str(raw), '2M'],
                capture_output=True, check=True,
            )
            _qemu_io('raw', raw,
                     'write -P 0x11 0 65536',
                     'write -P 0x22 1048576 65536')
            # Tolerate the exit-1-despite-valid-output quirk.
            subprocess.run(
                ['qemu-img', 'convert', '-c', '-f', 'raw', '-O', 'qcow',
                 str(raw), str(comp)],
                capture_output=True,
            )
            self.assertTrue(comp.exists() and comp.stat().st_size > 0,
                            'qemu-img did not write the compressed qcow')

            _, stderr, rc = self.run_instar_convert(comp, i_out)
            self.assertEqual(rc, 0, f'instar convert of compressed qcow '
                             f'failed: {stderr!r}')

            self.run_qemu_img_convert(comp, q_out)
            self.assert_bytes_identical(
                i_out.read_bytes(), q_out.read_bytes(),
                'instar read of compressed qcow differs from qemu-img',
            )


class TestQcow1BackingChain(Qcow1SmokeBase):
    """Overlay + base (both qcow) read-through parity."""

    def test_overlay_reads_through_base(self):
        """instar convert of a qcow overlay reads through its qcow base."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base = tmp / 'base.qcow'
            overlay = tmp / 'overlay.qcow'
            i_out = tmp / 'instar.raw'
            q_out = tmp / 'qemu.raw'

            # Base carries data at offset 0; overlay adds data elsewhere,
            # so a correct read must descend to the base for the hole.
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', str(base), '1M'],
                capture_output=True, check=True,
            )
            _qemu_io('qcow', base, 'write -P 0xBB 0 4096')
            # Relative backing name (resolved against the overlay dir).
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', '-b', 'base.qcow',
                 '-F', 'qcow', str(overlay)],
                capture_output=True, check=True, cwd=str(tmp),
            )
            _qemu_io('qcow', overlay, 'write -P 0xAA 65536 4096')

            _, stderr, rc = self.run_instar_convert(overlay, i_out)
            self.assertEqual(rc, 0, f'instar convert of overlay failed: '
                             f'{stderr!r}')

            self.run_qemu_img_convert(overlay, q_out)
            self.assert_bytes_identical(
                i_out.read_bytes(), q_out.read_bytes(),
                'instar overlay read-through differs from qemu-img',
            )


class TestQcow1Dd(Qcow1SmokeBase):
    """dd windowed read-path parity vs qemu-img."""

    def test_dd_window_byte_identical(self):
        """instar dd of a qcow window matches qemu-img dd byte for byte.

        qemu-img dd's count is absolute from offset 0, so the same
        operands are handed to both tools and their raw outputs compared
        directly (byte equality, including any short-final-block padding).
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / 'src.qcow'
            i_out = tmp / 'instar.raw'
            q_out = tmp / 'qemu.raw'

            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', str(src), '4M'],
                capture_output=True, check=True,
            )
            _qemu_io('qcow', src,
                     'write -P 0x42 0 65536',
                     'write -P 0xAB 131072 65536')

            operands = [f'if={src}', f'of={i_out}', 'bs=65536', 'count=4']
            _, i_err, i_rc = self.run_instar_dd(list(operands))
            self.assertEqual(i_rc, 0, f'instar dd failed: {i_err!r}')

            q_operands = [f'if={src}', f'of={q_out}', 'bs=65536', 'count=4']
            _, q_err, q_rc = self.run_qemu_img_dd(q_operands)
            self.assertEqual(q_rc, 0, f'qemu-img dd failed: {q_err!r}')

            self.assert_bytes_identical(
                i_out.read_bytes(), q_out.read_bytes(),
                'instar dd window differs from qemu-img dd',
            )


class TestQcow1SubcommandPolicy(Qcow1SmokeBase):
    """check rc-63 and the map/measure refusals (recorded divergences)."""

    def _make_plain_qcow(self, tmp, name='src.qcow', size='2M'):
        src = Path(tmp) / name
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow', str(src), size],
            capture_output=True, check=True,
        )
        _qemu_io('qcow', src, 'write -P 0x42 0 65536')
        return src

    def test_check_exit_63(self):
        """check on a qcow exits 63.

        instar's message includes the format name — "This image format
        (qcow) does not support checks" — whereas qemu-img prints "This
        image format does not support checks" (no parenthetical). We pin
        instar's exact wording; the exit code (63) matches qemu.
        """
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_plain_qcow(tmp)

            stdout, _, rc = self.run_instar_check(src)
            self.assertEqual(rc, 63, f'expected rc 63, got {rc}: {stdout!r}')
            self.assertIn(
                'This image format (qcow) does not support checks', stdout)

            # qemu parity on the exit code (its wording lacks "(qcow)").
            _, _, q_rc = self.run_qemu_img_check(src)
            self.assertEqual(q_rc, 63)

    def test_map_refused(self):
        """map refuses a qcow source (recorded divergence: qemu supports it).

        See PLAN-format-coverage-phase-04 "map and measure stay
        refusals". Detection routes the image to Qcow1, which map's guest
        has no arm for, so it refuses with "source format unrecognised".
        """
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_plain_qcow(tmp)
            instar = self.get_instar_binary()
            r = subprocess.run(
                [str(instar), 'map', str(src)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(r.returncode, 0,
                                f'stdout={r.stdout!r} stderr={r.stderr!r}')
            self.assertIn('source format unrecognised', r.stdout + r.stderr)

    def test_measure_refused(self):
        """measure refuses a qcow source (recorded divergence: qemu supports it)."""
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_plain_qcow(tmp)
            instar = self.get_instar_binary()
            r = subprocess.run(
                [str(instar), 'measure', str(src), '-O', 'qcow2'],
                capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(r.returncode, 0,
                                f'stdout={r.stdout!r} stderr={r.stderr!r}')
            self.assertIn('source image is unsupported format',
                          r.stdout + r.stderr)


class TestQcow1Encrypted(Qcow1SmokeBase):
    """Encrypted (AES, crypt_method=1) qcow posture."""

    def _make_encrypted_qcow(self, tmp, size='2M'):
        src = Path(tmp) / 'enc.qcow'
        subprocess.run(
            ['qemu-img', 'create', '-f', 'qcow', str(src), size],
            capture_output=True, check=True,
        )
        # Byte-patch crypt_method (BE u32 @36) to 1 (AES-128-CBC).
        data = bytearray(src.read_bytes())
        struct.pack_into('>I', data, QCOW1_CRYPT_METHOD_OFFSET, 1)
        src.write_bytes(bytes(data))
        return src

    def test_info_reports_encrypted_line(self):
        """info on an AES qcow succeeds (rc 0) and prints the encrypted line."""
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_encrypted_qcow(tmp)
            stdout, stderr, rc = self.run_instar_info(src)
            self.assertEqual(rc, 0, f'info failed: {stderr!r}')
            self.assertIn('file format: qcow', stdout)
            self.assertIn('encrypted: yes', stdout)

    def test_info_json_reports_encrypted_true(self):
        """info --output json on an AES qcow emits "encrypted": true."""
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_encrypted_qcow(tmp)
            stdout, stderr, rc = self.run_instar_info(
                src, output_format='json')
            self.assertEqual(rc, 0, f'info json failed: {stderr!r}')
            self.assertIn('"encrypted": true', stdout)

    def test_convert_refuses_cleanly(self):
        """convert of an AES qcow refuses cleanly (non-zero, no hang).

        Keyless qemu likewise refuses to read encrypted data, so this is
        behavioural parity; instar surfaces "convert operation failed".
        """
        with tempfile.TemporaryDirectory() as tmp:
            src = self._make_encrypted_qcow(tmp)
            out = Path(tmp) / 'out.raw'
            stdout, stderr, rc = self.run_instar_convert(src, out)
            self.assertNotEqual(rc, 0,
                                f'expected refusal: {stdout!r} {stderr!r}')
            self.assertIn('convert operation failed', stdout + stderr)


class TestQcow1MisdetectionGuard(Qcow1SmokeBase):
    """A fresh qcow must no longer be misdetected as qcow2 with vsize 0."""

    def test_info_reports_qcow_with_real_size(self):
        """info on a fresh qcow reports "file format: qcow" and the real size.

        Before phase 4c, version-blind detection matched the shared
        qcow2 magic and reported "file format: qcow2" with "virtual size:
        0" (and a garbage qcow2 format-specific block). This guards
        against a regression back to that behaviour.
        """
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'fresh.qcow'
            subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow', str(src), '4M'],
                capture_output=True, check=True,
            )
            stdout, stderr, rc = self.run_instar_info(src)
            self.assertEqual(rc, 0, f'info failed: {stderr!r}')
            self.assertIn('file format: qcow\n', stdout)
            self.assertNotIn('file format: qcow2', stdout)
            self.assertIn('virtual size: 4 MiB (4194304 bytes)', stdout)
