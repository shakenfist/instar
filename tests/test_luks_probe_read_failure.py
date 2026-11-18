"""A failed read must not be read as "this LUKS image has no inner format".

A LUKS container's payload is either a flat image or another image
format, and `convert` tells the two apart by reading the first payload
sector, decrypting it and looking for QCOW2 magic. The probe is one
host read, and a host read can fail. If a failed probe read is treated
as a probe that found nothing, a LUKS-wrapped QCOW2 is converted as
though its payload were flat: the output holds the decrypted QCOW2
bytes in a file declared to be the target format, and the operation
exits 0 with nothing on stderr.

Reaching that outcome needs one read of the payload sector to fail and
the identical read to succeed moments later, because the flat path's
first iteration re-reads exactly the sector the probe read. That is
what a transient failure gives you -- a loaded host, a backing store
that is not a local disk -- and it is why the wrong answer is not
caught by the fatal read failure a few lines below.

So the failure is injected exactly that way: one read of the payload
offset returns EIO, and every other read of the image, including the
next one of the same offset, succeeds. The operation must fail and say
what failed, rather than produce an image.
"""

import re
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from strace_injection import StraceInjectionMixin


class TestLuksInnerFormatProbeReadFailure(StraceInjectionMixin, InstarTestBase):
    """Prove a failed inner-format probe read fails the conversion."""

    # The fixture: a LUKS v1 container whose payload is a QCOW2 image,
    # which is the only shape in which the probe's answer changes what
    # the conversion does.
    IMAGE_ID = 'luks-v1-qcow2-inner'
    PASSPHRASE = 'test-passphrase'

    # Where a LUKS v1 header keeps the payload offset, as a big-endian
    # count of 512-byte sectors. Read from the fixture rather than
    # hardcoded, because the number is a property of the image and the
    # test has to delay the read of *its* payload offset.
    PAYLOAD_OFFSET_FIELD = 104
    LUKS_HEADER_SECTOR = 512

    # strace's own marker on a syscall whose result it supplied.
    _INJECTED_EIO = re.compile(r'= -1 EIO .*\(INJECTED\)')

    # A read line's entry, which is one invocation of read: the shape
    # `when=` counts. A line that strace split across a thread switch
    # ends in "<unfinished ...>" and still matches, because it is still
    # an invocation and dropping it would shift every later index.
    _READ_ENTRY = re.compile(r'^(?:(?P<pid>\d+)\s+)?read\((?P<fd>\d+), ')
    _LSEEK = re.compile(
        r'^(?:(?P<pid>\d+)\s+)?lseek\((?P<fd>\d+), (?P<offset>\d+), SEEK_SET\)'
    )

    def _payload_byte_offset(self, image_path):
        """Read the fixture's own LUKS v1 payload offset, in bytes."""
        header = image_path.read_bytes()[:self.PAYLOAD_OFFSET_FIELD + 4]
        self.assertEqual(
            header[:4], b'LUKS',
            f'{image_path} does not start with LUKS magic, so it is not the '
            f'fixture this test was written against'
        )
        field = header[self.PAYLOAD_OFFSET_FIELD:self.PAYLOAD_OFFSET_FIELD + 4]
        return int.from_bytes(field, 'big') * self.LUKS_HEADER_SECTOR

    def _reads_of_offset(self, log, offset):
        """Index every read in *log*, and say which read that offset.

        Returns `(hits, counts)`: `hits` is every data read of *offset*
        as `(pid, index)` with the index counted within its own thread
        and starting at 1, which is the number `when=` takes; `counts`
        is how many reads each thread made in all.

        The offset comes from the preceding `lseek` on the same
        descriptor, because the VMM's backing store seeks and then
        reads rather than using `pread`. The trace holds only reads of
        the image, so every read counted here is one the guest asked
        for -- strace is run with `-P` on the image path, which keeps
        the eventfd queue notifications and the reads of instar's own
        binaries out of the count and therefore out of `when=`.
        """
        counts = {}
        hits = []
        position = {}
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                seek = self._LSEEK.match(line)
                if seek:
                    position[seek.group('fd')] = int(seek.group('offset'))
                    continue
                read = self._READ_ENTRY.match(line)
                if not read:
                    continue
                pid = read.group('pid')
                counts[pid] = counts.get(pid, 0) + 1
                length = self._READ_LINE.match(line.rstrip('\n'))
                long_enough = (length is not None
                               and int(length.group('length')) >= self.DATA_READ_BYTES)
                if long_enough and position.get(read.group('fd')) == offset:
                    hits.append((pid, counts[pid]))
        return hits, counts

    def _derive_injection_index(self, log, offset):
        """Choose the read to fail: the first data read of *offset*.

        The probe read is the first read of the payload offset in the
        run -- the flat path's re-read of the same sector, and the
        chain reader's reads of the inner QCOW2 header, come after it.

        `when=` counts a syscall's invocations per thread, so an index
        is only unambiguous if no other thread reaches it. That is
        asserted rather than assumed: the number is derived from a
        trace of the very conversion about to be run, so a change in
        how many reads the VMM makes before the guest starts moves the
        number with it instead of silently aiming it elsewhere.
        """
        hits, counts = self._reads_of_offset(log, offset)
        self.assertTrue(
            hits,
            f'no read of payload offset {offset} appears in {log}, so the '
            f'inner-format probe is not where this test believes it is'
        )
        pid, index = hits[0]
        others = [n for other, n in counts.items() if other != pid]
        self.assertTrue(
            all(n < index for n in others),
            f'the probe read is invocation {index} of thread {pid}, but '
            f'another thread made {max(others, default=0)} reads of the '
            f'image, so injecting at {index} could fail a read in the wrong '
            f'thread'
        )
        return index

    def _run_convert(self, binary, image, out, log, when=None):
        """Convert *image* under strace; return the completed process.

        Traced with `-P` on the image path so that only reads of the
        image are traced and counted, and traced in the uninjected run
        too, with the same options, so the two runs differ by the
        injection alone.
        """
        argv = ['strace', '-f', '-qq', '-T', '-P', str(image), '-e', 'trace=read,lseek']
        if when is not None:
            argv += ['-e', 'inject=read:error=EIO:when=%d' % when]
        argv += ['-o', str(log),
                 str(binary), 'convert', '-O', 'raw',
                 '--luks-passphrase', self.PASSPHRASE,
                 str(image), str(out)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)

    def _assert_injection_landed(self, log, when, offset):
        """Assert strace failed the read the index named, and only it.

        This is the assertion that keeps the test honest. A run in
        which nothing was injected also converts and also exits 0, so
        without reading the injection back out of the trace a test that
        stopped injecting would look like a test that passed -- in the
        direction that hides the defect, because the defect's symptom
        *is* a successful conversion.
        """
        injected = []
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                if self._INJECTED_EIO.search(line):
                    injected.append(line.strip())
        self.assertEqual(
            len(injected), 1,
            f'strace was asked to fail read {when} of the image with EIO and '
            f'reported {len(injected)} injected failures: {injected}'
        )
        hits, _counts = self._reads_of_offset(log, offset)
        self.assertTrue(
            hits and hits[0][1] == when,
            f'the injected run read payload offset {offset} first at '
            f'invocation {hits[0][1] if hits else None} rather than at {when}, '
            f'so the failure did not land on the inner-format probe'
        )

    def test_failed_probe_read_fails_the_conversion(self):
        """A failed probe read fails the convert, and says what failed."""
        image = self.get_image(self.IMAGE_ID)
        if not image.path.exists():
            self.skipTest(f'Image not found: {image.path}')

        binary = self.get_instar_binary()
        offset = self._payload_byte_offset(image.path)

        with tempfile.TemporaryDirectory() as td:
            self._require_strace_injection(td)

            work = Path(td)
            baseline_log = work / 'baseline.log'
            baseline_out = work / 'baseline.raw'
            baseline = self._run_convert(
                binary, image.path, baseline_out, baseline_log)
            self.assertEqual(
                baseline.returncode, 0,
                f'the uninjected conversion failed: rc={baseline.returncode} '
                f'stderr={baseline.stderr!r}'
            )

            when = self._derive_injection_index(baseline_log, offset)

            injected_log = work / 'injected.log'
            injected_out = work / 'injected.raw'
            injected = self._run_convert(
                binary, image.path, injected_out, injected_log, when=when)

            self._assert_injection_landed(injected_log, when, offset)
            self.assertNotEqual(
                injected.returncode, 0,
                f'a failed read of payload offset {offset} did not fail the '
                f'conversion: the probe treated the failure as "no inner '
                f'format" and converted the image as a flat payload. '
                f'stdout={injected.stdout!r} stderr={injected.stderr!r}'
            )
            self.assertIn(
                str(offset), injected.stderr,
                f'the failure message does not name the offset that failed: '
                f'stderr={injected.stderr!r}'
            )
            self.assertIn(
                'Input/output error', injected.stderr,
                f'the failure message does not say what the host said went '
                f'wrong: stderr={injected.stderr!r}'
            )

            # The outcome being guarded against is not only a zero exit
            # code: it is an output file holding the decrypted inner
            # QCOW2 written out as though it were the target format. A
            # failed conversion must not have produced one.
            if injected_out.exists():
                self.assertNotEqual(
                    injected_out.read_bytes()[:4], b'QFI\xfb',
                    'the output of the failed conversion starts with QCOW2 '
                    'magic, so the inner image was written out as a flat raw '
                    'payload'
                )
