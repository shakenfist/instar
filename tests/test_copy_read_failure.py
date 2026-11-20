"""A failed read must fail the copy, not leave a short file at exit 0.

`instar copy` reads the input device sector by sector and writes each
sector through to the output. Every failure path in the operation
reported the failure and returned, and the host inferred success from
the guest reaching HLT -- which a failed run reaches too. So an ordinary
`EIO` on the source gave exit 0, nothing on stderr, and an output file
holding only the sectors copied before the failure: a caller that checks
the exit status concludes the copy succeeded, and the truncated file
looks like a valid short image.

The failure is injected the way the other host-read tests inject one,
with strace: one read of the input returns EIO and every other read
succeeds. What the test insists on is the whole verdict -- a non-zero
exit, a message naming the image, the offset and the errno, and a file
that is demonstrably not the copy that was asked for.
"""

import re
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from strace_injection import StraceInjectionMixin


class TestCopyReadFailure(StraceInjectionMixin, InstarTestBase):
    """Prove a failed host read fails the copy and says what failed."""

    # The input is generated rather than taken from the image set: this
    # test is about the copy operation's reporting and not about any
    # format, so a plain file of known bytes is both sufficient and free
    # of the "fixture absent" skip the format tests have to carry.
    INPUT_SECTORS = 16
    SECTOR_SIZE = 65536

    # Which of the input's data reads to fail. Not the first, because a
    # failure at offset 0 cannot show the half-copied file the defect
    # leaves behind, and not the last, so that reads after it would have
    # succeeded had the operation kept going.
    FAIL_NTH_DATA_READ = 5

    # strace's own marker on a syscall whose result it supplied.
    _INJECTED_EIO = re.compile(r'= -1 EIO .*\(INJECTED\)')

    # A read line's entry, and the seek that placed it. The VMM's
    # backing store seeks and then reads rather than using `pread`, so
    # the offset of a read comes from the preceding lseek on the same
    # descriptor.
    _READ_ENTRY = re.compile(r'^(?:(?P<pid>\d+)\s+)?read\((?P<fd>\d+), ')
    _LSEEK = re.compile(
        r'^(?:(?P<pid>\d+)\s+)?lseek\((?P<fd>\d+), (?P<offset>\d+), SEEK_SET\)'
    )

    def _write_input(self, path):
        """Write an input file whose every sector is distinguishable."""
        with open(path, 'wb') as f:
            for sector in range(self.INPUT_SECTORS):
                f.write(bytes([(sector % 255) + 1]) * self.SECTOR_SIZE)
        return self.INPUT_SECTORS * self.SECTOR_SIZE

    def _data_reads(self, log):
        """Every data read of the traced image, in order.

        Returns `(reads, counts)`: `reads` is `(pid, index, offset)` per
        read of at least `DATA_READ_BYTES`, where the index counts the
        thread's own read invocations from 1 -- which is the number
        `when=` takes -- and `counts` is each thread's total.
        """
        counts = {}
        reads = []
        position = {}
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                seek = self._LSEEK.match(line)
                if seek:
                    position[seek.group('fd')] = int(seek.group('offset'))
                    continue
                entry = self._READ_ENTRY.match(line)
                if not entry:
                    continue
                pid = entry.group('pid')
                counts[pid] = counts.get(pid, 0) + 1
                length = self._READ_LINE.match(line.rstrip('\n'))
                if length is None or int(length.group('length')) < self.DATA_READ_BYTES:
                    continue
                reads.append((pid, counts[pid], position.get(entry.group('fd'))))
        return reads, counts

    def _derive_injection(self, log):
        """Choose the read to fail; return its `when=` index and offset.

        The number is derived from a trace of the very copy about to be
        run, so a change in how many reads the VMM makes before the
        guest starts moves it rather than silently aiming it elsewhere.
        `when=` counts per thread, so the choice is only unambiguous if
        no other thread reaches that index, which is asserted.
        """
        reads, counts = self._data_reads(log)
        self.assertGreaterEqual(
            len(reads), self.FAIL_NTH_DATA_READ,
            f'the uninjected copy made {len(reads)} data reads of the input, '
            f'fewer than the {self.FAIL_NTH_DATA_READ} this test aims at'
        )
        pid, index, offset = reads[self.FAIL_NTH_DATA_READ - 1]
        self.assertIsNotNone(
            offset,
            'no lseek precedes the chosen read, so its offset in the input '
            'cannot be established from the trace'
        )
        others = [n for other, n in counts.items() if other != pid]
        self.assertTrue(
            all(n < index for n in others),
            f'the chosen read is invocation {index} of thread {pid}, but '
            f'another thread made {max(others, default=0)} reads of the '
            f'input, so injecting at {index} could fail a read in the wrong '
            f'thread'
        )
        return index, offset

    def _run_copy(self, binary, source, out, log, when=None):
        """Copy *source* under strace; return the completed process.

        Traced with `-P` on the input path so only reads of the input
        are traced and counted, and traced in the uninjected run too,
        with the same options, so the two runs differ by the injection
        alone.
        """
        argv = ['strace', '-f', '-qq', '-T', '-P', str(source),
                '-e', 'trace=read,lseek']
        if when is not None:
            argv += ['-e', 'inject=read:error=EIO:when=%d' % when]
        argv += ['-o', str(log),
                 str(binary), 'copy',
                 '--input-sector-size', str(self.SECTOR_SIZE),
                 '--output-sector-size', str(self.SECTOR_SIZE),
                 str(source), str(out)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)

    def _assert_injection_landed(self, log, when):
        """Assert strace failed the read the index named, and only it.

        A run in which nothing was injected also copies and also exits
        0, so without reading the injection back out of the trace a test
        that stopped injecting would look like a test that passed -- in
        the direction that hides the defect, because the defect's
        symptom is a successful-looking copy.
        """
        injected = []
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                if self._INJECTED_EIO.search(line):
                    injected.append(line.strip())
        self.assertEqual(
            len(injected), 1,
            f'strace was asked to fail read {when} of the input with EIO and '
            f'reported {len(injected)} injected failures: {injected}'
        )

    def test_failed_read_fails_the_copy(self):
        """A failed input read fails the copy, and says what failed."""
        binary = self.get_instar_binary()

        with tempfile.TemporaryDirectory() as td:
            self._require_strace_injection(td)

            work = Path(td)
            source = work / 'source.raw'
            input_size = self._write_input(source)

            baseline_log = work / 'baseline.log'
            baseline_out = work / 'baseline.raw'
            baseline = self._run_copy(binary, source, baseline_out, baseline_log)
            self.assertEqual(
                baseline.returncode, 0,
                f'the uninjected copy failed: rc={baseline.returncode} '
                f'stderr={baseline.stderr!r}'
            )
            self.assertEqual(
                baseline_out.stat().st_size, input_size,
                'the uninjected copy did not write the whole input, so this '
                'test cannot tell a short copy from an ordinary one'
            )

            when, offset = self._derive_injection(baseline_log)

            injected_log = work / 'injected.log'
            injected_out = work / 'injected.raw'
            injected = self._run_copy(
                binary, source, injected_out, injected_log, when=when)

            self._assert_injection_landed(injected_log, when)

            self.assertNotEqual(
                injected.returncode, 0,
                f'a failed read at input offset {offset} did not fail the '
                f'copy: the host reported success for a run that copied '
                f'part of the input. stdout={injected.stdout!r} '
                f'stderr={injected.stderr!r}'
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
            self.assertIn(
                str(source.name), injected.stderr,
                f'the failure message does not name the image that failed: '
                f'stderr={injected.stderr!r}'
            )

            # The defect's shape, not only its exit code: the file left
            # behind holds the sectors copied before the failure. The
            # exit status is now what tells a caller that, so the file
            # being short is what makes the exit status load-bearing.
            if injected_out.exists():
                self.assertLess(
                    injected_out.stat().st_size, input_size,
                    'the failed copy left an output file as long as the '
                    'input, so this test is no longer measuring the short '
                    'file the failure leaves behind'
                )
