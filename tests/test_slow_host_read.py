"""A host read that takes seconds must not fail a guest operation.

Every byte a guest operation reads comes from the host: the guest puts
a request on the virtio queue, kicks it, and spins on the used ring
until the host completes it. The host side of that read is an ordinary
`read(2)` on the image file, so anything that makes a read slow -- a
loaded CI runner, a network filesystem, a backing store that is not a
local disk -- makes the guest's wait long. A long wait is not a
failure, and the operation must complete with the same bytes it would
have produced had the read been fast.

The regression this guards against is the opposite behaviour: a guest
that gave up on a request after a fixed number of spin iterations and
reported a timeout, turning an everyday slow read into a failed
conversion. The number was about 1.3 seconds of spinning on a modern
host, which a loaded runner reaches without anything being wrong.

The latency is injected with strace, which can delay a chosen syscall
in a traced process without the process cooperating. That is the only
way to make a read slow from outside without a FUSE mount or a device
mapper, both of which need privileges an integration suite does not
have.
"""

import subprocess
import tempfile
import time
from pathlib import Path

from base import InstarTestBase
from strace_injection import StraceInjectionMixin


class TestSlowHostRead(StraceInjectionMixin, InstarTestBase):
    """Prove a slow host read does not fail a conversion."""

    # The delay injected into one host read. It has to be comfortably
    # longer than the spin budget the guest used to give up after
    # (about 1.3 seconds), so that a reintroduced budget fails this
    # test rather than squeezing under it, and short enough that the
    # test costs a few seconds rather than a minute.
    INJECTED_DELAY_SECONDS = 3.0

    # How much of the injected delay has to show up in the elapsed
    # time of the run. Generous on purpose: this suite runs at four
    # workers beside other suites on a shared runner, so the
    # unaffected part of a conversion is worth whole seconds of
    # variance between two runs and a tight threshold would fail on
    # load rather than on behaviour. The precise check is
    # `_assert_delay_landed`, which reads the delay out of strace's own
    # per-syscall timing; this one is the cheap cross-check that the
    # process really did sit still.
    ELAPSED_FRACTION = 0.5

    def _derive_injection_index(self, log):
        """Choose which read to delay, by reading an undelayed trace.

        Hardcoding the number is what rots: it is a per-thread count of
        reads, so anything that changes how many reads the VMM does
        before the guest starts -- a differently sized guest binary, an
        extra probe of the input, a new format -- moves the read that
        number names, and a number that lands in the main thread
        delays a process that is not waiting on anything. So the index
        comes out of a trace of the very conversion about to be run.

        Two properties are required of it, and both are asserted:

        * It is larger than the number of reads any other thread does,
          because `when=` is counted per thread and an index no other
          thread can reach is one only the I/O thread can be delayed
          at.
        * It names a data read in the middle of the run, so the guest
          is demonstrably waiting on a request when the delay lands
          rather than starting up or finishing.
        """
        reads, others = self._busiest_thread(log)
        self.assertGreater(
            len(reads), 32,
            f'the thread servicing the virtio queue made only {len(reads)} '
            f'reads, which is too few for this fixture to be exercising the '
            f'guest I/O path at all'
        )
        # One data read per cluster of a fully allocated image, against
        # the handful it takes to load the guest binaries: a thread with
        # this many is servicing the queue and not just starting the VMM
        # up. Counted rather than identified by file descriptor or by
        # the 8-byte queue notifications, because the VMM services the
        # queue from its I/O thread or from the vCPU exit depending on
        # whether it could register an ioeventfd, and both are the right
        # thread to delay.
        data_reads = sum(1 for _fd, length, _d in reads
                         if length is not None and length >= self.DATA_READ_BYTES)
        self.assertGreater(
            data_reads, 16,
            f'the busiest thread read image data only {data_reads} times, '
            f'which is the shape of a thread loading an executable rather '
            f'than one serving guest I/O'
        )

        # Clear of every other thread's read count by a margin, so a
        # run that does a few more reads on another thread than the
        # trace did cannot have the delay land there instead.
        floor = others + 16
        middle = len(reads) // 2
        candidates = [
            i + 1 for i, (_fd, length, _d) in enumerate(reads)
            if length is not None and length >= self.DATA_READ_BYTES and i + 1 > floor
        ]
        self.assertTrue(
            candidates,
            f'no data read in the I/O thread sits past read {floor}: the '
            f'thread made {len(reads)} reads and the busiest other thread '
            f'made {others}'
        )
        return min(candidates, key=lambda i: abs(i - middle))

    def _run_convert(self, src, dst, log, when=None):
        """Convert *src* to *dst* under strace; return (elapsed, result).

        The uninjected run is traced too, with the same options and the
        same trace written to a file, so the two runs' elapsed times
        differ by the injected delay rather than by the cost of being
        traced.
        """
        argv = ['strace', '-f', '-qq', '-T', '-e', 'trace=read']
        if when is not None:
            argv += ['-e', 'inject=read:delay_enter=%d:when=%d'
                     % (int(self.INJECTED_DELAY_SECONDS * 1e6), when)]
        argv += ['-o', str(log),
                 str(self.get_instar_binary()), 'convert', '-O', 'raw',
                 str(src), str(dst)]
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        return time.monotonic() - started, result

    def _assert_delay_landed(self, log, when):
        """Assert strace delayed the read the index named, and no other.

        This is the assertion that keeps the test honest. Everything
        else here passes just as well when nothing is injected at all:
        a conversion with no delay exits 0 and produces identical
        bytes, which is exactly the result being asserted. So the run
        is required to show the delay where it was asked for, read out
        of strace's own per-syscall timing, and to show it against a
        data read on the thread servicing the queue.
        """
        reads, _others = self._busiest_thread(log)
        self.assertGreaterEqual(
            len(reads), when,
            f'the delay was injected at read {when} of the I/O thread but '
            f'that thread made only {len(reads)} reads in the injected run'
        )
        fd, length, duration = reads[when - 1]
        self.assertIsNotNone(
            duration,
            f'strace reported no duration for read {when} on fd {fd}, so '
            f'there is no evidence the delay was injected'
        )
        self.assertGreaterEqual(
            duration, self.INJECTED_DELAY_SECONDS * self.SYSCALL_FRACTION,
            f'read {when} on fd {fd} took {duration:.4f} seconds where a '
            f'{self.INJECTED_DELAY_SECONDS} second delay was injected into '
            f'it: the injection is no longer landing, so this test is not '
            f'exercising a slow host read'
        )
        self.assertIsNotNone(
            length,
            f'read {when} on fd {fd} was delayed but strace could not '
            f'attribute a length to it, so it cannot be confirmed as a data '
            f'read'
        )
        self.assertGreaterEqual(
            length, self.DATA_READ_BYTES,
            f'the delayed read asked for {length} bytes, which is a queue '
            f'notification rather than the image read this test means to '
            f'slow down'
        )

    def test_slow_host_read_does_not_fail_convert(self):
        """A three second host read converts correctly, not to a timeout."""
        self._require_qemu_tools()

        with tempfile.TemporaryDirectory() as td:
            self._require_strace_injection(td)

            work = Path(td)
            source = work / 'fully-allocated.qcow2'
            # Eight fully allocated megabytes: large enough that the
            # guest issues enough requests for a delay in the middle of
            # the run to be unambiguously inside the I/O loop, small
            # enough that the conversion itself is a fraction of a
            # second. A sparse image would read almost nothing from the
            # host and give the injection nowhere to land.
            self._run_tool(
                ['qemu-img', 'create', '-f', 'qcow2', str(source), '8M'], work)
            self._run_tool(
                ['qemu-io', '-c', 'write -P 0xab 0 8M', str(source)], work)

            reference = work / 'reference.raw'
            baseline_log = work / 'baseline.log'
            baseline_elapsed, baseline = self._run_convert(
                source, reference, baseline_log)
            self.assertEqual(
                baseline.returncode, 0,
                f'the undelayed conversion failed: rc={baseline.returncode} '
                f'stderr={baseline.stderr!r}'
            )

            when = self._derive_injection_index(baseline_log)

            delayed = work / 'delayed.raw'
            delayed_log = work / 'delayed.log'
            delayed_elapsed, injected = self._run_convert(
                source, delayed, delayed_log, when=when)

            self.assertEqual(
                injected.returncode, 0,
                f'a {self.INJECTED_DELAY_SECONDS} second delay on host read '
                f'{when} failed the conversion: rc={injected.returncode} '
                f'stdout={injected.stdout!r} stderr={injected.stderr!r}'
            )
            self._assert_delay_landed(delayed_log, when)
            self.assert_bytes_identical(
                delayed.read_bytes(), reference.read_bytes(),
                f'a conversion whose host read was delayed by '
                f'{self.INJECTED_DELAY_SECONDS} seconds produced different '
                f'bytes from an undelayed one'
            )
            self.assertGreaterEqual(
                delayed_elapsed - baseline_elapsed,
                self.INJECTED_DELAY_SECONDS * self.ELAPSED_FRACTION,
                f'the delayed conversion took {delayed_elapsed:.2f} seconds '
                f'against {baseline_elapsed:.2f} for the undelayed one, so a '
                f'{self.INJECTED_DELAY_SECONDS} second delay did not reach '
                f'the process'
            )
