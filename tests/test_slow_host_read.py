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

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from base import InstarTestBase


class TestSlowHostRead(InstarTestBase):
    """Prove a slow host read does not fail a conversion."""

    # Set by CI in the job whose image installs strace. See
    # `_missing_strace` below and .github/workflows/functional-tests.yml.
    REQUIRE_STRACE_ENV = 'INSTAR_REQUIRE_STRACE'

    # The delay injected into one host read. It has to be comfortably
    # longer than the spin budget the guest used to give up after
    # (about 1.3 seconds), so that a reintroduced budget fails this
    # test rather than squeezing under it, and short enough that the
    # test costs a few seconds rather than a minute.
    INJECTED_DELAY_SECONDS = 3.0

    # A read of at least this many bytes is image data rather than an
    # eventfd notification: the queue kicks are 8-byte reads and the
    # data reads are a cluster or more. Only a data read is a candidate
    # for injection, because a slow read of the image is the event
    # being reproduced.
    DATA_READ_BYTES = 4096

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

    # How much of the injected delay strace must report against the
    # read it delayed. Not the whole delay, because strace's own
    # bookkeeping rounds, but close enough that a delay which silently
    # stopped being injected cannot pass.
    SYSCALL_FRACTION = 0.8

    def _missing_strace(self, reason):
        """Skip because latency cannot be injected -- or fail.

        A probe that skips is a probe whose failure looks exactly like
        a pass, and a test that quietly stops running is worse than no
        test: the behaviour it guards is a one-line change away from
        coming back. So the skip is conditional, as `_require_vhdiinfo`
        makes it for libvhdi: an environment that sets
        `INSTAR_REQUIRE_STRACE` has declared that injection works
        there, and anything missing is a failure. A developer whose
        host has no strace, or whose kernel refuses ptrace, still gets
        a skip.
        """
        if os.environ.get(self.REQUIRE_STRACE_ENV):
            self.fail(
                f'{self.REQUIRE_STRACE_ENV} is set, so this environment has '
                f'declared syscall injection available, but {reason}. Either '
                f'restore it (the test image installs strace, and tracing '
                f'needs ptrace to be permitted) or unset the variable -- do '
                f'not let this test skip, because a skip reads as a pass.'
            )
        self.skipTest(reason)

    def _require_strace_injection(self, workdir):
        """Skip unless strace can really delay a syscall on this host.

        The capability is probed, not the binary. strace can be
        installed and still be unable to inject: `-e inject=` and its
        `delay_enter` are missing from builds old enough to still be
        packaged somewhere, a container without ptrace permitted cannot
        trace anything at all, and a kernel with `yama/ptrace_scope`
        set to 2 or 3 refuses a tracer that is not already privileged.
        Each of those produces a working `strace --version` and a
        useless injection, so the probe delays a real syscall in
        `/bin/true` and insists on seeing the delay in strace's own
        timing.
        """
        if shutil.which('strace') is None:
            self._missing_strace('strace is not installed')

        probe_delay = 0.2
        log = Path(workdir) / 'inject-probe.log'
        argv = [
            'strace', '-f', '-qq', '-T',
            '-e', 'trace=read',
            '-e', 'inject=read:delay_enter=%d:when=1' % int(probe_delay * 1e6),
            '-o', str(log),
            '/bin/true',
        ]
        try:
            probe = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            self._missing_strace('a 0.2 second injection probe did not finish in a minute')
        except OSError as exc:
            self._missing_strace(f'strace could not be run ({exc})')

        if probe.returncode != 0:
            self._missing_strace(
                f'strace exited {probe.returncode} on an injection probe: '
                f'{(probe.stderr or probe.stdout).strip()!r}'
            )
        if not log.exists():
            self._missing_strace('strace wrote no trace for an injection probe')

        durations = [d for _pid, _fd, _length, d in self._parse_reads(log)
                     if d is not None]
        if not durations:
            self._missing_strace(
                'strace traced no timed read in /bin/true, so the trace '
                'format is not one this test can read'
            )
        if max(durations) < probe_delay * self.SYSCALL_FRACTION:
            self._missing_strace(
                f'strace accepted a {probe_delay} second delay injection but '
                f'the longest read it timed took {max(durations):.4f} '
                f'seconds, so nothing was delayed'
            )

    # A completed read: pid, fd, buffer, requested length, result, and
    # -T's duration. A read that strace split because another thread
    # ran in the middle of it loses the length on the entry line and
    # carries its result and duration on the matching resumed line, so
    # the two shapes are matched separately and stitched together by
    # `_parse_reads`. The thread prefix is optional because strace
    # omits it for a process that never had a second thread, which is
    # the injection probe's /bin/true.
    _PID = r'^(?:(?P<pid>\d+)\s+)?'
    _READ_LINE = re.compile(
        _PID + r'read\((?P<fd>\d+), .*, (?P<length>\d+)\)\s+= '
        r'(?P<result>-?\d+).*?(?:<(?P<duration>\d+\.\d+)>)?\s*$'
    )
    _READ_UNFINISHED = re.compile(_PID + r'read\((?P<fd>\d+), .*<unfinished \.\.\.>\s*$')
    _READ_RESUMED = re.compile(
        _PID + r'<\.\.\. read resumed>.*?(?:<(?P<duration>\d+\.\d+)>)?\s*$'
    )

    def _parse_reads(self, log):
        """Return every read in *log* as (pid, fd, length, duration).

        In trace order, which is what matters: strace's `when=` counts
        a syscall's invocations per thread, so a read's position in its
        own thread's list is the number to inject at. A read strace
        could not attribute a length to (one it split across a thread
        switch) is still counted, with a length of None, because
        dropping it would shift every later index in that thread.
        """
        reads = []
        # Index into `reads` of the invocation each thread is waiting
        # to see resumed, so a split read's duration lands on the
        # invocation it belongs to rather than on a new one.
        pending = {}
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                m = self._READ_LINE.match(line)
                if m:
                    reads.append((
                        m.group('pid'),
                        int(m.group('fd')),
                        int(m.group('length')),
                        float(m.group('duration')) if m.group('duration') else None,
                    ))
                    continue
                m = self._READ_UNFINISHED.match(line)
                if m:
                    pending[m.group('pid')] = len(reads)
                    reads.append((m.group('pid'), int(m.group('fd')), None, None))
                    continue
                m = self._READ_RESUMED.match(line)
                if m and m.group('pid') in pending:
                    at = pending.pop(m.group('pid'))
                    pid, fd, length, _duration = reads[at]
                    duration = float(m.group('duration')) if m.group('duration') else None
                    reads[at] = (pid, fd, length, duration)
        return reads

    def _reads_by_thread(self, log):
        """Group `_parse_reads` by thread, each thread's reads in order."""
        by_thread = {}
        for pid, fd, length, duration in self._parse_reads(log):
            by_thread.setdefault(pid, []).append((fd, length, duration))
        return by_thread

    def _busiest_thread(self, log):
        """Return (reads, other_threads_max) for the thread doing the I/O.

        Whichever thread services the virtio queue does a read of image
        data plus two eventfd reads for every request the guest makes,
        so against a fully allocated image it does an order of
        magnitude more reads than anything else in the process. Found
        by count rather than by file descriptor or thread identity,
        because the queue is serviced from the VMM's I/O thread or from
        the vCPU exit depending on whether an ioeventfd could be
        registered, and the delay belongs on the reads either way.
        """
        by_thread = self._reads_by_thread(log)
        self.assertTrue(by_thread, f'strace recorded no read at all in {log}')
        busiest = max(by_thread, key=lambda pid: len(by_thread[pid]))
        others = [len(v) for pid, v in by_thread.items() if pid != busiest]
        return by_thread[busiest], (max(others) if others else 0)

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
