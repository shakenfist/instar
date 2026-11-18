"""Shared machinery for tests that make a host read misbehave.

Everything a guest operation reads comes from the host, so the way to
test what the guest does when a host read is slow or fails is to make
one host read slow or fail from outside the process. strace can do
both: `-e inject=` delays a chosen syscall or returns a chosen errno
from it, without the traced process cooperating. That is the only
technique available to an integration suite -- a FUSE mount or a device
mapper target would need privileges the suite does not have.

Two things are shared by every test built on it, and both are here
rather than in one test so that neither can drift from the other: the
capability probe, which decides whether injection works on this host
and refuses to skip where CI has declared that it does, and the parser
for strace's read lines, which is how a test proves an injection
landed on the syscall it aimed at.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path


class StraceInjectionMixin:
    """Probe strace syscall injection, and read back what it did.

    Mixed into an `InstarTestBase` subclass: the assertion and skip
    methods used here are the unittest ones.
    """

    # Set by CI in the job whose image installs strace. See
    # `_missing_strace` below and .github/workflows/functional-tests.yml.
    REQUIRE_STRACE_ENV = 'INSTAR_REQUIRE_STRACE'

    # A read of at least this many bytes is image data rather than an
    # eventfd notification: the queue kicks are 8-byte reads and the
    # data reads are a cluster or more. Only a data read is a candidate
    # for injection, because a slow or failing read of the image is the
    # event being reproduced.
    DATA_READ_BYTES = 4096

    # How much of an injected delay strace must report against the read
    # it delayed. Not the whole delay, because strace's own bookkeeping
    # rounds, but close enough that a delay which silently stopped
    # being injected cannot pass.
    SYSCALL_FRACTION = 0.8

    def _missing_strace(self, reason):
        """Skip because injection is unavailable -- or fail.

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

    def _missing_injection_fixture(self, reason):
        """Skip because the image this test injects into is absent -- or fail.

        Same gate as `_missing_strace`, for the same reason: these two
        modules exist because a failure that looks like a success is
        what the defects they guard did, so a silent skip is the one
        outcome they must not have. An environment that sets
        `INSTAR_REQUIRE_STRACE` has declared the injection rig complete,
        and the test data is part of that rig -- `make test-container-core`
        mounts the image set and the functional-tests workflow prepares
        it. A developer without the images still gets a skip.
        """
        if os.environ.get(self.REQUIRE_STRACE_ENV):
            self.fail(
                f'{self.REQUIRE_STRACE_ENV} is set, so this environment has '
                f'declared the injection rig available, but {reason}. Either '
                f'restore the test data (see tests/manifest.json) or unset '
                f'the variable -- do not let this test skip, because the '
                f'behaviour it guards fails by succeeding.'
            )
        self.skipTest(reason)

    def _require_strace_injection(self, workdir):
        """Skip unless strace can really inject into a syscall here.

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

        A delay is probed even by tests that inject an error, because
        what is in question is `-e inject=` and the ptrace permission
        underneath it, and a delay is the one injection whose effect is
        visible in the trace of a process that does nothing else. Each
        test still proves its own injection landed in its own run.
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
        registered, and the injection belongs on the reads either way.
        """
        by_thread = self._reads_by_thread(log)
        self.assertTrue(by_thread, f'strace recorded no read at all in {log}')
        busiest = max(by_thread, key=lambda pid: len(by_thread[pid]))
        others = [len(v) for pid, v in by_thread.items() if pid != busiest]
        return by_thread[busiest], (max(others) if others else 0)
