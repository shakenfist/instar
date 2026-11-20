"""What a failed run leaves on disk.

instar creates its output file before launching the guest, so a run the
guest fails has already created the target. For most failures that file
was empty, and an empty file left behind gives a caller that tests for
the file's existence a reason to believe the operation ran -- which is
the one thing a failed run must not do.

The rule has two halves, and this module tests both, because a fix that
removed the output unconditionally would be just as wrong:

* an output this run created and left with no bytes in it is removed;
* an output holding bytes stays, as `qemu-img convert` keeps its own
  after "Invalid cluster entry found".

A failing write is injected with strace rather than a failing read,
because which write fails decides which half is under test: the first
write failing leaves nothing in the file, the second leaves one sector.
"""

import re
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from strace_injection import StraceInjectionMixin


class TestFailedOutputFile(StraceInjectionMixin, InstarTestBase):
    """Prove the empty output goes and the partial output stays."""

    # The input is generated: nothing here depends on a format, and a
    # generated file avoids the "fixture absent" skip.
    INPUT_SECTORS = 16
    SECTOR_SIZE = 65536

    # strace's own marker on a syscall whose result it supplied.
    _INJECTED = re.compile(r'= -1 ENOSPC .*\(INJECTED\)')

    def _write_input(self, path):
        """Write an input file with no zero sectors.

        Every sector must hold data: the default conversion skips a
        zero sector instead of writing it, so a zero-filled input would
        make the first write land somewhere this test cannot predict.
        """
        with open(path, 'wb') as f:
            for sector in range(self.INPUT_SECTORS):
                f.write(bytes([(sector % 255) + 1]) * self.SECTOR_SIZE)
        return self.INPUT_SECTORS * self.SECTOR_SIZE

    def _run(self, binary, out, log, when, argv_tail):
        """Run instar with the *when*th write to *out* failing.

        strace resolves `-P` at startup, so the output file has to exist
        before the run; instar truncates it when it opens it, which is
        what makes "empty afterwards" mean "instar wrote nothing" rather
        than "instar never opened it".
        """
        argv = ['strace', '-f', '-qq', '-T', '-P', str(out),
                '-e', 'trace=write',
                '-e', 'inject=write:error=ENOSPC:when=%d' % when,
                '-o', str(log), str(binary)] + argv_tail
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)

    def _assert_injection_landed(self, log, when):
        """Assert strace failed the write the index named, and only it.

        Without this, a test that stopped injecting would look like a
        test that passed: an uninjected run writes the whole output and
        exits 0, and the assertions below would then be measuring a
        successful run.
        """
        injected = []
        with open(log, encoding='utf-8', errors='replace') as f:
            for line in f:
                if self._INJECTED.search(line):
                    injected.append(line.strip())
        self.assertEqual(
            len(injected), 1,
            f'strace was asked to fail write {when} of the output with '
            f'ENOSPC and reported {len(injected)} injected failures: '
            f'{injected}'
        )

    def _case(self, when, argv_tail, out_name='out.raw'):
        """Run one injected case; return (process, output path)."""
        binary = self.get_instar_binary()
        td = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ['rm', '-rf', td])
        self._require_strace_injection(td)

        work = Path(td)
        source = work / 'source.raw'
        self._write_input(source)
        out = work / out_name
        out.touch()
        self.assertTrue(out.exists(), 'the output file was not pre-created')

        log = work / 'injected.log'
        tail = [arg.format(source=source, out=out) for arg in argv_tail]
        proc = self._run(binary, out, log, when, tail)
        self._assert_injection_landed(log, when)
        self.assertNotEqual(
            proc.returncode, 0,
            f'a failed write did not fail the run: stdout={proc.stdout!r} '
            f'stderr={proc.stderr!r}'
        )
        return proc, out

    def test_convert_removes_an_output_it_left_empty(self):
        """A convert that wrote nothing leaves no output file."""
        proc, out = self._case(
            1, ['convert', '-O', 'raw', '{source}', '{out}'])
        self.assertFalse(
            out.exists(),
            'the failed conversion left an empty output file behind, which '
            'a caller that tests for the file\'s existence reads as a '
            'conversion that ran'
        )
        self.assertIn(
            'No space left on device', proc.stderr,
            f'the failure message does not say what went wrong: '
            f'stderr={proc.stderr!r}'
        )

    def test_convert_keeps_a_partially_written_output(self):
        """A convert that wrote a sector keeps its output, as qemu does."""
        proc, out = self._case(
            2, ['convert', '-O', 'raw', '{source}', '{out}'])
        self.assertTrue(
            out.exists(),
            'the failed conversion removed an output holding the bytes it '
            'had written; qemu-img keeps its own partial output and so '
            'should instar'
        )
        self.assertEqual(
            out.stat().st_size, self.SECTOR_SIZE,
            'the kept output does not hold exactly the one sector written '
            'before the second write failed'
        )

    def test_copy_removes_an_output_it_left_empty(self):
        """A copy that wrote nothing leaves no output file."""
        _proc, out = self._case(1, ['copy', '{source}', '{out}'])
        self.assertFalse(
            out.exists(),
            'the failed copy left an empty output file behind'
        )

    def test_copy_keeps_a_partially_written_output(self):
        """A copy that wrote a sector keeps its output."""
        _proc, out = self._case(2, ['copy', '{source}', '{out}'])
        self.assertTrue(
            out.exists(),
            'the failed copy removed an output holding the bytes it had '
            'written'
        )
        self.assertEqual(
            out.stat().st_size, self.SECTOR_SIZE,
            'the kept output does not hold exactly the one sector written '
            'before the second write failed'
        )
