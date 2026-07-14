"""Cross-version COW parity (phase 7 step 7e).

The per-op COW tests (``TestCommitSnapshotCow`` / ``TestRebaseSnapshotCow`` /
``TestBenchSnapshotCow``) prove qemu-parity against the *system* qemu-img
(10.0.11). This module widens that proof across the **pinned** qemu-img
versions shipped in ``instar-testdata/qemu-img-binaries``: instar's COW
output must be accepted and read back correctly by every pinned qemu
release, not just the one on the host.

For a representative COW fixture per op (commit into a snapshot-bearing
backing, safe-mode rebase of a snapshot-bearing overlay, ``bench -w`` into
a snapshot-bearing image), at cluster sizes {512, 65536}, we run instar's
COW **once**, then for EACH pinned version V:

* ``qemu-img check`` (V) on instar's result is clean — no
  ``refcount=1 reference=2``, no leaks (C5);
* ``qemu-img compare`` (V) of instar's active view against V's own COW
  twin is identical (C5);
* the snapshot read-back oracle (with V's qemu-img) of every pre-existing
  snapshot equals V's own twin's read-back (C6/C7/C8).

The twin for version V is built by copying the identical seed fixture and
running V's qemu-img for the same op, so the comparison is
version-consistent (instar-under-V vs qemu-V, never cross-wired). Content
seeding uses the system qemu-io (write patterns are version-agnostic
bytes); every version claim is made with the pinned qemu-img. This pins
the 7p finding that qemu's COW semantics are version-invariant
(6.2.0 .. 10.2.0), now against instar's own COW output.

Gated on the pinned binaries being present (skips if absent), like the
other version-matrix tests. Bounded to a small version subset spanning the
range rather than the full ~85-version matrix.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from base import InstarTestBase
from helpers.snapshot_readback import snapshot_readback


class TestCowCrossVersion(InstarTestBase):
    """instar's COW output is valid + parity-correct under pinned qemu."""

    # Representative pinned versions spanning 6.x .. 10.x. Bounded on
    # purpose (7e: "a few fixtures x versions, not a huge matrix").
    VERSIONS = ['6.2.0', '7.2.0', '8.2.0', '9.2.0', '10.2.0']
    CLUSTER_SIZES = [512, 65536]

    def setUp(self):
        super().setUp()
        if shutil.which('qemu-img') is None:
            self.skipTest('system qemu-img not installed')
        if shutil.which('qemu-io') is None:
            self.skipTest('system qemu-io not installed')

    # -- pinned-binary discovery ----------------------------------------

    def _qb_root(self):
        """Return the pinned qemu-img binary root for this arch."""
        return self._testdata_root / 'qemu-img-binaries' / 'x86_64'

    def _present_versions(self):
        """Return [(version, qemu_img_path)] for pinned binaries present.

        Skips the test when none of the pinned versions are available,
        mirroring the other version-matrix tests' graceful degradation.
        """
        root = self._qb_root()
        found = []
        for v in self.VERSIONS:
            p = root / v / 'qemu-img'
            if p.exists() and os.access(p, os.X_OK):
                found.append((v, str(p)))
        if not found:
            self.skipTest(
                f'no pinned qemu-img binaries present under {root}')
        return found

    # -- process helpers -------------------------------------------------

    def _run(self, argv, cwd=None, timeout=180):
        """Run a tool asserting rc 0; return the CompletedProcess."""
        r = subprocess.run(
            [str(a) for a in argv], capture_output=True, text=True,
            timeout=timeout, cwd=str(cwd) if cwd else None)
        self.assertEqual(
            r.returncode, 0,
            f'{argv[0]} failed: argv={argv!r} rc={r.returncode} '
            f'stdout={r.stdout!r} stderr={r.stderr!r}')
        return r

    def _instar(self, *args, timeout=180):
        """Run instar with args; return (stdout, stderr, rc)."""
        instar = self.get_instar_binary()
        r = subprocess.run(
            [str(instar), *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode

    # -- parity assertions ----------------------------------------------

    def _assert_check_clean(self, qbin, ver, image, ctx):
        """Assert `qbin check image` is clean (C5)."""
        r = subprocess.run(
            [qbin, 'check', str(image)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f'[{ver} {ctx}] qemu-img check not clean on instar COW '
            f'output: rc={r.returncode} stdout={r.stdout!r} '
            f'stderr={r.stderr!r}')
        self.assertNotIn(
            'refcount=1 reference=2', r.stdout + r.stderr,
            f'[{ver} {ctx}] refcount=1 reference=2 in instar COW output')

    def _assert_compare_identical(self, qbin, ver, a, b, ctx):
        """Assert `qbin compare a b` reports the active views equal (C5)."""
        r = subprocess.run(
            [qbin, 'compare', str(a), str(b)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f'[{ver} {ctx}] qemu-img compare instar-vs-twin diverged: '
            f'rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')

    def _assert_readback_parity(self, qbin, ver, instar_img, twin_img,
                                snaps, ctx):
        """Assert every snapshot's read-back matches V's own twin."""
        for s in snaps:
            a = snapshot_readback(qbin, instar_img, s)
            b = snapshot_readback(qbin, twin_img, s)
            self.assertEqual(
                a, b,
                f'[{ver} {ctx}] snapshot {s!r} read-back diverged: '
                f'instar={a} twin={b}')

    # -- seed builders (version-agnostic content) -----------------------

    def _seed_commit(self, seed, cs):
        """Q1 commit fixture: snapshot-bearing backing + overlay.

        base.qcow2 (64M, 0xaa at [1M,3M)) with snap1, overlay on it
        (0xcc at [1536k,2560k)). Commit preserves snap1 (C6).
        """
        seed.mkdir(parents=True, exist_ok=True)
        opt = f'cluster_size={cs}'
        self._run(['qemu-img', 'create', '-f', 'qcow2', '-o', opt,
                   'base.qcow2', '64M'], cwd=seed)
        self._run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xaa 1M 2M',
                   'base.qcow2'], cwd=seed)
        self._run(['qemu-img', 'snapshot', '-c', 'snap1', 'base.qcow2'],
                  cwd=seed)
        self._run(['qemu-img', 'create', '-f', 'qcow2', '-o',
                   f'{opt},backing_file=base.qcow2,backing_fmt=qcow2',
                   'overlay.qcow2', '64M'], cwd=seed)
        self._run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xcc 1536k 1M',
                   'overlay.qcow2'], cwd=seed)
        return ['snap1']

    def _seed_rebase(self, seed, cs):
        """Q2 rebase fixture: base_old, base_new, snapshot-bearing overlay.

        base_old (6M, 0x11 [0,4M)), base_new (6M, 0x22 [2M,6M)), overlay
        on base_old (0x33 [1M,2M)) with snap1. Safe rebase reads snap1
        through base_new afterward (C7).
        """
        seed.mkdir(parents=True, exist_ok=True)
        opt = f'cluster_size={cs}'
        for name, pattern in (('base_old.qcow2', 'write -P 0x11 0 4M'),
                              ('base_new.qcow2', 'write -P 0x22 2M 4M')):
            self._run(['qemu-img', 'create', '-f', 'qcow2', '-o', opt,
                       name, '6M'], cwd=seed)
            self._run(['qemu-io', '-f', 'qcow2', '-c', pattern, name],
                      cwd=seed)
        self._run(['qemu-img', 'create', '-f', 'qcow2', '-o',
                   f'backing_file=base_old.qcow2,backing_fmt=qcow2,{opt}',
                   'overlay.qcow2', '6M'], cwd=seed)
        self._run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x33 1M 1M',
                   'overlay.qcow2'], cwd=seed)
        self._run(['qemu-img', 'snapshot', '-c', 'snap1', 'overlay.qcow2'],
                  cwd=seed)
        return ['snap1']

    def _seed_bench(self, seed, cs):
        """bench fixture: a single image whose active clusters are shared.

        64M image, 0xaa across [0,1M), then snap1 -> every allocated
        cluster is snapshot-shared, so `bench -w` must COW (C8).
        """
        seed.mkdir(parents=True, exist_ok=True)
        self._run(['qemu-img', 'create', '-f', 'qcow2', '-o',
                   f'cluster_size={cs}', 'img.qcow2', '64M'], cwd=seed)
        self._run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0xaa 0 1M',
                   'img.qcow2'], cwd=seed)
        self._run(['qemu-img', 'snapshot', '-c', 'snap1', 'img.qcow2'],
                  cwd=seed)
        return ['snap1']

    # -- tests -----------------------------------------------------------

    def test_commit_backing_snapshot_cross_version(self):
        """Commit COW output is check-clean + read-back-parity under all
        pinned qemu versions (C5/C6)."""
        versions = self._present_versions()
        for cs in self.CLUSTER_SIZES:
            with self.subTest(cluster_size=cs), \
                    tempfile.TemporaryDirectory() as td:
                td = Path(td)
                seed = td / 'seed'
                snaps = self._seed_commit(seed, cs)

                idir = td / 'instar'
                shutil.copytree(seed, idir)
                _, err, rc = self._instar('commit', str(idir / 'overlay.qcow2'))
                self.assertEqual(
                    rc, 0, f'instar commit failed (cs={cs}): {err!r}')
                instar_img = idir / 'base.qcow2'

                for ver, qbin in versions:
                    ctx = f'commit cs={cs}'
                    tdir = td / f'twin_{ver}'
                    shutil.copytree(seed, tdir)
                    self._run([qbin, 'commit', 'overlay.qcow2'], cwd=tdir)
                    twin_img = tdir / 'base.qcow2'
                    self._assert_check_clean(qbin, ver, instar_img, ctx)
                    self._assert_compare_identical(
                        qbin, ver, instar_img, twin_img, ctx)
                    self._assert_readback_parity(
                        qbin, ver, instar_img, twin_img, snaps, ctx)
                    shutil.rmtree(tdir)

    def test_safe_rebase_overlay_snapshot_cross_version(self):
        """Safe-rebase COW output is check-clean + read-through-new-backing
        read-back-parity under all pinned qemu versions (C5/C7)."""
        versions = self._present_versions()
        for cs in self.CLUSTER_SIZES:
            with self.subTest(cluster_size=cs), \
                    tempfile.TemporaryDirectory() as td:
                td = Path(td)
                seed = td / 'seed'
                snaps = self._seed_rebase(seed, cs)

                idir = td / 'instar'
                shutil.copytree(seed, idir)
                _, err, rc = self._instar(
                    'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2',
                    str(idir / 'overlay.qcow2'))
                self.assertEqual(
                    rc, 0, f'instar rebase failed (cs={cs}): {err!r}')
                instar_img = idir / 'overlay.qcow2'

                for ver, qbin in versions:
                    ctx = f'rebase cs={cs}'
                    tdir = td / f'twin_{ver}'
                    shutil.copytree(seed, tdir)
                    self._run(
                        [qbin, 'rebase', '-b', 'base_new.qcow2', '-F',
                         'qcow2', 'overlay.qcow2'], cwd=tdir)
                    twin_img = tdir / 'overlay.qcow2'
                    self._assert_check_clean(qbin, ver, instar_img, ctx)
                    self._assert_compare_identical(
                        qbin, ver, instar_img, twin_img, ctx)
                    self._assert_readback_parity(
                        qbin, ver, instar_img, twin_img, snaps, ctx)
                    shutil.rmtree(tdir)

    def test_bench_write_snapshot_cross_version(self):
        """`bench -w` COW output is check-clean + read-back-parity (snapshot
        preserved) under all pinned qemu versions (C5/C8)."""
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            self.skipTest('/dev/kvm not readable+writable')
        versions = self._present_versions()
        bench_args = ['-w', '-c', '100', '--pattern', '65', '-f', 'qcow2']
        for cs in self.CLUSTER_SIZES:
            with self.subTest(cluster_size=cs), \
                    tempfile.TemporaryDirectory() as td:
                td = Path(td)
                seed = td / 'seed'
                snaps = self._seed_bench(seed, cs)

                idir = td / 'instar'
                shutil.copytree(seed, idir)
                instar_img = idir / 'img.qcow2'
                _, err, rc = self._instar(
                    'bench', *bench_args, str(instar_img))
                self.assertEqual(
                    rc, 0, f'instar bench -w failed (cs={cs}): {err!r}')

                for ver, qbin in versions:
                    ctx = f'bench cs={cs}'
                    tdir = td / f'twin_{ver}'
                    shutil.copytree(seed, tdir)
                    twin_img = tdir / 'img.qcow2'
                    self._run([qbin, 'bench', *bench_args, str(twin_img)])
                    self._assert_check_clean(qbin, ver, instar_img, ctx)
                    self._assert_compare_identical(
                        qbin, ver, instar_img, twin_img, ctx)
                    self._assert_readback_parity(
                        qbin, ver, instar_img, twin_img, snaps, ctx)
                    shutil.rmtree(tdir)
