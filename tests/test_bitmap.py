"""Integration tests for `instar bitmap`.

Phase 7 of PLAN-bitmap.md. The live differential suite: for each
case in `BITMAP_CASES`, create a qcow2 image with `qemu-img`, copy
it to A (instar) and B (qemu), apply the same sequence of bitmap
actions to each -- `instar bitmap ...` on A and `qemu-img bitmap
...` on B -- then assert `qemu-img check` passes on the instar
output and the two images carry an equivalent `bitmaps` array (read
via `qemu-img info --output=json` on *both* copies).

CRITICAL: instar's `info` emits no bitmaps (Phase-1 step 1e was
deferred), so the info cross-check is **qemu-vs-qemu**: both A and B
are read with `qemu-img info` and their `format-specific.data.bitmaps`
arrays compared, sorted by name (the on-disk directory order may
differ between the two independently-produced images).

This is the *live* differential against the locally-installed
`qemu-img` (10.0.8). `bitmap` launches a guest VM, so the test
classes guard on `/dev/kvm` (mirroring amend's guest-needs-kvm
skip). Fixtures are built with `qemu-img create` at compat=1.1
(bitmaps require qcow2 v3).

Step 7a covers the metadata-action + ordered-sequence + empty-merge
matrix across a cluster-size spread. The bits-set merge oracle
(7b) and the refusal suite (7c) are added in later steps.
"""

import copy  # noqa: F401  (registry-style symmetry with test_amend.py)
import json  # noqa: F401  (used by helpers/future steps)
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from base import InstarTestBase


# ----------------------------------------------------------------------
# KNOWN_BITMAP_DIVERGENCES -- registry of intentional instar-vs-qemu
# differences. Mirrors `KNOWN_AMEND_DIVERGENCES`. Keyed by a descriptive
# string -> reason. A cross-validation case that fails while NOT
# registered here is a real regression to investigate, not to silence.
#
# In every case instar is deliberately MORE CONSERVATIVE than qemu-img:
# it refuses an operation qemu accepts. `TestBitmapRefusals` asserts the
# instar refusal AND (where a live scenario is cheap to build) that qemu
# accepts the same input, documenting -- not failing on -- the gap.
# Entries without a live test still document the intentional divergence.
# ----------------------------------------------------------------------
KNOWN_BITMAP_DIVERGENCES = {
    'merge_mixed':
        'qemu applies --merge and metadata actions in CLI order in one '
        'invocation; instar v1 requires a merge to be the sole action',
    'cross_file_merge':
        'qemu supports --merge -b SOURCE_FILE; instar v1 same-file merge '
        'only',
    'refcount_bits':
        'instar refuses refcount_bits != 16 '
        '(ERROR_UNSUPPORTED_REFCOUNT_WIDTH); qemu supports other widths',
    'refcount_exhausted':
        'instar refuses when existing refblocks are full (ERROR_NO_SPACE) '
        'rather than growing the refcount table',
}


class TestBitmapSmoke(InstarTestBase):
    """Parent class for the bitmap test families.

    Owns the `instar bitmap` runner, the `/dev/kvm` skip guard, the
    `qemu-img create` fixture helper, the `qemu-img bitmap` oracle,
    the JSON-info helper, and the bitmaps-array comparison. Child
    classes (the cross-validation matrix and later the merge-bits and
    refusal suites) inherit all of it.
    """

    def run_instar_bitmap(self, *args, timeout=120):
        """Helper: invoke `instar bitmap` with the given args.

        Returns (stdout, stderr, returncode). Timeout 120s because
        bitmap spins up the guest VMM.
        """
        instar = self.get_instar_binary()
        cmd = [str(instar), 'bitmap', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _require_kvm(self):
        """Skip the test when `/dev/kvm` is not readable+writable.

        bitmap launches a guest VM; mirror amend's guest-needs-kvm
        skip so the suite degrades gracefully where kvm is
        unavailable.
        """
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            self.skipTest('/dev/kvm not readable+writable')

    def _qemu_create(self, path, cluster_size=65536, compat='1.1',
                     size='64M'):
        """Create a qcow2 fixture with `qemu-img create`.

        Bitmaps require qcow2 v3, so the default is compat=1.1. The
        cluster size is parametrised so the cross-validation matrix
        can sweep the sizes that surfaced the amend `.bss` bug.
        """
        cmd = ['qemu-img', 'create', '-f', 'qcow2',
               '-o', f'compat={compat},cluster_size={cluster_size}',
               str(path), str(size)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img create failed for {path}: {r.stderr!r}')

    def _qemu_info_json(self, path, timeout=30):
        """Run `qemu-img info --output=json` and return the parsed dict.

        instar `info` emits no bitmaps, so the bitmaps cross-check
        reads *both* copies with qemu-img.
        """
        r = subprocess.run(
            ['qemu-img', 'info', '--output=json', str(path)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-img info --output=json failed for {path}: {r.stderr!r}')
        return json.loads(r.stdout)

    def _qemu_bitmap(self, *args, timeout=60):
        """Run `qemu-img bitmap` (the oracle side).

        Returns (stdout, stderr, returncode). Positional shape mirrors
        instar: `qemu-img bitmap [ACTIONS] FILENAME BITMAP`.
        """
        cmd = ['qemu-img', 'bitmap', *[str(a) for a in args]]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            return '', f'Timeout after {timeout}s', -1

    def _bitmaps_of(self, info_json):
        """Extract the normalised, name-sorted bitmaps list from a
        parsed `qemu-img info --output=json` dict.

        Each entry is `{name, granularity, flags}`; the `flags` list is
        sorted so flag ordering never causes a false mismatch, and the
        overall list is sorted by name so on-disk directory order (which
        may differ between two independently-produced images) is
        irrelevant. Missing keys collapse to an empty list.
        """
        data = (info_json.get('format-specific', {}) or {}).get('data', {}) or {}
        bitmaps = data.get('bitmaps', []) or []
        normalised = []
        for b in bitmaps:
            normalised.append({
                'name': b.get('name'),
                'granularity': b.get('granularity'),
                'flags': sorted(b.get('flags', []) or []),
            })
        normalised.sort(key=lambda e: (e['name'] is None, e['name']))
        return normalised

    def assert_bitmaps_equivalent(self, path_a, path_b, msg=''):
        """Assert the bitmaps arrays of two images match (qemu-vs-qemu).

        Reads both `path_a` (instar output) and `path_b` (qemu output)
        with `qemu-img info --output=json`, extracts and name-sorts the
        `format-specific.data.bitmaps` arrays, and asserts equality.
        This is the Open-question-1 order-safe comparison; corruption is
        caught separately by `qemu-img check`.
        """
        ba = self._bitmaps_of(self._qemu_info_json(path_a))
        bb = self._bitmaps_of(self._qemu_info_json(path_b))
        self.assertEqual(
            bb, ba,
            f'{msg}\n--- instar A bitmaps ---\n'
            f'{json.dumps(ba, indent=2, sort_keys=True)}\n'
            f'--- qemu B bitmaps ---\n'
            f'{json.dumps(bb, indent=2, sort_keys=True)}')

    # ------------------------------------------------------------------
    # Bits-set seeding + read-back oracle (step 7b, Open question 2).
    #
    # `_seed_bitmap` uses qemu-img/qemu-io to write KNOWN dirty extents
    # into a bitmap (never instar), and `_bitmap_dirty_extents` reads
    # them back neutrally via a qemu-storage-daemon NBD export. The
    # `x-dirty-bitmap` DIRTY == `"data": false` polarity lives in ONE
    # place (`_bitmap_dirty_extents`) so no other test reasons about it.
    # Neither helper needs /dev/kvm -- only the `instar bitmap` call
    # under test does.
    # ------------------------------------------------------------------

    def _qemu_io(self, img, cmd, timeout=30):
        """Run a single `qemu-io -c CMD IMG` command; assert rc 0."""
        r = subprocess.run(
            ['qemu-io', '-c', cmd, str(img)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(
            r.returncode, 0,
            f'qemu-io -c {cmd!r} failed for {img}: {r.stderr!r}')
        return r

    def _seed_bitmap(self, img, name, writes, granularity=None):
        """Seed a bitmap with KNOWN dirty extents, then disable it.

        `qemu-img bitmap --add [-g granularity] IMG name` creates an
        enabled/auto bitmap; each `(offset, length)` in `writes` is
        dirtied into it with `qemu-io -c "write OFF LEN"`; then
        `qemu-img bitmap --disable IMG name` stops recording (required
        before a read-only NBD export).

        Seed (and DISABLE) the source bitmap BEFORE adding an empty
        destination, so a later `qemu-io` write cannot also dirty the
        destination's auto bitmap.
        """
        add_args = ['--add']
        if granularity is not None:
            add_args += ['-g', str(granularity)]
        add_args += [str(img), name]
        _, err, rc = self._qemu_bitmap(*add_args)
        self.assertEqual(
            rc, 0, f'qemu-img bitmap --add {name} failed: {err!r}')
        for off, length in writes:
            self._qemu_io(img, f'write {off} {length}')
        _, err, rc = self._qemu_bitmap('--disable', str(img), name)
        self.assertEqual(
            rc, 0, f'qemu-img bitmap --disable {name} failed: {err!r}')

    def _qmp_exchange(self, sock, command):
        """Send one QMP command and return its `return`/`error` reply.

        Handles the JSON-line protocol: asynchronous events (which lack
        both `return` and `error`) are skipped until the reply to this
        command arrives.
        """
        sock.sendall((json.dumps(command) + '\r\n').encode())
        buf = b''
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError(
                    f'QMP socket closed awaiting reply to {command!r}')
            buf += chunk
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                line = line.strip()
                if not line:
                    continue
                msg = json.loads(line)
                if 'return' in msg or 'error' in msg:
                    return msg

    def _bitmap_dirty_extents(self, img, name, timeout=30):
        """Read a bitmap's dirty extents back neutrally (the oracle).

        Launches `qemu-storage-daemon` exposing `img` (read-only) over a
        unix NBD socket with the named bitmap attached, driven via QMP
        `block-export-add`, then runs `qemu-img map --output=json` over
        the NBD export with `x-dirty-bitmap=qemu:dirty-bitmap:NAME`.

        The `x-dirty-bitmap` convention inverts `data`: a DIRTY cluster
        reports `"data": false` and a clean cluster `"data": true`. This
        polarity is centralised HERE (Open question 2).

        Returns a SORTED, COALESCED list of `(offset, length)` dirty
        ranges. The bitmap MUST be disabled (see `_seed_bitmap`) for the
        read-only export. Needs no /dev/kvm. The daemon is always torn
        down and the sockets removed in a `finally`.
        """
        tmpd = tempfile.mkdtemp(prefix='bitmap-oracle.')
        nbd_sock = os.path.join(tmpd, 'nbd.sock')
        qmp_sock = os.path.join(tmpd, 'qmp.sock')
        daemon = None
        sock = None
        try:
            daemon = subprocess.Popen(
                ['qemu-storage-daemon',
                 '--blockdev',
                 f'node-name=n0,driver=qcow2,file.filename={img},'
                 f'file.driver=file,read-only=on',
                 '--nbd-server', f'addr.type=unix,addr.path={nbd_sock}',
                 '--chardev',
                 f'socket,id=qmp,path={qmp_sock},server=on,wait=off',
                 '--monitor', 'chardev=qmp'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Wait for the QMP socket to appear (or the daemon to die).
            deadline = time.time() + timeout
            while not os.path.exists(qmp_sock):
                if daemon.poll() is not None:
                    _, err = daemon.communicate()
                    raise RuntimeError(
                        f'qemu-storage-daemon exited early: '
                        f'{err.decode(errors="replace")}')
                if time.time() > deadline:
                    raise RuntimeError('QMP socket did not appear in time')
                time.sleep(0.02)

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(qmp_sock)
            sock.recv(65536)  # QMP greeting.

            reply = self._qmp_exchange(sock, {'execute': 'qmp_capabilities'})
            self.assertIn(
                'return', reply, f'qmp_capabilities failed: {reply!r}')
            reply = self._qmp_exchange(sock, {
                'execute': 'block-export-add',
                'arguments': {
                    'type': 'nbd', 'id': 'exp', 'node-name': 'n0',
                    'name': 'exp', 'writable': False, 'bitmaps': [name]}})
            self.assertIn(
                'return', reply, f'block-export-add failed: {reply!r}')

            deadline = time.time() + timeout
            while not os.path.exists(nbd_sock):
                if time.time() > deadline:
                    raise RuntimeError('NBD socket did not appear in time')
                time.sleep(0.02)

            image_opts = (
                f'driver=nbd,server.type=unix,server.path={nbd_sock},'
                f'export=exp,x-dirty-bitmap=qemu:dirty-bitmap:{name}')
            mp = subprocess.run(
                ['qemu-img', 'map', '--output=json', '--image-opts',
                 image_opts],
                capture_output=True, text=True, timeout=timeout)
            self.assertEqual(
                mp.returncode, 0,
                f'qemu-img map failed for bitmap {name}: {mp.stderr!r}')

            # DIRTY == "data": false (the x-dirty-bitmap convention).
            extents = [
                (int(e['start']), int(e['length']))
                for e in json.loads(mp.stdout)
                if e.get('data') is False]
            extents.sort()
            coalesced = []
            for start, length in extents:
                if coalesced and start == coalesced[-1][0] + coalesced[-1][1]:
                    coalesced[-1] = (coalesced[-1][0],
                                     coalesced[-1][1] + length)
                else:
                    coalesced.append((start, length))

            try:
                self._qmp_exchange(sock, {'execute': 'quit'})
            except Exception:
                pass
            return coalesced
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            if daemon is not None:
                try:
                    daemon.terminate()
                    daemon.wait(timeout=5)
                except Exception:
                    daemon.kill()
                    try:
                        daemon.wait(timeout=5)
                    except Exception:
                        pass
            shutil.rmtree(tmpd, ignore_errors=True)


# ----------------------------------------------------------------------
# BITMAP_CASES -- the differential matrix.
#
# Each case is `(case_name, ops)` where `ops` is a list of bitmap
# invocations to apply, in order, to BOTH copies. Each op is a tuple
# of argument tokens that follow the subcommand but PRECEDE the
# positional `<FILENAME> <BITMAP>`; the factory appends `str(path)`
# and the bitmap name from the op's last token. To keep instar and
# qemu perfectly parallel we express each op as:
#
#     (flags..., bitmap_name)
#
# and, for --merge, as ('--merge', source_name, bitmap_name) with the
# filename spliced between source and bitmap by the factory. See
# `_make_bitmap_diff_test` for the exact splicing.
# ----------------------------------------------------------------------
BITMAP_CASES = [
    # name              ops (each: list of (flag-tokens..., final positional))
    ('add',             [('--add', 'b0')]),
    ('add_gran',        [('--add', '-g', '131072', 'b0')]),
    ('remove',          [('--add', 'b0'), ('--remove', 'b0')]),
    ('clear',           [('--add', 'b0'), ('--clear', 'b0')]),
    ('disable',         [('--add', 'b0'), ('--disable', 'b0')]),
    ('enable',          [('--add', 'b0'), ('--disable', 'b0'),
                         ('--enable', 'b0')]),
    ('add_disable_seq', [('--add', '--disable', 'b1')]),
    ('two_bitmaps',     [('--add', 'b0'), ('--add', '-g', '131072', 'b1')]),
    ('empty_merge',     [('--add', 'src'), ('--add', 'dst'),
                         ('--merge', 'src', 'dst')]),
]

# Cluster sizes to sweep. Every case runs at the 64 KiB default; a
# subset (the pure metadata add/remove/add-disable ops) also runs at
# 512 / 4096 / 1 MiB to catch cluster-size-dependent corruption of
# the class the amend `.bss` bug belonged to.
DEFAULT_CLUSTER_SIZE = 65536
EXTRA_CLUSTER_SIZES = [512, 4096, 1048576]
EXTRA_CLUSTER_CASES = {'add', 'remove', 'add_disable_seq'}


class TestBitmapCrossValidation(TestBitmapSmoke):
    """Live cross-validation against the system qemu-img.

    For each `(case, cluster_size)` in the matrix, builds a start
    image, copies it to A (instar) and B (qemu), applies the same op
    sequence to each, then asserts `qemu-img check(A)` passes and the
    two images' bitmaps arrays are equivalent (sorted by name).
    """

    pass


def _make_bitmap_diff_test(case, cluster_size):
    """Factory: one differential test method per (case, cluster_size)."""
    case_name, ops = case

    def test(self):
        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=cluster_size)

            path_a = td / 'a.qcow2'  # instar
            path_b = td / 'b.qcow2'  # qemu
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)

            for op in ops:
                if op[0] == '--merge':
                    # ('--merge', source, bitmap) -> instar/qemu shape is
                    # `bitmap --merge <source> <FILENAME> <BITMAP>`.
                    _, source, bitmap = op
                    i_out, i_err, i_rc = self.run_instar_bitmap(
                        '--merge', source, str(path_a), bitmap)
                    q_out, q_err, q_rc = self._qemu_bitmap(
                        '--merge', source, str(path_b), bitmap)
                else:
                    # (flags..., bitmap) -> `bitmap <flags...> <FILE> <BITMAP>`.
                    flags = list(op[:-1])
                    bitmap = op[-1]
                    i_out, i_err, i_rc = self.run_instar_bitmap(
                        *flags, str(path_a), bitmap)
                    q_out, q_err, q_rc = self._qemu_bitmap(
                        *flags, str(path_b), bitmap)

                self.assertEqual(
                    i_rc, 0,
                    f'instar bitmap {op} failed for {case_name} '
                    f'(cluster_size={cluster_size}): stderr={i_err!r}')
                self.assertEqual(
                    q_rc, 0,
                    f'qemu-img bitmap {op} failed for {case_name} '
                    f'(cluster_size={cluster_size}): stderr={q_err!r}')

            # The instar output must pass qemu-img check.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output for {case_name} '
                f'(cluster_size={cluster_size}): stderr={chk_err}')

            # Bitmaps-array equivalence (qemu-vs-qemu, sorted by name).
            self.assert_bitmaps_equivalent(
                path_a, path_b,
                msg=f'bitmap cross-validation {case_name} '
                    f'(cluster_size={cluster_size})')

    safe = case_name.replace('-', '_')
    test.__name__ = f'test_diff_{safe}_cs{cluster_size}'
    test.__doc__ = (
        f'instar bitmap vs qemu-img bitmap for {case_name} at '
        f'cluster_size={cluster_size}: apply {ops}, then check + '
        f'bitmaps-array equivalence.')
    return test


def _install_bitmap_diff_tests():
    """Install the (case x cluster-size) differential matrix."""
    for case in BITMAP_CASES:
        case_name = case[0]
        sizes = [DEFAULT_CLUSTER_SIZE]
        if case_name in EXTRA_CLUSTER_CASES:
            sizes = sizes + EXTRA_CLUSTER_SIZES
        for cs in sizes:
            t = _make_bitmap_diff_test(case, cs)
            setattr(TestBitmapCrossValidation, t.__name__, t)


_install_bitmap_diff_tests()


# ----------------------------------------------------------------------
# MERGE_BITS_VARIANTS -- the bits-set same-file merge matrix (step 7b).
#
# Each variant seeds a SOURCE bitmap 'src' with known dirty writes and a
# DEST bitmap 'dst' (possibly pre-seeded with its own writes), then merges
# 'src' into 'dst' and asserts the resulting dst dirty extents match qemu
# bit-for-bit. Writes are `(offset, length)` byte ranges; the expected
# result is the coalesced union of the src and dst writes. All images are
# v3 (compat=1.1) with a 64 KiB cluster and 64 KiB bitmap granularity so
# a write maps to exactly one bitmap cluster.
#
# name -> (src_writes, dst_writes, expected_dst_extents)
# ----------------------------------------------------------------------
_G = 65536  # bitmap granularity (bytes); also the cluster size.

MERGE_BITS_VARIANTS = {
    # disjoint: src {0..128k}, dst empty -> dst gets {0..128k}.
    'disjoint': (
        [(0, 128 * 1024)],
        [],
        [(0, 128 * 1024)],
    ),
    # overlapping: src {0..128k}, dst pre-seeded {64k..192k} ->
    # dst becomes the union {0..192k}.
    'overlapping': (
        [(0, 128 * 1024)],
        [(64 * 1024, 128 * 1024)],
        [(0, 192 * 1024)],
    ),
    # into_nonempty_disjoint: src {0..64k}, dst pre-seeded {1M..1M+64k}
    # -> union of both (two disjoint ranges).
    'into_nonempty_disjoint': (
        [(0, 64 * 1024)],
        [(1024 * 1024, 64 * 1024)],
        [(0, 64 * 1024), (1024 * 1024, 64 * 1024)],
    ),
}


class TestBitmapMergeBits(TestBitmapSmoke):
    """Bits-set same-file `--merge`, cross-validated against qemu.

    The first real exercise of the Phase-4 guest merge orchestration:
    seed known dirty bits into 'src' (and optionally 'dst'), copy the
    image to A (instar) and B (qemu), run `bitmap --merge src <img> dst`
    on each, then assert (a) `qemu-img check(A)` clean, (b) the bitmaps
    metadata (name/granularity/flags) equivalent, and (c) the actual
    merged dst dirty extents identical -- the merged BITS match qemu.

    `test_oracle_roundtrip` proves the read-back oracle in isolation
    (no instar, no merge) before the merge matrix is built on it.
    """

    def test_oracle_roundtrip(self):
        """The read-back oracle returns exactly the seeded extents.

        Proves `_seed_bitmap` + `_bitmap_dirty_extents` before the merge
        matrix relies on them. Needs no /dev/kvm.
        """
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'oracle.qcow2'
            self._qemu_create(img, cluster_size=_G, size='4M')
            writes = [(0, 128 * 1024), (1024 * 1024, 64 * 1024)]
            self._seed_bitmap(img, 'b0', writes, granularity=_G)
            self.assertEqual(
                self._bitmap_dirty_extents(img, 'b0'),
                [(0, 128 * 1024), (1024 * 1024, 64 * 1024)],
                'oracle read-back did not match the seeded writes')


def _make_merge_bits_test(name, spec):
    """Factory: one bits-set merge differential test per variant."""
    src_writes, dst_writes, expected = spec

    def test(self):
        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=_G, size='4M')

            # Seed 'src' (add + writes + DISABLE) BEFORE adding 'dst',
            # so the dst writes below cannot dirty src's auto bitmap.
            self._seed_bitmap(start, 'src', src_writes, granularity=_G)
            # 'dst': add + optional pre-seed writes + DISABLE. An empty
            # `dst_writes` yields an empty, disabled destination bitmap.
            self._seed_bitmap(start, 'dst', dst_writes, granularity=_G)

            path_a = td / 'a.qcow2'  # instar
            path_b = td / 'b.qcow2'  # qemu
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)

            _, i_err, i_rc = self.run_instar_bitmap(
                '--merge', 'src', str(path_a), 'dst')
            self.assertEqual(
                i_rc, 0,
                f'instar bitmap --merge failed for {name}: {i_err!r}')
            _, q_err, q_rc = self._qemu_bitmap(
                '--merge', 'src', str(path_b), 'dst')
            self.assertEqual(
                q_rc, 0,
                f'qemu-img bitmap --merge failed for {name}: {q_err!r}')

            # instar output must pass qemu-img check.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output for {name}: '
                f'{chk_err}')

            # Bitmaps metadata equivalence (qemu-vs-qemu, sorted).
            self.assert_bitmaps_equivalent(
                path_a, path_b,
                msg=f'bits-set merge metadata {name}')

            # THE actual merged bits: dst extents must match qemu AND the
            # independently-computed expected union.
            ext_a = self._bitmap_dirty_extents(path_a, 'dst')
            ext_b = self._bitmap_dirty_extents(path_b, 'dst')
            self.assertEqual(
                ext_a, ext_b,
                f'merged dst extents diverge from qemu for {name}:\n'
                f'  instar A: {ext_a}\n  qemu   B: {ext_b}')
            self.assertEqual(
                ext_a, expected,
                f'merged dst extents wrong for {name}:\n'
                f'  got:      {ext_a}\n  expected: {expected}')

    test.__name__ = f'test_merge_bits_{name}'
    test.__doc__ = (
        f'bits-set same-file merge ({name}): merge src {src_writes} into '
        f'dst {dst_writes}; assert check + metadata + merged extents '
        f'{expected} match qemu.')
    return test


def _install_merge_bits_tests():
    """Install the bits-set merge differential matrix."""
    for name, spec in MERGE_BITS_VARIANTS.items():
        t = _make_merge_bits_test(name, spec)
        setattr(TestBitmapMergeBits, t.__name__, t)


_install_merge_bits_tests()


# ----------------------------------------------------------------------
# TestBitmapRefusals -- the error-path contracts (step 7c, Mission §4).
#
# Every case asserts `rc != 0` and `assertIn(substr, stderr)` against the
# EXACT Phase-5 host messages (`src/vmm/src/main.rs` `run_bitmap` +
# `map_bitmap_error`). Cases split into two kinds:
#
#   * HOST-SIDE (argument validation + the non-qcow2 probe): these fail
#     in `run_bitmap` / `probe_bitmap_target` BEFORE any guest launch, so
#     they DO NOT call `_require_kvm()` -- they run (fast) even without
#     /dev/kvm.
#   * GUEST-SIDE (mapped from `map_bitmap_error`): these launch the guest
#     VMM, so they call `_require_kvm()` first and self-skip without kvm.
#
# Where qemu-img is MORE permissive than instar (mixed --merge, cross-
# file -b), the test also runs the qemu equivalent, asserts qemu accepts
# it, and records the difference against KNOWN_BITMAP_DIVERGENCES rather
# than failing -- exactly `test_amend.py`'s divergence-record pattern.
# ----------------------------------------------------------------------
class TestBitmapRefusals(TestBitmapSmoke):
    """Refusal contracts for `instar bitmap`, matched to the Phase-5
    host messages, plus the intentional instar-over-refuses divergences.
    """

    # ---- Host-side argument-validation refusals (no guest, no kvm) ----

    def test_object_refused(self):
        """`--object` is an unsupported surface, refused host-side."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--add', '--object', 'foo', str(img), 'b0')
            self.assertNotEqual(
                rc, 0, f'instar should refuse --object; stderr={stderr!r}')
            self.assertIn('--object is not yet supported', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_image_opts_refused(self):
        """`--image-opts` is an unsupported surface, refused host-side."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--add', '--image-opts', str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse --image-opts; stderr={stderr!r}')
            self.assertIn('--image-opts', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_cross_file_merge_refused(self):
        """Cross-file `--merge -b SOURCE_FILE` is refused host-side.

        DIVERGENCE (KNOWN_BITMAP_DIVERGENCES['cross_file_merge']): qemu
        supports cross-file merge; instar v1 is same-file only. We assert
        instar refuses AND that qemu accepts the same operation, recording
        (not failing on) the gap.
        """
        self.assertIn('cross_file_merge', KNOWN_BITMAP_DIVERGENCES)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            img = td / 'img.qcow2'
            other = td / 'other.qcow2'
            self._qemu_create(img)
            self._qemu_create(other)
            # Source bitmap 'src' lives in `other`; destination 'dst' in
            # `img` (qemu needs both to actually perform the merge).
            self.assertEqual(
                self._qemu_bitmap('--add', str(other), 'src')[2], 0)
            self.assertEqual(
                self._qemu_bitmap('--add', str(img), 'dst')[2], 0)

            _, stderr, rc = self.run_instar_bitmap(
                '--merge', 'src', '-b', str(other), str(img), 'dst')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse cross-file merge; stderr={stderr!r}')
            self.assertIn('cross-file merge', stderr,
                          f'unexpected stderr: {stderr!r}')

            # qemu accepts the same cross-file merge -> record divergence.
            qimg = td / 'qemu.qcow2'
            shutil.copy2(img, qimg)
            _, q_err, q_rc = self._qemu_bitmap(
                '--merge', 'src', '-b', str(other), str(qimg), 'dst')
            self.assertEqual(
                q_rc, 0,
                f'qemu unexpectedly refused cross-file merge (the '
                f'divergence premise no longer holds): stderr={q_err!r}')

    def test_no_actions_refused(self):
        """No action flags at all is refused host-side."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse no-action invocation; '
                f'stderr={stderr!r}')
            self.assertIn('Need at least one of --add', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_granularity_without_add_refused(self):
        """`-g` without `--add` is refused host-side."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--disable', '-g', '64k', str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse -g without --add; stderr={stderr!r}')
            self.assertIn('granularity only supported with --add', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_merge_mixed_refused(self):
        """`--merge` mixed with metadata actions is refused host-side.

        DIVERGENCE (KNOWN_BITMAP_DIVERGENCES['merge_mixed']): qemu applies
        --merge and metadata actions in CLI order in one invocation;
        instar v1 requires a merge to be the sole action. We assert instar
        refuses AND that qemu accepts the mixed invocation, recording the
        gap.
        """
        self.assertIn('merge_mixed', KNOWN_BITMAP_DIVERGENCES)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            img = td / 'img.qcow2'
            self._qemu_create(img)
            # 'src' must exist for qemu's merge half to succeed.
            self.assertEqual(self._qemu_bitmap('--add', str(img), 'src')[2], 0)

            _, stderr, rc = self.run_instar_bitmap(
                '--merge', 'src', '--add', str(img), 'dst')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse mixed --merge + --add; '
                f'stderr={stderr!r}')
            self.assertIn('mixing --merge with other actions', stderr,
                          f'unexpected stderr: {stderr!r}')

            # qemu accepts `--add --merge src img dst` (adds dst, merges
            # src into it, in CLI order) -> record divergence.
            qimg = td / 'qemu.qcow2'
            shutil.copy2(img, qimg)
            _, q_err, q_rc = self._qemu_bitmap(
                '--add', '--merge', 'src', str(qimg), 'dst')
            self.assertEqual(
                q_rc, 0,
                f'qemu unexpectedly refused mixed --add/--merge (the '
                f'divergence premise no longer holds): stderr={q_err!r}')

    def test_bad_granularity_refused(self):
        """A non-power-of-two granularity is refused host-side."""
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--add', '-g', '100000', str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a non-power-of-two granularity; '
                f'stderr={stderr!r}')
            self.assertIn('granularity must be a power of two', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_not_qcow2_refused(self):
        """A non-qcow2 image is refused host-side by `probe_bitmap_target`.

        The probe runs before any guest launch, so this needs no kvm.
        """
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td) / 'raw.img'
            # A plain zero-filled file: not a qcow2 magic header.
            with open(raw, 'wb') as f:
                f.truncate(4 * 1024 * 1024)
            _, stderr, rc = self.run_instar_bitmap('--add', str(raw), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a non-qcow2 image; stderr={stderr!r}')
            self.assertIn('not a qcow2 image', stderr,
                          f'unexpected stderr: {stderr!r}')

    # ---- Guest-side refusals (mapped from map_bitmap_error; need kvm) --

    def test_v2_image_refused(self):
        """A qcow2 v2 image cannot store dirty bitmaps (guest-side)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'v2.qcow2'
            self._qemu_create(img, compat='0.10')
            _, stderr, rc = self.run_instar_bitmap('--add', str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a qcow2 v2 image; stderr={stderr!r}')
            self.assertIn(
                'cannot store dirty bitmaps in a qcow2 v2 image', stderr,
                f'unexpected stderr: {stderr!r}')

    def test_duplicate_add_refused(self):
        """Adding a bitmap that already exists is refused (guest-side)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            self.assertEqual(self._qemu_bitmap('--add', str(img), 'b0')[2], 0)
            _, stderr, rc = self.run_instar_bitmap('--add', str(img), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a duplicate --add; stderr={stderr!r}')
            self.assertIn('bitmap already exists', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_remove_missing_refused(self):
        """Removing a non-existent bitmap is refused (guest-side)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--remove', str(img), 'nope')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse removing a missing bitmap; '
                f'stderr={stderr!r}')
            self.assertIn('bitmap not found', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_enable_missing_refused(self):
        """Enabling a non-existent bitmap is refused (guest-side)."""
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            _, stderr, rc = self.run_instar_bitmap(
                '--enable', str(img), 'nope')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse enabling a missing bitmap; '
                f'stderr={stderr!r}')
            self.assertIn('bitmap not found', stderr,
                          f'unexpected stderr: {stderr!r}')

    def test_merge_source_missing_refused(self):
        """Merging from a non-existent source is refused (guest-side).

        The destination bitmap exists; only the merge SOURCE is missing,
        so the guest returns ERROR_MERGE_SOURCE_NOT_FOUND
        ("merge source bitmap not found").
        """
        self._require_kvm()
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            self.assertEqual(
                self._qemu_bitmap('--add', str(img), 'dst')[2], 0)
            _, stderr, rc = self.run_instar_bitmap(
                '--merge', 'nosrc', str(img), 'dst')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a missing merge source; '
                f'stderr={stderr!r}')
            self.assertIn('merge source', stderr,
                          f'unexpected stderr: {stderr!r}')
