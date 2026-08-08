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

import json  # noqa: F401  (used by helpers/future steps)
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from base import InstarTestBase
from helpers.info_json import assert_info_equivalent


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

    # ------------------------------------------------------------------
    # Baseline helpers (bitmap is qcow2-only, so no `target` parameter).
    # Mirror TestAmendSmoke._baseline_* with the bitmap-info-json tree.
    # ------------------------------------------------------------------

    @classmethod
    def _baseline_root(cls):
        """Root of the bitmap info-JSON baseline tree."""
        return (cls._testdata_root / 'expected-outputs' /
                'bitmap-info-json' / 'qcow2')

    def _baseline_version_dir(self):
        """Version dir under _baseline_root() best matching the
        installed qemu-img (full-version selection via the shared
        base helper), or None when the root is missing or empty.
        """
        return self._pick_baseline_version_dir(self._baseline_root())

    def _baseline_stdout(self, case_name):
        """Return the Path to <version>/<case>.stdout.txt, or None."""
        v_dir = self._baseline_version_dir()
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.stdout.txt'
        return p if p.exists() else None

    def _baseline_meta(self, case_name):
        """Return parsed JSON of <version>/<case>.meta.json, or None."""
        v_dir = self._baseline_version_dir()
        if v_dir is None:
            return None
        p = v_dir / f'{case_name}.meta.json'
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

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
                # Best-effort QMP quit; the finally block below forcibly
                # tears the daemon and sockets down, so a failure here is
                # intentionally ignored.
                pass
            return coalesced
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    # Best-effort socket close during teardown; ignored.
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
                        # Best-effort final reap after kill; ignored.
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

    def test_merge_multi_source_union(self):
        """Multi-source `--merge srcA --merge srcB` in ONE invocation.

        Regression for the host merge-collapse bug (PR #386 finding #1):
        the host used to emit one action per `--merge`, making
        `num_actions == N`, which the guest refuses (it requires
        `num_actions == 1` and loops over `num_merge_sources`). A single
        invocation with two sources must now succeed and produce the
        UNION of both sources' bits in the destination.

        Seed two source bitmaps with DISJOINT dirty ranges at the same
        granularity, add an empty dest, then run the two-source merge on
        an instar copy (A) and a qemu copy (B); assert instar exit 0
        (NOT the old refusal), qemu-img check clean, bitmaps metadata
        equivalent, and dst extents(A) == extents(B) == the union.
        """
        self._require_kvm()

        src_a_writes = [(0, 64 * 1024)]
        src_b_writes = [(1024 * 1024, 64 * 1024)]
        expected_union = [(0, 64 * 1024), (1024 * 1024, 64 * 1024)]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=_G, size='4M')

            # Seed each source (add + writes + DISABLE) BEFORE adding the
            # empty dst, so no seed write can dirty another bitmap's auto
            # recording. Disjoint ranges + same granularity.
            self._seed_bitmap(start, 'srcA', src_a_writes, granularity=_G)
            self._seed_bitmap(start, 'srcB', src_b_writes, granularity=_G)
            self._seed_bitmap(start, 'dst', [], granularity=_G)

            path_a = td / 'a.qcow2'  # instar
            path_b = td / 'b.qcow2'  # qemu
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)

            _, i_err, i_rc = self.run_instar_bitmap(
                '--merge', 'srcA', '--merge', 'srcB', str(path_a), 'dst')
            self.assertEqual(
                i_rc, 0,
                f'instar multi-source --merge should succeed (not the old '
                f'refusal); stderr={i_err!r}')

            _, q_err, q_rc = self._qemu_bitmap(
                '--merge', 'srcA', '--merge', 'srcB', str(path_b), 'dst')
            self.assertEqual(
                q_rc, 0,
                f'qemu-img multi-source --merge failed: {q_err!r}')

            # instar output must pass qemu-img check.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output: {chk_err}')

            # Bitmaps metadata equivalence (qemu-vs-qemu, sorted).
            self.assert_bitmaps_equivalent(
                path_a, path_b, msg='multi-source merge metadata')

            # THE actual merged bits: dst extents must match qemu AND the
            # independently-computed expected union of both sources.
            ext_a = self._bitmap_dirty_extents(path_a, 'dst')
            ext_b = self._bitmap_dirty_extents(path_b, 'dst')
            self.assertEqual(
                ext_a, ext_b,
                f'multi-source merged dst extents diverge from qemu:\n'
                f'  instar A: {ext_a}\n  qemu   B: {ext_b}')
            self.assertEqual(
                ext_a, expected_union,
                f'multi-source merged dst extents wrong:\n'
                f'  got:      {ext_a}\n  expected: {expected_union}')


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


class TestBitmapSameInvocationAddThenFree(TestBitmapSmoke):
    """Add-then-free the SAME bitmap in ONE `instar bitmap` invocation.

    Regression for the stale-table-read corruption (PR #386 finding #1).
    `action_add` allocates a table cluster but DEFERS zero-filling it to
    write_back's end-of-loop ZeroList flush (nothing is written to disk
    during the action loop, for crash safety). If a `--remove`/`--clear`
    of that SAME freshly-added bitmap runs later in the SAME invocation,
    the guest used to call `free_bitmap_data_clusters` on the just-added
    table offset -- which READS the table cluster from disk. That cluster
    was never written, so the read returned STALE bytes from whatever
    previously occupied the reused cluster; decoded as bitmap-table
    entries, any that looked `Allocated(offset)` had their refcount
    zeroed -- silent corruption of live image structures (or a clean
    ERROR_PARSE_FAILED, depending on the stale bytes).

    The fix skips the on-disk table walk when the target table offset is
    still pending in the ZeroList (i.e. freshly added this invocation,
    never written, provably zero data clusters). These tests prove the
    result passes `qemu-img check` and -- the strongest assertion -- that
    an UNRELATED pre-seeded bitmap's live dirty extents are untouched.
    """

    def _diff_add_then_free(self, free_flag, cluster_size=DEFAULT_CLUSTER_SIZE):
        """add + free the same bitmap 'foo' in one invocation; A vs B.

        Runs `bitmap --add foo <free_flag> foo <IMG> foo` on an instar
        copy (A) and a qemu copy (B). Asserts both exit 0, qemu-img
        check(A) CLEAN (pre-fix A could be corrupt), and the bitmaps
        arrays equivalent (neither should have 'foo').
        """
        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=cluster_size)

            path_a = td / 'a.qcow2'  # instar
            path_b = td / 'b.qcow2'  # qemu
            shutil.copy2(start, path_a)
            shutil.copy2(start, path_b)

            _, i_err, i_rc = self.run_instar_bitmap(
                '--add', free_flag, str(path_a), 'foo')
            self.assertEqual(
                i_rc, 0,
                f'instar bitmap --add {free_flag} foo (one invocation) '
                f'failed (cluster_size={cluster_size}): stderr={i_err!r}')
            _, q_err, q_rc = self._qemu_bitmap(
                '--add', free_flag, str(path_b), 'foo')
            self.assertEqual(
                q_rc, 0,
                f'qemu-img bitmap --add {free_flag} foo (one invocation) '
                f'failed (cluster_size={cluster_size}): stderr={q_err!r}')

            # THE key assertion: pre-fix the stale table read could zero a
            # live refcount and leave A corrupt.
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed on instar output for '
                f'--add {free_flag} foo (cluster_size={cluster_size}): '
                f'{chk_err}')

            # Both images should now have no 'foo' bitmap.
            self.assert_bitmaps_equivalent(
                path_a, path_b,
                msg=f'same-invocation add+{free_flag} foo '
                    f'(cluster_size={cluster_size})')

    def test_add_then_remove_same_name(self):
        """`--add foo --remove foo` in one invocation stays CLEAN."""
        self._diff_add_then_free('--remove')

    def test_add_then_clear_same_name(self):
        """`--add foo --clear foo` in one invocation stays CLEAN.

        `--clear` frees the data clusters then defers zeroing the table;
        the stale-read walk lived on this path too, so it exercises a
        distinct free_bitmap_data_clusters call site.
        """
        self._diff_add_then_free('--clear')

    def _keep_bitmap_untouched(self, free_flag):
        """Strongest corruption regression: a live bitmap survives intact.

        Seed an UNRELATED bitmap 'keep' with SET bits (real data + table
        clusters), copy to A (instar), then run `--add foo <free_flag>
        foo` on A in ONE invocation. Pre-fix the guest walked foo's
        never-written table, decoded stale bytes, and could zero the
        refcount of one of keep's live clusters. Assert qemu-img check(A)
        CLEAN and keep's dirty extents are IDENTICAL before and after.
        """
        self._require_kvm()

        keep_writes = [(0, 128 * 1024), (1024 * 1024, 64 * 1024)]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            start = td / 'start.qcow2'
            self._qemu_create(start, cluster_size=_G, size='4M')

            # Seed 'keep' with known dirty bits (add + writes + DISABLE) so
            # it owns live data/table clusters a stale decode could clobber.
            self._seed_bitmap(start, 'keep', keep_writes, granularity=_G)

            path_a = td / 'a.qcow2'  # instar
            shutil.copy2(start, path_a)

            # Baseline keep extents BEFORE the add+free invocation.
            keep_before = self._bitmap_dirty_extents(path_a, 'keep')
            self.assertEqual(
                keep_before, keep_writes,
                f'seed sanity: keep extents {keep_before} != seeded '
                f'{keep_writes}')

            _, i_err, i_rc = self.run_instar_bitmap(
                '--add', free_flag, str(path_a), 'foo')
            self.assertEqual(
                i_rc, 0,
                f'instar bitmap --add {free_flag} foo (with live keep) '
                f'failed: stderr={i_err!r}')

            # Image must be structurally clean...
            _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
            self.assertEqual(
                chk_rc, 0,
                f'qemu-img check failed after --add {free_flag} foo with '
                f'live keep bitmap: {chk_err}')

            # ...and keep's live dirty extents must be UNCHANGED -- proof
            # the stale table read did not zero a live cluster's refcount.
            keep_after = self._bitmap_dirty_extents(path_a, 'keep')
            self.assertEqual(
                keep_after, keep_before,
                f'live keep bitmap corrupted by same-invocation '
                f'--add {free_flag} foo:\n'
                f'  before: {keep_before}\n  after:  {keep_after}')

    def test_add_then_remove_keeps_live_bitmap(self):
        """`--add foo --remove foo` leaves an unrelated 'keep' intact."""
        self._keep_bitmap_untouched('--remove')

    def test_add_then_clear_keeps_live_bitmap(self):
        """`--add foo --clear foo` leaves an unrelated 'keep' intact."""
        self._keep_bitmap_untouched('--clear')

    def _reuse_stale_table_corruption(self, free_flag):
        """Deterministic stale-table-reuse corruption reproduction.

        Force the freshly-added bitmap's DEFERRED (never-written) table
        cluster to REUSE a freed cluster that still holds a stale
        `Allocated(offset)` bitmap-table entry pointing at a NOW-LIVE
        cluster, then free that bitmap in the SAME invocation. Pre-fix,
        `free_bitmap_data_clusters` read the never-written table cluster,
        decoded the stale entry, and zeroed a LIVE cluster's refcount --
        qemu-img check reports `refcount=0 reference=1`. Post-fix the
        walk is skipped for a freshly-added table, so the image is CLEAN.

        Recipe (verified to corrupt pre-fix on qemu-img 10.0.8):
          1. Add a bitmap 'victim' with SET bits: qemu allocates a data
             cluster D and a table cluster T whose entry is
             `Allocated(D)`.
          2. Remove 'victim': qemu ZEROES D but leaves T's stale
             `Allocated(D)` bytes on disk, both now freed (refcount 0).
          3. Reallocate the low freed clusters (INCLUDING D) with fresh
             guest-data writes, so D becomes LIVE again while the stale
             table cluster T remains the lowest free cluster.
          4. `--add foo <free_flag> foo` in ONE invocation: foo's add
             reuses T (deferred, unwritten); the same-invocation free
             walked T pre-fix and zeroed D's (now live) refcount.

        Which cluster the linear-scan allocator lands on is qcow2-layout
        dependent, so a few guest-write counts are swept. The fix makes
        EVERY one CLEAN regardless of the cluster reused (the invariant
        under test); at least one count reproduced the corruption pre-fix
        (n_writes=1 -> `cluster 4 refcount=0`, n_writes=3 ->
        `cluster 9 refcount=0`).
        """
        self._require_kvm()

        for n_writes in (1, 2, 3, 4):
            with tempfile.TemporaryDirectory() as td:
                td = Path(td)
                img = td / 'img.qcow2'
                self._qemu_create(img, cluster_size=_G, size='4M')

                # victim: a table cluster holding Allocated(data-cluster).
                _, err, rc = self._qemu_bitmap(
                    '--add', '-g', str(_G), str(img), 'victim')
                self.assertEqual(rc, 0, f'add victim failed: {err!r}')
                self._qemu_io(img, 'write 0 128k')
                _, err, rc = self._qemu_bitmap('--remove', str(img), 'victim')
                self.assertEqual(rc, 0, f'remove victim failed: {err!r}')

                # Reallocate the low freed clusters (incl. victim's old
                # data cluster) so the stale entry's target is LIVE.
                off = 1024 * 1024
                for _ in range(n_writes):
                    self._qemu_io(img, f'write {off} 64k')
                    off += 128 * 1024

                path_a = td / 'a.qcow2'
                shutil.copy2(img, path_a)

                _, i_err, i_rc = self.run_instar_bitmap(
                    '--add', free_flag, str(path_a), 'foo')
                self.assertEqual(
                    i_rc, 0,
                    f'instar --add {free_flag} foo (n_writes={n_writes}) '
                    f'failed: stderr={i_err!r}')

                # THE regression assertion: the stale-table walk must not
                # have zeroed a live cluster's refcount.
                _, chk_err, chk_rc = self.run_qemu_img_check(path_a)
                self.assertEqual(
                    chk_rc, 0,
                    f'stale-table reuse corrupted the image for '
                    f'--add {free_flag} foo (n_writes={n_writes}): '
                    f'qemu-img check: {chk_err}')

    def test_stale_table_reuse_remove_stays_clean(self):
        """add + `--remove` reusing a stale table cluster stays CLEAN."""
        self._reuse_stale_table_corruption('--remove')

    def test_stale_table_reuse_clear_stays_clean(self):
        """add + `--clear` reusing a stale table cluster stays CLEAN."""
        self._reuse_stale_table_corruption('--clear')


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

    def test_too_many_merge_sources_refused(self):
        """More than 8 `--merge` sources is refused host-side.

        Regression for PR #386 finding #2: before the merge-collapse fix
        each `--merge` was a separate action, so the generic `too many
        actions (max 8)` guard fired first and the per-source
        `MAX_MERGE_SOURCES` limit was unreachable. Now a merge is ONE
        action carrying N sources, so 9 sources must hit the dedicated
        `too many --merge sources` message. Host-side; needs no /dev/kvm.
        """
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / 'img.qcow2'
            self._qemu_create(img)
            merge_flags = []
            for i in range(9):
                merge_flags += ['--merge', f'src{i}']
            _, stderr, rc = self.run_instar_bitmap(
                *merge_flags, str(img), 'dst')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse 9 --merge sources; stderr={stderr!r}')
            self.assertIn('too many --merge sources', stderr,
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

    def test_qed_refused(self):
        """A qed image is refused host-side, byte-unchanged.

        Format-coverage phase 6 keeps QED read-refused as policy (see
        docs/plans/PLAN-format-coverage-phase-06-qed.md).  QED's
        offset-0 header magic is recognised by `probe_bitmap_target`,
        which runs before any guest launch (no kvm) and refuses every
        non-qcow2 format -- so a QED image is refused with "not a qcow2
        image" and left untouched.  qemu-img has no QED bitmap driver
        either, so this is a refusal pin, not a divergence.
        """
        image = self.get_image('qed-simple')
        if not image.path.exists():
            self.skipTest(f'fixture not available: {image.path}')
        self.skip_if_hash_mismatch(image)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'img.qed'
            shutil.copy(str(image.path), str(path))
            before = path.read_bytes()
            _, stderr, rc = self.run_instar_bitmap('--add', str(path), 'b0')
            self.assertNotEqual(
                rc, 0,
                f'instar should refuse a qed image; stderr={stderr!r}')
            self.assertIn('not a qcow2 image', stderr,
                          f'unexpected stderr: {stderr!r}')
            self.assertEqual(
                path.read_bytes(), before,
                'a refused bitmap op must not touch the qed image')

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


# ----------------------------------------------------------------------
# Cross-version baseline comparison matrix (Phase 8).
#
# BITMAP_BASELINE_CASES is the instar-side replica of the generator's
# BITMAP_CASES (../instar-testdata/scripts/generate-baselines.py). Each
# entry maps a case name to the LIST of bitmap ops applied in order.
# Each op is a full `qemu-img bitmap` arg list whose trailing token is
# the bitmap name and whose leading tokens are the flags -- exactly the
# generator shape, so instar replays what qemu-img recorded. All cases
# create with `qemu-img create -f qcow2 -o compat=1.1 <tmp> 1M`.
#
# Unlike the live differential (BITMAP_CASES above), this compares
# qemu-img info of INSTAR's output against a stored pure-qemu baseline;
# instar's own `info` emitting no bitmaps is irrelevant here.
# ----------------------------------------------------------------------
BITMAP_BASELINE_CASES = {
    'add-default':     [['--add', 'b0']],
    'add-granularity': [['--add', '-g', '131072', 'b0']],
    'add-disabled':    [['--add', '--disable', 'b0']],
    'disable':         [['--add', 'b0'], ['--disable', 'b0']],
    'enable':          [['--add', 'b0'], ['--disable', 'b0'],
                        ['--enable', 'b0']],
    'clear':           [['--add', 'b0'], ['--clear', 'b0']],
    'two-bitmaps':     [['--add', 'b0'], ['--add', '-g', '131072', 'b1']],
    'remove-last':     [['--add', 'b0'], ['--remove', 'b0']],
}

# Registry of intentional instar-vs-qemu baseline divergences (cases to
# skip). Empty: the metadata surface is expected to match exactly.
KNOWN_BITMAP_BASELINE_DIVERGENCES = {}


class TestBitmapBaselineMatrix(TestBitmapSmoke):
    """Cross-version baseline comparison for `instar bitmap`.

    For each entry in BITMAP_BASELINE_CASES, the per-case factory:
    - Builds the start image with system `qemu-img create -f qcow2 -o
      compat=1.1 <tmp> 1M` (matching the generator exactly).
    - Replays the case's op sequence with `instar bitmap`.
    - Runs system `qemu-img info --output=json` on the result.
    - Asserts equivalence (via the bitmaps-array-sorting normaliser)
      against the version-matched baseline recorded in the sibling
      `instar-testdata` repo under expected-outputs/bitmap-info-json/
      qcow2/<version>/<case>.stdout.txt.

    The whole matrix skips when the baseline tree is absent (not yet
    generated for the host qemu version).
    """

    @staticmethod
    def _run_qemu_img_info(path, timeout=30):
        """Run system `qemu-img info --output=json`.

        No -f flag so auto-detect matches what the baseline generator
        recorded. Returns (stdout, stderr, rc). Returns
        ('', 'qemu-img info ... not installed', -1) on FileNotFoundError.
        """
        try:
            r = subprocess.run(
                ['qemu-img', 'info', '--output=json', str(path)],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return '', 'qemu-img info: command not installed', -1
        except subprocess.TimeoutExpired:
            return '', f'qemu-img info timeout after {timeout}s', -1

    def test_bitmap_cases_match_baselines(self):
        """Schema-drift tripwire: on-disk baseline stems must equal
        BITMAP_BASELINE_CASES names.

        Walks <testdata>/expected-outputs/bitmap-info-json/qcow2/
        <version>/ and asserts the *.stdout.txt stems match the mirror.
        Catches drift between this mirror and the testdata baseline
        generator in either direction.
        """
        v_dir = self._baseline_version_dir()
        if v_dir is None:
            self.skipTest('no bitmap baseline dir found in testdata')
        on_disk = {
            p.stem.rsplit('.stdout', 1)[0]
            for p in v_dir.glob('*.stdout.txt')
        }
        in_mirror = set(BITMAP_BASELINE_CASES)
        missing_from_mirror = on_disk - in_mirror
        missing_from_disk = in_mirror - on_disk
        self.assertEqual(
            missing_from_mirror, set(),
            f'Baselines on disk not in BITMAP_BASELINE_CASES: '
            f'{missing_from_mirror}',
        )
        self.assertEqual(
            missing_from_disk, set(),
            f'BITMAP_BASELINE_CASES entries with no on-disk baseline: '
            f'{missing_from_disk}. Regenerate baselines via '
            f'instar-testdata (bitmap-baselines branch).',
        )


def _make_bitmap_baseline_test(case_name):
    """Factory: one baseline test method per BITMAP_BASELINE_CASES entry.

    The returned test:
    - Skips when no version-matched baseline is on disk.
    - Skips when the baseline recorded a non-zero create/op/info rc
      (qemu couldn't produce a comparable artefact for that version),
      or when the case is in KNOWN_BITMAP_BASELINE_DIVERGENCES.
    - Requires /dev/kvm (bitmap launches a guest VMM).
    - Builds the start image with system qemu-img create -o compat=1.1
      <tmp> 1M (matching the generator exactly).
    - Replays the op sequence with instar bitmap (each op rc must be 0 --
      an instar failure where qemu succeeded is a real bug).
    - Runs system qemu-img info --output=json.
    - Asserts equivalence via assert_info_equivalent (the normaliser
      sorts the bitmaps array).
    """
    ops = BITMAP_BASELINE_CASES[case_name]

    def test(self):
        meta = self._baseline_meta(case_name)
        if meta is None:
            self.skipTest(
                f'no baseline meta for qcow2/{case_name} '
                f'(installed qemu version not in matrix?)'
            )
        if meta.get('create_return_code', 0) != 0:
            self.skipTest(
                f'baseline create_rc={meta["create_return_code"]} '
                f'(qemu rejected create); no comparable artefact'
            )
        if any(rc != 0 for rc in meta.get('op_return_codes', [])):
            self.skipTest(
                f'baseline op_return_codes={meta["op_return_codes"]} '
                f'(qemu rejected an op); no comparable artefact'
            )
        if meta.get('info_return_code', 0) != 0:
            self.skipTest(
                f'baseline info_rc={meta["info_return_code"]} '
                f'(no comparable JSON)'
            )
        if case_name in KNOWN_BITMAP_BASELINE_DIVERGENCES:
            self.skipTest(
                f'known bitmap divergence: '
                f'{KNOWN_BITMAP_BASELINE_DIVERGENCES[case_name]}'
            )

        baseline_path = self._baseline_stdout(case_name)
        if baseline_path is None:
            self.skipTest(f'no baseline stdout for qcow2/{case_name}')

        self._require_kvm()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'image.qcow2'

            # Build the start image with system qemu-img create, matching
            # the generator: `qemu-img create -f qcow2 -o compat=1.1 1M`.
            cmd = ['qemu-img', 'create', '-f', 'qcow2',
                   '-o', 'compat=1.1', str(path), '1M']
            try:
                r = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30)
            except FileNotFoundError:
                self.skipTest('system qemu-img not installed')
            self.assertEqual(
                r.returncode, 0,
                f'qemu-img create failed for qcow2/{case_name}: '
                f'{r.stderr!r}'
            )

            # Replay the op sequence with instar bitmap. op[-1] is the
            # bitmap name; op[:-1] are the flag tokens.
            for op in ops:
                flags = list(op[:-1])
                name = op[-1]
                _, i_stderr, i_rc = self.run_instar_bitmap(
                    *flags, str(path), name)
                self.assertEqual(
                    i_rc, 0,
                    f'instar bitmap {op} failed for qcow2/{case_name}: '
                    f'stderr={i_stderr!r}'
                )

            # Run system qemu-img info --output=json.
            info_stdout, info_stderr, info_rc = self._run_qemu_img_info(path)
            if info_rc == -1 and 'not installed' in info_stderr:
                self.skipTest('system qemu-img not installed')
            self.assertEqual(
                info_rc, 0,
                f'qemu-img info failed for qcow2/{case_name}: '
                f'{info_stderr!r}'
            )

            expected = baseline_path.read_text()
            assert_info_equivalent(
                self, info_stdout, expected, 'qcow2',
                tmp_path=str(path),
                msg=f'qcow2/{case_name}',
            )

    test.__name__ = f'test_baseline_{case_name.replace("-", "_")}'
    test.__doc__ = (
        f'instar bitmap qcow2/{case_name}: create compat=1.1 -> apply '
        f'{ops} matches recorded baseline.'
    )
    return test


for _bcase in BITMAP_BASELINE_CASES:
    _bname = f'test_baseline_{_bcase.replace("-", "_")}'
    setattr(TestBitmapBaselineMatrix, _bname,
            _make_bitmap_baseline_test(_bcase))
