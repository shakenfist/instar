#!/usr/bin/env python3
"""Migration-proof harness: instar-before vs instar-after byte identity.

The phase-1 Q3 oracle for the qcow2-write migrations (phases 4-6 of
PLAN-qcow2-write-infrastructure.md). For a deterministic fixture matrix
built fresh each run with a pinned qemu-img, the harness:

  1. builds THREE identical fixture sets per combo (twin equality is
     verified by sha256 before anything runs);
  2. runs the after-binary twice on twins and asserts instar's own
     run-to-run determinism (rc, stdout, stderr, and the sha256 of every
     mutated file) — the premise of the proof;
  3. runs the before-binary on the third twin and asserts before == after
     per bucket:
       - both-succeed: identical rc, stdout, stderr, and sha256 of the
         overlay and the backing;
       - both-refuse: identical rc, stdout, stderr, AND identical sha256s
         of the mutated scaffolding (pre-refusal mutation must be byte-
         identical too — a mismatch is a hard failure, not an exclusion);
       - refuse-before/succeed-after: must be pre-declared (the deliberate
         capacity widenings); anything undeclared is a hard failure;
       - succeed-before/refuse-after: always a hard failure.

Every combo appears in the per-combo TSV with its bucket and verdict;
nothing is skipped and there are no tolerance windows. The only sanctioned
fallback is the D9 unaligned-virtual-size combo (decision 7 of the phase-4
plan): if raw sha256 differs there, virtual-content equality (qemu-img
convert to raw) is checked and the divergence reported loudly and
separately — it is expected to be unnecessary after step 4q.

For --op commit the matrix is: cluster_size {512, 4096, 65536} x
size {1M, 64M} x seed {empty, 64k-at-0, multi-extent} x lazy_refcounts
{off, on} x {implicit, explicit -b} = 72 combos, plus one unaligned-size
combo (1M+512, 64K clusters, seeded, implicit). The expected-refusal
inventory (exactly the eight cs=512 multi-extent combos, wire-11 refcount
exhaustion) carries over from the 4p D6 probe, so the seed recipes must
not drift from d6-matrix.py's offsets and patterns.

Commit additionally runs the D6 capacity-widening exemplar outside the
matrix (cs=512 16M backing with 8M seeded -> 66 populated refcount-table
entries): before must refuse wire-10 pre-mutation, after must succeed
deterministically, `qemu-img check` must be clean on the result, and the
result must be info-equivalent to a `qemu-img commit` twin.

Usage:
    scripts/migration-proof.py --op commit \
        --before /path/to/pre-migration/dist/instar \
        --after src/target/release/instar \
        [--qemu-img qemu-img] [--qemu-io qemu-io] \
        [--workdir /path/to/workdir] [--combo cs512] [--keep-all]

Both instar binaries are invoked by absolute path with the fixture set
directory as cwd; each binary loads its .bin operation siblings relative
to its own location, so the surrounding dist/target layout matters — pass
the binary inside its build output directory, do not copy it out alone.

Exit status is non-zero on any failure. Combo directories are deleted on
PASS to bound disk use (keep with --keep-all); failing directories are
always kept for post-mortem.

Reusable for phases 5-6: add an entry to OPS wiring up the op's fixture
builder, invocation, mutated-file list and expected-refusal inventory.
"""

import argparse
import hashlib
import itertools
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile


CLUSTER_SIZES = [512, 4096, 65536]
SIZES = [1024 * 1024, 64 * 1024 * 1024]
SEEDS = ['empty', '64k-at-0', 'multi-extent']
SEEDS_REBASE = ['divergent', 'identical', 'empty']
LAZY = ['off', 'on']
BASE_MODES = ['implicit', 'explicit']

RUN_TIMEOUT = 600

# qemu-img info fields that legitimately diverge between two writers of
# the same logical image (cribbed from tests/helpers/info_json.py).
INFO_STRIP_KEYS = {
    'actual-size',
    'dirty-flag',
    'refcount-block-cache-size',
    'l2-cache-size',
    'l2-cache-entry-size',
    'cache-clean-interval',
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd, timeout=RUN_TIMEOUT):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def check_run(cmd, cwd, timeout=RUN_TIMEOUT):
    r = run(cmd, cwd, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f'fixture command failed rc={r.returncode}: {cmd}\nstderr: {r.stderr}')
    return r


class Invocation:
    """rc/stdout/stderr plus the post-run sha256 of every mutated file."""

    def __init__(self, result, setdir, mutated_files):
        self.rc = result.returncode
        self.stdout = result.stdout
        self.stderr = result.stderr
        self.shas = {name: sha256(os.path.join(setdir, name)) for name in mutated_files}

    def signature(self):
        return (self.rc, self.stdout, self.stderr, tuple(sorted(self.shas.items())))


def diff_invocations(label_a, a, label_b, b):
    """Human-readable list of differing fields between two invocations."""
    diffs = []
    if a.rc != b.rc:
        diffs.append(f'rc {label_a}={a.rc} {label_b}={b.rc}')
    if a.stdout != b.stdout:
        diffs.append(f'stdout {label_a}={a.stdout!r} {label_b}={b.stdout!r}')
    if a.stderr != b.stderr:
        diffs.append(f'stderr {label_a}={a.stderr!r} {label_b}={b.stderr!r}')
    for name in a.shas:
        if a.shas[name] != b.shas[name]:
            diffs.append(f'sha256({name}) {label_a}={a.shas[name]} {label_b}={b.shas[name]}')
    return diffs


# ---------------------------------------------------------------------------
# commit fixtures
# ---------------------------------------------------------------------------

def commit_matrix():
    """The phase-1 Q3 matrix plus the decision-7 unaligned-size combo.

    Expected buckets are the 4p D6 inventory (d6-results.tsv): every
    refusal on this matrix is wire-11 refcount exhaustion on the eight
    cs=512 multi-extent combos; refuse-before/succeed-after is empty ON
    the matrix (the widening exemplar lives outside it).
    """
    combos = []
    for cs, size, seed, lazy, bm in itertools.product(CLUSTER_SIZES, SIZES, SEEDS, LAZY, BASE_MODES):
        tag = f'cs{cs}-sz{size // (1024 * 1024)}M-{seed}-lazy{lazy}-{bm}'
        expected = 'both-refuse' if (cs == 512 and seed == 'multi-extent') else 'both-succeed'
        combos.append({'tag': tag, 'cs': cs, 'size': size, 'seed': seed, 'lazy': lazy,
                       'base_mode': bm, 'expected': expected, 'd9': False})
    combos.append({'tag': 'cs65536-sz1M+512-64k-at-0-lazyoff-implicit-UNALIGNED',
                   'cs': 65536, 'size': 1024 * 1024 + 512, 'seed': '64k-at-0', 'lazy': 'off',
                   'base_mode': 'implicit', 'expected': 'both-succeed', 'd9': True})
    return combos


def build_commit_fixture(combo, setdir, qemu_img, qemu_io):
    """One backing + seeded overlay pair; relative paths only, so twin
    sets built in different directories are byte-identical. Seed offsets
    and patterns must match 4p's d6-matrix.py exactly."""
    os.makedirs(setdir)
    opts = f'cluster_size={combo["cs"]},lazy_refcounts={combo["lazy"]}'
    size = str(combo['size'])
    check_run([qemu_img, 'create', '-f', 'qcow2', '-o', opts, 'backing.qcow2', size], setdir)
    check_run([qemu_img, 'create', '-f', 'qcow2', '-o', opts, '-b', 'backing.qcow2', '-F', 'qcow2',
               'overlay.qcow2', size], setdir)
    ios = []
    if combo['seed'] == '64k-at-0':
        ios = ['write -P 0xbb 0 64k']
    elif combo['seed'] == 'multi-extent':
        half = combo['size'] // 2
        tail = combo['size'] - 65536
        ios = ['write -P 0xb1 0 64k', f'write -P 0xb2 {half} 64k', f'write -P 0xb3 {tail} 64k']
    if ios:
        args = []
        for c in ios:
            args += ['-c', c]
        check_run([qemu_io, '-f', 'qcow2'] + args + ['overlay.qcow2'], setdir)


def run_commit(binary, setdir, combo):
    cmd = [binary, 'commit']
    if combo['base_mode'] == 'explicit':
        cmd += ['-b', 'backing.qcow2']
    cmd += ['overlay.qcow2']
    r = run(cmd, setdir)
    return Invocation(r, setdir, COMMIT_MUTATED_FILES)


COMMIT_MUTATED_FILES = ['overlay.qcow2', 'backing.qcow2']


def virtual_sha256(qemu_img, setdir, name):
    """sha256 of the image's virtual content via qemu-img convert to raw."""
    raw = os.path.join(setdir, name + '.virtual.raw')
    check_run([qemu_img, 'convert', '-f', 'qcow2', '-O', 'raw', name, os.path.basename(raw)], setdir)
    digest = sha256(raw)
    os.unlink(raw)
    return digest


# ---------------------------------------------------------------------------
# matrix driver
# ---------------------------------------------------------------------------

def prove_combo(combo, workdir, args):
    """Build twins, assert determinism, bucket, verdict. Returns a TSV row
    dict; row['fail'] truthy means the run must exit non-zero.

    Op-generic: the fixture builder, the invocation runner and the mutated-
    file list come from the OPS registry entry for args.op, so commit's code
    path is byte-for-byte the functions it always called (build_commit_fixture
    / run_commit / COMMIT_MUTATED_FILES)."""
    spec = OPS[args.op]
    build = spec['build']
    runner = spec['run']
    files = spec['files'](combo)
    combo_dir = os.path.join(workdir, combo['tag'])
    if os.path.exists(combo_dir):
        shutil.rmtree(combo_dir)
    sets = {name: os.path.join(combo_dir, name) for name in ('after-run-1', 'after-run-2', 'before-run')}
    for setdir in sets.values():
        build(combo, setdir, args.qemu_img, args.qemu_io)

    # Twin equality before anything runs.
    pre = {}
    for name, setdir in sets.items():
        pre[name] = {f: sha256(os.path.join(setdir, f)) for f in files}
    if not (pre['after-run-1'] == pre['after-run-2'] == pre['before-run']):
        return {'combo': combo, 'bucket': 'n/a', 'verdict': 'FIXTURE-NONDETERMINISTIC',
                'detail': f'twin fixture sets differ pre-run: {pre}', 'fail': True,
                'before': None, 'after': None}

    after1 = runner(args.after, sets['after-run-1'], combo)
    after2 = runner(args.after, sets['after-run-2'], combo)
    before = runner(args.before, sets['before-run'], combo)
    row = {'combo': combo, 'before': before, 'after': after1, 'fail': False, 'detail': ''}

    # Premise: run-to-run determinism of the after binary.
    det_diffs = diff_invocations('run1', after1, 'run2', after2)
    if det_diffs:
        row.update(bucket='n/a', verdict='DETERMINISM-FAIL', fail=True,
                   detail='after-run-1 vs after-run-2: ' + '; '.join(det_diffs))
        return row

    if before.rc == 0 and after1.rc == 0:
        bucket = 'both-succeed'
    elif before.rc != 0 and after1.rc != 0:
        bucket = 'both-refuse'
    elif before.rc != 0:
        bucket = 'refuse-before-succeed-after'
    else:
        bucket = 'succeed-before-refuse-after'
    row['bucket'] = bucket

    if bucket != combo['expected']:
        row.update(verdict='BUCKET-MISMATCH', fail=True,
                   detail=f'expected {combo["expected"]}, observed {bucket} '
                          f'(before rc={before.rc} stderr={before.stderr!r}; '
                          f'after rc={after1.rc} stderr={after1.stderr!r})')
        return row

    diffs = diff_invocations('before', before, 'after', after1)
    if not diffs:
        row['verdict'] = 'PASS'
        return row

    # The single sanctioned fallback: D9 unaligned-size combo, virtual-content
    # equality when raw sha256 differs (decision 7; expected unnecessary
    # after 4q — flag loudly if it triggers).
    only_sha_diffs = all(d.startswith('sha256(') for d in diffs)
    if combo['d9'] and bucket == 'both-succeed' and only_sha_diffs:
        virt_equal = all(
            virtual_sha256(args.qemu_img, sets['before-run'], f) ==
            virtual_sha256(args.qemu_img, sets['after-run-1'], f)
            for f in files)
        if virt_equal:
            row.update(verdict='D9-VIRTUAL-EQUAL', fail=False,
                       detail='LOUD: raw sha256 divergence on a pre-declared D9 combo, virtual content '
                              'identical (EOV-tail / decision-8 fallback triggered — expected for commit '
                              'unnecessary after 4q, expected for rebase on the oversized-backing shape): '
                              + '; '.join(diffs))
            return row
        row.update(verdict='D9-VIRTUAL-DIVERGENT', fail=True,
                   detail='unaligned combo diverges even in virtual content: ' + '; '.join(diffs))
        return row

    row.update(verdict='BYTE-MISMATCH', fail=True, detail='; '.join(diffs))
    return row


# ---------------------------------------------------------------------------
# commit extra checks: the D6 capacity-widening exemplar (off-matrix)
# ---------------------------------------------------------------------------

def build_widening_fixture(setdir, qemu_img, qemu_io):
    """4p's off-matrix exemplar: cs=512 16M backing with 8M seeded (66
    populated refcount-table entries > the old 32-refblock cap), small
    seeded overlay."""
    os.makedirs(setdir)
    check_run([qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=512', 'base.qcow2', '16M'], setdir)
    check_run([qemu_io, '-f', 'qcow2', '-c', 'write -P 0x11 0 8M', 'base.qcow2'], setdir)
    check_run([qemu_img, 'create', '-f', 'qcow2',
               '-o', 'cluster_size=512,backing_file=base.qcow2,backing_fmt=qcow2', 'overlay.qcow2', '16M'], setdir)
    check_run([qemu_io, '-f', 'qcow2', '-c', 'write -P 0xbb 0 64k', 'overlay.qcow2'], setdir)


def normalise_info(stdout_json):
    """Strip writer-divergent fields (cribbed from tests/helpers/info_json.py).

    Fixtures are built and inspected with relative paths from inside the
    set directory, so filename fields are already identical across sets
    and need no substitution."""
    obj = json.loads(stdout_json)

    def strip(node):
        if isinstance(node, dict):
            for k in list(node.keys()):
                if k in INFO_STRIP_KEYS:
                    del node[k]
                else:
                    strip(node[k])
        elif isinstance(node, list):
            for item in node:
                strip(item)

    strip(obj)
    children = obj.get('children') if isinstance(obj, dict) else None
    if isinstance(children, list):
        for child in children:
            info = child.get('info') if isinstance(child, dict) else None
            if isinstance(info, dict):
                info.pop('virtual-size', None)
    return obj


def prove_widening_exemplar(workdir, args):
    """Returns a list of failure strings (empty on success)."""
    failures = []
    ex_dir = os.path.join(workdir, 'widening-exemplar')
    if os.path.exists(ex_dir):
        shutil.rmtree(ex_dir)
    sets = {name: os.path.join(ex_dir, name) for name in ('before-run', 'after-run-1', 'after-run-2', 'qemu-run')}
    for setdir in sets.values():
        build_widening_fixture(setdir, args.qemu_img, args.qemu_io)

    files = ['overlay.qcow2', 'base.qcow2']
    pre = {name: {f: sha256(os.path.join(setdir, f)) for f in files} for name, setdir in sets.items()}
    if len({tuple(sorted(v.items())) for v in pre.values()}) != 1:
        return [f'widening exemplar twin sets differ pre-run: {pre}']

    def run_instar(binary, setdir):
        r = run([binary, 'commit', 'overlay.qcow2'], setdir)
        inv = Invocation.__new__(Invocation)
        inv.rc, inv.stdout, inv.stderr = r.returncode, r.stdout, r.stderr
        inv.shas = {f: sha256(os.path.join(setdir, f)) for f in files}
        return inv

    # before: wire-10 refusal, pre-mutation (backing untouched).
    before = run_instar(args.before, sets['before-run'])
    if before.rc == 0:
        failures.append('widening exemplar: before-binary unexpectedly succeeded (expected wire-10 refusal)')
    elif 'error 10' not in before.stderr:
        failures.append(f'widening exemplar: before-binary refused but not wire-10: stderr={before.stderr!r}')
    if before.shas['base.qcow2'] != pre['before-run']['base.qcow2']:
        failures.append('widening exemplar: before-binary refusal mutated the backing (expected pre-mutation)')

    # after: succeeds, deterministically.
    after1 = run_instar(args.after, sets['after-run-1'])
    after2 = run_instar(args.after, sets['after-run-2'])
    if after1.rc != 0:
        failures.append(f'widening exemplar: after-binary refused: rc={after1.rc} stderr={after1.stderr!r}')
        return failures
    det = diff_invocations('run1', after1, 'run2', after2)
    if det:
        failures.append('widening exemplar: after-binary nondeterministic: ' + '; '.join(det))

    # qemu-img check clean on both mutated files.
    for f in files:
        r = run([args.qemu_img, 'check', f], sets['after-run-1'])
        if r.returncode != 0:
            failures.append(f'widening exemplar: qemu-img check {f} not clean after instar commit: '
                            f'rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')

    # qemu-img commit twin; normalized info equivalence on overlay + backing.
    r = run([args.qemu_img, 'commit', 'overlay.qcow2'], sets['qemu-run'])
    if r.returncode != 0:
        failures.append(f'widening exemplar: qemu-img commit twin failed: {r.stderr!r}')
    else:
        for f in files:
            a = check_run([args.qemu_img, 'info', '--output=json', f], sets['after-run-1'])
            b = check_run([args.qemu_img, 'info', '--output=json', f], sets['qemu-run'])
            na, nb = normalise_info(a.stdout), normalise_info(b.stdout)
            if na != nb:
                failures.append(f'widening exemplar: normalized info mismatch on {f}: '
                                f'instar={json.dumps(na, sort_keys=True)} '
                                f'qemu={json.dumps(nb, sort_keys=True)}')

    if not failures and not args.keep_all:
        shutil.rmtree(ex_dir)
    return failures


# ---------------------------------------------------------------------------
# rebase fixtures (phase 5)
# ---------------------------------------------------------------------------
#
# The 5b matrix per the phase-5 plan and its 5p outcome notes:
#
#   cluster_size {512, 4096, 65536} x overlay size {1M, 64M}
#     x chain {2-chain rebase-to-base, 3-chain CHAIN-SHORTENING, safe detach}
#     x seed {divergent, identical, empty} x mode {safe, -u}
#
# Pruning (documented, honest — every surviving combo is in the TSV):
#   * detach x identical is incoherent (no new backing to be identical to);
#     5p pruned it. Dropped.
#   * -u ignores the seed entirely (metadata-only header/path patch), so it
#     is run ONCE per (cs, size, chain), not once per seed. The -u fixture is
#     built with the 'divergent' seed as a representative (its content is
#     ignored by -u).
#   * 3-chain uses the SHORTENING form (overlay->mid0->base, new backing =
#     base): the plain rebase-to-mid keeps old and new chains identical and
#     copies nothing (5p warning). mid0.qcow2 (10 chars) >= base.qcow2 so the
#     new-backing path fits the overlay's existing backing-path slot (5p
#     wire-8 warning).
#   * NO `write -z` zero-flag seeds anywhere (the P7 chain-reader defect would
#     contaminate the comparison).
#
# Seed offsets/patterns are frozen to 5p's run_matrix.py so the expected
# both-refuse inventory does not drift: every cs=512 x divergent x safe combo
# refuses wire 10 (v1 never appends refblocks — orphan-append scaffolding
# identity is the both-refuse bar). That is exactly 3 chains x 2 sizes = 6
# rows.
#
# Plus three appended combos:
#   * UNALIGNED (1M+512, cs=65536): backings sized to the overlay, divergence
#     placed in the EOV-tail cluster so the crate's zero-fill of beyond-EOV
#     bytes is compared against a source that is itself zero there -> fully
#     byte-identical (no D9).
#   * OVERSIZED (P6's shape): old backing 2M carrying 0x55 past the overlay's
#     1M+512 EOV, divergent -> the pre-declared D9 fallback (raw sha diverges
#     beyond EOV, virtual content identical).
#   * JSON-COUNTER: a cs=65536/64M/2chain/divergent/safe combo run with
#     --output json so before-vs-after stdout identity pins clusters_copied /
#     bytes_copied (they print in --output json only).

REBASE_DIV = {1024 * 1024: ('256k', '256k'), 64 * 1024 * 1024: ('2M', '2M')}
UNALIGNED_SIZE = 1024 * 1024 + 512
OVERSIZED_BACKING = 2 * 1024 * 1024


def rebase_files(combo):
    """The overlay plus every backing file in the fixture. Backings are never
    mutated by rebase; comparing them too is the honest superset (both-succeed
    demands overlay AND backing sha identity)."""
    chain = combo['chain']
    if chain == '3chainb':
        return ['overlay.qcow2', 'base.qcow2', 'mid0.qcow2']
    if chain == 'detach':
        return ['overlay.qcow2', 'base_old.qcow2']
    # 2chain, unaligned, oversized
    return ['overlay.qcow2', 'base_old.qcow2', 'base_new.qcow2']


def _q_create(qemu_img, setdir, name, size, cs, backing=None):
    opts = f'cluster_size={cs}'
    cmd = [qemu_img, 'create', '-f', 'qcow2', '-o', opts]
    if backing:
        cmd = [qemu_img, 'create', '-f', 'qcow2', '-o',
               f'backing_file={backing},backing_fmt=qcow2,cluster_size={cs}']
    cmd += [name, str(size)]
    check_run(cmd, setdir)


def _q_write(qemu_io, setdir, name, *cmds):
    args = [qemu_io, '-f', 'qcow2']
    for c in cmds:
        args += ['-c', c]
    args.append(name)
    check_run(args, setdir)


def build_rebase_fixture(combo, setdir, qemu_img, qemu_io):
    """Relative paths only, so twin sets in different dirs are byte-identical.

    Frozen to 5p's run_matrix.py / run_matrix_3chainb.py seed offsets."""
    os.makedirs(setdir)
    cs = combo['cs']
    special = combo.get('special')
    ovl_w = 'write -P 0x33 0 64k'

    if special == 'unaligned':
        # 2-chain, overlay 1M+512, backings sized to the overlay: the tail
        # cluster's beyond-EOV source bytes are zeros -> byte-identical copy.
        for name in ('base_old.qcow2', 'base_new.qcow2'):
            _q_create(qemu_img, setdir, name, UNALIGNED_SIZE, cs)
        _q_write(qemu_io, setdir, 'base_old.qcow2', 'write -P 0x55 1M 512')
        _q_create(qemu_img, setdir, 'overlay.qcow2', UNALIGNED_SIZE, cs, backing='base_old.qcow2')
        _q_write(qemu_io, setdir, 'overlay.qcow2', ovl_w)
        return
    if special == 'oversized':
        # P6's D9 shape: old backing 2M carrying 0x55 over [1M, 2M) (non-zero
        # past the overlay's 1M+512 EOV); new backing 2M empty.
        for name in ('base_old.qcow2', 'base_new.qcow2'):
            _q_create(qemu_img, setdir, name, OVERSIZED_BACKING, cs)
        _q_write(qemu_io, setdir, 'base_old.qcow2', 'write -P 0x55 1M 1M')
        _q_create(qemu_img, setdir, 'overlay.qcow2', UNALIGNED_SIZE, cs, backing='base_old.qcow2')
        _q_write(qemu_io, setdir, 'overlay.qcow2', ovl_w)
        return

    size = combo['size']
    seed = combo['seed']
    div_off, div_len = REBASE_DIV[size]
    chain = combo['chain']

    if chain == '2chain':
        _q_create(qemu_img, setdir, 'base_old.qcow2', size, cs)
        _q_create(qemu_img, setdir, 'base_new.qcow2', size, cs)
        if seed == 'divergent':
            _q_write(qemu_io, setdir, 'base_old.qcow2', f'write -P 0xaa {div_off} {div_len}')
            _q_write(qemu_io, setdir, 'base_new.qcow2', f'write -P 0xbb {div_off} {div_len}')
        elif seed == 'identical':
            _q_write(qemu_io, setdir, 'base_old.qcow2', f'write -P 0xaa {div_off} {div_len}')
            _q_write(qemu_io, setdir, 'base_new.qcow2', f'write -P 0xaa {div_off} {div_len}')
        _q_create(qemu_img, setdir, 'overlay.qcow2', size, cs, backing='base_old.qcow2')
        _q_write(qemu_io, setdir, 'overlay.qcow2', ovl_w)
        return
    if chain == '3chainb':
        _q_create(qemu_img, setdir, 'base.qcow2', size, cs)
        _q_create(qemu_img, setdir, 'mid0.qcow2', size, cs, backing='base.qcow2')
        if seed == 'divergent':
            _q_write(qemu_io, setdir, 'base.qcow2', f'write -P 0xaa {div_off} {div_len}')
            _q_write(qemu_io, setdir, 'mid0.qcow2', f'write -P 0xbb {div_off} {div_len}')
        elif seed == 'identical':
            _q_write(qemu_io, setdir, 'base.qcow2', f'write -P 0xaa {div_off} {div_len}')
            # mid0 left unallocated over R: old view == new view == base's data
        _q_create(qemu_img, setdir, 'overlay.qcow2', size, cs, backing='mid0.qcow2')
        _q_write(qemu_io, setdir, 'overlay.qcow2', ovl_w)
        return
    if chain == 'detach':
        _q_create(qemu_img, setdir, 'base_old.qcow2', size, cs)
        if seed == 'divergent':
            _q_write(qemu_io, setdir, 'base_old.qcow2', f'write -P 0xaa {div_off} {div_len}')
        _q_create(qemu_img, setdir, 'overlay.qcow2', size, cs, backing='base_old.qcow2')
        _q_write(qemu_io, setdir, 'overlay.qcow2', ovl_w)
        return
    raise RuntimeError(f'unknown chain shape {chain!r}')


def rebase_new_backing(combo):
    """The -b argument for this combo's chain shape."""
    chain = combo['chain']
    if chain == '3chainb':
        return 'base.qcow2'
    if chain == 'detach':
        return ''
    return 'base_new.qcow2'


def run_rebase(binary, setdir, combo):
    cmd = [binary, 'rebase']
    if combo.get('output') == 'json':
        cmd += ['--output', 'json']
    new_backing = rebase_new_backing(combo)
    cmd += ['-b', new_backing]
    if new_backing:
        cmd += ['-F', 'qcow2']
    if combo['mode'] == 'u':
        cmd += ['-u']
    cmd += ['overlay.qcow2']
    r = run(cmd, setdir)
    return Invocation(r, setdir, rebase_files(combo))


def rebase_matrix():
    """The deterministic 5b matrix (see the section header for the pruning
    rationale). Expected buckets follow 5p's refusal inventory exactly."""
    combos = []
    for cs in CLUSTER_SIZES:
        for size in SIZES:
            m = size // (1024 * 1024)
            for chain in ('2chain', '3chainb', 'detach'):
                for seed in SEEDS_REBASE:
                    if chain == 'detach' and seed == 'identical':
                        continue  # incoherent: no new backing to be identical to
                    expected = 'both-refuse' if (cs == 512 and seed == 'divergent') else 'both-succeed'
                    combos.append({'tag': f'cs{cs}-sz{m}M-{chain}-{seed}-safe',
                                   'cs': cs, 'size': size, 'chain': chain, 'seed': seed,
                                   'mode': 'safe', 'expected': expected, 'd9': False})
                # -u once per (cs, size, chain); seed ignored, built divergent.
                combos.append({'tag': f'cs{cs}-sz{m}M-{chain}-u',
                               'cs': cs, 'size': size, 'chain': chain, 'seed': 'divergent',
                               'mode': 'u', 'expected': 'both-succeed', 'd9': False})
    # Appended combos.
    combos.append({'tag': 'cs65536-sz1M+512-2chain-divergent-safe-UNALIGNED',
                   'cs': 65536, 'size': UNALIGNED_SIZE, 'chain': '2chain', 'seed': 'divergent',
                   'mode': 'safe', 'special': 'unaligned', 'expected': 'both-succeed', 'd9': False})
    combos.append({'tag': 'cs65536-sz1M+512-2chain-divergent-safe-OVERSIZED-D9',
                   'cs': 65536, 'size': UNALIGNED_SIZE, 'chain': '2chain', 'seed': 'divergent',
                   'mode': 'safe', 'special': 'oversized', 'expected': 'both-succeed', 'd9': True})
    combos.append({'tag': 'cs65536-sz64M-2chain-divergent-safe-JSON',
                   'cs': 65536, 'size': 64 * 1024 * 1024, 'chain': '2chain', 'seed': 'divergent',
                   'mode': 'safe', 'output': 'json', 'expected': 'both-succeed', 'd9': False})
    return combos


# ---------------------------------------------------------------------------
# rebase extra checks (off-matrix): P8 widening, eviction, holed-RT refusal
# ---------------------------------------------------------------------------

def prove_rebase_extras(workdir, args):
    """Returns a list of failure strings (empty on success)."""
    failures = []
    failures += _rebase_widening_exemplar(workdir, args)
    failures += _rebase_eviction(workdir, args)
    failures += _rebase_holed_rt(workdir, args)
    return failures


def _rebase_widening_exemplar(workdir, args):
    """P8: cs=512 / 64M / 512 populated L2 tables / IDENTICAL chains. Before
    refuses wire 9 pre-mutation (sha unchanged); after succeeds
    deterministically, check-clean, info-equivalent to a qemu-img rebase
    twin."""
    failures = []
    ex_dir = os.path.join(workdir, 'rebase-widening-exemplar')
    if os.path.exists(ex_dir):
        shutil.rmtree(ex_dir)
    sets = {n: os.path.join(ex_dir, n) for n in ('before-run', 'after-run-1', 'after-run-2', 'qemu-run')}
    files = ['overlay.qcow2', 'base_old.qcow2', 'base_new.qcow2']

    def build(setdir):
        os.makedirs(setdir)
        for name in ('base_old.qcow2', 'base_new.qcow2'):
            check_run([args.qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=512', name, '64M'], setdir)
        writes = []
        for i in range(512):
            writes += ['-c', f'write -P 0x33 {i * 32768} 512']
        check_run([args.qemu_img, 'create', '-f', 'qcow2',
                   '-o', 'backing_file=base_old.qcow2,backing_fmt=qcow2,cluster_size=512',
                   'overlay.qcow2', '64M'], setdir)
        check_run([args.qemu_io, '-f', 'qcow2'] + writes + ['overlay.qcow2'], setdir)

    for setdir in sets.values():
        build(setdir)
    pre = {n: {f: sha256(os.path.join(sd, f)) for f in files} for n, sd in sets.items()}
    if len({tuple(sorted(v.items())) for v in pre.values()}) != 1:
        return [f'rebase widening exemplar twin sets differ pre-run: {pre}']

    def run_instar(binary, setdir):
        r = run([binary, 'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2', 'overlay.qcow2'], setdir)
        inv = Invocation.__new__(Invocation)
        inv.rc, inv.stdout, inv.stderr = r.returncode, r.stdout, r.stderr
        inv.shas = {f: sha256(os.path.join(setdir, f)) for f in files}
        return inv

    before = run_instar(args.before, sets['before-run'])
    if before.rc == 0:
        failures.append('rebase widening exemplar: before-binary unexpectedly succeeded (expected wire-9)')
    elif 'error 9' not in before.stderr:
        failures.append(f'rebase widening exemplar: before refused but not wire-9: stderr={before.stderr!r}')
    if before.shas != pre['before-run']:
        failures.append('rebase widening exemplar: before-binary wire-9 refusal was not pre-mutation')

    after1 = run_instar(args.after, sets['after-run-1'])
    after2 = run_instar(args.after, sets['after-run-2'])
    if after1.rc != 0:
        failures.append(f'rebase widening exemplar: after-binary refused: rc={after1.rc} stderr={after1.stderr!r}')
        return failures
    det = diff_invocations('run1', after1, 'run2', after2)
    if det:
        failures.append('rebase widening exemplar: after-binary nondeterministic: ' + '; '.join(det))

    r = run([args.qemu_img, 'check', 'overlay.qcow2'], sets['after-run-1'])
    if r.returncode != 0:
        failures.append(f'rebase widening exemplar: qemu-img check not clean: '
                        f'rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')
    r = run([args.qemu_img, 'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2', 'overlay.qcow2'], sets['qemu-run'])
    if r.returncode != 0:
        failures.append(f'rebase widening exemplar: qemu-img rebase twin failed: {r.stderr!r}')
    else:
        a = check_run([args.qemu_img, 'info', '--output=json', 'overlay.qcow2'], sets['after-run-1'])
        b = check_run([args.qemu_img, 'info', '--output=json', 'overlay.qcow2'], sets['qemu-run'])
        na, nb = normalise_info(a.stdout), normalise_info(b.stdout)
        if na != nb:
            failures.append(f'rebase widening exemplar: normalized info mismatch: '
                            f'instar={json.dumps(na, sort_keys=True)} qemu={json.dumps(nb, sort_keys=True)}')

    if not failures and not args.keep_all:
        shutil.rmtree(ex_dir)
    return failures


def _rebase_eviction(workdir, args):
    """The eviction shape (cs=64K, 34 divergent L2-coverage spans, sparse
    17408M): after touches more tables than window slots. Before stages
    everything and also succeeds -> a genuine byte-identity row (raw sha of
    the mutated overlay identical before-vs-after; R-D5 says final bytes match
    despite the mid-loop eviction I/O order). Plus virtual-content parity vs a
    qemu-img rebase twin (via streaming qemu-img compare, no 17 GB raw
    materialisation)."""
    failures = []
    ev_dir = os.path.join(workdir, 'rebase-eviction')
    if os.path.exists(ev_dir):
        shutil.rmtree(ev_dir)
    sets = {n: os.path.join(ev_dir, n) for n in ('before-run', 'after-run-1', 'after-run-2', 'qemu-run')}
    files = ['overlay.qcow2', 'base_old.qcow2', 'base_new.qcow2']
    size = '17408M'  # 34 x 512M L2-coverage spans at cs=64K

    def build(setdir):
        os.makedirs(setdir)
        check_run([args.qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=65536',
                   'base_old.qcow2', size], setdir)
        writes = []
        for k in range(34):
            writes += ['-c', f'write -P 0x11 {k * 512}M 64k']
        check_run([args.qemu_io, '-f', 'qcow2'] + writes + ['base_old.qcow2'], setdir)
        check_run([args.qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=65536',
                   'base_new.qcow2', size], setdir)
        check_run([args.qemu_img, 'create', '-f', 'qcow2',
                   '-o', 'backing_file=base_old.qcow2,backing_fmt=qcow2,cluster_size=65536',
                   'overlay.qcow2', size], setdir)

    for setdir in sets.values():
        build(setdir)
    pre = {n: {f: sha256(os.path.join(sd, f)) for f in files} for n, sd in sets.items()}
    if len({tuple(sorted(v.items())) for v in pre.values()}) != 1:
        return [f'rebase eviction twin sets differ pre-run: {pre}']

    def run_instar(binary, setdir):
        r = run([binary, 'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2', 'overlay.qcow2'], setdir, timeout=600)
        inv = Invocation.__new__(Invocation)
        inv.rc, inv.stdout, inv.stderr = r.returncode, r.stdout, r.stderr
        inv.shas = {f: sha256(os.path.join(setdir, f)) for f in files}
        return inv

    before = run_instar(args.before, sets['before-run'])
    after1 = run_instar(args.after, sets['after-run-1'])
    after2 = run_instar(args.after, sets['after-run-2'])
    if before.rc != 0:
        failures.append(f'rebase eviction: before-binary refused (expected success): stderr={before.stderr!r}')
    if after1.rc != 0:
        failures.append(f'rebase eviction: after-binary refused: rc={after1.rc} stderr={after1.stderr!r}')
        return failures
    det = diff_invocations('run1', after1, 'run2', after2)
    if det:
        failures.append('rebase eviction: after-binary nondeterministic: ' + '; '.join(det))
    if before.rc == 0:
        bd = diff_invocations('before', before, 'after', after1)
        if bd:
            failures.append('rebase eviction: before-vs-after byte identity failed (R-D5 says final bytes '
                            'match across eviction): ' + '; '.join(bd))

    r = run([args.qemu_img, 'check', 'overlay.qcow2'], sets['after-run-1'], timeout=600)
    if r.returncode != 0:
        failures.append(f'rebase eviction: qemu-img check not clean: rc={r.returncode} stdout={r.stdout!r}')
    # Deferred header/backing-path patch landed.
    info = check_run([args.qemu_img, 'info', '--output=json', 'overlay.qcow2'], sets['after-run-1'])
    if json.loads(info.stdout).get('backing-filename') != 'base_new.qcow2':
        failures.append('rebase eviction: deferred header/backing-path patch did not land')
    # Virtual-content parity vs qemu twin (streaming compare, no raw blowup).
    r = run([args.qemu_img, 'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2', 'overlay.qcow2'],
            sets['qemu-run'], timeout=600)
    if r.returncode != 0:
        failures.append(f'rebase eviction: qemu-img rebase twin failed: {r.stderr!r}')
    else:
        cmp = run([args.qemu_img, 'compare', os.path.join(sets['after-run-1'], 'overlay.qcow2'),
                   os.path.join(sets['qemu-run'], 'overlay.qcow2')], sets['after-run-1'], timeout=600)
        if cmp.returncode != 0:
            failures.append(f'rebase eviction: virtual content diverges from qemu twin: '
                            f'rc={cmp.returncode} stdout={cmp.stdout!r} stderr={cmp.stderr!r}')

    if not failures and not args.keep_all:
        shutil.rmtree(ev_dir)
    return failures


def _rebase_holed_rt(workdir, args):
    """Holed-refcount-table overlay (R-D4 recipe, adapted from 5p): the after
    binary refuses wire 16 pre-mutation. The before binary mis-allocates
    (live defect) — not run here; this is an after-only spot check that the
    contiguity gate fires before any mutation."""
    failures = []
    hr_dir = os.path.join(workdir, 'rebase-holed-rt')
    if os.path.exists(hr_dir):
        shutil.rmtree(hr_dir)
    setdir = os.path.join(hr_dir, 'after-run')
    os.makedirs(setdir)
    check_run([args.qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=4096', 'overlay.qcow2', '96M'], setdir)
    touch = []
    for i in range(22):
        touch += ['-c', f'write -P 0x01 {i * 2}M 4k']
    check_run([args.qemu_io, '-f', 'qcow2'] + touch + ['overlay.qcow2'], setdir)
    check_run([args.qemu_io, '-f', 'qcow2', '-c', 'write -P 0x22 0 44M', 'overlay.qcow2'], setdir)
    check_run([args.qemu_io, '-f', 'qcow2', '-c', 'discard 8M 32M', 'overlay.qcow2'], setdir)
    check_run([args.qemu_img, 'resize', '--shrink', 'overlay.qcow2', '82M'], setdir)
    for name, pattern in (('base_old.qcow2', 'write -P 0xaa 50M 10M'),
                          ('base_new.qcow2', 'write -P 0xbb 50M 10M')):
        check_run([args.qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=4096', name, '96M'], setdir)
        check_run([args.qemu_io, '-f', 'qcow2', '-c', pattern, name], setdir)
    check_run([args.qemu_img, 'rebase', '-u', '-b', 'base_old.qcow2', '-F', 'qcow2', 'overlay.qcow2'], setdir)
    # Precondition: the RT is really holed and the image is check-clean.
    chk = run([args.qemu_img, 'check', 'overlay.qcow2'], setdir)
    if chk.returncode != 0:
        failures.append(f'rebase holed-RT: fixture overlay is not check-clean: {chk.stdout!r}')

    files = ['overlay.qcow2', 'base_old.qcow2', 'base_new.qcow2']
    pre = {f: sha256(os.path.join(setdir, f)) for f in files}
    r = run([args.after, 'rebase', '-b', 'base_new.qcow2', '-F', 'qcow2', 'overlay.qcow2'], setdir)
    if r.returncode == 0:
        failures.append(f'rebase holed-RT: after-binary must refuse (wire 16): stdout={r.stdout!r}')
    elif 'error 16' not in r.stderr:
        failures.append(f'rebase holed-RT: after refused but not wire-16: stderr={r.stderr!r}')
    for f in files:
        if sha256(os.path.join(setdir, f)) != pre[f]:
            failures.append(f'rebase holed-RT: wire-16 refusal was not pre-mutation: {f} changed')

    if not failures and not args.keep_all:
        shutil.rmtree(hr_dir)
    return failures


# ---------------------------------------------------------------------------
# bench fixtures + proof (phase 6, decision 7)
# ---------------------------------------------------------------------------
#
# Bench is NOT a byte-identity migration for allocating schedules: the crate
# allocates L2-first while pre-migration bench allocated data-first, so with a
# shared linear cursor the two host offsets swap for every fresh-L2 write and
# the final images differ (divergence B-D1). The proof therefore pre-declares
# a bucket per combo (a/b/c/d, seeded from the 6p refusal inventory) and runs
# the right assertion for each bucket rather than a blanket byte compare:
#
#   (a) controls  — raw `-w`, read runs (paths untouched by the migration):
#       full identity (normalised stdout + stderr + per-file sha256).
#   (b) overwrite-only (no fresh-L2 allocation), INCLUDING the post-#433
#       overwrite-only INTERSECT growth corner: full byte identity
#       (sha-equal before-vs-after) + `qemu-img check` clean.
#   (c) allocating (fresh, growth-triggering, backed-overlay COW): NOT
#       sha-equal (B-D1). Instead: determinism (after x2 sha-equal within a
#       side), `qemu-img compare` content-equal (before-image vs after-image),
#       `qemu-img check` clean on both, normalised `info` equivalence,
#       `flushes-issued` identity (carried by the normalised JSON), and — for
#       growth shapes — identical RT-geometry deltas (rt offset/clusters +
#       populated-refblock count before->after).
#   (d) refusals: identical rc/stderr; sha-unchanged WHERE today's refusal is
#       pre-mutation (holed-RT wire-3; compressed with NO growth, gate-2). The
#       compressed-AFTER-growth shape is pre-declared recorded-NOT-sha-stable
#       (verdict = rc/stderr identical + check-clean, per 6p probe 7).
#
# Bench stdout/JSON normalisation (decision 7): the proof runs `bench
# --output json`, which emits ONLY the structured object (no human header /
# flush / completion lines). The three wall-clock fields
# (elapsed-seconds / requests-per-second / bytes-per-second) are stripped; the
# surviving fields (count, depth, effective-depth, buffer-size, step-size,
# offset, write, pattern, flush-interval, no-drain, flushes-issued, format,
# filename) are ALL deterministic and carry a strict superset of the human
# header + flush-line information, so asserting the normalised JSON identical
# subsumes "assert the header line, the flush line" and the `flushes-issued`
# identity check in one comparison. The wall-clock completion line is never
# emitted in JSON mode and is never asserted.

BENCH_CLUSTER_SIZES = [512, 4096, 65536, 2097152]
BENCH_SIZES = [16 * 1024 * 1024, 64 * 1024 * 1024]
BENCH_WALLCLOCK_KEYS = {'elapsed-seconds', 'requests-per-second', 'bytes-per-second'}


def normalise_bench_stdout(stdout):
    """Strip the three wall-clock JSON fields (decision 7).

    On a refusal bench emits no stdout (the error goes to stderr), so an empty
    string round-trips unchanged. On success the structured object is returned
    with the wall-clock fields removed and keys sorted for stable comparison.
    """
    s = (stdout or '').strip()
    if not s:
        return s
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return s
    for k in BENCH_WALLCLOCK_KEYS:
        obj.pop(k, None)
    return json.dumps(obj, sort_keys=True)


def bench_rt_geometry(path):
    """(cluster_size, rt_offset, rt_clusters, populated_refblocks) for a qcow2.

    populated_refblocks counts non-zero refcount-table entries (each points at
    a materialised refcount block). This is the bucket-(c) RT-geometry probe;
    growth shapes must show the SAME (offset, clusters, populated) transition
    before-vs-after (the growth planner is a pure relocation, B-D8)."""
    with open(path, 'rb') as f:
        header = f.read(72)
        if header[:4] != b'QFI\xfb':
            raise RuntimeError(f'{path}: not a qcow2 image')
        cluster_bits = struct.unpack('>I', header[20:24])[0]
        cluster_size = 1 << cluster_bits
        rt_offset = struct.unpack('>Q', header[48:56])[0]
        rt_clusters = struct.unpack('>I', header[56:60])[0]
        f.seek(rt_offset)
        data = f.read(rt_clusters * cluster_size)
    populated = 0
    for i in range(len(data) // 8):
        entry = struct.unpack('>Q', data[i * 8:i * 8 + 8])[0]
        if entry & 0xfffffffffffffe00:
            populated += 1
    return (cluster_size, rt_offset, rt_clusters, populated)


def bench_files(combo):
    """Files whose sha256 the proof tracks for this combo."""
    if combo['fixture'] == 'overlay':
        return ['overlay.qcow2', 'backing.qcow2']
    return [combo['image']]


def build_bench_fixture(combo, setdir, qemu_img, qemu_io):
    """Build one bench fixture. Relative paths only, so twin sets built in
    different directories are byte-identical (the backing filename embedded in
    an overlay header is the relative 'backing.qcow2' in every set — the 6p
    twin-fixture gotcha)."""
    os.makedirs(setdir)
    fixture = combo['fixture']
    cs = combo.get('cs')
    size = str(combo['size'])

    if fixture == 'raw':
        check_run([qemu_img, 'create', '-f', 'raw', 'img.raw', size], setdir)
        # instar's secure raw detection refuses headerless raw; carry the 55AA
        # MBR signature (mirrors tests/test_bench.py::make_raw_mbr).
        check_run([qemu_io, '-f', 'raw', '-c', 'write -P 0x55 510 1',
                   '-c', 'write -P 0xaa 511 1', 'img.raw'], setdir)
        return
    if fixture == 'overlay':
        check_run([qemu_img, 'create', '-f', 'qcow2', '-o', f'cluster_size={cs}',
                   'backing.qcow2', size], setdir)
        check_run([qemu_io, '-f', 'qcow2', '-c', f'write -P 0xbb 0 {size}', 'backing.qcow2'], setdir)
        check_run([qemu_img, 'create', '-f', 'qcow2', '-o',
                   f'backing_file=backing.qcow2,backing_fmt=qcow2,cluster_size={cs}',
                   'overlay.qcow2', size], setdir)
        return
    if fixture == 'compressed':
        # zlib is NOT an incompatible-features header bit; the setup gate does
        # not fire, so bench reaches the per-cluster compression refusal.
        check_run([qemu_img, 'create', '-f', 'qcow2', '-o', f'cluster_size={cs}',
                   'src.qcow2', size], setdir)
        check_run([qemu_io, '-f', 'qcow2', '-c', f'write -P 0x41 0 {size}', 'src.qcow2'], setdir)
        check_run([qemu_img, 'convert', '-c', '-O', 'qcow2', '-o', f'cluster_size={cs}',
                   'src.qcow2', 'img.qcow2'], setdir)
        os.unlink(os.path.join(setdir, 'src.qcow2'))
        return
    if fixture == 'holed':
        # Genuine holed refcount table (probe 5 recipe, adapted from #428/#430):
        # scatter touches, fill, discard a middle band, shrink -> the RT points
        # past a hole. Check-clean on qemu >= 10; bench's contiguity gate
        # refuses it wire-3, pre-mutation.
        check_run([qemu_img, 'create', '-f', 'qcow2', '-o', 'cluster_size=4096', 'img.qcow2', '96M'], setdir)
        touch = []
        for i in range(22):
            touch += ['-c', f'write -P 0x01 {i * 2}M 4k']
        check_run([qemu_io, '-f', 'qcow2'] + touch + ['img.qcow2'], setdir)
        check_run([qemu_io, '-f', 'qcow2', '-c', 'write -P 0x22 0 44M', 'img.qcow2'], setdir)
        check_run([qemu_io, '-f', 'qcow2', '-c', 'discard 8M 32M', 'img.qcow2'], setdir)
        check_run([qemu_img, 'resize', '--shrink', 'img.qcow2', '82M'], setdir)
        return

    # Plain qcow2 image (fresh / overwrite / growth / read).
    check_run([qemu_img, 'create', '-f', 'qcow2', '-o', f'cluster_size={cs}', 'img.qcow2', size], setdir)
    prefill = combo.get('prefill')
    if prefill:
        check_run([qemu_io, '-f', 'qcow2', '-c', f'write -P {prefill["pattern"]} 0 {prefill["bytes"]}',
                   'img.qcow2'], setdir)


def run_bench(binary, setdir, combo):
    """Run `bench --output json` for this combo; normalise the wall-clock JSON
    fields out of stdout. Returns an Invocation whose stdout is normalised."""
    argv = [binary, 'bench'] + combo['bench_args'] + ['-f', combo['fmt'], '--output', 'json', combo['image']]
    r = run(argv, setdir)
    inv = Invocation.__new__(Invocation)
    inv.rc = r.returncode
    inv.stdout = normalise_bench_stdout(r.stdout)
    inv.stderr = r.stderr
    inv.shas = {f: sha256(os.path.join(setdir, f)) for f in bench_files(combo)}
    return inv


def bench_matrix():
    """The decision-7 bench matrix, pruned to coherent combos, with every combo
    pre-assigned its proof bucket (a/b/c/d) IN CODE (seeded from the 6p refusal
    inventory). Cluster sizes {512, 4096, 65536, 2097152} x sizes {16M, 64M} x
    schedule classes {fresh-allocating, overwrite-only, growth-triggering,
    backed-overlay COW} x flush-interval {none, 0, k} x {pattern, straddling},
    plus raw/read controls and the pre-declared refusal shapes."""
    combos = []

    def flush_args(kind, count):
        # A cadence flush-interval must be >= the queue depth (qemu/instar both
        # reject 'flush interval smaller than depth'); the default depth is 64,
        # so a small cadence needs -d 1 (as 6p's cadence probes used).
        if kind == 'none':
            return [], 'none'
        if kind == '0':
            return ['--flush-interval', '0'], 'f0'
        k = max(1, count // 2)
        return ['-d', '1', '--flush-interval', str(k)], f'd1fk{k}'

    for cs in BENCH_CLUSTER_SIZES:
        for size in BENCH_SIZES:
            m = size // (1024 * 1024)

            # (c) fresh-allocating: a modest allocating schedule (64K buffers).
            for fk in ('none', '0', 'k'):
                fa, ftag = flush_args(fk, 8)
                combos.append({
                    'tag': f'bench-cs{cs}-sz{m}M-fresh-{ftag}', 'bucket': 'c', 'expected': 'success',
                    'fmt': 'qcow2', 'cs': cs, 'size': size, 'image': 'img.qcow2', 'fixture': 'fresh',
                    'bench_args': ['-w', '-c', '8', '-s', '65536', '-S', '65536', '--pattern', '80'] + fa,
                    'growth': False})

            # (b) overwrite-only, no growth: prefill the whole footprint so
            # every write lands in an already-allocated cluster.
            footprint = 8 * 65536
            for fk in ('none', 'k'):
                fa, ftag = flush_args(fk, 8)
                combos.append({
                    'tag': f'bench-cs{cs}-sz{m}M-overwrite-{ftag}', 'bucket': 'b', 'expected': 'success',
                    'fmt': 'qcow2', 'cs': cs, 'size': size, 'image': 'img.qcow2', 'fixture': 'overwrite',
                    'prefill': {'pattern': '0xcc', 'bytes': footprint},
                    'bench_args': ['-w', '-c', '8', '-s', '65536', '-S', '65536', '--pattern', '66'] + fa,
                    'growth': False})

            # (c) growth-triggering: fresh image, allocating schedule that
            # crosses the refcount-block threshold (unreachable at cs >= 64K
            # in-envelope -- one refblock covers >= 2 TiB; 6p probe 6).
            if cs in (512, 4096):
                gcount = '255' if cs == 512 else '200'
                combos.append({
                    'tag': f'bench-cs{cs}-sz{m}M-growth-none', 'bucket': 'c', 'expected': 'success',
                    'fmt': 'qcow2', 'cs': cs, 'size': size, 'image': 'img.qcow2', 'fixture': 'growth',
                    'bench_args': ['-w', '-c', gcount, '-s', '65536', '-S', '65536', '--pattern', '67'],
                    'growth': True})

            # (c) backed-overlay COW: sub-cluster partial writes over a backed
            # image drive the decision-3 try/refuse/fill/resubmit path.
            if size == BENCH_SIZES[0]:
                ovl_buf = min(cs // 2, 4096)
                combos.append({
                    'tag': f'bench-cs{cs}-sz{m}M-overlay-none', 'bucket': 'c', 'expected': 'success',
                    'fmt': 'qcow2', 'cs': cs, 'size': size, 'image': 'overlay.qcow2', 'fixture': 'overlay',
                    'bench_args': ['-w', '-c', '3', '-s', str(ovl_buf), '-S', str(cs),
                                   '-o', str(cs), '--pattern', '65'],
                    'growth': False})

    # (b) the post-#433 overwrite-only INTERSECT growth corner: overwrite the
    # prefilled band with a schedule whose worst-case touch estimate crosses
    # the preemptive-growth threshold. Post-fix the pre-grown refblocks are
    # materialised, so this is byte-identical AND check-clean (NEWDEF089).
    combos.append({
        'tag': 'bench-cs512-sz16M-overwrite-growth-corner', 'bucket': 'b', 'expected': 'success',
        'fmt': 'qcow2', 'cs': 512, 'size': 16 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'overwrite',
        'prefill': {'pattern': '0x11', 'bytes': 8 * 1024 * 1024},
        'bench_args': ['-w', '-c', '60', '-s', '65536', '-S', '65536', '--pattern', '66'],
        'growth': False})

    # (c) straddling-bufsize fresh variants (odd buffer crosses cluster edges).
    for cs in (4096, 65536):
        combos.append({
            'tag': f'bench-cs{cs}-sz16M-fresh-straddle', 'bucket': 'c', 'expected': 'success',
            'fmt': 'qcow2', 'cs': cs, 'size': 16 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'fresh',
            'bench_args': ['-w', '-c', '8', '-s', '4097', '-S', '4097', '--pattern', '89'],
            'growth': False})

    # (a) controls: raw `-w` and a read run (both on paths the migration never
    # touches -> full byte identity).
    combos.append({
        'tag': 'bench-raw-sz16M-write-control', 'bucket': 'a', 'expected': 'success',
        'fmt': 'raw', 'cs': None, 'size': 16 * 1024 * 1024, 'image': 'img.raw', 'fixture': 'raw',
        'bench_args': ['-w', '-c', '8', '-s', '65536', '-S', '65536', '--pattern', '90'],
        'growth': False})
    combos.append({
        'tag': 'bench-cs65536-sz16M-read-control', 'bucket': 'a', 'expected': 'success',
        'fmt': 'qcow2', 'cs': 65536, 'size': 16 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'overwrite',
        'prefill': {'pattern': '0xdd', 'bytes': 1024 * 1024},
        'bench_args': ['-c', '8', '-s', '65536', '-S', '65536', '--pattern', '90'],
        'growth': False})

    # (d) refusals (6p refusal inventory). holed-RT + compressed-no-growth are
    # pre-mutation (sha-stable); compressed-after-growth is recorded NOT
    # sha-stable (growth mutates before the per-cluster gate fires).
    combos.append({
        'tag': 'bench-cs4096-holed-rt-refusal', 'bucket': 'd', 'expected': 'refuse',
        'fmt': 'qcow2', 'cs': 4096, 'size': 96 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'holed',
        'bench_args': ['-w', '-c', '10', '-s', '65536', '-S', '65536', '--pattern', '65'],
        'growth': False, 'sha_stable': True})
    combos.append({
        'tag': 'bench-cs65536-compressed-nogrowth-refusal', 'bucket': 'd', 'expected': 'refuse',
        'fmt': 'qcow2', 'cs': 65536, 'size': 4 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'compressed',
        'bench_args': ['-w', '-c', '100', '-s', '65536', '-S', '65536', '--pattern', '65'],
        'growth': False, 'sha_stable': True})
    combos.append({
        'tag': 'bench-cs512-compressed-growth-refusal', 'bucket': 'd', 'expected': 'refuse',
        'fmt': 'qcow2', 'cs': 512, 'size': 4 * 1024 * 1024, 'image': 'img.qcow2', 'fixture': 'compressed',
        'bench_args': ['-w', '-c', '100', '-s', '65536', '-S', '65536', '--pattern', '65'],
        'growth': False, 'sha_stable': False})

    return combos


def _bench_qemu_check(qemu_img, setdir, name):
    """(clean, detail). Clean == qemu-img check exit 0."""
    r = run([qemu_img, 'check', name], setdir)
    if r.returncode != 0:
        return False, f'qemu-img check {name} rc={r.returncode} stdout={r.stdout.strip()!r} stderr={r.stderr.strip()!r}'
    return True, ''


def prove_bench_combo(combo, workdir, args):
    """Build twins, assert determinism, then run the pre-declared bucket's
    assertions. Returns a TSV row dict; row['fail'] truthy -> non-zero exit."""
    files = bench_files(combo)
    combo_dir = os.path.join(workdir, combo['tag'])
    if os.path.exists(combo_dir):
        shutil.rmtree(combo_dir)
    sets = {name: os.path.join(combo_dir, name) for name in ('after-run-1', 'after-run-2', 'before-run')}
    for setdir in sets.values():
        build_bench_fixture(combo, setdir, args.qemu_img, args.qemu_io)

    pre = {name: {f: sha256(os.path.join(setdir, f)) for f in files} for name, setdir in sets.items()}
    if not (pre['after-run-1'] == pre['after-run-2'] == pre['before-run']):
        return {'combo': combo, 'bucket': combo['bucket'], 'verdict': 'FIXTURE-NONDETERMINISTIC',
                'detail': f'twin fixture sets differ pre-run: {pre}', 'fail': True,
                'before': None, 'after': None}

    # Pristine RT geometry for growth-shape delta reporting (before the runs
    # mutate the images in place).
    pristine_geom = None
    if combo.get('growth'):
        pristine_geom = bench_rt_geometry(os.path.join(sets['after-run-1'], combo['image']))

    after1 = run_bench(args.after, sets['after-run-1'], combo)
    after2 = run_bench(args.after, sets['after-run-2'], combo)
    before = run_bench(args.before, sets['before-run'], combo)
    row = {'combo': combo, 'bucket': combo['bucket'], 'before': before, 'after': after1,
           'fail': False, 'detail': ''}

    det_diffs = diff_invocations('run1', after1, 'run2', after2)
    if det_diffs:
        row.update(verdict='DETERMINISM-FAIL', fail=True,
                   detail='after-run-1 vs after-run-2: ' + '; '.join(det_diffs))
        return row

    bucket = combo['bucket']

    if combo['expected'] == 'refuse':
        if before.rc == 0 or after1.rc == 0:
            row.update(verdict='BUCKET-MISMATCH', fail=True,
                       detail=f'bucket-d combo expected refusal but before rc={before.rc} after rc={after1.rc}')
            return row
        if before.rc != after1.rc or before.stderr != after1.stderr:
            row.update(verdict='REFUSAL-MISMATCH', fail=True,
                       detail=f'rc/stderr differ: before rc={before.rc} stderr={before.stderr!r}; '
                              f'after rc={after1.rc} stderr={after1.stderr!r}')
            return row
        if combo.get('sha_stable'):
            for f in files:
                if after1.shas[f] != pre['after-run-1'][f] or before.shas[f] != pre['before-run'][f]:
                    row.update(verdict='REFUSAL-MUTATED', fail=True,
                               detail=f'{f} changed on a pre-mutation refusal '
                                      f'(before {before.shas[f]} pristine {pre["before-run"][f]}; '
                                      f'after {after1.shas[f]} pristine {pre["after-run-1"][f]})')
                    return row
            row['verdict'] = 'PASS'
            return row
        # Recorded NOT sha-stable (compressed-after-growth): rc/stderr identical
        # + check-clean on both is the whole contract.
        for label, setdir in (('before', sets['before-run']), ('after', sets['after-run-1'])):
            clean, detail = _bench_qemu_check(args.qemu_img, setdir, combo['image'])
            if not clean:
                row.update(verdict='REFUSAL-CHECK-DIRTY', fail=True, detail=f'{label}: {detail}')
                return row
        row.update(verdict='PASS', detail=f'recorded-not-sha-stable (sha before={before.shas[combo["image"]]} '
                                          f'after={after1.shas[combo["image"]]}, both check-clean)')
        return row

    # expected success (buckets a/b/c)
    if before.rc != 0 or after1.rc != 0:
        row.update(verdict='BUCKET-MISMATCH', fail=True,
                   detail=f'expected success but before rc={before.rc} stderr={before.stderr!r}; '
                          f'after rc={after1.rc} stderr={after1.stderr!r}')
        return row

    diffs = diff_invocations('before', before, 'after', after1)

    if bucket in ('a', 'b'):
        if diffs:
            row.update(verdict='BYTE-MISMATCH', fail=True, detail='; '.join(diffs))
            return row
        if bucket == 'b':
            clean, detail = _bench_qemu_check(args.qemu_img, sets['after-run-1'], combo['image'])
            if not clean:
                row.update(verdict='BUCKET-C-CHECK-DIRTY', fail=True, detail=detail)
                return row
        row['verdict'] = 'PASS'
        return row

    # bucket (c): stdout/stderr/rc identity (flushes-issued lives in the
    # normalised JSON), then compare + check + info + RT-geometry. sha WILL
    # differ (B-D1) -- that is expected, not asserted.
    non_sha = [d for d in diffs if not d.startswith('sha256(')]
    if non_sha:
        row.update(verdict='BUCKET-C-STDOUT-MISMATCH', fail=True,
                   detail='normalised stdout/stderr/rc differ (flushes-issued identity lives here): '
                          + '; '.join(non_sha))
        return row

    failures = []
    for label, setdir in (('before', sets['before-run']), ('after', sets['after-run-1'])):
        clean, detail = _bench_qemu_check(args.qemu_img, setdir, combo['image'])
        if not clean:
            failures.append(f'{label}: {detail}')
    cmp = run([args.qemu_img, 'compare', os.path.join(sets['before-run'], combo['image']),
               os.path.join(sets['after-run-1'], combo['image'])], sets['after-run-1'])
    if cmp.returncode != 0:
        failures.append(f'qemu-img compare before-vs-after diverged: rc={cmp.returncode} '
                        f'stdout={cmp.stdout.strip()!r} stderr={cmp.stderr.strip()!r}')
    a = check_run([args.qemu_img, 'info', '--output=json', combo['image']], sets['before-run'])
    b = check_run([args.qemu_img, 'info', '--output=json', combo['image']], sets['after-run-1'])
    na, nb = normalise_info(a.stdout), normalise_info(b.stdout)
    if na != nb:
        failures.append(f'normalised info mismatch: before={json.dumps(na, sort_keys=True)} '
                        f'after={json.dumps(nb, sort_keys=True)}')

    detail = ''
    if combo.get('growth'):
        gb = bench_rt_geometry(os.path.join(sets['before-run'], combo['image']))
        ga = bench_rt_geometry(os.path.join(sets['after-run-1'], combo['image']))
        if gb != ga:
            failures.append(f'RT-geometry delta differs before={gb} after={ga} (pristine {pristine_geom})')
        else:
            detail = (f'RT-geometry delta {pristine_geom} -> {ga} identical before-vs-after; '
                      f'sha differs by B-D1 (before={before.shas[combo["image"]]} after={after1.shas[combo["image"]]})')

    if failures:
        row.update(verdict='BUCKET-C-FAIL', fail=True, detail='; '.join(failures))
        return row
    row.update(verdict='PASS', detail=detail or
               f'compare+check+info OK; sha differs by B-D1 (before={before.shas[combo["image"]]} '
               f'after={after1.shas[combo["image"]]})')
    return row


# ---------------------------------------------------------------------------
# op registry (phases 5-6 add entries here)
# ---------------------------------------------------------------------------

OPS = {
    'commit': {
        'matrix': commit_matrix,
        'build': build_commit_fixture,
        'run': run_commit,
        'files': lambda combo: COMMIT_MUTATED_FILES,
        'extra_checks': prove_widening_exemplar,
    },
    'rebase': {
        'matrix': rebase_matrix,
        'build': build_rebase_fixture,
        'run': run_rebase,
        'files': rebase_files,
        'extra_checks': prove_rebase_extras,
    },
    'bench': {
        'matrix': bench_matrix,
        'build': build_bench_fixture,
        'run': run_bench,
        'files': bench_files,
        'prove': prove_bench_combo,
    },
}


def main():
    parser = argparse.ArgumentParser(description='Migration-proof harness: before/after instar byte identity')
    parser.add_argument('--op', required=True, choices=sorted(OPS),
                        help='operation under proof (commit, rebase, bench)')
    parser.add_argument('--before', required=True, help='path to the pre-migration instar binary (inside its dist)')
    parser.add_argument('--after', required=True, help='path to the post-migration instar binary (inside its dist)')
    parser.add_argument('--qemu-img', default='qemu-img', help='pinned qemu-img for fixture generation')
    parser.add_argument('--qemu-io', default='qemu-io', help='matching qemu-io for fixture seeding')
    parser.add_argument('--workdir', default=None, help='working directory (default: a fresh temp dir)')
    parser.add_argument('--combo', default=None, help='only run combos whose tag contains this substring')
    parser.add_argument('--keep-all', action='store_true', help='keep passing combo directories too')
    args = parser.parse_args()

    if OPS[args.op] is None:
        parser.error(f'--op {args.op} is not implemented yet')
    args.before = os.path.abspath(args.before)
    args.after = os.path.abspath(args.after)
    for name, path in (('--before', args.before), ('--after', args.after)):
        if not os.access(path, os.X_OK):
            parser.error(f'{name} binary {path} is not executable')

    workdir = os.path.abspath(args.workdir) if args.workdir else tempfile.mkdtemp(prefix='migration-proof-')
    os.makedirs(workdir, exist_ok=True)

    combos = OPS[args.op]['matrix']()
    if args.combo:
        combos = [c for c in combos if args.combo in c['tag']]
        if not combos:
            parser.error(f'--combo {args.combo!r} matches no combo tag')

    prover = OPS[args.op].get('prove', prove_combo)

    rows = []
    for combo in combos:
        try:
            row = prover(combo, workdir, args)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            row = {'combo': combo, 'bucket': 'n/a', 'verdict': 'HARNESS-ERROR',
                   'detail': str(e).replace('\n', ' '), 'fail': True, 'before': None, 'after': None}
        rows.append(row)
        print(f'{row["verdict"]}\t{row["bucket"]}\t{combo["tag"]}\t{row["detail"]}', flush=True)
        if not row['fail'] and not args.keep_all:
            shutil.rmtree(os.path.join(workdir, combo['tag']), ignore_errors=True)

    tsv_path = os.path.join(workdir, f'migration-proof-{args.op}.tsv')
    with open(tsv_path, 'w') as f:
        f.write('combo\texpected\tbucket\tbefore_rc\tafter_rc\tverdict\tdetail\n')
        for row in rows:
            before_rc = row['before'].rc if row['before'] else ''
            after_rc = row['after'].rc if row['after'] else ''
            f.write(f'{row["combo"]["tag"]}\t{row["combo"]["expected"]}\t{row["bucket"]}\t'
                    f'{before_rc}\t{after_rc}\t{row["verdict"]}\t{row["detail"]}\n')

    extra_failures = []
    if not args.combo and OPS[args.op].get('extra_checks'):
        print('\n-- extra checks (off-matrix) --', flush=True)
        extra_failures = OPS[args.op]['extra_checks'](workdir, args)
        for fail in extra_failures:
            print(f'FAIL\t{fail}', flush=True)
        if not extra_failures:
            print(f'PASS\tall off-matrix extra checks for --op {args.op} passed', flush=True)

    buckets = {}
    for row in rows:
        buckets[row['bucket']] = buckets.get(row['bucket'], 0) + 1
    failures = [row for row in rows if row['fail']]
    d9_fallbacks = [row for row in rows if row['verdict'] == 'D9-VIRTUAL-EQUAL']

    print('\n== migration-proof summary ==')
    print(f'op: {args.op}')
    print(f'combos run: {len(rows)}')
    for bucket in sorted(buckets):
        print(f'  bucket {bucket}: {buckets[bucket]}')
    print(f'determinism failures: {sum(1 for r in rows if r["verdict"] == "DETERMINISM-FAIL")}')
    print(f'byte-identity failures: {sum(1 for r in rows if r["verdict"] == "BYTE-MISMATCH")}')
    d9_declared = sum(1 for r in rows if r['combo'].get('d9'))
    print(f'D9 virtual-content fallbacks triggered: {len(d9_fallbacks)} '
          f'(pre-declared D9 combos: {d9_declared}; commit expects 0 triggered after 4q, '
          f'rebase expects 1 on the oversized-backing shape)')
    for row in d9_fallbacks:
        print(f'  LOUD D9 divergence: {row["combo"]["tag"]}: {row["detail"]}')
    print(f'matrix failures: {len(failures)}')
    for row in failures:
        print(f'  FAIL {row["combo"]["tag"]}: {row["verdict"]}: {row["detail"]}')
    print(f'extra-check failures: {len(extra_failures)}')
    for fail in extra_failures:
        print(f'  FAIL {fail}')
    print(f'TSV: {tsv_path}')
    print(f'workdir: {workdir}')

    if failures or extra_failures:
        print('RESULT: FAIL')
        return 1
    print('RESULT: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
