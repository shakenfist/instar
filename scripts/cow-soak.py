#!/usr/bin/env python3
"""Randomized copy-on-write soak (phase 7 step 7e).

Generates many RANDOM snapshot-bearing qcow2 fixtures, exercises one of the
three COW consumers on each (commit into a snapshot-bearing backing/overlay,
safe-mode rebase of a snapshot-bearing overlay, or ``bench -w`` into a
snapshot-bearing image), and asserts qemu-parity against a live qemu-img
twin built from the identical seed:

* active-view ``qemu-img compare`` identical (C5);
* ``qemu-img check`` clean -- no ``refcount=1 reference=2``, no leaks (C5);
* every pre-existing snapshot's read-back equals the twin's (C6/C7/C8), via
  the reusable oracle ``tests/helpers/snapshot_readback``.

This is a SMOKE soak over hand-generated snapshot-bearing fixtures, NOT the
full differential-fuzz snapshot generator (that is phase 8). It varies
cluster size {512, 4096, 65536}, image size, snapshot count/placement, and
post-snapshot write patterns under a FIXED, recorded seed for
reproducibility.

On any divergence the soak STOPS, saves the failing instar + twin fixtures
and a decoded refcount dump (via scratchpad/7p/qcow2dump.py) under the
artifact directory, and exits non-zero. Only one op runs at a time (the
whole soak is a single sequential process -- bench is KVM-heavy and
contention causes flaky failures, a hard-won 7e lesson).

Usage::

    scripts/cow-soak.py [--seed N] [--iterations N] [--artifacts DIR]
"""

import argparse
import hashlib
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'tests'))
from helpers.snapshot_readback import snapshot_readback  # noqa: E402

QCOW2DUMP = REPO / 'scratchpad' / '7p' / 'qcow2dump.py'
CLUSTER_SIZES = [512, 4096, 65536]
OPS = ['commit', 'rebase', 'bench']


class SoakDivergence(Exception):
    """A parity divergence: real COW bug or environmental flake."""

    def __init__(self, kind, detail, images):
        super().__init__(f'{kind}: {detail}')
        self.kind = kind
        self.detail = detail
        self.images = images


def instar_bin():
    """Locate the instar release binary."""
    env = os.environ.get('INSTAR_BINARY_PATH')
    if env:
        return Path(env)
    return REPO / 'src' / 'target' / 'release' / 'instar'


def run(argv, cwd=None, timeout=240, check=True):
    """Run a command; optionally assert rc 0. Return CompletedProcess."""
    r = subprocess.run(
        [str(a) for a in argv], capture_output=True, text=True,
        timeout=timeout, cwd=str(cwd) if cwd else None)
    if check and r.returncode != 0:
        raise RuntimeError(
            f'command failed rc={r.returncode}: {argv!r}\n'
            f'stdout={r.stdout!r}\nstderr={r.stderr!r}')
    return r


def qemu_io_write(img, pattern, offset, length, cwd=None):
    """Issue a single `qemu-io write -P` at byte offset/length."""
    run(['qemu-io', '-f', 'qcow2', '-c',
         f'write -P {pattern} {offset} {length}', img], cwd=cwd)


def rand_writes(rng, img, size, cwd=None, n=None):
    """Issue a few random aligned pattern writes within [0, size)."""
    if n is None:
        n = rng.randint(1, 4)
    for _ in range(n):
        length = rng.randint(1, 8) * 512
        length = min(length, size)
        offset = rng.randrange(0, max(1, size - length) + 1)
        offset -= offset % 512
        pattern = f'0x{rng.randint(1, 255):02x}'
        qemu_io_write(img, pattern, offset, length, cwd=cwd)


def snapshot(img, name, cwd=None):
    """Create an internal snapshot named `name`."""
    run(['qemu-img', 'snapshot', '-c', name, img], cwd=cwd)


# ----------------------------------------------------------------------
# Fixture generators. Each builds a "seed" directory (pristine, pre-op)
# and returns a descriptor of how to run the op and what to compare.
# ----------------------------------------------------------------------

def gen_commit(rng, seed, cs):
    """Snapshot-bearing commit fixture (backing- or overlay-snapshot)."""
    seed.mkdir(parents=True, exist_ok=True)
    size = rng.choice([16, 32, 64]) * 1024 * 1024
    shape = rng.choice(['backing', 'overlay'])
    opt = f'cluster_size={cs}'
    run(['qemu-img', 'create', '-f', 'qcow2', '-o', opt,
         'base.qcow2', str(size)], cwd=seed)
    rand_writes(rng, 'base.qcow2', size, cwd=seed)
    snaps = []
    if shape == 'backing':
        for i in range(rng.randint(1, 3)):
            rand_writes(rng, 'base.qcow2', size, cwd=seed)
            snapshot('base.qcow2', f'snap{i + 1}', cwd=seed)
            snaps.append(f'snap{i + 1}')
        if rng.random() < 0.5:
            rand_writes(rng, 'base.qcow2', size, cwd=seed)
    run(['qemu-img', 'create', '-f', 'qcow2', '-o',
         f'{opt},backing_file=base.qcow2,backing_fmt=qcow2',
         'overlay.qcow2', str(size)], cwd=seed)
    rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
    if shape == 'overlay':
        for i in range(rng.randint(1, 3)):
            rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
            snapshot('overlay.qcow2', f'osnap{i + 1}', cwd=seed)
            snaps.append(f'osnap{i + 1}')
        if rng.random() < 0.5:
            rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
    if shape == 'backing':
        carrier, compare = 'base.qcow2', ['base.qcow2']
    else:
        carrier, compare = 'overlay.qcow2', ['base.qcow2', 'overlay.qcow2']
    return {
        'op': 'commit', 'shape': shape, 'cs': cs, 'size': size,
        'instar': ['commit', '{overlay}'], 'overlay': 'overlay.qcow2',
        'qemu': ['commit', 'overlay.qcow2'],
        'carrier': carrier, 'compare': compare, 'snaps': snaps}


def gen_rebase(rng, seed, cs):
    """Snapshot-bearing safe-rebase fixture (Q2 shape)."""
    seed.mkdir(parents=True, exist_ok=True)
    size = rng.choice([8, 16, 32]) * 1024 * 1024
    opt = f'cluster_size={cs}'
    for name, pat in (('base_old.qcow2', '0x11'), ('base_new.qcow2', '0x22')):
        run(['qemu-img', 'create', '-f', 'qcow2', '-o', opt, name,
             str(size)], cwd=seed)
        # Distinct, partially-overlapping content in each backing.
        rand_writes(rng, name, size, cwd=seed, n=rng.randint(2, 5))
    run(['qemu-img', 'create', '-f', 'qcow2', '-o',
         f'backing_file=base_old.qcow2,backing_fmt=qcow2,{opt}',
         'overlay.qcow2', str(size)], cwd=seed)
    rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
    snaps = []
    for i in range(rng.randint(1, 3)):
        rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
        snapshot('overlay.qcow2', f'snap{i + 1}', cwd=seed)
        snaps.append(f'snap{i + 1}')
    if rng.random() < 0.5:
        rand_writes(rng, 'overlay.qcow2', size, cwd=seed)
    return {
        'op': 'rebase', 'shape': 'overlay', 'cs': cs, 'size': size,
        'instar': ['rebase', '-b', 'base_new.qcow2', '-F', 'qcow2',
                   '{overlay}'],
        'overlay': 'overlay.qcow2',
        'qemu': ['rebase', '-b', 'base_new.qcow2', '-F', 'qcow2',
                 'overlay.qcow2'],
        'carrier': 'overlay.qcow2', 'compare': ['overlay.qcow2'],
        'snaps': snaps}


def gen_bench(rng, seed, cs):
    """Snapshot-bearing `bench -w` fixture: shared active clusters."""
    seed.mkdir(parents=True, exist_ok=True)
    size = 64 * 1024 * 1024
    count = rng.randint(50, 200)
    pattern = rng.randint(1, 254)
    run(['qemu-img', 'create', '-f', 'qcow2', '-o',
         f'cluster_size={cs}', 'img.qcow2', str(size)], cwd=seed)
    # bench writes sequentially from offset 0 over count*4096 bytes; make
    # sure that whole region is snapshot-shared so the write must COW.
    bench_span = count * 4096
    snaps = []
    nsnap = rng.randint(1, 2)
    step = max(4096, (bench_span // nsnap) - ((bench_span // nsnap) % 4096))
    off = 0
    for i in range(nsnap):
        length = min(step, size - off)
        if length > 0:
            qemu_io_write('img.qcow2', f'0x{rng.randint(1, 255):02x}',
                          off, length, cwd=seed)
        # top up to guarantee [0, bench_span) fully written before snap
        if i == nsnap - 1 and off + length < bench_span:
            qemu_io_write('img.qcow2', '0xaa', off + length,
                          bench_span - (off + length), cwd=seed)
        snapshot('img.qcow2', f'snap{i + 1}', cwd=seed)
        snaps.append(f'snap{i + 1}')
        off += length
    return {
        'op': 'bench', 'shape': 'image', 'cs': cs, 'size': size,
        'instar': ['bench', '-w', '-c', str(count), '--pattern',
                   str(pattern), '-f', 'qcow2', '{img}'],
        'qemu': ['bench', '-w', '-c', str(count), '--pattern',
                 str(pattern), '-f', 'qcow2', 'img.qcow2'],
        'image': 'img.qcow2',
        'carrier': 'img.qcow2', 'compare': ['img.qcow2'], 'snaps': snaps}


GENERATORS = {'commit': gen_commit, 'rebase': gen_rebase, 'bench': gen_bench}


# ----------------------------------------------------------------------
# Run + parity.
# ----------------------------------------------------------------------

def run_instar(desc, work_dir):
    """Run the instar op in `work_dir` (a copy of the seed)."""
    argv = [str(instar_bin())]
    for a in desc['instar']:
        if a == '{overlay}':
            argv.append(str(work_dir / desc['overlay']))
        elif a == '{img}':
            argv.append(str(work_dir / desc['image']))
        else:
            argv.append(a)
    r = subprocess.run(argv, capture_output=True, text=True, timeout=240)
    if r.returncode != 0:
        raise SoakDivergence(
            'instar-op-failed', f'{desc["op"]} rc={r.returncode} '
            f'stderr={r.stderr!r}', {'instar': work_dir})


def run_qemu(desc, work_dir):
    """Run the qemu-img twin op in `work_dir` (a copy of the seed)."""
    run(['qemu-img', *desc['qemu']], cwd=work_dir)


def assert_parity(desc, instar_dir, twin_dir):
    """Assert C5 (compare+check) and C6/C7/C8 (per-snapshot read-back)."""
    # C5: active-view compare identical.
    for img in desc['compare']:
        r = subprocess.run(
            ['qemu-img', 'compare', str(instar_dir / img),
             str(twin_dir / img)],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise SoakDivergence(
                'compare-mismatch',
                f'{img}: rc={r.returncode} stdout={r.stdout!r} '
                f'stderr={r.stderr!r}',
                {'instar': instar_dir, 'twin': twin_dir, 'image': img})

    # C5: check clean on every instar image involved.
    for img in set(desc['compare']) | {desc['carrier']}:
        r = subprocess.run(
            ['qemu-img', 'check', str(instar_dir / img)],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise SoakDivergence(
                'check-dirty',
                f'{img}: rc={r.returncode} stdout={r.stdout!r} '
                f'stderr={r.stderr!r}',
                {'instar': instar_dir, 'twin': twin_dir, 'image': img})
        if 'refcount=1 reference=2' in (r.stdout + r.stderr):
            raise SoakDivergence(
                'refcount-1-reference-2', f'{img}',
                {'instar': instar_dir, 'twin': twin_dir, 'image': img})

    # C6/C7/C8: every snapshot's read-back matches the twin.
    carrier = desc['carrier']
    for s in desc['snaps']:
        a = snapshot_readback('qemu-img', instar_dir / carrier, s)
        b = snapshot_readback('qemu-img', twin_dir / carrier, s)
        if a != b:
            raise SoakDivergence(
                'readback-mismatch',
                f'snapshot {s} on {carrier}: instar={a} twin={b}',
                {'instar': instar_dir, 'twin': twin_dir, 'image': carrier})


def save_evidence(art, i, seed, cs, desc, div):
    """Persist the failing fixtures + a decoded refcount dump."""
    dst = art / f'divergence-iter{i:04d}'
    dst.mkdir(parents=True, exist_ok=True)
    for role, d in div.images.items():
        if isinstance(d, Path) and d.is_dir():
            shutil.copytree(d, dst / role, dirs_exist_ok=True)
    img = div.images.get('image')
    lines = [
        f'iteration = {i}', f'seed = {seed}', f'cluster_size = {cs}',
        f'op = {desc["op"]}', f'shape = {desc.get("shape")}',
        f'size = {desc.get("size")}', f'snaps = {desc.get("snaps")}',
        f'kind = {div.kind}', f'detail = {div.detail}', '']
    if img:
        for role in ('instar', 'twin'):
            d = div.images.get(role)
            if d and (d / img).exists():
                dump = subprocess.run(
                    [sys.executable, str(QCOW2DUMP), str(d / img)],
                    capture_output=True, text=True)
                lines.append(f'===== qcow2dump {role}/{img} =====')
                lines.append(dump.stdout)
                lines.append(dump.stderr)
    (dst / 'EVIDENCE.txt').write_text('\n'.join(lines))
    return dst


def replay_once(seed, i, cs, op, art, tmp):
    """Run a single iteration deterministically. Returns the descriptor."""
    rng = random.Random(f'{seed}-fixture-{i}')
    seed_dir = tmp / f'iter{i:04d}' / 'seed'
    desc = GENERATORS[op](rng, seed_dir, cs)
    instar_dir = tmp / f'iter{i:04d}' / 'instar'
    twin_dir = tmp / f'iter{i:04d}' / 'twin'
    shutil.copytree(seed_dir, instar_dir)
    shutil.copytree(seed_dir, twin_dir)
    try:
        run_instar(desc, instar_dir)
        run_qemu(desc, twin_dir)
        assert_parity(desc, instar_dir, twin_dir)
    except SoakDivergence as div:
        # Attach the descriptor + real dirs for evidence capture.
        div.desc = desc
        div.images.setdefault('instar', instar_dir)
        div.images.setdefault('twin', twin_dir)
        raise
    return desc


def main():
    ap = argparse.ArgumentParser(description='Randomized COW parity soak.')
    ap.add_argument('--seed', type=int, default=20260713,
                    help='fixed RNG seed (recorded for reproducibility)')
    ap.add_argument('--iterations', type=int, default=50)
    ap.add_argument('--artifacts', type=Path,
                    default=REPO / 'scratchpad' / '7e')
    ap.add_argument('--keep', action='store_true',
                    help='keep all per-iteration fixtures (not just failures)')
    ap.add_argument('--replay', type=int, default=None,
                    help='re-run ONLY this iteration index (flake triage)')
    args = ap.parse_args()

    if not instar_bin().exists():
        print(f'instar binary not found at {instar_bin()}; run "make instar"',
              file=sys.stderr)
        return 2
    if shutil.which('qemu-img') is None or shutil.which('qemu-io') is None:
        print('system qemu-img/qemu-io required', file=sys.stderr)
        return 2

    art = args.artifacts
    art.mkdir(parents=True, exist_ok=True)
    log_path = art / 'soak.log'
    log = open(log_path, 'w')

    def emit(msg):
        print(msg)
        log.write(msg + '\n')
        log.flush()

    plan = []
    indices = ([args.replay] if args.replay is not None
               else range(args.iterations))
    for i in indices:
        # Draw the op/cs deterministically so --replay reproduces exactly.
        r = random.Random(f'{args.seed}-plan-{i}')
        plan.append((i, r.choice(CLUSTER_SIZES), r.choice(OPS)))

    emit(f'# cow-soak seed={args.seed} iterations={len(plan)} '
         f'instar={instar_bin()}')
    emit(f'# qemu-img={shutil.which("qemu-img")}')
    counts = {op: 0 for op in OPS}
    start = time.time()
    divergences = 0

    with_tmp = art / 'soak-work'
    if with_tmp.exists():
        shutil.rmtree(with_tmp)
    with_tmp.mkdir(parents=True)

    for i, cs, op in plan:
        counts[op] += 1
        t0 = time.time()
        try:
            desc = replay_once(args.seed, i, cs, op, art, with_tmp)
            dt = time.time() - t0
            emit(f'[{i:04d}] OK   op={op:6s} cs={cs:5d} '
                 f'shape={desc.get("shape"):8s} snaps={len(desc["snaps"])} '
                 f'size={desc["size"] // (1024 * 1024)}M {dt:5.2f}s')
            if not args.keep:
                shutil.rmtree(with_tmp / f'iter{i:04d}', ignore_errors=True)
        except SoakDivergence as div:
            divergences += 1
            desc = getattr(div, 'desc', {'op': op})
            dst = save_evidence(art, i, args.seed, cs, desc, div)
            emit(f'[{i:04d}] DIVERGENCE op={op} cs={cs} kind={div.kind} '
                 f'detail={div.detail}')
            emit(f'         evidence saved under {dst}')
            emit(f'         REPLAY: scripts/cow-soak.py --seed {args.seed} '
                 f'--replay {i} --keep')
            break

    wall = time.time() - start
    emit('')
    emit(f'# ran={sum(1 for _ in plan)} divergences={divergences} '
         f'wall={wall:.1f}s seed={args.seed}')
    emit(f'# op counts: {counts}')
    log.close()
    if not args.keep and divergences == 0:
        shutil.rmtree(with_tmp, ignore_errors=True)
    return 1 if divergences else 0


if __name__ == '__main__':
    sys.exit(main())
