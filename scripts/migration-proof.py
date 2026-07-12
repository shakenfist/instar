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
import subprocess
import sys
import tempfile


CLUSTER_SIZES = [512, 4096, 65536]
SIZES = [1024 * 1024, 64 * 1024 * 1024]
SEEDS = ['empty', '64k-at-0', 'multi-extent']
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
    dict; row['fail'] truthy means the run must exit non-zero."""
    combo_dir = os.path.join(workdir, combo['tag'])
    if os.path.exists(combo_dir):
        shutil.rmtree(combo_dir)
    sets = {name: os.path.join(combo_dir, name) for name in ('after-run-1', 'after-run-2', 'before-run')}
    for setdir in sets.values():
        build_commit_fixture(combo, setdir, args.qemu_img, args.qemu_io)

    # Twin equality before anything runs.
    pre = {}
    for name, setdir in sets.items():
        pre[name] = {f: sha256(os.path.join(setdir, f)) for f in COMMIT_MUTATED_FILES}
    if not (pre['after-run-1'] == pre['after-run-2'] == pre['before-run']):
        return {'combo': combo, 'bucket': 'n/a', 'verdict': 'FIXTURE-NONDETERMINISTIC',
                'detail': f'twin fixture sets differ pre-run: {pre}', 'fail': True,
                'before': None, 'after': None}

    after1 = run_commit(args.after, sets['after-run-1'], combo)
    after2 = run_commit(args.after, sets['after-run-2'], combo)
    before = run_commit(args.before, sets['before-run'], combo)
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
            for f in COMMIT_MUTATED_FILES)
        if virt_equal:
            row.update(verdict='D9-VIRTUAL-EQUAL', fail=False,
                       detail='LOUD: raw sha256 divergence on the unaligned combo, virtual content '
                              'identical (decision 7 fallback triggered — expected unnecessary '
                              'after 4q): ' + '; '.join(diffs))
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
# op registry (phases 5-6 add entries here)
# ---------------------------------------------------------------------------

OPS = {
    'commit': {
        'matrix': commit_matrix,
        'extra_checks': prove_widening_exemplar,
    },
    'rebase': None,   # phase 5
    'bench': None,    # phase 6
}


def main():
    parser = argparse.ArgumentParser(description='Migration-proof harness: before/after instar byte identity')
    parser.add_argument('--op', required=True, choices=sorted(OPS),
                        help='operation under proof (only commit is implemented so far)')
    parser.add_argument('--before', required=True, help='path to the pre-migration instar binary (inside its dist)')
    parser.add_argument('--after', required=True, help='path to the post-migration instar binary (inside its dist)')
    parser.add_argument('--qemu-img', default='qemu-img', help='pinned qemu-img for fixture generation')
    parser.add_argument('--qemu-io', default='qemu-io', help='matching qemu-io for fixture seeding')
    parser.add_argument('--workdir', default=None, help='working directory (default: a fresh temp dir)')
    parser.add_argument('--combo', default=None, help='only run combos whose tag contains this substring')
    parser.add_argument('--keep-all', action='store_true', help='keep passing combo directories too')
    args = parser.parse_args()

    if OPS[args.op] is None:
        parser.error(f'--op {args.op} is not implemented yet (phases 5-6)')
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

    rows = []
    for combo in combos:
        try:
            row = prove_combo(combo, workdir, args)
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
            print('PASS\twidening exemplar: before wire-10 pre-mutation refusal, after deterministic '
                  'success, check clean, info-equivalent to qemu-img commit twin', flush=True)

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
    print(f'D9 virtual-content fallbacks triggered: {len(d9_fallbacks)} (expected 0 after 4q)')
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
