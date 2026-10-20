#!/usr/bin/env python3
"""Measure what each static qemu-img build writes, and pin or check it.

Runs every case in `tests/helpers/qemu_pins.py` (`CASES`) against the
static `qemu-img` builds in instar-testdata's `qemu-img-binaries/x86_64/`,
then either writes the results as a pin file grouped by outcome (`--write`)
or compares them with an existing pin (`--check`), exiting 1 and naming the
case, version and field of every difference.

Typical use, after instar-testdata gains a qemu build:

    tools/sweep-qemu-create.py --write tests/golden/qemu-create-pins.json --jobs 4

and to replay a suspected version boundary on its own:

    tools/sweep-qemu-create.py --check tests/golden/qemu-create-pins.json \\
        --versions 8.1.5,8.2.0 --cases vhdx-fixed-64M

Nothing is written to instar-testdata. Images are made under `--scratch`
(a temporary directory by default) and each is deleted as soon as it has
been measured; the largest is a 128 GiB sparse file, so the scratch
filesystem must support sparse files.
"""

import argparse
import os
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_TESTS_DIR = REPO_ROOT / 'tests'
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))
from helpers import qemu_pins  # noqa: E402


def default_testdata() -> Path:
    env = os.environ.get('INSTAR_TESTDATA_PATH')
    return Path(env) if env else REPO_ROOT.parent / 'instar-testdata'


def binaries_root(testdata: Path) -> Path:
    return testdata / 'qemu-img-binaries' / 'x86_64'


def available_versions(testdata: Path) -> list:
    root = binaries_root(testdata)
    if not root.is_dir():
        raise SystemExit(f'no qemu-img builds at {root}')
    return sorted((entry.name for entry in root.iterdir() if (entry / 'qemu-img').is_file()),
                  key=qemu_pins.version_key)


def measure_version(qemu_img: str, version: str, case_names: list, scratch: str) -> tuple:
    """Run the named cases on one build; returns (version, {case: result}, seconds)."""
    started = time.monotonic()
    workdir = Path(scratch) / version
    workdir.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in case_names:
        results[name] = qemu_pins.run_case(qemu_img, name, workdir)
    try:
        workdir.rmdir()
    except OSError:
        pass
    return version, results, time.monotonic() - started


def measure(testdata: Path, versions: list, case_names: list, scratch: Path, jobs: int) -> dict:
    root = binaries_root(testdata)
    work = [(str(root / version / 'qemu-img'), version, case_names, str(scratch)) for version in versions]
    results = {}

    def record(outcome):
        version, by_case, seconds = outcome
        results[version] = by_case
        print(f'{version}: {len(by_case)} cases in {seconds:.1f} s', file=sys.stderr, flush=True)

    if jobs <= 1:
        for item in work:
            record(measure_version(*item))
    else:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for outcome in pool.map(measure_version, *zip(*work)):
                record(outcome)
    return results


def write_pin(path: Path, results: dict) -> None:
    data = qemu_pins.encode_pin(list(results), qemu_pins.group_results(results))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(qemu_pins.dump_pin(data), encoding='utf-8')
    print(f'wrote {path}: {len(data["versions"])} versions', file=sys.stderr)
    for name, groups in data['cases'].items():
        spans = ', '.join(f'{group["versions"][0]}..{group["versions"][-1]}' for group in groups)
        print(f'  {name}: {len(groups)} group{"s" if len(groups) != 1 else ""} ({spans})', file=sys.stderr)


def check_pin(path: Path, results: dict) -> list:
    pin = qemu_pins.load_pin(path)
    differences = []
    for version in sorted(results, key=qemu_pins.version_key):
        if version not in pin['versions']:
            differences.append(f'version {version}: not in the pin')
            continue
        for name, result in results[version].items():
            group = qemu_pins.find_group(pin, name, version)
            if group is None:
                differences.append(f'case {name}, version {version}: not in the pin')
                continue
            for message in qemu_pins.result_diff(group['result'], result):
                differences.append(f'case {name}, version {version}: {message}')
    return differences


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Measure what static qemu-img builds write for the pinned create and convert cases.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', metavar='PIN', type=Path, help='write the results to this pin file')
    mode.add_argument('--check', metavar='PIN', type=Path,
                      help='compare the results with this pin file and exit 1 on any difference')
    parser.add_argument('--testdata', type=Path, default=default_testdata(),
                        help='the instar-testdata checkout (default: $INSTAR_TESTDATA_PATH, else ../instar-testdata '
                             'beside this repository)')
    parser.add_argument('--versions', help='comma-separated qemu versions (default: every build in the testdata)')
    parser.add_argument('--cases', help='comma-separated case names, with --check only (default: every case)')
    parser.add_argument('--scratch', type=Path, help='directory for the images (default: a temporary directory)')
    parser.add_argument('--jobs', type=int, default=1, help='versions measured in parallel (default: 1)')
    args = parser.parse_args(argv)
    if args.cases and args.write:
        parser.error('--cases is for replaying with --check; a pin is always written for every case')
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    available = available_versions(args.testdata)
    if args.versions:
        versions = [v.strip() for v in args.versions.split(',') if v.strip()]
        missing = [v for v in versions if v not in available]
        if missing:
            raise SystemExit(f'no qemu-img build for {", ".join(missing)} under {binaries_root(args.testdata)}')
    else:
        versions = available
    case_names = [case['name'] for case in qemu_pins.CASES]
    if args.cases:
        case_names = [name.strip() for name in args.cases.split(',') if name.strip()]
        unknown = [name for name in case_names if name not in qemu_pins.CASES_BY_NAME]
        if unknown:
            raise SystemExit(f'unknown case {", ".join(unknown)}')

    started = time.monotonic()
    if args.scratch:
        args.scratch.mkdir(parents=True, exist_ok=True)
        results = measure(args.testdata, versions, case_names, args.scratch, args.jobs)
    else:
        with tempfile.TemporaryDirectory(prefix='sweep-qemu-create-') as scratch:
            results = measure(args.testdata, versions, case_names, Path(scratch), args.jobs)
    print(f'measured {len(versions)} versions x {len(case_names)} cases in {time.monotonic() - started:.1f} s',
          file=sys.stderr)

    if args.write:
        write_pin(args.write, results)
        return 0
    differences = check_pin(args.check, results)
    for message in differences:
        print(message)
    if differences:
        print(f'{len(differences)} difference{"s" if len(differences) != 1 else ""} from {args.check} '
              f'(each reads: field: pinned != measured)', file=sys.stderr)
        return 1
    print(f'{len(versions)} versions x {len(case_names)} cases match {args.check}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
