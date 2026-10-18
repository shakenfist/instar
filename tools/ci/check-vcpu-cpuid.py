#!/usr/bin/env python3
"""Assert every vCPU is given a guest CPUID before its control registers.

A freshly created KVM vCPU has an empty guest CPUID, which advertises no
long mode. Since Linux 6.12.112 the kernel validates EFER against the
guest's capabilities when userspace calls KVM_SET_SREGS, so the
EFER.LME|EFER.LMA that setup_sregs writes is refused with EINVAL unless
KVM_SET_CPUID2 has already run on that vCPU. Every instar operation
starts a guest, so missing it breaks all of them at once, and the only
symptom is `Error: Error(22)`.

The VMM creates a vCPU in every operation's setup path -- seventeen of
them when this guard was written -- so the risk is not the call sites
that exist today but the eighteenth, added later, that forgets. This
guard reads the source rather than running anything: it needs no
/dev/kvm, so it can run on a lightweight runner alongside the other CI
tooling guards.

Two properties are checked:

  1. Between each `create_vcpu(` and the `set_sregs(` that follows it,
     there is a `setup_cpuid(` call.
  2. `setup_cpuid` itself still calls `set_cpuid2`, so the helper cannot
     be hollowed out into something that satisfies property 1 while
     setting nothing.
"""

import argparse
import re
import sys

CREATE = re.compile(r'\bcreate_vcpu\s*\(')
SET_SREGS = re.compile(r'\bset_sregs\s*\(')
SETUP_CPUID = re.compile(r'\bsetup_cpuid\s*\(')
HELPER_DEF = re.compile(r'^fn setup_cpuid\b')


def check_call_sites(lines):
    """Return a list of complaints about vCPUs that reach SREGS unprepared."""
    problems = []
    for index, line in enumerate(lines):
        if not CREATE.search(line):
            continue
        prepared = False
        for offset in range(index + 1, len(lines)):
            follower = lines[offset]
            if SETUP_CPUID.search(follower):
                prepared = True
                break
            if SET_SREGS.search(follower) or CREATE.search(follower):
                break
        if not prepared:
            problems.append(
                f'line {index + 1}: this vCPU reaches set_sregs without a '
                f'setup_cpuid call, so KVM_SET_SREGS will fail with EINVAL '
                f'on Linux 6.12.112 and newer'
            )
    return problems


def check_helper(lines):
    """Return a complaint if setup_cpuid no longer sets a CPUID at all."""
    for index, line in enumerate(lines):
        if not HELPER_DEF.match(line):
            continue
        body = '\n'.join(lines[index:index + 20])
        if 'set_cpuid2' in body:
            return []
        return [
            f'line {index + 1}: setup_cpuid no longer calls set_cpuid2, so '
            f'the call sites below are satisfied by a helper that sets '
            f'nothing'
        ]
    return ['setup_cpuid is not defined; every vCPU reaches set_sregs unprepared']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='src/vmm/src/main.rs',
                        help='the VMM source to read (default: %(default)s)')
    args = parser.parse_args()

    with open(args.source, encoding='utf-8') as source:
        lines = source.read().splitlines()

    problems = check_helper(lines) + check_call_sites(lines)
    vcpus = sum(1 for line in lines if CREATE.search(line))

    if problems:
        print(f'{args.source}: guest CPUID setup is missing or incomplete:',
              file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        return 1

    print(f'{args.source}: all {vcpus} vCPU(s) are given a guest CPUID '
          f'before their control registers')
    return 0


if __name__ == '__main__':
    sys.exit(main())
