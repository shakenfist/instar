# HTTP input phase 4: confining the fetcher

## Status: In progress

Master plan: `PLAN-http-input.md`.

## Planning effort

High. The phase decides where in a process's life each confinement
layer can be applied, and the answer is not the one the master plan
assumed. Getting it wrong fails in two directions that a passing test
does not show: a layer that silently does nothing, and a layer that
kills the fetcher on a syscall it needed on a distro nobody ran. Review
effort: high for step 4c, the seccomp allowlist, where an omitted
syscall is a `SIGSYS` on someone else's glibc.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-18, and binding here:

1. **The fetcher takes descriptor numbers, not paths.** There is no
   path argument and no fallback that accepts one. That is what makes a
   deny-all filesystem policy possible at all, and it is why this phase
   can be strict rather than approximate.
2. **Nothing the fetcher says to the privileged side is text.** A
   failure is a `Status` value; the sentence the user reads is written
   on the privileged side. The fetcher's stderr is diagnostics and
   never part of the protocol.

From phase 3, 2026-11-25, and inherited here:

3. **The child's stdin and stdout are `/dev/null` and its stderr
   follows the caller's `--verbose`.** A default run writes nothing to
   stderr, and `tests/test_info_safe.py` asserts that for both a path
   and a URL. Any confinement message this phase adds lives inside that
   constraint.
4. **The fetcher holds exactly `{0, 1, 2, 3, 4}`**, asserted as the
   whole set by `fetch::tests::the_child_holds_exactly_the_five_descriptors_it_needs`.
   Descriptor hygiene, which the master plan lists as this phase's
   work, already shipped.

Taken when this phase was planned, 2026-11-26: decisions 5 to 17
below.

## Scope

In scope:

* A two-stage confinement: what only the parent can set, set in
  `pre_exec`; what wants a late, tight policy, applied by the fetcher
  to itself before it reads a byte from the peer.
* `RLIMIT_NPROC`, `RLIMIT_CORE`, `RLIMIT_NOFILE` and
  `PR_SET_NO_NEW_PRIVS` in `pre_exec`.
* A deny-all Landlock filesystem ruleset, tolerant of the ABI the
  running kernel reports.
* A seccomp-bpf allowlist for the serving loop, hand-written, with no
  new dependency in the untrusted binary.
* The host-side probe that decides which layers the running kernel can
  provide, the argument that tells the child which to require, and the
  rule that a required layer the child cannot apply is a failure rather
  than a silence.
* Tests that prove each layer bites, including the enforcement proof
  (a denied syscall really dies) and the Docker-tier measurement.
* The mutations that prove the tests bite.

Out of scope, with reasons:

* **User and mount namespaces.** Declined; see decision 13 and the
  Future work entry. The measurements are in the survey.
* **`PR_SET_DUMPABLE` 0.** Declined; see decision 12.
* **Any network policy beyond denying the syscalls outright.** Phase 5
  brings an HTTP backend and its own policy; this phase gives the file
  backend a policy of its own rather than one both will share, so
  phase 5 adds a second policy instead of loosening this one.
* **A user-visible flag for strictness.** Phase 8 owns failure
  semantics and UX. This phase's default is in decision 16 and the
  back brief asks the operator to confirm it.
* **`docs/security.md`'s partition section and `ARCHITECTURE.md`.**
  Phase 10 owns both. This phase documents the mechanism where the
  mechanism is already described, in `docs/crates/fetch-protocol.md`.

## What the survey found

Measured on 2026-11-26 against `develop` at `c43b08f1`, on the
development host (kernel 6.12.117+deb13-amd64, uid 1000, host LSM list
`lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm`).
The probe scripts are in the session scratchpad; each finding below
states what was run, because several of them contradict the master
plan.

1. **There is no confinement code in instar today.** `seccomp`,
   `landlock`, `setrlimit`, `RLIMIT_`, `NO_NEW_PRIVS`, `SET_DUMPABLE`,
   `unshare`, `CLONE_NEW*` and `pivot_root` appear nowhere under
   `src/`. The only hits in the tree are `RLIMIT_FSIZE` and
   `RLIMIT_AS` in the Python test harness (`tests/base.py:1516`,
   `tests/test_create.py:2312`), which limit *instar* from the outside.
   Nothing to extend; this is all new.

2. **A deny-all Landlock ruleset applied before `exec` makes the
   `exec` fail.** The master plan says every layer is "applied in the
   child before `exec`". Measured: a ruleset handling every ABI 1 to 3
   filesystem access bit, with no rules added, then
   `prctl(PR_SET_NO_NEW_PRIVS)`, then `landlock_restrict_self`, then
   `execv("/bin/true")` -- the `execv` fails with `EACCES`. A
   pre-`exec` Landlock policy would have to permit read and execute on
   the fetcher binary and on everything the dynamic loader opens, which
   is most of what the policy existed to deny.

3. **The same ruleset applied after startup is exactly what is
   wanted.** Measured in a child that holds an already-open file
   descriptor: after `landlock_restrict_self` with a deny-all ruleset,
   `pread` on the inherited descriptor succeeds, and `open` of *the
   very same path* fails with `EACCES`. That is the whole policy the
   file backend needs, and it is only reachable after the loader has
   finished.

4. **Landlock is ABI 6 on this kernel.**
   `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
   returns 6. A ruleset handling access bits the running kernel does
   not know is refused with `EINVAL`, so the handled mask has to be
   derived from the reported ABI rather than from a constant.

5. **An unprivileged process can install a seccomp filter on itself,
   and a denial is a `SIGSYS` kill.** Measured with a six-instruction
   cBPF allowlist and `SECCOMP_RET_KILL_PROCESS`: with
   `PR_SET_NO_NEW_PRIVS` set, `prctl(PR_SET_SECCOMP,
   SECCOMP_MODE_FILTER, &prog)` succeeds as uid 1000 with no
   capability; `pread` on an inherited descriptor still works
   afterwards; and the denied `socket()` kills the process with
   `SIGSYS`. No crate is needed for this.

6. **`PR_SET_DUMPABLE` 0 blinds the parent's own diagnostics.** The
   master plan names it. Measured, with the child's
   `PR_GET_DUMPABLE` read back as 0 through a pipe before the parent
   looks: the parent, same uid, same session, gets `EACCES` from
   `listdir("/proc/<pid>/fd")`. That is the exact call in
   `src/vmm/src/fetch.rs:820`, which phase 3's definition of done
   item 3 and phase 9's planned confinement test both rest on.

   The first run of this probe reported the opposite, because the
   parent listed `/proc/<pid>/fd` before the child had been scheduled
   to run its `prctl`. The synchronised result is the one above. It is
   recorded here because the unsynchronised version is the easier
   probe to write and it returns a confident wrong answer.

7. **`RLIMIT_FSIZE` 0 is not a cheap win.** The master plan calls it
   one. Measured: a child with `RLIMIT_FSIZE` 0 whose stderr is a
   *regular file* is killed by `SIGXFSZ` on its first diagnostic
   write; with stderr a pipe, the same write succeeds. `instar info
   --verbose file:///x 2>log` makes stderr a regular file, so the
   limit would kill the fetcher for printing the line it was asked to
   print.

8. **`RLIMIT_NPROC` 0 is a cheap win.** Measured: a child that sets it
   and then `execv`s succeeds, because the limit is enforced at `fork`
   and `execve` does not fork.

9. **A mount namespace is unreachable on its own.** Measured:
   `unshare(CLONE_NEWNS)` alone fails with `EPERM` as uid 1000;
   `unshare(CLONE_NEWUSER | CLONE_NEWNS)` in one call succeeds. So the
   master plan's "user and mount namespaces" is really one decision,
   not two, and it is a decision to enter a user namespace.

10. **The unit tests run inside Docker with no privileges added.**
    `make test-rust` is a `docker run` with `-u <uid>:<gid>` and no
    `--security-opt`, `--cap-add` or `--privileged`; `grep` finds none
    of those three anywhere in the `Makefile`, `.github/workflows/`
    or `tools/`. So every Rust unit test of this phase runs under the
    daemon's default seccomp profile without `CAP_SYS_ADMIN`, which is
    the strictest environment the code will meet and the one that
    decides whether a layer can be *tested* at all. By contrast
    `make test-integration` runs the suite on the host, unconfined.
    The distro matrix (`debian:12`, `debian:13`, `ubuntu:22.04`,
    `ubuntu:24.04`, `fedora:latest`, `rockylinux:9`, `rockylinux:10`)
    runs containers on the *runner's* kernel, so what varies there is
    glibc, not the LSM.

    `docker run` could not be invoked directly from the planning
    session, so the in-container numbers are not in this plan. They
    are step 4a's first task, and the vehicle is `make test-rust`
    itself: that command *is* the container measurement.

11. **The protocol has a reserved `flags` field, but it is reserved by
    a strict rule.** `InitReply` carries `flags: u64` documented
    "Reserved; must be zero" (`src/crates/fetch-protocol/src/wire.rs:511`),
    and every message's decoder -- init request, init reply, read
    request, read reply -- rejects a non-zero `flags` as a typed
    `ProtocolError` (lines 481, 567, 698, 810). Reporting the applied
    sandbox over the wire therefore means relaxing an invariant that
    is currently checkable, in four places and in the fuzz target.
    Decision 15 does not do that.

12. **The serving loop allocates.** `read_source` builds a
    `vec![0u8; want]` per request
    (`src/fetch/src/main.rs:470`) and the reply encoder builds its own
    datagram, so the allowlist must permit the allocator's syscalls.
    Only the request buffer is a fixed stack array.

13. **No documentation claims the fetcher is confined.** `docs/info.md:28`
    calls it "a separate, untrusted `instar-fetch` process", which
    stays true. `docs/crates/fetch-protocol.md:217` says a socketpair
    leaves "nothing for a filesystem sandbox to have to permit", which
    this phase makes literal. The `Current Status` and `Limitations`
    sections say nothing about confinement either way, so there is no
    false claim to correct -- only a gap to fill.

14. **The repository already has the pattern for "reported, not
    silently skipped".** `tests/strace_injection.py` probes the
    *capability* rather than the binary, and `INSTAR_REQUIRE_STRACE`
    turns a silent skip into a failure in the CI job whose image has
    it (`make test-container-core` passes it through). Phase 4's tests
    follow that shape rather than inventing one.

15. **The fetcher already has a `Source` trait.** `answer` takes
    `source: &dyn Source` (`src/fetch/src/main.rs:372`), so phase 5's
    HTTP backend has a seam, and a per-backend confinement policy has
    somewhere obvious to hang.

16. **There is a side-effect-free probe for the seccomp action this
    phase relies on.** `seccomp(SECCOMP_GET_ACTION_AVAIL, 0,
    &SECCOMP_RET_KILL_PROCESS)` returns 0 on this kernel, and
    `PR_GET_SECCOMP` still reads 0 afterwards: the privileged process
    can ask whether the kill action exists without installing a filter
    on itself. `PR_GET_SECCOMP` is not that probe -- it reports the
    caller's own mode, which says nothing about whether a filter could
    be installed -- and the first draft of this plan said to use it.

What the survey corrected at source, in the master plan's phase 4
section and the `index.md` row, as part of this phase's planning
commit: that every layer is applied in the child before `exec`
(findings 2 and 3), that `RLIMIT_FSIZE` 0 is a cheap win (finding 7),
that `PR_SET_DUMPABLE` 0 is free (finding 6), that the mount namespace
is separable from the user namespace (finding 9), and that descriptor
hygiene is still to do (decision 4: it shipped in phase 3). A later
step does not need to redo any of that.

## Decisions

5. **Confinement is applied in two stages, by whichever side can do it
   best.** The parent, in `pre_exec`, sets what the child cannot set
   for itself without a syscall it will later deny, and what must be
   in place before the image of a new program exists: the rlimits and
   `PR_SET_NO_NEW_PRIVS`. The child, in `main`, applies Landlock and
   seccomp to itself after its setup and before its first `recvmsg`.
   Findings 2 and 3 force this: pre-`exec` is the one place a tight
   filesystem policy cannot go.

6. **The child confines itself before the init exchange, not after
   it.** The init request is the first peer-controlled input the
   fetcher parses, so the policy must already be on. Everything the
   setup needs -- `fstat` of the image, `setsockopt` and `getsockopt`
   for the datagram ceiling -- happens before, which is also what
   keeps those syscalls out of the allowlist.

7. **`pre_exec` stays async-signal-safe.** Phase 3 established that
   the closure allocates nothing, takes no lock and formats no string.
   Three `setrlimit` calls and one `prctl` keep that property. Nothing
   that builds a policy object may move into the closure; the seccomp
   program is not built there and not passed through it.

8. **Landlock handles every filesystem access bit the reported ABI
   knows, and adds no rules.** The handled mask is computed from the
   ABI version the kernel returns, so a kernel at ABI 1 gets the ABI 1
   mask rather than `EINVAL` (finding 4). An empty rule set is the
   policy: the fetcher opens no path after startup, and finding 3
   shows the descriptors it already holds keep working.

9. **The seccomp policy is an allowlist, hand-written as cBPF with
   `libc` and no new dependency.** The fetcher's manifest says its
   dependencies are `fetch-protocol` and `libc` and "nothing else:
   this process is the untrusted half of the partition, and every
   dependency it takes is code running next to the bytes an attacker
   controls". A filter crate would contradict that for roughly sixty
   lines of filter. Finding 5 shows the mechanism needs nothing else.

10. **The allowlist is derived by measurement, then widened by a named
    margin.** The serving loop's syscalls are read off an `strace` of a
    real run, not off the source, because glibc chooses some of them
    and the binary links against the *runtime* distro's glibc, not the
    one it was built with. On top of the measured set the filter allows
    a documented margin -- allocator and signal-return calls the
    allocator or the runtime may reach for on another libc
    (`brk`, `mmap`, `munmap`, `mremap`, `madvise`, `futex`,
    `rt_sigreturn`, `rseq`, `getrandom`, `clock_gettime`, `exit_group`)
    -- and the margin is listed in the code with the reason, so a
    reviewer can see what is deliberate. A `SIGSYS` on a user's distro
    is worse than a slightly wider allowlist; the bits that matter are
    the ones not on it.

11. **Violations kill the process.** `SECCOMP_RET_KILL_PROCESS`, not
    `ERRNO`. A fetcher that has reached a syscall outside its policy is
    not a fetcher whose error handling should be trusted to continue.
    The diagnosis is cheap: phase 3's `Drop` already `wait`s for the
    child, so the status is available, and `WTERMSIG == SIGSYS` names
    this exactly. The VMM reports it under `--verbose`.

12. **`PR_SET_DUMPABLE` 0 is declined; `RLIMIT_CORE` 0 is set
    instead.** What the master plan wanted from it is that a crash does
    not write the image's bytes to disk, and `RLIMIT_CORE` 0 does that
    without the cost. The cost, measured in finding 6, is that the
    operator can no longer read `/proc/<pid>/fd` or `strace` the
    fetcher -- the parent's own diagnostics, one of which is already a
    test. What is given up is protection against a same-uid process
    attaching to the fetcher, and a same-uid process can attach to the
    VMM just as easily, so it is not a boundary. The fetcher also holds
    no secret of its own: one socket to its parent, and an image the
    invoking user already owns.

13. **User and mount namespaces are declined in this phase.** This is
    the decision most likely to be argued with, so the reasoning in
    full. A mount namespace needs `CAP_SYS_ADMIN` or a user namespace
    in the same `unshare` (finding 9), so taking it means entering a
    user namespace. What a user namespace plus an empty mount tree
    would buy -- no path in the filesystem is reachable -- is what the
    deny-all Landlock ruleset already buys (finding 3), and what an
    empty network namespace would buy is what denying `socket`,
    `connect`, `sendto` and `bind` in the allowlist already buys, more
    precisely and with a better failure mode. Against that, a user
    namespace is a privilege transition: inside it the fetcher holds a
    full capability set over its own namespace, which is a strictly
    larger surface than the one it has now, and it is unavailable in
    the Docker tier where the unit tests run (finding 10), so the layer
    could not be tested where it matters. The honest summary is that
    namespaces are the right tool when a process must *open* things and
    you want to control what it can see; this process opens nothing.
    Recorded in Future work with the measurements, so it is a decision
    rather than an omission.

14. **The host decides which layers are required; the child obeys and
    does not negotiate.** The VMM probes the running kernel once before
    it spawns -- one `landlock_create_ruleset` ABI query and one
    `seccomp(SECCOMP_GET_ACTION_AVAIL)` for
    `SECCOMP_RET_KILL_PROCESS` (finding 16) -- and passes the layers
    it expects as
    `--confine=landlock,seccomp`. The child applies exactly the named
    layers and exits non-zero, before any init reply, if it cannot
    apply one that was named. A silent skip is therefore impossible by
    construction: either the host did not ask, or the child applied it,
    or the run failed. An unknown token in the list is refused rather
    than ignored.

15. **Nothing about the sandbox crosses the wire.** Finding 11 shows
    the `flags` fields are reserved by a rule that every decoder
    enforces and the fuzz target explores; spending that invariant on a
    status report would be a poor trade when the parent already knows
    the answer, having chosen it in decision 14. The protocol is
    unchanged by this phase, and `VERSION` stays 1.

16. **On a kernel that cannot provide a layer, the run proceeds and
    says so only under `--verbose`.** The default stays silent because
    decision 3 and an existing test require a default run to write
    nothing to stderr, and because three of the seven matrix distros
    may be in this position. This is the one the back brief asks the
    operator to confirm, because the alternative -- a warning on every
    unconfined run -- is defensible for a tool whose selling point is
    the partition, and it is cheaper to decide now than after the tests
    are written.

17. **The file backend's policy is written as the file backend's, not
    as the fetcher's.** One named policy per backend from the start, so
    phase 5 adds an HTTP policy beside this one rather than widening a
    shared one and quietly relaxing the file case with it.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | high | opus | none | **Measure the container tier, then set the parent's half.** First, the measurement the planning session could not make: write a throwaway Rust test that reports, from inside `make test-rust`'s container, the Landlock ABI (`landlock_create_ruleset(NULL, 0, 1)`), whether `prctl(PR_SET_NO_NEW_PRIVS)` then a one-instruction `SECCOMP_MODE_FILTER` install succeeds, and whether `unshare(CLONE_NEWUSER)` succeeds. Report the three results; do not commit that test. Then, in `src/vmm/src/fetch.rs`, add to the existing `pre_exec` closure (which phase 3 keeps allocation-free and lock-free -- read decision 7 and keep it that way): `setrlimit` for `RLIMIT_NPROC` 0, `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` 8, and `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Do **not** set `RLIMIT_FSIZE` and do **not** set `PR_SET_DUMPABLE`; decisions 7, 12 and finding 7 say why, and a reviewer will check. Add a host-side probe module function that returns which layers this kernel can provide -- the Landlock ABI query, and `seccomp(SECCOMP_GET_ACTION_AVAIL)` for `SECCOMP_RET_KILL_PROCESS`, which finding 16 measured as side-effect free; do not use `PR_GET_SECCOMP`, which answers a different question -- and thread `--confine=<list>` into `spawn_fetcher_binary`'s argv from it. Unit-test the limits through `/proc/<pid>/limits` of a live fetcher (readable because decision 12 declined `PR_SET_DUMPABLE`), and the probe against the host's own ABI. Commit subject: "Set the fetcher's resource limits before exec." |
| 4b | high | opus | none | **Deny the filesystem.** Create `src/fetch/src/confine.rs`, declared from `main.rs`. Implement the deny-all Landlock ruleset of decisions 8 and 17: query the ABI, build the handled-access mask for *that* ABI (finding 4 -- a mask with unknown bits is `EINVAL`), create the ruleset, `prctl(PR_SET_NO_NEW_PRIVS, 1)`, `landlock_restrict_self`, close the ruleset descriptor. The syscall numbers are 444 and 446 on x86_64; there is no glibc wrapper, so go through `libc::syscall`, and write the `SAFETY` comments in the shape `src/fetch/src/main.rs:199` already uses. Parse `--confine=` in `parse_args` per decision 14: unknown token refused, `none` accepted, a named layer that cannot be applied is a non-zero exit before any init reply. Call it from `serve` after `max_datagram` and before `initialise` (decision 6). Unit tests fork a child, apply the policy, and assert from the child's exit status that an inherited-descriptor `pread` still works and a fresh `open` of the same path fails -- finding 3 is the measurement to reproduce. Note for the test: the probe must synchronise before the parent inspects anything, for the reason in finding 6. Commit subject: "Deny the fetcher every path after startup." |
| 4c | high | fable | none | **Deny every syscall the serving loop does not need.** The hardest step in the phase, and the one where a wrong answer reaches a user as a `SIGSYS` on a distro we did not test. In `src/fetch/src/confine.rs`, add the seccomp allowlist of decisions 9, 10 and 11. Method, in this order: build the fetcher, `strace -f -c` a real `instar info --verbose file:///<fixture>` run and a hostile-peer run from `src/fetch/tests/hostile_peer.rs`, and record the union of syscalls the *fetcher* makes after its setup -- that is the measured set, and it goes in the plan's execution notes with the command that produced it. Then write the cBPF allowlist by hand (`struct sock_filter` is `{u16 code, u8 jt, u8 jf, u32 k}`; check `arch == AUDIT_ARCH_X86_64` first and kill on a mismatch, then dispatch on `nr`), action `SECCOMP_RET_KILL_PROCESS`, installed with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` after `PR_SET_NO_NEW_PRIVS`. Add the margin of decision 10 as a separate, commented list -- the reviewer must be able to see which entries are measured and which are insurance. `socket`, `connect`, `bind`, `sendto` and `openat` must be absent, and a test must prove each absence rather than assert the list's contents. The enforcement test forks a child, installs the real filter, attempts the denied call, and asserts `WTERMSIG == SIGSYS`; finding 5 is the working shape. Commit subject: "Allow the fetcher only the syscalls it serves with." |
| 4d | high | opus | none | **Prove it end to end, and prove the tests bite.** Integration tests in `tests/test_info_safe.py`, in the `TestInfoFileUrl` class phase 3 added: stdout over a `file://` URL is still byte-identical to the path's, for both output formats, with the sandbox on (the parity oracle is the point of the phase 3 work and this is what says confinement did not break it); a default run is still silent on stderr; `--verbose` names the layers that were applied. Put the exit status and the non-emptiness *inside* the comparison, as phase 3's tests do -- comparing two failed runs is how a false pass happens. Then the mutations, one at a time, on a scratch copy restored from that copy rather than with `git checkout`, each under `timeout`: (a) the Landlock install removed -- 4b's open test must fail; (b) the seccomp install removed -- 4c's `SIGSYS` test must fail; (c) `pread64` dropped from the allowlist -- an end-to-end test must fail, and record how it presents; (d) the unknown-`--confine`-token refusal turned into a silent ignore -- a test must fail; (e) the "named layer could not be applied" path changed from a non-zero exit to a warning -- a test must fail. Record all five in `## Mutation results` with the test that caught each, and if one survives, say so and say what enforces the choice instead. Run `tools/ci/check-stestr-run.sh` over the integration run and quote its verdict, not the totals block. Commit subject: "Test the fetcher's sandbox, and the tests." |
| 4e | medium | sonnet | none | **Document it, then close the phase.** `docs/crates/fetch-protocol.md`: extend the `Lifecycle` section phase 3 added with the confinement -- which layer is applied by which side and at which moment, what a kernel without Landlock means for the run, and what a `SIGSYS` exit tells the operator. Correct the `Current Status` section, which says nothing about confinement, and while in it rewrap the over-long line that ends "nothing here touches the network." `docs/info.md`'s `file://` section gains a sentence on what `--verbose` now prints. No plan, phase, step or decision numbers in any of it (`docs/plans/` is the only place those belong). Then the closeout: this phase's row in `docs/plans/PLAN-http-input.md` and `docs/plans/index.md`, the Future work entry for namespaces from decision 13 with its measurement, and the execution notes. Commit subject: "Document the fetcher's confinement." |

Steps run in order. 4b and 4c both edit `src/fetch/src/confine.rs` and
both run the repository's checks, so they cannot share the tree; 4d
needs both installed to test either; 4e describes what the others did.
4a's measurement comes first because its three results can change 4b's
and 4c's tests -- if the container refuses Landlock, the Landlock tests
have to assert the report rather than the policy.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| The allowlist omits a syscall some distro's glibc makes, and a user sees `SIGSYS` | The filter is installed late, after all loader and runtime startup (decision 6), which removes most of the variance; the set is measured rather than read (decision 10); the margin is deliberate and listed. The management session re-runs the `strace` for one fixture itself rather than trusting the step's reported set, and the distro matrix in `merge_group` is what covers the rest |
| A layer silently does nothing, and the phase reports success | Decision 14 makes a skip impossible by construction: the host names the layers, the child fails loudly if it cannot apply a named one. The mutations in 4d (a), (b) and (e) are what prove that is true rather than intended |
| Landlock is unavailable in the container tier, so the policy is never exercised in CI | 4a measures it before anything is written. If it is unavailable, the Landlock tests assert the *report* in the container tier and the policy on the host tier via `make test-integration`, and the plan says so in the execution notes rather than leaving a quietly skipping test. `INSTAR_REQUIRE_*` (finding 14) is the existing shape for making that visible |
| The `SIGSYS` kill presents to the user as an unexplained `ConnectionReset` | Decision 11: the `Drop` already `wait`s, so `WTERMSIG` is in hand; 4a's reporting path and 4d's test cover the message. Phase 8 owns the wording |
| `RLIMIT_NOFILE` 8 is too tight for a libc that opens something at startup | The limit is set in `pre_exec`, so it binds the loader too. 4a's unit test reads `/proc/<pid>/limits` of a *live* fetcher, which can only pass if the child got far enough to serve; the distro matrix covers the libc variance. If a distro fails, the number rises and the execution notes record why |
| Confinement breaks the phase 3 parity oracle and it is not noticed | 4d re-runs the byte-identical comparison with the sandbox on, over the same six fixtures, with exit status inside the comparison |

## Definition of done

Each item is falsifiable; the management session checks them before the
push.

1. `instar info file:///<abs>` and `instar info /<abs>` still produce
   byte-identical stdout, in both `--output human` and `--output
   json`, over the six fixtures `TestInfoFileUrl` already uses, with
   confinement applied. The run is classified with
   `tools/ci/check-stestr-run.sh` and its `Ran: N` recorded in the
   execution notes.
2. A default `instar info file:///<abs>` writes nothing to stderr.
   `--verbose` writes a line naming each layer that was applied, and
   each layer the kernel refused.
3. `/proc/<pid>/limits` of a live fetcher shows `Max processes` 0,
   `Max core file size` 0 and `Max open files` 8, asserted as those
   three values.
4. `grep -n 'RLIMIT_FSIZE\|PR_SET_DUMPABLE' src/vmm/src/fetch.rs
   src/fetch/src/` finds nothing: decisions 7 and 12 held.
5. A child with the real Landlock policy installed can `pread` an
   inherited descriptor and cannot `open` the same path, asserted from
   its exit status in a test that fails rather than hangs.
6. A child with the real seccomp filter installed dies with `SIGSYS`
   on `socket`, and the test asserts `WTERMSIG`, not an errno.
7. `socket`, `connect`, `bind`, `sendto` and `openat` are each proved
   absent from the allowlist by a test that attempts the call, not by
   an assertion about the filter's contents.
8. `instar-fetch --confine=nonsense` exits non-zero naming the
   token, and a `--confine=landlock` run on a kernel without Landlock
   exits non-zero before sending an init reply. Both asserted.
9. The protocol is unchanged: `git diff develop...HEAD --
   src/crates/fetch-protocol/` is empty, and `VERSION` is still 1.
10. No new dependency: `src/fetch/Cargo.toml`'s `[dependencies]` is
    still `fetch-protocol` and `libc`, and `src/vmm/Cargo.toml`'s is
    unchanged.
11. Five mutations recorded in `## Mutation results`, each naming the
    test that caught it, or recorded as surviving with what enforces
    the choice instead.
12. `tools/ci/check-test-partition.sh` exits 0.
13. `git diff origin/develop...HEAD -- src/ docs/ tests/ .github/
    ':!docs/plans' | grep -nE 'PLAN-|[Pp]hase [0-9]|step 4[a-e]'`
    prints nothing.
14. `pre-commit run --all-files` exits 0, `make instar` builds, and
    `make test-rust` passes with its count recorded in the execution
    notes.
15. `docs/crates/fetch-protocol.md` says which side applies each
    layer and when, what an unconfinable kernel means for the run, and
    what a `SIGSYS` exit tells the operator. No documentation page
    states a fact about the fetcher that contradicts another page.
16. The three container-tier measurements from 4a are in the execution
    notes with the command that produced them.

## Back brief

Three gates for the operator before any step runs.

1. **Decision 16, the default on a kernel that cannot confine.** The
   plan proceeds and says so only under `--verbose`. The alternative
   is a warning on every such run, or a refusal. This changes
   behaviour on possibly three of the seven matrix distros and it is
   cheaper to settle before 4d writes the tests.
2. **Decision 13, declining user and mount namespaces.** The master
   plan names them. The plan declines them with the measurements in
   findings 3, 9 and 10, and records them in Future work. Worth a
   confirmation, because reversing it later is a new phase rather than
   a change to this one.
3. **Decision 11, `SECCOMP_RET_KILL_PROCESS` over
   `SECCOMP_RET_ERRNO`.** Kill gives a blunt failure and a clean
   security property; errno lets the fetcher report and carry on with
   a policy it has already violated.

## Execution notes

**The back brief, answered 2026-11-26 (AEDT).** All three gates were
confirmed as the plan proposed them. A kernel that cannot provide a
layer does not stop the run and is reported only under `--verbose`
(decision 16). User and mount namespaces stay declined (decision 13).
A syscall outside the policy kills the process (decision 11).

**The container tier, measured 2026-11-26.** Step 4a's first task, run
as a throwaway test inside `make test-rust`'s container and then
deleted; the management session reproduced all of it with a throwaway
test of its own, because the numbers decide what the later steps can
test rather than merely describing the host:

* `landlock_create_ruleset(NULL, 0, 1)` returns **6**. The container
  shares the host's kernel, so the ABI is the host's.
* `prctl(PR_SET_NO_NEW_PRIVS, 1)` followed by a one-instruction
  `SECCOMP_MODE_FILTER` install, in a forked child, **succeeds**.
* `unshare(CLONE_NEWUSER)`, in a forked child, fails with **`EPERM`**.

So both layers this phase installs can be tested against the real
policy in the container tier, and no Landlock or seccomp test has to
settle for asserting a report instead -- which is what the plan's third
risk was written against. Namespaces could not have been tested there,
which is the measurement behind decision 13's last clause.

One further number, not asked for and worth keeping: `PR_GET_SECCOMP`
reads **2** inside the container, because the container runtime has
already installed a filter of its own. The privileged side would have
read that as "already confined" and asked for nothing. Finding 16
rejected that probe on the argument that it answers a different
question; this is the measurement that would have caught it.

**Decision 7's count was wrong, and is corrected at source.** It said
four `setrlimit` calls; the step table, the scope and definition-of-done
item 3 all name three, and the fourth was `RLIMIT_FSIZE`, which finding
7 declined. The decision now reads three.

**Step 4a touched the fetcher, which its row did not ask for.** The
fetcher's `parse_args` refuses a third argument, so threading
`--confine=` into the child's command line without tolerating it there
would have made every spawn fail. Step 4a therefore accepts and ignores
the flag, and step 4b replaces that with the parsing decision 14
describes.

That leaves one claim this step must not make. Until 4b and 4c, the
child does nothing with the list, so the `--verbose` lines say what
this kernel offers and what the fetcher was asked for -- not that a
policy is in force. The management session reworded them for that
reason; the applied form, which is what definition-of-done item 2
requires, arrives with the code that applies it.

## Mutation results

To be filled in by step 4d.
