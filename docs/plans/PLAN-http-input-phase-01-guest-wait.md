# HTTP input phase 1: the guest I/O wait

## Status: Not started

Master plan: `PLAN-http-input.md`.

## Planning effort

High. The change itself is small -- a bounded loop becomes an
unbounded one -- but it removes the only place in the codebase where
a call-table I/O outlives the call that issued it, and the guest side
is bare-metal `no_std` code with volatile MMIO where a wrong memory
ordering is invisible until it corrupts an image. Review effort:
high for steps 1a and 1e, which touch the virtio request path and
the host's error rendering respectively.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-18:

1. Open question 5: the spin budget is a real defect, reproduced by
   measurement, and phase 1 is a bug fix rather than enabling work.

Taken when this phase was planned, 2026-11-18:

2. **The guest waits indefinitely, and there is no host deadline.**
   Not a watchdog thread, and not a TSC-bounded guest wait. The
   survey below explains why a host deadline cannot be enforced by
   either thread that services the queue.
3. **Issue #849 is out of scope.** The leftover output file after a
   failed convert needs a per-failure keep-or-unlink policy measured
   against qemu-img, which is its own argument.
4. **This phase shares a pull request with the master plan**, as
   PR #921 did for multi-extent VMDK phase 1. The branch is
   `http-input-phase-01-guest-wait`.

## Scope

In scope:

* Removing `MAX_WAIT_ITERATIONS` from `src/core/src/virtio.rs`
  `do_request`, and with it the `send_error("timeout", ...)` path.
  Closes #923.
* Making a guest I/O failure legible from the host without
  `--verbose`: a reserved `send_error` marker for an I/O failure, the
  host decoder capturing it, and `convert` and `dd` rendering it by
  name with an exit code measured against qemu-img rather than
  guessed. Closes #924.
* The LUKS inner-format probe in `src/operations/convert/src/main.rs`
  that treats a failed read as "no inner format", which the master
  plan asked this phase to read carefully. It is a real defect of a
  different shape than the master plan guessed; see the survey.
* A test that proves a slow host read no longer fails an operation,
  and that it would have before.

Out of scope, with reasons:

* **#849**, the leftover output file (decision 3).
* **Queue depth greater than one.** The master plan's Future work
  owns it. This phase makes a slow read survivable, not fast.
* **The VMM's logging defaults.** The survey found that no logger is
  installed at all without `--verbose`, so *every* diagnostic record
  in the VMM is discarded by default, not only guest I/O errors.
  That is wider than #924 and wants its own issue; this phase fixes
  the error the user sees rather than the log they do not.
* **The other operations' I/O error sites.** Step 1d audits all 13
  and records what each one's host side does with it; it converts
  only the ones whose host side currently drops the detail, which
  the survey found to be `convert` and `dd`.

## What the survey found

The master plan's phase 1 section was written before any of this was
measured. One of its claims is wrong, and five things it does not
mention change the shape of the work.

**The one wrong claim, corrected at source in this phase's planning
commit.** The section said the fix was to "move the deadline to the
host where it can be generous and per-request". There is no host
deadline to move it to. `src/vmm/src/io_thread.rs` passes 100 ms to
`epoll_wait`, and the comment there says why: so the loop can
re-check the `running` flag. Nothing times a request, anywhere in
the VMM. Building one is not a move, and decision 2 says not to
build one.

**Why a host deadline is not cheap.** Two paths service a virtio
queue. The I/O thread polls the ioeventfd when `IoEvent::register`
succeeds; when it fails the VMM falls back to processing the queue
from the vCPU exit, which is `process_queue_for_device`, called from
16 operation run loops. Both call `process_queue`, which calls
`self.backing.read_at` synchronously. So the thread that would
notice a request was late is the thread blocked inside the read. A
deadline needs a third thread whose only job is to watch -- new
privileged machinery, in the process holding `/dev/kvm`, to catch a
case (a wedged VMM) that no reproduction in this repository has ever
produced.

**The guest already waits forever on the host elsewhere.**
`src/core/src/serial.rs` `read_config` spins unbounded, in two
loops, waiting for the host to send the device configuration at
startup. An unbounded wait on a trusted host is therefore already
the pattern for one of the two channels between them, which is the
strongest argument that decision 2 is consistent rather than novel.

**The abandon path breaks a documented invariant, which is the
finding most worth reading.** `docs/guest-architecture.md` says the
shared read-modify-write bounce sector in the planner executor is
"safe because all call-table I/O is synchronous and steps execute
serially", and that `Ordering` barriers are a no-op because "issue
order is completion order". The timeout is the only place where a
call-table I/O is *not* synchronous: `do_request` returns `false`
while the host is still working on the request it has no way to
cancel. Compounding it, `do_request` addresses its header, data and
status buffers at fixed addresses -- `DMA_POOL_BASE`,
`DMA_POOL_BASE + 16` and `DMA_POOL_BASE + 16 + sector_size` -- for
every request, while rotating only the descriptor slot. So after a
timeout two requests are in flight against one set of buffers.
Nothing has gone wrong yet because the host services the queue
serially and completes in order, so the guest's next wait still
observes its own bytes. That is safety by accident of serialisation,
and it holds only while nothing in the VMM ever services two
requests concurrently -- which is exactly what the master plan's
Future work proposes to change. Removing the abandon path removes
the hazard before anything depends on it.

**#924 is two layers deep, not one.** Guest messages are formatted
by `format_message` and logged with `debug!` at 16 sites, and
`Level::Error` records go the same way. The logger is installed in
one place, inside `if verbose`, and that is the only
`set_boxed_logger` call in the VMM. So without `-v` there is no
logger at all and the record is discarded before its level is
considered. Separately, `SerialDecoder`'s capture chain names six
guest refusals -- `cpu-exception`, `DifferencingRefusal`,
`VhdFooterChecksumRefusal`, `InvalidL2EntryRefusal`,
`DataFileEntryRefusal`, `MalformedL2EntryRefusal` -- and no I/O
failure, so nothing is kept for `execute_convert` to render in place
of `"convert operation failed"`. That generic string is the only
`"... operation failed"` in the VMM; every other operation already
fails with a sentence.

**What #924 must capture is not `"timeout"`.** Once step 1a lands,
`do_request` never reports a timeout. A genuine host read error
still fails the request through the virtio status byte, and the
*operation* is what reports it: `convert` sends
`send_error("convert", "input", read_sector, 1)` followed by
`send_complete("convert", bytes_read, false)`. Capturing
`"timeout"` would therefore fix a message that step 1a deletes. The
marker has to be the operation's own I/O failure, which is what
outlives this phase and what a remote backing store will report in
phase 3.

**The LUKS probe at `src/operations/convert/src/main.rs` is a
defect, but not the one the master plan guessed.** It wrote that the
`&&`-chained `read_input_sector` "may be a silent-zero-fill bug". It
is not: the probe reads the first payload sector to look for QCOW2
magic, and on a failed read it silently skips the magic check and
falls through to the flat LUKS path. That path then re-reads *the
same sector* -- `payload_offset` is 0, so its `read_sector` equals
the probe's `payload_sector` -- and treats a failure there as fatal,
with `send_error` and a failed completion. So a wrong answer needs
one read to fail and the identical read to succeed moments later,
which is precisely what a transient timeout provides and nothing
else in the tree does. The output would then be a LUKS-wrapped
qcow2 decrypted and written out as a flat image, at exit 0. It is
reachable only through the defect step 1a removes, which is why it
belongs in this phase and not in a later one.

**Test infrastructure does not exist for this, and a missing tool
here is a silent pass.** `strace` appears in no Dockerfile and no CI
workflow in the repository, and the Python suite runs both on the
host (`make test-integration`) and in a container
(`make test-container`). An injection test that skips when `strace`
is absent would therefore be green everywhere and run nowhere --
the shape of the libvhdi oracle problem, where `make
test-container-core` passed for want of an environment variable.
Step 1b has to add the tool where the suite runs and make its
absence loud. The harness's own subprocess timeouts (30 s by
default in `tests/base.py`) are what keep an unbounded guest wait
from hanging CI.

Nothing else in the master plan's phase 1 section was wrong.

## Decisions

1. **The wait becomes unconditional.** `do_request` spins on the
   used ring until the completion arrives, with `spin_loop()` kept
   as the hint. The `timed_out` flag, the budget constant and the
   `send_error("timeout", ...)` branch all go. `do_request` keeps
   returning `false` for the status-byte failure path, which is a
   completed request that failed, not an abandoned one.

2. **No host deadline, and no guest backstop.** Decision 2 of the
   operator's set. The honest statement of the consequence is that a
   VMM which loses a completion hangs the guest until the user
   interrupts it, where today it fails after about 1.3 s with a
   misleading message. That trade is worth taking: a lost completion
   is a VMM bug with no reproduction, a slow read is an everyday
   event with a reproduction in #923, and the current behaviour
   turns the everyday event into the symptom of the rare one.

3. **A reserved marker for an I/O failure, following the refusal
   pattern.** Add `shared::IoFailure` with an `OPERATION` string
   distinct from every real operation name and from the six existing
   markers, its NUL-terminated twin for the call table, and
   documented meanings for `device` (which device failed) and
   `sector`. This is the `InvalidL2EntryRefusal` shape exactly,
   including the unit test that asserts the C string matches the
   Rust string. The guest's I/O error sites send that marker instead
   of their own operation name.

4. **The host renders it in the returned error, not in a log.** The
   decoder captures the marker; `execute_convert` renders it in
   place of `"convert operation failed"`. This follows
   `compare`'s existing wording, which names the image and the
   offset and says what did not happen: "compare: reading the second
   image, ref.raw, failed at virtual offset 327680 (0x50000); the
   images were not compared". The logging defaults stay as they are
   (see Scope).

5. **The exit code is measured, not chosen.** `compare` uses
   qemu-img's read-error code. What `qemu-img convert` exits with on
   a read failure is a question about another tool, and this
   repository has a standing rule that such claims are measured or
   cited rather than asserted. Step 1e measures it with an injected
   read error and records the number in this plan before using it.

6. **The LUKS probe propagates the failure.** A failed probe read
   becomes an error, not a skipped branch. The fix is small; the
   reasoning for why it was reachable is what the commit message has
   to carry, because a reader looking at the diff alone will see a
   failure path added for a read that is retried successfully two
   screens later.

The decision most likely to be argued with is 2. "Wait forever" reads
as a worse answer than "wait longer", and a reviewer may reasonably
ask for a generous TSC-based bound as cheap insurance. The argument
against is that a bound is a number nobody can derive: the guest
cannot distinguish a host that is slow from a host that is stuck,
and any number large enough not to fail a legitimate slow read on a
loaded 16-worker CI host is also large enough that a genuinely
wedged VMM looks like a hang anyway. The bound would buy a better
message in a case that has never been observed, at the cost of
keeping the abandon path -- and the abandon path is what breaks the
synchrony invariant the shared executor relies on.

## Steps

One commit per step, with the subject given in the brief.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | high | opus | none | **Remove the spin budget.** In `src/core/src/virtio.rs` `do_request`, replace the bounded `for _ in 0..MAX_WAIT_ITERATIONS` loop with an unbounded wait on the used ring, keeping the `read_volatile` of `used_base + 2`, the `expected_used_idx` comparison and `core::hint::spin_loop()` exactly as they are. Delete the `MAX_WAIT_ITERATIONS` constant, the `timed_out` flag, the `if timed_out` block and its `send_error("timeout", ...)` call, and the comment above the constant that claims "100M iterations is generous". Do not touch the status-byte check below it: that path is a completed request that failed and must keep returning `false`. Write a comment in its place saying why the wait is unbounded -- the host is trusted for every byte the guest reads, `src/core/src/serial.rs` `read_config` already waits unbounded on it, and a request cannot be cancelled once issued, so abandoning one leaves two in flight against the fixed `DMA_POOL_BASE` buffers. Do not reference this plan, its phases or its steps in the comment: landed code never cites plan files in this repository. Build with `make instar` (Docker; do not install a Rust toolchain on the host) and confirm pre-commit's binary-size-against-memory-layout hook passes, since this changes `core.bin`'s size. Then reproduce #923 against the new binary and show it no longer fires: `strace -f -qq -e trace=read -e inject=read:delay_enter=3000000:when=30 -o /dev/null <binary> convert -O raw <8 MiB qcow2> out.raw` must exit 0 and produce a byte-identical output to an uninjected run (`cmp`). Report both runs' exit codes and the `cmp` result. Commit subject: `Wait for the virtio completion instead of giving up.` |
| 1b | high | opus | none | **Make the reproduction a test.** Add a test that proves a slow host read no longer fails an operation. Decide where it lives by reading `tools/ci/check-test-partition.sh` and the job claims it checks -- a new module must be claimed by a pull-request job or that guard fails, so either extend an existing claimed module or add the claim in the same commit. The test injects latency with `strace -e inject=read:delay_enter=...:when=...` exactly as #923 documents, asserts exit 0 and a byte-identical output, and must **fail loudly rather than skip** when `strace` cannot inject: probe the capability (run `strace -e inject=read:delay_enter=1:when=1 /bin/true` and check it works, do not test for the binary's presence), and gate the skip behind an environment variable in the style of `INSTAR_REQUIRE_LIBVHDI`, so CI sets it and a missing tool is a failure there while a developer without `strace` still gets a skip. `strace` is in no Dockerfile and no workflow in this repository: add it where the suite runs (`src/.devcontainer/Dockerfile` and/or the CI workflow's package step -- find which actually runs the Python suite, do not guess) and say in your report which files you changed and why. The `when=` index is fragile across trees; make the test derive or search for a value that lands inside the guest run loop rather than hardcoding 30, and say how. Prove the test would have caught the bug: follow the `mutation-check` skill's method, restoring the spin budget in a scratch copy of `virtio.rs`, and confirm this test fails with the budget present and passes without it. Run the module with stestr and check the "Ran: N" line, not just the exit code -- a crashed worker exits 0 in this suite. Commit subject: `Test that a slow host read no longer fails an operation.` |
| 1c | medium | sonnet | none | **The shared I/O-failure marker.** In `src/shared/src/lib.rs`, add an `IoFailure` marker type following `InvalidL2EntryRefusal` as the model, which is the closest existing one: a unit struct, an `OPERATION` string constant distinct from every real operation name and from the six existing markers, the NUL-terminated twin for the call table's `send_error`, and doc comments stating what `device` and `sector` carry (the device that failed, and the sector the operation was reading or writing). Copy the existing markers' test pattern -- there is a test asserting the C string matches the Rust string for each; add the equivalent one here. No guest or host code changes in this step. Run `cargo test -p shared` through the devcontainer (`make test-rust` or the narrower target; do not run native cargo) and report the test count. Commit subject: `Add a shared marker for a guest I/O failure.` |
| 1d | high | opus | none | **Report I/O failures through the marker, and audit the rest.** There are 13 `send_error` call sites across `src/operations/*/src/main.rs` whose arguments look like an I/O failure (grep for `send_error` and filter for `"input`, `"output`, `"chain`, read and write). For each one, record in a table in this plan: the operation, the file and line, what it passes, and what the host does with it today -- whether the host path renders a specific error or drops it into a generic one. The survey established that `convert` is the only operation whose host side has a generic `"... operation failed"` string, so expect most of the 13 to be fine; confirm that rather than assuming it. Convert *only* the sites whose host side drops the detail to use `shared::IoFailure` from step 1c, keeping the sector and adding the device. `dd` shares `execute_convert`, so its sites travel with convert's. Leave the rest as they are and say in the table why each is already adequate. Do not change any operation's result struct or completion message. Build with `make instar` and confirm the guest binaries still fit (the binary-size hook). Commit subject: `Report guest I/O failures through the shared marker.` |
| 1e | high | opus | none | **Render it host-side.** In `src/vmm/src/main.rs`: add a field to `SerialDecoder` for a captured I/O failure, capture `shared::IoFailure::OPERATION` in the `Payload::Error` chain alongside the six existing markers (follow `last_invalid_l2_entry` for the shape, including its comment style explaining what `sector` means), add a `format_message` arm so a `--verbose` run reads well, and render it in `execute_convert`'s failure tail in place of `"convert operation failed"` -- in the same position as the existing `last_differencing_refusal` and `l2_entry_refused` branches, which are the pattern to copy. Word it after `compare`'s existing read-failure error: name the image by the path the user passed, name the offset in both decimal and hex, and say what did not happen. `dd` and `convert` share the function, so pick the operation name the way the existing branches do (`exec.window.is_some()`). **Measure the exit code before choosing it**: run `qemu-img convert` against a source whose read fails (inject with `strace` as #923 documents, or use a source on a FUSE or loop device you can fail) and record qemu-img's exit code, the `qemu-img` version, and the exact command in a *Measurements* section of this plan. Use that code if `convert` can; if instar's exit-code plumbing cannot express it, say so in the plan and use the nearest thing, naming both. Add unit tests beside the existing decoder tests (`differencing_refusal_error_*` are the models) for: nothing captured yields the generic message, a captured failure names the image and offset, and the `dd` spelling. Commit subject: `Say what failed when a guest I/O error stops convert.` |
| 1f | medium | opus | none | **The LUKS inner-format probe.** In `src/operations/convert/src/main.rs`, the LUKS path's inner-format detection reads the first payload sector inside an `if` whose condition `&&`-chains `(call_table.read_input_sector)(...)`, so a failed read skips the QCOW2 magic check and falls through to the flat LUKS path. Make the failed read an error: report it through `shared::IoFailure` and fail the operation the way the main read loop below it already does (`send_error` then `send_complete(..., false)`), rather than continuing with an undetected inner format. Read the survey section of this plan first -- the reason this matters is that the main loop re-reads *the same sector* and treats a failure as fatal, so the only way to reach the bad outcome is a read that fails once and succeeds on retry, and the output is then a decrypted qcow2 written out as a flat image at exit 0. The commit message must carry that reasoning, because the diff alone looks like a redundant check. Do not reference this plan. If there is an existing LUKS-wrapped-qcow2 fixture in `tests/manifest.json`, add a test that the probe's failure path fails the operation rather than converting wrongly; if there is not, say so and record it in Future work rather than building a fixture here. Commit subject: `Fail convert when the LUKS inner-format probe cannot read.` |
| 1g | low | sonnet | none | **Close the phase.** Fold this phase's findings back into `PLAN-http-input.md`: record in the Bugs-fixed section what #923 and #924 turned out to be, and add to Future work the two things this phase deliberately left: the VMM installing no logger without `--verbose` (worth its own issue), and #849. Confirm `git diff origin/develop...HEAD -- src/ docs/ tests/ \| grep -nE 'PLAN-\|[Pp]hase [0-9]\|step 1[a-g]'` prints nothing: no plan, phase or step references in landed code, docs or tests. Confirm `docs/guest-architecture.md`'s statement that call-table I/O is synchronous is now true without qualification, and if it needs a sentence to say the wait is unbounded, add it there -- that file is the summary-and-index for the guest, so keep it to a sentence. Do not change the Execution table's status; the next phase's first commit closes this one out. Commit subject: `Record phase 1's findings in the master plan.` |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| An unbounded wait turns a VMM bug into a hang, in CI or for a user | The test harness already bounds every subprocess (30 s by default in `tests/base.py`), so a lost completion fails a test rather than hanging a run. For a user it is interruptible, and it is the behaviour qemu-img has against a hung mount. Decision 2 states the trade rather than hiding it; step 1g records it in Future work so a watchdog can be argued for on its own merits |
| Step 1b's test passes everywhere and runs nowhere | The step requires a capability probe rather than a presence check, an environment-variable guard in the style of `INSTAR_REQUIRE_LIBVHDI`, and the tool added where the suite actually runs. The management session checks the claim by running the module with the variable set and unset and confirming the two outcomes differ |
| The `when=` injection index drifts as the tree changes, so the test silently stops injecting into the guest run loop | Step 1b must derive or search for the index rather than hardcoding it, and assert that the injection actually delayed a read -- a test that injects into the wrong syscall and passes is worse than no test. The mutation check in the same step is what proves it is injecting where it matters |
| Converting the 13 `send_error` sites changes a message some test asserts on | Step 1d converts only the sites whose host side drops the detail, and the audit table is produced before any edit. The full Python suite is the check; per the repository's standing rule, a failure is root-caused against `develop` rather than waved through as pre-existing |
| The exit code for a failed convert is guessed and diverges from qemu-img | Decision 5 and step 1e require it to be measured, with the command, version and result written into this plan before the code uses it |
| Step 1a's comment or commit message cites the plan | Explicit in both briefs, and step 1g greps for it across `src/`, `docs/` and `tests/` |

## Definition of done

Each item is falsifiable; the management session checks them before
the push.

1. `grep -rn 'MAX_WAIT_ITERATIONS\|timed_out' src/core/` prints
   nothing, and `grep -rn '"timeout"' src/core/ src/operations/`
   prints nothing.
2. The #923 reproduction -- `strace -f -qq -e trace=read -e
   inject=read:delay_enter=3000000:when=<index> -o /dev/null instar
   convert -O raw <8 MiB qcow2> out.raw` -- exits 0, and `cmp`
   against an uninjected conversion of the same source reports no
   difference.
3. The same reproduction against a build with the spin budget
   restored fails, and step 1b's test fails with it and passes
   without it. Recorded in this plan as a mutation result, naming the
   test.
4. `instar convert` with a genuinely failing read, and **no**
   `--verbose`, prints an error that names the image, names the
   offset, and says the conversion did not happen. The exit code is
   the one step 1e measured from qemu-img, and this plan records that
   measurement with its command and version.
5. The `"convert operation failed"` string is reachable only for
   failures that are not I/O: `grep -n 'convert operation failed'
   src/vmm/src/main.rs` shows it still exists, and the I/O path no
   longer reaches it.
6. `shared::IoFailure`'s C marker and Rust string are asserted equal
   by a unit test, as the six existing markers are.
7. The failed LUKS probe fails the operation: demonstrated by a test
   where one exists, or by a recorded manual injection where a
   fixture does not.
8. Step 1d's audit table is in this plan, covering all 13 sites, with
   a reason for every one left unconverted.
9. `git diff origin/develop...HEAD -- src/ docs/ tests/ | grep -nE
   'PLAN-|[Pp]hase [0-9]|step 1[a-g]'` prints nothing.
10. `pre-commit run --all-files` exits 0, `make test-rust` passes,
    and the Python suite's `test_convert` and `test_compare` modules
    pass with their "Ran: N" lines checked rather than their exit
    codes trusted.
11. #923 and #924 are closed by this phase's pull request body, and
    #849 is not.

## Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.

One gate within the phase: step 1e's wording and exit code are
cheap to propose and expensive to redo once tests assert on them, so
the management session agrees the error sentence and the measured
exit code before step 1e's tests are written.
