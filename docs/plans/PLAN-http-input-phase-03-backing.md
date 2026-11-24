# HTTP input phase 3: the remote backing store

## Status: Not started

Master plan: `PLAN-http-input.md`.

## Planning effort

High. The phase puts a child process inside the lifetime of the
privileged one for the first time in instar's history, and the two
things it has to get right -- which descriptors cross the `exec`
boundary, and that the child is reaped on every exit path including
the panicking ones -- are both the kind of mistake that does not
show up in a passing test. Review effort: high for step 3b, the
spawn and the reap, which is the step where a wrong answer leaves
either a leaked descriptor in an untrusted process or a zombie in
every run.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-18:

1. **Open question 3:** the cache, the coalescing and the readahead
   all live in the fetcher. The VMM's `read_at` stays one round trip,
   so this phase adds no buffering of its own.
2. **Open question 8:** the fetcher is found the way the guest `.bin`
   files are -- the executable's own directory first, then
   `/usr/lib/instar/` -- and is packaged at mode 755.

From phase 2, 2026-11-19, and binding here:

3. **The fetcher takes descriptor numbers, not paths.** The
   privileged side opens the image and the fetcher inherits it. There
   is no path argument and no fallback that accepts one, because such
   a fallback is the hole phase 4's confinement would have to leave
   open.
4. **Nothing the fetcher says to the privileged side is text.** A
   failure is a `Status` value, and the sentence the user reads is
   written on this side from that value. The fetcher's stderr is for
   diagnostics and never becomes part of the protocol.

Taken when this phase was planned, 2026-11-25: decisions 5 to 14
below.

## Scope

In scope:

* Recognising a URL on an instar input, accepting `file://` and
  refusing every other scheme by name.
* `BackingStore` reading through a fetcher: a third `Storage`
  variant wrapping phase 2's `FetchClient`.
* The fetcher's lifecycle: spawned before `/dev/kvm` is opened,
  handed exactly two descriptors, and reaped on every exit path
  including a panic.
* `instar info file:///path` working end to end through the socket,
  with output byte-identical to `instar info /path`.
* The integration test that proves it, and the mutations that prove
  the tests bite.

Out of scope, with where each belongs:

* **Every read-only operation other than `info`** -- decision 5.
  Phase 7 owns the operation scope and the refusal-by-name policy
  across the whole CLI surface.
* **Host-side reads of the input that are not the device's bytes**
  -- the VMDK flat-descriptor preflight, the LUKS probe, and
  `metadata.blocks()` for the disk-size column. A `file://` input
  still has a path, so these keep working untouched; phase 5 is
  where the host loses the path and has to route or refuse them
  (see *What the survey found*, finding 6).
* **Confinement.** No Landlock, no seccomp, no namespaces, no
  rlimits. Phase 4. This phase only avoids handing the child
  anything phase 4 would then have to take away.
* **Any network code at all.** Phase 5. The grep in the definition
  of done keeps it out.
* **Progress reporting, deadlines, caps and `--spool`.** Phase 8.
  The client's existing 60-second reply timeout is what this phase
  ships with.
* **Issue #932.** It was fixed by #945, not by this phase -- see
  finding 1.

## What the survey found

Five of the master plan's claims about this phase were written
before phases 2 and 3 of two different plans landed, and three of
them are now wrong. All three have been corrected at source in
`PLAN-http-input.md` and `docs/plans/index.md` as part of the commit
that adds this file; a later step does not need to redo it.

1. **#932 is already fixed, by #945, not by this phase.** The master
   plan said twice -- in the phase 3 section and in Future work --
   that this phase "should also fix #932, the virtqueue error the
   host cannot read that hangs the guest". #945 ("Five failures that
   never reached the user", merged 2026-11-22 as `8ed88fc9`) carries
   `Fixes #932` and the fix: `src/vmm/src/io_thread.rs` gained
   `FatalIoError`, which records the failure and signals the vCPU out
   of `KVM_RUN` so the run fails with the recorded reason. The issue
   is CLOSED. `io_thread.rs:107` and its tests name the issue, so the
   fix is identifiable rather than inferred. **Corrected at source.**

2. **`BackingStore` is no longer a plain struct, so the polymorphism
   is already there.** The master plan said it "holds a `File`, a
   capacity, a size and a sparse flag, with no enum, trait or
   indirection -- so 'gains a second kind' means introducing the
   polymorphism as well as the remote implementation". That was true
   on 2026-11-19. It stopped being true on 2026-11-21, when #938
   (multi-extent VMDK phase 3) landed `b6f13211` "Let a backing store
   span several files", which added a private
   `enum Storage { Single(File), Concatenated(Vec<ConcatMember>) }`
   inside the struct (`src/vmm/src/backing.rs:40-53`).
   `BackingStore::read_at` already dispatches on it and already
   early-returns for the non-`Single` arm
   (`src/vmm/src/backing.rs:235-240`). So this phase adds a third
   variant to an existing enum, which touches none of the roughly
   forty `BackingStore` call sites. **Corrected at source.**

3. **The VMM has never spawned a child, and that claim still holds.**
   The only `Command::new` under `src/vmm/src/` is
   `version.rs:166`, `qemu-img --version`, which runs to completion
   and is read for its output. There is no `pre_exec`, no
   `waitpid`, no signal handling and no descriptor passing anywhere
   to extend. Everything in step 3b is new code.

4. **`Kvm::new()` is called at eighteen separate sites in
   `main.rs`**, one per operation path, not once in a shared setup
   function. "Started before `/dev/kvm` is opened, reaped on every
   exit path" therefore has eighteen places to be got right if it is
   written as explicit calls, which is decision 7's whole argument
   for putting the reap in a `Drop` instead. **Not a correction --
   the master plan did not say either way -- but it is the fact that
   shapes the phase.**

5. **The integration point in `run_info` is two lines, because the
   size already travels separately.**
   `VirtioBlockDevice::new(backing, size_bytes, sector_size, ...)`
   (`src/vmm/src/virtio/block.rs:131-137`) takes the device's size
   as its own argument rather than asking the backing store for it,
   and `run_info` fills it from `std::fs::metadata` at
   `main.rs:14193-14194` before opening the store at `main.rs:14212`.
   A remote input needs nothing more than a different pair of values
   there. There is also already a helper in the file returning
   exactly the shape this phase wants --
   `-> Result<(BackingStore, u64), Box<dyn Error>>` at
   `main.rs:5025` -- so the signature is not a novel one.

6. **The host reads the input path for three things besides the
   device's bytes**, and a `file://` input keeps all three working
   because it still resolves to a path:
   `std::fs::metadata(&args.input)` for the apparent size *and*
   `metadata.blocks()` for the disk-size column
   (`main.rs:14193-14201`), `resolve_vmdk_flat_descriptor` in the
   preflight above it (`main.rs:14185`), and the LUKS probe when
   `--luks-passphrase` is given. This is why the phase's end state is
   worth having as an oracle and also why it is not yet the hard
   problem: the device's bytes cross the socket, while the metadata
   does not. Phase 5 is where the path goes away and each of the
   three has to be routed through the client, derived from the
   protocol, or refused. Recorded in the master plan's Future work as
   part of this phase's planning commit.

7. **The fetcher already refuses a non-regular file**
   (`src/fetch/src/main.rs:241-245`), so the failure mode exists but
   arrives as a dead socket and an exit code rather than a sentence.
   Decision 11 puts the refusal on the privileged side first.

8. **Everything phase 2 built is where this phase needs it.**
   `FetchClient::read_at(&mut self, offset: u64, buf: &mut [u8]) ->
   io::Result<()>` (`client.rs:225`) is byte-for-byte
   `BackingStore::read_at`'s signature; it already zero-fills past
   the advertised capacity, wholly and partly
   (`client.rs:237-248`), exactly as the local store does past the
   end of its file; `capacity()` and `block_size()` are readable
   (`client.rs:178-183`); `SeqPacketSocket::pair()` exists and
   `impl From<SeqPacketSocket> for OwnedFd` (`socket.rs:397`) is how
   the child's end is handed over. The default reply timeout is 60
   seconds (`client.rs:71`).

9. **No URL or scheme handling exists anywhere in the VMM.** A grep
   for `file://`, `scheme` and `url` across `src/vmm/src/*.rs` finds
   nothing outside documentation comments. `InfoArgs.input` is a
   `String` (`main.rs:7181`), not a `PathBuf`, so a URL reaches
   `run_info` untouched and nothing has to change in the clap
   definition.

10. **`get_binary_dir()` already resolves to the right directory for
    the fetcher, but keys on the wrong file.** It searches
    `INSTAR_BIN_DIR`, then the executable's directory, then
    `/usr/lib/instar`, and takes the first that contains `core.bin`
    (`main.rs:3877-3897`). `instar-fetch` is installed in
    `/usr/lib/instar/` and built into `src/target/release/`
    alongside `core.bin` in both cases, so `get_binary_path(
    "instar-fetch")` lands correctly today -- but it does so because
    `core.bin` is its sentinel, and its doc comment says it returns
    the directory of "the instar guest binaries (.bin files)".
    Decision 10 keeps the function and fixes the comment rather than
    adding a second resolver.

One thing the survey could not settle: **whether kvm-ioctls 0.25
opens `/dev/kvm` with `O_CLOEXEC`.** The crate source is not on this
host (no native Rust toolchain by policy, and the registry lives in
a container volume), so step 3b verifies it in the devcontainer and
records the answer. The phase does not depend on it either way --
decision 6 orders the spawn before the open, which costs nothing and
holds regardless -- but it decides whether that ordering is the only
protection or a second one.

## Decisions

5. **Only `info` accepts a URL in this phase.** The master plan's
   phase 3 line says "the read-only operations accept a URL", plural,
   while its end state names one: `instar info file:///path` working
   end to end. This phase does the second. The mechanism it builds is
   a helper any operation can call, and phase 7 -- which already owns
   "URLs accepted only by read-only operations and refused by name
   everywhere else" -- extends acceptance to the rest in one place
   with one policy.

   This is the decision most likely to be argued with, so the
   argument against it, put properly: wiring the other read-only
   operations is mechanical once the helper exists, and leaving it
   undone means `instar check file:///x` fails with "No such file or
   directory" until phase 7 lands, which is a worse error than a
   refusal. The answer to the second half is decision 9, which makes
   every unwired operation say what is actually wrong. The answer to
   the first half is that "mechanical" here means eighteen
   `Kvm::new()` sites with their own input-opening preambles
   (finding 4), every one of which would be edited again in phase 7
   when the policy lands -- and that none of it would be exercised by
   anything, because there is no HTTP backend yet and the `file://`
   oracle proves the mechanism once, not six times.

6. **The fetcher is spawned before `Kvm::new()`.** The child cannot
   inherit a descriptor the parent has not yet opened, so ordering is
   a guarantee that does not depend on anyone remembering
   `O_CLOEXEC`. It is free: nothing in the operation paths needs the
   VM before the input.

7. **The reap lives in a `Drop`, not in eighteen call sites.** The
   remote source owns the `Child` and the `FetchClient` together, and
   its `Drop` closes the socket and then waits for the child. That is
   what makes "reaped on every exit path" true for the paths nobody
   writes down -- a `?` return halfway through an operation, a panic
   inside the vCPU loop, a `std::process::exit` further out (which it
   does not cover, and decision 8 handles).

   The wait is bounded, because a `Drop` that blocks forever is worse
   than a leaked process: close the socket, which makes the fetcher's
   `recv` return zero and it exits zero; poll `try_wait()` for up to
   two seconds; then `SIGKILL` and a blocking `wait()`. A fetcher
   that needs the `SIGKILL` is a bug in the fetcher, so that path
   writes one line to stderr naming the pid and the elapsed time.

8. **A remote input refuses to coexist with `std::process::exit`.**
   `Drop` does not run on `exit`, so any operation wired to a remote
   input must return through `main` rather than exiting under it.
   `run_info` already does. The definition of done greps for
   `process::exit` on the `info` path to keep it that way, rather
   than trusting that it stays true.

9. **A URL is recognised by its scheme, and every scheme but
   `file` is refused by name.** An input matching
   `^[A-Za-z][A-Za-z0-9+.-]*://` is a URL; `file` is served, and
   anything else -- `https`, `http`, `s3`, `nbd` -- is refused with a
   sentence naming the scheme and saying instar does not accept it
   yet. Anything that does not match is a path, exactly as today, so
   a file called `weird:name` still opens.

   The refusal is the point as much as the acceptance. Until phase 5
   lands, `instar info https://example.com/disk.qcow2` would
   otherwise fail with `No such file or directory`, which tells the
   user their file is missing rather than that the feature is not
   built. One grep-able table of schemes, in one module, is also what
   phase 5 edits to turn `https` on and phase 7 edits to vary it by
   operation.

10. **`file://` is parsed by hand, and narrowly.** Accepted:
    `file://` or `file://localhost`, followed by an absolute path.
    Refused with a reason: a non-empty, non-`localhost` authority
    (`file://evil.example/x`), a relative path, a query, a fragment,
    and any `%` escape. No `url` crate: phase 2's definition of done
    established that `cargo tree -p instar` names no new third-party
    crate, and keeping that property is worth more than percent
    decoding that nothing yet needs. Phase 5 adds a real URL parser
    when it adds a protocol that needs one, and it will be parsing in
    the fetcher where the parse is cheap to get wrong.

11. **The privileged side opens the file, checks it, and refuses
    first.** It resolves the path, opens it read-only, `fstat`s it,
    and refuses a non-regular file itself -- the fetcher's own
    refusal (finding 7) is a backstop, not the user's error message.
    The capacity the device is given comes from the *client's* init
    reply, not from that `fstat`, because that is the number phase 5
    will have; the `fstat` length is asserted against it in a test,
    which is a free cross-check of the protocol while there is still
    a local file to check against.

12. **The child gets exactly five descriptors: 0, 1, 2, and the
    socket and file at 3 and 4.** `SeqPacketSocket::pair()` sets
    `SOCK_CLOEXEC` on both ends and Rust's `File::open` sets
    `O_CLOEXEC`, so the two the child needs are placed with `dup2`
    inside a `pre_exec` closure, which clears the flag on the new
    descriptor as a side effect of duplicating. The closure calls
    `dup2` and nothing else: it runs after `fork` in a process that
    may hold locks it can never release, so it allocates nothing,
    takes no lock, and formats no string. A test reads
    `/proc/<pid>/fd` of a live fetcher and asserts the set is exactly
    `{0,1,2,3,4}`.

13. **The fetcher's stderr is inherited.** In this phase the only
    peer the fetcher has is instar itself, so the one-line-per-
    refused-request rate the master plan warns about is set by the
    VMM's own requests and is bounded by them. Phase 5 is where the
    bytes start coming from a server, and phase 8 owns the user-facing
    failure surface; the master plan's Future work records that
    whatever routes this stderr into a log then owns a rate a peer
    sets. Inheriting also means a fetcher diagnostic is visible in a
    failing test's output, which is worth a lot in the phase that
    debugs the mechanism for the first time.

14. **A remote store refuses writes rather than silently dropping
    them.** `Storage::Remote` makes `write_at` and `sync` return an
    `io::Error` naming the input as read-only, `is_sparse()` false,
    and `size()` the advertised capacity. Nothing in this phase can
    reach those paths -- the device is built read-only -- so the
    refusal is there for phase 7, when an operation with an output
    gets a remote input and a wrong turn would otherwise write into
    a `None`.

## Steps

One commit per step, with the subject given in the brief. The steps
are sequential and share the worktree: every one of them runs
`pre-commit run --all-files` and `make test-rust`, which two
concurrent steps would trip over. Build order matters on a cold
`src/target`: `make instar` before `make test-rust`, since they share
one target directory with different container images.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 3a | medium | sonnet | none | **Recognise a URL on an input.** Create `src/vmm/src/fetch.rs`, declared in `main.rs` next to the other `mod` lines (`main.rs:53` imports `backing::BackingStore`; follow that pattern). It holds, for now, one public enum and one function: `InputSource::{Path(PathBuf), FileUrl(PathBuf)}` and `fn classify_input(arg: &str) -> Result<InputSource, String>`. The rule is decision 9: an argument matching `^[A-Za-z][A-Za-z0-9+.-]*://` is a URL, anything else is `Path`. Do not add a regex crate -- match the scheme by hand with `char::is_ascii_alphanumeric` and friends, since `cargo tree -p instar` must name no new third-party crate. For a URL, the scheme is lowercased and compared: `file` parses per decision 10 (`file://` or `file://localhost` then an absolute path; refuse a non-empty non-localhost authority, a relative path, a `?`, a `#`, and any `%`), and every other scheme returns the refusal sentence naming it, e.g. `instar does not accept https:// inputs yet; pass a local path`. Keep the refusal text in one `const` table of (scheme, sentence) plus a fallback for unknown schemes, because phase 5 turns `https` on by editing it and phase 7 varies it per operation. Unit tests in the same file, one per accepted and refused shape named for the shape, including `file:///tmp/x`, `file://localhost/tmp/x`, `file://evil.example/tmp/x`, `file://relative`, `file:///x?y`, `file:///x#y`, `file:///%2e%2e/x`, `https://example.com/x`, `/plain/path`, `./rel`, and `weird:name` (a path, not a URL -- no `//`). Nothing in this step spawns anything or opens anything. Commit subject: `Recognise a file URL on an instar input.` |
| 3b | high | opus | none | **Spawn the fetcher and reap it.** In `src/vmm/src/fetch.rs`, add `pub struct RemoteSource` owning a `std::process::Child` and a `fetch_protocol::FetchClient`, and `pub fn spawn_file_fetcher(path: &Path) -> io::Result<RemoteSource>`. It: resolves the fetcher with `get_binary_path("instar-fetch")` from `main.rs:3899` (see finding 10 -- also fix that function's doc comment, which says it returns the directory of the guest `.bin` files, now that an executable is found through it; the `core.bin` sentinel stays); opens `path` read-only and `fstat`s it, refusing a non-regular file here with a clear message (decision 11); creates the socketpair with `fetch_protocol::SeqPacketSocket::pair()`; spawns the child with `std::process::Command`, `arg("3")`, `arg("4")`, `stderr(Stdio::inherit())`, and a `pre_exec` closure that `dup2`s the child's socket end to 3 and the file to 4 and does nothing else at all -- no allocation, no locks, no formatting, because it runs between `fork` and `exec` (decision 12); drops the parent's copies of the child's two descriptors; and builds the `FetchClient` on the parent's socket end, which performs the init exchange. Expose `client_mut()`, `capacity()` and `pid()`. `impl Drop` per decision 7: drop the socket, `try_wait()` in a poll loop for up to two seconds, then `libc::kill(pid, SIGKILL)` and a blocking `wait()`, printing one line to stderr naming the pid and the elapsed time when it comes to that. **Also, in this step, answer the open question the survey could not**: read kvm-ioctls 0.25's `Kvm::new()` in the devcontainer (`make test-rust` is how you build; the registry is in the container, the host has no toolchain by policy) and record in this plan's execution notes whether it opens `/dev/kvm` with `O_CLOEXEC`. Tests: spawn a real fetcher over a temporary file and read bytes back through `read_at`, comparing against `pread`; assert the client's advertised capacity equals the host's `fstat` length (decision 11); read `/proc/<pid>/fd` while it is alive and assert the descriptor set is exactly `{0,1,2,3,4}` (decision 12); assert that after the `RemoteSource` is dropped, `kill(pid, 0)` fails with `ESRCH` within the bounded window; assert a fifo and a directory are both refused before any spawn. Run every test under a bound so a hang fails rather than runs. Commit subject: `Spawn and reap the fetcher that serves an input.` |
| 3c | medium | opus | none | **Let a backing store read through a fetcher.** In `src/vmm/src/backing.rs`, add a third variant to the private `enum Storage` at line 40: `Remote(crate::fetch::RemoteSource)`. Add `pub fn open_remote(source: RemoteSource) -> Self`, setting `capacity` and `current_size` to the source's advertised capacity and `sparse` false. In `read_at` (line 231), add the arm beside the existing `Concatenated` early return: delegate straight to the client's `read_at`, with no bounds logic of its own -- `FetchClient::read_at` already zero-fills wholly and partly past the advertised capacity, exactly as the `Single` arm does past the end of its file (finding 8), and duplicating that here would be a second implementation of the same rule. In `write_at` and `sync`, return an `io::Error` naming the input as read-only (decision 14); `is_sparse()` false; `size()` the capacity. Do not introduce a trait, a `dyn` or a public enum: the roughly forty `BackingStore` call sites must not change, and the point of finding 2 is that the polymorphism already exists. Tests: a `Remote` store reads the same bytes as a `Single` store over the same file, including a read spanning the end, a read wholly past it, and offset 0; `write_at` and `sync` on a `Remote` store fail with the read-only error. Commit subject: `Let a backing store read through a fetcher.` |
| 3d | high | opus | none | **Read `instar info`'s input through the fetcher.** Wire step 3a's classification into `run_info` (`main.rs:14097`). The shape: classify `args.input` early, before the sector-size validation's siblings; for `InputSource::Path` nothing changes at all; for `FileUrl(path)` spawn the fetcher *before* `Kvm::new()` at `main.rs:14232` (decision 6 -- the existing input-open at 14212 is already before it, so the order falls out of putting the spawn there) and build the device from `BackingStore::open_remote` with the capacity from the client rather than from `metadata` (decision 11). The host's `std::fs::metadata` at 14193 stays for `blocks()` and the disk-size column, because a `file://` input still has a path (finding 6) -- say so in a comment naming phase 5 as where that stops being true, without citing this plan or a phase number in the code. Refuse, with a sentence each, the flags that would make the privileged side resolve the URL string as a path: `--chain` (which calls `discover_backing_chain` on the raw input at 14109) and anything else you find on the `info` path that does the same; grep the function for `args.input` and `input_path` and check every use. Confirm `run_info` returns its errors through `main` rather than calling `std::process::exit`, since `Drop` is what reaps the child (decision 8). The falsifiable end state: `instar info file:///path` and `instar info /path` produce byte-identical stdout for the same file, in both `human` and `json` output. Prove it in a Rust test if you can reach it from the binary crate's `#[cfg(test)]` module, and in step 3e's integration test regardless. Commit subject: `Read instar info's input through the fetcher.` |
| 3e | high | opus | none | **Prove it end to end, and prove the tests bite.** Add tests to the existing `tests/test_info_safe.py` rather than a new module -- a new Python module has to be claimed by a pull-request job in the same commit or `tools/ci/check-test-partition.sh` fails, and adding to a claimed module avoids that entirely; run that script anyway and confirm it exits 0. The tests: for a spread of the fixtures the module already uses, run `instar info` on the path and on `file://` + the absolute path and assert the stdout is byte-identical, for both `--output human` and `--output json`; assert `instar info file://localhost/<abs>` agrees too; assert `instar info https://example.com/x` fails with the scheme refusal and a non-zero exit, and that the message names the scheme; assert `instar info --chain file:///<abs>` fails with the refusal rather than a path error. Find the binary the way the suite already does, never a hardcoded path. Then prove the tests bite: follow the `mutation-check` skill and break three things in turn in a scratch copy, confirming a named test fails for each -- (i) in `RemoteSource::Drop`, delete the wait so the child is never reaped, (ii) in `classify_input`, accept every scheme instead of `file` alone, (iii) in `run_info`, take the device's capacity from the host `metadata` instead of the client's init reply. Restore from the copy, never with `git checkout <dir>`; clear `__pycache__` and bump mtimes after restoring a Python file, since CPython trusts a `.pyc` on (mtime, size) at one-second granularity. Record the three mutations and the test that caught each in a `## Mutation results` section of this plan, and record the suite's `Ran: N` line -- read, not inferred from the exit code -- in the execution notes. Classify the integration run with `tools/ci/check-stestr-run.sh`, never the totals block, which prints `Failed: 0` for a run that lost a worker. Commit subject: `Test instar info over a file URL end to end.` |
| 3f | medium | sonnet | none | **Document it, then close the phase.** Documentation first: `docs/info.md` (or whichever page documents `instar info`'s arguments -- find it, do not guess) gains what a `file://` input is and what is refused and why; `docs/crates/fetch-protocol.md` gains a section on the lifecycle this phase added -- who spawns, which descriptors cross the `exec`, who reaps and when -- since that page is the protocol's home and the lifecycle is now part of it; `docs/index.md` needs no new entry unless you add a page. Check whether `AGENTS.md` needs anything: it should not, unless the `pre_exec` constraint of decision 12 counts as a convention an agent cannot infer, which is a judgement call -- make it and say which way. Then close the phase: fold this phase's findings back into `PLAN-http-input.md` -- the stderr rate note of decision 13 and finding 6's three host-side reads go in Future work for phase 5, and record whether kvm-ioctls sets `O_CLOEXEC` as a fact phase 4 will want. Check that the corrections this phase's survey made at source are still there and still accurate (findings 1 and 2, in both the phase 3 section and Future work). Confirm `git diff origin/develop...HEAD -- src/ docs/ tests/ .github/ ':!docs/plans' \| grep -nE 'PLAN-\|[Pp]hase [0-9]\|step 3[a-f]'` prints nothing. Confirm `cargo tree -p instar` names no third-party crate it does not name on `develop`. Do not change the Execution table's status for this phase; the next phase's first commit closes it out. Commit subject: `Record phase 3's findings in the master plan.` |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A `Drop` that blocks forever: the fetcher ignores the closed socket and `wait()` never returns, so every instar run hangs at the end instead of exiting | Decision 7's bounded wait -- two seconds of `try_wait()`, then `SIGKILL`. Step 3b's test asserts the child is gone within the window, so the bound is tested rather than assumed. The management session reads that test, because it is the one test here whose absence would not fail anything |
| A zombie per run: `Drop` is skipped on a path nobody wrote down | The `Drop` is the mechanism, not a call site (decision 7), so the paths that need no author are covered. The one it does not cover is `std::process::exit`, which decision 8 greps for on the `info` path |
| A descriptor the child should not have crosses the `exec` -- the worst outcome in the phase, because phase 4 then confines a process that already holds it | Decision 12 plus step 3b's `/proc/<pid>/fd` test, which asserts the whole set rather than the absence of one descriptor. The ordering of decision 6 means `/dev/kvm` is not open yet whatever `O_CLOEXEC` says |
| `pre_exec` does something unsafe between `fork` and `exec` -- allocates, takes a lock, formats an error -- and deadlocks a run under load, rarely | The closure is `dup2` and nothing else, which is the review item for step 3b. A diagnostic in there is the specific thing to reject |
| The phase proves less than it looks like it proves, because a `file://` input still has a local path and the host still stats it | Said plainly in the scope and in finding 6, and recorded in the master plan's Future work for phase 5. What this phase proves is the mechanism: the device's bytes cross the socket. That is what makes it the oracle for every later phase, and it is worth having for that alone |
| `instar info file:///x` and `instar info /x` differ in some field nobody checks | The definition of done is byte-identical stdout in both output formats, over a spread of fixtures, which is a stronger claim than any field-by-field check and cheaper to write |
| The merge-queue distro matrix only runs in `merge_group`, so a matrix-only failure cannot be caught on the pull-request gate | Nothing in this phase can be matrix-specific except the `/proc` test, which is Linux-only and so is instar. Note for the management session: #939's qemu-create pin flake is live and unfixed, and it ejects merge groups on Ubuntu 22.04 for reasons unrelated to this phase -- a re-queue is the response, not a fixup |

## Execution notes

Filled in as the steps run. What belongs here: the `make test-rust`
count after each step, the integration suite's `Ran: N` line as read,
the kvm-ioctls `O_CLOEXEC` answer from step 3b, and anything a step
found that the plan got wrong.

Implementation began 2026-11-25 (AEDT). The back brief's three gates
were agreed as planned before any step ran: decision 5, `info` alone
rather than every read-only operation; decisions 7 and 12, the reap in
a `Drop` bounded at two seconds and then `SIGKILL`, with the child's
two descriptors at 3 and 4; and decision 9's refusal table, refusing
every scheme but `file` by name. The implementing session was also
given permission to push the branch and open the pull request once the
phase is done, which it otherwise would not have.

**Step 3a.** `make test-rust`: 3116 passed, 0 failed, of which 20 are
`fetch::tests`. `pre-commit run --all-files`: all ten hooks pass.
Three things worth recording:

* The module needs `#[allow(dead_code)]` on `InputSource` and
  `classify_input` until step 3d calls them, since the binary's
  dead-code lint rejects an unused public item in a binary crate.
  Step 3d removes both.
* `file:/tmp/x`, with one slash, classifies as a **path**, because
  decision 9's rule is `://`. RFC 8089 permits that form, so a URL
  some tools accept reports a missing file. Left as decided rather
  than silently widened; adding it is one branch in `classify_input`
  if it ever matters.
* A `%` escape, a `?`, a `#` and a NUL are refused anywhere after
  `file://` rather than only within the path, which is wider than
  decision 10's wording and the same thing in practice: none of them
  is legitimate in an authority either.

## Mutation results

Filled in by step 3e. Three mutations, each naming the test that
caught it.

## Definition of done

Each item is falsifiable; the management session checks them before
the push.

1. `instar info file:///<abs>` and `instar info /<abs>` produce
   byte-identical stdout for the same file, in both `--output human`
   and `--output json`, over at least three fixtures of different
   formats. The comparison is in `tests/test_info_safe.py` and it
   **runs** rather than skipping: its `Ran: N` line is recorded in
   the execution notes, and the run is classified with
   `tools/ci/check-stestr-run.sh`, not by the totals block.
2. `instar info https://example.com/x` exits non-zero with a message
   naming the scheme, and so does every other scheme in step 3a's
   table. `instar info --chain file:///<abs>` is refused with a
   sentence, not a path error.
3. A live fetcher's `/proc/<pid>/fd` contains exactly `{0,1,2,3,4}`,
   asserted as the whole set.
4. After the `RemoteSource` is dropped, `kill(pid, 0)` fails with
   `ESRCH` inside the bounded window, asserted by a test that fails
   rather than hangs if it does not.
5. The client's advertised capacity equals the host's `fstat` length
   for the same file, asserted in a test.
6. `grep -n 'process::exit' ` over `run_info` and everything it calls
   on the remote path finds nothing.
7. `grep -rn 'TcpStream\|TcpListener\|to_socket_addrs\|https\?://'
   src/vmm/src/fetch.rs src/vmm/src/backing.rs` finds nothing outside
   comments and the refusal table's text: there is still no network
   code in the tree.
8. `cargo tree -p instar` names no third-party crate it does not name
   on `develop` at the phase's base commit.
9. Three mutations recorded in `## Mutation results`, each naming the
   test that caught it: the missing reap, the scheme check, and the
   capacity's source.
10. `tools/ci/check-test-partition.sh` exits 0.
11. `git diff origin/develop...HEAD -- src/ docs/ tests/ .github/
    ':!docs/plans' | grep -nE 'PLAN-|[Pp]hase [0-9]|step 3[a-f]'`
    prints nothing.
12. `pre-commit run --all-files` exits 0, `make instar` builds,
    `make test-rust` passes with its count recorded in the execution
    notes, and the Python modules this phase touches pass with their
    `Ran: N` line read rather than their exit code trusted.
13. `docs/crates/fetch-protocol.md` describes the lifecycle: who
    spawns, which descriptors cross the `exec`, who reaps and when.
    No documentation page states a fact about the fetcher that
    contradicts another page.

## Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.

Three gates, all cheap to agree and expensive to redo:

1. **Decision 5, `info` only.** Agree it before step 3a, because it
   is the shape of the whole phase and the one a reviewer is most
   likely to want widened. Widening it later is additive; narrowing
   it after six operations are wired is not.
2. **Decisions 7 and 12 together -- the reap in a `Drop` and the two
   descriptors at 3 and 4** -- agreed at the end of step 3b before
   3c and 3d build on them. This is where a wrong answer is
   expensive: phase 4 confines the process this step spawns, and a
   descriptor that crosses the `exec` by accident is a hole the
   sandbox is then built around.
3. **Decision 9's refusal table**, agreed before step 3d wires it in.
   It is the user-visible surface of a feature that does not exist
   yet, phase 5 turns a row of it on and phase 7 varies it per
   operation, so the shape of the table matters more than any
   sentence in it.
