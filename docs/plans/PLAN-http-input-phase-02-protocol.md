# HTTP input phase 2: the fetch protocol and a file-backed fetcher

## Status: Not started

Master plan: `PLAN-http-input.md`.

## Planning effort

High. Nothing here is mechanical. The phase introduces the only new
untrusted parse in the privileged process, it needs a socket type
Rust's standard library does not provide, and every layout and
vocabulary choice it makes becomes a compatibility surface that
phases 3 to 6 build on and that tests will assert against. Review
effort: high for steps 2a and 2d, which are the parser and the
adversarial tests respectively.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-18:

1. **Open question 1:** a plain framed protocol that borrows
   virtio-blk's model and not its mechanism. No shared memory, no
   virtqueue over `memfd`, no real NBD, no serialisation library --
   `#[repr(C)]` headers with explicit bounds checks. The fetcher gets
   one socket and nothing else.
2. **Open question 2:** `SOCK_SEQPACKET`, 64 KiB default block size,
   with a ceiling negotiated at init rather than assumed. The survey
   below corrects the number this question quoted.
3. **Open question 3:** the cache, the coalescing and the readahead
   all live in the fetcher. The VMM's `read_at` stays one round trip.
4. **Open question 8:** the fetcher is found the same way the guest
   `.bin` files are -- the executable's own directory first, then
   `/usr/lib/instar/` -- and is packaged at mode 755.

Taken when this phase was planned, 2026-11-19: decisions 5 to 12
below.

## Scope

In scope:

* A new host-side library crate holding the wire format: the
  `#[repr(C)]` headers, their encode and decode with explicit bounds
  checks, the typed status vocabulary, and the `SOCK_SEQPACKET`
  socket type.
* `instar-fetch`, a workspace binary that serves a single file over
  that protocol and contains no network code at all.
* The VMM-side client, with a `read_at`-shaped API, so that phase 3
  wires in something that has already been tested rather than
  something written for the first time at the point of integration.
* A libFuzzer target for the decoder, registered in all three lists
  `tools/ci/check-fuzz-targets.sh` compares.
* The build and packaging changes that make `make instar` produce
  the fetcher and the `.deb`/`.rpm` ship it.
* `docs/crates/fetch-protocol.md`, following the one existing page in
  that directory.

Out of scope, with reasons:

* **Anything that reads a URL.** No scheme parsing, no `file://`, no
  CLI surface on `instar` at all. Phase 3 owns the CLI and
  `BackingStore`; this phase's fetcher takes file descriptors, not
  names.
* **`BackingStore` itself.** The client is a standalone type in this
  phase. Making `BackingStore` polymorphic is phase 3's first act and
  the survey found it is a larger change than the master plan implies.
* **Process lifecycle: spawning, reaping, supervision, exit paths.**
  Phase 3. This phase's tests spawn the fetcher themselves, which is
  not the same thing as the VMM owning one.
* **Confinement.** Phase 4. Decision 10 below is chosen partly to
  make phase 4 cheaper, but installs no sandbox.
* **Several requests outstanding.** The wire format carries request
  ids and permits out-of-order replies from day one (decision 11), so
  that phase 6 needs no protocol change; the client issues one at a
  time and the fetcher is single-threaded.
* **A reason string on the wire.** Decision 8 refuses one, and says
  why.

## What the survey found

Read against `a8387ffe` on 2026-11-19. Four of the master plan's
claims about this phase were wrong or imprecise, and three of them
change what the phase does. Everything here was corrected at its
source in the same commit that added this file, so a later step need
not redo it.

### The datagram ceiling is not what open question 2 says

The question states that "the measured `wmem_max` of 212992 caps a
single datagram near 256 KiB here". Measured on this host with an
`AF_UNIX`/`SOCK_SEQPACKET` socketpair:

| Condition | `SO_SNDBUF` | Largest single datagram |
|---|---|---|
| Fresh socketpair, untouched | 212992 | 212960 (208.0 KiB) |
| After `setsockopt(SO_SNDBUF, 4 MiB)` | 425984 | 425952 (416.0 KiB) |

So the claim is wrong in both directions. At the default, 256 KiB
does **not** fit -- the ceiling is 208 KiB. After an explicit
`setsockopt` it does, because the kernel clamps the requested value
to `wmem_max` and *then* doubles it, giving `2 * wmem_max - 32`.
Neither number is derivable from `wmem_max` by inspection, and a host
with `wmem_max` of 65536 would cap a datagram at 128 KiB - 32 even
after asking for more.

This is why decision 6 derives the ceiling from the `SO_SNDBUF` the
kernel actually granted rather than from any sysctl, and why 64 KiB
is the default: it is the only size that fits everywhere without
asking for anything.

### Rust's standard library has no `SOCK_SEQPACKET`

`std::os::unix::net` offers `UnixStream` (`SOCK_STREAM`) and
`UnixDatagram` (`SOCK_DGRAM`) and no way to ask for anything else.
Neither `nix` nor `socket2` appears in `src/Cargo.lock`, so a
SEQPACKET socket means either a new third-party dependency in the
privileged process or a `libc::socketpair` call behind a safe
wrapper. `libc` 0.2 is already a dependency of `instar`, and
`src/vmm/src/ioevent.rs` is the established pattern in this
repository for exactly this shape -- a raw `libc` call in an `unsafe`
block, wrapped in a type that owns the descriptor. Decision 5 takes
that route. **The toolchain lives in Docker, so this was not
compile-checked on the host**; step 2a's first act is to confirm it,
and to say so if `std` has grown the capability since.

### 64 KiB does match the guest's request size

This premise held up, and it is worth recording because the
arithmetic in the master plan's intent depends on it. One guest
request transfers exactly `sector_size` bytes --
`src/core/src/virtio.rs` `read_sector` refuses a buffer shorter than
`sector_size` and `do_request` moves that many -- and every read-only
operation defaults `--sector-size` to 65536: `InfoArgs`,
`MapArgs`, `CheckArgs`, `CompareArgs`, `ConvertArgs`, `MeasureArgs`
and `CopyArgs` all carry `#[arg(long, default_value = "65536")]` in
`src/vmm/src/main.rs`. `MAX_SECTOR_SIZE` in
`src/shared/src/lib.rs:721` is 65536 and is the ceiling, not the
request size.

The 512-byte sector sizes in the tree belong to `resize`, `bitmap`,
`amend` and `create` -- all operations phase 7 refuses a URL for
anyway. Open question 3's phrase "the coalescing of 512-byte
requests" therefore describes a case that cannot reach a remote
source; what the fetcher's cache is actually for is repeated and
overlapping 64 KiB reads, which a format parser walking a chain does
constantly. Corrected at source.

### `BackingStore` is not yet a thing that can gain a second kind

`src/vmm/src/backing.rs:15` is a plain `struct BackingStore { file:
File, capacity, current_size, sparse }`. There is no enum, no trait,
no indirection. `read_at(&mut self, offset: u64, buf: &mut [u8]) ->
io::Result<()>` fills the whole buffer or errors. Phase 3's sentence
"`BackingStore` gains a second kind" is a bigger change than it
sounds, and it has one consequence for this phase: the client's API
is specified to match that signature exactly (decision 7), so phase
3's work is introducing the polymorphism, not also designing the
remote side's shape.

### The VMM has never spawned a child process

The only `Command::new` anywhere under `src/vmm/src/` is
`version.rs:166`, running `qemu-img --version`. There is no
descriptor-passing code, no reaping, no supervision, no signal
handling for a child. Phase 3's lifecycle work is greenfield. It is
also why this phase stops where it does: a client tested against a
fetcher the *test* spawned is a different and much smaller claim than
a fetcher the VMM owns.

### `make instar` will not build a new binary by itself

`src/build.sh:337-339` builds the VMM with a `cd vmm` followed by
`cargo build --release` -- package-scoped, not workspace-scoped. A new workspace
member is simply not built. The packaging asset lists are in
`src/vmm/Cargo.toml` (`[package.metadata.deb]` assets at line 69,
`[package.metadata.generate-rpm]` at line 101) and name every
artefact explicitly. So the fetcher needs: a build block in
`build.sh`, a line in its closing summary, and a row in each of the
two asset lists at mode 755 rather than the 644 the guest `.bin`
files use.

`get_binary_dir()` in `src/vmm/src/main.rs:3550` needs no change at
all: it keys off the presence of `core.bin` and `get_binary_path`
simply joins a name onto the directory it returns, so
`get_binary_path("instar-fetch")` already resolves the way open
question 8 assumed.

### Where the protocol must not live

`src/shared` is `#![no_std]` with zero dependencies and is linked by
the bare-metal guest: it is the guest ABI and the fetch protocol has
no business in it. `crates/guest-protocol` is a standalone crate
(deliberately not a workspace member) using micropb and heapless for
the guest's variable-shape serial messages, which is the contrast
open question 1 draws and it is accurate. It also sets the precedent
this phase follows for documentation: `docs/crates/guest-protocol.md`
is the only page in `docs/crates/`, and it is registered at
`docs/index.md:230`.

### Guards a new crate, test and fuzz target must satisfy

* A new workspace member needs `[lints]` / `workspace = true` to
  inherit `unwrap_used = "warn"`, the way `src/crates/qcow2` and
  `src/vmm` do. A non-member would have to declare it directly, as
  `crates/guest-protocol` does.
* A new Python test module must be claimed by a pull-request job or
  `tools/ci/check-test-partition.sh` fails.
* A new fuzz target must appear in three places that
  `tools/ci/check-fuzz-targets.sh` compares for exact equality: the
  `.rs` file under `src/fuzz/fuzz_targets/`, a `[[bin]]` stanza in
  `src/fuzz/Cargo.toml`, and the `TARGETS=(...)` array in
  `.github/workflows/coverage-fuzz.yml`. It also wants a row in
  `docs/testing.md`.

### Phase 1's open issues that bear on this phase

#932 (a virtqueue error the host cannot read hangs the guest) is the
one that matters. Phase 1 made the guest's wait unbounded and made
the host complete a failed request with `IOERR`, which is what makes
a remote read's failure survivable at all -- a fetcher that dies
becomes an `io::Error` from the client, an `IOERR` completion, and a
failed operation with a sentence that names the image. But an error
the host cannot *read* still hangs, and phase 3 multiplies the ways
the host can fail to answer. This phase does not fix it; the plan
records that phase 3 should, and the risk table says why it is phase
3's problem rather than this one's.

## Decisions

5. **A `libc::socketpair` behind a safe wrapper, not a new
   dependency, and not a filesystem socket.** `std` cannot make a
   SEQPACKET socket, so one `unsafe` block is unavoidable unless
   `socket2` or `nix` joins the privileged process's dependency tree,
   which is a poor trade for one syscall. `src/vmm/src/ioevent.rs`
   shows the shape: a raw call, checked, wrapped in a type that owns
   the descriptor and closes it on drop.

   It is a `socketpair` rather than a bound path in the filesystem
   because the VMM is the fetcher's parent. There is no name for
   anything else to connect to, no directory to choose, no mode to
   get wrong, and nothing for phase 4's Landlock policy to have to
   permit. `SOCK_CLOEXEC` on creation, and the fetcher's end is
   `dup2`'d to a fixed descriptor number.

6. **64 KiB default, with what each side can carry measured from the
   granted `SO_SNDBUF`.** Both ends ask for a buffer large enough to
   carry the protocol's largest block, read back what the kernel
   granted, and the init exchange settles on the smaller of the two
   achievable maxima -- capped at the **64 KiB default**, not at the
   256 KiB maximum. No sysctl is read and no number is assumed. The
   survey explains why the measurement is necessary: the value in open
   question 2 was neither the default ceiling nor the reachable one.

   *Corrected 2026-11-19, during step 2f's review.* This decision
   originally said "capped at 256 KiB", which contradicted open
   question 2's "64 KiB default" -- and the code followed the
   decision, so a well-provisioned pair negotiated 256 KiB and
   `DEFAULT_BLOCK_SIZE` was used only by tests. The operator confirmed
   the 64 KiB default. A larger block buys nothing while a guest
   request is at most 64 KiB: it only changes how a larger read is
   divided, and holds four times the receive buffer for payloads that
   never arrive. The 256 KiB maximum stays the figure the headers and
   the requested socket buffers are built to reach, so phase 6 raises
   one constant rather than the protocol.

7. **The client's API is `read_at(&mut self, offset: u64, buf: &mut
   [u8]) -> io::Result<()>`.** Identical to `BackingStore`'s, so
   phase 3 introduces polymorphism over an interface that already
   matches on both sides. Errors surface as `io::Error`, which is
   what phase 1's `last_io_error` plumbing records and renders.

8. **A typed status vocabulary, and no free-form reason string on the
   wire.** The status is an enum the privileged side owns, rich enough
   to be actionable -- `OK`, `BAD_REQUEST`, `UNSUPPORTED`,
   `OUT_OF_RANGE`, `SHORT_READ`, `IO_ERROR`, and reserved space for
   the ones phase 5 needs (`NOT_FOUND`, `FORBIDDEN`,
   `RANGE_UNSUPPORTED`, `SOURCE_CHANGED`, `NETWORK`, `TIMEOUT`). The
   VMM maps each to a sentence it wrote itself.

   **This is the decision most likely to be argued with**, so here is
   the argument. A reason string is the obvious way to tell a user
   that a server returned 404, and refusing one looks like it throws
   away the diagnostic that matters. But the fetcher is the
   untrusted side of the partition, a string from it is attacker-
   influenced text, and phase 1 just finished building the path that
   renders a failure reason straight into the user's terminal --
   `terminal_safe_path` exists in `src/vmm/src/main.rs` precisely
   because a path can carry escape sequences, and a reason string
   would need the same treatment plus length bounds plus encoding
   validation, in the privileged process, for every message. A fixed
   enum costs one `match` and cannot carry a payload at all. The
   diagnostic is not lost: the fetcher has its own stderr, which
   phase 3 can route into the VMM's log, and #931 is the issue that
   makes the VMM's log visible without `--verbose`. If phase 5 finds
   the enum genuinely insufficient, extending it is a one-line change
   to a crate the VMM owns -- which is a much better position than
   having to retrofit sanitising onto a string that tests already
   assert on.

9. **Little-endian on the wire, explicitly.** The socket never leaves
   the machine, so native order would work, but an explicit `to_le` /
   `from_le` costs nothing on x86_64, makes the header layout a
   documented fact rather than a property of the build host, and
   means the fuzz corpus is portable.

10. **The VMM opens the file; the fetcher inherits the descriptor.**
    In this phase `instar-fetch` receives two descriptor numbers --
    the socket and the file -- and opens nothing. It takes no path.
    Resolving a path is an exercise of the invoking user's authority
    and belongs on the privileged side; and a fetcher that never
    opens a file is one phase 4 can confine to no filesystem access
    whatsoever, which is a stronger and cheaper sandbox than one that
    must be permitted to open the image. Phase 5 adds `--url`
    alongside, for a backend that needs a socket instead of a file.

11. **Request ids and out-of-order replies in the wire format from
    the start, with a single-threaded fetcher and one request
    outstanding.** The hinge, not the door. Phase 6 needs
    concurrency; the protocol that would have to change to get it is
    the expensive thing to change, and the implementation that would
    have to change is cheap. A reply carries the id it answers and
    the client matches on it rather than assuming order, so phase 6
    changes only how many are in flight.

12. **A magic and a version in the init message, and a mismatch is a
    hard failure naming both versions.** The fetcher is found by
    probing the executable's directory and then `/usr/lib/instar/`,
    so a developer build talking to a packaged fetcher -- or the
    reverse -- is a real mistake that will happen. It is cheap to
    detect exactly and miserable to debug as a protocol desync.

## Why not NBD, and why not a virtqueue

Open question 1 asks that this comparison be recorded where a
reviewer will find it, because the shape chosen here is NBD's and the
mechanism it rejects is one the repository already has working code
for.

**Not a virtqueue, even though the pieces are present.**
`virtio-queue` 0.18 and `vm-memory` 0.18 are already dependencies,
`src/vmm/src/ioevent.rs` already does eventfd notification, and
`SCM_RIGHTS` over the socket would pass a `memfd` and an eventfd
without trouble. It would work, and it would hand the untrusted
fetcher a writable mapping shared with the privileged process, where
whoever controls the ring controls indices the VMM dereferences.
That is the memory-corruption channel the whole partition exists to
remove, and defending it means writing adversarial-ring validation in
privileged code -- the same class of work as the existing virtio
boundary audit -- to save a copy that does not matter: a 256 KiB
`memcpy` is tens of microseconds against tens of milliseconds of
network.

**Not NBD, even though NBD is exactly this shape.** NBD is
offset-addressed reads over a socket with request handles and
out-of-order replies, and `nbdkit`'s curl plugin is an off-the-shelf
implementation of most of this feature. Speaking real NBD means
parsing a negotiated protocol -- option haggling, structured replies,
an extensible handshake -- from an untrusted peer, in the privileged
process. The few fixed-size headers here are a far smaller surface,
small enough that step 2e can fuzz the whole decoder. Steal the
shape; do not link the protocol.

**And not micropb, unlike the guest serial channel.**
`crates/guest-protocol` uses protobuf because the guest's results are
variable-shape messages with optional fields. This channel carries
fixed-size headers and raw bytes, so a serialisation library buys
nothing and adds a dependency and a decoder nobody in this
repository has fuzzed.

## Steps

One commit per step, with the subject given in the brief. The steps
are sequential: 2b to 2g all depend on 2a's types, and every step
runs `pre-commit` and the Rust tests in the shared worktree, which
two concurrent steps would trip over.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2a | high | opus | none | **The protocol crate.** Create `src/crates/fetch-protocol` as a new member of the workspace in `src/Cargo.toml` (add it to the `members` array next to the other `crates/*` entries), with `[lints]` / `workspace = true` so it inherits `unwrap_used = "warn"` the way `src/crates/qcow2/Cargo.toml:61` does. **First, before writing anything else, confirm the survey's claim that `std::os::unix::net` cannot create a `SOCK_SEQPACKET` socket** -- write a throwaway test that tries, build it through the devcontainer (`make test-rust`; never a native cargo, the host has no toolchain by policy), and report what you found. If `std` can do it, use `std` and say so. Otherwise follow `src/vmm/src/ioevent.rs` as the pattern for a raw `libc` call wrapped in a type that owns its descriptor: a `socketpair(AF_UNIX, SOCK_SEQPACKET \| SOCK_CLOEXEC, 0)` constructor returning the two ends, each a type implementing `AsRawFd` and closing on drop. The crate contains: the `#[repr(C)]` header structs for init-request, init-reply, read-request and read-reply; their encode and decode, little-endian explicitly (decision 9), with every decode checking the datagram's length against the header's own size *before* reading any field and checking every length and offset against the negotiated maximum; the `Status` enum of decision 8 with explicit discriminants and reserved values documented but unused; and the magic and version constants of decision 12. Add unit tests asserting `size_of` and the offset of every field (`std::mem::offset_of!`) against the numbers you document, so a layout change breaks a test rather than the wire, and tests that each malformed shape decodes to a typed error rather than a panic: a datagram shorter than the header, a bad magic, a version mismatch, an unknown opcode, an unknown status, a length past the negotiated max, and an offset that overflows when added to a length. No I/O in this step beyond the socket constructor -- no `instar-fetch`, no client. Report the test count from `make test-rust`. Commit subject: `Define the fetch protocol's wire format.` |
| 2b | high | opus | none | **The fetcher.** Create `src/fetch`, a new workspace member whose package name is `instar-fetch`, producing a binary of the same name, with `[lints]` / `workspace = true`. It depends on `fetch-protocol` by path and on nothing else beyond `libc` if it needs it. Per decision 10 it takes **descriptor numbers, not paths**: a CLI of two required numeric arguments, the SEQPACKET socket and the file to serve, and it opens nothing -- use `std::fs::File::from_raw_fd` (or the `OwnedFd` equivalent) and `fstat` for the capacity. It is single-threaded. It answers init with the capacity, the sector-agnostic block ceiling it can manage (decision 6: ask the kernel for the buffer you want, read back `SO_SNDBUF`, derive `granted - 32` as the largest datagram you can send and report it), and the protocol version; it answers a read by `pread`-ing the file at the requested offset and replying with the bytes and a status; it answers anything else with `UNSUPPORTED` rather than closing. A read that the file is too short for gets `SHORT_READ` with the bytes that were available, not `OK`; a read past the capacity it advertised gets `OUT_OF_RANGE`; a `pread` that fails gets `IO_ERROR`. It must never `panic!` on anything the peer sends and never `unwrap` a decode. Diagnostics go to its own stderr, one line each, and nowhere else. Then make it build and ship: add a build block to `src/build.sh` (the VMM's is at lines 337-339, a `cd vmm` followed by `cargo build --release` -- the fetcher needs its own, because that build is package-scoped and will not pick up a new member), add it to the closing summary `echo` list, and add a row to **both** asset lists in `src/vmm/Cargo.toml` -- `[package.metadata.deb]` at line 69 and `[package.metadata.generate-rpm]` at line 101 -- as `["target/release/instar-fetch", "usr/lib/instar/", "755"]`, noting that the guest `.bin` files there are 644 and this is an executable. Verify with `make instar` that `src/target/release/instar-fetch` exists afterwards. Commit subject: `Serve a file over the fetch protocol.` |
| 2c | medium | sonnet | none | **The client.** In `src/crates/fetch-protocol`, add the VMM-side client: a type holding the socket end, with `read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>` exactly as decision 7 specifies -- the same signature as `BackingStore::read_at` in `src/vmm/src/backing.rs:104`, filling the whole buffer or returning an error. It performs the init exchange on construction, stores the negotiated block size and the capacity, splits a `read_at` larger than the negotiated block into several requests, and matches each reply by request id rather than assuming order (decision 11), even though it keeps only one in flight. Every non-`OK` status maps to an `io::Error` whose `kind` and message are chosen by this crate, never taken from the peer (decision 8) -- `OUT_OF_RANGE` to `InvalidInput`, `IO_ERROR` to `Other`, and so on; document the mapping in the code. A reply whose id is unknown, or a status outside the enum, is an error and not a panic. Do **not** touch `src/vmm` at all in this step: nothing in the VMM uses this yet, and `BackingStore` is phase 3's. Add unit tests over a socketpair with a hand-rolled peer that replies out of order, replies with an unknown id, and returns each error status. Commit subject: `Add the VMM-side client for the fetch protocol.` |
| 2d | high | opus | none | **Prove it end to end, and against a hostile peer.** Two commits. **First**, an end-to-end test: spawn the real `instar-fetch` binary on one end of a socketpair with a temporary file on the other descriptor, and read a few hundred offsets -- including offset 0, the last partial block, an offset past the end, a read spanning the negotiated block size, and a set of random offsets and lengths from a fixed seed -- comparing every result against `pread` on the same file. Byte-identical or the test fails. Decide where this test lives by reading `tools/ci/check-test-partition.sh` and the job claims it checks: a new Python module must be claimed by a pull-request job in the same commit, or that guard fails. A Rust integration test under `src/crates/fetch-protocol/tests/` is also acceptable and is probably simpler, since it needs no fixture image at all -- choose, and say why. Find the fetcher binary the way the suite finds `instar`, not by a hardcoded path. **Second**, the adversarial half: a test peer that is not the real fetcher and misbehaves -- a truncated datagram, a reply with a length larger than the negotiated maximum, a reply claiming more bytes than the datagram carries, an id never requested, a status value outside the enum, a version mismatch at init, an init that advertises a capacity of `u64::MAX`, and a peer that closes mid-exchange. Each must produce an `io::Error` from the client promptly, with no panic, no hang and no out-of-bounds write. Run each under a bound (`timeout`) so a hang fails rather than runs. Then prove the tests bite: follow the `mutation-check` skill, and in a scratch copy break three things in turn -- the length check in the read-reply decode, the id match in the client, and the negotiated-maximum clamp -- confirming a named test fails for each. Restore from the copy, never with `git checkout <dir>`. Record the three mutations and which test caught each in a `## Mutation results` section of this plan. Commit subjects: `Read a file end to end through the fetch protocol.` and `Refuse a fetch peer that misbehaves.` |
| 2e | medium | sonnet | none | **Fuzz the decoder.** Add `src/fuzz/fuzz_targets/fuzz_fetch_protocol.rs`, modelled on an existing target that parses a header -- `fuzz_luks_header.rs` and `fuzz_parallels_header.rs` are the closest. It feeds arbitrary bytes to every decode entry point in `fetch-protocol` (init request, init reply, read request, read reply) and asserts only that nothing panics; it must not assert a successful parse. Register it in **all three** lists `tools/ci/check-fuzz-targets.sh` compares for exact equality: the `.rs` file, a `[[bin]]` stanza in `src/fuzz/Cargo.toml`, and the `TARGETS=(...)` array in `.github/workflows/coverage-fuzz.yml`. Read the top of that script first -- it explains what it compares and why a missing entry is silent. Add the target's row to `docs/testing.md`'s fuzz table. Run `tools/ci/check-fuzz-targets.sh` and report its exit code; then run the target briefly (a minute is plenty for a decoder this small) and report the iteration count and any crash. Commit subject: `Fuzz the fetch protocol decoder.` |
| 2f | medium | sonnet | none | **Document the protocol.** Write `docs/crates/fetch-protocol.md`, following `docs/crates/guest-protocol.md` closely -- same section shape (Overview, Location, the wire format in place of Schema, Message Types, Framing, Usage, Dependencies, Features, Current Status, Limitations) and the same register. It must state every header's size and field offsets, and those numbers must match step 2a's layout tests; say in the page that the tests are the authority. Document the status vocabulary including the reserved values, the init negotiation and where the block-size ceiling comes from, and the `SOCK_SEQPACKET` choice. Include a short section on why not NBD and why not a virtqueue, condensed from this plan's section of that name -- a maintainer reading the page will ask, and the plan file will eventually be retired. Register the page in `docs/index.md` beside the `guest-protocol` row at line 230. Do not describe HTTP, URLs, caching or confinement: none of it exists yet, and a page that promises them is a page that will be wrong for four phases. Do not reference this plan, its phases or its steps anywhere in the page: landed documentation never cites plan files in this repository. Commit subject: `Document the fetch protocol.` |
| 2g | low | sonnet | none | **Close the phase.** Fold this phase's findings back into `PLAN-http-input.md`: record in Future work that #932 should be fixed in phase 3 rather than later, because phase 3 multiplies the ways the host can fail to answer a request and an error the host cannot read still hangs the guest; and record the measured datagram ceiling as a fact phase 6 will need when it revisits the block size. Check that the corrections this phase's survey made at source are still there and still accurate (open question 2's ceiling, open question 3's 512-byte phrasing, phase 3's `BackingStore` sentence). Confirm `git diff origin/develop...HEAD -- src/ docs/ tests/ .github/ \| grep -nE 'PLAN-\|[Pp]hase [0-9]\|step 2[a-g]'` prints nothing. Confirm `cargo tree -p instar` names no new third-party crate -- the fetcher and the protocol crate are path dependencies and `instar` does not yet depend on either. Do not change the Execution table's status for this phase; the next phase's first commit closes it out. Commit subject: `Record phase 2's findings in the master plan.` |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Hand-rolled `unsafe` socket code lands in the privileged process | One constructor, one syscall, `SOCK_CLOEXEC`, a type that owns and closes the descriptor, modelled on `src/vmm/src/ioevent.rs` which has the same shape and has been reviewed. Step 2a is high effort and opus for this reason, and step 2a's first act is to check whether `std` makes the `unsafe` unnecessary |
| The decoder is a new untrusted parse in the privileged process -- the thing this whole plan is trying to avoid creating | Fixed-size `#[repr(C)]` headers, no serialisation library, every decode bounds-checked before any field is read, a fuzz target in this same phase rather than deferred to phase 9, and the adversarial peer tests of step 2d. The surface is a few hundred bytes of structs by design: if it grows past what step 2e can fuzz exhaustively, that is the signal the design went wrong |
| A reason string gets added later and reaches a terminal unsanitised | Decision 8 refuses one now, when nothing asserts on it. The mitigation is the decision; what makes it hold is that the enum is owned by the VMM's own crate, so adding a variant is cheaper than adding a string |
| The 256 KiB ceiling is unreachable on a host with a small `wmem_max`, and the negotiation silently settles on something that then fails | The ceiling is read back from the granted `SO_SNDBUF` rather than requested, on both sides, and the smaller wins. Step 2d sets a deliberately small `SO_SNDBUF` on the test peer and asserts the negotiation lands there and that reads still work |
| `instar-fetch` is built locally but missing from the packages, so it works for every developer and nobody else | Step 2b changes `build.sh` and both asset lists in one commit, and the definition of done greps the lists rather than trusting the step's report. Measured precedent: `src/build.sh` is package-scoped, so this failure is the default outcome if nobody acts |
| The client is written against a `BackingStore` signature that phase 3 then changes | Decision 7 pins it to today's signature, which the survey read off `src/vmm/src/backing.rs:104`. If phase 3 needs a different one, changing a type nothing in `src/vmm` yet uses is cheap -- which is also why step 2c is forbidden from touching `src/vmm` |
| An error the host cannot read hangs the guest (#932), and this phase adds new ways for the host to fail | Not this phase's to fix -- nothing here is wired into the VMM, so no new hang is reachable until phase 3. Step 2g records that phase 3 should fix #932 as part of its own work, before a remote source makes host-side failure ordinary rather than exotic |
| A new fuzz target exists but is never fuzzed in CI, silently | `tools/ci/check-fuzz-targets.sh` exists precisely for this and is a done criterion. Step 2e runs it and reports the exit code |

## Execution notes

Back brief answered 2026-11-19 (AEDT). Decisions taken there, and
departures from the plan as written, are recorded here as they
happen.

1. **The back brief confirmed decisions 8 and 10 unchanged.** A typed
   status enum and no free-form reason string on the wire, ever; and
   the fetcher inherits descriptors rather than taking a path. Both
   were offered with their alternatives and both were kept.
2. **Step 2d's end-to-end test is a Rust integration test**, under
   `src/crates/fetch-protocol/tests/`, rather than a Python module.
   The step's brief offered the choice; the operator settled it. This
   removes the `tools/ci/check-test-partition.sh` claim and the
   pull-request job wiring from the phase's scope entirely -- nothing
   in this phase touches `tests/` or `.github/workflows/` except the
   fuzz target's registration in step 2e.
3. **This session may push the branch and open the pull request** for
   this phase, granted in the back brief rather than asked for again
   at the end.
4. **`std` really cannot make a `SOCK_SEQPACKET` socket**, which the
   plan's survey could not confirm on the host. Step 2a established it
   by extracting the pinned toolchain's own standard-library source
   from the devcontainer image and reading
   `library/std/src/os/unix/net`: the only pair constructors are
   `SOCK_STREAM` and `SOCK_DGRAM`, and no exported type takes a socket
   type. It is now a test asserting `SO_TYPE` on both `std` pair
   constructors, so the day `std` grows the capability, that test is
   where it surfaces rather than a comment nobody rereads.
5. **Step 2a's socket module carries more than the bare constructor
   the brief asked for**, and it was kept deliberately: `send` with
   `MSG_NOSIGNAL` so a dead fetcher is an error rather than a
   `SIGPIPE` that kills the privileged process mid-operation; `recv`
   with `MSG_TRUNC` so an oversized datagram is detectable rather than
   silently truncated, which is the whole reason `SOCK_SEQPACKET` was
   chosen; buffer sizing, `max_datagram` and a receive timeout. Steps
   2b and 2c both need all of it, and decision 5's point is that the
   `unsafe` lives in one reviewed place rather than being written
   twice.
6. **The build-order rule is narrower than it looked.** `make instar`
   on a cold `src/target`, then `make test-rust`, then `make instar`
   again all succeed in this worktree. The ordering constraint applies
   to the first build on a cold tree, not to every alternation between
   the dev and release images, and no `clean-instar` was needed.

7. **This phase does touch `.github/workflows/release.yml` after
   all**, contrary to note 2. Step 2b found that the release
   workflow stages its tarball with `cp instar` and `cp *.bin`, so
   adding a host binary that is neither of those ships a tarball
   without it -- silently, and only visibly at release time. It is one
   line, it is a direct consequence of adding the binary, and
   deferring it to phase 3 means the tarball is wrong for however
   long phase 3 takes. Taken here. The class was swept rather than
   the instance fixed: the `.deb` list, the `.rpm` list, `build.sh`,
   the release tarball and `docs/installation.md` are the five places
   that enumerate what instar ships, and the first four now name the
   fetcher. The fifth is step 2f's, and it is wrong already for
   reasons that predate this plan -- it says the packages install
   "the six guest binaries" when there are seventeen.
8. **The plan's step 2b brief was wrong about the `.rpm` asset
   form.** It gave the same array form for both lists; the
   `generate-rpm` list is a list of objects with `source`, `dest` and
   `mode` keys, and `cargo-generate-rpm` does not accept the array
   form the `.deb` list uses. Step 2b used the right one and said so.
9. **The version-mismatch sentence was unified at source during
   review.** The shared error's wording named the two sides as "this
   build" and "the fetcher", which reads backwards on the fetcher's
   own stderr, and the step had worked around it by rendering that one
   case a second time in the fetcher. Since both ends link the same
   crate and a mismatch means the binaries came from different builds,
   the sentence now says "this build" and "the peer", reads correctly
   from either end, and the duplicate renderer is gone.

10. **A failed exchange now ends the client**, added during review of
    step 2c. The step's client reported a timeout, a socket error or an
    undecodable reply and left itself usable, with the request still
    owed an answer on the socket. Request ids make a stale reply
    detectable rather than silent -- it carries an older id than the one
    in flight -- but a half-finished conversation cannot be
    resynchronised without knowing how many answers are outstanding,
    which is the thing that was lost, and checking on every later read
    turns one failure into a run of misleading ones. The first failure
    now ends the client and the caller opens another. This matters more
    at phase 6, which puts several requests in flight and so loses the
    monotonic-id argument that makes the current behaviour merely
    noisy rather than wrong. Proved by one mutation: removing the flag
    makes `a_failed_exchange_ends_the_connection` fail.
11. **A reply timeout exists and phase 8 owns its value.** The client
    sets a 60-second default, which the plan did not ask for. A bound
    is right here even though phase 1 deliberately removed one from the
    guest: the guest waits on a host it trusts and cannot cancel a
    request, whereas this peer is untrusted and killable, so a fetcher
    that accepts a request and never answers would otherwise hang the
    privileged process for ever and defeat the partition. Sixty seconds
    is a placeholder rather than a policy; deadlines and caps are phase
    8's subject, and it should set this from the same policy as the
    rest.
12. **Step 2d's tests live in `src/fetch/tests/`, not in
    `src/crates/fetch-protocol/tests/`** as note 2 said. Both are Rust
    integration tests, so note 2's substance stands -- no Python module, no
    test-partition claim -- but the package matters:
    `env!("CARGO_BIN_EXE_instar-fetch")` is defined only for integration
    tests in the same package as the binary, so a test there is handed the
    exact path of the binary cargo built for it, and there is no case where
    the binary is absent to skip over. `src/fetch/tests/end_to_end.rs` is
    the end-to-end half (10 tests) and `src/fetch/tests/hostile_peer.rs`
    the adversarial half (7 tests); both run under
    `cargo test --release --workspace`.
13. **The negotiation really does follow the kernel's grant, measured both
    ways.** On this host a socket left alone is granted 212992 bytes, which
    is a 212960-byte datagram ceiling and a 212480-byte block; one asking
    for 4096 is granted 8192, which is an 8160-byte ceiling and a
    7680-byte block. Step 2d's small-buffer cases assert the relationship
    rather than those numbers -- the block equals
    `negotiate_block_size(granted, granted)` and is below both
    `DEFAULT_BLOCK_SIZE` and `MAX_BLOCK_SIZE` -- so neither the 64 KiB
    default nor the 256 KiB ceiling can satisfy them, and a read several
    times that block still comes back byte-identical, which it can only do
    by splitting.

14. **`docs/installation.md` was wrong before this work and is now
    right.** It said the packages install "the six guest binaries";
    there are sixteen `.bin` files in each packaging asset list, and a
    stale comment above the `.deb` metadata in `src/vmm/Cargo.toml`
    repeated the same number. Both now say sixteen, and both name the
    host-side `instar-fetch` separately, with the page saying plainly
    that nothing invokes it yet. That closes the fifth and last place
    that enumerates what instar ships.
15. **The two ends were not symmetric about asking the kernel for a
    buffer, and it quietly lowered the ceiling.** Only the fetcher
    asked; the client measured whatever its end happened to be given.
    Since what a side can offer is its *granted* buffer, and the
    default grant is below the protocol's largest block, the
    negotiation could never have reached that block however much the
    fetcher asked for -- invisibly, because the block in use is far
    below either figure. Sizing now happens where the pair is made,
    which is also the right place: it keeps the choice with the
    socket's owner, so a test that deliberately shrinks a buffer to
    prove the negotiation follows the grant is not silently
    overridden. The first attempt at this fix put the request inside
    the client and did override that test, which is how step 2d's test
    earned its keep.
16. **The block size the code settled on was not the one the operator
    resolved**, which decision 6 now records. Step 2d's tests needed no
    change, because they assert against `negotiate_block_size` rather
    than against a number -- which is the reason that choice was worth
    making.

## Mutation results

Step 2d's tests are only worth their runtime if they fail when the thing
they describe stops working. Each of the three mutations below was applied
on its own to a scratch copy's original, the narrowed suite
(`cargo test --release --no-fail-fast -p instar-fetch -p fetch-protocol`)
was run against it, and the file was restored from the copy. All three were
killed, and in every case one of step 2d's own tests is among the failures
rather than only a pre-existing unit test.

| Mutation | The exact edit | Tests that failed |
|---|---|---|
| The read reply's length check stops refusing a claim past the negotiated maximum | In `ReadReply::decode` (`wire.rs`), delete the `if length > max_block { return Err(ProtocolError::LengthTooLarge { length, max: max_block }); }` block, leaving `let length = ...` followed directly by `let available = ...` | `hostile_peer::a_reply_claiming_more_than_the_negotiated_maximum_is_refused`, `wire::tests::length_past_the_negotiated_maximum_is_refused` |
| The client stops matching a reply to the request in flight by id | In `FetchClient::read_block` (`client.rs`), delete the whole `if header.id != id { ... }` block | `hostile_peer::a_reply_replayed_from_an_earlier_block_is_refused`, `client::tests::reply_with_an_unrequested_id_is_an_error`, `client::tests::a_failed_exchange_ends_the_connection` |
| The block-size clamp stops following the granted socket buffer | In `InitReply::accepted_block_size` (`wire.rs`), change `if self.block_size > ours {` to `if self.block_size > MAX_BLOCK_SIZE {`, so the proposal is judged against the protocol's constant ceiling instead of what this side's socket was actually granted | `hostile_peer::a_peer_advertising_a_block_this_side_cannot_carry_is_refused`, `wire::tests::a_greedy_peer_block_size_is_clamped_to_what_this_side_can_carry` |

The third mutation is the one worth reading twice: it leaves every unit test
that uses a default-sized socket passing, because a 64 KiB proposal is
inside the constant ceiling. Only a test that shrinks its own socket buffer
and then watches where the negotiation lands can see it, which is why the
small-buffer cases exist in both halves.

## Definition of done

Each item is falsifiable; the management session checks them before
the push.

1. `make instar` produces `src/target/release/instar-fetch`, and
   `grep -c 'instar-fetch' src/vmm/Cargo.toml` is 2 -- one row in the
   `.deb` asset list and one in the `.rpm` one, both at mode 755.
2. `grep -n 'instar-fetch' src/build.sh` shows both a build block and
   a line in the closing summary.
3. Unit tests assert `size_of` and every field offset of all four
   header structs, and `docs/crates/fetch-protocol.md` states the
   same numbers. A script or a grep confirms the numbers in the page
   appear in the tests.
4. Every malformed shape in step 2a's list decodes to a typed error:
   one test per shape, named for the shape.
5. `tools/ci/check-fuzz-targets.sh` exits 0, and
   `fuzz_fetch_protocol` appears in all three lists and in
   `docs/testing.md`.
6. The end-to-end test reads a file through the real binary and
   compares against `pread`, and it **runs** rather than skipping:
   its "Ran: N" line (Python) or test count (Rust) is recorded in
   this plan's execution notes.
7. Three mutations recorded in `## Mutation results`, each naming the
   test that caught it: the read-reply length check, the client's id
   match, and the negotiated-maximum clamp.
8. `grep -rn 'TcpStream\|TcpListener\|to_socket_addrs\|https\?://'
   src/crates/fetch-protocol/src src/fetch/src` finds nothing outside
   comments: there is no network code in this phase.
9. `cargo tree -p instar` names no third-party crate it does not name
   on `develop` at `a8387ffe`.
10. The negotiation test proves the ceiling comes from the granted
    `SO_SNDBUF`: with a small buffer set on the test peer, the
    negotiated block size is the small value and reads larger than it
    still succeed by splitting.
11. `git diff origin/develop...HEAD -- src/ docs/ tests/ .github/ |
    grep -nE 'PLAN-|[Pp]hase [0-9]|step 2[a-g]'` prints nothing.
12. `pre-commit run --all-files` exits 0, `make test-rust` passes with
    its count recorded here, and any Python module this phase adds or
    touches passes with its "Ran: N" line read rather than its exit
    code trusted.

## Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.

Three gates, all of them cheap to agree and expensive to redo once
tests assert on them:

1. **The header layout and the status vocabulary**, agreed at the end
   of step 2a before 2b and 2c build on them. Decision 8's refusal of
   a reason string is the one to argue about if it is going to be
   argued about, and the time for that is before the fetcher has a
   diagnostic path.
2. **Decision 10**, the fetcher taking descriptor numbers rather than
   a path, agreed before step 2b. It shapes phase 4's sandbox and
   phase 5's CLI, and it is the decision a reviewer is most likely to
   find surprising.
3. **Where step 2d's end-to-end test lives** -- a Rust integration
   test or a claimed Python module -- since a new Python module drags
   in the test-partition claim and the CI job that runs it.
