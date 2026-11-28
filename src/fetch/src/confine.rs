//! What the fetcher does to itself once it is running, and why it cannot be
//! done any earlier.
//!
//! The privileged side sets the half of the policy that only a parent can
//! set, between the `fork` and the `exec`: the resource limits, and the
//! promise that no `exec` of this process's could gain privilege. A
//! filesystem denial cannot go there. A ruleset that handles every
//! filesystem access and permits none is exactly what this process wants,
//! and installing it before the `exec` denies the loader the fetcher binary
//! itself, so the `exec` fails `EACCES`. The only way to have a policy that
//! permits nothing is to apply it after the loader has finished, which means
//! the process applies it to itself.
//!
//! That works because a Landlock domain binds paths rather than open files:
//! a descriptor the parent passed goes on being readable with `pread` after
//! the policy is in force, while `open` of the very same path fails
//! `EACCES`. The fetcher is handed its socket and its image and opens
//! nothing afterwards, so an empty ruleset costs it nothing and leaves it
//! with no reachable path at all.
//!
//! # The calls it keeps
//!
//! Denying every path still leaves a process that could ask the kernel for
//! anything else: a socket of its own, a connection, a signal to the process
//! that spawned it. So the last thing this process does before it reads from
//! its peer is install a filter that allows the syscalls its serving loop was
//! measured to make and kills the process on any other. It can go on sending
//! and receiving, because that is its whole job, and that is harmless for a
//! reason outside the calls themselves: every call that makes a descriptor is
//! denied, so the only descriptors a send can ever name are the ones the
//! parent passed.
//!
//! The filter goes on last because it denies what the other steps need: the
//! filesystem policy is built with syscalls no serving loop makes, and they
//! are not on the list. After it, the only way to change this process's
//! confinement is to end the process.
//!
//! The two layers are not independent. The ruleset handles filesystem access
//! only, and not the network and scope masks later Landlock ABIs add, because
//! everything those would deny -- a socket, a connection, a signal to the
//! parent -- the filter denies already. A fetcher given Landlock without the
//! filter therefore gets the weaker of the two policies: no reachable path,
//! with the network and signals still open to it. Every kernel whose Landlock
//! knows the network mask also has the seccomp kill action, so that pairing
//! arises only where something between instar and the kernel hides the
//! action, such as a container profile that denies `seccomp(2)`; the
//! privileged side's `--verbose` lines say which layers a run got.
//!
//! # Being told rather than deciding
//!
//! Which layers to apply is not this process's choice. The privileged side
//! asks the running kernel what it can provide and names the answer on the
//! command line; this process applies exactly what it was named and fails
//! before it reads a byte from the peer if it cannot apply one of them. A
//! process that is assumed hostile choosing how confined to be would not be
//! a sandbox, and a layer that was asked for and quietly missing is the
//! failure a sandbox is most likely to have and least likely to show.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// The filter below compares syscall numbers and an architecture word, and
// both are facts about one instruction set. Another one has other numbers and
// makes other calls for the same work, so the list would have to be measured
// again there rather than recompiled.
#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "the fetcher's syscall policy is written for x86_64: its numbers and the calls it was \
     measured making are that architecture's, and have to be measured again for another"
);

/// The flag the privileged side names the confinement layers with.
pub const CONFINE_FLAG: &str = "--confine=";

/// The layer that leaves this process no reachable path.
const LAYER_LANDLOCK: &str = "landlock";

/// The layer that leaves this process only the syscalls it serves with.
const LAYER_SECCOMP: &str = "seccomp";

/// What the list says when the kernel can provide no layer at all.
const LAYER_NONE: &str = "none";

/// `landlock_create_ruleset`'s version query flag.
///
/// With a null attribute pointer and a zero size it is a question rather
/// than a creation: the kernel answers with the Landlock ABI it implements,
/// allocates nothing and returns no descriptor.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

// The filesystem accesses the first Landlock ABI knows how to handle, each
// one named rather than folded into a single mask: this is the policy, so a
// missing bit is an action the fetcher would be left able to perform, and a
// reviewer has to be able to check the list against the kernel's own
// `LANDLOCK_ACCESS_FS_*`. The numbering is a published interface and cannot
// change.

/// Execute a file.
const ACCESS_FS_EXECUTE: u64 = 1 << 0;

/// Open a file for writing.
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;

/// Open a file for reading.
const ACCESS_FS_READ_FILE: u64 = 1 << 2;

/// Open a directory or list its contents.
const ACCESS_FS_READ_DIR: u64 = 1 << 3;

/// Remove or rename a directory.
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;

/// Unlink or rename a file.
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;

/// Make a character device.
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;

/// Make a directory.
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;

/// Make a regular file.
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;

/// Make a unix socket.
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;

/// Make a fifo.
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;

/// Make a block device.
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;

/// Make a symbolic link.
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// Reparent a file hierarchy. Known from the second Landlock ABI.
const ACCESS_FS_REFER: u64 = 1 << 13;

/// Truncate a file. Known from the third Landlock ABI.
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// `ioctl` a character or block device. Known from the fifth Landlock ABI.
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// The Landlock ABI that first knows [`ACCESS_FS_REFER`].
const ABI_WITH_REFER: u32 = 2;

/// The Landlock ABI that first knows [`ACCESS_FS_TRUNCATE`].
const ABI_WITH_TRUNCATE: u32 = 3;

/// The Landlock ABI that first knows [`ACCESS_FS_IOCTL_DEV`].
const ABI_WITH_IOCTL_DEV: u32 = 5;

/// The ruleset definition `landlock_create_ruleset` takes.
///
/// Later Landlock ABIs add a network mask and a scope mask after this field,
/// and the kernel accepts any prefix of the structure it knows, down to this
/// one field. Only the filesystem mask is sent, so the size passed is the
/// size of this type and is valid on every ABI: the network and scope
/// policies are not this layer's business, and what they would deny is
/// denied outright by the syscall policy instead.
#[repr(C)]
struct RulesetAttr {
    /// The filesystem actions the ruleset handles.
    handled_access_fs: u64,
}

/// The architecture word the kernel shows a filter for a native 64-bit x86
/// syscall: `AUDIT_ARCH_X86_64`, which is the ELF machine number for x86_64
/// with the 64-bit and little-endian flags set. `libc` does not export it.
/// It is a published interface and cannot change.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// Where a filter finds the syscall number in the record the kernel shows
/// it.
const SECCOMP_DATA_NR: u32 = 0;

/// Where a filter finds the architecture word in that record.
const SECCOMP_DATA_ARCH: u32 = 4;

// The two offsets are written out because a filter instruction carries one
// as a 32-bit immediate, and checked against the structure they index so
// that neither can be a number somebody remembered.
const _: () = assert!(std::mem::offset_of!(libc::seccomp_data, nr) == SECCOMP_DATA_NR as usize);
const _: () = assert!(std::mem::offset_of!(libc::seccomp_data, arch) == SECCOMP_DATA_ARCH as usize);

/// Load a 32-bit word of the kernel's record into the filter's accumulator.
const BPF_LOAD_WORD: u16 = opcode(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);

/// Skip `jt` instructions if the accumulator equals the immediate, and `jf`
/// if it does not.
const BPF_JUMP_IF_EQUAL: u16 = opcode(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);

/// End the filter with the immediate as its verdict.
const BPF_RETURN: u16 = opcode(libc::BPF_RET | libc::BPF_K);

/// Narrow one of `libc`'s instruction codes to the width an instruction
/// stores it in, refusing at build time one that would not fit.
const fn opcode(code: u32) -> u16 {
    assert!(code <= u16::MAX as u32);
    code as u16
}

/// A syscall number as a filter compares it.
///
/// Refused at build time unless it is a plain native number. The x32 ABI
/// reaches the same kernel entry point with the same architecture word and a
/// high bit set in the number, so a list holding only plain numbers is a list
/// no x32 call can match, and the filter kills those without having to name
/// them.
const fn syscall(nr: libc::c_long) -> u32 {
    assert!(nr >= 0 && nr < X32_SYSCALL_BIT);
    nr as u32
}

/// The bit that marks a syscall number as the x32 ABI's.
const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;

/// The syscalls one backend may make once it is serving.
///
/// One policy for each backend rather than one for the fetcher, so that a
/// backend with different needs brings a list of its own instead of widening
/// this one and quietly loosening every other backend with it.
///
/// The two lists are kept apart because they are two different kinds of
/// claim. The first is what was seen; the second is what was not seen and is
/// allowed anyway, and a reader has to be able to tell at a glance which of
/// the two an entry is.
struct SyscallPolicy {
    /// The calls this backend was measured making.
    measured: &'static [u32],
    /// The calls it was never seen making, allowed as insurance.
    margin: &'static [u32],
}

/// The policy for a fetcher serving an already-open file.
const FILE_SOURCE_POLICY: SyscallPolicy = SyscallPolicy {
    measured: &FILE_SOURCE_MEASURED,
    margin: &FILE_SOURCE_MARGIN,
};

/// What a fetcher serving a file was measured making, from the first datagram
/// it receives to the end of the process.
///
/// Read off `strace -ff` of the release binary rather than off the source,
/// because the C library chooses some of these and the source does not say
/// which: over a real `instar info` of a `file://` URL, and over a peer that
/// refuses to play fair -- malformed inits, malformed requests, an image
/// truncated under the fetcher, an image that cannot be read, a peer that
/// leaves with replies unread, and a stderr that has gone away.
const FILE_SOURCE_MEASURED: [u32; 11] = [
    // The serving loop: a request in, bytes read from the image at an
    // offset, a reply out. `recv` and `send` have no syscalls of their own
    // on this architecture; the C library issues these two.
    syscall(libc::SYS_recvfrom),
    syscall(libc::SYS_pread64),
    syscall(libc::SYS_sendto),
    // Every diagnostic, one piece of a line at a time, on stderr.
    syscall(libc::SYS_write),
    // The image and the socket, dropped on the way out of `serve`. Without
    // it a run that went perfectly would end in a signal instead of a zero.
    syscall(libc::SYS_close),
    // How the process ends, whatever status it ends with.
    syscall(libc::SYS_exit_group),
    // The allocator, which the loop reaches on every request for the reply
    // it builds. The heap grows and shrinks with `brk` as the C library
    // ships; the other two were seen only with the caller's environment
    // lowering the size at which an allocation gets a mapping of its own,
    // and the fetcher inherits that environment.
    syscall(libc::SYS_brk),
    syscall(libc::SYS_mmap),
    syscall(libc::SYS_munmap),
    // A panic, seen by taking stderr away under a diagnostic: the runtime
    // asks for its thread id to name the thread in its message, and makes
    // one futex wake on its way to the exit. With these the process ends as
    // a panic does, with its own exit status; without them a bug in this
    // process would read to the privileged side as a violation of this
    // policy.
    syscall(libc::SYS_gettid),
    syscall(libc::SYS_futex),
];

/// What a fetcher serving a file was never seen making, and may make anyway.
///
/// The binary runs against whatever C library the machine it is installed on
/// has, and that is not the one it was measured with. A call missing from
/// this filter is a fetcher killed on somebody else's distribution, which is
/// a far worse failure than a list a little longer than it had to be -- so
/// each entry here is a call an allocator, a runtime or the kernel itself can
/// reach for in the course of the same work, and none of them gives a process
/// anything it did not already have. What makes this policy worth having is
/// what is on neither list.
const FILE_SOURCE_MARGIN: [u32; 10] = [
    // Allocators other than the measured one: growing a mapping in place
    // rather than replacing it, handing pages back without unmapping them,
    // and changing a mapping's protection -- a heap reserved inaccessible
    // and opened up as it grows, or a guard page.
    syscall(libc::SYS_mremap),
    syscall(libc::SYS_madvise),
    syscall(libc::SYS_mprotect),
    // A diagnostic written in pieces by a runtime that gathers them into one
    // vectored write rather than one `write` each. It reaches the same
    // descriptors `write` already does.
    syscall(libc::SYS_writev),
    // An allocator or a hasher seeding itself, and a clock read on a machine
    // whose kernel cannot answer it without a syscall. A C library that finds
    // `getrandom` missing falls back to opening `/dev/urandom`, which is a
    // kill here; that needs a kernel older than 3.17, where nothing else in
    // this file would work either, so the entry is for the libraries that
    // call it rather than a promise about the ones that cannot.
    syscall(libc::SYS_getrandom),
    syscall(libc::SYS_clock_gettime),
    // Returning from a signal handler. Nothing here handles a signal and
    // carries on, but a library the caller's environment preloads may, and
    // a handler that cannot return is a process that cannot survive one.
    syscall(libc::SYS_rt_sigreturn),
    // Not a call any library chooses: the kernel substitutes it for an
    // interrupted wait that had a timeout when a stopped process is
    // continued. It can only resume a call that was allowed to begin with.
    syscall(libc::SYS_restart_syscall),
    // The runtime on its way out. The one measured goes straight to the
    // exit. One that first took down the alternate stack its fault handler
    // runs on would make the first of these, and a C library that
    // unregistered the thread's restartable-sequence area the second.
    syscall(libc::SYS_sigaltstack),
    syscall(libc::SYS_rseq),
];

/// How many instructions a filter spends before the first comparison: load
/// the architecture, compare it, kill on a mismatch, load the number.
const FILTER_PREAMBLE: usize = 4;

/// How many it spends after the last: the kill, and the allow every match
/// jumps to.
const FILTER_VERDICTS: usize = 2;

/// The longest filter this file can build.
///
/// A fixed size so that the filter lives on the stack: it is built in the
/// one place a failure must still be reportable, and in the tests it is
/// built in a forked child that must not allocate.
const FILTER_CAPACITY: usize = 48;

// A jump is an 8-bit count of instructions to skip, so a policy that needed
// a longer filter than this would not merely overflow the array.
const _: () = assert!(FILTER_CAPACITY <= u8::MAX as usize);
const _: () = assert!(
    FILTER_PREAMBLE
        + FILE_SOURCE_POLICY.measured.len()
        + FILE_SOURCE_POLICY.margin.len()
        + FILTER_VERDICTS
        <= FILTER_CAPACITY
);

/// A syscall filter, as the kernel takes it.
struct Filter {
    /// The program. Instructions past `len` are never run, and are kills
    /// rather than zeroes so that being wrong about that could not allow
    /// anything.
    instructions: [libc::sock_filter; FILTER_CAPACITY],
    /// How many of them are the program.
    len: u16,
}

impl Filter {
    /// The filter that allows exactly the calls `policy` lists and kills the
    /// process on any other.
    ///
    /// The architecture is checked before the number, because a number means
    /// nothing without it: the 32-bit entry point on the same kernel numbers
    /// its calls differently, and what is `write` here is `exit` there. A
    /// call made any other way than natively is killed whatever its number.
    fn allowing(policy: &SyscallPolicy) -> io::Result<Filter> {
        let kill = instruction(BPF_RETURN, 0, 0, libc::SECCOMP_RET_KILL_PROCESS);
        let mut instructions = [kill; FILTER_CAPACITY];
        let allowed = policy.measured.len() + policy.margin.len();
        let len = FILTER_PREAMBLE + allowed + FILTER_VERDICTS;
        if len > FILTER_CAPACITY {
            return Err(io::Error::other(format!(
                "a {LAYER_SECCOMP} policy of {allowed} calls needs a longer filter than the \
                 {FILTER_CAPACITY} instructions there is room for"
            )));
        }

        instructions[0] = instruction(BPF_LOAD_WORD, 0, 0, SECCOMP_DATA_ARCH);
        // Native: step over the kill. Anything else falls into it.
        instructions[1] = instruction(BPF_JUMP_IF_EQUAL, 1, 0, AUDIT_ARCH_X86_64);
        instructions[2] = kill;
        instructions[3] = instruction(BPF_LOAD_WORD, 0, 0, SECCOMP_DATA_NR);
        for (index, nr) in policy.measured.iter().chain(policy.margin).enumerate() {
            // A match skips every comparison still to come and the kill
            // after them, and lands on the allow. A miss falls through to
            // the next comparison, and the last miss falls into the kill.
            let to_the_allow = u8::try_from(allowed - index).map_err(|_| {
                io::Error::other(format!(
                    "a {LAYER_SECCOMP} policy of {allowed} calls is longer than a filter can \
                     jump across"
                ))
            })?;
            instructions[FILTER_PREAMBLE + index] =
                instruction(BPF_JUMP_IF_EQUAL, to_the_allow, 0, *nr);
        }
        instructions[FILTER_PREAMBLE + allowed] = kill;
        instructions[FILTER_PREAMBLE + allowed + 1] =
            instruction(BPF_RETURN, 0, 0, libc::SECCOMP_RET_ALLOW);

        let len = u16::try_from(len).map_err(|_| {
            io::Error::other(format!(
                "a {LAYER_SECCOMP} filter of {len} instructions is longer than the kernel takes"
            ))
        })?;
        Ok(Filter { instructions, len })
    }
}

/// One filter instruction.
const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Which confinement layers the privileged side asked for.
///
/// Parsed from the command line rather than decided here, and carried as far
/// as the one place that applies it, so that the asking and the applying are
/// visibly the same list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confinement {
    /// Whether the filesystem policy was asked for.
    landlock: bool,
    /// Whether the syscall policy was asked for.
    seccomp: bool,
}

impl Confinement {
    /// Nothing was asked for.
    ///
    /// What a command line without the flag means. The privileged side always
    /// sends the flag, and sends `none` where the kernel can provide nothing,
    /// so this is the shape of a fetcher run by hand rather than of anything
    /// instar spawns.
    pub const NOTHING: Confinement = Confinement {
        landlock: false,
        seccomp: false,
    };

    /// Read the comma-separated list the flag carries.
    ///
    /// An unknown token is refused by name rather than ignored. Ignoring one
    /// would mean a privileged side that asked for a layer this build does
    /// not have got a fetcher that was not confined by it and said nothing,
    /// which is precisely the silence this whole arrangement exists to make
    /// impossible.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut asked = Confinement::NOTHING;
        let mut nothing_asked = false;
        for token in list.split(',') {
            match token {
                LAYER_LANDLOCK => asked.landlock = true,
                LAYER_SECCOMP => asked.seccomp = true,
                LAYER_NONE => nothing_asked = true,
                "" => {
                    return Err(format!(
                        "{CONFINE_FLAG} carries an empty layer name in {list:?}; a run that asks \
                         for no confinement says so with {LAYER_NONE:?}"
                    ))
                }
                unknown => {
                    return Err(format!(
                        "{CONFINE_FLAG} names {unknown:?}, which is not a confinement layer this \
                         process knows"
                    ))
                }
            }
        }
        if nothing_asked && asked != Confinement::NOTHING {
            return Err(format!(
                "{CONFINE_FLAG} asks for {LAYER_NONE:?} and for a layer as well, in {list:?}, and \
                 those cannot both be what was meant"
            ));
        }
        Ok(asked)
    }

    /// Apply every layer that was asked for.
    ///
    /// `Err` is the whole point of the return type: the caller turns it into
    /// a non-zero exit before the init exchange, so a layer that was asked
    /// for and could not be applied ends the run instead of weakening it.
    pub fn apply(&self) -> io::Result<()> {
        if self.landlock {
            restrict_filesystem(landlock_abi())?;
        }
        // Last, and it cannot be otherwise: the filter allows only what the
        // serving loop does, which is none of what the step above did, so
        // anything this function still had to do after it would be a call
        // the filter kills this process for.
        if self.seccomp {
            restrict_syscalls(&FILE_SOURCE_POLICY, kill_process_available())?;
        }
        Ok(())
    }
}

/// Leave this process no reachable path.
///
/// `abi` is what the running kernel answered, and `None` means it has no
/// Landlock at all, which is a failure here rather than a shrug: this
/// function is only called because the privileged side named the layer, and
/// it only names layers its own probe of the same kernel found.
fn restrict_filesystem(abi: Option<u32>) -> io::Result<()> {
    let Some(abi) = abi else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "this process was asked to apply the {LAYER_LANDLOCK} policy and this kernel has \
                 no {LAYER_LANDLOCK}"
            ),
        ));
    };
    let attr = RulesetAttr {
        handled_access_fs: handled_access_fs(abi),
    };

    // SAFETY: landlock_create_ruleset has no glibc wrapper, so it is reached
    // through syscall(2). The kernel reads the one u64 the attribute pointer
    // points at -- a local that outlives the call -- for the length given,
    // which is that local's own size; it writes nothing back, and the result
    // is checked below before it is treated as a descriptor.
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::addr_of!(attr),
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    };
    if ruleset < 0 {
        return Err(io::Error::other(format!(
            "building the {LAYER_LANDLOCK} ruleset for ABI {abi} failed: {}",
            io::Error::last_os_error()
        )));
    }
    let ruleset = RawFd::try_from(ruleset).map_err(|_| {
        io::Error::other(format!(
            "building the {LAYER_LANDLOCK} ruleset answered {ruleset}, which is not a descriptor"
        ))
    })?;
    // SAFETY: the syscall above returned this descriptor and nothing else has
    // seen it, so this is its only owner. Owning it is what closes it: the
    // ruleset is consumed by the call below and the fetcher's descriptor set
    // is accounted for, so it must not be left open.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset) };

    // Already set by the parent before the exec, and set again here because
    // this process cannot be left trusting that it was: without it an
    // unprivileged process cannot restrict itself at all, and a fetcher that
    // skipped the policy because a caller had not set a flag for it would be
    // the silent failure this is all built to prevent. Setting it twice is
    // free, and it can never be unset.
    //
    // SAFETY: PR_SET_NO_NEW_PRIVS takes its argument by value, reads no
    // pointer and affects only this process; the result is checked.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::other(format!(
            "promising this process can gain no privilege failed: {}",
            io::Error::last_os_error()
        )));
    }

    // SAFETY: landlock_restrict_self has no glibc wrapper either. It reads no
    // pointer: its arguments are the ruleset descriptor, which this process
    // owns and which outlives the call, and a zero flags word. It changes
    // nothing but this process's own domain, and the result is checked.
    let restricted =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) };
    if restricted < 0 {
        return Err(io::Error::other(format!(
            "applying the {LAYER_LANDLOCK} policy failed: {}",
            io::Error::last_os_error()
        )));
    }
    // The domain is this process's own from here on, and the descriptor that
    // described it is of no further use to anyone.
    drop(ruleset);
    Ok(())
}

/// The filesystem actions a ruleset may handle on the ABI the kernel reports.
///
/// Derived from the ABI rather than from a constant because a mask naming an
/// access the running kernel does not know is refused outright, not narrowed:
/// a fetcher that asked for the newest mask on an older kernel would get
/// `EINVAL` and no policy whatsoever. A kernel newer than this build gets
/// this build's whole mask, which is every access it knows how to deny.
fn handled_access_fs(abi: u32) -> u64 {
    let mut handled = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM;
    if abi >= ABI_WITH_REFER {
        handled |= ACCESS_FS_REFER;
    }
    if abi >= ABI_WITH_TRUNCATE {
        handled |= ACCESS_FS_TRUNCATE;
    }
    if abi >= ABI_WITH_IOCTL_DEV {
        handled |= ACCESS_FS_IOCTL_DEV;
    }
    handled
}

/// The Landlock ABI the running kernel implements, or `None` if it has none.
///
/// Asked here as well as on the privileged side, rather than passed across,
/// because the answer this process needs is a mask it has to build from its
/// own kernel's answer, and a number handed to it on a command line is a
/// number it would have to trust.
fn landlock_abi() -> Option<u32> {
    // SAFETY: the version query is landlock_create_ruleset with a null
    // attribute pointer, a zero size and the version flag. In that form the
    // kernel reads nothing through the pointer, creates no ruleset and
    // returns the ABI version; the result is checked before it is used.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    u32::try_from(abi).ok().filter(|abi| *abi > 0)
}

/// Leave this process only the syscalls `policy` lists.
///
/// `kill_available` is what the running kernel answered when asked whether
/// it can end a process for a violation. Without that, the same filter would
/// install and mean something weaker -- an older kernel reads a verdict it
/// does not know as the death of one thread -- so it is a failure here rather
/// than a policy that is not the one that was asked for. As with the
/// filesystem policy, this is only called because the privileged side named
/// the layer, and it names only what its own probe of the same kernel found.
fn restrict_syscalls(policy: &SyscallPolicy, kill_available: bool) -> io::Result<()> {
    if !kill_available {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "this process was asked to apply the {LAYER_SECCOMP} policy and this kernel \
                 cannot kill a process that breaks one"
            ),
        ));
    }
    let mut filter = Filter::allowing(policy)?;
    let program = libc::sock_fprog {
        len: filter.len,
        filter: filter.instructions.as_mut_ptr(),
    };

    // Set again for the reason the filesystem policy sets it again: an
    // unprivileged process may not install a filter without it, and this
    // process is not going to trust that somebody else set it.
    //
    // SAFETY: PR_SET_NO_NEW_PRIVS takes its argument by value, reads no
    // pointer and affects only this process; the result is checked.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::other(format!(
            "promising this process can gain no privilege failed: {}",
            io::Error::last_os_error()
        )));
    }

    // SAFETY: PR_SET_SECCOMP in filter mode reads the program header its
    // third argument points at, and through it `len` instructions. Both are
    // locals that outlive the call: the header's pointer is into `filter`,
    // which holds at least `len` instructions because `Filter::allowing`
    // built both from one count. The kernel copies the program and keeps no
    // pointer into this process. The mode is widened to the word the kernel
    // reads it as, since a variadic call would otherwise pass it as a
    // narrower one. The result is checked.
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            std::ptr::addr_of!(program),
        )
    };
    if installed < 0 {
        return Err(io::Error::other(format!(
            "applying the {LAYER_SECCOMP} policy failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Whether the running kernel can kill a process that breaks a syscall
/// policy.
///
/// Asked here as well as on the privileged side for the same reason the
/// filesystem ABI is: the answer decides what this process does, and an
/// answer handed to it is one it would have to trust. The question installs
/// nothing and changes nothing about the caller.
fn kill_process_available() -> bool {
    let action = libc::SECCOMP_RET_KILL_PROCESS;
    // SAFETY: seccomp(2) has no glibc wrapper, so it is reached through
    // syscall(2). The action-availability operation reads the one u32 its
    // third argument points at -- a local that outlives the call -- and
    // writes nothing; it returns 0 when the kernel has the action and -1
    // when it does not, or has no seccomp at all.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_ACTION_AVAIL,
            0_usize,
            std::ptr::addr_of!(action),
        )
    };
    ret == 0
}

#[cfg(test)]
mod tests;
