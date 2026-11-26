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
const FILE_SOURCE_MARGIN: [u32; 8] = [
    // Allocators other than the measured one: growing a mapping in place
    // rather than replacing it, and handing pages back without unmapping
    // them.
    syscall(libc::SYS_mremap),
    syscall(libc::SYS_madvise),
    // An allocator or a hasher seeding itself, and a clock read on a machine
    // whose kernel cannot answer it without a syscall.
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
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::fs::File;
    use std::os::unix::net::UnixDatagram;
    use std::time::{Duration, Instant};

    use fetch_protocol::SeqPacketSocket;
    use tempfile::tempdir;

    /// Turns a kernel without Landlock from a weaker test into a failure.
    ///
    /// Without it, a run on such a kernel asserts the refusal instead -- the
    /// behaviour that kernel is owed -- which is a real assertion but not the
    /// one that proves the policy bites. Setting it says the caller expects
    /// the strong form, so the weak one is a failure rather than a quiet
    /// substitution.
    const REQUIRE_LANDLOCK: &str = "INSTAR_REQUIRE_LANDLOCK";

    /// Turns a kernel that cannot kill on a syscall violation from a weaker
    /// test into a failure, in the same way and for the same reason: on such
    /// a kernel the tests below assert that a fetcher asked for the policy
    /// refuses to run, which is true and is not the proof that the policy
    /// bites.
    const REQUIRE_SECCOMP: &str = "INSTAR_REQUIRE_SECCOMP";

    /// The architecture word of a call made through the 32-bit entry point of
    /// the same kernel: `AUDIT_ARCH_I386`.
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;

    /// Where in the probe's file the byte it reads lives, chosen off zero so
    /// that a `pread` that ignored its offset would read a different byte.
    const PROBE_OFFSET: i64 = 11;

    /// The byte the probe expects to find there.
    const PROBE_BYTE: u8 = 0xA5;

    /// How long a probe child is given before it is killed and the test
    /// fails. Generous, because the suite runs one thread per core, and
    /// finite, because a test that hangs tells nobody anything.
    const PROBE_BUDGET: Duration = Duration::from_secs(30);

    /// How often the parent looks to see whether the probe has finished.
    const PROBE_POLL: Duration = Duration::from_millis(5);

    /// The probe applied the policy, read its descriptor and then opened the
    /// path: whatever the policy was, it did not deny the path.
    const PROBE_OPENED_THE_PATH: i32 = 20;

    /// The probe was denied the path, which is what the policy exists to do.
    const PROBE_DENIED_THE_PATH: i32 = 21;

    /// The probe was refused the path for some other reason than the policy,
    /// which would make a passing denial test prove the wrong thing.
    const PROBE_REFUSED_THE_PATH: i32 = 22;

    /// The probe could not apply the confinement it was given.
    const PROBE_POLICY_FAILED: i32 = 10;

    /// The probe's inherited descriptor stopped answering `pread`, which is
    /// the property the fetcher depends on and the policy must not cost it.
    const PROBE_PREAD_FAILED: i32 = 11;

    /// The inherited descriptor answered with bytes that are not the file's.
    const PROBE_PREAD_WRONG: i32 = 12;

    /// The probe made the one call it was sent to make, and the kernel
    /// carried it out.
    const PROBE_CALL_SUCCEEDED: i32 = 30;

    /// The probe made the call and the kernel returned an error, which is
    /// neither the policy killing it nor the call working, and would make
    /// either test prove the wrong thing.
    const PROBE_CALL_FAILED: i32 = 31;

    /// The probe did everything the serving loop does and reached the end.
    const PROBE_SERVED: i32 = 40;

    /// The first of the statuses that say which of the serving loop's calls
    /// came back wrong; the step's number is added to it.
    const PROBE_SERVING_STEP_FAILED: i32 = 41;

    /// How a probe child ended.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Ended {
        /// It exited, with this status.
        Exited(i32),
        /// It was killed, by this signal.
        Killed(i32),
    }

    /// A call that would get a confined fetcher something its parent never
    /// handed it.
    ///
    /// These are what the syscall policy is for. The fetcher may go on
    /// sending and receiving, and that is safe only while it can make no
    /// descriptor of its own to send on and open no path to read.
    #[derive(Clone, Copy, Debug)]
    enum Reach {
        /// Make a socket.
        Socket,
        /// Make a connected pair of sockets.
        Socketpair,
        /// Connect a socket it already holds to an address.
        Connect,
        /// Give a socket it already holds an address.
        Bind,
        /// Open a path the way the C library opens one.
        Openat,
        /// Open a path with the older call that takes no directory, which no
        /// library here makes and which would be the same hole.
        Open,
    }

    /// Every [`Reach`], so that a test cannot quietly cover some of them.
    const EVERY_REACH: [Reach; 6] = [
        Reach::Socket,
        Reach::Socketpair,
        Reach::Connect,
        Reach::Bind,
        Reach::Openat,
        Reach::Open,
    ];

    /// Apply `confinement` in a forked child holding an open descriptor, and
    /// report what the child made of its inherited descriptor and of the
    /// path that descriptor came from.
    ///
    /// A child rather than this process because the policy cannot be taken
    /// off again: a test that applied it here would confine the rest of the
    /// suite running in the same process. The answer comes back as an exit
    /// status rather than through a pipe because an exit status needs no
    /// descriptor, no read and no deadlock.
    fn probe(confinement: Confinement) -> i32 {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("probe.raw");
        let mut bytes = vec![0u8; 512];
        bytes[PROBE_OFFSET as usize] = PROBE_BYTE;
        std::fs::write(&path, &bytes).expect("a file for the probe to read");
        // Built before the fork, because building it in the child would
        // allocate, and a child of a multi-threaded process must not.
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).expect("a path without nul");
        let file = File::open(&path).expect("the probe's file opens before the policy");
        let fd = file.as_raw_fd();

        // SAFETY: fork(2) itself touches nothing of this process's state. The
        // child below calls only async-signal-safe libc functions and ends in
        // _exit, so it allocates nothing, takes no lock, runs no destructor
        // and never returns into the test harness. `confinement.apply` makes
        // syscalls and allocates only to format an error it is about to exit
        // on, and the parent's budget below is what covers even that.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: the child, as described above.
            unsafe {
                if confinement.apply().is_err() {
                    libc::_exit(PROBE_POLICY_FAILED);
                }
                let mut byte = 0u8;
                let read = libc::pread(fd, std::ptr::addr_of_mut!(byte).cast(), 1, PROBE_OFFSET);
                if read != 1 {
                    libc::_exit(PROBE_PREAD_FAILED);
                }
                if byte != PROBE_BYTE {
                    libc::_exit(PROBE_PREAD_WRONG);
                }
                let opened = libc::open(c_path.as_ptr(), libc::O_RDONLY);
                if opened >= 0 {
                    libc::_exit(PROBE_OPENED_THE_PATH);
                }
                if *libc::__errno_location() == libc::EACCES {
                    libc::_exit(PROBE_DENIED_THE_PATH);
                }
                libc::_exit(PROBE_REFUSED_THE_PATH);
            }
        }
        wait_for_probe(pid)
    }

    /// Wait for one probe that is expected to exit of its own accord, and
    /// render anything else as a failure rather than as a status code.
    fn wait_for_probe(pid: libc::pid_t) -> i32 {
        match wait_for_child(pid) {
            Ended::Exited(status) => status,
            Ended::Killed(signal) => {
                panic!("the probe did not exit of its own accord: killed by signal {signal}")
            }
        }
    }

    /// Wait for one probe, within a budget, and say how it ended.
    fn wait_for_child(pid: libc::pid_t) -> Ended {
        let deadline = Instant::now() + PROBE_BUDGET;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid writes the one int it is given, which is a
            // local, and reaps the child this function was handed.
            let waited =
                unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), libc::WNOHANG) };
            assert!(waited >= 0, "waitpid: {}", io::Error::last_os_error());
            if waited == pid {
                if libc::WIFEXITED(status) {
                    return Ended::Exited(libc::WEXITSTATUS(status));
                }
                assert!(
                    libc::WIFSIGNALED(status),
                    "the probe neither exited nor was killed: raw status {status:#x}"
                );
                return Ended::Killed(libc::WTERMSIG(status));
            }
            if Instant::now() >= deadline {
                // SAFETY: kill sends one signal to the child this function
                // owns; the subsequent blocking wait reaps it.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                panic!("the probe did not finish within {PROBE_BUDGET:?}");
            }
            std::thread::sleep(PROBE_POLL);
        }
    }

    /// Stop a probe that is about to be killed from leaving a core file.
    ///
    /// A policy violation is a signal that dumps core, and a probe sent to
    /// commit one would otherwise write a core into the source tree wherever
    /// the machine's core pattern says to. The real fetcher is spared this
    /// by its parent, which sets the same limit before the `exec`.
    ///
    /// # Safety
    ///
    /// For the forked child only: it makes one syscall on a local, allocates
    /// nothing and takes no lock.
    unsafe fn leave_no_core() {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the one structure it is given, which is a
        // local that outlives the call. A failure is not checked because
        // nothing depends on it but tidiness.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(none)) };
    }

    /// Apply `confinement` in a forked child and have it make `call`, and
    /// report how that ended.
    ///
    /// Everything the call needs is made before the fork, and so before the
    /// policy: the sockets `connect` and `bind` act on have to exist already,
    /// because making one is itself a call the policy denies, and the test
    /// is of each call rather than of the first one reached.
    fn reach(confinement: Confinement, call: Reach) -> Ended {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("probe.raw");
        std::fs::write(&path, [PROBE_BYTE]).expect("a file for the probe to open");
        // Built before the fork, because building it in the child would
        // allocate, and a child of a multi-threaded process must not.
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).expect("a path without nul");

        let listener = UnixDatagram::unbound().expect("a socket to connect to");
        let caller = UnixDatagram::unbound().expect("a socket to connect with");
        let unbound = UnixDatagram::unbound().expect("a socket to bind");
        let caller_fd = caller.as_raw_fd();
        let unbound_fd = unbound.as_raw_fd();

        // An address that is only a family asks the kernel to choose a name
        // in the abstract namespace: nothing to collide with between tests
        // running at once, and nothing left behind in a filesystem.
        let any_name = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
        let any_name_len = std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t;
        let mut listening_at = any_name;
        let mut listening_at_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: bind reads `any_name_len` bytes of a local address that
        // outlives the call. getsockname writes at most `listening_at_len`
        // bytes, which is the size of the local it writes into, and stores
        // the length it wrote in the other local. Both results are checked.
        unsafe {
            let bound = libc::bind(
                listener.as_raw_fd(),
                std::ptr::addr_of!(any_name).cast(),
                any_name_len,
            );
            assert_eq!(bound, 0, "bind: {}", io::Error::last_os_error());
            let named = libc::getsockname(
                listener.as_raw_fd(),
                std::ptr::addr_of_mut!(listening_at).cast(),
                std::ptr::addr_of_mut!(listening_at_len),
            );
            assert_eq!(named, 0, "getsockname: {}", io::Error::last_os_error());
        }

        // SAFETY: fork(2) itself touches nothing of this process's state. The
        // child below calls only async-signal-safe libc functions and ends in
        // _exit, so it allocates nothing, takes no lock, runs no destructor
        // and never returns into the test harness. `confinement.apply` makes
        // syscalls and allocates only to format an error it is about to exit
        // on, and the parent's budget is what covers even that.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: the child, as described above. Every pointer passed is
            // to a local or to the path built before the fork, each with the
            // length it is passed with, and all of them outlive the call.
            unsafe {
                leave_no_core();
                if confinement.apply().is_err() {
                    libc::_exit(PROBE_POLICY_FAILED);
                }
                let returned = match call {
                    Reach::Socket => {
                        libc::c_long::from(libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0))
                    }
                    Reach::Socketpair => {
                        let mut pair: [libc::c_int; 2] = [-1; 2];
                        libc::c_long::from(libc::socketpair(
                            libc::AF_UNIX,
                            libc::SOCK_SEQPACKET,
                            0,
                            pair.as_mut_ptr(),
                        ))
                    }
                    Reach::Connect => libc::c_long::from(libc::connect(
                        caller_fd,
                        std::ptr::addr_of!(listening_at).cast(),
                        listening_at_len,
                    )),
                    Reach::Bind => libc::c_long::from(libc::bind(
                        unbound_fd,
                        std::ptr::addr_of!(any_name).cast(),
                        any_name_len,
                    )),
                    Reach::Openat => libc::c_long::from(libc::openat(
                        libc::AT_FDCWD,
                        c_path.as_ptr(),
                        libc::O_RDONLY,
                    )),
                    Reach::Open => libc::syscall(libc::SYS_open, c_path.as_ptr(), libc::O_RDONLY),
                };
                libc::_exit(if returned >= 0 {
                    PROBE_CALL_SUCCEEDED
                } else {
                    PROBE_CALL_FAILED
                });
            }
        }
        wait_for_child(pid)
    }

    /// Apply `confinement` in a forked child and have it make each call the
    /// serving loop makes, in the order the loop makes them, and report how
    /// that ended.
    ///
    /// The other half of the denial tests: a policy that killed everything
    /// would pass every one of those.
    fn serve_under(confinement: Confinement) -> Ended {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("probe.raw");
        let mut bytes = vec![0u8; 512];
        bytes[PROBE_OFFSET as usize] = PROBE_BYTE;
        std::fs::write(&path, &bytes).expect("a file for the probe to read");
        let file = File::open(&path).expect("the probe's file opens before the policy");
        let file_fd = file.as_raw_fd();

        // The request is already waiting when the child asks for it, so a
        // child that could not receive fails rather than blocks.
        let request = [PROBE_BYTE; 4];
        let (ours, theirs) = SeqPacketSocket::pair().expect("a socket pair");
        ours.send(&request)
            .expect("a request for the probe to receive");
        let socket_fd = theirs.as_raw_fd();

        // SAFETY: as for the fork in `reach`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: the child, as described there. Every buffer is a local
            // passed with its own length.
            unsafe {
                leave_no_core();
                if confinement.apply().is_err() {
                    libc::_exit(PROBE_POLICY_FAILED);
                }
                let mut datagram = [0u8; 16];
                let mut byte = 0u8;
                let wanted = request.len() as isize;
                let steps = [
                    libc::recv(
                        socket_fd,
                        datagram.as_mut_ptr().cast(),
                        datagram.len(),
                        libc::MSG_TRUNC,
                    ) == wanted,
                    libc::pread(
                        file_fd,
                        std::ptr::addr_of_mut!(byte).cast(),
                        1,
                        PROBE_OFFSET,
                    ) == 1
                        && byte == PROBE_BYTE,
                    libc::send(
                        socket_fd,
                        datagram.as_ptr().cast(),
                        request.len(),
                        libc::MSG_NOSIGNAL,
                    ) == wanted,
                    // A diagnostic of no bytes: the call is made and the
                    // test's own output is left alone.
                    libc::write(libc::STDERR_FILENO, datagram.as_ptr().cast(), 0) == 0,
                    libc::close(file_fd) == 0,
                    libc::close(socket_fd) == 0,
                ];
                for (step, worked) in steps.iter().enumerate() {
                    if !worked {
                        libc::_exit(PROBE_SERVING_STEP_FAILED + step as i32);
                    }
                }
                libc::_exit(PROBE_SERVED);
            }
        }
        wait_for_child(pid)
    }

    /// Whether this kernel can run the syscall policy at all.
    ///
    /// Where it cannot, the tests assert the refusal such a kernel is owed
    /// instead, unless the caller said that is not good enough.
    fn the_syscall_policy_can_be_exercised() -> bool {
        if kill_process_available() {
            return true;
        }
        assert!(
            std::env::var_os(REQUIRE_SECCOMP).is_none(),
            "{REQUIRE_SECCOMP} is set and this kernel cannot kill on a {LAYER_SECCOMP} violation, \
             so the syscall policy cannot be exercised here at all"
        );
        false
    }

    /// What the kernel would decide for one call, by running the filter's
    /// own instructions over the record the kernel would show it.
    ///
    /// For the two things that cannot be had by making the call: a call
    /// through another architecture's entry point, which not every kernel
    /// has, and the whole range of numbers, most of which would do something
    /// if they were allowed.
    fn verdict(filter: &Filter, arch: u32, nr: u32) -> u32 {
        let program = &filter.instructions[..usize::from(filter.len)];
        let mut accumulator = 0u32;
        let mut next = 0usize;
        loop {
            let instruction = program
                .get(next)
                .expect("the filter runs off its own end, which the kernel would refuse");
            next += 1;
            match instruction.code {
                BPF_LOAD_WORD => {
                    accumulator = match instruction.k {
                        SECCOMP_DATA_NR => nr,
                        SECCOMP_DATA_ARCH => arch,
                        other => panic!("the filter loads offset {other}, which it has no use for"),
                    };
                }
                BPF_JUMP_IF_EQUAL => {
                    next += usize::from(if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                BPF_RETURN => return instruction.k,
                other => panic!("the filter holds instruction {other:#x}, which it never builds"),
            }
        }
    }

    /// Every call the file policy lists, measured or not.
    fn listed() -> Vec<u32> {
        FILE_SOURCE_POLICY
            .measured
            .iter()
            .chain(FILE_SOURCE_POLICY.margin)
            .copied()
            .collect()
    }

    #[test]
    fn every_layer_the_privileged_side_can_name_is_accepted() {
        assert_eq!(
            Confinement::parse("landlock,seccomp").expect("both layers parse"),
            Confinement {
                landlock: true,
                seccomp: true
            }
        );
        assert_eq!(
            Confinement::parse("landlock").expect("one layer parses"),
            Confinement {
                landlock: true,
                seccomp: false
            }
        );
        assert_eq!(
            Confinement::parse("seccomp").expect("the syscall layer alone parses"),
            Confinement {
                landlock: false,
                seccomp: true
            }
        );
        assert_eq!(
            Confinement::parse("none").expect("an explicit nothing parses"),
            Confinement::NOTHING
        );
    }

    /// The refusal has to name the token, because the operator reading it is
    /// looking at an argument this build and the privileged side disagree
    /// about.
    #[test]
    fn an_unknown_layer_is_refused_by_name() {
        let err = Confinement::parse("landlock,nonsense").expect_err("refused");
        assert!(err.contains("nonsense"), "{err}");
        let err = Confinement::parse("Landlock").expect_err("refused");
        assert!(err.contains("Landlock"), "{err}");
    }

    #[test]
    fn an_empty_layer_name_is_refused() {
        assert!(Confinement::parse("").is_err());
        assert!(Confinement::parse("landlock,").is_err());
    }

    /// `none` beside a layer is a list that cannot be obeyed, and obeying
    /// either half of it would be a guess about which half was meant.
    #[test]
    fn nothing_and_something_cannot_both_be_asked_for() {
        let err = Confinement::parse("none,landlock").expect_err("refused");
        assert!(err.contains("none"), "{err}");
        let err = Confinement::parse("none,seccomp").expect_err("refused");
        assert!(
            err.contains("none"),
            "`none` beside the syscall layer is as much a list nobody could have meant as \
             `none` beside the filesystem one: {err}"
        );
    }

    /// A mask with a bit the running kernel does not know is refused rather
    /// than narrowed, so the mask has to grow with the ABI and never ahead of
    /// it.
    #[test]
    fn the_handled_mask_names_only_the_accesses_its_abi_knows() {
        assert_eq!(handled_access_fs(1), 0x1fff);
        assert_eq!(handled_access_fs(2), 0x1fff | ACCESS_FS_REFER);
        let through_truncate = 0x1fff | ACCESS_FS_REFER | ACCESS_FS_TRUNCATE;
        assert_eq!(handled_access_fs(3), through_truncate);
        assert_eq!(
            handled_access_fs(4),
            through_truncate,
            "the fourth ABI adds a network policy and no filesystem access, so the mask is the \
             third ABI's"
        );
        let everything = through_truncate | ACCESS_FS_IOCTL_DEV;
        assert_eq!(handled_access_fs(5), everything);
        assert_eq!(handled_access_fs(6), everything);
        assert_eq!(
            handled_access_fs(u32::MAX),
            everything,
            "a kernel newer than this build has to get this build's whole mask, since an access \
             this build has never heard of is one it cannot ask to have denied"
        );
    }

    /// Asking for a layer the kernel cannot provide is a failure, and the
    /// privileged side's whole arrangement rests on it: it names only what
    /// its own probe found, so this path is what a disagreement between the
    /// two looks like, and it must not be a shrug.
    #[test]
    fn asking_for_the_filesystem_policy_without_landlock_fails() {
        let err = restrict_filesystem(None).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains(LAYER_LANDLOCK), "{err}");
    }

    /// The policy's whole shape in one assertion: the descriptors the parent
    /// passed go on working, and the path they came from does not open.
    #[test]
    fn the_policy_keeps_an_inherited_descriptor_and_denies_its_path() {
        let asked = Confinement::parse(LAYER_LANDLOCK).expect("the layer parses");
        if landlock_abi().is_none() {
            assert!(
                std::env::var_os(REQUIRE_LANDLOCK).is_none(),
                "{REQUIRE_LANDLOCK} is set and this kernel has no {LAYER_LANDLOCK}, so the \
                 filesystem policy cannot be exercised here at all"
            );
            // Not a skip: this kernel is owed the other behaviour, and that
            // behaviour is asserted instead.
            assert_eq!(
                probe(asked),
                PROBE_POLICY_FAILED,
                "this kernel has no {LAYER_LANDLOCK}, so a fetcher asked for it has to fail"
            );
            return;
        }
        assert_eq!(
            probe(asked),
            PROBE_DENIED_THE_PATH,
            "with the filesystem policy applied, a probe holding an inherited descriptor must \
             still read it and must not be able to open the path it came from"
        );
    }

    /// The control for the test above. Without it, a probe that could not
    /// open the path for some reason of its own -- a permission, a vanished
    /// directory -- would look exactly like a policy that worked.
    #[test]
    fn without_the_policy_the_same_probe_opens_the_path() {
        assert_eq!(
            probe(Confinement::NOTHING),
            PROBE_OPENED_THE_PATH,
            "an unconfined probe cannot open the file it just read, so the denial the policy \
             test asserts would not be the policy's doing"
        );
        assert_eq!(
            probe(Confinement::parse(LAYER_NONE).expect("an explicit nothing parses")),
            PROBE_OPENED_THE_PATH,
            "an explicit {LAYER_NONE:?} confined the process anyway"
        );
    }

    /// As for the filesystem policy: a layer the privileged side named and
    /// this kernel cannot provide ends the run, and must not be a shrug.
    #[test]
    fn asking_for_the_syscall_policy_without_the_kill_action_fails() {
        let err = restrict_syscalls(&FILE_SOURCE_POLICY, false).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains(LAYER_SECCOMP), "{err}");
    }

    /// The reason the policy exists, asserted by making each call rather
    /// than by reading the list: a list can be right about what it holds and
    /// a filter built from it still wrong about where a miss lands.
    #[test]
    fn the_syscall_policy_kills_every_call_that_reaches_past_what_it_was_handed() {
        let asked = Confinement::parse(LAYER_SECCOMP).expect("the layer parses");
        let exercised = the_syscall_policy_can_be_exercised();
        for call in EVERY_REACH {
            if !exercised {
                // Not a skip: this kernel is owed the other behaviour, and
                // that behaviour is asserted instead.
                assert_eq!(
                    reach(asked, call),
                    Ended::Exited(PROBE_POLICY_FAILED),
                    "this kernel cannot kill on a violation, so a fetcher asked for the \
                     {LAYER_SECCOMP} policy has to fail before it gets as far as {call:?}"
                );
                continue;
            }
            assert_eq!(
                reach(asked, call),
                Ended::Killed(libc::SIGSYS),
                "with the syscall policy applied, {call:?} has to end the process: it is one of \
                 the calls that would give a fetcher a descriptor its parent never handed it"
            );
        }
    }

    /// The control for the test above. Without it, a probe that died or
    /// failed for a reason of its own -- a container that forbids the call,
    /// an address that does not exist -- would look like a policy at work.
    #[test]
    fn without_the_syscall_policy_every_one_of_those_calls_succeeds() {
        for call in EVERY_REACH {
            assert_eq!(
                reach(Confinement::NOTHING, call),
                Ended::Exited(PROBE_CALL_SUCCEEDED),
                "an unconfined probe cannot make {call:?} succeed, so its death under the \
                 policy would not be the policy's doing"
            );
        }
    }

    /// The other direction. A filter that killed everything would pass the
    /// denial test, and would kill the fetcher on its first request: the
    /// loop's own calls have to go on working, with this layer alone and
    /// with both layers together, which is how instar runs it.
    #[test]
    fn the_syscall_policy_leaves_the_serving_loop_every_call_it_makes() {
        assert_eq!(
            serve_under(Confinement::NOTHING),
            Ended::Exited(PROBE_SERVED),
            "an unconfined probe cannot do what the serving loop does, so nothing below can be \
             laid at the policy's door"
        );
        if !the_syscall_policy_can_be_exercised() {
            let asked = Confinement::parse(LAYER_SECCOMP).expect("the layer parses");
            assert_eq!(serve_under(asked), Ended::Exited(PROBE_POLICY_FAILED));
            return;
        }
        let mut lists = vec![LAYER_SECCOMP.to_string()];
        if landlock_abi().is_some() {
            lists.push(format!("{LAYER_LANDLOCK},{LAYER_SECCOMP}"));
        }
        for list in lists {
            let asked = Confinement::parse(&list).expect("the layers parse");
            assert_eq!(
                serve_under(asked),
                Ended::Exited(PROBE_SERVED),
                "under {list:?} the probe could not receive, read, reply, write a diagnostic, \
                 close its descriptors and exit, which is everything a fetcher does"
            );
        }
    }

    /// The filter is the list and nothing but the list. Run over every
    /// number rather than over the ones somebody thought to try, because the
    /// mistake this catches is a jump that lands one instruction out, and
    /// that allows or kills a call nobody was looking at.
    #[test]
    fn the_filter_allows_exactly_the_calls_its_policy_lists() {
        let filter = Filter::allowing(&FILE_SOURCE_POLICY).expect("the policy fits a filter");
        let listed = listed();
        for (index, nr) in listed.iter().enumerate() {
            assert!(
                !listed[..index].contains(nr),
                "syscall {nr} is listed twice, so one of its entries says something untrue \
                 about whether it was measured"
            );
        }
        for nr in 0..1024 {
            let expected = if listed.contains(&nr) {
                libc::SECCOMP_RET_ALLOW
            } else {
                libc::SECCOMP_RET_KILL_PROCESS
            };
            assert_eq!(
                verdict(&filter, AUDIT_ARCH_X86_64, nr),
                expected,
                "the filter and the policy disagree about syscall {nr}"
            );
        }
    }

    /// A number means nothing without the architecture it was made under,
    /// so a call made any other way dies whatever its number -- including
    /// every number that is allowed natively, which is where a filter
    /// without the check would be fooled.
    #[test]
    fn a_call_made_through_another_abi_is_killed_whatever_its_number() {
        let filter = Filter::allowing(&FILE_SOURCE_POLICY).expect("the policy fits a filter");
        let x32_bit = u32::try_from(X32_SYSCALL_BIT).expect("the bit fits a syscall number");
        for nr in listed() {
            assert_eq!(
                verdict(&filter, AUDIT_ARCH_X86_64, nr),
                libc::SECCOMP_RET_ALLOW,
                "syscall {nr} is listed and is not allowed natively"
            );
            assert_eq!(
                verdict(&filter, AUDIT_ARCH_I386, nr),
                libc::SECCOMP_RET_KILL_PROCESS,
                "number {nr} is allowed through the 32-bit entry point, where it is a \
                 different call"
            );
            assert_eq!(
                verdict(&filter, AUDIT_ARCH_X86_64, nr | x32_bit),
                libc::SECCOMP_RET_KILL_PROCESS,
                "syscall {nr} is allowed through the x32 ABI, which nothing here was measured \
                 using"
            );
        }
    }
}
