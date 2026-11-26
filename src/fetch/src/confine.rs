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

/// Which confinement layers the privileged side asked for.
///
/// Parsed from the command line rather than decided here, and carried as far
/// as the one place that applies it, so that the asking and the applying are
/// visibly the same list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confinement {
    /// Whether the filesystem policy was asked for.
    landlock: bool,
}

impl Confinement {
    /// Nothing was asked for.
    ///
    /// What a command line without the flag means. The privileged side always
    /// sends the flag, and sends `none` where the kernel can provide nothing,
    /// so this is the shape of a fetcher run by hand rather than of anything
    /// instar spawns.
    pub const NOTHING: Confinement = Confinement { landlock: false };

    /// Read the comma-separated list the flag carries.
    ///
    /// An unknown token is refused by name rather than ignored. Ignoring one
    /// would mean a privileged side that asked for a layer this build does
    /// not have got a fetcher that was not confined by it and said nothing,
    /// which is precisely the silence this whole arrangement exists to make
    /// impossible.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut asked = Confinement::NOTHING;
        // Tracked beside the layers themselves, rather than read back off
        // them, so that a contradictory list is refused whichever layer it
        // names: a layer this build parses but does not yet install would
        // otherwise leave `none` beside it looking like agreement.
        let mut layers_asked = false;
        let mut nothing_asked = false;
        for token in list.split(',') {
            match token {
                LAYER_LANDLOCK => {
                    asked.landlock = true;
                    layers_asked = true;
                }
                // The syscall policy. Its filter is installed where the
                // allowlist it enforces is written, and the token is read
                // here so that a layer the privileged side names is never
                // refused as one this process does not know.
                LAYER_SECCOMP => layers_asked = true,
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
        if nothing_asked && layers_asked {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::fs::File;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    /// Turns a kernel without Landlock from a weaker test into a failure.
    ///
    /// Without it, a run on such a kernel asserts the refusal instead -- the
    /// behaviour that kernel is owed -- which is a real assertion but not the
    /// one that proves the policy bites. Setting it says the caller expects
    /// the strong form, so the weak one is a failure rather than a quiet
    /// substitution.
    const REQUIRE_LANDLOCK: &str = "INSTAR_REQUIRE_LANDLOCK";

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

    /// Wait for one probe, within a budget, and render anything that is not a
    /// plain exit as a failure rather than as a status code.
    fn wait_for_probe(pid: libc::pid_t) -> i32 {
        let deadline = Instant::now() + PROBE_BUDGET;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid writes the one int it is given, which is a
            // local, and reaps the child this function was handed.
            let waited =
                unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), libc::WNOHANG) };
            assert!(waited >= 0, "waitpid: {}", io::Error::last_os_error());
            if waited == pid {
                assert!(
                    libc::WIFEXITED(status),
                    "the probe did not exit of its own accord: raw status {status:#x}, signal {}",
                    libc::WTERMSIG(status)
                );
                return libc::WEXITSTATUS(status);
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

    #[test]
    fn every_layer_the_privileged_side_can_name_is_accepted() {
        assert_eq!(
            Confinement::parse("landlock,seccomp").expect("both layers parse"),
            Confinement { landlock: true }
        );
        assert_eq!(
            Confinement::parse("landlock").expect("one layer parses"),
            Confinement { landlock: true }
        );
        assert_eq!(
            Confinement::parse("seccomp").expect("the syscall layer alone parses"),
            Confinement::NOTHING
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
            "a layer this process parses and does not install is still a layer, and `none` \
             beside it is still a list nobody could have meant: {err}"
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
}
