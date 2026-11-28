//! The fetcher's confinement, tested by applying it.
//!
//! Kept apart from the policy it tests so that the policy file is the
//! review unit for the policy: the probes below fork, confine a child and
//! provoke it, and they are most of the lines.

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
        let waited = unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), libc::WNOHANG) };
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
