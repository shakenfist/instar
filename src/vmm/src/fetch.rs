//! Telling a URL from a path on an instar input, and serving a local one
//! through a fetcher.
//!
//! An input argument is either a filesystem path, exactly as it has always
//! been, or a URL that names where the bytes live. Deciding which has to happen
//! before anything is opened, because the wrong guess produces the wrong error:
//! `instar info https://example.com/disk.qcow2` would otherwise fail with "No
//! such file or directory", telling the user their file is missing rather than
//! that the feature is not built.
//!
//! The rule is deliberately mechanical. An argument that starts with a scheme
//! (a letter, then letters, digits, `+`, `-` or `.`) followed by `://` is a
//! URL. Anything else is a path, so a file called `weird:name` or `c:foo`
//! still opens, because without the `//` there is no URL here.
//!
//! The parse is by hand rather than through a URL or regex crate: instar's
//! dependency tree is part of its attack surface, and the only URL form
//! accepted today is a narrow `file://`, for which percent-decoding and the
//! rest of RFC 3986 would be machinery nothing uses. A real parser belongs
//! with the first protocol that needs one.
//!
//! # The fetcher that serves an input
//!
//! Classifying a string opens nothing and starts nothing. Serving the input it
//! names does both: [`spawn_file_fetcher`] opens the file with the invoking
//! user's authority, starts `instar-fetch` with that descriptor and one end of
//! a `SOCK_SEQPACKET` socketpair, and returns a [`RemoteSource`] owning the
//! child and the client to it together.
//!
//! Three things about that child are worth saying here rather than leaving to
//! be inferred:
//!
//! * **It is started before `/dev/kvm` is opened.** A child cannot inherit a
//!   descriptor its parent has not opened, so the ordering is a guarantee that
//!   does not depend on anyone remembering a flag. The KVM crate does open
//!   `/dev/kvm` close-on-exec, so this is the second protection rather than
//!   the only one -- but it is the one that costs nothing and cannot be
//!   changed by a dependency bump.
//! * **It holds five descriptors and no more:** the three standard ones, its
//!   socket, and the file. Everything it is handed is something a future
//!   sandbox would otherwise have to take back off it.
//! * **It is confined before its first instruction, and again once it is
//!   running.** What only a parent can set -- the resource limits, and the
//!   promise that no `exec` of its can gain privilege -- is set between the
//!   `fork` and the `exec`. The policies that have to come later, because a
//!   filesystem denial applied before `exec` would stop the `exec` itself,
//!   are applied by the fetcher to itself; this side decides which of those
//!   the running kernel can provide and names them on the command line, so
//!   the child applies what it was told or fails, and never quietly nothing.
//! * **It is reaped by a `Drop`,** not by a call at the end of an operation,
//!   because the paths that most need reaping are the ones nobody writes
//!   down. `std::process::exit` is the one path a `Drop` cannot cover, so an
//!   operation serving a remote input returns its errors through `main`.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fetch_protocol::{FetchClient, SeqPacketSocket};

/// What an input argument turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum InputSource {
    /// An ordinary filesystem path, to be opened as instar always has.
    Path(PathBuf),
    /// A `file://` URL, reduced to the absolute path it names. The path is
    /// not percent-decoded: a `%` anywhere in the URL is refused instead, so
    /// the text the user typed and the path that is opened cannot differ.
    FileUrl(PathBuf),
}

/// The sentence shown for each scheme that is recognised but not served,
/// keyed by lowercase scheme. This is the one place that says which schemes
/// exist, so enabling one, or wording it differently per operation, is an edit
/// to this table and nowhere else.
const REFUSED_SCHEMES: &[(&str, &str)] = &[
    (
        "https",
        "instar does not accept https:// inputs yet; pass a local path",
    ),
    (
        "http",
        "instar does not accept http:// inputs yet; pass a local path",
    ),
    (
        "s3",
        "instar does not accept s3:// inputs yet; pass a local path",
    ),
    (
        "nbd",
        "instar does not accept nbd:// inputs yet; pass a local path",
    ),
];

/// Returns the length of the scheme if `arg` begins with `scheme://`, where a
/// scheme is `[A-Za-z][A-Za-z0-9+.-]*`.
fn url_scheme_len(arg: &str) -> Option<usize> {
    let bytes = arg.as_bytes();
    if !bytes.first()?.is_ascii_alphabetic() {
        return None;
    }
    let len = bytes
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))
        .unwrap_or(bytes.len());
    if arg[len..].starts_with("://") {
        Some(len)
    } else {
        None
    }
}

/// Parses the part of a `file://` URL after the scheme: an empty authority or
/// `localhost`, then an absolute path. A query, a fragment, a percent escape,
/// a NUL, or any other authority is refused, because each would make the path
/// that is opened differ from the one the user wrote or reach a different host.
fn parse_file_url(rest: &str) -> Result<PathBuf, String> {
    let refuse = |why: &str| {
        Err(format!(
            "instar cannot use the input file://{}: {}",
            rest, why
        ))
    };
    if rest.contains('?') {
        return refuse("a query string is not supported");
    }
    if rest.contains('#') {
        return refuse("a fragment is not supported");
    }
    if rest.contains('%') {
        return refuse("percent escapes are not supported");
    }
    if rest.contains('\0') {
        return refuse("a NUL byte is not allowed");
    }
    let path = match rest.find("/") {
        Some(slash) => {
            let authority = &rest[..slash];
            if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
                return refuse("only an empty or localhost host is supported");
            }
            &rest[slash..]
        }
        // No slash at all: either `file://localhost` with no path, or a bare
        // word that is a relative path or a host. Neither is absolute.
        None => {
            return refuse(
                if rest.is_empty() || rest.eq_ignore_ascii_case("localhost") {
                    "no path was given"
                } else {
                    "the path must be absolute"
                },
            );
        }
    };
    Ok(PathBuf::from(path))
}

/// Classifies an input argument as a plain path or a `file://` URL, or refuses
/// it with a sentence fit to show the user.
///
/// The scheme is compared case-insensitively, as RFC 3986 says to. Every URL
/// scheme other than `file` is refused by name, using the sentence in
/// [`REFUSED_SCHEMES`] or a generic one for a scheme not in it.
pub fn classify_input(arg: &str) -> Result<InputSource, String> {
    let Some(len) = url_scheme_len(arg) else {
        return Ok(InputSource::Path(PathBuf::from(arg)));
    };
    let scheme = arg[..len].to_ascii_lowercase();
    if scheme == "file" {
        return parse_file_url(&arg[len + 3..]).map(InputSource::FileUrl);
    }
    match REFUSED_SCHEMES.iter().find(|(name, _)| *name == scheme) {
        Some((_, sentence)) => Err((*sentence).to_string()),
        None => Err(format!(
            "instar does not accept {}:// inputs; pass a local path",
            scheme
        )),
    }
}

/// The fetcher's file name, resolved from the directory instar loads its
/// runtime files out of.
const FETCHER_BINARY: &str = "instar-fetch";

/// Where the child finds the socket it answers on.
///
/// This and [`CHILD_FILE_FD`] are the two numbers passed on the fetcher's
/// command line, and -- with the three standard descriptors -- the only ones
/// it is meant to hold. A fetcher that was handed anything else would be a
/// process holding privilege nobody intended it to have, and the sandbox that
/// will one day confine it would have to be built around that hole.
const CHILD_SOCKET_FD: RawFd = 3;

/// Where the child finds the already-open file whose bytes it serves.
const CHILD_FILE_FD: RawFd = 4;

/// The lowest descriptor number the parent stages a copy on before the fork.
///
/// Above both of the child's, which is the entire point: see
/// [`stage_clear_of_child_fds`].
const FIRST_STAGING_FD: RawFd = CHILD_FILE_FD + 1;

/// The flag that names the confinement the fetcher must apply to itself.
const CONFINE_FLAG: &str = "--confine=";

/// The layer that denies the fetcher every path, named as the fetcher's
/// command line spells it.
///
/// The spellings are repeated in the fetcher rather than shared through a
/// crate on purpose: the fetcher's dependencies are the protocol and `libc`
/// and nothing else, because every crate it links is code running beside
/// bytes an attacker controls, and two string constants are a cheaper price
/// than a crate in that position. What keeps the two copies honest is that
/// every test here spawns the real binary with the real argument, so a
/// disagreement is a failed spawn rather than a silently unconfined child.
const LAYER_LANDLOCK: &str = "landlock";

/// The layer that denies the fetcher every syscall its serving loop does not
/// make.
const LAYER_SECCOMP: &str = "seccomp";

/// What the list says when this kernel can provide no layer at all.
const LAYER_NONE: &str = "none";

/// What the report says of the filesystem policy once it is in force.
///
/// A constant of its own because it is the one clause in the report that
/// claims a policy is applied rather than merely asked for, and the claim is
/// only true where it is printed: the lines are written after the init
/// exchange, and a fetcher that could not apply a layer it was named exits
/// non-zero before it replies to the init. Naming the clause is what lets a
/// test assert that it appears nowhere else.
const LANDLOCK_APPLIED: &str = "has left itself no reachable path";

/// What the report says of the syscall policy once it is in force.
///
/// Named for the same reason: it claims a filter is installed, which is true
/// only of a fetcher that was asked for one and then completed its init
/// exchange, and a test has to be able to say it appears nowhere else.
const SECCOMP_APPLIED: &str = "has left itself only the syscalls it serves with";

/// `landlock_create_ruleset`'s version query flag.
///
/// With a null attribute pointer and a zero size it is a question rather
/// than a creation: the kernel answers with the Landlock ABI it implements,
/// allocates nothing and returns no descriptor.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// How many descriptors the fetcher may hold.
///
/// It is given five -- the three standard ones, its socket and the image --
/// and opens nothing afterwards, so the ceiling bounds what a fetcher that
/// had been taken over could accumulate rather than anything a correct one
/// does. The three spare numbers are for the dynamic loader, which opens one
/// file at a time as it starts the process and is bound by this limit too,
/// because the limit is set before the `exec`.
const CHILD_MAX_FILES: libc::rlim_t = 8;

/// How long a fetcher is given to notice its socket has closed and exit by
/// itself before it is killed.
///
/// A fetcher that needs the kill is a bug in the fetcher. The bound is here
/// because the alternative is worse: a reap that waits for ever turns that
/// bug into every instar run hanging as it exits.
const REAP_GRACE: Duration = Duration::from_secs(2);

/// How often the reap looks to see whether the child has gone.
const REAP_POLL: Duration = Duration::from_millis(10);

/// Which confinement layers the running kernel can provide.
///
/// The privileged side asks this once, before it spawns anything, and names
/// what it found on the fetcher's command line. The fetcher applies exactly
/// the layers it was named and exits non-zero before answering anything if
/// it cannot apply one of them, so a layer is either asked for and applied,
/// or not asked for -- never asked for and quietly missing, which is the
/// failure a sandbox is most likely to have and least likely to show.
///
/// Deciding here also keeps the decision on the side that can be trusted
/// with it: a fetcher that chose its own confinement would be a process
/// under an attacker's influence choosing how confined to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelConfinement {
    /// The Landlock ABI this kernel implements, or `None` where it has no
    /// Landlock at all.
    ///
    /// The number is not passed to the fetcher. It asks the same question
    /// itself and builds its handled-access mask from its own answer,
    /// because a mask naming an access bit the kernel does not know is
    /// refused outright rather than narrowed.
    landlock_abi: Option<u32>,
    /// Whether this kernel offers the seccomp action the fetcher's filter
    /// uses, which kills the process rather than failing the call.
    seccomp_kill: bool,
}

impl KernelConfinement {
    /// Ask the running kernel what it can provide.
    ///
    /// Both questions are side-effect free: neither confines this process,
    /// installs anything on it or opens a descriptor that would then cross
    /// the `fork` into a child whose whole descriptor set is accounted for.
    fn probe() -> Self {
        KernelConfinement {
            landlock_abi: landlock_abi(),
            seccomp_kill: seccomp_kill_available(),
        }
    }

    /// The command-line argument naming every layer this kernel can provide.
    ///
    /// A kernel that can provide nothing still gets an explicit `none`
    /// rather than no argument: the fetcher then refuses a list it cannot
    /// make sense of, and an argument that went missing between here and
    /// there cannot read as "nothing was asked for".
    fn confine_argument(&self) -> String {
        let mut layers: Vec<&str> = Vec::new();
        if self.landlock_abi.is_some() {
            layers.push(LAYER_LANDLOCK);
        }
        if self.seccomp_kill {
            layers.push(LAYER_SECCOMP);
        }
        if layers.is_empty() {
            layers.push(LAYER_NONE);
        }
        format!("{CONFINE_FLAG}{}", layers.join(","))
    }

    /// One line per layer, for a caller that asked for verbosity.
    ///
    /// The lines say the fetcher is confined rather than that it was asked
    /// to be, and they can: the fetcher applies the layers this list names
    /// before it answers anything, and exits non-zero without answering if
    /// it cannot apply one of them, so a fetcher that completed its init
    /// exchange is a fetcher that applied what it was named. These lines are
    /// printed after that exchange for exactly that reason.
    ///
    /// Said on this side because this side is where the answer is known, and
    /// said only under `--verbose` because a default run of an operation
    /// reading a local file writes nothing to stderr and a `file://` input
    /// is not a reason to change that. A kernel that cannot provide a layer
    /// is not a failure -- the run goes ahead -- so the operator who wants
    /// to know asks, and the lines name the layer either way.
    fn report(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(match self.landlock_abi {
            Some(abi) => format!(
                "instar: this kernel provides {LAYER_LANDLOCK} (ABI {abi}), and the fetcher \
                 {LANDLOCK_APPLIED}"
            ),
            None => format!(
                "instar: this kernel has no {LAYER_LANDLOCK}, so the fetcher runs without a \
                 filesystem policy"
            ),
        });
        lines.push(if self.seccomp_kill {
            format!(
                "instar: this kernel can kill on a {LAYER_SECCOMP} violation, and the fetcher \
                 {SECCOMP_APPLIED}"
            )
        } else {
            format!(
                "instar: this kernel cannot kill on a {LAYER_SECCOMP} violation, so the fetcher \
                 runs without a syscall policy"
            )
        });
        lines
    }
}

/// The Landlock ABI the running kernel implements, or `None` if it has none.
fn landlock_abi() -> Option<u32> {
    // SAFETY: landlock_create_ruleset has no glibc wrapper, so it is reached
    // through syscall(2) with the arguments the version query is defined to
    // take: a null attribute pointer, a zero size and the version flag. In
    // that form the kernel reads nothing through the pointer, creates no
    // ruleset and returns the ABI version, and the result is checked before
    // it is used.
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

/// Whether this kernel offers the seccomp action that kills the process.
///
/// Asked with `SECCOMP_GET_ACTION_AVAIL`, which answers whether the action
/// exists and changes nothing about the caller: it installs no filter and
/// leaves this process's own seccomp state as it was. Reading this process's
/// own seccomp mode is not the same question -- it reports what *this*
/// process is already under, which says nothing about what a child could
/// install -- and the kill action is the one the fetcher's filter uses, so
/// the availability of a weaker action would not do.
fn seccomp_kill_available() -> bool {
    let action = libc::SECCOMP_RET_KILL_PROCESS;
    // SAFETY: seccomp(2) has no glibc wrapper either. The action-availability
    // operation reads the one u32 the third argument points at -- a local
    // that outlives the call -- and writes nothing; it returns 0 when the
    // action exists and -1 with EOPNOTSUPP when it does not.
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

/// Set both the soft and the hard limit of `resource` to `value`.
///
/// Called between `fork` and `exec`, so it builds the limit on the stack and
/// makes one syscall: no allocation, no lock, no formatting. The hard limit
/// goes down with the soft one deliberately, because a limit the process can
/// raise again is not a limit on a process that has been taken over.
fn set_hard_limit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit reads the rlimit it is handed and nothing else. The
    // value lives in this frame for the whole call, and the result is
    // checked.
    if unsafe { libc::setrlimit(resource, &limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Duplicate `fd` onto a descriptor number at or above [`FIRST_STAGING_FD`],
/// close-on-exec.
///
/// This exists because the two descriptors the child needs are very likely to
/// be sitting already on the two numbers they have to end up on. The image is
/// opened first and takes the lowest free number, typically 3; the socketpair
/// is created next and takes 4 and 5. A `dup2` of the socket onto 3 would
/// then close the image in the child, and a `dup2` of the image onto 4 would
/// close the socket -- and no ordering of the two calls escapes it, because
/// each one's target is the other's source. Both would leave the child
/// serving the wrong descriptor rather than failing outright, which is the
/// kind of mistake that survives a passing test.
///
/// Staging both copies out of the way first makes the two `dup2` calls in the
/// child independent of each other and of whatever the parent's descriptor
/// table happens to look like. The staged copies are close-on-exec, so they
/// are gone before the fetcher's first instruction: what crosses the `exec`
/// is the pair of copies `dup2` made, which are not.
fn stage_clear_of_child_fds(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates the descriptor onto the lowest free
    // number at or above its argument and returns it. The borrowed descriptor
    // is open for the whole call, and the result is checked before it is
    // adopted.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, FIRST_STAGING_FD) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl reported success, so raw is a fresh descriptor this
    // process owns and nothing else holds a copy of.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Clear `O_NONBLOCK` from a descriptor, leaving its other flags alone.
fn clear_nonblock(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_GETFL takes no further argument and returns the file status
    // flags; the result is checked before it is used.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL takes an int of file status flags, here the ones just
    // read with one bit cleared. The result is checked.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open `path` read-only for a fetcher to serve, refusing anything that is
/// not a regular file.
///
/// Resolving the path is an exercise of the invoking user's authority, so it
/// happens here and the open descriptor is what the child is given. The
/// refusal is written here too, for the same reason: this side has the path
/// the user typed and can say something about it. The fetcher refuses a
/// non-regular descriptor as well, but by then the user's error would be a
/// failed init on a socket, which says nothing about which input was wrong.
///
/// `O_NONBLOCK` is on the open because a FIFO opened read-only blocks until
/// someone opens its write end, which would turn "instar cannot read a FIFO"
/// into a hang; `O_NOCTTY` stops a terminal becoming this process's
/// controlling one. Neither flag means anything for a regular file, and
/// `O_NONBLOCK` is cleared once the file is known to be one, so what crosses
/// the `exec` is an ordinary blocking read-only descriptor.
fn open_regular_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("instar cannot open {}: {err}", path.display()),
            )
        })?;
    // Asked of the descriptor rather than of the path, so the answer
    // describes the file that was opened and will be served rather than
    // whatever the path named a moment ago.
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "instar cannot read {}: it is not a regular file, so it has no size to \
                 advertise and cannot answer a read at an offset",
                path.display()
            ),
        ));
    }
    clear_nonblock(file.as_fd())?;
    Ok(file)
}

/// A fetcher serving one input, and the client that talks to it.
///
/// The two are owned together because they are one lifetime: the client is
/// the only way to reach the child, and closing the client's socket is how
/// the child is told to stop. Dropping this does both, in that order, so no
/// caller has to remember to -- which is what makes the child reaped on the
/// paths nobody writes down, a `?` out of the middle of an operation or a
/// panic in the vCPU loop. The one path a `Drop` cannot cover is
/// `std::process::exit`, so an operation that serves a remote input must
/// return its errors through `main` instead of exiting under them.
#[derive(Debug)]
pub struct RemoteSource {
    /// The fetcher. Nothing else reaps it: `Child`'s own drop deliberately
    /// does not wait, so this type's `Drop` is the difference between an
    /// exited child and a zombie on every run.
    child: Child,
    /// The client. In an `Option` only so that `Drop` can close the socket
    /// before waiting for the child that is reading it; it is `Some` for the
    /// whole of the value's useful life, and `None` only while it is being
    /// torn down or if the init exchange never completed.
    client: Option<FetchClient>,
}

impl RemoteSource {
    /// The client, for reading the input's bytes.
    pub fn client_mut(&mut self) -> &mut FetchClient {
        self.client
            .as_mut()
            .expect("the client is taken only while the source is being dropped")
    }

    /// The size of the input in bytes, as the fetcher advertised it at init.
    ///
    /// This, rather than a `stat` of the path, is the number a device built
    /// on this source should be given: it is the only size a fetcher reading
    /// from somewhere other than a local file will be able to report, so
    /// taking it from the protocol now is what keeps this code honest while
    /// there is still a local file to check it against.
    pub fn capacity(&self) -> u64 {
        self.client
            .as_ref()
            .expect("the client is taken only while the source is being dropped")
            .capacity()
    }

    /// The fetcher's process id, for diagnostics and for the tests that
    /// inspect what the child holds.
    // Only the tests ask for it so far; everything else reaches the child
    // through the client.
    #[allow(dead_code)]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for RemoteSource {
    fn drop(&mut self) {
        // Closing the socket is how the fetcher is asked to stop: its `recv`
        // returns zero and it exits zero. Nothing is sent to it, because a
        // message would need an answer and the point here is to stop waiting
        // on this child, not to start.
        let _ = self.client.take();

        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(err) => {
                    // Nothing useful is left to do: the child cannot be
                    // waited for, so it also cannot be confirmed killed.
                    eprintln!(
                        "instar: could not wait for the fetcher (pid {}): {err}",
                        self.child.id()
                    );
                    return;
                }
            }
            if started.elapsed() >= REAP_GRACE {
                break;
            }
            std::thread::sleep(REAP_POLL);
        }

        let pid = self.child.id();
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            // Unreachable: the pid came from this process's own fork. There
            // is no safe fallback, because a wrong pid_t is another process.
            eprintln!("instar: the fetcher's pid {pid} is not a pid this process can signal");
            return;
        };
        // SAFETY: raw_pid is this process's own child and has not been
        // waited for, so the kernel still holds the pid against it and it
        // cannot have been reused by something else.
        unsafe { libc::kill(raw_pid, libc::SIGKILL) };
        eprintln!(
            "instar: the fetcher (pid {pid}) ignored its closed socket for {:?}; killed it",
            started.elapsed()
        );
        // Bounded by the SIGKILL above, which nothing can block or ignore.
        let _ = self.child.wait();
    }
}

/// Start a fetcher serving the file at `path`, and return it together with a
/// client that has completed the init exchange.
///
/// The fetcher is resolved out of the directory instar loads its runtime
/// files from, which is where the developer build and both packages put it.
///
/// Call this before opening `/dev/kvm`. A child cannot inherit a descriptor
/// its parent has not opened yet, so the ordering is a guarantee that holds
/// whatever flags someone else's `open` chooses, and it costs nothing:
/// nothing in an operation needs the VM before it has its input.
pub fn spawn_file_fetcher(path: &Path, verbose: bool) -> io::Result<RemoteSource> {
    spawn_fetcher_binary(&crate::get_binary_path(FETCHER_BINARY), path, verbose)
}

/// Start `fetcher` serving the file at `path`.
///
/// Separate from [`spawn_file_fetcher`] so that a test can run the binary it
/// has just built, rather than the one an installed instar would resolve to.
fn spawn_fetcher_binary(
    fetcher: &Path,
    path: &Path,
    inherit_stderr: bool,
) -> io::Result<RemoteSource> {
    // Opened, checked and refused before anything is spawned, so that a bad
    // input costs nothing and is reported in terms of the path the user gave.
    let file = open_regular_file(path)?;
    let (ours, theirs) = SeqPacketSocket::pair()?;

    // Staged clear of the numbers they have to land on, so that the two dup2
    // calls after the fork cannot overwrite one of these descriptors with
    // the other.
    let staged_socket = stage_clear_of_child_fds(theirs.as_fd())?;
    let staged_file = stage_clear_of_child_fds(file.as_fd())?;
    let staged_socket_fd = staged_socket.as_raw_fd();
    let staged_file_fd = staged_file.as_raw_fd();

    // Asked before the spawn, so that the layers the child is told to apply
    // are the ones this kernel really has, and so that the answer can be
    // reported to a caller who asked for it.
    let confinement = KernelConfinement::probe();

    let mut command = Command::new(fetcher);
    command
        .arg(confinement.confine_argument())
        .arg(CHILD_SOCKET_FD.to_string())
        .arg(CHILD_FILE_FD.to_string())
        // The child is assumed hostile, and instar's stdout is the output a
        // user pipes into something else: a fetcher that could write to it
        // could put text into a JSON document the user trusts. It has no use
        // for stdin either.
        //
        // Its stderr follows the caller's own verbosity. The fetcher says
        // two things on a run that goes well -- what it is serving, and
        // that its peer closed the socket -- and an operation reading a
        // local file says nothing at all on stderr, so inheriting
        // unconditionally would make the same command noisier for no
        // reason the user asked for. Its diagnostics are still the only
        // thing it can say that is not a status code, so a caller that
        // wants them asks, and every protocol failure reaches the user
        // anyway as a sentence this side writes from a status.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(if inherit_stderr {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    // What this closure does and does not do is the parent's half of the
    // confinement, and both halves are deliberate.
    //
    // It sets what only a parent can set. The three limits have to be in
    // place before the image of a new program exists, and `no_new_privs` has
    // to be set by something the fetcher cannot later be talked out of: once
    // set it cannot be unset, which is what makes it a promise that no
    // `exec` of the fetcher's -- it makes none -- could gain privilege, and
    // it is also the precondition for an unprivileged process installing a
    // seccomp filter on itself at all.
    //
    // It does not set a file-size limit, although a fetcher that writes
    // nothing looks like a free win for one. Its stderr is a file the caller
    // chose: `instar info --verbose file:///x 2>log` makes it a regular
    // file, and a zero file-size limit turns the fetcher's first diagnostic
    // line into a SIGXFSZ. The limit would kill the process for printing
    // what it was asked to print.
    //
    // It does not make the child undumpable either. What that would protect
    // against is a process of the same uid attaching to the fetcher, and
    // such a process can attach to instar itself just as easily, so it is
    // not a boundary; the fetcher holds no secret of its own beyond an image
    // the invoking user already owns. What it would cost is this side's own
    // diagnostics: `/proc/<pid>` of the child becomes unreadable even to its
    // parent, and reading it is how the descriptor set is asserted and how
    // an operator straces a fetcher that is misbehaving. The crash-dump
    // worry it is usually reached for is covered by the core limit below.
    //
    // SAFETY: the closure runs in the child between `fork` and `exec`, where
    // only async-signal-safe work is permitted: a thread holding a lock in
    // the parent did not come across the fork, so taking that lock here
    // would deadlock a process that can never be released. It therefore
    // makes two `dup2` calls, three `setrlimit` calls and one `prctl`, and
    // nothing else. It captures two descriptor numbers by value, allocates
    // nothing, locks nothing and formats nothing; `io::Error::last_os_error`
    // only records errno, and the message for it is rendered by the parent.
    //
    // The limits come after the two `dup2` calls, which is the only order
    // that works: the descriptors being copied are staged on numbers that
    // may be above the new ceiling, and lowering it first would leave them
    // uncopyable.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(staged_socket_fd, CHILD_SOCKET_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(staged_file_fd, CHILD_FILE_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            // A fetcher serves one file on one socket in one thread; it has
            // no reason to fork, and the limit is enforced at `fork` rather
            // than at `exec`, so setting it here costs the `exec` nothing.
            set_hard_limit(libc::RLIMIT_NPROC, 0)?;
            // A core dump of the fetcher would be the image's bytes written
            // somewhere nobody asked for them.
            set_hard_limit(libc::RLIMIT_CORE, 0)?;
            set_hard_limit(libc::RLIMIT_NOFILE, CHILD_MAX_FILES)?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("instar could not start {}: {err}", fetcher.display()),
        )
    })?;

    // The fork has taken its copies, so the parent closes all four of its
    // own. The child's socket end matters most: another copy of it open here
    // would keep the child's `recv` from ever seeing the connection close,
    // which is how it is told to exit.
    drop(staged_socket);
    drop(staged_file);
    drop(theirs);
    drop(file);

    // From here on the child is alive and has to be reaped on every path
    // out, so it is owned by a RemoteSource before the first thing that can
    // fail. The init exchange is that thing: if it fails, this value is
    // dropped on the way out, which closes what is left of the socket and
    // waits for the child.
    let mut source = RemoteSource {
        child,
        client: None,
    };
    source.client = Some(FetchClient::new(ours)?);

    // Said after the init exchange rather than before it, so that the lines
    // describe what happened: a fetcher that could not apply a layer it was
    // named exits before it replies, and there would have been no init to
    // complete.
    if inherit_stderr {
        for line in confinement.report() {
            eprintln!("{line}");
        }
    }
    Ok(source)
}

/// Helpers for any module's tests that need a real fetcher.
///
/// They live outside `mod tests` because the backing store's tests need them
/// too, and a second copy of the search below is how the two would come to
/// disagree: the one property that matters about it -- that a missing fetcher
/// fails loudly rather than skipping -- is exactly the one a divergent copy
/// would lose, and it would lose it silently, as a green run.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// How long a read is given in a test before it is a failure.
    ///
    /// Shorter than the client's operational default, because a test that
    /// hangs for a minute is still a test that hangs.
    pub(crate) const TEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// The byte a fixture holds at `offset`, so that a read answered from the
    /// wrong offset -- or from the wrong descriptor -- is a mismatch rather
    /// than a buffer of zeros that happens to agree.
    pub(crate) fn pattern(offset: u64) -> u8 {
        (offset.wrapping_mul(31).wrapping_add(offset >> 9) & 0xff) as u8
    }

    /// Write a fixture of `len` bytes of [`pattern`] at `path`.
    pub(crate) fn write_fixture(path: &Path, len: u64) {
        let bytes: Vec<u8> = (0..len).map(pattern).collect();
        std::fs::write(path, &bytes).expect("writing the fixture");
    }

    /// The `instar-fetch` binary for a test to spawn.
    ///
    /// `instar-fetch` is a different package, so `CARGO_BIN_EXE_` -- which
    /// cargo defines only for a package's own integration tests -- does not
    /// exist here. What does exist is this test binary's own path, and cargo
    /// links every workspace binary into the profile directory above
    /// wherever it put the test binary: that has been `target/<profile>/deps`
    /// and is `target/<profile>/build/<package>/<hash>/out` on the toolchain
    /// this is pinned to, so the depth is not something to hardcode. Every
    /// ancestor is searched instead, nearest first, which finds the right
    /// profile's fetcher whichever layout the toolchain uses.
    /// `INSTAR_BIN_DIR` is honoured first, exactly as the resolver instar
    /// uses in production honours it.
    ///
    /// Not finding it fails and never skips. A test that skips when its
    /// subject is missing is a green run that proved nothing, so this panics
    /// and names the command that builds what is missing.
    pub(crate) fn fetcher_binary() -> PathBuf {
        let mut candidates = Vec::new();
        if let Some(dir) = std::env::var_os("INSTAR_BIN_DIR") {
            candidates.push(PathBuf::from(dir));
        }
        let exe = std::env::current_exe().expect("this test binary has a path");
        candidates.extend(exe.ancestors().skip(1).map(Path::to_path_buf));

        let mut tried = Vec::new();
        for dir in candidates {
            let candidate = dir.join(FETCHER_BINARY);
            if candidate.is_file() {
                return candidate;
            }
            tried.push(candidate);
        }
        panic!(
            "{FETCHER_BINARY} is at none of {tried:?}; build the workspace with \
             `make instar`, or point INSTAR_BIN_DIR at the directory holding it, and run \
             this test again"
        );
    }

    /// Start the freshly built fetcher on `path`, with reads bounded so that a
    /// fetcher which never answers fails the test instead of holding it for
    /// the client's operational minute.
    pub(crate) fn spawn_test_fetcher(path: &Path) -> RemoteSource {
        let mut source = spawn_fetcher_binary(&fetcher_binary(), path, true)
            .expect("spawn a fetcher on the fixture");
        source
            .client_mut()
            .set_reply_timeout(TEST_READ_TIMEOUT)
            .expect("a ten-second read timeout is accepted");
        source
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileExt;

    use tempfile::tempdir;

    fn file_url(arg: &str) -> PathBuf {
        match classify_input(arg) {
            Ok(InputSource::FileUrl(p)) => p,
            other => panic!("{} did not classify as a file URL: {:?}", arg, other),
        }
    }

    fn refusal(arg: &str) -> String {
        match classify_input(arg) {
            Err(e) => e,
            other => panic!("{} was not refused: {:?}", arg, other),
        }
    }

    fn path(arg: &str) {
        assert_eq!(
            classify_input(arg),
            Ok(InputSource::Path(PathBuf::from(arg)))
        );
    }

    #[test]
    fn empty_authority_absolute_path() {
        assert_eq!(file_url("file:///tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn localhost_authority_absolute_path() {
        assert_eq!(file_url("file://localhost/tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn scheme_and_localhost_are_case_insensitive() {
        assert_eq!(file_url("FILE://LocalHost/tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn foreign_authority_refused() {
        assert!(refusal("file://evil.example/tmp/x").contains("host"));
    }

    #[test]
    fn relative_path_refused() {
        assert!(refusal("file://relative").contains("absolute"));
    }

    #[test]
    fn no_path_after_localhost_refused() {
        assert!(refusal("file://localhost").contains("no path"));
    }

    #[test]
    fn nothing_after_scheme_refused() {
        assert!(refusal("file://").contains("no path"));
    }

    #[test]
    fn query_refused() {
        assert!(refusal("file:///x?y").contains("query"));
    }

    #[test]
    fn fragment_refused() {
        assert!(refusal("file:///x#y").contains("fragment"));
    }

    #[test]
    fn percent_escape_refused() {
        assert!(refusal("file:///%2e%2e/x").contains("percent"));
    }

    #[test]
    fn nul_byte_refused() {
        assert!(refusal("file:///tm\0p/x").contains("NUL"));
    }

    #[test]
    fn https_refused_by_name() {
        assert_eq!(
            refusal("https://example.com/x"),
            "instar does not accept https:// inputs yet; pass a local path"
        );
    }

    #[test]
    fn scheme_case_is_folded_for_refusal() {
        assert!(refusal("HTTPS://example.com/x").contains("https://"));
    }

    #[test]
    fn unknown_scheme_refused_by_name() {
        assert!(refusal("gopher://example.com/x").contains("gopher://"));
    }

    #[test]
    fn plain_absolute_path() {
        path("/plain/path");
    }

    #[test]
    fn dot_relative_path() {
        path("./rel");
    }

    #[test]
    fn colon_without_slashes_is_a_path() {
        path("weird:name");
    }

    #[test]
    fn single_slash_after_colon_is_a_path() {
        path("file:/tmp/x");
    }

    #[test]
    fn digit_leading_scheme_is_a_path() {
        path("1http://x");
    }

    #[test]
    fn empty_argument_is_a_path() {
        path("");
    }

    /// A fetcher path that cannot be spawned.
    ///
    /// Used by the tests that assert an input is refused: with a fetcher that
    /// could never start, a refusal naming the input proves the check happens
    /// before the spawn rather than after it.
    const UNSPAWNABLE_FETCHER: &str = "/nonexistent/instar-fetch-that-is-never-spawned";

    /// How long after a drop a test waits for the child to be gone.
    const TEST_REAP_WINDOW: Duration = Duration::from_secs(5);

    #[test]
    fn a_staged_descriptor_is_clear_of_the_childs_numbers() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 64);
        let file = File::open(&path).expect("open the fixture");

        let staged = stage_clear_of_child_fds(file.as_fd()).expect("stage the descriptor");
        assert!(
            staged.as_raw_fd() >= FIRST_STAGING_FD,
            "a staged copy on descriptor {} is still in the way of the two the child is \
             given, so a dup2 onto one of them could close the other",
            staged.as_raw_fd()
        );

        // And it is a copy of the same file, not merely some descriptor: one
        // that read something else would have the child serving the wrong
        // bytes rather than failing.
        let staged_file = File::from(staged);
        let mut byte = [0u8; 1];
        FileExt::read_exact_at(&staged_file, &mut byte, 7).expect("read through the staged copy");
        assert_eq!(byte[0], pattern(7));
    }

    #[test]
    fn a_remote_read_matches_a_local_pread() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        // Not a multiple of any block size in play, so the last read of the
        // file is a partial one.
        write_fixture(&path, 70_001);
        let mut source = spawn_test_fetcher(&path);

        let local = File::open(&path).expect("open the fixture locally");
        for (offset, len) in [(0u64, 512usize), (512, 4096), (65_536, 4_465), (0, 70_001)] {
            let mut through_the_socket = vec![0u8; len];
            source
                .client_mut()
                .read_at(offset, &mut through_the_socket)
                .expect("the fetcher answers a read inside the file");
            let mut locally = vec![0u8; len];
            FileExt::read_exact_at(&local, &mut locally, offset).expect("pread the fixture");
            assert_eq!(
                through_the_socket, locally,
                "the {len} bytes at offset {offset} differ between the fetcher and a pread"
            );
        }
    }

    #[test]
    fn the_advertised_capacity_is_the_hosts_file_length() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 70_001);
        let source = spawn_fetcher_binary(&fetcher_binary(), &path, true).expect("spawn a fetcher");
        let length = std::fs::metadata(&path).expect("stat the fixture").len();
        assert_eq!(
            source.capacity(),
            length,
            "the capacity from the init reply disagrees with the host's own file length"
        );
    }

    #[test]
    fn the_child_holds_exactly_the_five_descriptors_it_needs() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 4096);
        let source = spawn_fetcher_binary(&fetcher_binary(), &path, true).expect("spawn a fetcher");

        // The whole set, not the absence of one descriptor: the failure this
        // guards against is the child holding something nobody meant to give
        // it, which an assertion about particular numbers would not see.
        let fds: BTreeSet<RawFd> = std::fs::read_dir(format!("/proc/{}/fd", source.pid()))
            .expect("a live fetcher has a /proc/<pid>/fd")
            .map(|entry| {
                entry
                    .expect("a /proc/<pid>/fd entry")
                    .file_name()
                    .to_string_lossy()
                    .parse::<RawFd>()
                    .expect("a descriptor is named by its number")
            })
            .collect();
        assert_eq!(
            fds,
            BTreeSet::from([0, 1, 2, CHILD_SOCKET_FD, CHILD_FILE_FD]),
            "the fetcher holds descriptors it was not given"
        );
    }

    /// The soft and hard limit `/proc/<pid>/limits` reports for `label`.
    ///
    /// The file is a fixed-width table whose first column is a label with
    /// spaces in it, so the line is found by its label and the two numbers
    /// are the first two fields of what is left.
    fn reported_limit(limits: &str, label: &str) -> (String, String) {
        let line = limits
            .lines()
            .find(|line| line.starts_with(label))
            .unwrap_or_else(|| panic!("/proc/<pid>/limits has no {label:?} line:\n{limits}"));
        let mut fields = line[label.len()..].split_whitespace();
        let soft = fields.next().expect("a soft limit").to_string();
        let hard = fields.next().expect("a hard limit").to_string();
        (soft, hard)
    }

    #[test]
    fn the_child_serves_under_the_limits_the_parent_set() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 4096);
        // Read of a fetcher that has completed its init exchange, so the
        // limits are asserted of a process that got far enough to serve
        // rather than of one that died on its way up.
        let mut source = spawn_fetcher_binary(&fetcher_binary(), &path, true)
            .expect("spawn a fetcher under the limits");
        let mut byte = [0u8; 1];
        source
            .client_mut()
            .read_at(7, &mut byte)
            .expect("a confined fetcher still answers a read");
        assert_eq!(byte[0], pattern(7));

        let limits = std::fs::read_to_string(format!("/proc/{}/limits", source.pid()))
            .expect("a live fetcher has a /proc/<pid>/limits");
        assert_eq!(
            reported_limit(&limits, "Max processes"),
            ("0".to_string(), "0".to_string()),
            "the fetcher can fork:\n{limits}"
        );
        assert_eq!(
            reported_limit(&limits, "Max core file size"),
            ("0".to_string(), "0".to_string()),
            "a crash would write the image's bytes to a core dump:\n{limits}"
        );
        assert_eq!(
            reported_limit(&limits, "Max open files"),
            (CHILD_MAX_FILES.to_string(), CHILD_MAX_FILES.to_string()),
            "the fetcher's descriptor ceiling is not the one it was given:\n{limits}"
        );
    }

    #[test]
    fn the_child_cannot_gain_privilege_by_exec() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 4096);
        let source = spawn_fetcher_binary(&fetcher_binary(), &path, true).expect("spawn a fetcher");

        let status = std::fs::read_to_string(format!("/proc/{}/status", source.pid()))
            .expect("a live fetcher has a /proc/<pid>/status");
        let line = status
            .lines()
            .find(|line| line.starts_with("NoNewPrivs:"))
            .expect("a kernel that reports NoNewPrivs");
        assert_eq!(
            line.split_whitespace().nth(1),
            Some("1"),
            "the fetcher runs without no_new_privs, so a setuid binary it exec'd could gain \
             privilege and it could not install a filter on itself: {line}"
        );
    }

    #[test]
    fn the_probe_reports_what_this_kernel_answers() {
        let probed = KernelConfinement::probe();

        // The same two questions, asked independently of the code under
        // test, so that a probe which answered from a constant or got the
        // argument order wrong disagrees here.
        // SAFETY: the version query takes a null attribute pointer and a
        // zero size by definition, creates nothing and returns the ABI.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        assert_eq!(
            probed.landlock_abi,
            u32::try_from(abi).ok().filter(|abi| *abi > 0),
            "the probe disagrees with this kernel's own landlock_create_ruleset version query \
             (which returned {abi})"
        );

        let action = libc::SECCOMP_RET_KILL_PROCESS;
        // SAFETY: the action-availability operation reads the u32 the third
        // argument points at and writes nothing.
        let avail = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_ACTION_AVAIL,
                0_usize,
                std::ptr::addr_of!(action),
            )
        };
        assert_eq!(
            probed.seccomp_kill,
            avail == 0,
            "the probe disagrees with this kernel's own SECCOMP_GET_ACTION_AVAIL (which \
             returned {avail})"
        );
    }

    /// How many probes the leak test makes.
    ///
    /// Many, because the question is asked of a process whose other tests
    /// are opening and closing descriptors of their own at the same time: a
    /// probe that created one descriptor each time leaves a mark far larger
    /// than that churn, where a single probe's leak would be lost in it.
    const PROBES_FOR_THE_LEAK_TEST: usize = 200;

    /// How much concurrent descriptor churn the leak test tolerates.
    ///
    /// The suite runs one test thread per core, and a test of this module
    /// holds a socketpair, an image and a child while it runs, so the
    /// descriptors other tests hold during this one's measurement are a
    /// two-figure number on a sixteen-core machine and larger on a bigger
    /// one. The allowance is set well above that and still far below the
    /// mark a probe leaking one descriptor each time would leave.
    const CHURN_ALLOWANCE: usize = 64;

    #[test]
    fn probing_confines_nothing_and_opens_nothing() {
        let before = own_descriptor_count();
        let mode_before = own_seccomp_mode();
        for _ in 0..PROBES_FOR_THE_LEAK_TEST {
            let _ = KernelConfinement::probe();
        }
        let after = own_descriptor_count();

        assert_eq!(
            own_seccomp_mode(),
            mode_before,
            "the probe changed the seccomp state of the privileged side, which is the process \
             holding the user's credentials; asking what the kernel can do must not be a way of \
             confining the asker"
        );
        assert!(
            after <= before + CHURN_ALLOWANCE,
            "{PROBES_FOR_THE_LEAK_TEST} probes took this process from {before} descriptors to \
             {after}, so the probe leaks one; a leaked descriptor crosses the fork into a \
             fetcher whose whole descriptor set is accounted for"
        );
    }

    /// This process's own seccomp mode.
    ///
    /// Compared before and against after rather than against zero, because
    /// it is not zero everywhere this runs: the unit tests run inside a
    /// container whose runtime has already installed a filter of its own, so
    /// the mode reads as filtered before instar does anything. That is the
    /// reason the layer probe does not ask this question of the kernel --
    /// it describes the asker, not what a child could install -- and the
    /// property worth asserting is that asking changed nothing.
    fn own_seccomp_mode() -> libc::c_int {
        // SAFETY: PR_GET_SECCOMP takes no further argument and only reports
        // the calling thread's own seccomp mode.
        unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
    }

    /// How many descriptors this process holds.
    fn own_descriptor_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("this process has a /proc/self/fd")
            .count()
    }

    #[test]
    fn the_argument_names_every_layer_the_kernel_offers() {
        let both = KernelConfinement {
            landlock_abi: Some(6),
            seccomp_kill: true,
        };
        assert_eq!(both.confine_argument(), "--confine=landlock,seccomp");

        let filesystem_only = KernelConfinement {
            landlock_abi: Some(1),
            seccomp_kill: false,
        };
        assert_eq!(filesystem_only.confine_argument(), "--confine=landlock");

        let syscalls_only = KernelConfinement {
            landlock_abi: None,
            seccomp_kill: true,
        };
        assert_eq!(syscalls_only.confine_argument(), "--confine=seccomp");
    }

    #[test]
    fn a_kernel_that_offers_nothing_is_still_asked_explicitly() {
        let neither = KernelConfinement {
            landlock_abi: None,
            seccomp_kill: false,
        };
        assert_eq!(
            neither.confine_argument(),
            "--confine=none",
            "a kernel with no layers has to be named as such, so that a lost argument cannot \
             read as a run nobody asked to confine"
        );
    }

    #[test]
    fn the_report_claims_a_policy_only_where_the_kernel_can_provide_it() {
        let both = KernelConfinement {
            landlock_abi: Some(6),
            seccomp_kill: true,
        };
        let applied = both.report();
        assert_eq!(applied.len(), 2, "one line per layer: {applied:?}");
        assert!(
            applied[0].contains(LAYER_LANDLOCK) && applied[0].contains("ABI 6"),
            "the landlock line does not say what was applied: {:?}",
            applied[0]
        );
        assert!(
            applied[0].contains(LANDLOCK_APPLIED),
            "the landlock line does not say the fetcher is confined by it, which is what a \
             completed init exchange proves: {:?}",
            applied[0]
        );
        assert!(
            applied[1].contains(LAYER_SECCOMP),
            "the seccomp line does not name the layer: {:?}",
            applied[1]
        );
        assert!(
            applied[1].contains(SECCOMP_APPLIED),
            "the seccomp line does not say the fetcher is confined by it, which is what a \
             completed init exchange proves: {:?}",
            applied[1]
        );

        let neither = KernelConfinement {
            landlock_abi: None,
            seccomp_kill: false,
        };
        let refused = neither.report();
        assert_eq!(refused.len(), 2, "one line per layer: {refused:?}");
        for (line, layer) in refused.iter().zip([LAYER_LANDLOCK, LAYER_SECCOMP]) {
            assert!(
                line.contains(layer) && line.contains("without"),
                "a layer this kernel cannot provide is not reported as missing: {line:?}"
            );
            assert!(
                !line.contains(LANDLOCK_APPLIED) && !line.contains(SECCOMP_APPLIED),
                "a kernel that cannot provide the layer is reported as though the fetcher had \
                 been confined by it anyway: {line:?}"
            );
        }

        // Each claim belongs to its own layer, so a kernel with one and not
        // the other must be told so line by line rather than all or nothing.
        let filesystem_only = KernelConfinement {
            landlock_abi: Some(1),
            seccomp_kill: false,
        }
        .report();
        assert!(
            filesystem_only[0].contains(LANDLOCK_APPLIED)
                && !filesystem_only[1].contains(SECCOMP_APPLIED),
            "a kernel with only the filesystem layer is misreported: {filesystem_only:?}"
        );
        let syscalls_only = KernelConfinement {
            landlock_abi: None,
            seccomp_kill: true,
        }
        .report();
        assert!(
            !syscalls_only[0].contains(LANDLOCK_APPLIED)
                && syscalls_only[1].contains(SECCOMP_APPLIED),
            "a kernel with only the syscall layer is misreported: {syscalls_only:?}"
        );
    }

    #[test]
    fn dropping_the_source_reaps_the_child() {
        let dir = tempdir().expect("a temporary directory");
        let path = dir.path().join("image.raw");
        write_fixture(&path, 4096);
        let source = spawn_fetcher_binary(&fetcher_binary(), &path, true).expect("spawn a fetcher");
        let pid = source.pid();

        let dropped_at = Instant::now();
        drop(source);
        let reap_took = dropped_at.elapsed();
        assert!(
            reap_took < REAP_GRACE,
            "the reap took {reap_took:?}, the whole grace period, so the fetcher (pid {pid}) \
             had to be killed instead of exiting when its socket closed"
        );

        // The pid is free once it has been waited for, so in principle
        // something could take it; nothing in this process forks while this
        // test runs, and the window is microseconds.
        let signal_pid = libc::pid_t::try_from(pid).expect("a pid fits a pid_t");
        let deadline = Instant::now() + TEST_REAP_WINDOW;
        loop {
            // SAFETY: signal 0 makes the permission checks and delivers
            // nothing, so this only asks whether the pid still exists.
            let ret = unsafe { libc::kill(signal_pid, 0) };
            if ret < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the fetcher (pid {pid}) was still there {TEST_REAP_WINDOW:?} after its \
                 source was dropped"
            );
            std::thread::sleep(REAP_POLL);
        }
    }

    #[test]
    fn a_fifo_is_refused_before_anything_is_spawned() {
        let dir = tempdir().expect("a temporary directory");
        let fifo = dir.path().join("pipe");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).expect("a path without a NUL");
        // SAFETY: the path is a NUL-terminated C string that outlives the
        // call, and the result is checked.
        let made = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo failed: {}", io::Error::last_os_error());

        // Reaching this with a fetcher that cannot be spawned is the point:
        // the refusal has to come from the input, not from the child.
        let err = spawn_fetcher_binary(Path::new(UNSPAWNABLE_FETCHER), &fifo, true)
            .expect_err("a FIFO cannot be served");
        assert!(
            err.to_string().contains("not a regular file"),
            "a FIFO was refused for the wrong reason: {err}"
        );
    }

    #[test]
    fn a_directory_is_refused_before_anything_is_spawned() {
        let dir = tempdir().expect("a temporary directory");
        let err = spawn_fetcher_binary(Path::new(UNSPAWNABLE_FETCHER), dir.path(), true)
            .expect_err("a directory cannot be served");
        assert!(
            err.to_string().contains("not a regular file"),
            "a directory was refused for the wrong reason: {err}"
        );
    }

    #[test]
    fn a_missing_input_is_refused_naming_the_path() {
        let dir = tempdir().expect("a temporary directory");
        let absent = dir.path().join("absent.raw");
        let err = spawn_fetcher_binary(Path::new(UNSPAWNABLE_FETCHER), &absent, true)
            .expect_err("a missing file cannot be served");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains(&absent.display().to_string()),
            "the refusal does not name the input: {err}"
        );
    }
}
