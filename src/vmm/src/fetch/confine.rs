//! What confinement the running kernel can give the fetcher, and the limits
//! the privileged side sets on it before it starts.
//!
//! The half of the fetcher's sandbox that runs in instar rather than in
//! `instar-fetch`: the probe that decides which layers to name on the
//! fetcher's command line, the report of what was applied, and the resource
//! limits the parent sets between the `fork` and the `exec`. The parent
//! module's module documentation says why the confinement is split this way.

use std::io;

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
/// every test in the parent module spawns the real binary with the real argument, so a
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
pub(super) const CHILD_MAX_FILES: libc::rlim_t = 8;

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
pub(super) struct KernelConfinement {
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
    pub(super) fn probe() -> Self {
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
    pub(super) fn confine_argument(&self) -> String {
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
    pub(super) fn report(&self) -> Vec<String> {
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
pub(super) fn set_hard_limit(
    resource: libc::__rlimit_resource_t,
    value: libc::rlim_t,
) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    /// The suite runs one test thread per core, and a test of the parent
    /// module holds a socketpair, an image and a child while it runs, so the
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
}
