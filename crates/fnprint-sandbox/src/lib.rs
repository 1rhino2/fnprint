//! Process jail for the part of fnprint that touches untrusted binaries.
//!
//! The doctrine is OpenSSH's: assume unicorn/capstone/sqlite get popped by a
//! crafted input and make that useless. Before the worker reads a single byte
//! of the target it drops into a jail: hard resource limits, no_new_privs, and
//! two stacked seccomp filters. The catastrophic syscalls (exec, ptrace, the
//! socket family, module/kexec/bpf, mount/chroot/namespace, the setuid family)
//! hard-kill the process; anything else not on the small allow set fails soft
//! with EPERM. A popped worker can compute in its own address space but cannot
//! open a file, touch the network, or exec anything. It can still spawn threads
//! (unicorn/qemu needs to), but a fork only yields another copy of this same
//! jail, and with execve killed that copy can't become anything else.
//!
//! Linux only. On any other OS `lock_down_worker` returns Err so the caller
//! fails closed (no jail, no untrusted work) unless the user opted out.

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result};
    use std::collections::BTreeMap;

    use seccompiler::{
        apply_filter_all_threads, BpfProgram, SeccompAction, SeccompFilter, TargetArch,
    };

    // hard ceilings the worker can't exceed even if an emulation cap is missed.
    const MAX_CPU_SECS: u64 = 120; // wall-CPU backstop to the instr cap
    const GIB: u64 = 1 << 30;

    // RLIMIT_AS bounds VIRTUAL address space, and every parallel unicorn instance
    // reserves a big (mostly non-resident) TCG translation buffer in the shared
    // process space. so the cap has to scale with the worker thread count or
    // qemu can't allocate its code buffer. this is a loader-bomb backstop, not
    // the primary memory guard (the loader's own MAX_TOTAL_MEM caps what actually
    // gets touched); virtual space is cheap, so we budget generously per thread.
    fn addr_space_cap() -> u64 {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(8);
        threads.saturating_mul(2 * GIB).saturating_add(8 * GIB)
    }

    fn set_rlimits() -> Result<()> {
        use rustix::process::{setrlimit, Resource, Rlimit};
        let cap = |current: u64| Rlimit {
            current: Some(current),
            maximum: Some(current),
        };
        // no core dumps (a core would spill the parsed bytes to disk), bounded
        // virtual memory, bounded cpu, few fds. two deliberate non-clamps:
        //  - NPROC: unicorn/qemu spawns helper threads during emulation and NPROC
        //    counts every thread, so clamping it breaks emulation. containment
        //    comes from seccomp killing execve, not from blocking thread create.
        //  - FSIZE: the worker can't open() a file at all (openat is EPERM-denied
        //    below), so it can't write to disk regardless. clamping FSIZE to 0
        //    only breaks qemu writing a diagnostic to an inherited stderr that
        //    happens to be a regular file, which is a legitimate, parent-chosen
        //    fd, not a disk-write the worker opened.
        setrlimit(Resource::Core, cap(0)).context("rlimit core")?;
        setrlimit(Resource::As, cap(addr_space_cap())).context("rlimit as")?;
        setrlimit(Resource::Cpu, cap(MAX_CPU_SECS)).context("rlimit cpu")?;
        setrlimit(Resource::Nofile, cap(64)).context("rlimit nofile")?;
        Ok(())
    }

    // the jail is two stacked seccomp filters. the kernel evaluates both on
    // every syscall and takes the most severe result, which lets us combine:
    //
    //   allow-filter:  the listed syscalls -> ALLOW, everything else -> EPERM.
    //   kill-filter:   the catastrophic syscalls -> KILL_PROCESS, else -> ALLOW.
    //
    // net effect: allowed set runs; the catastrophic set (exec/ptrace/net/module/
    // namespace/priv) hard-kills the process as a tripwire; anything else that
    // isn't explicitly allowed (e.g. qemu's best-effort openat on /sys and /proc)
    // fails soft with EPERM instead of crashing the analysis. open/openat land in
    // that soft-deny bucket: a popped worker still can't read a file, it just
    // gets EPERM rather than SIGSYS, which is what keeps qemu's benign probes
    // from taking the whole run down.

    // the syscalls the worker legitimately needs to SUCCEED: read/write on the
    // inherited pipes, the memory syscalls unicorn's TCG JIT and our allocator
    // use, thread creation + futex for rayon and qemu's helper threads,
    // scheduling, signals, time, randomness, and exit.
    fn allowed_syscalls() -> Vec<i64> {
        vec![
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_close,
            libc::SYS_lseek,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_brk,
            libc::SYS_futex,
            // thread creation for rayon + qemu helper threads. execve is NOT
            // allowed, so a clone/fork can only ever produce another jailed copy.
            // SYS_clone is added separately in build_allow_filter with a flag
            // condition (no CLONE_NEW*). clone3 stays unconditional: its flags
            // live in a struct behind a pointer that BPF cannot dereference.
            libc::SYS_clone3,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_rseq,
            libc::SYS_set_tid_address,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_setaffinity,
            libc::SYS_getrandom,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_sigaltstack,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_tgkill, // abort() path
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_restart_syscall,
            // qemu names its helper threads; harmless, no privilege effect since
            // no_new_privs is already latched.
            libc::SYS_prctl,
            libc::SYS_membarrier,
        ]
    }

    // the catastrophic set: any of these is an unambiguous escape attempt, never
    // something qemu/rayon does in normal emulation, so we hard-kill on them.
    // exec (spawn a shell), ptrace / process_vm_* (inspect or hijack another
    // proc), the whole socket family (network exfil / c2), module + kexec + bpf +
    // perf (kernel), mount / chroot / pivot_root / unshare / setns (namespace
    // escape), the setuid/setgid family + keyrings (privilege), and a few more.
    // the x32 ABI enters the same kernel with bit 30 (__X32_SYSCALL_BIT) set on
    // the syscall number. our worker is pure native x86-64 and never issues an x32
    // call, so for every catastrophic native syscall we also kill its x32 form.
    // most x32 numbers are native|bit, but the struct-passing calls (execve,
    // ptrace, the *msg family, kexec_load, process_vm_*) have dedicated numbers in
    // the 512+ range, so we add those explicitly too. adding a number that is not
    // actually a live x32 syscall is a harmless no-op (the worker issues none); a
    // miss would only drop an x32 catastrophic call onto the allow filter's EPERM
    // instead of SIGSYS, so it stays contained either way. this only sharpens the
    // tripwire, it cannot break the worker.
    const X32_BIT: i64 = 0x4000_0000;
    // dedicated x32 numbers (pre-bit) for the struct-passing calls in our set,
    // from the kernel x32 table.
    const X32_DEDICATED: &[i64] = &[
        520, // execve
        545, // execveat
        521, // ptrace
        539, // process_vm_readv
        540, // process_vm_writev
        518, // sendmsg
        538, // sendmmsg
        517, // recvfrom
        519, // recvmsg
        537, // recvmmsg
        528, // kexec_load
    ];

    fn kill_syscalls() -> Vec<i64> {
        let native = vec![
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_recvmmsg,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_chroot,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setreuid,
            libc::SYS_setregid,
            libc::SYS_setresuid,
            libc::SYS_setresgid,
            libc::SYS_setfsuid,
            libc::SYS_setfsgid,
            libc::SYS_setgroups,
            libc::SYS_add_key,
            libc::SYS_keyctl,
            libc::SYS_request_key,
            libc::SYS_open_by_handle_at,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_iopl,
            libc::SYS_ioperm,
            // async-io and fault-handling primitives a popped worker has no legit
            // use for. they were already contained (EPERM soft-deny by default),
            // but qemu/rayon never issue them, so promote them to a hard-kill
            // tripwire: an attempt is an unambiguous escape probe, not noise.
            // io_uring gives a shared submission ring that can sidestep per-syscall
            // filtering; userfaultfd hands page-fault handling to userspace (a
            // known exploit primitive); pidfd_getfd steals fds from another proc.
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_userfaultfd,
            libc::SYS_pidfd_getfd,
        ];
        // kill the x32 form of every native catastrophic call, plus the dedicated
        // x32 numbers for the struct-passing ones.
        let mut all = native;
        let x32: Vec<i64> = all.iter().map(|n| n | X32_BIT).collect();
        all.extend(x32);
        all.extend(X32_DEDICATED.iter().map(|n| n | X32_BIT));
        all
    }

    // CLONE_NEW* namespace-creation flags. clone with any of these makes a new
    // user/mount/net/etc namespace, which is the same escape-surface expansion we
    // hard-kill unshare/setns for. real thread creation (rayon, qemu) never sets
    // them, so gating clone on their absence costs legit code nothing. mask =
    // NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET.
    const CLONE_NEW_MASK: u64 = 0x7E02_0000;

    // clone flags are arg0 on x86_64. allow the call only when none of the
    // namespace bits are set; otherwise it falls through to the filter default
    // (EPERM), so a popped worker can spawn threads but not create a namespace.
    fn clone_flag_rule() -> Result<seccompiler::SeccompRule> {
        use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
        let cond = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(CLONE_NEW_MASK),
            0,
        )
        .context("clone flag condition")?;
        SeccompRule::new(vec![cond]).context("clone flag rule")
    }

    fn build_filter(
        syscalls: Vec<i64>,
        matched: SeccompAction,
        default: SeccompAction,
    ) -> Result<BpfProgram> {
        let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            syscalls.into_iter().map(|nr| (nr, vec![])).collect();
        let filter = SeccompFilter::new(rules, default, matched, TargetArch::x86_64)
            .context("build seccomp filter")?;
        filter.try_into().context("compile seccomp filter")
    }

    // the allow filter: every allowed syscall unconditionally, plus SYS_clone
    // gated on clone_flag_rule (no namespace bits). default is EPERM soft-deny.
    fn build_allow_filter(default: SeccompAction) -> Result<BpfProgram> {
        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = allowed_syscalls()
            .into_iter()
            .map(|nr| (nr, vec![]))
            .collect();
        rules.insert(libc::SYS_clone, vec![clone_flag_rule()?]);
        let filter = SeccompFilter::new(rules, default, SeccompAction::Allow, TargetArch::x86_64)
            .context("build allow filter")?;
        filter.try_into().context("compile allow filter")
    }

    fn install_seccomp() -> Result<()> {
        // EPERM(1): the soft-deny errno for anything not explicitly allowed.
        let eperm = SeccompAction::Errno(1);
        let allow = build_allow_filter(eperm)?;
        let kill = build_filter(
            kill_syscalls(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
        )?;
        // most-severe-wins: the kernel keeps every installed filter and runs all
        // of them per syscall, so runtime order is irrelevant. INSTALL order is
        // not: TSYNC needs the seccomp() syscall, which the EPERM-default allow
        // filter does not permit, so the allow filter must go on SECOND while the
        // kill filter (default-allow) still lets seccomp() through. if the second
        // apply fails, lock_down_worker returns Err and the worker aborts before
        // reading any input, so the transient kill-only posture never sees
        // untrusted bytes (fail-closed is the caller's abort, not filter order).
        apply_filter_all_threads(&kill).context("apply kill filter")?;
        install_program(&allow)
    }

    fn install_program(program: &BpfProgram) -> Result<()> {
        // TSYNC: apply to every thread in the process, not just this one. the
        // rayon pool and qemu's helper threads already exist (warmed pre-jail),
        // and the untrusted emulation runs ON those threads, so a main-thread-
        // only filter would leave the actual attack surface unjailed.
        apply_filter_all_threads(program).context("apply seccomp filter")?;
        Ok(())
    }

    pub fn lock_down_worker() -> Result<()> {
        set_rlimits()?;
        // required before SECCOMP_SET_MODE_FILTER without CAP_SYS_ADMIN, and it
        // also means a jailed exploit can't gain privs via a setuid helper.
        rustix::thread::set_no_new_privs(true).context("set no_new_privs")?;
        install_seccomp()?;
        Ok(())
    }
}

/// Install the worker jail: resource limits, no_new_privs, and the two stacked
/// seccomp filters (hard-kill on the catastrophic syscalls, EPERM soft-deny on
/// anything else not explicitly allowed). Call this in the worker before reading
/// any untrusted input. Returns Err on non-Linux or if any step fails, so the
/// caller can fail closed.
#[cfg(target_os = "linux")]
pub fn lock_down_worker() -> anyhow::Result<()> {
    linux::lock_down_worker()
}

#[cfg(not(target_os = "linux"))]
pub fn lock_down_worker() -> anyhow::Result<()> {
    anyhow::bail!("process sandbox is only implemented on linux")
}
