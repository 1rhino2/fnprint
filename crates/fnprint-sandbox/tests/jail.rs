// sandbox self-test: prove the jail actually kills a forbidden syscall and lets
// the allowed compute path through. drives the `jailbreak` example as a child
// with a pipe on stdout (a pipe, not a file, so RLIMIT_FSIZE=0 doesn't fire on
// the worker's own result writes). the real worker returns results over a pipe
// too, so this matches production.
#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

fn run(arg: &str) -> std::process::ExitStatus {
    // cargo hands the example path via CARGO_BIN_EXE_ only for [[bin]], not
    // examples, so build+locate it by convention next to the test binary.
    let exe = env!("CARGO_BIN_EXE_jailbreak_probe");
    Command::new(exe)
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn jail probe")
}

#[test]
fn forbidden_syscall_is_killed() {
    let st = run("socket");
    // seccomp SECCOMP_RET_KILL_PROCESS delivers SIGSYS (31). must not exit clean.
    assert_eq!(
        st.signal(),
        Some(libc::SIGSYS),
        "socket() should be SIGSYS-killed"
    );
    assert!(!st.success());
}

#[test]
fn allowed_path_runs() {
    let st = run("ok");
    assert!(
        st.success(),
        "compute+pipe-write path must survive the jail"
    );
}

#[test]
fn file_open_is_denied_but_not_killed() {
    // opening a real file must fail (EPERM soft-deny) so a popped worker can't
    // read secrets, but it must NOT kill the process the way a catastrophic
    // syscall does. the probe exits 0 iff the open returned an error.
    let st = run("open");
    assert_eq!(st.signal(), None, "file open must not hard-kill the worker");
    assert!(st.success(), "probe exits 0 only when the open was denied");
}

#[test]
fn exec_mmap_is_denied() {
    // the core no-JIT guarantee: a worker cannot map an executable page, so a
    // popped emulator can't run code it generates. denied soft (EPERM), and a
    // plain read/write mmap still works. exit 3 = exec page granted (hole),
    // 4 = we broke non-exec mmap.
    let st = run("mmap_exec");
    assert_eq!(st.signal(), None, "PROT_EXEC mmap must not hard-kill");
    assert_eq!(
        st.code(),
        Some(0),
        "PROT_EXEC mmap must be denied while plain mmap still works"
    );
}

#[test]
fn exec_mprotect_is_denied() {
    // the other half: a worker cannot flip an existing page to executable.
    let st = run("mprotect_exec");
    assert_eq!(st.signal(), None, "PROT_EXEC mprotect must not hard-kill");
    assert_eq!(
        st.code(),
        Some(0),
        "flipping a page to executable must be denied"
    );
}

#[test]
fn thread_creation_survives_clone3_enosys() {
    // clone3 is ENOSYS'd, so thread creation must fall back to the flag-gated
    // clone. if the fallback broke, this hangs or the probe exits 5.
    let st = run("thread");
    assert_eq!(
        st.signal(),
        None,
        "thread spawn must not hard-kill the worker"
    );
    assert_eq!(
        st.code(),
        Some(0),
        "spawning a thread must still work after clone3 is ENOSYS'd"
    );
}

#[test]
fn set_affinity_is_denied() {
    // FNP-001: sched_setaffinity was dropped from the allow set. it takes a target
    // pid, so an allowed one lets a popped worker pin any same-uid process. must
    // soft-deny (EPERM), not hard-kill and not succeed.
    let st = run("affinity");
    assert_eq!(st.signal(), None, "sched_setaffinity must not hard-kill");
    assert_eq!(
        st.code(),
        Some(0),
        "sched_setaffinity must be EPERM-denied inside the jail"
    );
}

#[test]
fn sibling_kill_via_tgkill_is_denied() {
    // FNP-001: tgkill was dropped from the allow set. its tgid/tid are runtime args
    // BPF can't pin to self, so an allowed tgkill is a cross-process kill. must
    // soft-deny (EPERM), not hard-kill and not go through.
    let st = run("tgkill");
    assert_eq!(st.signal(), None, "tgkill must not hard-kill");
    assert_eq!(
        st.code(),
        Some(0),
        "tgkill must be EPERM-denied inside the jail"
    );
}

#[test]
fn preinput_closes_inherited_fds() {
    // FNP-006: harden_worker_preinput closes every inherited fd above std{in,out,
    // err}. the probe opens one, arms the hardening, and checks it's gone.
    let st = run("harden_fds");
    assert_eq!(st.signal(), None, "fd-close probe must not be killed");
    assert_eq!(
        st.code(),
        Some(0),
        "inherited fd above 2 must be closed by harden_worker_preinput"
    );
}

#[test]
fn preinput_arms_pdeathsig() {
    // FNP-006: harden_worker_preinput arms PR_SET_PDEATHSIG=SIGKILL so an orphaned
    // worker dies with its parent. the probe reads it back.
    let st = run("pdeathsig");
    assert_eq!(st.signal(), None, "pdeathsig probe must not be killed");
    assert_eq!(
        st.code(),
        Some(0),
        "harden_worker_preinput must arm pdeathsig to SIGKILL"
    );
}

#[test]
fn clone3_userns_is_enosys() {
    // clone3(CLONE_NEWUSER) must come back ENOSYS (not success, not EPERM). ENOSYS
    // is what shuts off userns creation via clone3 while still letting glibc fall
    // back to the flag-gated clone. exit 3 = a child/namespace was created (hole),
    // 4 = wrong errno (EPERM would break thread creation).
    let st = run("userns");
    assert_eq!(st.signal(), None, "clone3 userns probe must not hard-kill");
    assert_eq!(
        st.code(),
        Some(0),
        "clone3(CLONE_NEWUSER) must be denied as ENOSYS"
    );
}
