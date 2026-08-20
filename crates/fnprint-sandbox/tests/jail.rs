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
