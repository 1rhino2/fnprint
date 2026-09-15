// `fnprint <cmd> ... | head` closes our stdout before we're done printing. that
// must exit 0 and quietly, not SIGABRT with a panic banner (panic=abort +
// println! on EPIPE). runs the real binary against the default sandboxed path.

use std::process::{Command, Stdio};

fn empty_db(dir: &std::path::Path, name: &str) -> String {
    let p = dir.join(name);
    let path = p.to_str().unwrap().to_string();
    // open() creates the schema, so an empty corpus is a valid `match` input
    fnprint_db::Db::open(&path).unwrap();
    path
}

fn run_into_closed_pipe(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fnprint"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // hang up on stdout before the child gets to its first line. if the child
    // somehow wins the race the lines just land in the pipe buffer and the run
    // still has to succeed, so this can't flake, it only loses coverage.
    drop(child.stdout.take());
    let stderr = child.stderr.take().unwrap();
    let status = child.wait().unwrap();
    let mut err = Vec::new();
    std::io::Read::read_to_end(&mut { stderr }, &mut err).unwrap();
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: err,
    }
}

#[test]
fn human_table_into_closed_pipe_exits_clean() {
    let dir = std::env::temp_dir().join(format!("fnprint-pipe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = empty_db(&dir, "a.db");
    let b = empty_db(&dir, "b.db");
    let out = run_into_closed_pipe(&["match", &a, &b]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status {:?}, stderr: {err}",
        out.status
    );
    assert!(!err.contains("panicked"), "panic banner on stderr: {err}");
    assert!(
        !err.contains("Broken pipe"),
        "EPIPE leaked to stderr: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn completions_into_closed_pipe_exits_clean() {
    let out = run_into_closed_pipe(&["completions", "bash"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status {:?}, stderr: {err}",
        out.status
    );
    assert!(!err.contains("panicked"), "panic banner on stderr: {err}");
}
