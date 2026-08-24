use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fnprint_core::{
    dump_traces, eval, index_bytes, index_bytes_shard, match_by_name, query_corpus, source_str,
    triage, warm_pool, EffectTrace, IndexedFunc, Verdict, MIN_COMPLEXITY,
};
use fnprint_db::{Db, FuncRec, MemCorpus};
use fnprint_emu::Config;
use fnprint_loader::FuncSource;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// hard caps on the privsep pipe so neither side can be pushed into an unbounded
// alloc. an ELF bigger than this we refuse; a worker reply bigger than this we
// treat as a compromised worker.
const MAX_INPUT: u64 = 512 << 20; // 512 MiB
                                  // the reply is fingerprints, far smaller than the input binary, so cap it well
                                  // below the input. this wire cap (enforced by the take(MAX_REPLY+1) read) is
                                  // the only bound on the reply: the parent sets no RLIMIT_AS on itself (setrlimit
                                  // only runs inside the jailed worker), so nothing else catches an oversized
                                  // decode. a compromised worker can amplify the wire size on decode: postcard
                                  // varint-decodes each zero u64 (1 wire byte) into 8 resident bytes, and the
                                  // Vec<String>/Vec<FuncRec> shapes add per-element String/struct overhead on top,
                                  // so the real worst case is ~24x: a full 128 MiB reply can balloon to roughly
                                  // 3 GiB transient in the parent before validate_* rejects it. that is the
                                  // accepted residual here - a compromised-worker-only transient spike (the jail
                                  // already held to let it get popped), not a persistent leak. we keep the cap at
                                  // 128 MiB rather than lower it (a smaller cap would false-reject a legit large
                                  // binary's prints) and rather than add a parent RLIMIT_AS (which would risk
                                  // false-killing a legitimately large in-memory corpus build).
const MAX_REPLY: u64 = 128 << 20;

// the hidden argv token the parent re-execs itself with to become the jailed
// worker. anything the emulator touches runs behind it.
const WORKER_TOKEN: &str = "__worker";

// wall-clock backstop on the whole worker interaction. the worker has its own
// deterministic per-function caps plus an RLIMIT_CPU, but neither bounds the
// PARENT: a worker wedged not consuming CPU, or one that forked a subtree before
// the jail latched, would otherwise block the parent's read/wait forever. past
// this deadline the parent SIGKILLs the worker's whole process group.
//
// it MUST sit strictly above the worker's own CPU budget so RLIMIT_CPU (the
// intended CPU bound) always fires first: the worker jail sets
// RLIMIT_CPU = 120 * threads cpu-seconds, and emulation is serialized behind a
// lock, so a legit large index can burn up to ~120 * threads WALL seconds. a
// flat wall cap below that would false-abort a big index on a many-core box. so
// scale with the same thread count and add margin; this only ever catches a true
// hang (a blocked syscall consuming no CPU, which RLIMIT_CPU can never catch).
fn worker_deadline() -> Duration {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(8);
    Duration::from_secs(120u64.saturating_mul(threads).saturating_add(300))
}

// once the reply is in hand the worker only has to unwind and exit (milliseconds).
// bound the reap anyway: a worker that closed stdout (giving us EOF) then made a
// blocking syscall burns no CPU, so RLIMIT_CPU can't catch it and a plain wait()
// would hang the parent forever. reachable only via a pre-jail compromise, but the
// parent should never be hangable.
const POST_REPLY_GRACE: Duration = Duration::from_secs(30);

// reap the worker without ever hanging. poll for exit up to `grace`, then SIGKILL
// the whole group and reap. kill-before-reap: the pid is still valid at the kill,
// so there is no window where we could signal a reused pid/pgid.
fn reap_bounded(
    child: &mut std::process::Child,
    pgid: Option<rustix::process::Pid>,
    grace: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let until = std::time::Instant::now() + grace;
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        if std::time::Instant::now() >= until {
            if let Some(pgid) = pgid {
                let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::Kill);
            }
            return child.wait();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// what the jailed worker sends back over stdout. the parent treats every field
// as untrusted (a popped worker can put anything here): entry addresses and
// names are only ever printed escaped or written to the db, never used to index.
#[derive(Serialize, Deserialize)]
enum WorkerReply {
    IndexOk(Vec<IndexedFunc>),
    DumpOk(Vec<String>),
    // decoded corpus rows from the jailed db-reader. the parent rebuilds the LSH
    // index from these in memory; it never runs sqlite on the .db itself.
    DbOk(Vec<FuncRec>),
    Err(String),
}

#[derive(Parser)]
#[command(
    name = "fnprint",
    version,
    about = "behavioral function fingerprinting"
)]
struct Cli {
    /// run the emulator in-process without the sandbox. unsafe: only for a
    /// platform that can't jail, or debugging. default is always jailed.
    #[arg(long, global = true)]
    no_sandbox: bool,
    /// output format. human (default) is the readable tables; json is a stable
    /// machine schema for scripting/plugins; r2 emits a rizin script (query/triage
    /// only) that renames matched functions.
    #[arg(long, value_enum, default_value_t = Format::Human, global = true)]
    format: Format,
    #[command(subcommand)]
    cmd: Cmd,
}

// json/r2 consumers key off this; bump only when a schema shape changes, so it's
// independent of the fingerprint format.
const OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    Human,
    Json,
    R2,
}

#[derive(Subcommand)]
enum Cmd {
    /// fingerprint every function in a binary, optionally into a db
    Index {
        binary: String,
        #[arg(short, long)]
        out: Option<String>,
    },
    /// diff two binaries (or dbs) by behavior, the n-day view
    Match { a: String, b: String },
    /// name unknown functions in a binary using a corpus db
    Query {
        target: String,
        #[arg(long)]
        corpus: String,
        #[arg(long, default_value_t = 0.7)]
        threshold: f64,
    },
    /// accuracy metrics between two builds, using symbol names as ground truth
    Eval { a: String, b: String },
    /// n-day triage: rank a target against known-vulnerable and patched corpora
    Triage {
        target: String,
        #[arg(long)]
        vuln: String,
        #[arg(long)]
        patched: String,
        /// a side has to be at least this similar to count as a real lead
        #[arg(long, default_value_t = 0.6)]
        min_sim: f64,
        /// how far the two sides must separate before we commit to a verdict
        #[arg(long, default_value_t = 0.08)]
        margin: f64,
    },
    /// print the recorded effect trace for one function (debugging)
    Dump { binary: String, func: String },
}

fn main() -> Result<()> {
    // privsep worker entrypoint. the parent re-execs itself as
    // `fnprint __worker <op> [func]`; the worker jails itself, reads the
    // untrusted binary from stdin, and writes a postcard reply to stdout. we
    // intercept it before clap so the worker protocol stays out of the cli.
    let mut raw = std::env::args();
    let _bin = raw.next();
    if raw.next().as_deref() == Some(WORKER_TOKEN) {
        let op = raw.next().unwrap_or_default();
        let func = raw.next();
        return worker_main(&op, func.as_deref());
    }

    let cli = Cli::parse();
    let ns = cli.no_sandbox;
    let fmt = cli.format;
    match cli.cmd {
        Cmd::Index { binary, out } => cmd_index(&binary, out.as_deref(), ns, fmt),
        Cmd::Match { a, b } => cmd_match(&a, &b, ns, fmt),
        Cmd::Query {
            target,
            corpus,
            threshold,
        } => cmd_query(&target, &corpus, threshold, ns, fmt),
        Cmd::Eval { a, b } => cmd_eval(&a, &b, ns, fmt),
        Cmd::Triage {
            target,
            vuln,
            patched,
            min_sim,
            margin,
        } => cmd_triage(&target, &vuln, &patched, min_sim, margin, ns, fmt),
        Cmd::Dump { binary, func } => cmd_dump(&binary, &func, ns, fmt),
    }
}

// ---- jailed worker ----------------------------------------------------------

fn worker_main(op: &str, func: Option<&str>) -> Result<()> {
    // spin up the rayon pool before we jail so the parallel index is warm and
    // doesn't pay thread-spawn cost under the sandbox.
    warm_thread_pool();

    // fail-closed: if the jail won't install, we do not read or touch the input.
    fnprint_sandbox::lock_down_worker().context("worker could not enter sandbox")?;

    // read the untrusted binary from stdin (read is allowed inside the jail, so
    // the worker never needs open()). bounded so a huge stdin can't OOM us.
    let mut input = Vec::new();
    let n = std::io::stdin()
        .lock()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .context("worker reading stdin")?;
    if n as u64 > MAX_INPUT {
        return emit(&WorkerReply::Err("input over size cap".into()));
    }

    // run the requested op, folding any error into the reply. this path parses
    // and micro-executes hostile bytes, so it must never panic the process.
    let reply = match op {
        "index" => {
            // func carries the shard as "idx/count" (absent -> whole binary).
            let (idx, cnt) = parse_shard(func);
            match index_bytes_shard(&input, Config::default(), idx, cnt) {
                Ok(funcs) => WorkerReply::IndexOk(funcs),
                Err(e) => WorkerReply::Err(format!("{e:#}")),
            }
        }
        "dump" => {
            let name = func.unwrap_or_default();
            match dump_traces(&input, name, Config::default()) {
                Ok(traces) => WorkerReply::DumpOk(render_traces(&traces)),
                Err(e) => WorkerReply::Err(format!("{e:#}")),
            }
        }
        // parse the untrusted corpus .db image in memory (no file open, so it
        // runs under this same jail) and hand the decoded rows back.
        "dbload" => match Db::open_image(&input).and_then(|db| db.all()) {
            Ok(recs) => WorkerReply::DbOk(recs),
            Err(e) => WorkerReply::Err(format!("{e:#}")),
        },
        other => WorkerReply::Err(format!("unknown worker op: {other}")),
    };
    emit(&reply)
}

fn warm_thread_pool() {
    // touching the global pool spins up its worker threads now, pre-jail.
    warm_pool();
}

// render the dump output to plain lines in the worker so the parent doesn't have
// to serialize the whole effect enum. matches the old cmd_dump format exactly.
fn render_traces(traces: &[EffectTrace]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, t) in traces.iter().enumerate() {
        out.push(format!(
            "-- path {} ({} effects, instret {}, capped {}, coverage {:.2}) --",
            i,
            t.effects.len(),
            t.instret,
            t.capped,
            t.coverage
        ));
        for e in &t.effects {
            out.push(format!("   {e:?}"));
        }
    }
    out
}

fn emit(reply: &WorkerReply) -> Result<()> {
    let buf = postcard::to_allocvec(reply).context("serializing worker reply")?;
    std::io::stdout()
        .lock()
        .write_all(&buf)
        .context("worker writing reply")?;
    Ok(())
}

// ---- parent side of privsep -------------------------------------------------

// re-exec self as the jailed worker, hand it the bytes over stdin, read its
// postcard reply back. the input is written on a separate thread so a large ELF
// can't deadlock against the reply on a full pipe.
fn run_worker(op: &str, func: Option<&str>, input: &[u8]) -> Result<WorkerReply> {
    let exe = std::env::current_exe().context("locating self for worker re-exec")?;
    let mut cmd = Command::new(exe);
    cmd.arg(WORKER_TOKEN).arg(op);
    if let Some(f) = func {
        cmd.arg(f);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // capture stderr instead of handing the worker our terminal. a crash or
        // panic message there can carry attacker-controlled bytes (a symbol name
        // echoed by the parser), and an inherited tty would let raw escape
        // sequences through unescaped. we drain it on a thread, keep a bounded
        // tail, and esc() it before it ever reaches the terminal.
        .stderr(Stdio::piped());
    // put the worker in its own process group (pgid == its pid) so we can signal
    // the whole subtree at once. setpgid runs in the child after fork, before
    // exec, so long before the worker installs its seccomp jail.
    cmd.process_group(0);
    let mut child = cmd.spawn().context("spawning jailed worker")?;
    // pgid == pid because of process_group(0) above
    let wpgid = rustix::process::Pid::from_raw(child.id() as i32);

    // stdin writer: feed the payload on its own thread so a large ELF can't
    // deadlock against the reply on a full pipe.
    let mut stdin = child.stdin.take().context("worker stdin")?;
    let payload = input.to_vec();
    let writer = std::thread::spawn(move || {
        // ignore the error: if the worker died early we'll see it in wait()
        let _ = stdin.write_all(&payload);
        drop(stdin);
    });

    // drain stderr on its own thread so a chatty worker can't wedge on a full
    // stderr pipe. keep only a bounded tail; discard the rest so the worker never
    // blocks writing.
    let mut errpipe = child.stderr.take().context("worker stderr")?;
    let errdrain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = errpipe.by_ref().take(8 * 1024).read_to_end(&mut buf);
        let _ = std::io::copy(&mut errpipe, &mut std::io::sink());
        buf
    });

    // read the reply on its own thread and hand it back over a channel, so the
    // main thread can put a wall-clock deadline on the whole exchange with
    // recv_timeout. doing the kill from here (rather than a separate thread
    // watching an already-reaped child) means the SIGKILL on timeout always
    // happens BEFORE we wait()/reap, while the pid is still valid: there is no
    // window where we could signal a reused pid/pgid.
    let mut stdout = child.stdout.take().context("worker stdout")?;
    let (reply_tx, reply_rx) = std::sync::mpsc::channel::<std::io::Result<Vec<u8>>>();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let r = stdout.by_ref().take(MAX_REPLY + 1).read_to_end(&mut out);
        let _ = reply_tx.send(r.map(|_| out));
    });

    let deadline = worker_deadline();
    let out = match reply_rx.recv_timeout(deadline) {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            // read failed (worker died mid-write, etc). reap and report.
            let _ = child.wait();
            let _ = writer.join();
            let _ = reader.join();
            return Err(anyhow::Error::new(e).context("reading worker reply"));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // deadline hit. SIGKILL the whole group BEFORE reaping so the pid is
            // still valid (no reuse window) and any forked subtree dies too. we do
            // not join reader/writer/errdrain here: if a descendant escaped the
            // group and holds a pipe fd (only reachable via a pre-jail compromise)
            // a join could hang, and the parent is bailing out regardless.
            if let Some(pgid) = wpgid {
                let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::Kill);
            }
            let _ = child.wait();
            bail!(
                "jailed worker exceeded the {}s time budget and was killed",
                deadline.as_secs()
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // reader thread vanished without sending (panicked). reap and report.
            let _ = child.wait();
            bail!("jailed worker reply reader failed");
        }
    };

    // reply in hand; reap the worker, bounded so a post-reply blocking hang can't
    // wedge the parent (see reap_bounded).
    let status = reap_bounded(&mut child, wpgid, POST_REPLY_GRACE).context("waiting on worker")?;
    let _ = writer.join();
    let _ = reader.join();
    let errtail = errdrain.join().unwrap_or_default();

    if !status.success() {
        let tail = String::from_utf8_lossy(&errtail);
        let tail = tail.trim();
        if tail.is_empty() {
            bail!("jailed worker exited abnormally ({status}) - likely killed by the sandbox or a crash in the emulator");
        }
        bail!(
            "jailed worker exited abnormally ({status}) - likely killed by the sandbox or a crash in the emulator; stderr: {}",
            esc(tail)
        );
    }
    if out.len() as u64 > MAX_REPLY {
        bail!("jailed worker reply over size cap");
    }
    let reply: WorkerReply = postcard::from_bytes(&out).context("decoding worker reply")?;
    Ok(reply)
}

// parse the "idx/count" shard spec the parent hands an index worker. absent or
// malformed -> the whole binary (0 of 1), so the worker path stays fail-safe.
fn parse_shard(spec: Option<&str>) -> (usize, usize) {
    let s = match spec {
        Some(s) => s,
        None => return (0, 1),
    };
    let mut it = s.split('/');
    let idx = it.next().and_then(|v| v.parse::<usize>().ok());
    let cnt = it.next().and_then(|v| v.parse::<usize>().ok());
    match (idx, cnt) {
        (Some(i), Some(c)) if c >= 1 && i < c => (i, c),
        _ => (0, 1),
    }
}

// how many jailed worker processes to shard an index across. emulation is
// serialized inside each process (shared qemu TCG state), so parallelism comes
// from running several processes; one per core, capped, since each carries a
// softmmu/context cost. FNPRINT_SHARDS overrides (used by the determinism gate).
fn shard_count() -> usize {
    if let Ok(v) = std::env::var("FNPRINT_SHARDS") {
        if let Ok(n) = v.parse::<usize>() {
            return n.clamp(1, 64);
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 16)
}

// coverage is advisory and never gates, but a popped worker controls the reply, so
// sanitize NaN/negative/huge to "assume covered" before it can render a garbage %.
fn sanitize_coverage(funcs: &mut [IndexedFunc]) {
    for f in funcs {
        f.coverage = if f.coverage.is_finite() {
            f.coverage.clamp(0.0, 1.0)
        } else {
            1.0
        };
    }
}

// index a binary's bytes, jailed by default. --no-sandbox runs it in-process.
fn run_index(bytes: &[u8], no_sandbox: bool) -> Result<Vec<IndexedFunc>> {
    if no_sandbox {
        eprintln!("warning: --no-sandbox, running the emulator without the jail");
        return index_bytes(bytes, Config::default());
    }
    let n = shard_count();
    if n <= 1 {
        // single worker: exactly the old path (whole binary, one jailed process).
        return match run_worker("index", None, bytes)? {
            WorkerReply::IndexOk(mut funcs) => {
                validate_reply_fps(&funcs)?;
                sanitize_coverage(&mut funcs);
                Ok(funcs)
            }
            WorkerReply::Err(e) => bail!("{}", esc(&e)),
            _ => bail!("worker returned the wrong reply kind for index"),
        };
    }
    run_workers_sharded(bytes, n)
}

// spawn N jailed workers concurrently, one per shard, and merge. each worker
// jails itself the same way; a failure in any shard fails the whole index (no
// partial corpus). the merged result is sorted by (entry, name, source) to
// reconstruct the single-process order, so the corpus is byte-identical whatever
// N is (fingerprints are per-function independent + the func list is sorted).
fn run_workers_sharded(bytes: &[u8], n: usize) -> Result<Vec<IndexedFunc>> {
    // share the input across worker threads instead of cloning it N times (the
    // ELF can be up to MAX_INPUT); each thread hands the same bytes to its child.
    let shared = Arc::new(bytes.to_vec());
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let spec = format!("{i}/{n}");
                run_worker("index", Some(&spec), &shared)
            })
        })
        .collect();

    let mut all: Vec<IndexedFunc> = Vec::new();
    let mut first_err: Option<anyhow::Error> = None;
    for h in handles {
        // join every thread even after an error so no child is left orphaned.
        let res = match h.join() {
            Ok(r) => r,
            Err(_) => {
                if first_err.is_none() {
                    first_err = Some(anyhow::anyhow!("a shard worker thread panicked"));
                }
                continue;
            }
        };
        match res {
            Ok(WorkerReply::IndexOk(mut funcs)) => {
                if let Err(e) = validate_reply_fps(&funcs) {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    continue;
                }
                sanitize_coverage(&mut funcs);
                all.append(&mut funcs);
            }
            Ok(WorkerReply::Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(anyhow::anyhow!("{}", esc(&e)));
                }
            }
            Ok(_) => {
                if first_err.is_none() {
                    first_err = Some(anyhow::anyhow!("worker returned the wrong reply kind"));
                }
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    // fail-closed: any shard failure aborts the whole index, no partial corpus.
    if let Some(e) = first_err {
        return Err(e);
    }
    // canonical order == single-process order: the loader sorts funcs by entry
    // (deduped), and rayon collect preserves that, so sorting the merged shards by
    // entry (name/source break ties defensively) reproduces it byte-for-byte.
    all.sort_by(|a, b| {
        a.entry
            .cmp(&b.entry)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| source_str(a.source).cmp(source_str(b.source)))
    });
    Ok(all)
}

// a compromised worker controls its reply. every fingerprint must carry a
// SIG_LEN signature; reject a malformed one loudly here rather than letting it
// flow into the comparators as silent zero-similarity noise.
fn validate_reply_fps(funcs: &[IndexedFunc]) -> Result<()> {
    for f in funcs {
        if f.fp.sig.len() != fnprint_core::SIG_LEN {
            bail!("jailed worker returned a fingerprint with an invalid signature length");
        }
    }
    Ok(())
}

fn run_dump(bytes: &[u8], func: &str, no_sandbox: bool) -> Result<Vec<String>> {
    if no_sandbox {
        eprintln!("warning: --no-sandbox, running the emulator without the jail");
        return Ok(render_traces(&dump_traces(bytes, func, Config::default())?));
    }
    match run_worker("dump", Some(func), bytes)? {
        WorkerReply::DumpOk(lines) => Ok(lines),
        WorkerReply::Err(e) => bail!("{}", esc(&e)),
        _ => bail!("worker returned the wrong reply kind for dump"),
    }
}

// ---- commands ---------------------------------------------------------------

fn is_db(p: &str) -> bool {
    Path::new(p).extension().map(|e| e == "db").unwrap_or(false)
}

// symbol names and labels come out of attacker-controlled ELF strings. anything
// that isn't a plain printable ascii char gets escaped so a crafted name can't
// smuggle terminal escape sequences (colors, cursor moves, title sets) into our
// output. c/rust symbol names are ascii so real names print unchanged.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b == b' ' || b.is_ascii_graphic() {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

// a symbol name emitted into a rizin script is a COMMAND TOKEN, not display text,
// so esc() (which only defangs terminal escapes) is not enough: spaces, ';', '`',
// newlines etc. could break out of the `afn <name> <addr>` argument and inject r2
// commands. map the name to a safe identifier ([A-Za-z0-9_.] only) and prefix it
// so a crafted name can never be anything but an argument. distinct escaping
// context from esc(), on purpose.
fn r2_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    out.push_str("fnp.");
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

// print a serde_json value as one line and return Ok, the json output path.
fn emit_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

// a compromised db-reader worker controls its reply, same threat model as the
// index reply: reject any record whose fingerprint isn't a well-formed SIG_LEN
// signature rather than letting it flow into the comparators as silent noise.
fn validate_corpus_records(recs: &[FuncRec]) -> Result<()> {
    for r in recs {
        if r.fp.sig.len() != fnprint_core::SIG_LEN {
            bail!("jailed db worker returned a record with an invalid signature length");
        }
    }
    Ok(())
}

// read a corpus .db and return its decoded rows. jailed by default: the parent
// reads the file bytes off disk but never parses them with sqlite; a jailed
// worker deserializes the image in memory and hands back decoded records. so a
// hostile .db can only ever hit sqlite inside the jail. --no-sandbox keeps the
// old in-process sqlite read for platforms that can't jail (loud opt-out).
fn load_corpus_records(path: &str, no_sandbox: bool) -> Result<Vec<FuncRec>> {
    if no_sandbox {
        eprintln!("warning: --no-sandbox, parsing corpus with in-process sqlite (unjailed)");
        return Db::open(path)
            .with_context(|| format!("opening corpus {path}"))?
            .all();
    }
    let bytes = read_input(path)?;
    match run_worker("dbload", None, &bytes)? {
        WorkerReply::DbOk(recs) => {
            validate_corpus_records(&recs)?;
            Ok(recs)
        }
        // the worker's error text can carry attacker bytes (sqlite echoing a
        // crafted string); escape it before it reaches the terminal.
        WorkerReply::Err(e) => bail!("{}", esc(&e)),
        _ => bail!("worker returned the wrong reply kind for dbload"),
    }
}

// build the in-memory corpus (records + rebuilt LSH bands) that query/triage
// consume. no sqlite touches the untrusted image in the trusted parent.
fn load_corpus(path: &str, no_sandbox: bool) -> Result<MemCorpus> {
    Ok(MemCorpus::from_records(load_corpus_records(
        path, no_sandbox,
    )?))
}

// read a file we're about to hand the jailed worker, refusing anything over
// MAX_INPUT. check metadata first so a huge file can't OOM the parent on the read
// itself (the worker's own stdin cap only fires after the parent holds the bytes).
// metadata is best-effort (a proc/pipe path may report 0), so the post-read length
// check stays as the backstop.
fn read_input(path: &str) -> Result<Vec<u8>> {
    if let Ok(md) = fs::metadata(path) {
        if md.len() > MAX_INPUT {
            bail!(
                "{path} is {} bytes, over the {MAX_INPUT} byte cap",
                md.len()
            );
        }
    }
    let bytes = fs::read(path).with_context(|| format!("reading {path}"))?;
    if bytes.len() as u64 > MAX_INPUT {
        bail!("{path} over the {MAX_INPUT} byte cap");
    }
    Ok(bytes)
}

// load an index from either an ELF (jailed emulation) or a prebuilt db (jailed
// sqlite parse). in both cases the untrusted bytes are parsed behind the jail.
fn load_index(path: &str, no_sandbox: bool) -> Result<Vec<IndexedFunc>> {
    if is_db(path) {
        Ok(load_corpus_records(path, no_sandbox)?
            .into_iter()
            .map(|r| IndexedFunc {
                name: r.name,
                entry: r.entry,
                source: FuncSource::Symtab,
                fp: r.fp,
                // a .db target was indexed earlier and never stored coverage, so
                // we can't re-derive it. assume covered rather than gate a corpus.
                coverage: 1.0,
            })
            .collect())
    } else {
        let bytes = read_input(path)?;
        run_index(&bytes, no_sandbox)
    }
}

fn cmd_index(binary: &str, out: Option<&str>, no_sandbox: bool, fmt: Format) -> Result<()> {
    if fmt == Format::R2 {
        bail!("r2 output is only supported for query and triage");
    }
    let bytes = read_input(binary)?;
    let funcs = run_index(&bytes, no_sandbox)?;
    let label = Path::new(binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(binary);

    let named = funcs.iter().filter(|f| f.name.is_some()).count();
    let usable = funcs
        .iter()
        .filter(|f| f.fp.complexity >= MIN_COMPLEXITY)
        .count();

    let mut wrote = None;
    if let Some(path) = out {
        let db = Db::open(path)?;
        for f in &funcs {
            db.insert(
                label,
                f.name.as_deref(),
                f.entry,
                source_str(f.source),
                &f.fp,
            )?;
        }
        wrote = Some(path);
    }

    if fmt == Format::Json {
        let list: Vec<serde_json::Value> = funcs
            .iter()
            .map(|f| {
                serde_json::json!({
                    "entry": format!("{:#x}", f.entry),
                    "name": f.name.as_deref().map(esc),
                    "source": source_str(f.source),
                    "complexity": f.fp.complexity,
                    "shingles": f.fp.shingles,
                    "capped": f.fp.capped,
                    "coverage": f.coverage,
                })
            })
            .collect();
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "binary": esc(label),
            "functions": funcs.len(),
            "named": named,
            "with_signal": usable,
            "wrote": wrote,
            "funcs": list,
        }));
    }

    println!(
        "{}: {} functions, {} named, {} with enough signal",
        esc(label),
        funcs.len(),
        named,
        usable
    );
    if let Some(path) = wrote {
        println!("wrote {} prints -> {}", funcs.len(), path);
    }
    Ok(())
}

fn cmd_match(a: &str, b: &str, no_sandbox: bool, fmt: Format) -> Result<()> {
    if fmt == Format::R2 {
        bail!("r2 output is only supported for query and triage");
    }
    let ia = load_index(a, no_sandbox)?;
    let ib = load_index(b, no_sandbox)?;
    let rep = match_by_name(&ia, &ib);

    if fmt == Format::Json {
        let changed: Vec<serde_json::Value> = rep
            .changed
            .iter()
            .map(|c| serde_json::json!({ "name": esc(&c.name), "similarity": c.similarity }))
            .collect();
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "compared": rep.compared,
            "unchanged": rep.same,
            "changed": changed,
            "low_signal": rep.low_signal,
            "only_a": rep.only_a.iter().map(|s| esc(s)).collect::<Vec<_>>(),
            "only_b": rep.only_b.iter().map(|s| esc(s)).collect::<Vec<_>>(),
        }));
    }

    println!("compared {} functions present in both", rep.compared);
    println!("  unchanged:  {}", rep.same);
    println!("  changed:    {}", rep.changed.len());
    println!("  low-signal: {} (too small to judge)", rep.low_signal);
    println!("  only in {}: {}", a, rep.only_a.len());
    println!("  only in {}: {}", b, rep.only_b.len());

    if !rep.changed.is_empty() {
        println!("\nchanged behavior (lowest similarity first):");
        for c in rep.changed.iter().take(40) {
            println!("  {:>5.1}%  {}", c.similarity * 100.0, esc(&c.name));
        }
    }
    Ok(())
}

fn cmd_query(
    target: &str,
    corpus: &str,
    threshold: f64,
    no_sandbox: bool,
    fmt: Format,
) -> Result<()> {
    let it = load_index(target, no_sandbox)?;
    let db = load_corpus(corpus, no_sandbox)?;
    let named = query_corpus(&it, &db, threshold)?;

    if fmt == Format::Json {
        let list: Vec<serde_json::Value> = named
            .iter()
            .map(|n| {
                serde_json::json!({
                    "entry": format!("{:#x}", n.entry),
                    "guess": esc(&n.guess),
                    "from_binary": esc(&n.from_binary),
                    "similarity": n.similarity,
                })
            })
            .collect();
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "threshold": threshold,
            "named": list,
        }));
    }

    if fmt == Format::R2 {
        // a rizin script: run with `. fnprint.r2` inside r2/rizin on the target.
        // names go through r2_ident so a crafted symbol can't inject commands.
        println!(
            "# fnprint: {} function(s) named at >= {:.0}%",
            named.len(),
            threshold * 100.0
        );
        for n in &named {
            println!("afn {} {:#x}", r2_ident(&n.guess), n.entry);
        }
        return Ok(());
    }

    if named.is_empty() {
        println!(
            "no matches above {:.0}% (try a lower --threshold)",
            threshold * 100.0
        );
        return Ok(());
    }
    println!("named {} function(s):", named.len());
    for n in &named {
        println!(
            "  {:#010x}  {:>5.1}%  {}  ({})",
            n.entry,
            n.similarity * 100.0,
            esc(&n.guess),
            esc(&n.from_binary)
        );
    }
    Ok(())
}

fn cmd_eval(a: &str, b: &str, no_sandbox: bool, fmt: Format) -> Result<()> {
    if fmt == Format::R2 {
        bail!("r2 output is only supported for query and triage");
    }
    let ia = load_index(a, no_sandbox)?;
    let ib = load_index(b, no_sandbox)?;
    let r = eval(&ia, &ib);

    if fmt == Format::Json {
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "scored": r.scored,
            "rank1_acc": r.rank1_acc(),
            "recall_at_3": r.recall_at(3),
            "recall_at_5": r.recall_at(5),
            "mrr": r.mrr(),
            "precision": r.precision(),
            "recall": r.recall(),
            "abstain_rate": r.abstain_rate(),
            "tp": r.tp,
            "fp": r.fp,
            "abstained": r.abstained,
        }));
    }

    println!("scored {} functions (had signal + a twin in B)", r.scored);
    println!("  rank-1 accuracy: {:.1}%", r.rank1_acc() * 100.0);
    println!("  recall@3:        {:.1}%", r.recall_at(3) * 100.0);
    println!("  recall@5:        {:.1}%", r.recall_at(5) * 100.0);
    println!("  MRR:             {:.3}", r.mrr());
    println!(
        "  precision@same:  {:.1}%  ({} tp / {} fp)",
        r.precision() * 100.0,
        r.tp,
        r.fp
    );
    println!("  recall@same:     {:.1}%", r.recall() * 100.0);
    println!(
        "  abstained:       {:.1}%  ({} of {} below same-threshold)",
        r.abstain_rate() * 100.0,
        r.abstained,
        r.scored
    );
    Ok(())
}

fn cmd_triage(
    target: &str,
    vuln: &str,
    patched: &str,
    min_sim: f64,
    margin: f64,
    no_sandbox: bool,
    fmt: Format,
) -> Result<()> {
    let it = load_index(target, no_sandbox)?;
    let vdb = load_corpus(vuln, no_sandbox)?;
    let pdb = load_corpus(patched, no_sandbox)?;
    let hits = triage(&it, &vdb, &pdb, min_sim, margin)?;

    let vulns: Vec<_> = hits
        .iter()
        .filter(|h| h.verdict == Verdict::Vulnerable)
        .collect();

    if fmt == Format::Json {
        let verdict_str = |v: &Verdict| match v {
            Verdict::Vulnerable => "vulnerable",
            Verdict::Patched => "patched",
            Verdict::Inconclusive => "inconclusive",
        };
        let list: Vec<serde_json::Value> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "entry": format!("{:#x}", h.entry),
                    "verdict": verdict_str(&h.verdict),
                    "vuln_sim": h.vuln_sim,
                    "vuln_name": esc(&h.vuln_name),
                    "patched_sim": h.patched_sim,
                    "patched_name": esc(&h.patched_name),
                    "margin": h.margin(),
                    "coverage": h.coverage,
                })
            })
            .collect();
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "counts": {
                "vulnerable": vulns.len(),
                "patched": hits.iter().filter(|h| h.verdict == Verdict::Patched).count(),
                "inconclusive": hits.iter().filter(|h| h.verdict == Verdict::Inconclusive).count(),
            },
            "hits": list,
        }));
    }

    if fmt == Format::R2 {
        // name the vuln-leaning targets in rizin so the analyst opens them first.
        println!("# fnprint triage: {} vuln-leaning function(s)", vulns.len());
        for h in &vulns {
            println!("afn {} {:#x}", r2_ident(&h.vuln_name), h.entry);
        }
        return Ok(());
    }

    println!(
        "{} functions triaged: {} look vulnerable, {} patched, {} inconclusive",
        hits.len(),
        vulns.len(),
        hits.iter()
            .filter(|h| h.verdict == Verdict::Patched)
            .count(),
        hits.iter()
            .filter(|h| h.verdict == Verdict::Inconclusive)
            .count(),
    );

    if vulns.is_empty() {
        println!("\nno function leans vulnerable above the margin. nothing to review.");
        return Ok(());
    }
    // the review queue: strongest vulnerable lead first
    println!("\nreview queue (vuln-leaning, strongest first):");
    println!("   addr         vuln%  patched%  margin  cov   matches");
    for h in vulns {
        // advisory: flag a lead built from little observed behavior so it gets a
        // second look. not a filter, the lead still shows.
        let cov_flag = if h.coverage <= fnprint_core::LOW_COVERAGE_ADVISORY {
            "!"
        } else {
            " "
        };
        println!(
            "   {:#010x}  {:>5.1}   {:>6.1}   {:>+5.1}  {:>3.0}%{} {} vs {}",
            h.entry,
            h.vuln_sim * 100.0,
            h.patched_sim * 100.0,
            h.margin() * 100.0,
            h.coverage * 100.0,
            cov_flag,
            esc(&h.vuln_name),
            esc(&h.patched_name),
        );
    }
    println!("\ncov = fraction of the target function body microexecution observed.");
    println!(
        "a low cov (flagged !) means the verdict rests on little behavior; give it a second look."
    );
    Ok(())
}

fn cmd_dump(binary: &str, func: &str, no_sandbox: bool, fmt: Format) -> Result<()> {
    if fmt == Format::R2 {
        bail!("r2 output is only supported for query and triage");
    }
    let bytes = read_input(binary)?;
    let lines = run_dump(&bytes, func, no_sandbox)?;
    if fmt == Format::Json {
        return emit_json(&serde_json::json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "func": esc(func),
            "lines": lines.iter().map(|l| esc(l)).collect::<Vec<_>>(),
        }));
    }
    for line in &lines {
        println!("{}", esc(line));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{esc, r2_ident};

    #[test]
    fn r2_ident_strips_injection() {
        // a crafted symbol name must not be able to break out of the afn argument
        // and inject r2 commands. everything outside [A-Za-z0-9_.] becomes '_'.
        assert_eq!(r2_ident("adler32_z"), "fnp.adler32_z");
        // every char outside [A-Za-z0-9_.] (space, ;, -, /) becomes _
        assert_eq!(r2_ident("x; rm -rf /"), "fnp.x__rm__rf__");
        // no spaces, semicolons, backticks, or newlines survive
        let bad = r2_ident("a b;c`d`\ne");
        assert!(!bad.contains(' '));
        assert!(!bad.contains(';'));
        assert!(!bad.contains('`'));
        assert!(!bad.contains('\n'));
        assert!(bad.starts_with("fnp."));
    }

    #[test]
    fn esc_defangs_terminal_escapes() {
        // an ansi color escape in a crafted symbol name must not survive: the
        // ESC byte becomes literal text so the terminal can't interpret it
        assert_eq!(esc("foo\x1b[31mbar"), "foo\\x1b[31mbar");
        // newline / carriage return escaped so a name can't spoof lines
        assert_eq!(esc("a\nb\r"), "a\\x0ab\\x0d");
        // plain ascii names pass through unchanged
        assert_eq!(esc("adler32_z"), "adler32_z");
        // non-ascii bytes escaped per byte
        assert_eq!(esc("é"), "\\xc3\\xa9");
    }
}
