use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use fnprint_core::{
    dump_traces, eval, index_bytes, match_by_name, query_corpus, source_str, triage, warm_pool,
    EffectTrace, IndexedFunc, Verdict, MIN_COMPLEXITY,
};
use fnprint_db::{Db, FuncRec, MemCorpus};
use fnprint_emu::Config;
use fnprint_loader::FuncSource;
use serde::{Deserialize, Serialize};

// hard caps on the privsep pipe so neither side can be pushed into an unbounded
// alloc. an ELF bigger than this we refuse; a worker reply bigger than this we
// treat as a compromised worker.
const MAX_INPUT: u64 = 512 << 20; // 512 MiB
                                  // the reply is fingerprints, far smaller than the input binary, so cap it well
                                  // below the input. a compromised worker can amplify the wire size on decode:
                                  // postcard varint-decodes each zero u64 (1 wire byte) into 8 resident bytes,
                                  // and the Vec<String>/Vec<FuncRec> shapes add per-element String/struct
                                  // overhead on top, so the real worst case is ~24x, not 8x: a full 128 MiB
                                  // reply can balloon to roughly 3 GiB transient in the parent before it is
                                  // dropped. that is a compromised-worker-only DoS (the jail already held), it
                                  // stays bounded by the parent's own RLIMIT_AS, and 128 MiB still fits any
                                  // realistic binary's prints (~400k functions). we keep the cap here rather
                                  // than lower it (a smaller cap would false-reject a legit large binary's
                                  // reply as if the worker were compromised).
const MAX_REPLY: u64 = 128 << 20;

// the hidden argv token the parent re-execs itself with to become the jailed
// worker. anything the emulator touches runs behind it.
const WORKER_TOKEN: &str = "__worker";

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
    #[command(subcommand)]
    cmd: Cmd,
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
    match cli.cmd {
        Cmd::Index { binary, out } => cmd_index(&binary, out.as_deref(), ns),
        Cmd::Match { a, b } => cmd_match(&a, &b, ns),
        Cmd::Query {
            target,
            corpus,
            threshold,
        } => cmd_query(&target, &corpus, threshold, ns),
        Cmd::Eval { a, b } => cmd_eval(&a, &b, ns),
        Cmd::Triage {
            target,
            vuln,
            patched,
            min_sim,
            margin,
        } => cmd_triage(&target, &vuln, &patched, min_sim, margin, ns),
        Cmd::Dump { binary, func } => cmd_dump(&binary, &func, ns),
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
        "index" => match index_bytes(&input, Config::default()) {
            Ok(funcs) => WorkerReply::IndexOk(funcs),
            Err(e) => WorkerReply::Err(format!("{e:#}")),
        },
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
            "-- path {} ({} effects, instret {}, capped {}) --",
            i,
            t.effects.len(),
            t.instret,
            t.capped
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
    let mut child = cmd.spawn().context("spawning jailed worker")?;

    let mut stdin = child.stdin.take().context("worker stdin")?;
    let payload = input.to_vec();
    let writer = std::thread::spawn(move || {
        // ignore the error: if the worker died early we'll see it in wait()
        let _ = stdin.write_all(&payload);
        drop(stdin);
    });

    // drain stderr on its own thread so a chatty worker can't wedge on a full
    // stderr pipe while we're blocked reading stdout. keep only a bounded tail;
    // discard the rest so the worker never blocks writing.
    let mut errpipe = child.stderr.take().context("worker stderr")?;
    let errdrain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = errpipe.by_ref().take(8 * 1024).read_to_end(&mut buf);
        let _ = std::io::copy(&mut errpipe, &mut std::io::sink());
        buf
    });

    let mut out = Vec::new();
    {
        let mut stdout = child.stdout.take().context("worker stdout")?;
        stdout
            .by_ref()
            .take(MAX_REPLY + 1)
            .read_to_end(&mut out)
            .context("reading worker reply")?;
    }
    let status = child.wait().context("waiting on worker")?;
    let _ = writer.join();
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

// index a binary's bytes, jailed by default. --no-sandbox runs it in-process.
fn run_index(bytes: &[u8], no_sandbox: bool) -> Result<Vec<IndexedFunc>> {
    if no_sandbox {
        eprintln!("warning: --no-sandbox, running the emulator without the jail");
        return index_bytes(bytes, Config::default());
    }
    match run_worker("index", None, bytes)? {
        WorkerReply::IndexOk(funcs) => {
            validate_reply_fps(&funcs)?;
            Ok(funcs)
        }
        // the worker's error text is built from the parser, which handles attacker
        // bytes; escape it so a crafted error can't smuggle terminal sequences.
        WorkerReply::Err(e) => bail!("{}", esc(&e)),
        _ => bail!("worker returned the wrong reply kind for index"),
    }
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
    let bytes = fs::read(path).with_context(|| format!("reading corpus {path}"))?;
    if bytes.len() as u64 > MAX_INPUT {
        bail!("corpus {path} over size cap");
    }
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
            })
            .collect())
    } else {
        let bytes = fs::read(path).with_context(|| format!("reading {path}"))?;
        run_index(&bytes, no_sandbox)
    }
}

fn cmd_index(binary: &str, out: Option<&str>, no_sandbox: bool) -> Result<()> {
    let bytes = fs::read(binary).with_context(|| format!("reading {binary}"))?;
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
    println!(
        "{}: {} functions, {} named, {} with enough signal",
        esc(label),
        funcs.len(),
        named,
        usable
    );

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
        println!("wrote {} prints -> {}", funcs.len(), path);
    }
    Ok(())
}

fn cmd_match(a: &str, b: &str, no_sandbox: bool) -> Result<()> {
    let ia = load_index(a, no_sandbox)?;
    let ib = load_index(b, no_sandbox)?;
    let rep = match_by_name(&ia, &ib);

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

fn cmd_query(target: &str, corpus: &str, threshold: f64, no_sandbox: bool) -> Result<()> {
    let it = load_index(target, no_sandbox)?;
    let db = load_corpus(corpus, no_sandbox)?;
    let named = query_corpus(&it, &db, threshold)?;

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

fn cmd_eval(a: &str, b: &str, no_sandbox: bool) -> Result<()> {
    let ia = load_index(a, no_sandbox)?;
    let ib = load_index(b, no_sandbox)?;
    let r = eval(&ia, &ib);
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
) -> Result<()> {
    let it = load_index(target, no_sandbox)?;
    let vdb = load_corpus(vuln, no_sandbox)?;
    let pdb = load_corpus(patched, no_sandbox)?;
    let hits = triage(&it, &vdb, &pdb, min_sim, margin)?;

    let vulns: Vec<_> = hits
        .iter()
        .filter(|h| h.verdict == Verdict::Vulnerable)
        .collect();
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
    println!("   addr         vuln%  patched%  margin  matches");
    for h in vulns {
        println!(
            "   {:#010x}  {:>5.1}   {:>6.1}   {:>+5.1}  {} vs {}",
            h.entry,
            h.vuln_sim * 100.0,
            h.patched_sim * 100.0,
            h.margin() * 100.0,
            esc(&h.vuln_name),
            esc(&h.patched_name),
        );
    }
    Ok(())
}

fn cmd_dump(binary: &str, func: &str, no_sandbox: bool) -> Result<()> {
    let bytes = fs::read(binary).with_context(|| format!("reading {binary}"))?;
    let lines = run_dump(&bytes, func, no_sandbox)?;
    for line in &lines {
        println!("{}", esc(line));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::esc;

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
