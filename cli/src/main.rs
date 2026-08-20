use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fnprint_core::{
    dump_traces, eval, index_bytes, match_by_name, query_corpus, source_str, triage, IndexedFunc,
    Verdict, MIN_COMPLEXITY,
};
use fnprint_db::Db;
use fnprint_emu::Config;
use fnprint_loader::FuncSource;

#[derive(Parser)]
#[command(
    name = "fnprint",
    version,
    about = "behavioral function fingerprinting"
)]
struct Cli {
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
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Index { binary, out } => cmd_index(&binary, out.as_deref()),
        Cmd::Match { a, b } => cmd_match(&a, &b),
        Cmd::Query {
            target,
            corpus,
            threshold,
        } => cmd_query(&target, &corpus, threshold),
        Cmd::Eval { a, b } => cmd_eval(&a, &b),
        Cmd::Triage {
            target,
            vuln,
            patched,
            min_sim,
            margin,
        } => cmd_triage(&target, &vuln, &patched, min_sim, margin),
        Cmd::Dump { binary, func } => cmd_dump(&binary, &func),
    }
}

fn is_db(p: &str) -> bool {
    Path::new(p).extension().map(|e| e == "db").unwrap_or(false)
}

// load an index from either an ELF or a prebuilt db
fn load_index(path: &str) -> Result<Vec<IndexedFunc>> {
    if is_db(path) {
        let db = Db::open(path)?;
        Ok(db
            .all()?
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
        index_bytes(&bytes, Config::default())
    }
}

fn cmd_index(binary: &str, out: Option<&str>) -> Result<()> {
    let bytes = fs::read(binary).with_context(|| format!("reading {binary}"))?;
    let funcs = index_bytes(&bytes, Config::default())?;
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
        label,
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

fn cmd_match(a: &str, b: &str) -> Result<()> {
    let ia = load_index(a)?;
    let ib = load_index(b)?;
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
            println!("  {:>5.1}%  {}", c.similarity * 100.0, c.name);
        }
    }
    Ok(())
}

fn cmd_query(target: &str, corpus: &str, threshold: f64) -> Result<()> {
    let it = load_index(target)?;
    let db = Db::open(corpus).with_context(|| format!("opening corpus {corpus}"))?;
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
            n.guess,
            n.from_binary
        );
    }
    Ok(())
}

fn cmd_eval(a: &str, b: &str) -> Result<()> {
    let ia = load_index(a)?;
    let ib = load_index(b)?;
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
) -> Result<()> {
    let it = load_index(target)?;
    let vdb = Db::open(vuln).with_context(|| format!("opening vuln corpus {vuln}"))?;
    let pdb = Db::open(patched).with_context(|| format!("opening patched corpus {patched}"))?;
    let hits = triage(&it, &vdb, &pdb, min_sim, margin)?;

    let vulns: Vec<_> = hits
        .iter()
        .filter(|h| h.verdict == Verdict::Vulnerable)
        .collect();
    println!(
        "{} functions triaged: {} look vulnerable, {} patched, {} inconclusive",
        hits.len(),
        vulns.len(),
        hits.iter().filter(|h| h.verdict == Verdict::Patched).count(),
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
            h.vuln_name,
            h.patched_name,
        );
    }
    Ok(())
}

fn cmd_dump(binary: &str, func: &str) -> Result<()> {
    let bytes = std::fs::read(binary)?;
    let traces = dump_traces(&bytes, func, fnprint_emu::Config::default())?;
    for (i, t) in traces.iter().enumerate() {
        println!(
            "-- path {} ({} effects, instret {}, capped {}) --",
            i,
            t.effects.len(),
            t.instret,
            t.capped
        );
        for e in &t.effects {
            println!("   {:?}", e);
        }
    }
    Ok(())
}
