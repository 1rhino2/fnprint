//! Index / match / query, built on the loader + emulator + fingerprint + db.

use std::collections::HashMap;

use anyhow::Result;
use fnprint_db::Db;
use fnprint_emu::{Config, MicroExec};
use fnprint_loader::{Func, FuncSource};
use fnprint_sig::Fingerprint;
use rayon::prelude::*;

/// below this we don't trust a match, thunks and tiny leaves all look alike
pub const MIN_COMPLEXITY: u32 = 4;
/// two prints this close are "the same function"
pub const SAME_THRESH: f64 = 0.88;
/// fixed seeds used per function. deterministic, so prints are reproducible.
const SEEDS: [u64; 4] = [0, 0x9e3779b9, 0x1234_5678, 0xdead_beef];

pub struct IndexedFunc {
    pub name: Option<String>,
    pub entry: u64,
    pub source: FuncSource,
    pub fp: Fingerprint,
}

pub fn source_str(s: FuncSource) -> &'static str {
    match s {
        FuncSource::Symtab => "symtab",
        FuncSource::DynSym => "dynsym",
        FuncSource::EhFrame => "eh_frame",
    }
}

/// micro-execute + fingerprint every discovered function in an ELF blob.
pub fn index_bytes(bytes: &[u8], cfg: Config) -> Result<Vec<IndexedFunc>> {
    let loaded = fnprint_loader::load(bytes)?;
    let image = &loaded.image;

    // entry -> name, so stubbed calls can be resolved to a symbol
    let mut symbols: HashMap<u64, String> = HashMap::new();
    for f in &loaded.funcs {
        if let Some(n) = &f.name {
            symbols.insert(f.entry, n.clone());
        }
    }

    let out: Vec<IndexedFunc> = loaded
        .funcs
        .par_iter()
        .filter(|f| f.size > 0 && image.code_at(f.entry, 1).is_some())
        .map(|f: &Func| {
            let ex = MicroExec::new(cfg.clone());
            // a few deterministic seeds vary the input buffers so behavior that
            // only shows up on some inputs still makes it into the print.
            let traces = ex.run_explore(image, f, &symbols, &SEEDS);
            IndexedFunc {
                name: f.name.clone(),
                entry: f.entry,
                source: f.source,
                fp: Fingerprint::from_traces(&traces),
            }
        })
        .collect();

    Ok(out)
}

pub fn index_to_db(bytes: &[u8], binary: &str, db: &Db, cfg: Config) -> Result<usize> {
    let funcs = index_bytes(bytes, cfg)?;
    for f in &funcs {
        db.insert(
            binary,
            f.name.as_deref(),
            f.entry,
            source_str(f.source),
            &f.fp,
        )?;
    }
    Ok(funcs.len())
}

// -------- match (n-day / cross-version diff) --------

pub struct Changed {
    pub name: String,
    pub similarity: f64,
}

#[derive(Default)]
pub struct MatchReport {
    pub same: usize,
    pub changed: Vec<Changed>,
    pub only_a: Vec<String>,
    pub only_b: Vec<String>,
    pub compared: usize,
    /// present in both but too little signal to judge (tiny/scalar helpers)
    pub low_signal: usize,
}

/// align two indexes by symbol name and report which shared functions actually
/// changed behavior. this is the "what did the vendor quietly patch" view.
pub fn match_by_name(a: &[IndexedFunc], b: &[IndexedFunc]) -> MatchReport {
    let mut bmap: HashMap<&str, &IndexedFunc> = HashMap::new();
    for f in b {
        if let Some(n) = &f.name {
            bmap.insert(n.as_str(), f);
        }
    }
    let mut amap: HashMap<&str, &IndexedFunc> = HashMap::new();
    for f in a {
        if let Some(n) = &f.name {
            amap.insert(n.as_str(), f);
        }
    }

    let mut rep = MatchReport::default();
    for (name, fa) in &amap {
        match bmap.get(name) {
            Some(fb) => {
                rep.compared += 1;
                // don't cry wolf on thunks/scalar helpers: not enough behavior
                // to tell "changed" from "recompiled the same".
                if fa.fp.complexity < MIN_COMPLEXITY || fb.fp.complexity < MIN_COMPLEXITY {
                    rep.low_signal += 1;
                    continue;
                }
                let sim = fa.fp.similarity(&fb.fp);
                if sim >= SAME_THRESH {
                    rep.same += 1;
                } else {
                    rep.changed.push(Changed {
                        name: name.to_string(),
                        similarity: sim,
                    });
                }
            }
            None => rep.only_a.push(name.to_string()),
        }
    }
    for name in bmap.keys() {
        if !amap.contains_key(name) {
            rep.only_b.push(name.to_string());
        }
    }
    rep.changed
        .sort_by(|x, y| x.similarity.total_cmp(&y.similarity));
    rep.only_a.sort();
    rep.only_b.sort();
    rep
}

// -------- query (auto-name against a corpus) --------

pub struct Named {
    pub entry: u64,
    pub guess: String,
    pub from_binary: String,
    pub similarity: f64,
}

/// best-scoring named function in a corpus for one print. narrows with the LSH
/// bands first and falls back to the full set if no band hit. returns
/// (similarity, name, binary). the preloaded `all` is the fallback pool.
fn best_in_corpus(
    fp: &Fingerprint,
    db: &Db,
    all: &[fnprint_db::FuncRec],
) -> Result<Option<(f64, String, String)>> {
    let cands = db.candidates(fp)?;
    let pool: &[fnprint_db::FuncRec] = if cands.is_empty() { all } else { &cands };
    let mut best: Option<(f64, String, String)> = None;
    for c in pool {
        if c.fp.complexity < MIN_COMPLEXITY {
            continue;
        }
        let cname = match &c.name {
            Some(n) => n,
            None => continue,
        };
        let sim = fp.similarity(&c.fp);
        if best.as_ref().map(|(s, _, _)| sim > *s).unwrap_or(true) {
            best = Some((sim, cname.clone(), c.binary.clone()));
        }
    }
    Ok(best)
}

/// for each function in the target that we can trust, pull the best-matching
/// named function out of the corpus db. withholds tiny/low-signal functions.
pub fn query_corpus(target: &[IndexedFunc], corpus: &Db, threshold: f64) -> Result<Vec<Named>> {
    let named = corpus.all()?; // small corpora, fine to hold in memory
    let mut out = Vec::new();
    for f in target {
        if f.fp.complexity < MIN_COMPLEXITY || f.fp.shingles == 0 {
            continue;
        }
        if let Some((sim, name, bin)) = best_in_corpus(&f.fp, corpus, &named)? {
            if sim >= threshold {
                out.push(Named {
                    entry: f.entry,
                    guess: name,
                    from_binary: bin,
                    similarity: sim,
                });
            }
        }
    }
    out.sort_by(|a, b| b.similarity.total_cmp(&a.similarity));
    Ok(out)
}

// -------- triage (n-day: vulnerable vs patched, the actionable view) --------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// leans toward the known-vulnerable version, clear of the patched one
    Vulnerable,
    /// leans toward the patched version
    Patched,
    /// neither side is close enough, or the two are too close to separate
    Inconclusive,
}

pub struct TriageHit {
    pub entry: u64,
    pub verdict: Verdict,
    pub vuln_sim: f64,
    pub vuln_name: String,
    pub patched_sim: f64,
    pub patched_name: String,
}

impl TriageHit {
    /// how far the vulnerable side leads the patched side. negative means it
    /// looks patched. this is the separation the reviewer actually cares about.
    pub fn margin(&self) -> f64 {
        self.vuln_sim - self.patched_sim
    }
}

fn verdict_order(v: Verdict) -> u8 {
    // vulnerable-leaning to the top of the review queue, patched to the bottom
    match v {
        Verdict::Vulnerable => 0,
        Verdict::Inconclusive => 1,
        Verdict::Patched => 2,
    }
}

/// rank each target function against a known-vulnerable corpus and a known-patched
/// corpus and call which side it leans to. a function close to the vulnerable
/// version and clearly separated from the patched one is a candidate worth a
/// human's time, which is more useful for n-day work than a single match score.
///
/// `min_sim`: a side has to be at least this similar to count as a real lead.
/// `margin`: how far the two sides must separate before we commit to a verdict.
/// the result is sorted as a review queue, strongest vulnerable lead first.
pub fn triage(
    target: &[IndexedFunc],
    vuln: &Db,
    patched: &Db,
    min_sim: f64,
    margin: f64,
) -> Result<Vec<TriageHit>> {
    let vuln_all = vuln.all()?;
    let patched_all = patched.all()?;
    let mut out = Vec::new();
    for f in target {
        if f.fp.complexity < MIN_COMPLEXITY || f.fp.shingles == 0 {
            continue;
        }
        let (vuln_sim, vuln_name) = best_in_corpus(&f.fp, vuln, &vuln_all)?
            .map(|(s, n, _)| (s, n))
            .unwrap_or((0.0, String::new()));
        let (patched_sim, patched_name) = best_in_corpus(&f.fp, patched, &patched_all)?
            .map(|(s, n, _)| (s, n))
            .unwrap_or((0.0, String::new()));

        let top = vuln_sim.max(patched_sim);
        let verdict = if top < min_sim {
            Verdict::Inconclusive
        } else if vuln_sim - patched_sim >= margin {
            Verdict::Vulnerable
        } else if patched_sim - vuln_sim >= margin {
            Verdict::Patched
        } else {
            Verdict::Inconclusive
        };
        out.push(TriageHit {
            entry: f.entry,
            verdict,
            vuln_sim,
            vuln_name,
            patched_sim,
            patched_name,
        });
    }
    out.sort_by(|a, b| {
        verdict_order(a.verdict)
            .cmp(&verdict_order(b.verdict))
            .then(b.vuln_sim.total_cmp(&a.vuln_sim))
    });
    Ok(out)
}

// -------- eval (accuracy metrics against symbol-name ground truth) --------

pub struct EvalResult {
    /// functions in A that we scored (had signal and a same-named twin in B)
    pub scored: usize,
    /// top-1 ranked match in B is the same-named function
    pub rank1: usize,
    /// sum of 1/rank of the correct match, for mean reciprocal rank
    pub rr_sum: f64,
    /// at SAME_THRESH: predicted-same that are actually same-named
    pub tp: usize,
    pub fp: usize,
    /// same-named pairs we failed to call same
    pub fn_: usize,
    /// 1-based rank of the correct match for each scored function. lets us ask
    /// "does reviewing the top k candidates find it", not just the top-1 number.
    pub ranks: Vec<usize>,
    /// scored functions where the top-1 similarity was below SAME_THRESH, i.e.
    /// the tool would decline to make a confident call rather than guess.
    pub abstained: usize,
}

impl EvalResult {
    pub fn rank1_acc(&self) -> f64 {
        if self.scored == 0 {
            0.0
        } else {
            self.rank1 as f64 / self.scored as f64
        }
    }
    pub fn mrr(&self) -> f64 {
        if self.scored == 0 {
            0.0
        } else {
            self.rr_sum / self.scored as f64
        }
    }
    pub fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            0.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    pub fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            0.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    /// fraction of scored functions whose correct match lands in the top k.
    /// recall@5 answers "if an analyst looks at 5 candidates, do they find it".
    pub fn recall_at(&self, k: usize) -> f64 {
        if self.scored == 0 {
            return 0.0;
        }
        let hits = self.ranks.iter().filter(|&&r| r <= k).count();
        hits as f64 / self.scored as f64
    }
    /// how often the tool declined a confident top-1 call. high abstention with
    /// high precision is the honest tradeoff: quiet when it isn't sure.
    pub fn abstain_rate(&self) -> f64 {
        if self.scored == 0 {
            0.0
        } else {
            self.abstained as f64 / self.scored as f64
        }
    }
}

/// rank every signal-bearing function in A against all of B, using symbol names
/// as ground truth. this is the headline accuracy measurement.
pub fn eval(a: &[IndexedFunc], b: &[IndexedFunc]) -> EvalResult {
    let bsig: Vec<&IndexedFunc> = b
        .iter()
        .filter(|f| f.fp.complexity >= MIN_COMPLEXITY && f.fp.shingles > 0 && f.name.is_some())
        .collect();

    let mut res = EvalResult {
        scored: 0,
        rank1: 0,
        rr_sum: 0.0,
        tp: 0,
        fp: 0,
        fn_: 0,
        ranks: Vec::new(),
        abstained: 0,
    };

    for fa in a {
        if fa.fp.complexity < MIN_COMPLEXITY || fa.fp.shingles == 0 {
            continue;
        }
        let aname = match &fa.name {
            Some(n) => n.as_str(),
            None => continue,
        };
        // only score functions that actually exist in B (a fair denominator)
        if !bsig.iter().any(|f| f.name.as_deref() == Some(aname)) {
            continue;
        }
        res.scored += 1;

        // rank B by similarity
        let mut scored: Vec<(f64, &str)> = bsig
            .iter()
            .map(|f| (fa.fp.similarity(&f.fp), f.name.as_deref().unwrap()))
            .collect();
        scored.sort_by(|x, y| y.0.total_cmp(&x.0));

        if scored[0].1 == aname {
            res.rank1 += 1;
        }
        if let Some(pos) = scored.iter().position(|(_, n)| *n == aname) {
            res.rr_sum += 1.0 / (pos as f64 + 1.0);
            res.ranks.push(pos + 1); // 1-based rank for recall@k
        }

        // threshold-based precision/recall on the top-1 call
        let (top_sim, top_name) = scored[0];
        let predicted_same = top_sim >= SAME_THRESH;
        if !predicted_same {
            res.abstained += 1; // below threshold, we'd decline to call it
        }
        let correct = top_name == aname;
        match (predicted_same, correct) {
            (true, true) => res.tp += 1,
            (true, false) => res.fp += 1,
            (false, true) => res.fn_ += 1,
            (false, false) => {}
        }
    }
    res
}

/// debug helper: micro-execute one named function and return its effect traces
/// (one per seed/path). used by `fnprint dump` to see what the engine records.
pub fn dump_traces(
    bytes: &[u8],
    name: &str,
    cfg: Config,
) -> Result<Vec<fnprint_trace::EffectTrace>> {
    let loaded = fnprint_loader::load(bytes)?;
    let image = &loaded.image;
    let mut symbols: HashMap<u64, String> = HashMap::new();
    for f in &loaded.funcs {
        if let Some(n) = &f.name {
            symbols.insert(f.entry, n.clone());
        }
    }
    let f = loaded
        .funcs
        .iter()
        .find(|f| f.name.as_deref() == Some(name))
        .ok_or_else(|| anyhow::anyhow!("no function named {name}"))?;
    let ex = MicroExec::new(cfg);
    Ok(ex.run_explore(image, f, &symbols, &SEEDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    // a tiny position-independent ELF-less path isn't easy here, so we test the
    // matcher/eval logic on hand-built indexes instead. loader+emu are covered
    // in their own crates and end-to-end by the bench harness.
    fn ifunc(name: &str, sig_seed: u64, complexity: u32) -> IndexedFunc {
        IndexedFunc {
            name: Some(name.to_string()),
            entry: 0,
            source: FuncSource::Symtab,
            fp: fnprint_sig::Fingerprint {
                sig: (0..fnprint_sig::SIG_LEN as u64)
                    .map(|i| i.wrapping_mul(sig_seed))
                    .collect(),
                shingles: 20,
                complexity,
                capped: false,
            },
        }
    }

    #[test]
    fn identical_indexes_report_no_changes() {
        let a = vec![ifunc("foo", 3, 10), ifunc("bar", 7, 10)];
        let b = vec![ifunc("foo", 3, 10), ifunc("bar", 7, 10)];
        let rep = match_by_name(&a, &b);
        assert_eq!(rep.changed.len(), 0);
        assert_eq!(rep.same, 2);
    }

    #[test]
    fn changed_behavior_is_flagged() {
        let a = vec![ifunc("foo", 3, 10)];
        let b = vec![ifunc("foo", 999, 10)]; // very different sig
        let rep = match_by_name(&a, &b);
        assert_eq!(rep.changed.len(), 1);
    }

    #[test]
    fn low_signal_not_called_changed() {
        // same name, low complexity on one side -> low_signal, never "changed"
        let a = vec![ifunc("foo", 3, 2)];
        let b = vec![ifunc("foo", 999, 2)];
        let rep = match_by_name(&a, &b);
        assert_eq!(rep.changed.len(), 0);
        assert_eq!(rep.low_signal, 1);
    }

    #[test]
    fn triage_leans_to_matching_side() {
        // vuln corpus holds the function at seed 3, patched holds it at seed 999.
        // a target that behaves like seed 3 must come back Vulnerable, and one
        // like seed 999 must come back Patched.
        let vuln = Db::open_memory().unwrap();
        vuln.insert("v1", Some("f"), 0x1000, "symtab", &ifunc("f", 3, 10).fp)
            .unwrap();
        let patched = Db::open_memory().unwrap();
        patched
            .insert("v2", Some("f"), 0x1000, "symtab", &ifunc("f", 999, 10).fp)
            .unwrap();

        let looks_vuln = triage(&[ifunc("x", 3, 10)], &vuln, &patched, 0.5, 0.1).unwrap();
        assert_eq!(looks_vuln[0].verdict, Verdict::Vulnerable);
        assert!(looks_vuln[0].margin() > 0.0);

        let looks_patched = triage(&[ifunc("x", 999, 10)], &vuln, &patched, 0.5, 0.1).unwrap();
        assert_eq!(looks_patched[0].verdict, Verdict::Patched);
    }

    #[test]
    fn triage_abstains_when_nothing_close() {
        // target matches neither side -> below min_sim -> Inconclusive
        let vuln = Db::open_memory().unwrap();
        vuln.insert("v1", Some("f"), 0x1000, "symtab", &ifunc("f", 3, 10).fp)
            .unwrap();
        let patched = Db::open_memory().unwrap();
        patched
            .insert("v2", Some("f"), 0x1000, "symtab", &ifunc("f", 999, 10).fp)
            .unwrap();

        let hits = triage(&[ifunc("x", 55555, 10)], &vuln, &patched, 0.9, 0.1).unwrap();
        assert_eq!(hits[0].verdict, Verdict::Inconclusive);
    }
}
