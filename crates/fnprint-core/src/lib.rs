//! Index / match / query, built on the loader + emulator + fingerprint + db.

use std::collections::HashMap;

use anyhow::Result;
use fnprint_db::Db;
use fnprint_emu::{Config, MicroExec};
use fnprint_loader::{Func, FuncSource};
use fnprint_sig::Fingerprint;
use rayon::prelude::*;

/// below this we don't trust a match, thunks and tiny leaves all look alike
pub const MIN_COMPLEXITY: u32 = 3;
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
        .sort_by(|x, y| x.similarity.partial_cmp(&y.similarity).unwrap());
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

/// for each function in the target that we can trust, pull the best-matching
/// named function out of the corpus db. withholds tiny/low-signal functions.
pub fn query_corpus(target: &[IndexedFunc], corpus: &Db, threshold: f64) -> Result<Vec<Named>> {
    let named = corpus.all()?; // small corpora, fine to hold in memory
    let mut out = Vec::new();
    for f in target {
        if f.fp.complexity < MIN_COMPLEXITY || f.fp.shingles == 0 {
            continue;
        }
        // narrow with LSH, then score
        let cands = corpus.candidates(&f.fp)?;
        let pool = if cands.is_empty() { &named } else { &cands };
        let mut best: Option<(f64, &str, &str)> = None;
        for c in pool {
            if c.fp.complexity < MIN_COMPLEXITY {
                continue;
            }
            let sim = f.fp.similarity(&c.fp);
            let cname = match &c.name {
                Some(n) => n.as_str(),
                None => continue,
            };
            if best.map(|(s, _, _)| sim > s).unwrap_or(true) {
                best = Some((sim, cname, c.binary.as_str()));
            }
        }
        if let Some((sim, name, bin)) = best {
            if sim >= threshold {
                out.push(Named {
                    entry: f.entry,
                    guess: name.to_string(),
                    from_binary: bin.to_string(),
                    similarity: sim,
                });
            }
        }
    }
    out.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
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
        scored.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap());

        if scored[0].1 == aname {
            res.rank1 += 1;
        }
        if let Some(pos) = scored.iter().position(|(_, n)| *n == aname) {
            res.rr_sum += 1.0 / (pos as f64 + 1.0);
        }

        // threshold-based precision/recall on the top-1 call
        let (top_sim, top_name) = scored[0];
        let predicted_same = top_sim >= SAME_THRESH;
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
}
