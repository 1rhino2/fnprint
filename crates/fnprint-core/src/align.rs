//! Global 1:1 alignment of one function set against another, with call-graph
//! propagation.
//!
//! The old query/triage path scored each target function on its own and took
//! the best corpus hit, so 27 functions could all claim the same corpus
//! function (they did: every deflate*/inflate* entry at -O2 inlines the same
//! state check and bails on junk input, so their entry behavior IS that check).
//! Alignment fixes that structurally: a corpus function can be claimed once,
//! best pair first. Then the call graph gets a say: a pair whose callees and
//! callers are also paired with each other is more believable than one that
//! only looks alike, which is what separates behavioral twins (two checksums,
//! two accessors) that a print alone can't.

use std::collections::HashMap;

use fnprint_db::{FuncRec, BAND_ROWS};
use fnprint_sig::Fingerprint;

use crate::{IndexedFunc, MIN_COMPLEXITY};

/// one side of an alignment. `group` scopes the callee entries (a corpus can hold
/// several binaries, and an entry is only meaningful inside its own binary).
pub struct Node<'a> {
    pub fp: &'a Fingerprint,
    pub entry: u64,
    pub callees: &'a [u64],
    pub name: Option<&'a str>,
    pub group: &'a str,
}

impl<'a> Node<'a> {
    pub fn from_indexed(f: &'a IndexedFunc) -> Node<'a> {
        Node {
            fp: &f.fp,
            entry: f.entry,
            callees: &f.callees,
            name: f.name.as_deref(),
            group: "",
        }
    }
    pub fn from_rec(r: &'a FuncRec) -> Node<'a> {
        Node {
            fp: &r.fp,
            entry: r.entry,
            callees: &r.callees,
            name: r.name.as_deref(),
            group: &r.binary,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Opts {
    /// a pair is accepted when its score (sim + graph bonus) reaches this
    pub threshold: f64,
    /// how much a fully consistent call-graph neighbourhood adds to a pair's
    /// score. 0 turns propagation off (pure behavioral, 1:1 only).
    pub graph_weight: f64,
    /// re-score + re-assign passes after the behavioral round. 2 is enough
    /// in practice, the assignment stops moving.
    pub rounds: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            threshold: 0.7,
            graph_weight: GRAPH_WEIGHT,
            rounds: 2,
        }
    }
}

/// default call-graph weight. swept on the bench (0.3 / 0.5 / 1.0): recall
/// rises at every step with precision flat or better, and a cross-program
/// query (lua against a zlib corpus and back) still names nothing at 1.0, so
/// consistent neighbours don't cascade into junk. FLOOR is the real guard: a
/// pair the prints don't support at all is never a candidate however good its
/// neighbourhood looks.
pub const GRAPH_WEIGHT: f64 = 1.0;
/// pairs below this behavioral similarity are never candidates, whatever the
/// graph says. keeps the pair pool small and stops propagation inventing matches.
const FLOOR: f64 = 0.2;

/// one accepted pair, indexes into the two input slices.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pair {
    pub a: usize,
    pub b: usize,
    /// behavioral similarity, the honest number
    pub sim: f64,
    /// call-graph consistency in [0,1], 0 when neither side has edges
    pub graph: f64,
    /// sim + weight * graph, what the assignment ranked on, clamped to 1
    pub score: f64,
}

struct Cand {
    a: usize,
    b: usize,
    sim: f64,
    graph: f64,
}

fn usable(fp: &Fingerprint) -> bool {
    fp.complexity >= MIN_COMPLEXITY && fp.shingles > 0
}

/// align `a` (the target) to `b` (the corpus / other build). returns the accepted
/// pairs sorted by score desc, and every function appears in at most one pair.
pub fn align(a: &[Node], b: &[Node], opts: Opts) -> Vec<Pair> {
    let w = opts.graph_weight.max(0.0);
    let rounds = if w > 0.0 { opts.rounds } else { 0 };

    // lsh band index over b, same bands the db uses, so the candidate pool is
    // the same set query used to scan. fallback to a full scan per target when
    // nothing shares a band, also as before.
    let mut bands: HashMap<(usize, u64), Vec<usize>> = HashMap::new();
    for (j, n) in b.iter().enumerate() {
        if !usable(n.fp) {
            continue;
        }
        for (band, key) in n.fp.band_keys(BAND_ROWS).into_iter().enumerate() {
            bands.entry((band, key)).or_default().push(j);
        }
    }
    let b_usable: Vec<usize> = (0..b.len()).filter(|&j| usable(b[j].fp)).collect();

    let mut cands: Vec<Cand> = Vec::new();
    let mut seen: Vec<usize> = Vec::new();
    for (i, n) in a.iter().enumerate() {
        if !usable(n.fp) {
            continue;
        }
        seen.clear();
        for (band, key) in n.fp.band_keys(BAND_ROWS).into_iter().enumerate() {
            if let Some(v) = bands.get(&(band, key)) {
                seen.extend_from_slice(v);
            }
        }
        seen.sort_unstable();
        seen.dedup();
        let pool: &[usize] = if seen.is_empty() { &b_usable } else { &seen };
        for &j in pool {
            let sim = n.fp.similarity(b[j].fp);
            if sim >= FLOOR {
                cands.push(Cand {
                    a: i,
                    b: j,
                    sim,
                    graph: 0.0,
                });
            }
        }
    }

    // entry -> index maps for both sides, so callee entries become neighbours.
    // callers are the reverse edges, built once.
    let a_idx: HashMap<u64, usize> = a.iter().enumerate().map(|(i, n)| (n.entry, i)).collect();
    let b_idx: HashMap<(&str, u64), usize> = b
        .iter()
        .enumerate()
        .map(|(j, n)| ((n.group, n.entry), j))
        .collect();
    let a_callees: Vec<Vec<usize>> = a
        .iter()
        .map(|n| {
            n.callees
                .iter()
                .filter_map(|e| a_idx.get(e).copied())
                .collect()
        })
        .collect();
    let b_callees: Vec<Vec<usize>> = b
        .iter()
        .map(|n| {
            n.callees
                .iter()
                .filter_map(|e| b_idx.get(&(n.group, *e)).copied())
                .collect()
        })
        .collect();
    let a_callers = reverse(&a_callees, a.len());
    let b_callers = reverse(&b_callees, b.len());

    let mut assign = assign_greedy(&mut cands, a, b, w);
    for _ in 0..rounds {
        // a's partner for each index this round, None if unassigned
        let mut partner: Vec<Option<usize>> = vec![None; a.len()];
        let mut b_paired = vec![false; b.len()];
        for p in &assign {
            partner[p.a] = Some(p.b);
            b_paired[p.b] = true;
        }
        for c in cands.iter_mut() {
            c.graph = graph_score(
                c.a, c.b, &partner, &b_paired, &a_callees, &a_callers, &b_callees, &b_callers,
            );
        }
        let next = assign_greedy(&mut cands, a, b, w);
        let moved = next != assign;
        assign = next;
        if !moved {
            break;
        }
    }

    // accept: score over the line. graph can lift a borderline pair (sim within
    // `w` of the threshold) but not a junk one, since graph <= 1.
    let mut out: Vec<Pair> = assign
        .into_iter()
        .filter(|p| p.score >= opts.threshold)
        .collect();
    out.sort_by(|x, y| {
        y.score
            .total_cmp(&x.score)
            .then(y.sim.total_cmp(&x.sim))
            .then(a[x.a].entry.cmp(&a[y.a].entry))
    });
    out
}

fn reverse(callees: &[Vec<usize>], n: usize) -> Vec<Vec<usize>> {
    let mut callers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, cs) in callees.iter().enumerate() {
        for &c in cs {
            callers[c].push(i);
        }
    }
    for v in callers.iter_mut() {
        v.sort_unstable();
        v.dedup();
    }
    callers
}

// dice overlap of the two neighbourhoods under the current assignment: how many
// of a's paired callees+callers are paired with one of b's callees+callers, over
// the number of paired neighbours on both sides. neighbours nobody could pair
// (thunks, low-signal leaves) are left out of the denominator, otherwise a
// function whose helpers are all tiny scores 0 however consistent its real
// neighbours are. 0 when nothing is paired on either side (no opinion), so a
// leaf-vs-leaf pair is neither helped nor hurt.
#[allow(clippy::too_many_arguments)]
fn graph_score(
    a: usize,
    b: usize,
    partner: &[Option<usize>],
    b_paired: &[bool],
    a_callees: &[Vec<usize>],
    a_callers: &[Vec<usize>],
    b_callees: &[Vec<usize>],
    b_callers: &[Vec<usize>],
) -> f64 {
    let na = a_callees[a]
        .iter()
        .filter(|&&x| partner[x].is_some())
        .count()
        + a_callers[a]
            .iter()
            .filter(|&&x| partner[x].is_some())
            .count();
    let nb = b_callees[b].iter().filter(|&&y| b_paired[y]).count()
        + b_callers[b].iter().filter(|&&y| b_paired[y]).count();
    if na + nb == 0 {
        return 0.0;
    }
    let mut hit = 0usize;
    for &x in &a_callees[a] {
        if let Some(y) = partner[x] {
            if b_callees[b].binary_search(&y).is_ok() {
                hit += 1;
            }
        }
    }
    for &x in &a_callers[a] {
        if let Some(y) = partner[x] {
            if b_callers[b].binary_search(&y).is_ok() {
                hit += 1;
            }
        }
    }
    (2 * hit) as f64 / (na + nb) as f64
}

// best pair first, each side claimed once. ties broken on sim, then the a
// entry, then the (group, entry) of b, so the result never depends on input
// order or hash iteration.
fn assign_greedy(cands: &mut [Cand], a: &[Node], b: &[Node], w: f64) -> Vec<Pair> {
    cands.sort_by(|x, y| {
        let sx = x.sim + w * x.graph;
        let sy = y.sim + w * y.graph;
        sy.total_cmp(&sx)
            .then(y.sim.total_cmp(&x.sim))
            .then(a[x.a].entry.cmp(&a[y.a].entry))
            .then((b[x.b].group, b[x.b].entry).cmp(&(b[y.b].group, b[y.b].entry)))
    });
    let mut a_taken = vec![false; a.len()];
    let mut b_taken = vec![false; b.len()];
    let mut out = Vec::new();
    for c in cands.iter() {
        if a_taken[c.a] || b_taken[c.b] {
            continue;
        }
        a_taken[c.a] = true;
        b_taken[c.b] = true;
        out.push(Pair {
            a: c.a,
            b: c.b,
            sim: c.sim,
            graph: c.graph,
            score: (c.sim + w * c.graph).min(1.0),
        });
    }
    out.sort_by_key(|p| p.a);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fnprint_sig::Fingerprint;
    use fnprint_trace::{CallTarget, Effect, EffectTrace, Region, ValueClass};

    fn trace(effects: Vec<Effect>, callees: Vec<u64>) -> EffectTrace {
        EffectTrace {
            effects,
            instret: 100,
            capped: false,
            coverage: 1.0,
            callees,
        }
    }
    fn body(k: u16) -> Vec<Effect> {
        vec![
            Effect::NewRegion(Region::Arg(0)),
            Effect::Write {
                region: Region::Arg(0),
                off: 8 * k as i32,
                val: ValueClass::Input(1),
            },
            Effect::Call(CallTarget::Sym("memcpy".into())),
            Effect::Write {
                region: Region::Arg(0),
                off: 16,
                val: ValueClass::SmallConst(k as i64),
            },
            Effect::Ret(ValueClass::Zero),
        ]
    }
    struct F {
        fp: Fingerprint,
        entry: u64,
        callees: Vec<u64>,
        name: String,
    }
    fn f(name: &str, entry: u64, k: u16, callees: Vec<u64>) -> F {
        F {
            fp: Fingerprint::from_trace(&trace(body(k), callees.clone())),
            entry,
            callees,
            name: name.into(),
        }
    }
    fn nodes(fs: &[F]) -> Vec<Node<'_>> {
        fs.iter()
            .map(|x| Node {
                fp: &x.fp,
                entry: x.entry,
                callees: &x.callees,
                name: Some(&x.name),
                group: "",
            })
            .collect()
    }

    #[test]
    fn one_to_one_never_double_claims() {
        // two identical-behaving target functions and one corpus twin: only one
        // may claim it, the greedy per-function path used to name both.
        let a = vec![f("x", 0x1000, 1, vec![]), f("y", 0x2000, 1, vec![])];
        let b = vec![f("x", 0x1000, 1, vec![])];
        let pairs = align(&nodes(&a), &nodes(&b), Opts::default());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].b, 0);
    }

    #[test]
    fn graph_breaks_a_behavioral_tie() {
        // target: p calls q; r calls s. q and s behave identically (twins).
        // corpus: same shape with names. p<->P and r<->R are unambiguous, so the
        // graph must put q with Q (called by P) and s with S (called by R).
        let a = vec![
            f("p", 0x100, 2, vec![0x300]),
            f("r", 0x200, 3, vec![0x400]),
            f("q", 0x300, 1, vec![]),
            f("s", 0x400, 1, vec![]),
        ];
        // corpus laid out in the other order so a tie on sim alone would pick
        // by entry order and get one of the two wrong.
        let b = vec![
            f("S", 0x10, 1, vec![]),
            f("Q", 0x20, 1, vec![]),
            f("R", 0x30, 3, vec![0x10]),
            f("P", 0x40, 2, vec![0x20]),
        ];
        let an = nodes(&a);
        let bn = nodes(&b);
        let pairs = align(
            &an,
            &bn,
            Opts {
                threshold: 0.5,
                graph_weight: 0.3,
                rounds: 2,
            },
        );
        let name_of = |p: &Pair| (an[p.a].name.unwrap(), bn[p.b].name.unwrap());
        let got: Vec<_> = pairs.iter().map(name_of).collect();
        assert!(got.contains(&("p", "P")), "{got:?}");
        assert!(got.contains(&("r", "R")), "{got:?}");
        assert!(got.contains(&("q", "Q")), "{got:?}");
        assert!(got.contains(&("s", "S")), "{got:?}");
        // without the graph the twins are a coin flip on entry order: one wrong
        let flat = align(
            &an,
            &bn,
            Opts {
                threshold: 0.5,
                graph_weight: 0.0,
                rounds: 0,
            },
        );
        let got: Vec<_> = flat.iter().map(name_of).collect();
        assert!(
            got.contains(&("q", "S")) || got.contains(&("s", "Q")),
            "{got:?}"
        );
    }

    #[test]
    fn graph_cannot_lift_junk() {
        // unrelated behavior stays unmatched no matter how consistent the
        // neighbourhood is: sim below FLOOR is never a candidate.
        let a = vec![f("p", 0x100, 2, vec![0x300]), f("q", 0x300, 1, vec![])];
        let junk = Fingerprint::from_trace(&trace(
            vec![Effect::Syscall(60), Effect::Ret(ValueClass::Unknown)],
            vec![],
        ));
        let b_p = f("P", 0x40, 2, vec![0x20]);
        let bn = vec![
            Node {
                fp: &junk,
                entry: 0x20,
                callees: &[],
                name: Some("J"),
                group: "",
            },
            Node {
                fp: &b_p.fp,
                entry: 0x40,
                callees: &b_p.callees,
                name: Some("P"),
                group: "",
            },
        ];
        let pairs = align(&nodes(&a), &bn, Opts::default());
        assert!(pairs.iter().all(|p| bn[p.b].name != Some("J")));
    }

    #[test]
    fn deterministic_under_input_order() {
        let a = vec![
            f("p", 0x100, 2, vec![0x300]),
            f("r", 0x200, 3, vec![0x400]),
            f("q", 0x300, 1, vec![]),
            f("s", 0x400, 1, vec![]),
        ];
        let mut b = vec![
            f("S", 0x10, 1, vec![]),
            f("Q", 0x20, 1, vec![]),
            f("R", 0x30, 3, vec![0x10]),
            f("P", 0x40, 2, vec![0x20]),
        ];
        let an = nodes(&a);
        let p1: Vec<(u64, u64)> = align(&an, &nodes(&b), Opts::default())
            .iter()
            .map(|p| (a[p.a].entry, b[p.b].entry))
            .collect();
        b.reverse();
        let p2: Vec<(u64, u64)> = align(&an, &nodes(&b), Opts::default())
            .iter()
            .map(|p| (a[p.a].entry, b[p.b].entry))
            .collect();
        assert_eq!(p1, p2);
    }
}
