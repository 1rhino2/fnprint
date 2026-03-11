//! Turn an effect trace into a fixed-size fingerprint we can compare fuzzily.
//!
//! Pipeline: effect tokens -> shingles (n-grams) -> minhash signature. Two
//! functions with near-identical behavior land on near-identical signatures,
//! and the fraction of matching minhash slots estimates the jaccard overlap of
//! their shingle sets. LSH band keys let us bucket so we don't compare
//! everything against everything.

use fnprint_trace::EffectTrace;
use serde::{Deserialize, Serialize};

pub const SIG_LEN: usize = 128; // minhash slots
const SHINGLE_N: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fingerprint {
    pub sig: Vec<u64>, // len == SIG_LEN
    pub shingles: u32, // how many distinct shingles fed it (0 == empty/trivial)
    pub complexity: u32,
    pub capped: bool,
}

impl Fingerprint {
    pub fn from_trace(t: &EffectTrace) -> Fingerprint {
        let toks = t.tokens();
        let shingles = shingle_set(&toks);
        let sig = minhash(&shingles);
        Fingerprint {
            sig,
            shingles: shingles.len() as u32,
            complexity: t.complexity() as u32,
            capped: t.capped,
        }
    }

    /// build one print from several traces (e.g. multiple seeds of the same
    /// function). we union the shingle sets first, so behavior only some seeds
    /// exercised still lands in the signature. this is what makes optimized
    /// code with lots of similar helpers stay distinguishable.
    pub fn from_traces(traces: &[EffectTrace]) -> Fingerprint {
        let mut all: Vec<u64> = Vec::new();
        let mut complexity = 0u32;
        let mut capped = false;
        for t in traces {
            all.extend(shingle_set(&t.tokens()));
            complexity = complexity.max(t.complexity() as u32);
            capped |= t.capped;
        }
        all.sort_unstable();
        all.dedup();
        let sig = minhash(&all);
        Fingerprint {
            sig,
            shingles: all.len() as u32,
            complexity,
            capped,
        }
    }

    /// estimated jaccard of the two shingle sets, in [0,1].
    pub fn similarity(&self, other: &Fingerprint) -> f64 {
        if self.sig.len() != other.sig.len() || self.sig.is_empty() {
            return 0.0;
        }
        let eq = self
            .sig
            .iter()
            .zip(&other.sig)
            .filter(|(a, b)| a == b)
            .count();
        eq as f64 / self.sig.len() as f64
    }

    /// LSH band keys. b bands of r rows, b*r == SIG_LEN. Two prints that share
    /// any band key are worth actually comparing.
    pub fn band_keys(&self, r: usize) -> Vec<u64> {
        let mut out = Vec::new();
        for band in self.sig.chunks(r) {
            let mut h = 0xcbf29ce484222325u64;
            for v in band {
                for i in 0..8 {
                    h ^= (v >> (i * 8)) as u8 as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
            }
            out.push(h);
        }
        out
    }
}

fn shingle_set(toks: &[u64]) -> Vec<u64> {
    // union of unigrams and n-grams. unigrams give order-free overlap so a
    // single changed effect degrades gracefully; the n-grams add back the
    // ordering signal so a shuffled sequence doesn't look identical.
    let mut set = Vec::new();
    if toks.is_empty() {
        return set;
    }
    // unigrams, tagged so they can't collide with an n-gram hash
    for &t in toks {
        set.push(mix(&[0x01, t]));
    }
    if toks.len() >= SHINGLE_N {
        for w in toks.windows(SHINGLE_N) {
            let mut buf = Vec::with_capacity(SHINGLE_N + 1);
            buf.push(0x03);
            buf.extend_from_slice(w);
            set.push(mix(&buf));
        }
    }
    set.sort_unstable();
    set.dedup();
    set
}

fn mix(vals: &[u64]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for v in vals {
        for i in 0..8 {
            h ^= (v >> (i * 8)) as u8 as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

// classic minhash: SIG_LEN independent hash perms, keep the min over the set.
// perms are (a*x + b) with fixed odd multipliers so results are reproducible.
fn minhash(shingles: &[u64]) -> Vec<u64> {
    let mut sig = vec![u64::MAX; SIG_LEN];
    if shingles.is_empty() {
        // empty set -> all zeros, so two empties look identical (they are).
        return vec![0u64; SIG_LEN];
    }
    for (i, slot) in sig.iter_mut().enumerate() {
        let a = PERM_A[i % PERM_A.len()]
            .wrapping_mul((i as u64) | 1)
            .wrapping_add(0x9e3779b97f4a7c15);
        let b = PERM_B[i % PERM_B.len()].wrapping_add((i as u64).wrapping_mul(0x2545f4914f6cdd1d));
        let mut m = u64::MAX;
        for &x in shingles {
            let v = x.wrapping_mul(a | 1).wrapping_add(b);
            // mix so low bits aren't garbage
            let v = v ^ (v >> 29);
            if v < m {
                m = v;
            }
        }
        *slot = m;
    }
    sig
}

const PERM_A: [u64; 8] = [
    0xff51afd7ed558ccd,
    0xc4ceb9fe1a85ec53,
    0x9e3779b97f4a7c15,
    0x2545f4914f6cdd1d,
    0xbf58476d1ce4e5b9,
    0x94d049bb133111eb,
    0xd6e8feb86659fd93,
    0xa0761d6478bd642f,
];
const PERM_B: [u64; 8] = [
    0xe7037ed1a0b428db,
    0x8ebc6af09c88c6e3,
    0x589965cc75374cc3,
    0x1d8e4e27c47d124f,
    0xeb44accab455d165,
    0x165667b19e3779f9,
    0x27d4eb2f165667c5,
    0x2545f4914f6cdd1d,
];

