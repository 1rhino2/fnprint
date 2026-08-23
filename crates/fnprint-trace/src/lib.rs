//! The arch-neutral effect model.
//!
//! The emulator produces a stream of these while a function runs. Everything
//! here is deliberately independent of the CPU it came from and of absolute
//! addresses, so an x86 trace and an arm trace of the same logic line up.

use serde::{Deserialize, Serialize};

/// Where a memory access landed, relative to something we seeded.
/// Absolute addresses are useless for matching so we never keep them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Region {
    /// inside the buffer we pointed argument `k` at
    Arg(u16),
    /// on the stack (offset sign kept, magnitude bucketed)
    Stack,
    /// static/global data in the binary's own segments (.rodata/.data/.bss).
    /// distinguishes table-driven code (crc32 reads a table, adler32 doesn't).
    Global,
    /// somewhere we lazily mapped that isn't an arg or the stack
    Heapish,
}

/// What a value looks like, again without keeping the raw bits when they'd
/// just be an address. Small constants carry real signal so we keep those.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ValueClass {
    /// straight copy of the value we seeded into input `k`
    Input(u16),
    /// derived from input `k` (add/sub/mask etc, we saw it drift)
    InputDeriv(u16),
    Zero,
    /// a small literal, kept exactly because e.g. `1` vs `-1` matters
    SmallConst(i64),
    /// big literal, almost always an address, so we drop the bits
    BigConst,
    Unknown,
}

/// Who a call went to.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CallTarget {
    /// resolved to a name (plt/symbol)
    Sym(String),
    /// unresolved, bucketed by a rough distance class so recompiles still line up
    Anon,
}

/// One observable thing the function did. Order matters.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Effect {
    /// wrote `val` into `region` at a bucketed offset
    Write {
        region: Region,
        off: i32,
        val: ValueClass,
    },
    /// read a distinct field (region + offset). recorded once per field, so it
    /// captures the *set* of struct fields a function touches, not every access.
    Read {
        region: Region,
        off: i32,
    },
    /// first touch of a fresh region (shape signal: how many buffers it walks)
    NewRegion(Region),
    Call(CallTarget),
    Syscall(u32),
    /// a conditional branch happened here. we don't keep the outcome, just that
    /// the function has a decision point at this point in the effect stream.
    Branch,
    Ret(ValueClass),
    /// run hit a cap (loop/instr/time). still a usable partial.
    Capped,
}

impl Effect {
    /// Stable token for this effect. FNV-1a by hand so it does not depend on
    /// std's hasher, which is not stable across toolchains. Same effect ->
    /// same u64 forever, which is what the on-disk fingerprints rely on.
    pub fn token(&self) -> u64 {
        let mut h = Fnv::new();
        match self {
            Effect::Write { region, off, val } => {
                h.tag(1);
                region.hash(&mut h);
                h.i32(*off);
                val.hash(&mut h);
            }
            Effect::Read { region, off } => {
                h.tag(8);
                region.hash(&mut h);
                h.i32(*off);
            }
            Effect::NewRegion(r) => {
                h.tag(2);
                r.hash(&mut h);
            }
            Effect::Call(t) => {
                h.tag(3);
                match t {
                    CallTarget::Sym(s) => {
                        h.tag(1);
                        for b in s.as_bytes() {
                            h.byte(*b);
                        }
                    }
                    CallTarget::Anon => h.tag(2),
                }
            }
            Effect::Syscall(n) => {
                h.tag(4);
                h.u64(*n as u64);
            }
            Effect::Branch => h.tag(5),
            Effect::Ret(v) => {
                h.tag(6);
                v.hash(&mut h);
            }
            Effect::Capped => h.tag(7),
        }
        h.0
    }
}

impl Region {
    fn hash(&self, h: &mut Fnv) {
        match self {
            Region::Arg(k) => {
                h.tag(10);
                h.u64(*k as u64);
            }
            Region::Stack => h.tag(11),
            Region::Global => h.tag(13),
            Region::Heapish => h.tag(12),
        }
    }
}

impl ValueClass {
    fn hash(&self, h: &mut Fnv) {
        match self {
            ValueClass::Input(k) => {
                h.tag(20);
                h.u64(*k as u64);
            }
            ValueClass::InputDeriv(k) => {
                h.tag(21);
                h.u64(*k as u64);
            }
            ValueClass::Zero => h.tag(22),
            ValueClass::SmallConst(v) => {
                h.tag(23);
                h.u64(*v as u64);
            }
            ValueClass::BigConst => h.tag(24),
            ValueClass::Unknown => h.tag(25),
        }
    }
}

/// The full result of micro-executing one function.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectTrace {
    pub effects: Vec<Effect>,
    /// instructions retired before we stopped
    pub instret: u64,
    /// did we cut it off (loop/instr/time)
    pub capped: bool,
    /// fraction of the function's own code bytes we actually executed, in [0,1].
    /// advisory confidence signal: a low value means most of the body sat behind
    /// branches microexecution never took, so the print reflects little observed
    /// behavior. surfaced to the analyst; not used to gate a verdict (complex
    /// input-driven functions legitimately run almost none of their body).
    pub coverage: f32,
}

impl EffectTrace {
    pub fn tokens(&self) -> Vec<u64> {
        self.effects.iter().map(|e| e.token()).collect()
    }

    /// rough "is there enough here to trust a match" gate. thunks and 2-effect
    /// leaves all look alike, so callers use this to withhold confident hits.
    pub fn complexity(&self) -> usize {
        // count effects that actually say something, calls/writes weigh more
        let mut c = 0usize;
        for e in &self.effects {
            c += match e {
                Effect::Call(_) | Effect::Syscall(_) => 3,
                Effect::Write { .. } | Effect::NewRegion(_) => 2,
                Effect::Read { .. } => 1,
                Effect::Ret(ValueClass::Input(_)) | Effect::Ret(ValueClass::InputDeriv(_)) => 1,
                _ => 0,
            };
        }
        c
    }
}

// small fnv-1a. nothing fancy, just needs to be stable.
pub struct Fnv(pub u64);
impl Fnv {
    pub fn new() -> Self {
        Fnv(0xcbf29ce484222325)
    }
    #[inline]
    pub fn byte(&mut self, b: u8) {
        self.0 ^= b as u64;
        self.0 = self.0.wrapping_mul(0x100000001b3);
    }
    pub fn tag(&mut self, t: u8) {
        self.byte(t);
    }
    pub fn u64(&mut self, v: u64) {
        for i in 0..8 {
            self.byte((v >> (i * 8)) as u8);
        }
    }
    pub fn i32(&mut self, v: i32) {
        self.u64(v as i64 as u64);
    }
}
impl Default for Fnv {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_stable_and_distinct() {
        let a = Effect::Write {
            region: Region::Arg(0),
            off: 8,
            val: ValueClass::Input(1),
        };
        let b = Effect::Write {
            region: Region::Arg(0),
            off: 8,
            val: ValueClass::Input(1),
        };
        let c = Effect::Write {
            region: Region::Arg(0),
            off: 16,
            val: ValueClass::Input(1),
        };
        assert_eq!(a.token(), b.token());
        assert_ne!(a.token(), c.token());
    }

    #[test]
    fn complexity_withholds_tiny() {
        let thunk = EffectTrace {
            effects: vec![Effect::Ret(ValueClass::Input(0))],
            instret: 2,
            capped: false,
            coverage: 1.0,
        };
        assert!(thunk.complexity() < 3);
        let real = EffectTrace {
            effects: vec![
                Effect::NewRegion(Region::Arg(0)),
                Effect::Write {
                    region: Region::Arg(0),
                    off: 0,
                    val: ValueClass::Input(1),
                },
                Effect::Call(CallTarget::Sym("memcpy".into())),
            ],
            instret: 40,
            capped: false,
            coverage: 1.0,
        };
        assert!(real.complexity() >= 3);
    }
}
