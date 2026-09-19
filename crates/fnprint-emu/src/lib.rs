//! Micro-execute one function and record what it does.
//!
//! The trick (Godefroid's microexecution, also BLEX): run a function with no
//! real context. Any read from memory we didn't set up returns a deterministic
//! value and the page gets mapped on the fly, so wild pointers never crash and
//! the same seed always produces the same run. We seed the arg registers with
//! tagged pointers, stub out calls so we never dive into libc, and log an
//! arch-neutral effect stream. That stream is the thing we fingerprint.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use capstone::prelude::*;
use fnprint_loader::{Arch as Isa, Func, Image};
use fnprint_trace::{CallTarget, Effect, EffectTrace, Region, ValueClass};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, RegisterX86, Unicorn};

const PAGE: u64 = 0x1000;
const NARGS: usize = 6;
const ARG_BASE: u64 = 0x10_0000_0000;
const ARG_STRIDE: u64 = 0x01_0000_0000;
const ARG_SIZE: u64 = 0x0000_8000;
const STACK_BASE: u64 = 0x20_0000_0000;
const STACK_SIZE: u64 = 0x0004_0000;
const RSP0: u64 = STACK_BASE + STACK_SIZE / 2;
const RET_ADDR: u64 = 0x30_0000_0000;
/// most on-the-fly pages one run may map before we stop and mark it capped.
/// qemu asserts once a context holds too many memory regions, so this sits well
/// under that ceiling. a run that wants more than this is pathological anyway.
/// kept low on purpose: softmmu bookkeeping grows super-linearly with resident
/// maps, so a crafted read-flood binary that touches thousands of distinct pages
/// used to burn ~90s cpu before the old 1024 cap fired. legit functions touch
/// far fewer (reads dedup at 64 fields, max_heapish is 24), so 256 gives real
/// code plenty of headroom while cutting the worst-case cost ~16x. bench accuracy
/// is unchanged at this value (verified against NUMBERS.md).
const MAX_RUNTIME_MAPS: usize = 256;
/// most coalesced page-runs a single setup ensure_pages call may create in its
/// overlap fallback. byte-disjoint segments (the loader rejects real overlaps)
/// split a span into at most a couple of runs at shared boundary pages, so this
/// is far above legit need; exceeding it means a pathological layout, and we fail
/// the run closed (capped trace) rather than march toward qemu's region cap.
const MAX_SETUP_RUNS: usize = 64;
/// default blanket restarts per seed: off. measured on the bench with the
/// restart effects filtered to import calls + syscalls (the least build-specific
/// slice): gcc O2->O3 aligned acc 63 -> 68, but gcc/clang O3 92.6 -> 61.1 and
/// gcc O0->O2 93 -> 82, because a restart at -O0 runs helpers that -O3 inlined
/// away and the union print drifts. it needs to be a second print with its own
/// similarity, not a union with the entry print. FNPRINT_BLANKET=N turns it on.
pub const BLANKET_RESTARTS: usize = 0;
/// stop restarting once this much of the body has executed; the rest is
/// padding, unreachable tails, or not worth another run.
const BLANKET_ENOUGH: f32 = 0.9;

#[derive(Clone)]
pub struct Config {
    pub instr_cap: u64,
    pub visit_cap: u32,
    /// wall-clock backstop only, NOT a fingerprint-shaping bound. termination is
    /// bounded deterministically by instr_cap + visit_cap + max_effects, plus a
    /// per-run mem-op ceiling (instr_cap * MEM_OPS_PER_INSTR_CAP) that stops a
    /// single rep-prefixed string op without leaning on this timer; this just
    /// catches a genuine unicorn hang. keep it big so it never fires under
    /// parallel CPU load, otherwise it truncates traces and the same binary
    /// fingerprints differently run to run.
    pub timeout_us: u64,
    pub seed: u64,
    pub max_heapish: usize,
    /// stop after this many effects. bounds the garbage-fed tail of big
    /// data-dependent functions, which is both noise and build-specific, so
    /// the print reflects stable early behavior. also keeps runs fast.
    pub max_effects: usize,
    /// experimental path exploration: flip the first N branch outcomes to step
    /// past validation gates. off by default (0) because forced impossible
    /// paths add build-specific noise that hurts cross-build matching. see the
    /// roadmap notes on concolic-lite before turning this up.
    pub explore_depth: usize,
    /// blanket execution: after the natural run, restart at the lowest
    /// instruction of the body nothing executed yet, with fresh state, and
    /// union what that run does. repeat up to this many times per seed. this
    /// is what gets past an input-validation gate that junk input fails: the
    /// code behind it still runs, just from a fresh start. 0 = entry only.
    pub blanket_restarts: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            instr_cap: 20_000,
            visit_cap: 64,
            timeout_us: 3_000_000, // 3s hang guard, not a per-run budget
            seed: 0,
            max_heapish: 24,
            max_effects: 96,
            explore_depth: 0,
            blanket_restarts: BLANKET_RESTARTS,
        }
    }
}

pub struct MicroExec {
    cfg: Config,
}

// one run's output: the trace, the natural branch directions (for path
// exploration), and the body instructions executed (addr -> len, for blanket)
type RunOut = (EffectTrace, Vec<bool>, HashMap<u64, u64>);

// everything the hooks need lives here so unicorn can hand it back via get_data.
struct Rec {
    effects: Vec<Effect>,
    visits: HashMap<u64, u32>,
    instret: u64,
    capped: bool,
    seen_heapish: HashSet<u64>,
    seen_reads: HashSet<u64>,
    heapish_count: usize,
    // x86 needs a real decoder for instruction length and kind. aarch64 is
    // fixed-width and the handful of kinds we steer on decode from bit masks.
    cs: Option<Capstone>,
    isa: Isa,
    // shared, not owned per-run: cloning this into every Rec deep-copied the whole
    // symbol map once per force-path. an Arc makes the per-run clone a refcount bump.
    symbols: Arc<HashMap<u64, String>>,
    ret_ctr: u64,
    cfg: Config,
    // ranges of the binary's own loaded segments, for Global classification
    segs: Vec<(u64, u64)>,
    // bounded path exploration: force the first N branch outcomes, record the
    // rest. lets us step past input-validation gates that fail on junk input.
    force: Vec<bool>,
    branch_seen: usize,
    natural_dirs: Vec<bool>,
    pending_branch: Option<u64>, // target of the branch we just passed
    // pages we've mapped on the fly during the run. qemu caps how many memory
    // regions a context can hold, so we stop mapping past a limit and let the
    // run end capped instead of letting unicorn abort the whole process.
    map_count: usize,
    // function body range [func_lo, func_hi) and the count of its own code bytes
    // we executed (each in-range instruction counted once). the ratio to func
    // size is the coverage signal: a function that hides behavior behind a guard
    // we never cross shows low coverage.
    func_lo: u64,
    func_hi: u64,
    covered_bytes: u64,
    // body instruction addr -> length, for blanket restart selection
    covered: HashMap<u64, u64>,
    // direct call targets inside the image that are not imports. the call-graph
    // edges for the matcher, kept out of the effect tokens.
    callees: HashSet<u64>,
    // total mem-hook callbacks (reads + writes) this run. a single rep-prefixed
    // string op is ONE instruction (so instr_cap/visit_cap count it once) but
    // fires a mem hook per iteration with RCX seeded huge. the write side is
    // bounded by max_effects, but reads dedup and never grow effects, so a pure
    // read rep (rep lodsb/scasb/cmpsb) would otherwise run to RCX exhaustion,
    // bounded only by the wall-clock timeout. this counter bounds it
    // deterministically, independent of wall time.
    mem_op_iters: u64,
}

// deterministic ceiling on mem-hook callbacks per run, as a multiple of the
// instruction cap. a legit function does only a handful of memory ops per
// instruction, so instr_cap * this is far above any real run while still stopping
// a single rep string op in bounded, wall-clock-independent time.
const MEM_OPS_PER_INSTR_CAP: u64 = 64;

impl Rec {
    fn arg_base(k: usize) -> u64 {
        ARG_BASE + k as u64 * ARG_STRIDE
    }

    fn classify_value(&self, v: u64) -> ValueClass {
        if v == 0 {
            return ValueClass::Zero;
        }
        for k in 0..NARGS {
            let base = Self::arg_base(k);
            if v == base {
                return ValueClass::Input(k as u16);
            }
            // same 8k window, or within a few bytes: treat as drifted-from-input
            if v >= base && v < base + ARG_SIZE {
                return ValueClass::InputDeriv(k as u16);
            }
        }
        let sv = v as i64;
        if (-4096..=4096).contains(&sv) {
            return ValueClass::SmallConst(sv);
        }
        ValueClass::BigConst
    }

    // where did this address land, and at what offset from that region's base
    fn classify_addr(&self, addr: u64) -> (Region, i64) {
        for k in 0..NARGS {
            let base = Self::arg_base(k);
            if addr >= base && addr < base + ARG_SIZE {
                return (Region::Arg(k as u16), (addr - base) as i64);
            }
        }
        if (STACK_BASE..STACK_BASE + STACK_SIZE).contains(&addr) {
            return (Region::Stack, (addr as i64).wrapping_sub(RSP0 as i64));
        }
        for &(lo, hi) in &self.segs {
            if addr >= lo && addr < hi {
                return (Region::Global, 0); // absolute global offset isn't stable across builds
            }
        }
        // keep the in-struct offset so different field writes stay distinct
        (Region::Heapish, (addr & (PAGE - 1)) as i64)
    }

    fn note_new_region(&mut self, addr: u64) {
        let (region, _) = self.classify_addr(addr);
        match region {
            // first time we touch arg k: signal that the function uses it.
            // key args by a low id so they never collide with heap page keys.
            Region::Arg(k) => {
                let key = 0xA00 + k as u64;
                if self.seen_heapish.insert(key) {
                    self.effects.push(Effect::NewRegion(Region::Arg(k)));
                }
            }
            // touched static/global data (a table, a global var)
            Region::Global => {
                if self.seen_heapish.insert(0xB00) {
                    self.effects.push(Effect::NewRegion(Region::Global));
                }
            }
            // fresh buffer reached by chasing a pointer, strong shape signal
            Region::Heapish => {
                let page = addr & !(PAGE - 1);
                if self.seen_heapish.insert(page) && self.heapish_count < self.cfg.max_heapish {
                    self.heapish_count += 1;
                    self.effects.push(Effect::NewRegion(Region::Heapish));
                }
            }
            Region::Stack => {}
        }
    }
}

// what an instruction is, decoded just enough to steer the run
enum Kind {
    /// target: the direct call destination, or for `call [rip+disp]` the got
    /// slot it reads. direct says which, so only real e8 targets become callees.
    Call {
        target: Option<u64>,
        direct: bool,
    },
    Ret,
    Syscall,
    Branch {
        target: Option<u64>,
    },
    Plain,
}

impl MicroExec {
    pub fn new(cfg: Config) -> Self {
        MicroExec { cfg }
    }

    /// a single natural run, no forced branches. used by tests and as the
    /// baseline that path exploration diverges from.
    pub fn run(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
    ) -> EffectTrace {
        self.run_forced(image, func, symbols, &[]).0
    }

    /// explore a handful of paths per seed: the natural run plus one run for
    /// each of the first few branches where we take the other direction. this
    /// steps past input-validation gates that bail on our junk input, which is
    /// what keeps otherwise-identical-looking functions distinct. all traces
    /// are unioned into one fingerprint by the caller.
    pub fn run_explore(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
        seeds: &[u64],
    ) -> Vec<EffectTrace> {
        let mut out = Vec::new();
        // instruction starts of the body, for picking blanket restart points.
        // computed once, only if blanket is on.
        let starts: Vec<u64> = if self.cfg.blanket_restarts > 0 {
            insn_starts(image, func)
        } else {
            Vec::new()
        };
        for &sd in seeds {
            let mut cfg = self.cfg.clone();
            cfg.seed = sd;
            let ex = MicroExec { cfg };
            let (base, dirs, mut covered) = ex.run_from(image, func, symbols, &[], func.entry);
            out.push(base);
            let depth = dirs.len().min(ex.cfg.explore_depth);
            for i in 0..depth {
                // follow the natural path up to branch i, then flip it
                let mut plan = dirs[..i].to_vec();
                plan.push(!dirs[i]);
                out.push(ex.run_forced(image, func, symbols, &plan).0);
            }
            // blanket: restart at the first instruction nobody executed yet.
            // the union of covered addresses is the stopping rule, and every
            // restart trace reports the cumulative coverage so the caller's max
            // is the blanket figure, not the entry run's.
            let body: u64 = func.size.max(1);
            for _ in 0..ex.cfg.blanket_restarts {
                let covered_bytes: u64 = covered.values().sum();
                if covered_bytes as f32 / body as f32 >= BLANKET_ENOUGH {
                    break;
                }
                let Some(&at) = starts.iter().find(|a| !covered.contains_key(a)) else {
                    break;
                };
                let (mut t, _, more) = ex.run_from(image, func, symbols, &[], at);
                let before = covered.len();
                covered.extend(more);
                if covered.len() == before {
                    // ran nothing new (bad restart point, decode error): move
                    // on past it rather than spin on the same address.
                    covered.insert(at, 0);
                }
                let covered_bytes: u64 = covered.values().sum();
                t.coverage = (covered_bytes as f32 / body as f32).clamp(0.0, 1.0);
                // a restart begins with whatever was in the registers, which is
                // nothing like the real mid-function state and differs by build
                // (register allocation), so its memory offsets are noise. calls
                // and syscalls are the part that survives: keep those, drop the
                // rest. tried keeping everything: rank-1 on the bench halved.
                t.effects.retain(|e| {
                    matches!(
                        e,
                        Effect::Call(CallTarget::Sym(_)) | Effect::Syscall(_) | Effect::Capped
                    )
                });
                out.push(t);
            }
        }
        out
    }

    fn run_forced(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
        force: &[bool],
    ) -> (EffectTrace, Vec<bool>) {
        let (t, d, _) = self.run_from(image, func, symbols, force, func.entry);
        (t, d)
    }

    // one run starting at `start` (the entry, or a blanket restart point). also
    // hands back the body instructions it executed (addr -> length) so the
    // caller can pick the next restart.
    fn run_from(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
        force: &[bool],
        start: u64,
    ) -> RunOut {
        match self.try_run(image, func, symbols, force, start) {
            Ok(x) => x,
            // a run that blew up is still a (short, capped) signature, not a crash
            Err(_) => (
                EffectTrace {
                    effects: vec![Effect::Capped],
                    instret: 0,
                    capped: true,
                    coverage: 0.0,
                    callees: Vec::new(),
                },
                Vec::new(),
                HashMap::new(),
            ),
        }
    }

    fn try_run(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
        force: &[bool],
        start: u64,
    ) -> Result<RunOut, unicorn_engine::uc_error> {
        let cs = match image.arch {
            Isa::X86_64 => Some(
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .build()
                    .map_err(|_| unicorn_engine::uc_error::EXCEPTION)?,
            ),
            Isa::Aarch64 => None,
        };

        let rec = Rec {
            effects: Vec::new(),
            visits: HashMap::new(),
            instret: 0,
            capped: false,
            seen_heapish: HashSet::new(),
            seen_reads: HashSet::new(),
            heapish_count: 0,
            cs,
            isa: image.arch,
            symbols: symbols.clone(),
            ret_ctr: 0,
            cfg: self.cfg.clone(),
            segs: image
                .segments
                .iter()
                .map(|s| (s.vaddr, s.vaddr.saturating_add(s.bytes.len() as u64)))
                .collect(),
            force: force.to_vec(),
            branch_seen: 0,
            natural_dirs: Vec::new(),
            pending_branch: None,
            map_count: 0,
            mem_op_iters: 0,
            func_lo: func.entry,
            func_hi: func.entry.saturating_add(func.size),
            covered_bytes: 0,
            covered: HashMap::new(),
            callees: HashSet::new(),
        };

        let (ua, um) = match image.arch {
            Isa::X86_64 => (Arch::X86, Mode::MODE_64),
            Isa::Aarch64 => (Arch::ARM64, Mode::LITTLE_ENDIAN),
        };
        let mut uc = Unicorn::new_with_data(ua, um, rec)?;
        let mut mapped: HashSet<u64> = HashSet::new();

        for s in &image.segments {
            ensure_pages(&mut uc, &mut mapped, s.vaddr, s.bytes.len() as u64)?;
            uc.mem_write(s.vaddr, &s.bytes)?;
        }

        for k in 0..NARGS {
            let base = Rec::arg_base(k);
            ensure_pages(&mut uc, &mut mapped, base, ARG_SIZE)?;
            let mut fill = vec![0u8; ARG_SIZE as usize];
            fill_bytes(&mut fill, base, self.cfg.seed);
            uc.mem_write(base, &fill)?;
        }

        ensure_pages(&mut uc, &mut mapped, STACK_BASE, STACK_SIZE)?;
        // the return sentinel: on x86 it is the word at [rsp] the final ret
        // pops, on aarch64 it is the link register. either way the run ends
        // when the function returns to it, and emu_start stops there.
        uc.mem_write(RSP0, &RET_ADDR.to_le_bytes())?;
        match image.arch {
            Isa::X86_64 => {
                uc.reg_write(RegisterX86::RSP, RSP0)?;
                uc.reg_write(RegisterX86::RBP, RSP0)?;
                let argregs = [
                    RegisterX86::RDI,
                    RegisterX86::RSI,
                    RegisterX86::RDX,
                    RegisterX86::RCX,
                    RegisterX86::R8,
                    RegisterX86::R9,
                ];
                for (k, r) in argregs.iter().enumerate() {
                    uc.reg_write(*r, Rec::arg_base(k))?;
                }
            }
            Isa::Aarch64 => {
                uc.reg_write(RegisterARM64::SP, RSP0)?;
                uc.reg_write(RegisterARM64::X29, RSP0)?;
                uc.reg_write(RegisterARM64::X30, RET_ADDR)?;
                let argregs = [
                    RegisterARM64::X0,
                    RegisterARM64::X1,
                    RegisterARM64::X2,
                    RegisterARM64::X3,
                    RegisterARM64::X4,
                    RegisterARM64::X5,
                ];
                for (k, r) in argregs.iter().enumerate() {
                    uc.reg_write(*r, Rec::arg_base(k))?;
                }
            }
        }

        install_hooks(&mut uc)?;

        let cfg = self.cfg.clone();
        let run_res = uc.emu_start(start, RET_ADDR, cfg.timeout_us, cfg.instr_cap as usize);
        let rip = pc(&uc);

        let rec = uc.get_data_mut();
        if rec.instret >= cfg.instr_cap {
            rec.capped = true;
        }
        // a clean run stops exactly at our return sentinel. anything else - the
        // wall-clock backstop firing on a genuine hang, or an emu error - left a
        // truncated trace, so mark it capped instead of letting a partial run
        // look like a complete one. without this a function engineered to stall
        // past the deterministic caps but under the timer could forge a short,
        // clean-looking print run to run.
        if !rec.capped && (run_res.is_err() || rip != RET_ADDR) {
            rec.capped = true;
        }
        let mut effects = std::mem::take(&mut rec.effects);
        let dirs = std::mem::take(&mut rec.natural_dirs);
        let capped = rec.capped;
        let instret = rec.instret;
        // fraction of the function's own code bytes we executed. size is > 0 for
        // every indexed func (index filters size==0), but guard the divide and
        // clamp: overlapping/greedy sizes could push covered past size.
        let coverage = if func.size == 0 {
            1.0
        } else {
            (rec.covered_bytes as f32 / func.size as f32).clamp(0.0, 1.0)
        };
        if capped {
            effects.push(Effect::Capped);
        }
        let mut callees: Vec<u64> = rec.callees.iter().copied().collect();
        callees.sort_unstable();
        let covered = std::mem::take(&mut rec.covered);
        Ok((
            EffectTrace {
                effects,
                instret,
                capped,
                coverage,
                callees,
            },
            dirs,
            covered,
        ))
    }
}

// instruction start addresses of a function body, linear sweep, sorted. same
// decode-and-step-past-junk loop as static_calls.
fn insn_starts(image: &Image, func: &Func) -> Vec<u64> {
    let mut out = Vec::new();
    if image.arch == Isa::Aarch64 {
        let n = func.size.min(1 << 20) / 4;
        return (0..n).map(|i| func.entry.wrapping_add(i * 4)).collect();
    }
    let Ok(cs) = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()
    else {
        return out;
    };
    let lo = func.entry;
    let Some(code) = image.code_at(lo, func.size.min(1 << 20) as usize) else {
        return out;
    };
    let mut off = 0usize;
    while off < code.len() {
        let Ok(insns) = cs.disasm_all(&code[off..], lo + off as u64) else {
            break;
        };
        let mut advanced = 0usize;
        for insn in insns.iter() {
            out.push(insn.address());
            advanced += insn.bytes().len();
        }
        off += advanced.max(1);
    }
    out
}

/// the static call graph of one function: every direct `call` target inside the
/// image, every `call [rip+slot]` / direct call that resolves through `imports`
/// (returned by name), and a direct `jmp` that leaves the body (a tail call).
/// linear sweep, so it sees calls microexecution never reached on junk input,
/// which is most of a real function. returns (in-image callee entries, import
/// names), both deduped and sorted.
pub fn static_calls(
    image: &Image,
    func: &Func,
    imports: &HashMap<u64, String>,
) -> (Vec<u64>, Vec<String>) {
    let mut callees: Vec<u64> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let lo = func.entry;
    let hi = func.entry.saturating_add(func.size);
    // a crafted size can claim the whole image; a real function is far under this
    let Some(code) = image.code_at(lo, func.size.min(1 << 20) as usize) else {
        return (callees, names);
    };
    let segs: Vec<(u64, u64)> = image
        .segments
        .iter()
        .map(|s| (s.vaddr, s.vaddr.saturating_add(s.bytes.len() as u64)))
        .collect();
    let in_image = |t: u64| segs.iter().any(|&(a, b)| t >= a && t < b);
    if image.arch == Isa::Aarch64 {
        // bl = call, b out of the body = tail call. both pc-relative imm26.
        for (i, w) in code.chunks_exact(4).enumerate() {
            let a = lo.wrapping_add((i * 4) as u64);
            let w = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            let t = if w & 0xfc00_0000 == 0x9400_0000 {
                Some(a64_rel(a, w & 0x03ff_ffff, 26))
            } else if w & 0xfc00_0000 == 0x1400_0000 {
                let t = a64_rel(a, w & 0x03ff_ffff, 26);
                if t >= lo && t < hi {
                    None
                } else {
                    Some(t)
                }
            } else {
                None
            };
            if let Some(t) = t {
                if let Some(n) = imports.get(&t) {
                    names.push(n.clone());
                } else if in_image(t) {
                    callees.push(t);
                }
            }
        }
        callees.sort_unstable();
        callees.dedup();
        names.sort();
        names.dedup();
        return (callees, names);
    }
    let Ok(cs) = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()
    else {
        return (callees, names);
    };
    let mut off = 0usize;
    // capstone stops at the first byte it can't decode; step past it and keep
    // going so one odd byte (padding, data in text) doesn't hide the rest.
    while off < code.len() {
        let addr = lo + off as u64;
        let Ok(insns) = cs.disasm_all(&code[off..], addr) else {
            break;
        };
        let mut advanced = 0usize;
        for insn in insns.iter() {
            let b = insn.bytes();
            let ilen = b.len() as u64;
            let a = insn.address();
            advanced += b.len();
            let m = insn.mnemonic().unwrap_or("");
            let target = if b[0] == 0xe8 && b.len() >= 5 {
                let rel = i32::from_le_bytes([b[1], b[2], b[3], b[4]]) as i64;
                Some(a.wrapping_add(ilen).wrapping_add(rel as u64))
            } else if b[0] == 0xe9 && b.len() >= 5 && m == "jmp" {
                let rel = i32::from_le_bytes([b[1], b[2], b[3], b[4]]) as i64;
                let t = a.wrapping_add(ilen).wrapping_add(rel as u64);
                // a jmp inside the body is a loop/branch, outside it is a tail call
                if t >= lo && t < hi {
                    None
                } else {
                    Some(t)
                }
            } else if b.len() >= 6 && b[0] == 0xff && (b[1] == 0x15 || b[1] == 0x25) {
                // call/jmp [rip+disp32]: the got slot, named if it is an import
                let rel = i32::from_le_bytes([b[2], b[3], b[4], b[5]]) as i64;
                let slot = a.wrapping_add(ilen).wrapping_add(rel as u64);
                if let Some(n) = imports.get(&slot) {
                    names.push(n.clone());
                }
                None
            } else {
                None
            };
            if let Some(t) = target {
                if let Some(n) = imports.get(&t) {
                    names.push(n.clone());
                } else if in_image(t) {
                    callees.push(t);
                }
            }
        }
        if advanced == 0 {
            off += 1;
        } else {
            off += advanced;
        }
    }
    callees.sort_unstable();
    callees.dedup();
    names.sort();
    names.dedup();
    (callees, names)
}

fn install_hooks(uc: &mut Unicorn<Rec>) -> Result<(), unicorn_engine::uc_error> {
    // lazy memory: map + deterministically fill any data page we touch.
    // an unmapped *fetch* means we ran off into nonsense, so bail on those.
    uc.add_mem_hook(
        HookType::MEM_UNMAPPED,
        0,
        u64::MAX,
        |uc, ty, addr, _sz, _val| {
            if matches!(
                ty,
                MemType::FETCH_UNMAPPED | MemType::FETCH_PROT | MemType::FETCH
            ) {
                return false;
            }
            // too many distinct pages this run: stop before qemu's region cap
            // aborts us. end the run capped, the partial trace is still usable.
            {
                let rec = uc.get_data_mut();
                if rec.map_count >= MAX_RUNTIME_MAPS {
                    rec.capped = true;
                    return false;
                }
                rec.map_count += 1;
            }
            let page = addr & !(PAGE - 1);
            let seed = uc.get_data().cfg.seed;
            if uc.mem_map(page, PAGE, Prot::ALL).is_err() {
                return false;
            }
            let mut fill = [0u8; PAGE as usize];
            fill_bytes(&mut fill, page, seed);
            let _ = uc.mem_write(page, &fill);
            uc.get_data_mut().note_new_region(addr);
            true
        },
    )?;

    // reads don't produce a value effect, but first touch of an arg/heap region
    // tells us which inputs the function actually walks.
    uc.add_mem_hook(
        HookType::MEM_READ,
        0,
        u64::MAX,
        |uc, _ty, addr, _size, _val| {
            // reads dedup and never grow effects, so max_effects can't stop a pure
            // read rep (rep lodsb/scasb/cmpsb): one instruction, RCX seeded huge,
            // a callback per iteration. bound the total mem-op callbacks so it
            // stops deterministically instead of running to the wall-clock timeout.
            {
                let rec = uc.get_data_mut();
                rec.mem_op_iters += 1;
                if rec.mem_op_iters >= rec.cfg.instr_cap.saturating_mul(MEM_OPS_PER_INSTR_CAP) {
                    rec.capped = true;
                }
            }
            if uc.get_data().capped {
                uc.emu_stop().ok();
                return true;
            }
            let rec = uc.get_data_mut();
            rec.note_new_region(addr);
            let (region, off) = rec.classify_addr(addr);
            if region != Region::Stack {
                let off = bucket_off(off);
                // one Read per distinct field, so we get the footprint not the noise
                let key = fnprint_trace::Effect::Read { region, off }.token();
                if rec.seen_reads.insert(key) && rec.seen_reads.len() <= 64 {
                    rec.effects
                        .push(fnprint_trace::Effect::Read { region, off });
                }
            }
            true
        },
    )?;

    // record meaningful writes (arg buffers + fresh heap, stack spills ignored)
    uc.add_mem_hook(
        HookType::MEM_WRITE,
        0,
        u64::MAX,
        |uc, _ty, addr, size, val| {
            // the code hook enforces max_effects, but only between instructions.
            // a single `rep stos/movs` fires this write hook once per iteration
            // with RCX seeded huge, so without a gate here the effects vec grows
            // to millions from a 2-byte body. cap here too and stop the run.
            {
                let rec = uc.get_data_mut();
                rec.mem_op_iters += 1;
                if rec.effects.len() >= rec.cfg.max_effects
                    || rec.mem_op_iters >= rec.cfg.instr_cap.saturating_mul(MEM_OPS_PER_INSTR_CAP)
                {
                    rec.capped = true;
                }
            }
            if uc.get_data().capped {
                uc.emu_stop().ok();
                return true;
            }
            let rec = uc.get_data_mut();
            rec.note_new_region(addr);
            let (region, off) = rec.classify_addr(addr);
            if region == Region::Stack {
                return true;
            }
            let vc = rec.classify_value(mask_to_size(val as u64, size));
            let off = bucket_off(off);
            rec.effects.push(Effect::Write {
                region,
                off,
                val: vc,
            });
            true
        },
    )?;

    // per-instruction: steer calls/rets/syscalls, count for the caps
    uc.add_code_hook(0, u64::MAX, |uc, addr, _size| {
        let mut buf = [0u8; 16];
        let _ = uc.mem_read(addr, &mut buf);

        let (kind, ilen) = decode(uc.get_data(), addr, &buf);

        // resolve which way the previous branch actually went, by seeing where
        // we landed. only recorded for un-forced branches (the baseline run).
        {
            let rec = uc.get_data_mut();
            if let Some(t) = rec.pending_branch.take() {
                rec.natural_dirs.push(addr == t);
            }
        }

        // caps first
        {
            let rec = uc.get_data_mut();
            rec.instret += 1;
            let c = rec.visits.entry(addr).or_insert(0);
            *c += 1;
            if *c > rec.cfg.visit_cap
                || rec.instret > rec.cfg.instr_cap
                || rec.effects.len() >= rec.cfg.max_effects
            {
                rec.capped = true;
                uc.emu_stop().ok();
                return;
            }
        }
        // body coverage: count each in-range instruction once. separate borrow of
        // the data so the cap-counter borrow above doesn't tangle with emu_stop.
        {
            let rec = uc.get_data_mut();
            let first_visit = rec.visits.get(&addr).copied() == Some(1);
            if first_visit && addr >= rec.func_lo && addr < rec.func_hi {
                rec.covered_bytes = rec.covered_bytes.saturating_add(ilen);
                rec.covered.insert(addr, ilen);
            }
        }

        match kind {
            Kind::Call { target, direct } => {
                // `symbols` holds imports only (plt stubs + got slots), so a call
                // names as Sym(import) or Anon on both a symboled and a stripped
                // build. internal direct targets go to the callee edge list instead.
                let name = target.and_then(|t| uc.get_data().symbols.get(&t).cloned());
                let tag = {
                    let rec = uc.get_data_mut();
                    if let (Some(t), true, None) = (target, direct, name.as_ref()) {
                        if rec.segs.iter().any(|&(lo, hi)| t >= lo && t < hi) {
                            rec.callees.insert(t);
                        }
                    }
                    rec.ret_ctr += 1;
                    rec.effects.push(Effect::Call(match name {
                        Some(n) => CallTarget::Sym(n),
                        None => CallTarget::Anon,
                    }));
                    // deterministic stubbed return value
                    0x5555_0000_0000_0000u64 ^ rec.ret_ctr.wrapping_mul(0x9e3779b97f4a7c15)
                };
                // skip the call entirely: callee never runs, stack stays balanced
                set_retval(uc, tag);
                set_pc(uc, addr.wrapping_add(ilen));
            }
            Kind::Syscall => {
                let nr = syscall_nr(uc);
                let tag = {
                    let rec = uc.get_data_mut();
                    rec.effects.push(Effect::Syscall(nr));
                    rec.ret_ctr += 1;
                    0x6666_0000_0000_0000u64 ^ rec.ret_ctr
                };
                set_retval(uc, tag);
                set_pc(uc, addr.wrapping_add(ilen));
            }
            Kind::Ret => {
                let rax = retval(uc);
                let rec = uc.get_data_mut();
                let vc = rec.classify_value(rax);
                rec.effects.push(Effect::Ret(vc));
                // let it execute: it pops our sentinel and emu stops at RET_ADDR
            }
            Kind::Branch { target } => {
                // decide: are we forcing this one, or letting it run naturally?
                let forced = {
                    let rec = uc.get_data_mut();
                    rec.effects.push(Effect::Branch);
                    let idx = rec.branch_seen;
                    rec.branch_seen += 1;
                    if idx < rec.force.len() {
                        Some(rec.force[idx])
                    } else {
                        None
                    }
                };
                match (forced, target) {
                    (Some(dir), Some(t)) => {
                        // redirect to the chosen successor, skip the real jcc
                        let dest = if dir { t } else { addr.wrapping_add(ilen) };
                        set_pc(uc, dest);
                    }
                    _ => {
                        // natural: remember the target so we can read the
                        // outcome on the next instruction
                        uc.get_data_mut().pending_branch = target;
                    }
                }
            }
            Kind::Plain => {}
        }
    })?;

    Ok(())
}

// the per-isa register plumbing the code hook needs: where the pc, the return
// value and the syscall number live.
fn pc(uc: &Unicorn<Rec>) -> u64 {
    match uc.get_data().isa {
        Isa::X86_64 => uc.reg_read(RegisterX86::RIP).unwrap_or(0),
        Isa::Aarch64 => uc.reg_read(RegisterARM64::PC).unwrap_or(0),
    }
}
fn set_pc(uc: &mut Unicorn<Rec>, v: u64) {
    let _ = match uc.get_data().isa {
        Isa::X86_64 => uc.reg_write(RegisterX86::RIP, v),
        Isa::Aarch64 => uc.reg_write(RegisterARM64::PC, v),
    };
}
fn retval(uc: &Unicorn<Rec>) -> u64 {
    match uc.get_data().isa {
        Isa::X86_64 => uc.reg_read(RegisterX86::RAX).unwrap_or(0),
        Isa::Aarch64 => uc.reg_read(RegisterARM64::X0).unwrap_or(0),
    }
}
fn set_retval(uc: &mut Unicorn<Rec>, v: u64) {
    let _ = match uc.get_data().isa {
        Isa::X86_64 => uc.reg_write(RegisterX86::RAX, v),
        Isa::Aarch64 => uc.reg_write(RegisterARM64::X0, v),
    };
}
fn syscall_nr(uc: &Unicorn<Rec>) -> u32 {
    match uc.get_data().isa {
        Isa::X86_64 => uc.reg_read(RegisterX86::RAX).unwrap_or(0) as u32,
        Isa::Aarch64 => uc.reg_read(RegisterARM64::X8).unwrap_or(0) as u32,
    }
}

// decode just enough: what kind of instruction and how long.
fn decode(rec: &Rec, addr: u64, buf: &[u8]) -> (Kind, u64) {
    let Some(cs) = rec.cs.as_ref() else {
        return decode_a64(addr, buf);
    };
    let insns = match cs.disasm_count(buf, addr, 1) {
        Ok(i) => i,
        Err(_) => return (Kind::Plain, 1),
    };
    let insn = match insns.iter().next() {
        Some(i) => i,
        None => return (Kind::Plain, 1),
    };
    let ilen = insn.bytes().len() as u64;
    let m = insn.mnemonic().unwrap_or("");

    let kind = if m.starts_with("call") {
        // direct call E8 rel32 -> resolve target. `call [rip+disp32]` (ff 15, the
        // -fno-plt / -z now shape) -> the got slot address, which the import map
        // also keys. anything else is indirect -> anon.
        let (target, direct) = if buf[0] == 0xe8 {
            let rel = i32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as i64;
            // wrapping: rip-relative math wraps on x86 and addr can sit near the
            // top of the space, so never let this overflow-panic
            (Some(addr.wrapping_add(ilen).wrapping_add(rel as u64)), true)
        } else if buf[0] == 0xff && buf[1] == 0x15 {
            let rel = i32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as i64;
            (
                Some(addr.wrapping_add(ilen).wrapping_add(rel as u64)),
                false,
            )
        } else {
            (None, false)
        };
        Kind::Call { target, direct }
    } else if m == "ret" || m.starts_with("ret") {
        Kind::Ret
    } else if m == "syscall" || m == "sysenter" || m == "int" {
        Kind::Syscall
    } else if m.starts_with('j') && m != "jmp" {
        // conditional jump. work out the taken target so we can force it.
        let target = branch_target(addr, ilen, buf);
        Kind::Branch { target }
    } else {
        Kind::Plain
    };
    (kind, ilen)
}

// aarch64: fixed 4-byte words, the kinds we steer on are all top-bits patterns.
//   bl imm26            1001 01ii ...           call, direct
//   blr xn              1101 0110 0011 1111 0000 00nn nnn0 0000   call, indirect
//   ret {xn}            1101 0110 0101 1111 0000 00nn nnn0 0000
//   svc #imm            1101 0100 000i iiii iiii iiii iii0 0001
//   b.cond imm19        0101 0100 iiii iiii iiii iiii iii0 cccc
//   cbz/cbnz imm19      x011 010o iiii iiii iiii iiii iiit tttt
//   tbz/tbnz imm14      x011 011o bbbb biii iiii iiii iiit tttt
// an unconditional b is a jump, not a decision, so it is Plain here (the static
// sweep treats one that leaves the body as a tail call).
fn decode_a64(addr: u64, buf: &[u8]) -> (Kind, u64) {
    if buf.len() < 4 {
        return (Kind::Plain, 4);
    }
    let w = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let kind = if w & 0xfc00_0000 == 0x9400_0000 {
        Kind::Call {
            target: Some(a64_rel(addr, w & 0x03ff_ffff, 26)),
            direct: true,
        }
    } else if w & 0xffff_fc1f == 0xd63f_0000 {
        Kind::Call {
            target: None,
            direct: false,
        }
    } else if w & 0xffff_fc1f == 0xd65f_0000 {
        Kind::Ret
    } else if w & 0xffe0_001f == 0xd400_0001 {
        Kind::Syscall
    } else if w & 0xff00_0010 == 0x5400_0000 || w & 0x7e00_0000 == 0x3400_0000 {
        Kind::Branch {
            target: Some(a64_rel(addr, (w >> 5) & 0x7_ffff, 19)),
        }
    } else if w & 0x7e00_0000 == 0x3600_0000 {
        Kind::Branch {
            target: Some(a64_rel(addr, (w >> 5) & 0x3fff, 14)),
        }
    } else {
        Kind::Plain
    };
    (kind, 4)
}

// pc-relative target from an aarch64 immediate of `bits` bits, in words
fn a64_rel(addr: u64, imm: u32, bits: u32) -> u64 {
    let shift = 64 - bits;
    let off = ((imm as u64) << shift) as i64 >> shift; // sign extend
    addr.wrapping_add((off as u64).wrapping_mul(4))
}

// taken-target of a conditional jump. handles the two common encodings:
// jcc rel8 (0x70..0x7f) and jcc rel32 (0x0f 0x80..0x8f). anything else -> None,
// and we just let it run naturally instead of forcing it.
fn branch_target(addr: u64, ilen: u64, buf: &[u8]) -> Option<u64> {
    if (0x70..=0x7f).contains(&buf[0]) {
        let rel = buf[1] as i8 as i64;
        Some(addr.wrapping_add(ilen).wrapping_add(rel as u64))
    } else if buf[0] == 0x0f && (0x80..=0x8f).contains(&buf[1]) {
        let rel = i32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as i64;
        Some(addr.wrapping_add(ilen).wrapping_add(rel as u64))
    } else {
        None
    }
}

fn ensure_pages(
    uc: &mut Unicorn<Rec>,
    mapped: &mut HashSet<u64>,
    start: u64,
    len: u64,
) -> Result<(), unicorn_engine::uc_error> {
    let first = start & !(PAGE - 1);
    // saturating so a wild start+len from a crafted segment can't wrap the
    // rounding; worst case last pins to the top page and the loop is bounded.
    let last = start.saturating_add(len).saturating_add(PAGE - 1) & !(PAGE - 1);
    if last <= first {
        return Ok(());
    }
    // map the whole span in ONE call, not page by page. qemu caps how many
    // memory regions a context can hold (phys_section_add asserts and aborts
    // the process), so a multi-MB segment mapped a page at a time blows past
    // that. one flat region per segment keeps the region count tiny.
    let span = last - first;
    if uc.mem_map(first, span, Prot::ALL).is_ok() {
        let mut p = first;
        while p < last {
            mapped.insert(p);
            p += PAGE;
        }
        return Ok(());
    }
    // bulk map failed: part of the span overlaps an already-mapped region (a
    // legit shared boundary page between byte-disjoint segments). map just the
    // still-unmapped pages, but COALESCE maximal runs of them into one mem_map
    // each so a fragmented span can't explode into one region per page. `mapped`
    // is our authoritative mirror of what's mapped during setup (nothing else
    // maps here), so a page absent from it is genuinely free: a run of such
    // pages must map cleanly, and a failure is a real error we propagate rather
    // than swallow (swallowing left a page unmapped and faulted mid-run later).
    let mut runs = 0usize;
    let mut p = first;
    while p < last {
        if mapped.contains(&p) {
            p += PAGE;
            continue;
        }
        let run_start = p;
        while p < last && !mapped.contains(&p) {
            p += PAGE;
        }
        runs += 1;
        // a legit disjoint layout splits a span into at most a couple of runs
        // (boundary pages only). many runs means a pathological overlap pattern;
        // fail closed (-> capped trace) before we approach qemu's region cap.
        if runs > MAX_SETUP_RUNS {
            return Err(unicorn_engine::uc_error::NOMEM);
        }
        uc.mem_map(run_start, p - run_start, Prot::ALL)?;
        let mut q = run_start;
        while q < p {
            mapped.insert(q);
            q += PAGE;
        }
    }
    Ok(())
}

// deterministic page contents. splitmix64 keyed on the address so re-reads of
// the same byte always give the same value within a run.
fn fill_bytes(out: &mut [u8], base: u64, seed: u64) {
    let words = out.len() / 8;
    for i in 0..words {
        let mut x = base
            .wrapping_add((i as u64) << 3)
            .wrapping_add(seed.wrapping_mul(0x9e3779b97f4a7c15));
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
        x ^= x >> 31;
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
}

fn mask_to_size(v: u64, size: usize) -> u64 {
    match size {
        1 => v & 0xff,
        2 => v & 0xffff,
        4 => v & 0xffff_ffff,
        _ => v,
    }
}

// keep small struct offsets, drop the noise. bucket to 8, clamp.
fn bucket_off(off: i64) -> i32 {
    let b = (off / 8) * 8;
    b.clamp(-2048, 2048) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use fnprint_loader::{FuncSource, Segment};

    // build a tiny image out of raw machine code at 0x401000
    fn img(code: &[u8]) -> Image {
        Image {
            segments: vec![Segment {
                vaddr: 0x401000,
                bytes: code.to_vec(),
                exec: true,
                write: false,
            }],
            entry: 0x401000,
            is_pie: false,
            arch: Isa::X86_64,
        }
    }
    fn f() -> Func {
        Func {
            name: None,
            entry: 0x401000,
            size: 0x100,
            source: FuncSource::Symtab,
        }
    }

    #[test]
    fn coalescing_fallback_maps_shared_boundary_page() {
        // two byte-disjoint segments that share a rounded page: A ends mid-page and
        // B begins in that same page. B's span overlaps A's already-mapped page, so
        // ensure_pages takes the coalescing fallback. setup must still complete and
        // the function must actually run (instret > 0), proving the fallback mapped
        // the free pages instead of erroring the whole run out.
        let mut a = vec![0u8; 0xf00];
        a[0] = 0xc3; // `ret` at the entry 0x401000
        let image = Image {
            segments: vec![
                Segment {
                    vaddr: 0x401000,
                    bytes: a,
                    exec: true,
                    write: false,
                },
                Segment {
                    vaddr: 0x401f00,
                    bytes: vec![0u8; 0x200],
                    exec: false,
                    write: true,
                },
            ],
            entry: 0x401000,
            is_pie: false,
            arch: Isa::X86_64,
        };
        let func = Func {
            name: None,
            entry: 0x401000,
            size: 0x10,
            source: FuncSource::Symtab,
        };
        let t = MicroExec::new(Config::default()).run(&image, &func, &Arc::new(HashMap::new()));
        assert!(
            t.instret >= 1,
            "shared-boundary-page setup must map cleanly and run, got instret {}",
            t.instret
        );
    }

    #[test]
    fn writes_arg0_and_returns_it() {
        // mov [rdi], rsi ; mov rax, rdi ; ret
        let code = [0x48, 0x89, 0x37, 0x48, 0x89, 0xf8, 0xc3];
        let t = MicroExec::new(Config::default()).run(&img(&code), &f(), &Arc::new(HashMap::new()));
        let has_write = t.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Write {
                    region: Region::Arg(0),
                    val: ValueClass::Input(1),
                    ..
                }
            )
        });
        let ret_arg0 = t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Ret(ValueClass::Input(0))));
        assert!(
            has_write,
            "missing write of arg1 into arg0 buffer: {:?}",
            t.effects
        );
        assert!(ret_arg0, "should return arg0: {:?}", t.effects);
    }

    #[test]
    fn coverage_low_when_body_unexecuted() {
        // a single ret, but the func claims a large body. we only executed the
        // ret, so coverage is tiny: the body sat behind code we never reached.
        // this is the advisory signal for a print built from little behavior.
        let code = [0xc3]; // ret
        let func = Func {
            name: None,
            entry: 0x401000,
            size: 0x200,
            source: FuncSource::Symtab,
        };
        let t =
            MicroExec::new(Config::default()).run(&img(&code), &func, &Arc::new(HashMap::new()));
        assert!(t.coverage < 0.05, "coverage should be tiny: {}", t.coverage);
    }

    #[test]
    fn coverage_full_when_whole_body_runs() {
        // mov [rdi],rsi ; mov rax,rdi ; ret, with size == exactly these bytes.
        // every instruction runs, so coverage is ~1.0.
        let code = [0x48, 0x89, 0x37, 0x48, 0x89, 0xf8, 0xc3];
        let func = Func {
            name: None,
            entry: 0x401000,
            size: code.len() as u64,
            source: FuncSource::Symtab,
        };
        let t =
            MicroExec::new(Config::default()).run(&img(&code), &func, &Arc::new(HashMap::new()));
        assert!(t.coverage > 0.9, "coverage should be ~full: {}", t.coverage);
    }

    #[test]
    fn blanket_restart_reaches_code_behind_a_guard() {
        // test rdi,rdi ; jz +6 ; ret ; (dead on our input:) call 0x401100 ; ret
        // wait, rdi is a seeded pointer so the jz is NOT taken and we ret at
        // once. the call sits behind the early return and the entry run never
        // reaches it. a blanket restart starts at the first unexecuted
        // instruction (the call) and runs it, so the import shows up in the
        // union and coverage climbs.
        //   401000: 48 85 ff        test rdi,rdi
        //   401003: 74 01           jz  401006
        //   401005: c3              ret
        //   401006: e8 f5 00 00 00  call 401100   (rel = 0x401100 - 0x40100b)
        //   40100b: c3              ret
        let code = [
            0x48, 0x85, 0xff, 0x74, 0x01, 0xc3, 0xe8, 0xf5, 0x00, 0x00, 0x00, 0xc3,
        ];
        let func = Func {
            name: None,
            entry: 0x401000,
            size: code.len() as u64,
            source: FuncSource::Symtab,
        };
        let mut syms = HashMap::new();
        syms.insert(0x401100u64, "hidden_call".to_string());
        let syms = Arc::new(syms);
        let off = MicroExec::new(Config {
            blanket_restarts: 0,
            ..Config::default()
        })
        .run_explore(&img(&code), &func, &syms, &[0]);
        assert_eq!(off.len(), 1);
        assert!(!off[0].effects.iter().any(|e| matches!(e, Effect::Call(_))));
        let on = MicroExec::new(Config {
            blanket_restarts: 4,
            ..Config::default()
        })
        .run_explore(&img(&code), &func, &syms, &[0]);
        assert!(on.len() >= 2, "expected a restart trace: {}", on.len());
        let named = on
            .iter()
            .flat_map(|t| &t.effects)
            .any(|e| matches!(e, Effect::Call(CallTarget::Sym(n)) if n == "hidden_call"));
        assert!(named, "restart should reach the guarded call: {:?}", on);
        let cov = on.iter().map(|t| t.coverage).fold(0.0f32, f32::max);
        assert!(cov > 0.9, "blanket coverage should be ~full: {cov}");
        // restart traces carry calls only, never the junk memory shape
        for t in &on[1..] {
            assert!(t.effects.iter().all(|e| matches!(
                e,
                Effect::Call(CallTarget::Sym(_)) | Effect::Syscall(_) | Effect::Capped
            )));
        }
    }

    fn img_a64(code: &[u8]) -> Image {
        let mut i = img(code);
        i.arch = Isa::Aarch64;
        i
    }

    #[test]
    fn a64_decode_kinds_and_targets() {
        let le = |w: u32| w.to_le_bytes();
        // bl +0x100 from 0x401000 -> 0x401100
        assert!(matches!(
            decode_a64(0x401000, &le(0x9400_0040)).0,
            Kind::Call {
                target: Some(0x401100),
                direct: true
            }
        ));
        // bl backwards: imm26 = -1 -> pc - 4
        assert!(matches!(
            decode_a64(0x401000, &le(0x97ff_ffff)).0,
            Kind::Call {
                target: Some(0x400ffc),
                ..
            }
        ));
        assert!(matches!(
            decode_a64(0, &le(0xd63f_0000)).0,
            Kind::Call {
                target: None,
                direct: false
            }
        )); // blr x0
        assert!(matches!(decode_a64(0, &le(0xd65f_03c0)).0, Kind::Ret)); // ret
        assert!(matches!(decode_a64(0, &le(0xd400_0001)).0, Kind::Syscall)); // svc #0
                                                                             // b.eq +8, cbz x0 +8, tbz x0 #0 +8 all branch to pc+8
        for w in [0x5400_0040u32, 0xb400_0040, 0x3600_0040] {
            assert!(
                matches!(
                    decode_a64(0x1000, &le(w)).0,
                    Kind::Branch {
                        target: Some(0x1008)
                    }
                ),
                "{w:#x}"
            );
        }
        // plain: add x0, x0, #1 ; unconditional b is plain too (a jump, not a decision)
        assert!(matches!(decode_a64(0, &le(0x9100_0400)).0, Kind::Plain));
        assert!(matches!(decode_a64(0, &le(0x1400_0002)).0, Kind::Plain));
        assert_eq!(decode_a64(0, &le(0)).1, 4);
    }

    #[test]
    fn a64_writes_arg0_and_returns_it() {
        // str x1, [x0] ; mov x0, x1 ; ret   == the x86 test, other isa, same effects
        let mut code = Vec::new();
        code.extend_from_slice(&0xf900_0001u32.to_le_bytes());
        code.extend_from_slice(&0xaa01_03e0u32.to_le_bytes());
        code.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        let func = Func {
            name: None,
            entry: 0x401000,
            size: code.len() as u64,
            source: FuncSource::Symtab,
        };
        let t = MicroExec::new(Config::default()).run(
            &img_a64(&code),
            &func,
            &Arc::new(HashMap::new()),
        );
        assert!(!t.capped, "{t:?}");
        assert!(
            t.effects.iter().any(|e| matches!(
                e,
                Effect::Write {
                    region: Region::Arg(0),
                    off: 0,
                    val: ValueClass::Input(1)
                }
            )),
            "{:?}",
            t.effects
        );
        assert!(t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Ret(ValueClass::Input(1)))));
        assert!(t.coverage > 0.9);
    }

    #[test]
    fn a64_stubs_bl_and_records_callee_and_import() {
        // bl 0x401100 (local) ; bl 0x401200 (import) ; ret
        let mut code = Vec::new();
        code.extend_from_slice(&0x9400_0040u32.to_le_bytes());
        code.extend_from_slice(&0x9400_007fu32.to_le_bytes()); // 0x401004 + 0x7f*4 = 0x401200
        code.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        // give the image a big enough body that both targets are in-image
        let mut body = code.clone();
        body.resize(0x300, 0);
        let func = Func {
            name: None,
            entry: 0x401000,
            size: code.len() as u64,
            source: FuncSource::Symtab,
        };
        let mut imports = HashMap::new();
        imports.insert(0x401200u64, "memcpy".to_string());
        let image = img_a64(&body);
        let t = MicroExec::new(Config::default()).run(&image, &func, &Arc::new(imports.clone()));
        assert_eq!(t.callees, vec![0x401100], "{t:?}");
        assert!(t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Call(CallTarget::Sym(n)) if n == "memcpy")));
        assert!(t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Call(CallTarget::Anon))));
        assert!(t.effects.iter().any(|e| matches!(e, Effect::Ret(_))));
        let (callees, names) = static_calls(&image, &func, &imports);
        assert_eq!(callees, vec![0x401100]);
        assert_eq!(names, vec!["memcpy".to_string()]);
    }

    #[test]
    fn branch_target_no_overflow_near_top_of_space() {
        // a jcc with the most-negative rel32 at an address near u64::MAX. the
        // old code did `addr as i64 + rel` and panicked on i64 overflow; the
        // wrapping version must just return a wrapped target, no panic.
        let addr = u64::MAX - 3;
        let mut buf = [0u8; 16];
        buf[0] = 0x0f;
        buf[1] = 0x8c; // jl rel32
        buf[2..6].copy_from_slice(&i32::MIN.to_le_bytes());
        assert!(branch_target(addr, 6, &buf).is_some());
        // rel8 backward at the very top too
        let mut b8 = [0u8; 16];
        b8[0] = 0x7c; // jl rel8
        b8[1] = 0x80; // -128
        assert!(branch_target(u64::MAX, 2, &b8).is_some());
    }

    #[test]
    fn stubs_calls_and_records_name() {
        // call rel32 to 0x401100 ; ret. symbol map names that target.
        // e8 <rel> where rel = 0x401100 - (0x401000+5) = 0xfb
        let code = [0xe8, 0xfb, 0x00, 0x00, 0x00, 0xc3];
        let mut syms = HashMap::new();
        syms.insert(0x401100u64, "do_thing".to_string());
        let t = MicroExec::new(Config::default()).run(&img(&code), &f(), &Arc::new(syms));
        let named = t.effects.iter().any(|e| {
            matches!(e,
            Effect::Call(CallTarget::Sym(n)) if n == "do_thing")
        });
        assert!(named, "should stub+name the call: {:?}", t.effects);
        // and it must have returned (call was skipped, not dived into)
        assert!(t.effects.iter().any(|e| matches!(e, Effect::Ret(_))));
    }

    #[test]
    fn deterministic_across_runs() {
        // mov rax,[rdi] ; mov [rdi+8],rax ; ret  (chases a pointer, writes back)
        let code = [0x48, 0x8b, 0x07, 0x48, 0x89, 0x47, 0x08, 0xc3];
        let ex = MicroExec::new(Config::default());
        let a = ex.run(&img(&code), &f(), &Arc::new(HashMap::new()));
        let b = ex.run(&img(&code), &f(), &Arc::new(HashMap::new()));
        assert_eq!(a.tokens(), b.tokens());
    }

    #[test]
    fn effect_cap_is_respected() {
        // a long run of writes must stop at max_effects, not grow forever.
        // mov [rdi+rax*8], rax ; inc rax ; jmp back  (writes then loops)
        // simpler: unrolled-ish store loop via a tight self-jump with a store.
        // 48 89 07  mov [rdi],rax ; 48 ff c0 inc rax ; 48 89 07 ...; eb xx
        let mut code = Vec::new();
        for _ in 0..200 {
            code.extend_from_slice(&[0x48, 0x89, 0x07]); // mov [rdi], rax
            code.extend_from_slice(&[0x48, 0xff, 0xc7]); // inc rdi
        }
        code.push(0xc3);
        let cfg = Config {
            max_effects: 32,
            ..Config::default()
        };
        let t = MicroExec::new(cfg).run(&img(&code), &f(), &Arc::new(HashMap::new()));
        assert!(
            t.effects.len() <= 40,
            "effects not capped: {}",
            t.effects.len()
        );
    }

    #[test]
    fn rep_store_flood_is_capped() {
        // `rep stosb` is ONE instruction that writes RCX times, and RCX is seeded
        // huge. the per-instruction code-hook cap never runs between the writes,
        // so the write hook itself has to enforce max_effects or the effects vec
        // grows to millions from a 2-byte body. f3 aa = rep stos byte ; c3 ret.
        let code = [0xf3, 0xaa, 0xc3];
        let cfg = Config {
            max_effects: 32,
            ..Config::default()
        };
        let t = MicroExec::new(cfg).run(&img(&code), &f(), &Arc::new(HashMap::new()));
        assert!(
            t.effects.len() <= 40,
            "rep-store effects not capped: {}",
            t.effects.len()
        );
        assert!(t.capped, "rep flood should mark the trace capped");
    }

    #[test]
    fn rep_read_flood_is_capped() {
        // `rep lodsb` (f3 ac) is ONE read-only instruction repeated RCX times with
        // RCX seeded huge. reads dedup, so max_effects can't stop it; the mem-op
        // ceiling (instr_cap * MEM_OPS_PER_INSTR_CAP) must, deterministically and
        // without waiting on the wall-clock timeout. small instr_cap makes that
        // ceiling the binding bound. f3 ac = rep lodsb ; c3 ret.
        let code = [0xf3, 0xac, 0xc3];
        let cfg = Config {
            instr_cap: 10,
            ..Config::default()
        };
        let t = MicroExec::new(cfg).run(&img(&code), &f(), &Arc::new(HashMap::new()));
        assert!(
            t.capped,
            "pure-read rep flood should be capped by the mem-op ceiling"
        );
    }

    #[test]
    fn wild_loop_gets_capped_not_hung() {
        // jmp $ (eb fe) -> infinite. visit cap must stop it.
        let code = [0xeb, 0xfe];
        let t = MicroExec::new(Config::default()).run(&img(&code), &f(), &Arc::new(HashMap::new()));
        assert!(t.capped, "infinite loop should be capped");
    }
}
