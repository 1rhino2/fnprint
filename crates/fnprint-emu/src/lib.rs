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
use fnprint_loader::{Func, Image};
use fnprint_trace::{CallTarget, Effect, EffectTrace, Region, ValueClass};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

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
        }
    }
}

pub struct MicroExec {
    cfg: Config,
}

// everything the hooks need lives here so unicorn can hand it back via get_data.
struct Rec {
    effects: Vec<Effect>,
    visits: HashMap<u64, u32>,
    instret: u64,
    capped: bool,
    seen_heapish: HashSet<u64>,
    seen_reads: HashSet<u64>,
    heapish_count: usize,
    cs: Capstone,
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
    Call { target: Option<u64> },
    Ret,
    Syscall,
    Branch { target: Option<u64> },
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
        for &sd in seeds {
            let mut cfg = self.cfg.clone();
            cfg.seed = sd;
            let ex = MicroExec { cfg };
            let (base, dirs) = ex.run_forced(image, func, symbols, &[]);
            out.push(base);
            let depth = dirs.len().min(ex.cfg.explore_depth);
            for i in 0..depth {
                // follow the natural path up to branch i, then flip it
                let mut plan = dirs[..i].to_vec();
                plan.push(!dirs[i]);
                out.push(ex.run_forced(image, func, symbols, &plan).0);
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
        match self.try_run(image, func, symbols, force) {
            Ok(x) => x,
            // a run that blew up is still a (short, capped) signature, not a crash
            Err(_) => (
                EffectTrace {
                    effects: vec![Effect::Capped],
                    instret: 0,
                    capped: true,
                    coverage: 0.0,
                },
                Vec::new(),
            ),
        }
    }

    fn try_run(
        &self,
        image: &Image,
        func: &Func,
        symbols: &Arc<HashMap<u64, String>>,
        force: &[bool],
    ) -> Result<(EffectTrace, Vec<bool>), unicorn_engine::uc_error> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .map_err(|_| unicorn_engine::uc_error::EXCEPTION)?;

        let rec = Rec {
            effects: Vec::new(),
            visits: HashMap::new(),
            instret: 0,
            capped: false,
            seen_heapish: HashSet::new(),
            seen_reads: HashSet::new(),
            heapish_count: 0,
            cs,
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
        };

        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, rec)?;
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
        uc.reg_write(RegisterX86::RSP, RSP0)?;
        uc.reg_write(RegisterX86::RBP, RSP0)?;
        uc.mem_write(RSP0, &RET_ADDR.to_le_bytes())?;

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

        install_hooks(&mut uc)?;

        let cfg = self.cfg.clone();
        let run_res = uc.emu_start(func.entry, RET_ADDR, cfg.timeout_us, cfg.instr_cap as usize);
        let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);

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
        Ok((
            EffectTrace {
                effects,
                instret,
                capped,
                coverage,
            },
            dirs,
        ))
    }
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
            }
        }

        match kind {
            Kind::Call { target } => {
                let name = target.and_then(|t| uc.get_data().symbols.get(&t).cloned());
                let tag = {
                    let rec = uc.get_data_mut();
                    rec.ret_ctr += 1;
                    rec.effects.push(Effect::Call(match name {
                        Some(n) => CallTarget::Sym(n),
                        None => CallTarget::Anon,
                    }));
                    // deterministic stubbed return value
                    0x5555_0000_0000_0000u64 ^ rec.ret_ctr.wrapping_mul(0x9e3779b97f4a7c15)
                };
                // skip the call entirely: callee never runs, stack stays balanced
                let _ = uc.reg_write(RegisterX86::RAX, tag);
                let _ = uc.reg_write(RegisterX86::RIP, addr.wrapping_add(ilen));
            }
            Kind::Syscall => {
                let nr = uc.reg_read(RegisterX86::RAX).unwrap_or(0) as u32;
                let tag = {
                    let rec = uc.get_data_mut();
                    rec.effects.push(Effect::Syscall(nr));
                    rec.ret_ctr += 1;
                    0x6666_0000_0000_0000u64 ^ rec.ret_ctr
                };
                let _ = uc.reg_write(RegisterX86::RAX, tag);
                let _ = uc.reg_write(RegisterX86::RIP, addr.wrapping_add(ilen));
            }
            Kind::Ret => {
                let rax = uc.reg_read(RegisterX86::RAX).unwrap_or(0);
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
                        let _ = uc.reg_write(RegisterX86::RIP, dest);
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

// decode just enough: what kind of instruction and how long.
fn decode(rec: &Rec, addr: u64, buf: &[u8]) -> (Kind, u64) {
    let insns = match rec.cs.disasm_count(buf, addr, 1) {
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
        // direct call E8 rel32 -> resolve target, else indirect -> anon
        let target = if buf[0] == 0xe8 {
            let rel = i32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as i64;
            // wrapping: rip-relative math wraps on x86 and addr can sit near the
            // top of the space, so never let this overflow-panic
            Some(addr.wrapping_add(ilen).wrapping_add(rel as u64))
        } else {
            None
        };
        Kind::Call { target }
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
