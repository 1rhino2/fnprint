//! Micro-execute one function and record what it does.
//!
//! The trick (Godefroid's microexecution, also BLEX): run a function with no
//! real context. Any read from memory we didn't set up returns a deterministic
//! value and the page gets mapped on the fly, so wild pointers never crash and
//! the same seed always produces the same run. We seed the arg registers with
//! tagged pointers, stub out calls so we never dive into libc, and log an
//! arch-neutral effect stream. That stream is the thing we fingerprint.

use std::collections::{HashMap, HashSet};

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

#[derive(Clone)]
pub struct Config {
    pub instr_cap: u64,
    pub visit_cap: u32,
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
            timeout_us: 250_000,
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
    symbols: HashMap<u64, String>,
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
}

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
            return (Region::Stack, addr as i64 - RSP0 as i64);
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
    pub fn run(&self, image: &Image, func: &Func, symbols: &HashMap<u64, String>) -> EffectTrace {
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
        symbols: &HashMap<u64, String>,
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
        symbols: &HashMap<u64, String>,
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
                },
                Vec::new(),
            ),
        }
    }

    fn try_run(
        &self,
        image: &Image,
        func: &Func,
        symbols: &HashMap<u64, String>,
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
                .map(|s| (s.vaddr, s.vaddr + s.bytes.len() as u64))
                .collect(),
            force: force.to_vec(),
            branch_seen: 0,
            natural_dirs: Vec::new(),
            pending_branch: None,
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
        let _ = uc.emu_start(func.entry, RET_ADDR, cfg.timeout_us, cfg.instr_cap as usize);

        let rec = uc.get_data_mut();
        if rec.instret >= cfg.instr_cap {
            rec.capped = true;
        }
        let mut effects = std::mem::take(&mut rec.effects);
        let dirs = std::mem::take(&mut rec.natural_dirs);
        let capped = rec.capped;
        let instret = rec.instret;
        if capped {
            effects.push(Effect::Capped);
        }
        Ok((
            EffectTrace {
                effects,
                instret,
                capped,
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
                let _ = uc.reg_write(RegisterX86::RIP, addr + ilen);
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
                let _ = uc.reg_write(RegisterX86::RIP, addr + ilen);
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
                        let dest = if dir { t } else { addr + ilen };
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
            Some((addr as i64 + ilen as i64 + rel) as u64)
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
        Some((addr as i64 + ilen as i64 + rel) as u64)
    } else if buf[0] == 0x0f && (0x80..=0x8f).contains(&buf[1]) {
        let rel = i32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as i64;
        Some((addr as i64 + ilen as i64 + rel) as u64)
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
    let last = (start + len + PAGE - 1) & !(PAGE - 1);
    let mut p = first;
    while p < last {
        if mapped.insert(p) {
            // ignore already-mapped errors from overlap, keep going
            let _ = uc.mem_map(p, PAGE, Prot::ALL);
        }
        p += PAGE;
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

