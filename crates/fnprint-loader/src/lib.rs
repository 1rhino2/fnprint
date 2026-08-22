//! Load an ELF, hand back the loadable segments and a best-effort list of
//! functions. x86-64 only for now (v0.1). We try symbols first, fall back to
//! .eh_frame FDE ranges when the thing is stripped, which covers most release
//! binaries since they keep unwind info even without a symtab.

use anyhow::{bail, Context, Result};
use goblin::elf::Elf;

#[derive(Clone)]
pub struct Segment {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
    pub exec: bool,
    pub write: bool,
}

#[derive(Clone, Debug)]
pub struct Func {
    pub name: Option<String>,
    pub entry: u64,
    pub size: u64,
    /// how we found it, handy for debugging discovery
    pub source: FuncSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FuncSource {
    Symtab,
    DynSym,
    EhFrame,
}

pub struct Image {
    pub segments: Vec<Segment>,
    pub entry: u64,
    pub is_pie: bool,
}

impl Image {
    /// grab the code bytes for a function out of the mapped segments.
    /// vaddr/len come from attacker-controlled headers, so every bound is
    /// checked without ever doing arithmetic that can wrap.
    pub fn code_at(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let len = len as u64;
        for s in &self.segments {
            if vaddr < s.vaddr {
                continue;
            }
            let off = vaddr - s.vaddr; // safe: vaddr >= s.vaddr
            let seg_len = s.bytes.len() as u64;
            // off + len must fit inside the segment, no overflow
            if off.checked_add(len).is_none_or(|end| end > seg_len) {
                continue;
            }
            let off = off as usize;
            return Some(&s.bytes[off..off + len as usize]);
        }
        None
    }
}

pub struct Loaded {
    pub image: Image,
    pub funcs: Vec<Func>,
}

/// a single PT_LOAD bigger than this is refused rather than allocated. real RE
/// targets, firmware included, sit well under it (real binaries run single-digit
/// to low-hundreds of MB); anything past it is a crafted header (tiny p_filesz,
/// huge p_memsz) trying to amplify a few bytes of file into a big zero-fill and
/// allocate our way into an OOM. kept at 1 GiB: still orders of magnitude over
/// any real input, but it halves the worst-case single-shot allocation a crafted
/// bss claim can force.
const MAX_SEG_MEM: u64 = 1 << 30; // 1 GiB
/// total mapped memory across all segments, same idea, bounds a fan-out of many
/// medium segments that each pass the per-segment check.
const MAX_TOTAL_MEM: u64 = 1 << 31; // 2 GiB

pub fn load(bytes: &[u8]) -> Result<Loaded> {
    let elf = Elf::parse(bytes).context("not a valid elf")?;
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        bail!(
            "only x86-64 is supported in this version (got e_machine {})",
            elf.header.e_machine
        );
    }

    // first pass: validate every PT_LOAD and sum what it WILL allocate, WITHOUT
    // allocating anything yet. the total-memory guard has to count the actual
    // bytes each segment holds, which is the file-window copy (end-start) grown to
    // the bss tail (memsz), not p_memsz alone. a header with p_memsz=0 but a huge
    // p_filesz still copies a whole file window, so many overlapping ones would
    // amplify past the cap if we only counted memsz. computing the sum before any
    // copy means such a bomb is rejected outright instead of ballooning up to the
    // cap and only then bailing.
    let mut plans: Vec<(usize, usize, usize, u64, bool, bool)> = Vec::new();
    let mut total_mem: u64 = 0;
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        // refuse a bss claim we won't allocate for (loader bomb)
        if ph.p_memsz > MAX_SEG_MEM {
            bail!(
                "PT_LOAD p_memsz {} over {}-byte limit, refusing",
                ph.p_memsz,
                MAX_SEG_MEM
            );
        }
        // a vaddr+memsz that wraps u64 is nonsense and would overflow the
        // page math downstream, reject it here at the boundary.
        if ph.p_vaddr.checked_add(ph.p_memsz).is_none() {
            bail!("PT_LOAD vaddr {:#x} + memsz overflows", ph.p_vaddr);
        }

        // clamp the file window: p_offset past EOF must not slice-panic. try_from
        // so a value too big for usize (32-bit target) clamps to EOF instead of
        // truncating past the .min() guard.
        let start = usize::try_from(ph.p_offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let fsz = usize::try_from(ph.p_filesz).unwrap_or(usize::MAX);
        let end = start.saturating_add(fsz).min(bytes.len());
        // p_memsz is already capped under MAX_SEG_MEM above, so it fits usize.
        let memsz = usize::try_from(ph.p_memsz).unwrap_or(usize::MAX);

        let alloc_len = (end - start).max(memsz); // end >= start, no wrap
        total_mem = total_mem.saturating_add(alloc_len as u64);
        if total_mem > MAX_TOTAL_MEM {
            bail!("total PT_LOAD memory over {}-byte limit", MAX_TOTAL_MEM);
        }
        plans.push((
            start,
            end,
            memsz,
            ph.p_vaddr,
            ph.is_executable(),
            ph.is_write(),
        ));
    }
    if plans.is_empty() {
        bail!("no PT_LOAD segments");
    }

    // second pass: now that the total is known-bounded, actually copy.
    let mut segments = Vec::with_capacity(plans.len());
    for (start, end, memsz, vaddr, exec, write) in plans {
        let mut data = Vec::with_capacity((end - start).max(memsz));
        data.extend_from_slice(&bytes[start..end]);
        // bss: memsz > filesz, pad with zeros so reads there are defined.
        if memsz > data.len() {
            data.resize(memsz, 0);
        }
        segments.push(Segment {
            vaddr,
            bytes: data,
            exec,
            write,
        });
    }

    let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    let mut funcs = discover(&elf, bytes)?;
    // sort + dedup by entry, prefer named entries
    funcs.sort_by(|a, b| {
        a.entry
            .cmp(&b.entry)
            .then(b.name.is_some().cmp(&a.name.is_some()))
    });
    funcs.dedup_by_key(|f| f.entry);

    Ok(Loaded {
        image: Image {
            segments,
            entry: elf.header.e_entry,
            is_pie,
        },
        funcs,
    })
}

// a crafted ELF can point thousands of symbols at one long strtab run, so cloning
// each name would be (symbol count * name length) bytes: a small file forcing a
// huge allocation. cap both. real binaries are far under these (libcrypto ~6k
// functions, symbol names tens of bytes); a name past the cap is truncated, and we
// stop after MAX_FUNCS symbols. the segment loader's own MAX_TOTAL_MEM does not
// cover the symbol table, so this is where that amplification is bounded.
const MAX_NAME: usize = 4096;
const MAX_FUNCS: usize = 1_000_000;

fn clamp_name(s: &str) -> String {
    if s.len() <= MAX_NAME {
        return s.to_string();
    }
    let mut end = MAX_NAME;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn discover(elf: &Elf, raw: &[u8]) -> Result<Vec<Func>> {
    let mut out = Vec::new();

    for (sym, src) in elf
        .syms
        .iter()
        .map(|s| (s, FuncSource::Symtab))
        .chain(elf.dynsyms.iter().map(|s| (s, FuncSource::DynSym)))
    {
        if out.len() >= MAX_FUNCS {
            break; // pathological symbol count; stop rather than amplify
        }
        if sym.st_type() != goblin::elf::sym::STT_FUNC {
            continue;
        }
        if sym.st_value == 0 || sym.st_size == 0 {
            continue; // imports / plt stubs with no body
        }
        let name = match src {
            FuncSource::Symtab => elf.strtab.get_at(sym.st_name),
            _ => elf.dynstrtab.get_at(sym.st_name),
        }
        .map(clamp_name)
        .filter(|s| !s.is_empty());
        out.push(Func {
            name,
            entry: sym.st_value,
            size: sym.st_size,
            source: src,
        });
    }

    // stripped? lean on unwind info.
    if out.is_empty() {
        if let Some(mut fdes) = eh_frame_funcs(elf, raw) {
            out.append(&mut fdes);
        }
    }

    Ok(out)
}

// pull function start+length out of every FDE in .eh_frame.
fn eh_frame_funcs(elf: &Elf, raw: &[u8]) -> Option<Vec<Func>> {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};

    let sh = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".eh_frame"))?;
    // sh_offset/sh_size are attacker-controlled. try_from (None if too big for
    // usize) + checked_add so a crafted size can't overflow the range and
    // panic; get() handles past-EOF as None.
    let start = usize::try_from(sh.sh_offset).ok()?;
    let size = usize::try_from(sh.sh_size).ok()?;
    let end = start.checked_add(size)?;
    let data = raw.get(start..end)?;

    let eh = EhFrame::new(data, LittleEndian);
    let bases = BaseAddresses::default().set_eh_frame(sh.sh_addr);

    let mut entries = eh.entries(&bases);
    let mut out = Vec::new();
    loop {
        match entries.next() {
            Ok(Some(CieOrFde::Fde(partial))) => {
                if let Ok(fde) = partial.parse(EhFrame::cie_from_offset) {
                    let entry = fde.initial_address();
                    let size = fde.len();
                    if size > 0 {
                        out.push(Func {
                            name: None,
                            entry,
                            size,
                            source: FuncSource::EhFrame,
                        });
                    }
                }
            }
            Ok(Some(CieOrFde::Cie(_))) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_input_errors_not_panics() {
        assert!(load(b"").is_err());
        assert!(load(b"not an elf at all, just text here").is_err());
        // elf magic then garbage bytes
        let mut junk = vec![0x7f, b'E', b'L', b'F'];
        junk.extend(std::iter::repeat_n(0x41u8, 400));
        let _ = load(&junk); // must return Err/Ok, never panic
    }

    #[test]
    fn truncated_header_does_not_panic() {
        let mut hdr = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        hdr.extend(std::iter::repeat_n(0u8, 48));
        let _ = load(&hdr);
    }

    // minimal ELF64 x86-64 with exactly one PT_LOAD, so we can craft hostile
    // program-header fields and prove the loader refuses them instead of
    // panicking or allocating its way into an OOM.
    fn craft_elf(p_offset: u64, p_vaddr: u64, p_filesz: u64, p_memsz: u64) -> Vec<u8> {
        let mut e = vec![0u8; 64 + 56];
        e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        e[4] = 2; // ELFCLASS64
        e[5] = 1; // ELFDATA2LSB
        e[6] = 1; // EV_CURRENT
        let put16 =
            |e: &mut [u8], off: usize, v: u16| e[off..off + 2].copy_from_slice(&v.to_le_bytes());
        let put32 =
            |e: &mut [u8], off: usize, v: u32| e[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |e: &mut [u8], off: usize, v: u64| e[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put16(&mut e, 16, 2); // e_type ET_EXEC
        put16(&mut e, 18, 62); // e_machine EM_X86_64
        put32(&mut e, 20, 1); // e_version
        put64(&mut e, 32, 64); // e_phoff, header is 64 bytes
        put16(&mut e, 52, 64); // e_ehsize
        put16(&mut e, 54, 56); // e_phentsize
        put16(&mut e, 56, 1); // e_phnum
                              // program header at offset 64
        let ph = 64;
        put32(&mut e, ph, 1); // p_type PT_LOAD
        put32(&mut e, ph + 4, 5); // p_flags R+X
        put64(&mut e, ph + 8, p_offset);
        put64(&mut e, ph + 16, p_vaddr);
        put64(&mut e, ph + 32, p_filesz);
        put64(&mut e, ph + 40, p_memsz);
        put64(&mut e, ph + 48, 0x1000); // p_align
        e
    }

    #[test]
    fn huge_memsz_is_refused_not_allocated() {
        // p_memsz near u64::MAX must error, never try to allocate ~16 EiB
        let elf = craft_elf(0, 0x1000, 0, u64::MAX);
        assert!(load(&elf).is_err());
        // just over the cap is refused too
        let elf = craft_elf(0, 0x1000, 0, MAX_SEG_MEM + 1);
        assert!(load(&elf).is_err());
    }

    #[test]
    fn vaddr_plus_memsz_overflow_is_refused() {
        let elf = craft_elf(0, u64::MAX - 16, 0, 4096);
        assert!(load(&elf).is_err());
    }

    // many overlapping file-backed PT_LOAD headers (p_memsz=0, huge p_filesz).
    // each copies a full file window; the old cap only summed p_memsz so it never
    // tripped and the loader would allocate n*filesize (hundreds of GB). the fix
    // sums the real copy length and refuses before allocating anything.
    fn craft_elf_many_load(n: u16) -> Vec<u8> {
        let phoff = 64usize;
        let file_len = phoff + (n as usize) * 56;
        let mut e = vec![0u8; file_len];
        e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        e[4] = 2; // ELFCLASS64
        e[5] = 1; // ELFDATA2LSB
        e[6] = 1; // EV_CURRENT
        let put16 =
            |e: &mut [u8], off: usize, v: u16| e[off..off + 2].copy_from_slice(&v.to_le_bytes());
        let put32 =
            |e: &mut [u8], off: usize, v: u32| e[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |e: &mut [u8], off: usize, v: u64| e[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put16(&mut e, 16, 2); // e_type ET_EXEC
        put16(&mut e, 18, 62); // e_machine EM_X86_64
        put32(&mut e, 20, 1);
        put64(&mut e, 32, phoff as u64);
        put16(&mut e, 52, 64);
        put16(&mut e, 54, 56);
        put16(&mut e, 56, n);
        for i in 0..n as usize {
            let ph = phoff + i * 56;
            put32(&mut e, ph, 1); // PT_LOAD
            put32(&mut e, ph + 4, 4); // R
            put64(&mut e, ph + 8, 0); // p_offset = 0
            put64(&mut e, ph + 16, 0x1000 + i as u64 * 0x1000); // distinct vaddr
            put64(&mut e, ph + 32, file_len as u64); // p_filesz = whole file
            put64(&mut e, ph + 40, 0); // p_memsz = 0, evades the old sum
            put64(&mut e, ph + 48, 0x1000);
        }
        e
    }

    #[test]
    fn overlapping_file_backed_segments_are_refused_not_allocated() {
        // n * file_len copies far exceed MAX_TOTAL_MEM. must Err on accounting,
        // never allocate its way there. (if this OOMs the test, the fix regressed.)
        let elf = craft_elf_many_load(20000);
        let r = load(&elf);
        assert!(
            r.is_err(),
            "expected the alloc-amplification bomb to be refused"
        );
    }

    #[test]
    fn offset_past_eof_does_not_panic() {
        // p_offset way past the file end must clamp, not slice-panic
        let elf = craft_elf(0xffff_0000, 0x1000, 32, 32);
        let _ = load(&elf); // Err or Ok, never a panic
    }

    #[test]
    fn code_at_high_vaddr_no_overflow() {
        // a segment near the top of the address space, then a read whose
        // vaddr+len would wrap: must return None, not panic
        let img = Image {
            segments: vec![Segment {
                vaddr: u64::MAX - 8,
                bytes: vec![0u8; 8],
                exec: true,
                write: false,
            }],
            entry: 0,
            is_pie: false,
        };
        assert!(img.code_at(u64::MAX - 4, 64).is_none());
        assert!(img.code_at(u64::MAX, 16).is_none());
    }
}
