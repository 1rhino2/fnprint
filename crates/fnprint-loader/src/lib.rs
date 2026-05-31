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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// grab the code bytes for a function out of the mapped segments
    pub fn code_at(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        for s in &self.segments {
            if vaddr >= s.vaddr && vaddr + len as u64 <= s.vaddr + s.bytes.len() as u64 {
                let off = (vaddr - s.vaddr) as usize;
                return Some(&s.bytes[off..off + len]);
            }
        }
        None
    }
}

pub struct Loaded {
    pub image: Image,
    pub funcs: Vec<Func>,
}

pub fn load(bytes: &[u8]) -> Result<Loaded> {
    let elf = Elf::parse(bytes).context("not a valid elf")?;
    if elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        bail!(
            "only x86-64 is supported in this version (got e_machine {})",
            elf.header.e_machine
        );
    }

    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let start = ph.p_offset as usize;
        let fsz = ph.p_filesz as usize;
        let end = start.saturating_add(fsz).min(bytes.len());
        let mut data = bytes[start..end].to_vec();
        // bss: memsz > filesz, pad with zeros so reads there are defined
        if (ph.p_memsz as usize) > data.len() {
            data.resize(ph.p_memsz as usize, 0);
        }
        segments.push(Segment {
            vaddr: ph.p_vaddr,
            bytes: data,
            exec: ph.is_executable(),
            write: ph.is_write(),
        });
    }
    if segments.is_empty() {
        bail!("no PT_LOAD segments");
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

fn discover(elf: &Elf, raw: &[u8]) -> Result<Vec<Func>> {
    let mut out = Vec::new();

    for (sym, src) in elf
        .syms
        .iter()
        .map(|s| (s, FuncSource::Symtab))
        .chain(elf.dynsyms.iter().map(|s| (s, FuncSource::DynSym)))
    {
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
        .map(|s| s.to_string())
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
    let start = sh.sh_offset as usize;
    let data = raw.get(start..start + sh.sh_size as usize)?;

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
}
