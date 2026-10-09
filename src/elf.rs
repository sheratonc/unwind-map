//! Minimal ELF32/ELF64 little-endian parser: headers, program headers,
//! section headers and function symbols.
//!
//! Section headers are optional at run time, so they are treated as
//! untrusted: if the table is missing or malformed the parser records a
//! warning and carries on with program headers alone.

use crate::reader::Reader;
use crate::{Error, Result};

pub const PT_LOAD: u32 = 1;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PF_X: u32 = 1;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xffff;

pub const EM_386: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

impl Class {
    pub fn addr_size(self) -> u8 {
        match self {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        }
    }

    pub fn bits(self) -> u8 {
        self.addr_size() * 8
    }
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub index: usize,
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SymbolTable {
    Symtab,
    Dynsym,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    /// `STB_LOCAL` (0), `STB_GLOBAL` (1) or `STB_WEAK` (2).
    pub bind: u8,
    pub table: SymbolTable,
}

/// A contiguous range of executable bytes that is backed by the file.
#[derive(Debug, Clone)]
pub struct ExecRange {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub offset: u64,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub class: Class,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_with(data, false)
    }

    /// Parses `data`; with `ignore_sections` the section header table is
    /// skipped entirely, as if the binary had been run through `sstrip`.
    pub fn parse_with(data: &'a [u8], ignore_sections: bool) -> Result<Self> {
        if data.len() < 16 || &data[..4] != b"\x7fELF" {
            bail!("not an ELF file");
        }
        let class = match data[4] {
            1 => Class::Elf32,
            2 => Class::Elf64,
            c => bail!("unknown ELF class {c}"),
        };
        match data[5] {
            1 => {}
            2 => bail!("big-endian ELF files are not supported yet"),
            d => bail!("unknown ELF data encoding {d}"),
        }

        let ws = class.addr_size();
        let mut r = Reader::at(data, 16);
        let e_type = r.u16()?;
        let machine = r.u16()?;
        let _version = r.u32()?;
        let entry = r.word(ws)?;
        let phoff = r.word(ws)?;
        let shoff = r.word(ws)?;
        let _flags = r.u32()?;
        let _ehsize = r.u16()?;
        let phentsize = r.u16()?;
        let phnum = r.u16()?;
        let shentsize = r.u16()?;
        let shnum = r.u16()?;
        let shstrndx = r.u16()?;

        let mut elf = Elf {
            data,
            class,
            e_type,
            machine,
            entry,
            segments: Vec::new(),
            sections: Vec::new(),
            warnings: Vec::new(),
        };
        elf.segments = elf.parse_segments(phoff, phentsize, phnum)?;
        if !ignore_sections && shoff != 0 {
            match elf.parse_sections(shoff, shentsize, shnum, shstrndx) {
                Ok(sections) => elf.sections = sections,
                Err(e) => elf
                    .warnings
                    .push(format!("ignoring section header table: {e}")),
            }
        }
        Ok(elf)
    }

    pub fn addr_size(&self) -> u8 {
        self.class.addr_size()
    }

    /// Returns `len` bytes at file offset `offset`.
    pub fn slice(&self, offset: u64, len: u64) -> Result<&'a [u8]> {
        let start = usize::try_from(offset).ok();
        let end = offset
            .checked_add(len)
            .and_then(|e| usize::try_from(e).ok());
        match (start, end) {
            (Some(s), Some(e)) if e <= self.data.len() => Ok(&self.data[s..e]),
            _ => bail!(
                "range {offset:#x}+{len:#x} is outside the file ({:#x} bytes)",
                self.data.len()
            ),
        }
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_data(&self, section: &Section) -> Result<&'a [u8]> {
        if section.sh_type == SHT_NOBITS {
            return Ok(&[]);
        }
        self.slice(section.offset, section.size)
            .map_err(|e| Error::new(format!("section {}: {e}", section.name)))
    }

    /// Returns the file-backed bytes from virtual address `vaddr` to the end
    /// of the loadable segment that contains it.
    pub fn bytes_from_vaddr(&self, vaddr: u64) -> Option<&'a [u8]> {
        self.segments
            .iter()
            .filter(|s| s.p_type == PT_LOAD)
            .find(|s| vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz)
            .and_then(|s| {
                let delta = vaddr - s.vaddr;
                self.slice(s.offset + delta, s.filesz - delta).ok()
            })
    }

    /// Lowest page-aligned load address, i.e. the address the file's first
    /// byte maps to when loaded at its link-time base.
    pub fn link_base(&self) -> u64 {
        self.segments
            .iter()
            .filter(|s| s.p_type == PT_LOAD)
            .map(|s| s.vaddr.wrapping_sub(s.offset) & !0xfff)
            .min()
            .unwrap_or(0)
    }

    /// Executable ranges: `SHF_EXECINSTR` sections when section headers are
    /// available, otherwise executable `PT_LOAD` segments.
    pub fn exec_ranges(&self) -> Vec<ExecRange> {
        let file_len = self.data.len() as u64;
        let mut out: Vec<ExecRange> = if self.sections.is_empty() {
            self.segments
                .iter()
                .filter(|s| s.p_type == PT_LOAD && s.flags & PF_X != 0 && s.filesz > 0)
                .map(|s| ExecRange {
                    name: format!("PT_LOAD[{}]", s.index),
                    start: s.vaddr,
                    end: s.vaddr + s.filesz,
                    offset: s.offset,
                })
                .collect()
        } else {
            self.sections
                .iter()
                .filter(|s| {
                    s.flags & (SHF_ALLOC | SHF_EXECINSTR) == SHF_ALLOC | SHF_EXECINSTR
                        && s.sh_type != SHT_NOBITS
                        && s.size > 0
                })
                .map(|s| ExecRange {
                    name: s.name.clone(),
                    start: s.addr,
                    end: s.addr + s.size,
                    offset: s.offset,
                })
                .collect()
        };
        out.retain(|r| r.offset.saturating_add(r.end - r.start) <= file_len);
        out.sort_by_key(|r| r.start);
        out
    }

    /// All defined function symbols from `.symtab` and `.dynsym`.
    pub fn function_symbols(&self) -> Vec<Symbol> {
        let mut out = Vec::new();
        for section in &self.sections {
            let table = match section.sh_type {
                SHT_SYMTAB => SymbolTable::Symtab,
                SHT_DYNSYM => SymbolTable::Dynsym,
                _ => continue,
            };
            // Symbols are only used for naming, so a damaged table is not
            // fatal: keep whatever was read before the damage.
            let _ = self.read_symbols(section, table, &mut out);
        }
        out
    }

    pub fn machine_name(&self) -> String {
        match self.machine {
            EM_386 => "x86".into(),
            EM_X86_64 => "x86-64".into(),
            EM_AARCH64 => "AArch64".into(),
            8 => "MIPS".into(),
            20 => "PowerPC".into(),
            21 => "PowerPC64".into(),
            40 => "ARM".into(),
            243 => "RISC-V".into(),
            258 => "LoongArch".into(),
            m => format!("machine {m}"),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self.e_type {
            1 => "REL",
            2 => "EXEC",
            3 => "DYN",
            4 => "CORE",
            _ => "unknown",
        }
    }

    fn parse_segments(&self, phoff: u64, entsize: u16, count: u16) -> Result<Vec<Segment>> {
        let need = match self.class {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        };
        if count == 0 {
            return Ok(Vec::new());
        }
        if entsize < need {
            bail!("program header entry size {entsize} is too small");
        }
        let mut out = Vec::with_capacity(count.into());
        for index in 0..usize::from(count) {
            let off = phoff + (index as u64) * u64::from(entsize);
            let raw = self
                .slice(off, u64::from(need))
                .map_err(|e| Error::new(format!("program header {index}: {e}")))?;
            let mut r = Reader::new(raw);
            let seg = match self.class {
                Class::Elf32 => {
                    let p_type = r.u32()?;
                    let offset = r.u32()?.into();
                    let vaddr = r.u32()?.into();
                    let _paddr = r.u32()?;
                    let filesz = r.u32()?.into();
                    let memsz = r.u32()?.into();
                    let flags = r.u32()?;
                    Segment {
                        index,
                        p_type,
                        flags,
                        offset,
                        vaddr,
                        filesz,
                        memsz,
                    }
                }
                Class::Elf64 => {
                    let p_type = r.u32()?;
                    let flags = r.u32()?;
                    let offset = r.u64()?;
                    let vaddr = r.u64()?;
                    let _paddr = r.u64()?;
                    let filesz = r.u64()?;
                    let memsz = r.u64()?;
                    Segment {
                        index,
                        p_type,
                        flags,
                        offset,
                        vaddr,
                        filesz,
                        memsz,
                    }
                }
            };
            out.push(seg);
        }
        Ok(out)
    }

    fn parse_sections(
        &self,
        shoff: u64,
        entsize: u16,
        shnum: u16,
        shstrndx: u16,
    ) -> Result<Vec<Section>> {
        let need: u16 = match self.class {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        };
        if entsize < need {
            bail!("section header entry size {entsize} is too small");
        }
        let read = |index: u64| -> Result<(u32, Section)> {
            let raw = self.slice(shoff + index * u64::from(entsize), need.into())?;
            let mut r = Reader::new(raw);
            let ws = self.addr_size();
            let name = r.u32()?;
            let sh_type = r.u32()?;
            let flags = r.word(ws)?;
            let addr = r.word(ws)?;
            let offset = r.word(ws)?;
            let size = r.word(ws)?;
            let link = r.u32()?;
            Ok((
                name,
                Section {
                    name: String::new(),
                    sh_type,
                    flags,
                    addr,
                    offset,
                    size,
                    link,
                },
            ))
        };

        // Extended numbering: the real counts live in section header 0.
        let (_, first) = read(0)?;
        let count = if shnum == 0 {
            first.size
        } else {
            u64::from(shnum)
        };
        let strndx = if shstrndx == SHN_XINDEX {
            u64::from(first.link)
        } else {
            u64::from(shstrndx)
        };
        if count > 0x10000
            || shoff.saturating_add(count * u64::from(entsize)) > self.data.len() as u64
        {
            bail!(
                "section header table ({count} entries at {shoff:#x}) runs past the end of the file"
            );
        }

        let mut raw = Vec::with_capacity(count as usize);
        for i in 0..count {
            raw.push(read(i)?);
        }
        let strtab = raw
            .get(strndx as usize)
            .filter(|(_, s)| s.sh_type != SHT_NOBITS)
            .and_then(|(_, s)| self.slice(s.offset, s.size).ok())
            .ok_or_else(|| Error::new(format!("section name table index {strndx} is invalid")))?;

        Ok(raw
            .into_iter()
            .map(|(name_off, mut s)| {
                s.name = Reader::at(strtab, name_off as usize)
                    .cstr()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                s
            })
            .collect())
    }

    fn read_symbols(
        &self,
        section: &Section,
        table: SymbolTable,
        out: &mut Vec<Symbol>,
    ) -> Result<()> {
        let data = self.section_data(section)?;
        let strtab = self
            .sections
            .get(section.link as usize)
            .ok_or_else(|| Error::new("symbol table has no string table"))?;
        let strings = self.section_data(strtab)?;
        let entsize = match self.class {
            Class::Elf32 => 16,
            Class::Elf64 => 24,
        };
        for raw in data.chunks_exact(entsize).skip(1) {
            let mut r = Reader::new(raw);
            let (name, value, size, info, shndx) = match self.class {
                Class::Elf32 => {
                    let name = r.u32()?;
                    let value = u64::from(r.u32()?);
                    let size = u64::from(r.u32()?);
                    let info = r.u8()?;
                    let _other = r.u8()?;
                    (name, value, size, info, r.u16()?)
                }
                Class::Elf64 => {
                    let name = r.u32()?;
                    let info = r.u8()?;
                    let _other = r.u8()?;
                    let shndx = r.u16()?;
                    (name, r.u64()?, r.u64()?, info, shndx)
                }
            };
            let kind = info & 0xf;
            if !(kind == STT_FUNC || kind == STT_GNU_IFUNC) || shndx == SHN_UNDEF || value == 0 {
                continue;
            }
            let Ok(name) = Reader::at(strings, name as usize).cstr() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            out.push(Symbol {
                name: String::from_utf8_lossy(name).into_owned(),
                addr: value,
                size,
                bind: info >> 4,
                table,
            });
        }
        Ok(())
    }
}
