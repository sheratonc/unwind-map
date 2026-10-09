//! Turns raw FDEs into a named, de-duplicated function map with coverage
//! statistics.

use std::collections::HashMap;

use crate::ehframe::{EhFrame, Walk, parse_eh_frame_hdr};
use crate::elf::{Class, Elf, ExecRange, PT_GNU_EH_FRAME, SHT_NOBITS, Symbol, SymbolTable};
use crate::padding::code_span;
use crate::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Ignore section headers and find unwind data through `PT_GNU_EH_FRAME`.
    pub ignore_sections: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// `.symtab`, i.e. the binary was not stripped.
    Symtab,
    /// `.dynsym`, which survives stripping for exported functions.
    Dynsym,
    /// The function starts exactly at an executable section such as `.plt`.
    Section,
    /// No symbol, but it is the ELF entry point: named `entry`, as in Ghidra.
    Entry,
    /// No name available: `sub_<address>`.
    Synthetic,
}

/// Name used for an unnamed function or gap at the ELF entry point.
pub const ENTRY_NAME: &str = "entry";

#[derive(Debug, Clone)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub name_source: NameSource,
    pub has_lsda: bool,
    pub has_personality: bool,
    pub signal_frame: bool,
}

impl Function {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_named(&self) -> bool {
        matches!(self.name_source, NameSource::Symtab | NameSource::Dynsym)
    }
}

/// Executable bytes with no unwind information that do not look like
/// alignment padding: hand-written assembly, code built without unwind
/// tables, or PLT stubs.
#[derive(Debug, Clone)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
    pub section: String,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UnwindSource {
    /// Read from the `.eh_frame` section.
    Section { eh_frame: u64, size: u64 },
    /// Located through `PT_GNU_EH_FRAME` / `.eh_frame_hdr`.
    Header {
        eh_frame_hdr: u64,
        eh_frame: u64,
        via_table: bool,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub cies: usize,
    pub fdes: usize,
    pub named: usize,
    /// FDEs whose start is not inside executable code (e.g. discarded functions).
    pub outside_exec: usize,
    /// FDEs with an empty or wrapping range.
    pub empty: usize,
    /// FDEs that start at the same address as an earlier one.
    pub duplicates: usize,
    pub exec_bytes: u64,
    pub covered_bytes: u64,
    pub uncovered_code_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub class: Class,
    pub machine: u16,
    pub machine_name: String,
    pub file_type: &'static str,
    pub entry: u64,
    pub link_base: u64,
    pub has_sections: bool,
    pub source: UnwindSource,
    pub functions: Vec<Function>,
    pub gaps: Vec<Gap>,
    pub exec: Vec<ExecRange>,
    pub stats: Stats,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn coverage(&self) -> f64 {
        if self.stats.exec_bytes == 0 {
            0.0
        } else {
            self.stats.covered_bytes as f64 * 100.0 / self.stats.exec_bytes as f64
        }
    }
}

/// Analyzes an ELF image held in memory.
pub fn analyze(data: &[u8], opts: &Options) -> Result<Report> {
    let elf = Elf::parse_with(data, opts.ignore_sections)?;
    let mut warnings = elf.warnings.clone();
    let (walk, source) = load_fdes(&elf)?;
    warnings.extend(walk.warnings);

    let exec = elf.exec_ranges();
    let mut stats = Stats {
        cies: walk.cie_count,
        fdes: walk.fdes.len(),
        ..Default::default()
    };

    let mut fdes = Vec::with_capacity(walk.fdes.len());
    for fde in walk.fdes {
        if fde.end <= fde.start {
            stats.empty += 1;
        } else if !exec
            .iter()
            .any(|r| r.start <= fde.start && fde.start < r.end)
        {
            stats.outside_exec += 1;
        } else {
            fdes.push(fde);
        }
    }
    fdes.sort_by_key(|f| (f.start, f.end));
    let before = fdes.len();
    fdes.dedup_by_key(|f| f.start);
    stats.duplicates = before - fdes.len();

    let symbols = best_symbols(elf.function_symbols());
    let functions: Vec<Function> = fdes
        .into_iter()
        .map(|fde| {
            let (name, name_source) = match symbols.get(&fde.start) {
                Some(sym) => (
                    sym.name.clone(),
                    match sym.table {
                        SymbolTable::Symtab => NameSource::Symtab,
                        SymbolTable::Dynsym => NameSource::Dynsym,
                    },
                ),
                None => match exec
                    .iter()
                    .find(|r| r.start == fde.start && r.name != ".text")
                {
                    Some(r) if !elf.sections.is_empty() => (r.name.clone(), NameSource::Section),
                    _ if fde.start == elf.entry => (ENTRY_NAME.to_string(), NameSource::Entry),
                    _ => (format!("sub_{:x}", fde.start), NameSource::Synthetic),
                },
            };
            Function {
                start: fde.start,
                end: fde.end,
                name,
                name_source,
                has_lsda: fde.has_lsda,
                has_personality: fde.has_personality,
                signal_frame: fde.signal_frame,
            }
        })
        .collect();
    stats.named = functions.iter().filter(|f| f.is_named()).count();

    let gaps = coverage(&elf, &exec, &functions, &symbols, &mut stats);

    Ok(Report {
        class: elf.class,
        machine: elf.machine,
        machine_name: elf.machine_name(),
        file_type: elf.type_name(),
        entry: elf.entry,
        link_base: elf.link_base(),
        has_sections: !elf.sections.is_empty(),
        source,
        functions,
        gaps,
        exec,
        stats,
        warnings,
    })
}

fn load_fdes(elf: &Elf) -> Result<(Walk, UnwindSource)> {
    let addr_size = elf.addr_size();

    if let Some(sec) = elf
        .section(".eh_frame")
        .filter(|s| s.sh_type != SHT_NOBITS && s.size > 0)
    {
        let data = elf.section_data(sec)?;
        let walk = EhFrame::new(data, sec.addr, addr_size).walk();
        return Ok((
            walk,
            UnwindSource::Section {
                eh_frame: sec.addr,
                size: sec.size,
            },
        ));
    }

    let Some(seg) = elf.segments.iter().find(|s| s.p_type == PT_GNU_EH_FRAME) else {
        return Err(Error::new(if elf.sections.is_empty() {
            "no PT_GNU_EH_FRAME segment and no section headers, so there are no unwind tables to read"
        } else {
            "no .eh_frame section and no PT_GNU_EH_FRAME segment: the binary has no unwind tables \
             (built with -fno-asynchronous-unwind-tables?)"
        }));
    };
    let hdr = parse_eh_frame_hdr(elf.slice(seg.offset, seg.filesz)?, seg.vaddr, addr_size)
        .map_err(|e| Error::new(format!(".eh_frame_hdr at {:#x}: {e}", seg.vaddr)))?;
    let data = elf.bytes_from_vaddr(hdr.eh_frame_ptr).ok_or_else(|| {
        Error::new(format!(
            ".eh_frame_hdr points at {:#x}, which is not inside any loaded segment",
            hdr.eh_frame_ptr
        ))
    })?;
    let mut eh = EhFrame::new(data, hdr.eh_frame_ptr, addr_size);

    let walk = match &hdr.table {
        // The search table lists every FDE, so the walk does not depend on
        // knowing where .eh_frame ends.
        Some(table) => {
            let mut walk = Walk::default();
            for &(_, fde_addr) in table {
                let offset = fde_addr.wrapping_sub(hdr.eh_frame_ptr);
                match usize::try_from(offset).ok().filter(|&o| o < data.len()) {
                    Some(o) => match eh.fde_at(o) {
                        Ok(fde) => walk.fdes.push(fde),
                        Err(e) => walk.warnings.push(format!("FDE at {fde_addr:#x}: {e}")),
                    },
                    None => walk
                        .warnings
                        .push(format!("FDE at {fde_addr:#x} is outside .eh_frame")),
                }
            }
            walk.cie_count = eh.cie_count();
            walk
        }
        None => eh.walk(),
    };

    Ok((
        walk,
        UnwindSource::Header {
            eh_frame_hdr: seg.vaddr,
            eh_frame: hdr.eh_frame_ptr,
            via_table: hdr.table.is_some(),
        },
    ))
}

/// Picks one name per address: global over weak over local, `.symtab` over
/// `.dynsym`, then alphabetical so the output is deterministic.
fn best_symbols(symbols: Vec<Symbol>) -> HashMap<u64, Symbol> {
    let rank = |s: &Symbol| {
        let bind = match s.bind {
            1 => 0,
            2 => 1,
            _ => 2,
        };
        (bind, s.table, s.name.clone())
    };
    let mut best: HashMap<u64, Symbol> = HashMap::new();
    for sym in symbols {
        match best.get(&sym.addr) {
            Some(cur) if rank(cur) <= rank(&sym) => {}
            _ => {
                best.insert(sym.addr, sym);
            }
        }
    }
    best
}

/// Computes byte coverage per executable range and collects uncovered,
/// non-padding regions.
fn coverage(
    elf: &Elf,
    exec: &[ExecRange],
    functions: &[Function],
    symbols: &HashMap<u64, Symbol>,
    stats: &mut Stats,
) -> Vec<Gap> {
    let mut gaps = Vec::new();
    for range in exec {
        stats.exec_bytes += range.end - range.start;
        let mut cursor = range.start;
        let mut holes = Vec::new();
        for f in functions
            .iter()
            .filter(|f| f.end > range.start && f.start < range.end)
        {
            let (s, e) = (f.start.max(range.start), f.end.min(range.end));
            if s > cursor {
                holes.push((cursor, s));
            }
            cursor = cursor.max(e);
        }
        if cursor < range.end {
            holes.push((cursor, range.end));
        }
        let uncovered: u64 = holes.iter().map(|(s, e)| e - s).sum();
        stats.covered_bytes += (range.end - range.start) - uncovered;

        for (s, e) in holes {
            let Ok(bytes) = elf.slice(range.offset + (s - range.start), e - s) else {
                continue;
            };
            let Some((first, last)) = code_span(elf.machine, bytes) else {
                continue;
            };
            // When symbols are available, split the region at function
            // boundaries so each function without unwind info is listed.
            let (start, end) = (s + first as u64, s + last as u64);
            let mut bounds: Vec<u64> = symbols
                .keys()
                .copied()
                .filter(|&a| a > start && a < end)
                .collect();
            bounds.sort_unstable();
            bounds.insert(0, start);
            bounds.push(end);
            for w in bounds.windows(2) {
                let piece = &bytes[(w[0] - s) as usize..(w[1] - s) as usize];
                let Some((first, last)) = code_span(elf.machine, piece) else {
                    continue;
                };
                let (gap_start, gap_end) = (w[0] + first as u64, w[0] + last as u64);
                stats.uncovered_code_bytes += gap_end - gap_start;
                gaps.push(Gap {
                    start: gap_start,
                    end: gap_end,
                    section: range.name.clone(),
                    symbol: match symbols.get(&w[0]).or_else(|| symbols.get(&gap_start)) {
                        Some(sym) => Some(sym.name.clone()),
                        None if gap_start == elf.entry => Some(ENTRY_NAME.to_string()),
                        None => None,
                    },
                });
            }
        }
    }
    gaps
}
