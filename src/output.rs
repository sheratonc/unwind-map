//! Renders a [`Report`] in the supported output formats.

use std::fmt::Write as _;

use crate::Result;
use crate::analysis::{Function, NameSource, Report, UnwindSource};
use crate::ehframe::mask;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable table with a summary.
    Text,
    Csv,
    Json,
    /// `nm`-style `ADDRESS T NAME` lines.
    Nm,
    /// Input for Ghidra's bundled `ImportSymbolsScript.py`.
    Ghidra,
    /// `--add-symbol` arguments for `objcopy` / `llvm-objcopy`.
    Objcopy,
    /// A Hilbert-curve picture of the executable code.
    Svg,
}

impl Format {
    pub const NAMES: &'static str = "text, csv, json, nm, ghidra, objcopy, svg";

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "text" => Format::Text,
            "csv" => Format::Csv,
            "json" => Format::Json,
            "nm" => Format::Nm,
            "ghidra" => Format::Ghidra,
            "objcopy" => Format::Objcopy,
            "svg" => Format::Svg,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct OutputOptions<'a> {
    pub format: Format,
    pub file: &'a str,
    /// Print addresses as if the image were loaded at this base.
    pub base: Option<u64>,
    /// Include uncovered code regions (text and JSON).
    pub gaps: bool,
    /// Only list functions without a symbol name.
    pub unnamed_only: bool,
    /// Use ANSI colors in text output.
    pub color: bool,
}

struct Ctx<'a> {
    report: &'a Report,
    opts: &'a OutputOptions<'a>,
    shift: u64,
    width: usize,
}

impl Ctx<'_> {
    fn addr(&self, a: u64) -> u64 {
        mask(a.wrapping_add(self.shift), self.report.class.addr_size())
    }

    fn hex(&self, a: u64) -> String {
        format!("0x{:0w$x}", self.addr(a), w = self.width)
    }

    /// Synthetic names follow the printed address, like Ghidra's `FUN_` names.
    fn name(&self, f: &Function) -> String {
        match f.name_source {
            NameSource::Synthetic => format!("sub_{:x}", self.addr(f.start)),
            _ => f.name.clone(),
        }
    }

    fn functions(&self) -> impl Iterator<Item = &Function> {
        self.report
            .functions
            .iter()
            .filter(|f| !self.opts.unnamed_only || !f.is_named())
    }
}

pub fn render(report: &Report, opts: &OutputOptions) -> Result<String> {
    let ctx = Ctx {
        report,
        opts,
        shift: opts.base.map_or(0, |b| b.wrapping_sub(report.link_base)),
        width: usize::from(report.class.addr_size()) * 2,
    };
    Ok(match opts.format {
        Format::Text => text(&ctx),
        Format::Csv => csv(&ctx),
        Format::Json => json(&ctx),
        Format::Nm => nm(&ctx),
        Format::Ghidra => ghidra(&ctx),
        Format::Objcopy => objcopy(&ctx)?,
        Format::Svg => {
            let names: Vec<String> = report.functions.iter().map(|f| ctx.name(f)).collect();
            crate::map::render(report, opts.file, &names)
        }
    })
}

fn flags(f: &Function) -> String {
    let mut s = String::new();
    if f.has_lsda {
        s.push('L');
    }
    if f.has_personality {
        s.push('P');
    }
    if f.signal_frame {
        s.push('S');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn human_bytes(n: u64) -> String {
    match n {
        0..1024 => format!("{n} bytes"),
        1024..1_048_576 => format!("{:.1} KiB", n as f64 / 1024.0),
        _ => format!("{:.1} MiB", n as f64 / 1_048_576.0),
    }
}

const BOLD: &str = "1";
const DIM: &str = "2";
const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const MAGENTA: &str = "35";
const CYAN: &str = "36";

impl Ctx<'_> {
    /// Wraps already-padded text in an ANSI style when color is enabled.
    fn paint(&self, text: &str, style: &str) -> String {
        if self.opts.color {
            format!("\x1b[{style}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

fn text(c: &Ctx) -> String {
    let r = c.report;
    let s = &r.stats;
    let mut out = String::new();
    let w = c.width + 4;

    let _ = writeln!(
        out,
        "{}: ELF{} {} {}, entry {}",
        c.paint(c.opts.file, BOLD),
        r.class.bits(),
        r.machine_name,
        r.file_type,
        c.paint(&c.hex(r.entry), CYAN)
    );
    let source = match &r.source {
        UnwindSource::Section { eh_frame, size } => format!(
            "unwind tables: .eh_frame at {} ({size:#x} bytes), {}, {}",
            c.hex(*eh_frame),
            plural(s.cies, "CIE", "CIEs"),
            plural(s.fdes, "FDE", "FDEs")
        ),
        UnwindSource::Header {
            eh_frame_hdr,
            eh_frame,
            via_table,
        } => format!(
            "unwind tables: found through PT_GNU_EH_FRAME (.eh_frame_hdr at {}, .eh_frame at {}{}), {}, {}",
            c.hex(*eh_frame_hdr),
            c.hex(*eh_frame),
            if *via_table {
                ", via its search table"
            } else {
                ""
            },
            plural(s.cies, "CIE", "CIEs"),
            plural(s.fdes, "FDE", "FDEs")
        ),
    };
    let _ = writeln!(out, "{}", c.paint(&source, DIM));
    if let Some(base) = c.opts.base {
        let line = format!("addresses rebased from {:#x} to {base:#x}", r.link_base);
        let _ = writeln!(out, "{}", c.paint(&line, DIM));
    }
    out.push('\n');

    let header = format!(
        "{:<w$}{:<w$}{:>8}  {:<6}NAME",
        "START", "END", "SIZE", "FLAGS"
    );
    let _ = writeln!(out, "{}", c.paint(&header, BOLD));
    for f in c.functions() {
        let flags = flags(f);
        let name_style = match f.name_source {
            NameSource::Symtab | NameSource::Dynsym => GREEN,
            NameSource::Section | NameSource::Entry => MAGENTA,
            NameSource::Synthetic => "0",
        };
        let _ = writeln!(
            out,
            "{}{}{:>8}  {}{}",
            c.paint(&format!("{:<w$}", c.hex(f.start)), CYAN),
            c.paint(&format!("{:<w$}", c.hex(f.end)), DIM),
            f.size(),
            c.paint(
                &format!("{flags:<6}"),
                if flags == "-" { DIM } else { YELLOW }
            ),
            c.paint(&c.name(f), name_style)
        );
    }

    if c.opts.gaps && !r.gaps.is_empty() {
        let title = "uncovered code (no unwind info, not padding):";
        let _ = writeln!(out, "\n{}", c.paint(title, BOLD));
        let header = format!(
            "{:<w$}{:<w$}{:>8}  {:<12}SYMBOL",
            "START", "END", "SIZE", "SECTION"
        );
        let _ = writeln!(out, "{}", c.paint(&header, BOLD));
        for g in &r.gaps {
            let row = format!(
                "{:<w$}{:<w$}{:>8}  {:<12}{}",
                c.hex(g.start),
                c.hex(g.end),
                g.end - g.start,
                g.section,
                g.symbol.as_deref().unwrap_or("-")
            );
            let _ = writeln!(out, "{}", c.paint(&row, RED));
        }
    }

    let total = r.functions.len();
    let summary = format!(
        "{} ({} named, {} unnamed), covering {:.1}% of {} of executable code",
        plural(total, "function", "functions"),
        s.named,
        total - s.named,
        r.coverage(),
        human_bytes(s.exec_bytes)
    );
    let _ = writeln!(out, "\n{}", c.paint(&summary, BOLD));
    let skipped = s.outside_exec + s.empty + s.duplicates;
    if skipped > 0 {
        let line = format!(
            "skipped {}: {} outside executable code, {} empty, {} duplicate",
            plural(skipped, "FDE", "FDEs"),
            s.outside_exec,
            s.empty,
            s.duplicates
        );
        let _ = writeln!(out, "{}", c.paint(&line, DIM));
    }
    if !r.gaps.is_empty() && !c.opts.gaps {
        let line = format!(
            "{} of executable code ha{} no unwind info ({}); list with --gaps",
            plural(r.gaps.len(), "region", "regions"),
            if r.gaps.len() == 1 { "s" } else { "ve" },
            human_bytes(s.uncovered_code_bytes)
        );
        let _ = writeln!(out, "{}", c.paint(&line, RED));
    }
    out
}

pub(crate) fn human_size(n: u64) -> String {
    human_bytes(n)
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv(c: &Ctx) -> String {
    let mut out = String::from("start,end,size,name,named,lsda,personality,signal_frame\n");
    for f in c.functions() {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{}",
            c.hex(f.start),
            c.hex(f.end),
            f.size(),
            csv_field(&c.name(f)),
            f.is_named(),
            f.has_lsda,
            f.has_personality,
            f.signal_frame
        );
    }
    out
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json(c: &Ctx) -> String {
    let r = c.report;
    let s = &r.stats;
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"file\": {},", json_str(c.opts.file));
    let _ = writeln!(out, "  \"class\": {},", r.class.bits());
    let _ = writeln!(out, "  \"machine\": {},", json_str(&r.machine_name));
    let _ = writeln!(out, "  \"type\": {},", json_str(r.file_type));
    let _ = writeln!(out, "  \"entry\": \"{}\",", c.hex(r.entry));
    if let Some(base) = c.opts.base {
        let _ = writeln!(out, "  \"base\": \"{base:#x}\",");
    }
    let _ = match &r.source {
        UnwindSource::Section { eh_frame, size } => writeln!(
            out,
            "  \"unwind_source\": {{\"kind\": \"section\", \"eh_frame\": \"{}\", \"size\": {size}}},",
            c.hex(*eh_frame)
        ),
        UnwindSource::Header {
            eh_frame_hdr,
            eh_frame,
            via_table,
        } => writeln!(
            out,
            "  \"unwind_source\": {{\"kind\": \"eh_frame_hdr\", \"eh_frame_hdr\": \"{}\", \"eh_frame\": \"{}\", \"via_table\": {via_table}}},",
            c.hex(*eh_frame_hdr),
            c.hex(*eh_frame)
        ),
    };

    out.push_str("  \"functions\": [");
    for (i, f) in c.functions().enumerate() {
        let _ = write!(
            out,
            "{}\n    {{\"start\": \"{}\", \"end\": \"{}\", \"size\": {}, \"name\": {}, \"named\": {}, \"lsda\": {}, \"personality\": {}, \"signal_frame\": {}}}",
            if i == 0 { "" } else { "," },
            c.hex(f.start),
            c.hex(f.end),
            f.size(),
            json_str(&c.name(f)),
            f.is_named(),
            f.has_lsda,
            f.has_personality,
            f.signal_frame
        );
    }
    out.push_str("\n  ],\n");

    if c.opts.gaps {
        out.push_str("  \"gaps\": [");
        for (i, g) in r.gaps.iter().enumerate() {
            let _ = write!(
                out,
                "{}\n    {{\"start\": \"{}\", \"end\": \"{}\", \"size\": {}, \"section\": {}, \"symbol\": {}}}",
                if i == 0 { "" } else { "," },
                c.hex(g.start),
                c.hex(g.end),
                g.end - g.start,
                json_str(&g.section),
                g.symbol.as_deref().map_or("null".to_string(), json_str)
            );
        }
        out.push_str("\n  ],\n");
    }

    let _ = writeln!(
        out,
        "  \"stats\": {{\"cies\": {}, \"fdes\": {}, \"functions\": {}, \"named\": {}, \"outside_exec\": {}, \"empty\": {}, \"duplicates\": {}, \"exec_bytes\": {}, \"covered_bytes\": {}, \"uncovered_code_bytes\": {}}},",
        s.cies,
        s.fdes,
        r.functions.len(),
        s.named,
        s.outside_exec,
        s.empty,
        s.duplicates,
        s.exec_bytes,
        s.covered_bytes,
        s.uncovered_code_bytes
    );
    let warnings: Vec<String> = r.warnings.iter().map(|w| json_str(w)).collect();
    let _ = writeln!(out, "  \"warnings\": [{}]", warnings.join(", "));
    out.push_str("}\n");
    out
}

fn nm(c: &Ctx) -> String {
    let mut out = String::new();
    for f in c.functions() {
        let kind = if f.is_named() { 'T' } else { 't' };
        let _ = writeln!(
            out,
            "{:0w$x} {kind} {}",
            c.addr(f.start),
            c.name(f),
            w = c.width
        );
    }
    out
}

fn ghidra(c: &Ctx) -> String {
    let mut out = String::new();
    for f in c.functions() {
        let _ = writeln!(out, "{} 0x{:x} f", c.name(f), c.addr(f.start));
    }
    out
}

fn objcopy(c: &Ctx) -> Result<String> {
    if !c.report.has_sections {
        bail!("objcopy output needs section headers, and this binary has none");
    }
    if c.opts.base.is_some() {
        bail!("--base cannot be combined with objcopy output (symbols are section-relative)");
    }
    let mut out = String::new();
    for f in c.functions() {
        let Some(sec) = c
            .report
            .exec
            .iter()
            .find(|r| r.start <= f.start && f.start < r.end)
        else {
            continue;
        };
        let _ = writeln!(
            out,
            "--add-symbol {}={}:{:#x},function,{}",
            c.name(f),
            sec.name,
            f.start - sec.start,
            if f.is_named() { "global" } else { "local" }
        );
    }
    Ok(out)
}
