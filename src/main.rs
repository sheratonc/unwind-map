use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use unwind_map::analysis::{Options, analyze};
use unwind_map::output::{Format, OutputOptions, render};

const USAGE: &str = "\
Recover function boundaries from stripped ELF binaries using .eh_frame.

Usage: unwind-map [OPTIONS] <FILE>

Options:
  -f, --format <FORMAT>  Output format: text (default), csv, json, nm, ghidra, objcopy, svg
  -g, --gaps             Also list executable code that has no unwind info and is not padding
  -b, --base <ADDR>      Print addresses as if the image were loaded at ADDR
                         (e.g. 0x100000 for Ghidra, or a base from /proc/<pid>/maps)
      --ignore-sections  Ignore section headers; locate unwind data via PT_GNU_EH_FRAME only
  -u, --unnamed-only     Only list functions that have no symbol name
      --color <WHEN>     Color text output: auto (default), always, never
  -q, --quiet            Do not print warnings
  -h, --help             Print this help
  -V, --version          Print the version";

struct Args {
    file: String,
    format: Format,
    gaps: bool,
    base: Option<u64>,
    ignore_sections: bool,
    unnamed_only: bool,
    quiet: bool,
    color: Color,
}

#[derive(Clone, Copy)]
enum Color {
    Auto,
    Always,
    Never,
}

impl Color {
    /// `auto` colors only an interactive terminal, honouring NO_COLOR.
    fn enabled(self) -> bool {
        match self {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => {
                std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && (cfg!(not(windows))
                        || std::env::var_os("WT_SESSION").is_some()
                        || std::env::var_os("TERM").is_some())
            }
        }
    }
}

enum Parsed {
    Run(Args),
    Exit(String),
}

fn parse_number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

fn parse_args(raw: impl Iterator<Item = String>) -> Result<Parsed, String> {
    let mut file = None;
    let mut format = Format::Text;
    let (mut gaps, mut ignore_sections, mut unnamed_only, mut quiet) = (false, false, false, false);
    let mut base = None;
    let mut color = Color::Auto;
    let mut raw = raw.peekable();

    while let Some(arg) = raw.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| raw.next())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Exit(USAGE.to_string())),
            "-V" | "--version" => {
                return Ok(Parsed::Exit(format!(
                    "unwind-map {}",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            "-f" | "--format" => {
                let v = value("--format")?;
                format = Format::parse(&v).ok_or_else(|| {
                    format!("unknown format '{v}' (expected one of: {})", Format::NAMES)
                })?;
            }
            "-b" | "--base" => {
                let v = value("--base")?;
                base = Some(parse_number(&v).ok_or_else(|| format!("invalid address '{v}'"))?);
            }
            "--color" => {
                color = match value("--color")?.as_str() {
                    "auto" => Color::Auto,
                    "always" => Color::Always,
                    "never" => Color::Never,
                    v => {
                        return Err(format!(
                            "invalid --color '{v}' (expected auto, always or never)"
                        ));
                    }
                };
            }
            "-g" | "--gaps" => gaps = true,
            "--ignore-sections" => ignore_sections = true,
            "-u" | "--unnamed-only" => unnamed_only = true,
            "-q" | "--quiet" => quiet = true,
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option '{s}'")),
            _ if file.is_none() => file = Some(arg),
            _ => return Err(format!("unexpected argument '{arg}'")),
        }
    }

    let file = file.ok_or("missing input file")?;
    Ok(Parsed::Run(Args {
        file,
        format,
        gaps,
        base,
        ignore_sections,
        unnamed_only,
        quiet,
        color,
    }))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Parsed::Run(args)) => args,
        Ok(Parsed::Exit(text)) => {
            println!("{text}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("unwind-map: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unwind-map: {}: {e}", args.file);
            ExitCode::from(1)
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let data = std::fs::read(&args.file).map_err(|e| e.to_string())?;
    let report = analyze(
        &data,
        &Options {
            ignore_sections: args.ignore_sections,
        },
    )
    .map_err(|e| e.to_string())?;

    if !args.quiet {
        for w in &report.warnings {
            eprintln!("unwind-map: warning: {w}");
        }
    }

    let opts = OutputOptions {
        format: args.format,
        file: &args.file,
        base: args.base,
        gaps: args.gaps,
        unnamed_only: args.unnamed_only,
        color: args.format == Format::Text && args.color.enabled(),
    };
    let text = render(&report, &opts).map_err(|e| e.to_string())?;
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(text.as_bytes()) {
        // Piping into `head` closes stdout early; that is not an error.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.map_err(|e| e.to_string()),
    }
}
