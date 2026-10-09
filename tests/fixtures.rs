//! End-to-end checks against the binaries in tests/fixtures/bin, which are
//! built from tests/fixtures/src/fixture.rs by tests/fixtures/build.sh.

use std::path::PathBuf;

use unwind_map::analysis::{NameSource, Options, Report, UnwindSource, analyze};
use unwind_map::elf::Elf;

const FIXTURES: &[&str] = &["x86_64-exec", "x86_64-pie", "i686-exec", "aarch64-exec"];

/// Functions every fixture defines (plus a local helper with a mangled name).
const EXPECTED: &[&str] = &[
    "_start",
    "leaf_add",
    "fib",
    "big_frame",
    "many_args",
    "dispatch",
];

/// Hand-written assembly without CFI directives, so it has no FDE.
const NO_CFI: &str = "asm_no_cfi";

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bin")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn run(data: &[u8], ignore_sections: bool) -> Report {
    analyze(data, &Options { ignore_sections }).expect("analysis failed")
}

fn ranges(report: &Report) -> Vec<(u64, u64)> {
    report.functions.iter().map(|f| (f.start, f.end)).collect()
}

/// Simulates `sstrip`: removes every reference to the section header table.
fn without_section_headers(mut data: Vec<u8>) -> Vec<u8> {
    let (shoff, width, shnum, shstrndx) = match data[4] {
        1 => (0x20, 4, 0x30, 0x32),
        _ => (0x28, 8, 0x3c, 0x3e),
    };
    data[shoff..shoff + width].fill(0);
    data[shnum..shnum + 2].fill(0);
    data[shstrndx..shstrndx + 2].fill(0);
    data
}

#[test]
fn every_fde_starts_at_a_real_function() {
    for name in FIXTURES {
        let report = run(&load(name), false);
        assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);
        for f in &report.functions {
            assert_eq!(
                f.name_source,
                NameSource::Symtab,
                "{name}: no symbol at {:#x}",
                f.start
            );
        }
    }
}

#[test]
fn every_compiled_function_is_recovered_with_its_exact_size() {
    for name in FIXTURES {
        let data = load(name);
        let report = run(&data, false);
        for sym in Elf::parse(&data).unwrap().function_symbols() {
            let found = report.functions.iter().find(|f| f.start == sym.addr);
            if sym.name == NO_CFI {
                assert!(found.is_none(), "{name}: {NO_CFI} should have no FDE");
                continue;
            }
            let f = found.unwrap_or_else(|| panic!("{name}: {} was not recovered", sym.name));
            assert_eq!(f.size(), sym.size, "{name}: size of {}", sym.name);
        }
        for expected in EXPECTED {
            assert!(
                report.functions.iter().any(|f| f.name == *expected),
                "{name}: missing {expected}"
            );
        }
        assert!(
            report
                .functions
                .iter()
                .any(|f| f.name.ends_with("local_helper")),
            "{name}"
        );
    }
}

#[test]
fn stripping_does_not_change_the_function_map() {
    for name in FIXTURES {
        let full = run(&load(name), false);
        let stripped = run(&load(&format!("{name}.stripped")), false);
        assert_eq!(ranges(&stripped), ranges(&full), "{name}");
        for f in &stripped.functions {
            if f.name_source == NameSource::Entry {
                assert_eq!(f.name, "entry", "{name}");
                continue;
            }
            assert_eq!(f.name_source, NameSource::Synthetic, "{name}");
            assert_eq!(f.name, format!("sub_{:x}", f.start));
        }
    }
}

#[test]
fn works_without_section_headers() {
    for name in FIXTURES {
        let expected = ranges(&run(&load(name), false));

        let sstripped = run(
            &without_section_headers(load(&format!("{name}.stripped"))),
            false,
        );
        assert_eq!(ranges(&sstripped), expected, "{name}");
        assert!(
            matches!(
                sstripped.source,
                UnwindSource::Header {
                    via_table: true,
                    ..
                }
            ),
            "{name}: {:?}",
            sstripped.source
        );

        let ignored = run(&load(name), true);
        assert_eq!(ranges(&ignored), expected, "{name} with --ignore-sections");
    }
}

#[test]
fn hand_written_assembly_is_reported_as_a_gap() {
    for name in FIXTURES {
        let data = load(name);
        let asm = Elf::parse(&data)
            .unwrap()
            .function_symbols()
            .into_iter()
            .find(|s| s.name == NO_CFI)
            .unwrap();

        let report = run(&data, false);
        let gaps: Vec<_> = report
            .gaps
            .iter()
            .map(|g| (g.start, g.end, g.symbol.as_deref()))
            .collect();
        assert_eq!(
            gaps,
            vec![(asm.addr, asm.addr + asm.size, Some(NO_CFI))],
            "{name}"
        );
        assert_eq!(report.stats.uncovered_code_bytes, asm.size, "{name}");

        // The same region is found when only program headers are left.
        let bare = run(
            &without_section_headers(load(&format!("{name}.stripped"))),
            false,
        );
        let bare_gaps: Vec<_> = bare.gaps.iter().map(|g| (g.start, g.end)).collect();
        assert_eq!(
            bare_gaps,
            vec![(asm.addr, asm.addr + asm.size)],
            "{name} without sections"
        );
    }
}

#[test]
fn reports_target_details() {
    let cases = [
        ("x86_64-exec", 64, "x86-64", "EXEC"),
        ("x86_64-pie", 64, "x86-64", "DYN"),
        ("i686-exec", 32, "x86", "EXEC"),
        ("aarch64-exec", 64, "AArch64", "EXEC"),
    ];
    for (name, bits, machine, kind) in cases {
        let report = run(&load(name), false);
        assert_eq!(
            (
                report.class.bits(),
                report.machine_name.as_str(),
                report.file_type
            ),
            (bits, machine, kind)
        );
    }
}

#[test]
fn garbage_and_truncated_input_fail_cleanly() {
    assert!(analyze(b"definitely not an elf file", &Options::default()).is_err());
    let data = load("x86_64-exec");
    for len in [0, 4, 16, 63, 64, 200, data.len() / 2] {
        // Must return (Ok or Err) without panicking.
        let _ = analyze(&data[..len], &Options::default());
    }
}
