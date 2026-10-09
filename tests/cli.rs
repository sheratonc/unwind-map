//! Command-line behaviour: formats, flags and exit codes.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bin")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_unwind-map"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn text_output_has_a_table_and_a_summary() {
    let text = stdout(&[&fixture("x86_64-exec.stripped")]);
    assert!(text.contains("ELF64 x86-64 EXEC"), "{text}");
    assert!(text.contains("8 functions (0 named, 8 unnamed)"), "{text}");
    assert!(text.contains(" entry\n"), "{text}");
    assert!(text.contains(" sub_201430\n"), "{text}");
    assert!(text.contains("list with --gaps"), "{text}");
}

#[test]
fn gaps_flag_lists_uncovered_code() {
    let text = stdout(&["--gaps", &fixture("i686-exec")]);
    assert!(text.contains("uncovered code"), "{text}");
    assert!(text.contains("asm_no_cfi"), "{text}");
}

#[test]
fn line_formats_have_one_line_per_function() {
    let file = fixture("x86_64-exec.stripped");
    for (format, needle) in [
        ("nm", "0000000000201430 t sub_201430"),
        ("ghidra", "sub_201430 0x201430 f"),
        ("objcopy", "--add-symbol sub_201430=.text:0x"),
    ] {
        let text = stdout(&["--format", format, &file]);
        assert_eq!(text.lines().count(), 8, "{format}:\n{text}");
        assert!(text.contains(needle), "{format}:\n{text}");
    }
}

#[test]
fn csv_has_a_header_row() {
    let text = stdout(&["-f", "csv", &fixture("aarch64-exec")]);
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("start,end,size,name,named,lsda,personality,signal_frame")
    );
    assert_eq!(lines.count(), 8);
}

#[test]
fn json_output_lists_functions_and_gaps() {
    let text = stdout(&["-f", "json", "-g", &fixture("i686-exec")]);
    assert!(text.starts_with("{\n") && text.ends_with("}\n"), "{text}");
    assert_eq!(
        text.matches("\"start\":").count(),
        9,
        "8 functions + 1 gap:\n{text}"
    );
    assert!(text.contains("\"symbol\": \"asm_no_cfi\""), "{text}");
    assert_eq!(text.matches('{').count(), text.matches('}').count());
    assert_eq!(text.matches('[').count(), text.matches(']').count());
}

#[test]
fn base_rebases_addresses_and_synthetic_names() {
    let text = stdout(&[
        "-f",
        "nm",
        "--base",
        "0x100000",
        &fixture("x86_64-pie.stripped"),
    ]);
    assert!(
        text.starts_with("0000000000101440 t sub_101440\n"),
        "{text}"
    );
}

#[test]
fn unnamed_only_filters_named_functions() {
    let text = stdout(&["-f", "nm", "--unnamed-only", &fixture("x86_64-exec")]);
    assert_eq!(text, "");
}

#[test]
fn errors_use_distinct_exit_codes() {
    assert_eq!(
        run(&[]).status.code(),
        Some(2),
        "missing file is a usage error"
    );
    assert_eq!(run(&["--format", "xml", "x"]).status.code(), Some(2));
    assert_eq!(run(&["no-such-file"]).status.code(), Some(1));
    let not_elf = run(&[file!()]);
    assert_eq!(not_elf.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&not_elf.stderr).contains("not an ELF file"));
    assert_eq!(
        run(&["-f", "objcopy", "--base", "0x1000", &fixture("x86_64-pie")])
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn help_and_version() {
    assert!(stdout(&["--help"]).contains("Usage: unwind-map"));
    assert_eq!(
        stdout(&["--version"]),
        format!("unwind-map {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn color_is_opt_in_outside_a_terminal() {
    let file = fixture("x86_64-exec");
    assert!(
        !stdout(&[&file]).contains('\x1b'),
        "piped output must stay plain"
    );
    let colored = stdout(&["--color", "always", &file]);
    assert!(colored.contains("\x1b[32m_start\x1b[0m"), "{colored}");
    assert!(!stdout(&["--color", "never", &file]).contains('\x1b'));
    assert_eq!(run(&["--color", "rainbow", &file]).status.code(), Some(2));
}

#[test]
fn svg_map_draws_every_function() {
    let svg = stdout(&["-f", "svg", &fixture("aarch64-exec")]);
    assert!(
        svg.starts_with("<svg") && svg.trim_end().ends_with("</svg>"),
        "{svg}"
    );
    for name in ["fib", "big_frame", "many_args", "dispatch", "_start"] {
        assert!(
            svg.contains(&format!("<title>{name} 0x")),
            "{name} missing from map"
        );
    }
    assert!(
        svg.contains("no unwind info 0x"),
        "the asm gap should be drawn"
    );
    assert!(svg.contains("8 functions"), "{svg}");
}
