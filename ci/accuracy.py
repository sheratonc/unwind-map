#!/usr/bin/env python3
"""Checks unwind-map against independent ground truth from unstripped binaries.

    accuracy.py corpus  <unwind-map>              build ci/corpus with GCC and Clang, check every build
    accuracy.py compare <unwind-map> <binary>...  check existing unstripped binaries

Each binary is stripped and analysed; the result is compared with the
original's FUNC symbols and with readelf's own decoding of .eh_frame:

    precision  every recovered start is a FUNC symbol (or a linker stub section)
    readelf    every recovered range matches an FDE readelf decodes; nothing else is missing
    unwind     every function that has an FDE is recovered
    no-CFI     every function without an FDE is reported by --gaps
    sstrip     the same map comes back with the section header table removed
    objcopy    objcopy can re-symbolize the stripped binary from --format objcopy

Tools are configurable for non-GNU environments (defaults in brackets):
    STRIP [strip]   OBJCOPY [objcopy]
    READELF_SYMBOLS ["readelf --symbols --wide"]   GNU-style symbol table dump
    READELF_FRAMES  ["readelf --debug-dump=frames"]  .eh_frame dump, GNU or LLVM style
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

STRIP = os.environ.get("STRIP", "strip")
OBJCOPY = os.environ.get("OBJCOPY", "objcopy")
READELF_SYMBOLS = shlex.split(os.environ.get("READELF_SYMBOLS", "readelf --symbols --wide"))
READELF_FRAMES = shlex.split(os.environ.get("READELF_FRAMES", "readelf --debug-dump=frames"))

CORPUS = Path(__file__).resolve().parent / "corpus"

# (label, compiler, compile flags, link flags, source)
BUILDS = [
    ("gcc -O0", "gcc", ["-O0"], [], "corpus.c"),
    ("gcc -O2", "gcc", ["-O2"], [], "corpus.c"),
    ("gcc -O2 -no-pie", "gcc", ["-O2", "-fno-pie"], ["-no-pie"], "corpus.c"),
    ("clang -O2", "clang", ["-O2"], [], "corpus.c"),
    ("g++ -O2", "g++", ["-O2"], [], "corpus.cpp"),
    ("clang++ -O2", "clang++", ["-O2"], [], "corpus.cpp"),
]

SYMBOL_LINE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(?:FUNC|IFUNC)\s+\w+\s+\w+(?:\s+\[[^\]]*\])?\s+(\w+)\s+(\S+)"
)
GNU_FDE = re.compile(r"FDE cie=\S+ pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)")
LLVM_FDE = re.compile(r"FDE length=.*?initial_location: 0x([0-9a-fA-F]+)\s+address_range: 0x[0-9a-fA-F]+ \(end : 0x([0-9a-fA-F]+)\)", re.S)


def run(*cmd: str) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def func_symbols(path: Path) -> dict[int, tuple[str, int]]:
    """Defined FUNC/IFUNC symbols as address -> (name, size)."""
    out = {}
    for line in run(*READELF_SYMBOLS, str(path)).splitlines():
        m = SYMBOL_LINE.match(line)
        if not m or m.group(3) == "UND":
            continue
        addr, size = int(m.group(1), 16), int(m.group(2), 0)
        if addr:
            out.setdefault(addr, (m.group(4).split("@")[0], size))
    return out


def readelf_fdes(path: Path) -> list[tuple[int, int]]:
    text = run(*READELF_FRAMES, str(path))
    if "FDE cie=" in text:
        matches = GNU_FDE.findall(text)
    else:
        # llvm-readobj --unwind also lists .eh_frame_hdr; only parse the .eh_frame part.
        matches = LLVM_FDE.findall(text[text.find(".eh_frame section") :])
    return [(int(a, 16), int(b, 16)) for a, b in matches]


def analyse(tool: str, path: Path, *flags: str) -> dict:
    return json.loads(run(tool, "--format", "json", "--gaps", "--quiet", *flags, str(path)))


def drop_section_headers(src: Path, dst: Path) -> None:
    """Simulates `sstrip`: zeroes e_shoff, e_shnum and e_shstrndx."""
    data = bytearray(src.read_bytes())
    shoff, width, shnum, shstrndx = (0x20, 4, 0x30, 0x32) if data[4] == 1 else (0x28, 8, 0x3C, 0x3E)
    data[shoff : shoff + width] = bytes(width)
    data[shnum : shnum + 2] = bytes(2)
    data[shstrndx : shstrndx + 2] = bytes(2)
    dst.write_bytes(data)


def check(tool: str, binary: Path, work: Path) -> tuple[list, list[str]]:
    errors = []
    stripped = work / (binary.name + ".stripped")
    run(STRIP, "--strip-all", "-o", str(stripped), str(binary))

    report = analyse(tool, stripped)
    functions = report["functions"]
    ranges = {(int(f["start"], 16), int(f["end"], 16)) for f in functions}
    starts = {start for start, _ in ranges}
    gaps = [(int(g["start"], 16), int(g["end"], 16)) for g in report["gaps"]]
    symbols = func_symbols(binary)

    # precision: no invented functions. Entries named after a section
    # (".plt", ".plt.sec", ...) cover linker stubs rather than functions.
    real = [f for f in functions if not f["name"].startswith(".")]
    bogus = [f["start"] for f in real if int(f["start"], 16) not in symbols]
    if bogus:
        errors.append(f"{len(bogus)} recovered starts are not FUNC symbols: {bogus[:5]}")

    # readelf agreement: same FDE ranges, and only the skipped ones missing.
    fdes = readelf_fdes(binary)
    unknown = ranges - set(fdes)
    if unknown:
        errors.append(f"{len(unknown)} ranges that readelf does not decode: {sorted(unknown)[:5]}")
    stats = report["stats"]
    skipped = stats["outside_exec"] + stats["empty"] + stats["duplicates"]
    if len(fdes) - len(ranges) != skipped:
        errors.append(f"readelf decodes {len(fdes)} FDEs, unwind-map kept {len(ranges)} and skipped {skipped}")

    # unwind recall: every function with an FDE is found.
    fde_starts = {start for start, end in fdes if end > start}
    with_fde = {a for a in symbols if a in fde_starts}
    missed = sorted(symbols[a][0] for a in with_fde - starts)
    if missed:
        errors.append(f"functions with an FDE that were not recovered: {missed[:5]}")

    # no-CFI functions: not covered by any FDE, and must overlap a reported gap.
    no_cfi = {a: s for a, (_, s) in symbols.items() if s > 0 and not any(lo <= a < hi for lo, hi in fdes)}
    unreported = sorted(symbols[a][0] for a, s in no_cfi.items() if not any(lo < a + s and a < hi for lo, hi in gaps))
    if unreported:
        errors.append(f"functions without unwind info missing from --gaps: {unreported[:5]}")

    # sstrip: same answer from program headers alone.
    bare = work / (binary.name + ".nosections")
    drop_section_headers(stripped, bare)
    bare_ranges = {(int(f["start"], 16), int(f["end"], 16)) for f in analyse(tool, bare)["functions"]}
    if bare_ranges != ranges:
        errors.append(f"without section headers: {len(bare_ranges ^ ranges)} functions differ")

    # objcopy: re-symbolize the stripped binary and read the symbols back.
    args = work / (binary.name + ".objcopy")
    resym = work / (binary.name + ".resym")
    args.write_text(run(tool, "--format", "objcopy", "--quiet", str(stripped)))
    run(OBJCOPY, f"@{args}", str(stripped), str(resym))
    before = set(func_symbols(stripped))  # e.g. exported functions still in .dynsym
    after = set(func_symbols(resym))
    lost, invented = starts - after, after - starts - before
    if lost or invented:
        errors.append(f"objcopy round trip: {len(lost)} missing, {len(invented)} unexpected symbols")

    row = [
        report["machine"],
        len(symbols),
        len(with_fde),
        len(functions),
        f"{1 - len(bogus) / max(len(real), 1):.1%}",
        f"{(len(with_fde) - len(missed)) / max(len(with_fde), 1):.1%}",
        f"{len(no_cfi) - len(unreported)}/{len(no_cfi)}",
        sum(f["lsda"] for f in functions),
        f"{stats['covered_bytes'] / max(stats['exec_bytes'], 1):.1%}",
    ]
    return row, errors


HEADER = ["build", "arch", "FUNC syms", "with FDE", "recovered", "precision", "recall", "no-CFI in gaps", "LSDA", "coverage"]


def print_table(rows: list[list]) -> None:
    rows = [HEADER] + [[str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in rows) for i in range(len(HEADER))]
    for i, r in enumerate(rows):
        print("  ".join(c.ljust(w) if j == 0 else c.rjust(w) for j, (c, w) in enumerate(zip(r, widths))))
        if i == 0:
            print("  ".join("-" * w for w in widths))


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in ("corpus", "compare"):
        print(__doc__)
        return 2
    mode, tool = sys.argv[1], str(Path(sys.argv[2]).resolve())
    rows, failures = [], []

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        if mode == "corpus":
            jobs = []
            for label, cc, cflags, ldflags, source in BUILDS:
                if shutil.which(cc) is None:
                    print(f"skipping {label}: {cc} not installed")
                    continue
                obj = work / (label.replace(" ", "_") + ".o")
                binary = work / label.replace(" ", "_")
                run(cc, *cflags, "-c", str(CORPUS / source), "-o", str(obj))
                run(cc, *ldflags, str(obj), "-o", str(binary))
                jobs.append((label, binary))
        else:
            jobs = [(Path(p).name, Path(p)) for p in sys.argv[3:]]

        for label, binary in jobs:
            row, errors = check(tool, binary, work)
            rows.append([label, *row])
            failures += [f"{label}: {e}" for e in errors]

    print_table(rows)
    for f in failures:
        print(f"FAIL {f}")
    print(f"\n{len(rows)} binaries checked, {len(failures)} failures")
    return 1 if failures or not rows else 0


if __name__ == "__main__":
    sys.exit(main())
