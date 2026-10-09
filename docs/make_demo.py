#!/usr/bin/env python3
"""Renders docs/demo-transcript.txt (a recorded shell session) as an animated
terminal SVG: commands are typed out, output appears line by line, and the
final frame stays on screen.

    python3 docs/make_demo.py > docs/demo.svg

Lines starting with "$ " are commands; everything else is output, colored
the way unwind-map colors a terminal.
"""

import re
import sys
from html import escape
from pathlib import Path

TRANSCRIPT = Path(__file__).with_name("demo-transcript.txt")

FONT = ("ui-monospace, 'JetBrains Mono', 'Cascadia Code', SFMono-Regular, "
        "Consolas, 'Liberation Mono', Menlo, monospace")
SIZE = 13.2
CW = 7.95          # advance per character; every line is pinned to this grid
LH = 19.5
PAD_X, PAD_TOP, PAD_BOTTOM, BAR = 22, 18, 20, 36

BG, BAR_BG, BORDER = "#0d1117", "#161b22", "#30363d"
FG, MUTED, DIM = "#e6edf3", "#8b949e", "#6e7681"
CYAN, GREEN, YELLOW, RED, AMBER = "#79c0ff", "#7ee787", "#e3b341", "#ff7b72", "#ffa657"

ROW = re.compile(r"^(0x[0-9a-f]+)(\s+)(0x[0-9a-f]+)(\s+\d+  )(\S+)(\s+)(.*)$")
NM = re.compile(r"^([0-9a-f]{8,16})( [tT] )(.*)$")


def segments(line: str) -> list[tuple[str, str, bool]]:
    """Splits an output line into (text, color, bold) runs."""
    if line.startswith("$ "):
        return [("$ ", GREEN, True), (line[2:], FG, True)]
    if m := ROW.match(line):
        start, s1, end, size, flags, s2, name = m.groups()
        return [(start, CYAN, False), (s1, FG, False), (end, DIM, False), (size, FG, False),
                (flags, DIM if flags == "-" else YELLOW, False), (s2, FG, False), (name, FG, False)]
    if m := NM.match(line):
        return [(m.group(1), CYAN, False), (m.group(2), DIM, False), (m.group(3), GREEN, False)]
    if line.startswith("START"):
        return [(line, FG, True)]
    if line.startswith("unwind tables:"):
        return [(line, DIM, False)]
    if re.match(r"^\d+ functions", line):
        return [(line, FG, True)]
    if "no unwind info" in line:
        return [(line, RED, False)]
    if line == "...":
        return [(line, DIM, False)]
    if ": ELF" in line:
        path, rest = line.split(": ", 1)
        if rest.endswith("not stripped"):
            return [(path + ": ", FG, True), (rest[: -len("not stripped")], MUTED, False),
                    ("not stripped", GREEN, True)]
        if rest.endswith("stripped"):
            return [(path + ": ", FG, True), (rest[: -len("stripped")], MUTED, False), ("stripped", RED, True)]
        entry = re.search(r"entry (0x[0-9a-f]+)$", rest)
        if entry:
            return [(path + ": ", FG, True), (rest[: entry.start(1)], FG, False), (entry.group(1), CYAN, False)]
    return [(line, FG, False)]


def text_element(line: str, y: float, extra: str = "") -> str:
    bold_attr = ' font-weight="700"'
    spans = "".join(
        f'<tspan fill="{color}"{bold_attr if bold else ""}>{escape(text)}</tspan>'
        for text, color, bold in segments(line)
    )
    length = f' textLength="{len(line) * CW:.1f}" lengthAdjust="spacing"' if line else ""
    return f'<text x="{PAD_X}" y="{y:.1f}"{length}{extra} xml:space="preserve">{spans}</text>'


def main() -> None:
    lines = TRANSCRIPT.read_text(encoding="utf-8").splitlines()
    cols = max(len(l) for l in lines)
    width = PAD_X * 2 + cols * CW
    rows = len(lines) + 1  # plus the final prompt
    height = BAR + PAD_TOP + rows * LH + PAD_BOTTOM

    css = [
        f"text {{ font-family: {FONT}; font-size: {SIZE}px; }}",
        ".l { opacity: 0; animation: show 0.01s steps(1, end) forwards; }",
        "@keyframes show { to { opacity: 1; } }",
        "@keyframes hide { to { opacity: 0; } }",
        ".cursor { animation: blink 1.06s step-end infinite; }",
        "@keyframes blink { 50% { opacity: 0; } }",
    ]
    body = []
    t = 0.6
    for i, line in enumerate(lines):
        y = BAR + PAD_TOP + (i + 1) * LH - 5
        top = y - LH + 5
        if line.startswith("$ "):
            command = line[2:]
            n = len(command)
            typing = min(1.8, max(0.4, n * 0.03))
            shift = n * CW
            css.append(f"@keyframes type{i} {{ to {{ transform: translateX({shift:.1f}px); }} }}")
            css.append(f".ty{i} {{ animation: type{i} {typing:.2f}s steps({n}, end) {t:.2f}s both; }}")
            css.append(f".cu{i} {{ animation: hide 0.01s steps(1, end) {t + typing:.2f}s forwards; }}")
            x0 = PAD_X + 2 * CW
            body.append(
                f'<g class="l" style="animation-delay: {t:.2f}s">'
                f"{text_element(line, y)}"
                f'<g class="ty{i}"><rect class="cover" x="{x0:.1f}" y="{top:.1f}" width="{width - x0:.1f}" height="{LH}" fill="{BG}"/>'
                f'<rect class="cu{i} cover" x="{x0:.1f}" y="{top + 3:.1f}" width="{CW:.1f}" height="{LH - 5}" fill="{FG}" opacity="0.85"/></g>'
                f"</g>"
            )
            t += typing + 0.45
        else:
            body.append(text_element(line, y, f' class="l" style="animation-delay: {t:.2f}s"'))
            t += 0.05 if line else 0.02
            if i + 1 < len(lines) and lines[i + 1].startswith("$ "):
                t += 0.7

    # Final prompt with a blinking cursor.
    y = BAR + PAD_TOP + rows * LH - 5
    body.append(
        f'<g class="l" style="animation-delay: {t:.2f}s">'
        f'<text x="{PAD_X}" y="{y:.1f}"><tspan fill="{GREEN}" font-weight="700">$</tspan></text>'
        f'<rect class="cursor" x="{PAD_X + 2 * CW:.1f}" y="{y - LH + 8:.1f}" width="{CW:.1f}" height="{LH - 5}" fill="{FG}" opacity="0.85"/>'
        f"</g>"
    )
    css.append("@media (prefers-reduced-motion: reduce) { .l { animation: none; opacity: 1; } .cover { display: none; } g[class^=\"ty\"], .cursor { animation: none; } }")

    dots = "".join(
        f'<circle cx="{20 + k * 18}" cy="{BAR / 2}" r="5.5" fill="{c}"/>'
        for k, c in enumerate(["#ff5f57", "#febc2e", "#28c840"])
    )
    title = f'<text x="{width / 2:.1f}" y="{BAR / 2 + 4.5}" text-anchor="middle" fill="{MUTED}" font-size="12">unwind-map — bash</text>'
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.1f} {height:.1f}" role="img" aria-label="Terminal demo: unwind-map recovers 578 functions from a stripped binary and puts symbols back with objcopy">
  <style>
    {chr(10).join("    " + c for c in css).strip()}
  </style>
  <rect x="0.75" y="0.75" width="{width - 1.5:.1f}" height="{height - 1.5:.1f}" rx="12" fill="{BG}" stroke="{BORDER}" stroke-width="1.5"/>
  <path d="M0.75 {BAR}V12.75a12 12 0 0 1 12-12h{width - 25.5:.1f}a12 12 0 0 1 12 12V{BAR}z" fill="{BAR_BG}"/>
  <line x1="0.75" y1="{BAR}" x2="{width - 0.75:.1f}" y2="{BAR}" stroke="{BORDER}"/>
  {dots}
  {title}
  {chr(10).join("  " + b for b in body).strip()}
</svg>
"""
    sys.stdout.buffer.write(svg.encode("utf-8"))


if __name__ == "__main__":
    main()
