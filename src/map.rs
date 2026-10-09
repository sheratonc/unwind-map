//! `--format svg`: a picture of a binary's executable code.
//!
//! Executable bytes are laid out along a Hilbert curve, which keeps nearby
//! addresses next to each other in 2D, so every recovered function shows up
//! as one contiguous patch of color. Code without unwind info is red and
//! alignment padding is dark.

use std::fmt::Write as _;

use crate::analysis::Report;
use crate::output::human_size;

const MAX_SIDE: u64 = 128;
const MAP: f64 = 552.0;
const PAD: f64 = 24.0;
const WIDTH: f64 = MAP + 2.0 * PAD;
const HEIGHT: f64 = MAP + 2.0 * PAD + 112.0;
const FONT: &str = "ui-monospace, 'JetBrains Mono', 'Cascadia Code', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace";

const GAP_COLOR: &str = "#ff4d6d";
const PADDING_COLOR: &str = "#262c36";

/// Trace width in cells: the dark channels between traces show the curve.
const TRACE: f64 = 0.62;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Function(usize),
    Gap(usize),
    Padding,
}

/// Position of the `d`-th cell on a Hilbert curve filling a `side` x `side`
/// square (`side` a power of two). Starts top-left, ends top-right.
fn d2xy(side: u64, d: u64) -> (u64, u64) {
    let (mut x, mut y, mut t) = (0, 0, d);
    let mut s = 1;
    while s < side {
        let rx = 1 & (t / 2);
        let ry = 1 & (t ^ rx);
        if ry == 0 {
            if rx == 1 {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            std::mem::swap(&mut x, &mut y);
        }
        x += s * rx;
        y += s * ry;
        t /= 4;
        s *= 2;
    }
    (x, y)
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Distinct, non-red colors for neighbouring functions; exception-aware
/// functions (with an LSDA) get a warm palette of their own.
fn function_color(index: usize, lsda: bool) -> String {
    let golden = (index as f64 * 137.508) % 360.0;
    let (hue, light) = if lsda {
        (28.0 + golden % 24.0, 58 + (index % 2) * 8)
    } else {
        (175.0 + golden % 90.0, 55 + (index % 3) * 7)
    };
    format!("hsl({hue:.0},78%,{light}%)")
}

/// Index of the interval containing `addr`, or else the first one starting
/// in `[addr, addr + len)`. `starts` must be sorted.
fn owner_of(ranges: &[(u64, u64)], addr: u64, len: u64) -> Option<usize> {
    let i = ranges.partition_point(|&(start, _)| start <= addr);
    if i > 0 && addr < ranges[i - 1].1 {
        return Some(i - 1);
    }
    (i < ranges.len() && ranges[i].0 < addr + len).then_some(i)
}

pub(crate) fn render(report: &Report, file: &str, names: &[String]) -> String {
    let segments: Vec<(u64, u64)> = report.exec.iter().map(|r| (r.start, r.end)).collect();
    let total: u64 = segments.iter().map(|(s, e)| e - s).sum();
    let wanted = total.clamp(1, MAX_SIDE * MAX_SIDE);
    let mut side = 16;
    while side * side < wanted {
        side *= 2;
    }
    let per_cell = total.div_ceil(side * side).max(1);
    let cells = total.div_ceil(per_cell);

    let functions: Vec<(u64, u64)> = report.functions.iter().map(|f| (f.start, f.end)).collect();
    let mut gaps: Vec<(u64, u64)> = report.gaps.iter().map(|g| (g.start, g.end)).collect();
    gaps.sort_unstable();

    // Owner of every cell, in address order.
    let mut owners = Vec::with_capacity(cells as usize);
    let (mut seg, mut seg_off) = (0usize, 0u64);
    for _ in 0..cells {
        while seg < segments.len() && seg_off >= segments[seg].1 - segments[seg].0 {
            seg_off -= segments[seg].1 - segments[seg].0;
            seg += 1;
        }
        let addr = segments.get(seg).map_or(0, |s| s.0 + seg_off);
        let owner = match owner_of(&functions, addr, per_cell) {
            Some(i) => Owner::Function(i),
            None => owner_of(&gaps, addr, per_cell).map_or(Owner::Padding, Owner::Gap),
        };
        owners.push(owner);
        seg_off += per_cell;
    }

    let scale = MAP / side as f64;
    let mut out = String::new();
    let _ = writeln!(
        out,
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="Map of the executable code in {file}">
  <style>text {{ font-family: {FONT}; }}</style>
  <rect x="0.75" y="0.75" width="{w}" height="{h}" rx="14" fill="#0d1117" stroke="#30363d" stroke-width="1.5"/>
  <rect x="{PAD}" y="{PAD}" width="{MAP}" height="{MAP}" fill="#010409"/>
  <defs>
    <filter id="glow" x="-5%" y="-5%" width="110%" height="110%">
      <feGaussianBlur stdDeviation="0.55" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <g transform="translate({PAD} {PAD}) scale({scale})" fill="none" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)">"##,
        file = xml(file),
        w = WIDTH - 1.5,
        h = HEIGHT - 1.5,
    );

    // One polyline per run of cells with the same owner.
    let mut d = 0;
    while d < owners.len() {
        let owner = owners[d];
        let mut points: Vec<(u64, u64)> = Vec::new();
        while d < owners.len() && owners[d] == owner {
            let p = d2xy(side, d as u64);
            if points.len() >= 2 {
                let (a, b) = (points[points.len() - 2], points[points.len() - 1]);
                if (a.0 == b.0 && b.0 == p.0) || (a.1 == b.1 && b.1 == p.1) {
                    points.pop();
                }
            }
            points.push(p);
            d += 1;
        }
        let (color, title, width) = match owner {
            Owner::Function(i) => {
                let f = &report.functions[i];
                (
                    function_color(i, f.has_lsda),
                    format!(
                        "{} {:#x}-{:#x} ({} bytes)",
                        names[i],
                        f.start,
                        f.end,
                        f.size()
                    ),
                    TRACE,
                )
            }
            Owner::Gap(i) => {
                let (s, e) = gaps[i];
                (
                    GAP_COLOR.to_string(),
                    format!("no unwind info {s:#x}-{e:#x} ({} bytes)", e - s),
                    TRACE,
                )
            }
            // Padding is drawn as a faint wire so the curve stays visible.
            Owner::Padding => (PADDING_COLOR.to_string(), String::new(), TRACE / 3.0),
        };
        let title = if title.is_empty() {
            String::new()
        } else {
            format!("<title>{}</title>", xml(&title))
        };
        if points.len() == 1 {
            let (x, y) = points[0];
            let _ = writeln!(
                out,
                r#"    <circle cx="{x}.5" cy="{y}.5" r="{}" fill="{color}">{title}</circle>"#,
                width / 2.0
            );
        } else {
            let coords: Vec<String> = points.iter().map(|(x, y)| format!("{x}.5,{y}.5")).collect();
            let _ = writeln!(
                out,
                r#"    <polyline points="{}" stroke="{color}" stroke-width="{width}">{title}</polyline>"#,
                coords.join(" ")
            );
        }
    }
    out.push_str("  </g>\n");

    // Caption: what this is, the numbers, and a legend.
    let y = PAD + MAP + 32.0;
    let shown_file = if file.chars().count() > 48 {
        format!(
            "…{}",
            file.chars()
                .rev()
                .take(47)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        )
    } else {
        file.to_string()
    };
    let _ = writeln!(
        out,
        r##"  <text x="{PAD}" y="{y}" font-size="15"><tspan fill="#ffa657" font-weight="700">unwind-map</tspan><tspan fill="#8b949e">  {}</tspan></text>"##,
        xml(&shown_file)
    );
    let _ = writeln!(
        out,
        r##"  <text x="{PAD}" y="{}" font-size="13" fill="#c9d1d9">ELF{} {} {} · {} functions · {:.1}% of {} covered</text>"##,
        y + 24.0,
        report.class.bits(),
        xml(&report.machine_name),
        report.file_type,
        report.functions.len(),
        report.coverage(),
        human_size(report.stats.exec_bytes)
    );
    let legend = [
        (function_color(1, false), "function", 0.0),
        (function_color(1, true), "has landing pads", 106.0),
        (GAP_COLOR.to_string(), "no unwind info", 262.0),
        (PADDING_COLOR.to_string(), "padding", 404.0),
    ];
    for (color, label, dx) in legend {
        let _ = writeln!(
            out,
            r##"  <rect x="{}" y="{}" width="12" height="12" rx="2" fill="{color}" stroke="#30363d"/><text x="{}" y="{}" font-size="12" fill="#8b949e">{label}</text>"##,
            PAD + dx,
            y + 40.0,
            PAD + dx + 18.0,
            y + 50.5
        );
    }
    let _ = writeln!(
        out,
        r##"  <text x="{PAD}" y="{}" font-size="11.5" fill="#6e7681">Hilbert curve from top-left to top-right · 1 cell = {per_cell} byte{} · {} cells</text>"##,
        y + 74.0,
        if per_cell == 1 { "" } else { "s" },
        cells
    );
    out.push_str("</svg>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hilbert_curve_visits_every_cell_once_in_adjacent_steps() {
        let side = 16;
        let mut seen = vec![false; (side * side) as usize];
        let mut prev = d2xy(side, 0);
        assert_eq!(prev, (0, 0));
        for d in 0..side * side {
            let (x, y) = d2xy(side, d);
            assert!(!seen[(y * side + x) as usize]);
            seen[(y * side + x) as usize] = true;
            if d > 0 {
                assert_eq!(x.abs_diff(prev.0) + y.abs_diff(prev.1), 1, "step {d}");
            }
            prev = (x, y);
        }
        assert_eq!(prev, (side - 1, 0));
    }

    #[test]
    fn owner_lookup_prefers_containing_interval() {
        let ranges = [(0x10, 0x20), (0x30, 0x40)];
        assert_eq!(owner_of(&ranges, 0x15, 4), Some(0));
        assert_eq!(owner_of(&ranges, 0x2e, 4), Some(1));
        assert_eq!(owner_of(&ranges, 0x22, 4), None);
        assert_eq!(owner_of(&ranges, 0x50, 4), None);
    }
}
