//! Tells alignment padding apart from real code in bytes that no FDE covers.

use crate::elf::{EM_386, EM_AARCH64, EM_X86_64};

/// `lea`/`mov` no-ops that 32-bit binutils uses to pad between functions.
const I386_PADDING: &[&[u8]] = &[
    &[0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00],
    &[0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00],
    &[0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00],
    &[0x8d, 0x74, 0x26, 0x00],
    &[0x8d, 0x76, 0x00],
    &[0x89, 0xf6],
];

const AARCH64_NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

/// Length of the padding instruction at the start of `bytes`, if any.
fn padding_len(machine: u16, bytes: &[u8]) -> Option<usize> {
    match machine {
        EM_X86_64 | EM_386 => x86_padding_len(bytes, machine == EM_386),
        EM_AARCH64 => {
            let word = bytes.get(..4)?;
            (word == [0; 4] || word == AARCH64_NOP).then_some(4)
        }
        _ => (bytes.first() == Some(&0)).then_some(1),
    }
}

fn x86_padding_len(b: &[u8], is_i386: bool) -> Option<usize> {
    // Zero fill, `nop`, and the `int3` fill LLD uses between functions.
    if matches!(b.first()?, 0x00 | 0x90 | 0xcc) {
        return Some(1);
    }
    if is_i386 && let Some(p) = I386_PADDING.iter().find(|p| b.starts_with(p)) {
        return Some(p.len());
    }
    // Multi-byte NOPs: any number of operand-size / CS prefixes, then either
    // `90` (`xchg ax, ax`) or `0f 1f /0` with an arbitrary memory operand.
    let mut i = 0;
    while i < b.len() && i < 14 && matches!(b[i], 0x66 | 0x2e) {
        i += 1;
    }
    if i > 0 && b.get(i) == Some(&0x90) {
        return Some(i + 1);
    }
    if b.get(i) != Some(&0x0f) || b.get(i + 1) != Some(&0x1f) {
        return None;
    }
    let modrm = *b.get(i + 2)?;
    let (md, rm) = (modrm >> 6, modrm & 7);
    let mut len = i + 3;
    if md != 3 && rm == 4 {
        let sib = *b.get(len)?;
        len += 1;
        if md == 0 && sib & 7 == 5 {
            len += 4;
        }
    }
    len += match (md, rm) {
        (0, 5) => 4,
        (1, _) => 1,
        (2, _) => 4,
        _ => 0,
    };
    (len <= b.len()).then_some(len)
}

/// Returns the `[first, last)` byte span of `bytes` that is not padding, or
/// `None` if everything is padding.
pub fn code_span(machine: u16, bytes: &[u8]) -> Option<(usize, usize)> {
    let step = if machine == EM_AARCH64 { 4 } else { 1 };
    let mut first = None;
    let mut last = 0;
    let mut i = 0;
    while i < bytes.len() {
        match padding_len(machine, &bytes[i..]) {
            Some(n) => i += n,
            None => {
                let n = step.min(bytes.len() - i);
                first.get_or_insert(i);
                last = i + n;
                i += n;
            }
        }
    }
    first.map(|f| (f, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_nop_sequences_are_padding() {
        let pad: &[u8] = &[
            0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nopw cs:[rax+rax]
            0x0f, 0x1f, 0x44, 0x00, 0x00, // nopl [rax+rax]
            0x0f, 0x1f, 0x40, 0x00, // nopl [rax]
            0x66, 0x90, // xchg ax, ax
            0xcc, 0xcc, 0x90,
        ];
        assert_eq!(code_span(EM_X86_64, pad), None);
    }

    #[test]
    fn x86_code_between_padding_is_found() {
        // padding, `lea rax, [rdi+rsi]; ret`, padding
        let bytes = [0xcc, 0xcc, 0x48, 0x8d, 0x04, 0x37, 0xc3, 0x0f, 0x1f, 0x00];
        assert_eq!(code_span(EM_X86_64, &bytes), Some((2, 7)));
    }

    #[test]
    fn i386_lea_padding_is_padding() {
        let bytes = [0x8d, 0xb4, 0x26, 0, 0, 0, 0, 0x8d, 0x76, 0x00, 0x90];
        assert_eq!(code_span(EM_386, &bytes), None);
        assert!(code_span(EM_X86_64, &bytes).is_some());
    }

    #[test]
    fn aarch64_nops_and_zero_words_are_padding() {
        let mut bytes = AARCH64_NOP.repeat(3);
        bytes.extend_from_slice(&[0; 4]);
        assert_eq!(code_span(EM_AARCH64, &bytes), None);
        // `add x0, x0, x1; ret` after one nop
        bytes.splice(4..4, [0x00, 0x00, 0x01, 0x8b, 0xc0, 0x03, 0x5f, 0xd6]);
        assert_eq!(code_span(EM_AARCH64, &bytes), Some((4, 12)));
    }
}
