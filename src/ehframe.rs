//! Decoder for `.eh_frame` (CIE/FDE records) and `.eh_frame_hdr`.
//!
//! The format is the Linux Standard Base "Exception Frames" variant of DWARF
//! call frame information. Only the parts needed to recover function ranges
//! are decoded; the CFA programs themselves are skipped.

use std::collections::HashMap;

use crate::reader::Reader;
use crate::{Error, Result};

/// `DW_EH_PE_omit`: the value is not present.
pub const DW_EH_PE_OMIT: u8 = 0xff;

const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_DATAREL: u8 = 0x30;

/// Context needed to resolve `DW_EH_PE_*` encoded pointers.
#[derive(Debug, Clone, Copy)]
pub struct Bases {
    /// Virtual address of byte 0 of the buffer being read.
    pub vaddr: u64,
    /// Base for `DW_EH_PE_datarel` (the start of `.eh_frame_hdr`).
    pub data: Option<u64>,
    pub addr_size: u8,
}

/// Truncates `value` to the target's address width.
pub fn mask(value: u64, addr_size: u8) -> u64 {
    if addr_size == 4 {
        value & 0xffff_ffff
    } else {
        value
    }
}

/// Reads the raw value of a pointer in format `enc & 0x0f`, ignoring how it
/// is applied.
pub fn read_format(r: &mut Reader, enc: u8, addr_size: u8) -> Result<u64> {
    Ok(match enc & 0x0f {
        0x00 => r.word(addr_size)?,
        0x01 => r.uleb128()?,
        0x02 => u64::from(r.u16()?),
        0x03 => u64::from(r.u32()?),
        0x04 => r.u64()?,
        0x09 => r.sleb128()? as u64,
        0x0a => r.u16()? as i16 as i64 as u64,
        0x0b => r.u32()? as i32 as i64 as u64,
        0x0c => r.u64()?,
        f => bail!("unsupported pointer format {f:#x}"),
    })
}

/// Size in bytes of a fixed-size pointer format, or `None` for LEB128.
fn format_size(enc: u8, addr_size: u8) -> Option<usize> {
    match enc & 0x0f {
        0x00 => Some(addr_size.into()),
        0x02 | 0x0a => Some(2),
        0x03 | 0x0b => Some(4),
        0x04 | 0x0c => Some(8),
        _ => None,
    }
}

/// Reads and resolves a `DW_EH_PE_*` encoded pointer.
///
/// As in libgcc, a raw value of zero always decodes to zero, which is how
/// "no pointer" is represented (and how some linkers mark FDEs of discarded
/// functions). The indirect bit (`0x80`) is ignored: the address of the
/// pointer is returned rather than its target.
pub fn read_encoded(r: &mut Reader, enc: u8, bases: &Bases) -> Result<u64> {
    let field = bases.vaddr.wrapping_add(r.pos() as u64);
    let raw = read_format(r, enc, bases.addr_size)?;
    if raw == 0 {
        return Ok(0);
    }
    let value = match enc & 0x70 {
        DW_EH_PE_ABSPTR => raw,
        DW_EH_PE_PCREL => field.wrapping_add(raw),
        DW_EH_PE_DATAREL => match bases.data {
            Some(base) => base.wrapping_add(raw),
            None => bail!("data-relative pointer outside .eh_frame_hdr"),
        },
        app => bail!("unsupported pointer application {app:#x}"),
    };
    Ok(mask(value, bases.addr_size))
}

/// Common Information Entry: shared parameters for a group of FDEs.
#[derive(Debug, Clone)]
pub struct Cie {
    pub version: u8,
    pub augmentation: String,
    pub code_align: u64,
    pub data_align: i64,
    pub return_register: u64,
    pub fde_encoding: u8,
    pub lsda_encoding: u8,
    pub has_personality: bool,
    pub signal_frame: bool,
    has_augmentation_data: bool,
}

/// Frame Description Entry: unwind information for one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fde {
    /// Offset of the record within `.eh_frame`.
    pub offset: usize,
    pub cie_offset: usize,
    pub start: u64,
    pub end: u64,
    /// The function has a language-specific data area, i.e. landing pads for
    /// exceptions, panics or cleanups.
    pub has_lsda: bool,
    pub has_personality: bool,
    pub signal_frame: bool,
}

#[derive(Debug, Default)]
pub struct Walk {
    pub fdes: Vec<Fde>,
    pub cie_count: usize,
    pub warnings: Vec<String>,
}

struct Header {
    id_pos: usize,
    id: u32,
    end: usize,
}

/// A `.eh_frame` image mapped at a known virtual address.
pub struct EhFrame<'a> {
    data: &'a [u8],
    bases: Bases,
    cies: HashMap<usize, Cie>,
}

impl<'a> EhFrame<'a> {
    pub fn new(data: &'a [u8], vaddr: u64, addr_size: u8) -> Self {
        Self {
            data,
            bases: Bases {
                vaddr,
                data: None,
                addr_size,
            },
            cies: HashMap::new(),
        }
    }

    /// Number of distinct CIEs decoded so far.
    pub fn cie_count(&self) -> usize {
        self.cies.len()
    }

    /// Walks every record from the start of the buffer until the end, a zero
    /// terminator, or a record whose length cannot be trusted.
    pub fn walk(&mut self) -> Walk {
        let mut out = Walk::default();
        let mut pos = 0usize;
        while pos + 4 <= self.data.len() {
            let header = match self.header(pos) {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    out.warnings
                        .push(format!(".eh_frame+{pos:#x}: {e}; stopping"));
                    break;
                }
            };
            let result = if header.id == 0 {
                self.cie_at(pos).map(|_| ())
            } else {
                self.fde_at(pos).map(|fde| out.fdes.push(fde))
            };
            if let Err(e) = result {
                out.warnings.push(format!(".eh_frame+{pos:#x}: {e}"));
            }
            pos = header.end;
        }
        out.cie_count = self.cies.len();
        out
    }

    /// Decodes the FDE at `offset`.
    pub fn fde_at(&mut self, offset: usize) -> Result<Fde> {
        let h = self
            .header(offset)?
            .ok_or_else(|| Error::new("expected an FDE, found a terminator"))?;
        if h.id == 0 {
            bail!("expected an FDE, found a CIE");
        }
        let cie_offset = h.id_pos.checked_sub(h.id as usize).ok_or_else(|| {
            Error::new(format!("CIE pointer {:#x} points before .eh_frame", h.id))
        })?;
        let cie = self.cie_at(cie_offset)?;
        let addr_size = self.bases.addr_size;

        let mut r = Reader::at(&self.data[..h.end], h.id_pos + 4);
        let start = read_encoded(&mut r, cie.fde_encoding, &self.bases)?;
        let range = mask(read_format(&mut r, cie.fde_encoding, addr_size)?, addr_size);

        let mut has_lsda = false;
        if cie.has_augmentation_data {
            let len = r.uleb128()? as usize;
            let aug = r.bytes(len)?;
            if cie.lsda_encoding != DW_EH_PE_OMIT && !aug.is_empty() {
                has_lsda = read_format(&mut Reader::new(aug), cie.lsda_encoding, addr_size)? != 0;
            }
        }

        Ok(Fde {
            offset,
            cie_offset,
            start,
            end: mask(start.wrapping_add(range), addr_size),
            has_lsda,
            has_personality: cie.has_personality,
            signal_frame: cie.signal_frame,
        })
    }

    /// Decodes (and caches) the CIE at `offset`.
    pub fn cie_at(&mut self, offset: usize) -> Result<Cie> {
        if let Some(cie) = self.cies.get(&offset) {
            return Ok(cie.clone());
        }
        let cie = self.parse_cie(offset)?;
        self.cies.insert(offset, cie.clone());
        Ok(cie)
    }

    fn parse_cie(&self, offset: usize) -> Result<Cie> {
        let h = self
            .header(offset)?
            .ok_or_else(|| Error::new("expected a CIE, found a terminator"))?;
        if h.id != 0 {
            bail!("expected a CIE at .eh_frame+{offset:#x}, found an FDE");
        }
        let mut r = Reader::at(&self.data[..h.end], h.id_pos + 4);
        let version = r.u8()?;
        if !matches!(version, 1 | 3 | 4) {
            bail!("unsupported CIE version {version}");
        }
        let augmentation = String::from_utf8_lossy(r.cstr()?).into_owned();
        if augmentation.contains("eh") {
            bail!("legacy \"eh\" CIE augmentation is not supported");
        }
        if version == 4 {
            let _address_size = r.u8()?;
            let _segment_size = r.u8()?;
        }
        let code_align = r.uleb128()?;
        let data_align = r.sleb128()?;
        let return_register = if version == 1 {
            u64::from(r.u8()?)
        } else {
            r.uleb128()?
        };

        let mut cie = Cie {
            version,
            augmentation: augmentation.clone(),
            code_align,
            data_align,
            return_register,
            fde_encoding: DW_EH_PE_ABSPTR,
            lsda_encoding: DW_EH_PE_OMIT,
            has_personality: false,
            signal_frame: false,
            has_augmentation_data: false,
        };

        if let Some(letters) = augmentation.strip_prefix('z') {
            cie.has_augmentation_data = true;
            let len = r.uleb128()? as usize;
            let mut a = Reader::new(r.bytes(len)?);
            for letter in letters.chars() {
                match letter {
                    'R' => cie.fde_encoding = a.u8()?,
                    'L' => cie.lsda_encoding = a.u8()?,
                    'P' => {
                        let enc = a.u8()?;
                        read_format(&mut a, enc, self.bases.addr_size)?;
                        cie.has_personality = true;
                    }
                    'S' => cie.signal_frame = true,
                    // AArch64 pointer authentication (B key) and MTE tagging
                    // carry no augmentation data.
                    'B' | 'G' => {}
                    // The length prefix lets us skip anything newer.
                    _ => break,
                }
            }
        } else if !augmentation.is_empty() {
            bail!("unknown CIE augmentation {augmentation:?}");
        }
        Ok(cie)
    }

    fn header(&self, pos: usize) -> Result<Option<Header>> {
        let mut r = Reader::at(self.data, pos);
        let len32 = r.u32()?;
        if len32 == 0 {
            return Ok(None);
        }
        let len = if len32 == 0xffff_ffff {
            r.u64()?
        } else {
            u64::from(len32)
        };
        let id_pos = r.pos();
        let end = (id_pos as u64)
            .checked_add(len)
            .filter(|&end| end <= self.data.len() as u64 && len >= 4)
            .ok_or_else(|| Error::new(format!("record length {len:#x} is invalid")))?
            as usize;
        let id = r.u32()?;
        Ok(Some(Header { id_pos, id, end }))
    }
}

/// Decoded `.eh_frame_hdr`.
#[derive(Debug, Clone)]
pub struct EhFrameHdr {
    pub eh_frame_ptr: u64,
    /// Sorted `(initial_location, fde_address)` pairs, if the linker emitted
    /// the binary search table.
    pub table: Option<Vec<(u64, u64)>>,
}

pub fn parse_eh_frame_hdr(data: &[u8], vaddr: u64, addr_size: u8) -> Result<EhFrameHdr> {
    let mut r = Reader::new(data);
    let version = r.u8()?;
    if version != 1 {
        bail!("unsupported .eh_frame_hdr version {version}");
    }
    let ptr_enc = r.u8()?;
    let count_enc = r.u8()?;
    let table_enc = r.u8()?;
    if ptr_enc == DW_EH_PE_OMIT {
        bail!(".eh_frame_hdr does not record where .eh_frame is");
    }
    let bases = Bases {
        vaddr,
        data: Some(vaddr),
        addr_size,
    };
    let eh_frame_ptr = read_encoded(&mut r, ptr_enc, &bases)?;

    if count_enc == DW_EH_PE_OMIT || table_enc == DW_EH_PE_OMIT {
        return Ok(EhFrameHdr {
            eh_frame_ptr,
            table: None,
        });
    }
    let count = read_encoded(&mut r, count_enc, &bases)?;
    let entry = format_size(table_enc, addr_size)
        .ok_or_else(|| Error::new("variable-length .eh_frame_hdr table encoding"))?
        * 2;
    if count > (r.remaining() / entry) as u64 {
        bail!(
            ".eh_frame_hdr claims {count} entries but only has room for {}",
            r.remaining() / entry
        );
    }
    let mut table = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let location = read_encoded(&mut r, table_enc, &bases)?;
        let fde = read_encoded(&mut r, table_enc, &bases)?;
        table.push((location, fde));
    }
    Ok(EhFrameHdr {
        eh_frame_ptr,
        table: Some(table),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bases(vaddr: u64, addr_size: u8) -> Bases {
        Bases {
            vaddr,
            data: Some(0x9000),
            addr_size,
        }
    }

    #[test]
    fn pcrel_sdata4_is_relative_to_the_field() {
        // Field at 0x2000 + 4, value -0x1004 => 0x1000.
        let data = [0, 0, 0, 0, 0xfc, 0xef, 0xff, 0xff];
        let mut r = Reader::at(&data, 4);
        assert_eq!(
            read_encoded(&mut r, 0x1b, &bases(0x2000, 8)).unwrap(),
            0x1000
        );
    }

    #[test]
    fn pcrel_wraps_to_32_bits_on_elf32() {
        // Field at 0xffff_fff0, +0x20 wraps past 4 GiB.
        let data = 0x20u32.to_le_bytes();
        let mut r = Reader::new(&data);
        assert_eq!(
            read_encoded(&mut r, 0x1b, &bases(0xffff_fff0, 4)).unwrap(),
            0x10
        );
    }

    #[test]
    fn datarel_uses_the_header_base() {
        let data = 0x40u32.to_le_bytes();
        assert_eq!(
            read_encoded(&mut Reader::new(&data), 0x3b, &bases(0, 8)).unwrap(),
            0x9040
        );
    }

    #[test]
    fn zero_raw_value_means_null() {
        let data = [0u8; 4];
        assert_eq!(
            read_encoded(&mut Reader::new(&data), 0x1b, &bases(0x5000, 8)).unwrap(),
            0
        );
    }

    /// Builds a small `.eh_frame` with one "zPLR" CIE and two FDEs.
    fn sample() -> Vec<u8> {
        let mut cie = vec![0, 0, 0, 0]; // CIE id
        cie.push(1); // version
        cie.extend_from_slice(b"zPLR\0");
        cie.push(1); // code alignment
        cie.push(0x78); // data alignment -8
        cie.push(16); // return address register
        cie.push(7); // augmentation data length
        cie.extend_from_slice(&[0x03, 0, 0, 0, 0]); // P: udata4 personality pointer
        cie.push(0x1b); // L: pcrel sdata4
        cie.push(0x1b); // R: pcrel sdata4
        while (cie.len() + 4) % 4 != 0 {
            cie.push(0);
        }
        let mut out = (cie.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&cie);

        for (target, lsda) in [(0x1000i64, 0u32), (0x1100, 0x2222)] {
            let start = out.len();
            let mut fde = Vec::new();
            fde.extend_from_slice(&((start + 4) as u32).to_le_bytes()); // CIE pointer
            let field = 0x4000 + start as i64 + 8;
            fde.extend_from_slice(&((target - field) as i32).to_le_bytes());
            fde.extend_from_slice(&0x80u32.to_le_bytes()); // range
            fde.push(4);
            fde.extend_from_slice(&lsda.to_le_bytes());
            out.extend_from_slice(&(fde.len() as u32).to_le_bytes());
            out.extend_from_slice(&fde);
        }
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    #[test]
    fn walks_cies_and_fdes() {
        let data = sample();
        let walk = EhFrame::new(&data, 0x4000, 8).walk();
        assert!(walk.warnings.is_empty(), "{:?}", walk.warnings);
        assert_eq!(walk.cie_count, 1);
        let ranges: Vec<_> = walk
            .fdes
            .iter()
            .map(|f| (f.start, f.end, f.has_lsda))
            .collect();
        assert_eq!(
            ranges,
            vec![(0x1000, 0x1080, false), (0x1100, 0x1180, true)]
        );
        assert!(walk.fdes.iter().all(|f| f.has_personality));
    }

    #[test]
    fn truncated_record_stops_the_walk_with_a_warning() {
        let mut data = sample();
        data.truncate(data.len() - 10);
        let walk = EhFrame::new(&data, 0x4000, 8).walk();
        assert_eq!(walk.fdes.len(), 1);
        assert_eq!(walk.warnings.len(), 1);
    }

    #[test]
    fn parses_eh_frame_hdr_table() {
        let mut hdr = vec![1, 0x1b, 0x03, 0x3b];
        hdr.extend_from_slice(&(-0x100i32).to_le_bytes()); // eh_frame_ptr: pcrel from 0x9004
        hdr.extend_from_slice(&2u32.to_le_bytes());
        for (loc, fde) in [(-0x8000i32, -0x100i32), (-0x7000, -0xe0)] {
            hdr.extend_from_slice(&loc.to_le_bytes());
            hdr.extend_from_slice(&fde.to_le_bytes());
        }
        let parsed = parse_eh_frame_hdr(&hdr, 0x9000, 8).unwrap();
        assert_eq!(parsed.eh_frame_ptr, 0x8f04);
        assert_eq!(
            parsed.table.unwrap(),
            vec![(0x1000, 0x8f00), (0x2000, 0x8f20)]
        );
    }
}
