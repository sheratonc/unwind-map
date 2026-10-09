//! Bounds-checked little-endian cursor over a byte slice.

use crate::Result;

#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        match self.pos.checked_add(n) {
            Some(end) if end <= self.data.len() => {
                let out = &self.data[self.pos..end];
                self.pos = end;
                Ok(out)
            }
            _ => bail!(
                "unexpected end of data at offset {:#x} (needed {n} more bytes)",
                self.pos
            ),
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads a 4- or 8-byte word, as used by ELF32 / ELF64 address fields.
    pub fn word(&mut self, size: u8) -> Result<u64> {
        match size {
            4 => self.u32().map(u64::from),
            8 => self.u64(),
            _ => bail!("unsupported word size {size}"),
        }
    }

    pub fn uleb128(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            if shift >= 70 {
                bail!("ULEB128 value longer than 10 bytes");
            }
        }
    }

    pub fn sleb128(&mut self) -> Result<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= i64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
            if shift >= 70 {
                bail!("SLEB128 value longer than 10 bytes");
            }
        }
    }

    /// Reads a NUL-terminated string and returns it without the terminator.
    pub fn cstr(&mut self) -> Result<&'a [u8]> {
        let rest = &self.data[self.pos.min(self.data.len())..];
        match rest.iter().position(|&b| b == 0) {
            Some(n) => {
                let out = &rest[..n];
                self.pos += n + 1;
                Ok(out)
            }
            None => bail!("unterminated string at offset {:#x}", self.pos),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_reference_values() {
        // Examples from the DWARF 5 specification, section 7.6.
        assert_eq!(Reader::new(&[0x02]).uleb128().unwrap(), 2);
        assert_eq!(Reader::new(&[0x7f]).uleb128().unwrap(), 127);
        assert_eq!(Reader::new(&[0x80, 0x01]).uleb128().unwrap(), 128);
        assert_eq!(Reader::new(&[0xe5, 0x8e, 0x26]).uleb128().unwrap(), 624_485);
        assert_eq!(Reader::new(&[0x7e]).sleb128().unwrap(), -2);
        assert_eq!(Reader::new(&[0xff, 0x00]).sleb128().unwrap(), 127);
        assert_eq!(Reader::new(&[0x80, 0x7f]).sleb128().unwrap(), -128);
        assert_eq!(
            Reader::new(&[0xc0, 0xbb, 0x78]).sleb128().unwrap(),
            -123_456
        );
    }

    #[test]
    fn overlong_leb128_is_rejected() {
        assert!(Reader::new(&[0x80; 11]).uleb128().is_err());
    }

    #[test]
    fn reads_past_the_end_fail() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.u32().is_err());
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(r.cstr().is_err());
    }
}
