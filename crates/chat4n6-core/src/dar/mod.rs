pub mod catalog;
pub mod fs;
pub mod header;

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum DarVersion {
    V8,
    V9,
}

impl DarVersion {
    pub fn from_magic(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            bail!("too short for magic");
        }
        match bytes[0] {
            0xd2 if bytes[1] == 0xab => Ok(DarVersion::V8),
            0xd3 if bytes[1] == 0xab => Ok(DarVersion::V9),
            _ => bail!(
                "unrecognized DAR magic: {:#04x} {:#04x}",
                bytes[0],
                bytes[1]
            ),
        }
    }
}

/// Decode a DAR infinint (variable-length integer).
/// Format: N zero bytes followed by N non-zero bytes (big-endian value).
/// Returns (value, bytes_consumed).
pub fn decode_infinint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        bail!("empty infinint");
    }
    // Count leading zero bytes to determine N (the prefix length).
    // The format is: N zero bytes followed by N value bytes (big-endian).
    // When all available bytes are zero, cap N at data.len()/2 so the
    // remaining data.len()/2 bytes serve as the (zero-valued) value group.
    // When a non-zero byte is found first, use the natural count — if the
    // resulting N*2 bytes aren't available, that's a truncation error.
    let all_zero = data.iter().all(|&b| b == 0);
    let zero_count = if all_zero {
        data.len() / 2
    } else {
        let mut n = 0usize;
        for &b in data {
            if b == 0 {
                n += 1;
            } else {
                break;
            }
        }
        n
    };
    if zero_count == 0 {
        // single-byte encoding: value is the byte itself
        return Ok((data[0] as u64, 1));
    }
    let end = zero_count * 2;
    if data.len() < end {
        bail!(
            "truncated infinint: need {} bytes, have {}",
            end,
            data.len()
        );
    }
    let value_bytes = &data[zero_count..end];
    let mut value = 0u64;
    for &b in value_bytes {
        value = (value << 8) | b as u64;
    }
    Ok((value, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dar_magic_v8() {
        let magic_v8 = DarVersion::from_magic(b"\xd2\xab\xea\x18\x00\x08").unwrap();
        assert_eq!(magic_v8, DarVersion::V8);
    }

    #[test]
    fn test_detect_dar_magic_v9() {
        let magic_v9 = DarVersion::from_magic(b"\xd3\xab\x00\x00\x00\x09").unwrap();
        assert_eq!(magic_v9, DarVersion::V9);
    }

    #[test]
    fn test_infinint_decode_single_byte() {
        // Single byte infinint: 1 zero byte + 1 value byte => value=5
        let result = decode_infinint(&[0x00, 0x05]).unwrap();
        assert_eq!(result, (5u64, 2));
    }

    #[test]
    fn test_infinint_decode_multi_byte() {
        // 2 zero bytes + 2 value bytes (big-endian): 0x01 0x00 = 256
        let result = decode_infinint(&[0x00, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(result, (256u64, 4));
    }

    #[test]
    fn test_infinint_decode_zero_value() {
        // 1 zero byte + 1 zero value byte = value 0
        let result = decode_infinint(&[0x00, 0x00]).unwrap();
        assert_eq!(result, (0u64, 2));
    }

    #[test]
    fn test_detect_dar_magic_unknown_errors() {
        assert!(DarVersion::from_magic(b"\xff\xff\x00\x00").is_err());
    }

    #[test]
    fn test_infinint_truncated_error() {
        // 2 zero bytes but only 1 value byte (need 4 total)
        assert!(decode_infinint(&[0x00, 0x00, 0x01]).is_err());
    }
}
