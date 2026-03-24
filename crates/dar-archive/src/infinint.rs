use anyhow::{bail, Result};

/// Decode a libdar infinint (variable-length integer) from the beginning of `data`.
///
/// libdar infinint encoding (confirmed from real_infinint.cpp, TG = 4):
///
///   The bitfield byte (BB) encodes the number of 4-byte data groups via its
///   highest set bit:
///     BB = 0x80  → 1 group  →  5 bytes total  (1 BB + 4 data)
///     BB = 0x40  → 2 groups →  9 bytes total  (1 BB + 8 data)
///     BB = 0x20  → 3 groups → 13 bytes total
///     ...
///     BB = 0x00  → 0 groups →  1 byte  total  (value = 0, edge case)
///
///   For values that require N × 8 complete groups of 4-byte integers, N
///   leading 0x00 preamble bytes precede BB.  In practice (values ≤ u64::MAX)
///   N is always 0, so we do not implement the preamble.
///
/// Returns `(value, bytes_consumed)`.
pub fn decode_infinint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        bail!("truncated infinint: empty slice");
    }
    let bb = data[0];
    if bb == 0x00 {
        // BB = 0x00: zero 4-byte groups → value 0, 1 byte consumed.
        return Ok((0, 1));
    }
    // Highest set bit of BB (counting from MSB) determines num_groups:
    //   0x80 → leading_zeros = 0 → num_groups = 1
    //   0x40 → leading_zeros = 1 → num_groups = 2
    let num_groups = (bb.leading_zeros() as usize) + 1;
    let data_bytes = num_groups * 4;
    let total = 1 + data_bytes;
    if total > data.len() {
        bail!("truncated infinint: need {total} bytes, have {}", data.len());
    }
    if data_bytes > 8 {
        // Value > u64::MAX — not representable; skip gracefully.
        return Ok((u64::MAX, total));
    }
    let mut value = 0u64;
    for i in 0..data_bytes {
        value = (value << 8) | (data[1 + i] as u64);
    }
    Ok((value, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_zero_five_bytes() {
        // libdar canonically encodes 0 as: 0x80 0x00 0x00 0x00 0x00
        let (v, n) = decode_infinint(&[0x80, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(v, 0);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_bb_zero_edge_case() {
        // BB=0x00: zero groups → value 0, 1 byte consumed.
        let (v, n) = decode_infinint(&[0x00]).unwrap();
        assert_eq!(v, 0);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_value_1() {
        let (v, n) = decode_infinint(&[0x80, 0x00, 0x00, 0x00, 0x01]).unwrap();
        assert_eq!(v, 1);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_value_1000() {
        // 1000 = 0x000003E8
        let (v, n) = decode_infinint(&[0x80, 0x00, 0x00, 0x03, 0xE8]).unwrap();
        assert_eq!(v, 1000);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_value_max_u32() {
        // 0xFFFF_FFFF → 80 FF FF FF FF
        let (v, n) = decode_infinint(&[0x80, 0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(v, 0xFFFF_FFFF);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_value_u64_two_groups() {
        // Two groups (BB = 0x40): value 0x0000_0001_0000_0000 = 2^32
        let (v, n) = decode_infinint(&[
            0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        assert_eq!(v, 0x1_0000_0000u64);
        assert_eq!(n, 9);
    }

    #[test]
    fn test_truncated_error() {
        assert!(decode_infinint(&[0x80, 0x00]).is_err());
    }

    #[test]
    fn test_empty_error() {
        assert!(decode_infinint(&[]).is_err());
    }

    #[test]
    fn test_trailing_bytes_ignored() {
        // Extra bytes after a valid infinint should not affect the result.
        let (v, n) = decode_infinint(&[0x80, 0x00, 0x00, 0x00, 0x07, 0xFF, 0xFF]).unwrap();
        assert_eq!(v, 7);
        assert_eq!(n, 5);
    }
}
