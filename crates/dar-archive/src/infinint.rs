use anyhow::{bail, Result};

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
    fn test_single_nonzero_byte() {
        let result = decode_infinint(&[0x05]).unwrap();
        assert_eq!(result, (5u64, 1));
    }

    #[test]
    fn test_one_zero_prefix() {
        let result = decode_infinint(&[0x00, 0x05]).unwrap();
        assert_eq!(result, (5u64, 2));
    }

    #[test]
    fn test_two_zero_prefix() {
        let result = decode_infinint(&[0x00, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(result, (256u64, 4));
    }

    #[test]
    fn test_zero_value() {
        let result = decode_infinint(&[0x00, 0x00]).unwrap();
        assert_eq!(result, (0u64, 2));
    }

    #[test]
    fn test_truncated_error() {
        assert!(decode_infinint(&[0x00, 0x00, 0x01]).is_err());
    }
}
