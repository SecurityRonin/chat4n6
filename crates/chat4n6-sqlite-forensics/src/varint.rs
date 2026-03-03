/// Read a SQLite variable-length integer from `data` at `offset`.
/// SQLite varint: up to 9 bytes. Bytes 1-8 use 7 bits (MSB=1 means continue).
/// Byte 9 (if reached) uses all 8 bits.
/// Returns (value, bytes_consumed).
pub fn read_varint(data: &[u8], offset: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut i = offset;
    for n in 0..9 {
        let b = data[i];
        i += 1;
        if n == 8 {
            result = (result << 8) | b as u64;
            return (result, 9);
        }
        result = (result << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return (result, i - offset);
        }
    }
    unreachable!()
}

/// Decode a varint walking backwards from `offset` (exclusive).
/// Used to recover ROWIDs in freelist/carved records.
/// Returns (value, start_offset) or None if no valid varint found.
pub fn read_varint_reverse(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let max_len = std::cmp::min(9, offset);
    for len in 1..=max_len {
        let start = offset - len;
        // Last byte of a varint must have MSB=0
        if data[offset - 1] & 0x80 != 0 {
            continue;
        }
        // All prior bytes (if any) must have MSB=1 (continuation)
        let all_continuation = (start..offset - 1).all(|i| data[i] & 0x80 != 0);
        if !all_continuation && len > 1 {
            continue;
        }
        let (val, consumed) = read_varint(data, start);
        if consumed == len {
            return Some((val, start));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_single_byte() {
        assert_eq!(read_varint(&[0x07], 0), (7, 1));
    }

    #[test]
    fn test_varint_two_bytes() {
        // 0x81 0x01 = 129
        assert_eq!(read_varint(&[0x81, 0x01], 0), (129, 2));
    }

    #[test]
    fn test_varint_max_9bytes() {
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let (val, len) = read_varint(&bytes, 0);
        assert_eq!(len, 9);
        assert!(val > 0);
    }
}
