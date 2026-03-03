/// Read a SQLite variable-length integer from `data` at `offset`.
/// SQLite varint: up to 9 bytes. Bytes 1-8 use 7 data bits (MSB=1 means continue).
/// Byte 9 (if reached) uses all 8 bits — including the MSB.
/// Returns `Some((value, bytes_consumed))` or `None` if data is truncated.
pub fn read_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut i = offset;
    for n in 0..9 {
        let b = *data.get(i)?;
        i += 1;
        if n == 8 {
            // 9th byte: all 8 bits are data, no continuation flag.
            result = (result << 8) | b as u64;
            return Some((result, 9));
        }
        result = (result << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return Some((result, i - offset));
        }
    }
    unreachable!()
}

/// Decode a varint walking backwards from `offset` (exclusive).
/// Used to recover ROWIDs in freelist/carved records by probing backwards
/// from a known record header start position.
/// Returns `Some((value, start_offset))` or `None` if no valid varint found.
pub fn read_varint_reverse(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let max_len = std::cmp::min(9, offset);
    for len in 1..=max_len {
        let start = offset - len;
        // For varints of length < 9, the terminal byte (data[offset-1]) must have
        // MSB=0 (the continuation bit is clear). For a 9-byte varint, the last byte
        // uses all 8 bits and may have MSB=1.
        if len < 9 && data[offset - 1] & 0x80 != 0 {
            continue;
        }
        // All bytes before the terminal byte must have MSB=1 (continuation set).
        let all_continuation = (start..offset - 1).all(|i| data[i] & 0x80 != 0);
        if !all_continuation && len > 1 {
            continue;
        }
        let (val, consumed) = read_varint(data, start)?;
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
        assert_eq!(read_varint(&[0x07], 0), Some((7, 1)));
    }

    #[test]
    fn test_varint_two_bytes() {
        // 0x81 0x01 = 129
        assert_eq!(read_varint(&[0x81, 0x01], 0), Some((129, 2)));
    }

    #[test]
    fn test_varint_max_9bytes() {
        // 8x 0xff (7 bits each) + 0x7f (8 bits) = 0xFFFF_FFFF_FFFF_FF7F
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert_eq!(read_varint(&bytes, 0), Some((0xFFFF_FFFF_FFFF_FF7Fu64, 9)));
    }

    #[test]
    fn test_varint_9bytes_high_msb() {
        // 9-byte varint where last byte has MSB=1 (all bits data in byte 9)
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let result = read_varint(&bytes, 0);
        assert_eq!(result, Some((0xFFFF_FFFF_FFFF_FFFFu64, 9)));
    }

    #[test]
    fn test_varint_truncated_returns_none() {
        // Two-byte varint but only one byte available
        assert_eq!(read_varint(&[0x81], 0), None);
    }

    #[test]
    fn test_varint_at_offset() {
        // Read varint starting at offset 1
        assert_eq!(read_varint(&[0x00, 0x07], 1), Some((7, 1)));
    }

    #[test]
    fn test_varint_reverse_single_byte() {
        // [0x07] at data[0]; reverse from offset=1
        assert_eq!(read_varint_reverse(&[0x07], 1), Some((7, 0)));
    }

    #[test]
    fn test_varint_reverse_prefers_shorter_match() {
        // [0x81, 0x01]: the terminal byte 0x01 (MSB=0) is itself a valid 1-byte
        // varint (value=1). The reverse scan returns the shortest valid match first,
        // so value=1 at position 1 is found before the 2-byte value=129 at position 0.
        assert_eq!(read_varint_reverse(&[0x81, 0x01], 2), Some((1, 1)));
    }

    #[test]
    fn test_varint_reverse_skips_continuation_terminal() {
        // [0x81, 0x81]: last byte 0x81 has MSB=1 → not a valid terminal for a
        // 1-8 byte varint. Only the 9-byte path could match, but data is only
        // 2 bytes long. Returns None.
        assert_eq!(read_varint_reverse(&[0x81, 0x81], 2), None);
    }

    #[test]
    fn test_varint_reverse_9byte_high_msb() {
        // 9-byte varint with last byte having MSB=1; reverse from offset=9
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let result = read_varint_reverse(&bytes, 9);
        assert_eq!(result, Some((0xFFFF_FFFF_FFFF_FFFFu64, 0)));
    }

    #[test]
    fn test_varint_reverse_none_when_no_valid_varint() {
        // Continuation byte at end — cannot be a valid 1-byte varint terminus
        // And there's only 1 byte, so no room for multi-byte. Returns None.
        assert_eq!(read_varint_reverse(&[0x81], 1), None);
    }
}
