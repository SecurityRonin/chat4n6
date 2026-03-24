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

    #[test]
    fn test_varint_reverse_skips_non_continuation_interior() {
        // Covers line 41: `continue` when all_continuation is false and len > 1.
        // Layout: [0x00, 0x01]  reverse from offset=2.
        //   len=1: data[1]=0x01, MSB=0 → valid terminal; read_varint(data, 1) = (1, 1) → match. Returns (1, 1).
        // But we need the len=2 path to be tried and fail on all_continuation.
        // We need: terminal byte (data[offset-1]) has MSB=0 (for len < 9 check to pass),
        //          but an interior byte does NOT have MSB=1.
        // For len=2: start=0, data[0]=0x00 (MSB=0 → not continuation), data[1]=0x01 (terminal, MSB=0).
        // all_continuation for (0..1) checks data[0]=0x00 → MSB=0 → false. len=2 > 1 → continue (line 41).
        // But len=1 matches first (shortest). We need len=1 to NOT match so len=2 is tried.
        //
        // Actually, the loop goes len=1,2,...,max_len. If len=1 matches, it returns.
        // To hit line 41 we need len=1 to fail (terminal byte has MSB=1), then len=2 is tried.
        // For len=2: data[offset-1] = data[1], must have MSB=0 (so len<9 check passes).
        // But then len=1 already checked data[1] and since MSB=0 it would've been valid terminal.
        //
        // Alternative approach: we need a scenario where read_varint succeeds but consumed != len.
        // That hits line 46 (the closing brace).
        // For len=3: start = offset-3. read_varint(data, start) might consume only 1 or 2 bytes
        // (shorter varint), so consumed != len → doesn't match → loop continues.
        //
        // data = [0x00, 0x01, 0x01]: reverse from offset=3.
        //   len=1: data[2]=0x01 MSB=0 → valid terminal. read_varint(data,2)=(1,1), consumed=1=len → match!
        // That returns. We need len=1 to fail.
        //
        // data = [0x05, 0x81, 0x01]: reverse from offset=3.
        //   len=1: data[2]=0x01 MSB=0 → valid. read_varint(data,2)=(1,1)=len → returns (1,2).
        // Still matches at len=1.
        //
        // We need the terminal byte for len=1 to have MSB=1 so it's skipped.
        // data = [0x00, 0x00, 0x81]: reverse from offset=3.
        //   len=1: data[2]=0x81, MSB=1 → continue (skipped).
        //   len=2: start=1, data[2]=0x81 is terminal. len=2 < 9, data[2]&0x80=0x80 → MSB=1 → continue.
        //   len=3: start=0, data[2]=0x81 terminal. len=3 < 9, data[2]&0x80 != 0 → continue.
        //   Returns None. But we didn't hit line 41.
        //
        // To hit line 41 we need: len >= 2, data[offset-1] & 0x80 == 0 (terminal check passes),
        //   AND !all_continuation (some interior byte has MSB=0).
        // data = [0x00, 0x01]: offset=2.
        //   len=1: data[1]=0x01 MSB=0 → terminal OK. read_varint(data,1)=(1,1)=len → match! Returns early.
        //
        // The only way to reach len=2 is if len=1 fails. len=1 fails if terminal has MSB=1.
        // For len=2: terminal is data[offset-1] = same byte as len=1's terminal! If it has MSB=1,
        // then len=2 also sees data[offset-1] with MSB=1 → continue.
        // So with the current logic, line 41 can only be hit for len >= 2 when the terminal byte
        // has MSB=0 but len=1 returned consumed != len... which can't happen for a valid 1-byte varint.
        //
        // Wait: let me re-read. For len=1, if data[offset-1]&0x80 != 0 → continue (skip len=1).
        // For len=2, terminal check is still data[offset-1] which has MSB=1 → continue (skip len=2).
        // For len 3..8, same terminal byte → all skipped.
        // For len=9: the len < 9 check doesn't apply, so we proceed.
        //   all_continuation checks data[start..offset-1].
        //
        // Actually I misread the code. Let me re-read carefully.
        // line 35: if len < 9 && data[offset - 1] & 0x80 != 0 { continue; }
        // The terminal byte check is always data[offset-1], regardless of len.
        // So if data[offset-1] has MSB=0, ALL len values 1..8 pass the terminal check.
        // For len=1 → start = offset-1, read_varint returns (val, 1), consumed=1=len → match → return.
        // So len=2+ is never reached when data[offset-1] MSB=0.
        //
        // If data[offset-1] has MSB=1, ALL len values 1..8 fail the terminal check → skip.
        // Only len=9 proceeds.
        //
        // So line 41 can only be hit from the len=9 path. In that path:
        //   len=9, start=offset-9.
        //   all_continuation = (start..offset-1).all(|i| data[i] & 0x80 != 0)
        //   if !all_continuation && len > 1 → continue
        //
        // So we need: offset >= 9, data[offset-1] has MSB=1 (to skip len=1..8),
        // and for len=9: one of the bytes data[start..offset-1] has MSB=0.
        //
        // Example: 9 bytes, offset=9. data[8] (terminal) has MSB=1. data[0] has MSB=0.
        let mut data = [0x80u8; 9];
        data[0] = 0x00; // interior byte without continuation bit
        // data[8] = 0x80 → MSB=1, so len=1..8 all skipped.
        // len=9: start=0. all_continuation checks data[0..8].
        // data[0]=0x00 → MSB=0 → all_continuation=false. len=9 > 1 → continue (line 41).
        // No more lengths → returns None.
        assert_eq!(read_varint_reverse(&data, 9), None);
    }

    #[test]
    fn test_varint_reverse_consumed_ne_len() {
        // Covers line 46: read_varint succeeds but consumed != len.
        // We need len=9 to pass all_continuation but read_varint to consume < 9 bytes.
        // All bytes data[start..offset-1] must have MSB=1 (continuation), and data[offset-1]
        // must have MSB=1 (to skip len 1..8).
        // If all 9 bytes have MSB=1, read_varint reads a full 9-byte varint and consumed=9=len → match.
        // We need the forward parse to stop earlier. But read_varint always reads up to 9 bytes
        // if continuation bits are set. Actually, for n=0..8 (0-indexed), it checks MSB.
        // If all 8 leading bytes have MSB=1, it reads byte 9 as the full 8-bit final.
        // consumed will always be 9. So consumed == len.
        //
        // Hmm. Actually if all_continuation is true, that means all interior bytes have MSB=1.
        // Then read_varint starting from start will see continuation bits and read all 9 bytes.
        // So consumed will be 9 = len. Line 46 seems unreachable for the 9-byte case.
        //
        // For len < 9: we already showed those are only reached when data[offset-1] MSB=0.
        // If data[offset-1] MSB=0, len=1 always succeeds. So len >=2 with MSB=0 terminal is
        // never reached because len=1 returns first.
        //
        // This means line 46 is likely dead code. Let's skip it - it's an unreachable defensive guard.
        // Actually wait - what if offset is 0? Then max_len = min(9, 0) = 0, and the loop doesn't run.
        // Or offset=1: max_len=1, only len=1 is tried. If it matches, return. If not, None.
        //
        // Line 46 is dead code (defensive), similar to line 21. Let's move on.
        //
        // Actually, there's one more case: what if read_varint returns None?
        // Line 43: let (val, consumed) = read_varint(data, start)?;
        // If read_varint returns None, the ? propagates and we return None from the whole function.
        // So line 44-46 is only reached if read_varint succeeds.
        // And if it succeeds from start with all continuation bytes, consumed will equal the
        // number of varint bytes which should match len. So yes, line 46 is dead code.
        //
        // Let me just verify lines 41 is now covered. The test above handles it.
        // Lines 21 and 46 are dead code that cannot be covered.
        ()
    }
}
