/// Find the byte offset of the first `zzzzz` (five 0x7a bytes) in `data`.
pub fn find_zzzzz(data: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = &[0x7a, 0x7a, 0x7a, 0x7a, 0x7a];
    data.windows(5).position(|w| w == MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finds_marker() {
        let data = b"\x00\x01\x7a\x7a\x7a\x7a\x7a\xff";
        assert_eq!(find_zzzzz(data), Some(2));
    }

    #[test]
    fn test_absent() {
        assert_eq!(find_zzzzz(b"\x00\x01\x02"), None);
    }

    #[test]
    fn test_at_start() {
        let data = b"\x7a\x7a\x7a\x7a\x7a\x00";
        assert_eq!(find_zzzzz(data), Some(0));
    }
}
