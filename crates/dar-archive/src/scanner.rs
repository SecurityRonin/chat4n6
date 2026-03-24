/// Find the byte offset of the catalog start in `data`.
///
/// Tries two strategies, searching only the last 200 MB for performance:
///   1. libdar escape marker `AD FD EA 77 21 00 43` — catalog bytes start
///      immediately after the 7-byte marker.
///   2. Root directory pattern `64 72 6f 6f 74 00` (`droot\0`) — catalog
///      bytes start at the `d` sig byte.
///
/// Returns the absolute offset into `data` where the catalog begins, or
/// `None` if neither pattern is found.
pub fn find_catalog_start(data: &[u8]) -> Option<usize> {
    const SEARCH_WINDOW: usize = 200 * 1024 * 1024;
    const ESCAPE_CATALOG: &[u8] = &[0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x00, b'C'];
    const ROOT_PATTERN: &[u8] = b"\x64root\x00";

    let search_start = data.len().saturating_sub(SEARCH_WINDOW);
    let tail = &data[search_start..];

    // Strategy 1: libdar escape marker (standard libdar archives).
    if let Some(rel) = tail
        .windows(ESCAPE_CATALOG.len())
        .position(|w| w == ESCAPE_CATALOG)
    {
        return Some(search_start + rel + ESCAPE_CATALOG.len());
    }

    // Strategy 2: root directory name pattern (Passware and similar tools).
    if let Some(rel) = tail
        .windows(ROOT_PATTERN.len())
        .position(|w| w == ROOT_PATTERN)
    {
        return Some(search_start + rel);
    }

    None
}

/// Find the byte offset of the *last* `zzzzz` (five 0x7A bytes) in `data`,
/// searching only the last 100 MB.
///
/// The catalog is located *before* this marker; everything after it is the
/// slice footer (≤ ~100 bytes).
pub fn find_last_zzzzz(data: &[u8]) -> Option<usize> {
    const SEARCH_WINDOW: usize = 100 * 1024 * 1024;
    const MARKER: &[u8] = &[0x7A, 0x7A, 0x7A, 0x7A, 0x7A];

    let search_start = data.len().saturating_sub(SEARCH_WINDOW);
    let tail = &data[search_start..];
    tail.windows(5)
        .rposition(|w| w == MARKER)
        .map(|rel| search_start + rel)
}

/// Legacy: find the byte offset of the *first* `zzzzz` in `data`.
/// Kept for backward compatibility; prefer `find_last_zzzzz` for catalogs.
pub fn find_zzzzz(data: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = &[0x7a, 0x7a, 0x7a, 0x7a, 0x7a];
    data.windows(5).position(|w| w == MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_zzzzz_first() {
        let data = b"\x00\x01\x7a\x7a\x7a\x7a\x7a\xff";
        assert_eq!(find_zzzzz(data), Some(2));
    }

    #[test]
    fn test_find_zzzzz_absent() {
        assert_eq!(find_zzzzz(b"\x00\x01\x02"), None);
    }

    #[test]
    fn test_find_last_zzzzz() {
        // Two zzzzz runs — should find the second (later) one.
        let mut data = vec![0u8; 20];
        data[2..7].copy_from_slice(&[0x7A; 5]);   // first  at offset 2
        data[12..17].copy_from_slice(&[0x7A; 5]); // second at offset 12
        assert_eq!(find_last_zzzzz(&data), Some(12));
    }

    #[test]
    fn test_find_catalog_start_escape() {
        let mut data = vec![0u8; 100];
        let marker = [0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x00, b'C'];
        data[10..17].copy_from_slice(&marker);
        // catalog bytes start at 17
        assert_eq!(find_catalog_start(&data), Some(17));
    }

    #[test]
    fn test_find_catalog_start_root_pattern() {
        let mut data = vec![0u8; 100];
        let pattern = b"\x64root\x00";
        data[20..26].copy_from_slice(pattern);
        // catalog bytes start at 20 (the 'd' sig byte)
        assert_eq!(find_catalog_start(&data), Some(20));
    }
}
