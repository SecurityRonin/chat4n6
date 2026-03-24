use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::varint::read_varint;
use chat4n6_plugin_api::EvidenceSource;

#[derive(Debug, Clone, PartialEq)]
pub enum CarveMode {
    /// Full SQLite record header intact (header_len + serial types + values).
    Normal,
    /// Header length byte is absent; data starts directly with serial type bytes.
    ColumnsOnly,
    /// First 4 bytes are overwritten by the freeblock's [next:u16][size:u16] pointer.
    /// Recovery starts from byte 4; the first column is represented as Null.
    FirstColMissing,
}

pub struct CarveMatch {
    pub offset: usize,
    pub mode: CarveMode,
    pub record: RecoveredRecord,
}

/// Attempt to carve records from freeblock data using 3-mode matching.
///
/// Normal mode is tried in a stacked loop (multiple records packed end-to-end,
/// loops while remaining_bytes >= 3). When Normal finds nothing, both ColumnsOnly
/// and FirstColMissing are tried from the buffer start and all results returned.
pub fn carve_freeblock(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Vec<CarveMatch> {
    let mut matches = Vec::new();

    if data.is_empty() {
        return matches;
    }

    // Stacked Normal mode loop: minimum viable record is 3 bytes
    let mut pos = 0;
    while pos + 3 <= data.len() {
        match try_carve_normal(&data[pos..], abs_offset + pos, table, expected_col_count) {
            Some((m, consumed)) if consumed > 0 => {
                pos += consumed;
                matches.push(m);
            }
            _ => break,
        }
    }

    // Fallback: try ColumnsOnly and FirstColMissing when Normal found nothing
    if matches.is_empty() {
        if let Some(m) = try_carve_columns_only(data, abs_offset, table, expected_col_count) {
            matches.push(m);
        }
        if let Some(m) = try_carve_first_col_missing(data, abs_offset, table, expected_col_count) {
            matches.push(m);
        }
    }

    matches
}

/// Returns `(CarveMatch, bytes_consumed)` to support advancing the stacked-record loop.
fn try_carve_normal(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Option<(CarveMatch, usize)> {
    let (header_len, hl_consumed) = read_varint(data, 0)?;
    let header_end = header_len as usize;
    // header_end includes the header_len varint itself; must not exceed data and must
    // be at least as large as the bytes consumed decoding the header_len varint.
    if header_end > data.len() || header_end < hl_consumed {
        return None;
    }

    let mut pos = hl_consumed;
    let mut serial_types = Vec::new();
    while pos < header_end && pos < data.len() {
        let (st, consumed) = read_varint(data, pos)?;
        serial_types.push(st);
        pos += consumed;
        if serial_types.len() >= expected_col_count {
            break;
        }
    }

    if serial_types.is_empty() {
        return None;
    }

    let mut values = Vec::new();
    let mut data_pos = header_end;
    for &st in &serial_types {
        match decode_serial_type(st, data, data_pos) {
            Some((val, consumed)) => {
                data_pos += consumed;
                values.push(val);
            }
            None => values.push(SqlValue::Null),
        }
    }

    let consumed = data_pos;
    Some((
        CarveMatch {
            offset: abs_offset,
            mode: CarveMode::Normal,
            record: RecoveredRecord {
                table: table.to_string(),
                row_id: None,
                values,
                source: EvidenceSource::Freelist,
                offset: abs_offset as u64,
                confidence: 0.8,
            },
        },
        consumed,
    ))
}

fn try_carve_columns_only(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Option<CarveMatch> {
    // No header_len prefix: interpret data directly as serial type bytes followed by values.
    let mut pos = 0;
    let mut serial_types = Vec::new();
    while pos < data.len() && serial_types.len() < expected_col_count {
        let (st, consumed) = read_varint(data, pos)?;
        serial_types.push(st);
        pos += consumed;
    }

    if serial_types.is_empty() {
        return None;
    }

    let mut values = Vec::new();
    let mut data_pos = pos;
    for &st in &serial_types {
        match decode_serial_type(st, data, data_pos) {
            Some((val, consumed)) => {
                data_pos += consumed;
                values.push(val);
            }
            None => values.push(SqlValue::Null),
        }
    }

    Some(CarveMatch {
        offset: abs_offset,
        mode: CarveMode::ColumnsOnly,
        record: RecoveredRecord {
            table: table.to_string(),
            row_id: None,
            values,
            source: EvidenceSource::Freelist,
            offset: abs_offset as u64,
            confidence: 0.5,
        },
    })
}

/// The freeblock's [next:u16][size:u16] header overwrites the first 4 bytes of the
/// former cell content. Skip those bytes, recover columns 2..N from byte 4 onwards,
/// and prepend a Null value for the destroyed first column.
pub(crate) fn try_carve_first_col_missing(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Option<CarveMatch> {
    if data.len() < 5 || expected_col_count < 2 {
        return None;
    }

    let start = 4; // skip overwritten bytes
    let col_count = expected_col_count - 1; // first column is lost
    let mut pos = start;
    let mut serial_types = Vec::new();
    while pos < data.len() && serial_types.len() < col_count {
        let (st, consumed) = read_varint(data, pos)?;
        serial_types.push(st);
        pos += consumed;
    }

    if serial_types.is_empty() {
        return None;
    }

    let mut values = Vec::new();
    let mut data_pos = pos;
    for &st in &serial_types {
        match decode_serial_type(st, data, data_pos) {
            Some((val, consumed)) => {
                data_pos += consumed;
                values.push(val);
            }
            None => values.push(SqlValue::Null),
        }
    }

    // Prepend Null for the destroyed first column
    let mut all_values = vec![SqlValue::Null];
    all_values.extend(values);

    Some(CarveMatch {
        offset: abs_offset,
        mode: CarveMode::FirstColMissing,
        record: RecoveredRecord {
            table: table.to_string(),
            row_id: None,
            values: all_values,
            source: EvidenceSource::Freelist,
            offset: abs_offset as u64,
            confidence: 0.3,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SqlValue;

    #[test]
    fn test_carve_freeblock_normal_mode() {
        // header_len=2 (includes itself), serial_type=1 (1-byte int), value=42
        let data: Vec<u8> = vec![
            0x02, // header_len = 2
            0x01, // serial type 1 = 1-byte signed int
            0x2a, // value = 42
        ];
        let matches = carve_freeblock(&data, 100, "test_table", 1);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].mode, CarveMode::Normal);
        assert!(matches[0].record.values.contains(&SqlValue::Int(42)));
        assert_eq!(matches[0].record.confidence, 0.8);
    }

    #[test]
    fn test_carve_empty_returns_empty() {
        let matches = carve_freeblock(&[], 0, "test_table", 2);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_carve_stacked_records() {
        // Two back-to-back Normal records: [header=2, st=1, val=1][header=2, st=1, val=2]
        let data: Vec<u8> = vec![
            0x02, 0x01, 0x01, // record 1: header_len=2, st=1, value=1
            0x02, 0x01, 0x02, // record 2: header_len=2, st=1, value=2
        ];
        let matches = carve_freeblock(&data, 0, "t", 1);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].mode, CarveMode::Normal);
        assert_eq!(matches[1].mode, CarveMode::Normal);
        assert!(matches[0].record.values.contains(&SqlValue::Int(1)));
        assert!(matches[1].record.values.contains(&SqlValue::Int(2)));
    }

    #[test]
    fn test_carve_columns_only_mode() {
        // data[0]=0x10=16 → Normal: header_end=16 > data.len()=3 → fails.
        // ColumnsOnly: st=16 (BLOB 2 bytes, serial type = even ≥ 12, size=(16-12)/2=2),
        // data[1..3] = [0x41, 0x42] → Blob([0x41, 0x42]).
        let data = vec![0x10u8, 0x41, 0x42];
        let matches = carve_freeblock(&data, 0, "t", 1);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].mode, CarveMode::ColumnsOnly);
        assert_eq!(matches[0].record.confidence, 0.5);
    }

    #[test]
    fn test_carve_first_col_missing_direct() {
        // 4 overwritten bytes, then st=1 (1-byte int), val=99 (0x63)
        // expected_col_count=2: col0=Null (lost), col1=Int(99)
        let data = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0x01, 0x63];
        let result = try_carve_first_col_missing(&data, 0, "t", 2);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.mode, CarveMode::FirstColMissing);
        assert_eq!(m.record.values[0], SqlValue::Null);
        assert_eq!(m.record.values[1], SqlValue::Int(99));
        assert_eq!(m.record.confidence, 0.3);
    }

    #[test]
    fn test_carve_first_col_missing_requires_at_least_two_cols() {
        let data = vec![0xFFu8; 10];
        // expected_col_count=1 → None (need at least 2 to have a recoverable second col)
        assert!(try_carve_first_col_missing(&data, 0, "t", 1).is_none());
    }

    #[test]
    fn test_carve_freeblock_fallback_first_col_missing() {
        // Covers line 57: matches.push(m) for FirstColMissing in the fallback path.
        // Normal fails because header_len is huge (> data.len()), both ColumnsOnly and
        // FirstColMissing are tried. expected_col_count=2 so FirstColMissing can succeed.
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x63];
        let matches = carve_freeblock(&data, 0, "t", 2);
        assert!(matches.len() >= 1);
        let has_first_col_missing = matches.iter().any(|m| m.mode == CarveMode::FirstColMissing);
        assert!(has_first_col_missing);
    }

    #[test]
    fn test_carve_normal_truncated_value_falls_back_to_null() {
        // Covers line 102: None => values.push(SqlValue::Null) in try_carve_normal.
        // header_len=2, st=6 (8-byte int), but only 1 value byte follows → decode fails → Null.
        let data = vec![0x02, 0x06, 0x00];
        let matches = carve_freeblock(&data, 0, "t", 1);
        assert!(!matches.is_empty());
        assert!(matches[0].record.values.contains(&SqlValue::Null));
    }

    #[test]
    fn test_carve_normal_empty_serial_types_via_2byte_varint() {
        // Covers line 87 (end of serial types loop) and line 91 (empty serial_types return None).
        // header_len=2 encoded as a 2-byte varint (0x80, 0x02). hl_consumed=2, header_end=2.
        // Since pos(2) == header_end(2), the serial types loop doesn't execute → empty → None.
        // Normal fails, then fallbacks are tried. We just verify it doesn't panic.
        let data = vec![0x80, 0x02, 0x00, 0x00];
        let _matches = carve_freeblock(&data, 0, "t", 1);
        // Normal returns None due to empty serial_types (lines 87, 91 covered).
    }

    #[test]
    fn test_carve_columns_only_empty_serial_types_via_zero_cols() {
        // Covers line 140: ColumnsOnly with expected_col_count=0.
        // The while loop condition `serial_types.len() < 0` is always false → loop never enters
        // → serial_types is empty → return None (line 140).
        // Normal with expected_col_count=0: the serial types loop enters, pushes at least one,
        // then breaks (since 1 >= 0). So Normal succeeds. But we need Normal to fail first.
        // Use data where Normal's header_len is too large.
        // data = [0x10, 0x01, 0x2A] → header_len=16 > data.len()=3 → Normal fails.
        // ColumnsOnly: expected_col_count=0 → loop doesn't enter → empty → line 140 → None.
        // FirstColMissing: data.len() < 5 → None.
        let matches = carve_freeblock(&[0x10, 0x01, 0x2A], 0, "t", 0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_carve_columns_only_decode_null_fallback() {
        // Covers line 151: ColumnsOnly succeeds at reading serial types but decode fails.
        // Normal must fail first. Use data where header_len is large.
        // data = [0x10, 0x06]: Normal reads header_len=16 > data.len()=2 → None.
        // ColumnsOnly: st1 = read_varint(&data, 0) = (0x10=16, 1). expected_col_count=1 → done.
        // data_pos=1, decode_serial_type(16, data, 1): st=16 → blob len=(16-12)/2=2, need data[1..3],
        // but data.len()=2 → data[1..3] fails → None → push Null. Line 151 covered.
        // But data.len()=2, pos+3=3>2 so Normal loop never enters.
        // Actually need 3+ bytes for the while loop: data = [0x10, 0x06, 0x00].
        // Normal: header_len=16 > 3 → fails (header_end > data.len()).
        // Actually, Normal's while loop checks pos+3 <= data.len(). pos=0, 0+3=3<=3 → enters.
        // try_carve_normal: read_varint=16, header_end=16 > 3 → return None.
        // matches empty. ColumnsOnly: read_varint(0)=16, serial_types=[16], expected=1 → stop.
        // data_pos=1. decode(16, data, 1): blob len=2, data[1..3]=[0x06, 0x00] → Ok!
        // So it succeeds. That covers ColumnsOnly but not line 151.
        // Need decode to fail: st=6 (8-byte int), data has < 8 bytes after serial type area.
        // data = [0x10, 0x06, 0x00]: ColumnsOnly reads st=16, then at pos=1 reads st=6,
        // expected_col_count=2 → has 2 serial types. data_pos=2.
        // decode(16, data, 2): blob len=2, data[2..4]? data.len()=3, only 1 byte → None → Null (line 151!)
        let data = vec![0x10, 0x06, 0x00];
        let matches = carve_freeblock(&data, 0, "t", 2);
        // Should find ColumnsOnly match with at least one Null
        let co = matches.iter().find(|m| m.mode == CarveMode::ColumnsOnly);
        assert!(co.is_some());
        assert!(co.unwrap().record.values.contains(&SqlValue::Null));
    }

    #[test]
    fn test_carve_first_col_missing_empty_serial_types() {
        // Covers line 193: return None when serial_types is empty in FirstColMissing.
        // After 4 skip bytes, byte 4 is a truncated continuation varint → read_varint fails.
        let data = vec![0x00, 0x00, 0x00, 0x00, 0xFF];
        let result = try_carve_first_col_missing(&data, 0, "t", 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_carve_first_col_missing_truncated_value() {
        // Covers line 204: decode fails → push Null in FirstColMissing.
        // After 4 skip bytes: st=6 (8-byte int) but only 1 byte of value data.
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x06, 0x00];
        let result = try_carve_first_col_missing(&data, 0, "t", 2);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.record.values[0], SqlValue::Null); // destroyed first column
        assert_eq!(m.record.values[1], SqlValue::Null); // truncated decode
    }
}
