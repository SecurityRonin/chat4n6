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
}
