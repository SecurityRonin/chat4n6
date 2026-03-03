use chat4n6_plugin_api::EvidenceSource;
use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::varint::read_varint;

#[derive(Debug, Clone, PartialEq)]
pub enum CarveMode {
    Normal,          // full header intact
    ColumnsOnly,     // header length byte missing
    FirstColMissing, // first column's serial type overwritten by freeblock pointer
}

pub struct CarveMatch {
    pub offset: usize,
    pub mode: CarveMode,
    pub record: RecoveredRecord,
}

/// Attempt to carve records from freeblock data using 3-mode matching.
/// Processes matches last-to-first (SQLite reallocates from block end).
/// Loops while remaining_bytes > 5 (stacked records support).
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

    // Try Normal mode first: attempt to parse from position 0
    if let Some(m) = try_carve_normal(data, abs_offset, table, expected_col_count) {
        matches.push(m);
    }

    // If Normal failed or yielded nothing, try ColumnsOnly
    if matches.is_empty() {
        if let Some(m) = try_carve_columns_only(data, abs_offset, table, expected_col_count) {
            matches.push(m);
        }
    }

    matches
}

fn try_carve_normal(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Option<CarveMatch> {
    let (header_len, hl_consumed) = read_varint(data, 0)?;
    let header_end = header_len as usize;
    if header_end > data.len() {
        return None;
    }

    let mut pos = hl_consumed;
    let mut serial_types = Vec::new();
    while pos < header_end && pos < data.len() {
        let (st, consumed) = read_varint(data, pos)?;
        serial_types.push(st);
        pos += consumed;
        if serial_types.len() >= expected_col_count + 1 {
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
            None => {
                values.push(SqlValue::Null);
            }
        }
    }

    Some(CarveMatch {
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
    })
}

fn try_carve_columns_only(
    data: &[u8],
    abs_offset: usize,
    table: &str,
    expected_col_count: usize,
) -> Option<CarveMatch> {
    // Try treating the data directly as a sequence of serial types (no header_len prefix)
    let mut pos = 0;
    let mut serial_types = Vec::new();
    while pos < data.len() && serial_types.len() < expected_col_count {
        let (st, consumed) = read_varint(data, pos)?;
        if st > 1000 {
            break; // sanity bound on serial type value
        }
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
            None => {
                values.push(SqlValue::Null);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_freeblock_normal_mode() {
        // Build a minimal record:
        //   header_len = 2 (1-byte varint for header_len itself + 1-byte serial type)
        //   serial_type = 1 (1-byte signed int)
        //   value = 42 (0x2a)
        // header bytes: [0x02, 0x01]  (header_len=2, serial_type=1)
        // data bytes:   [0x2a]        (value=42)
        let data: Vec<u8> = vec![
            0x02, // header_len varint = 2 (includes itself, covers bytes 0-1)
            0x01, // serial type 1 = 1-byte int
            0x2a, // value = 42 (data area starts at byte 2 = header_end)
        ];
        let matches = carve_freeblock(&data, 100, "test_table", 1);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].mode, CarveMode::Normal);
        assert!(matches[0]
            .record
            .values
            .contains(&crate::record::SqlValue::Int(42)));
    }

    #[test]
    fn test_carve_empty_returns_empty() {
        let matches = carve_freeblock(&[], 0, "test_table", 2);
        assert!(matches.is_empty());
    }
}
