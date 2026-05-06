use chat4n6_plugin_api::EvidenceSource;

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RecoveredRecord {
    pub table: String,
    pub row_id: Option<i64>,
    pub values: Vec<SqlValue>,
    pub source: EvidenceSource,
    pub offset: u64,
    /// Confidence in the recovery (1.0 = certain for live records).
    pub confidence: f32,
}

/// Decode a SQLite serial type into a value, consuming bytes from `data` at `offset`.
/// Returns (SqlValue, bytes_consumed) or None on truncation.
pub fn decode_serial_type(
    serial_type: u64,
    data: &[u8],
    offset: usize,
) -> Option<(SqlValue, usize)> {
    match serial_type {
        0 => Some((SqlValue::Null, 0)),
        1 => {
            let b = *data.get(offset)?;
            Some((SqlValue::Int(b as i8 as i64), 1))
        }
        2 => {
            let bytes = data.get(offset..offset + 2)?;
            let v = i16::from_be_bytes([bytes[0], bytes[1]]) as i64;
            Some((SqlValue::Int(v), 2))
        }
        3 => {
            let bytes = data.get(offset..offset + 3)?;
            let v = ((bytes[0] as i32) << 16 | (bytes[1] as i32) << 8 | bytes[2] as i32) as i64;
            // Sign-extend from 24 bits
            let v = if v & 0x800000 != 0 { v | !0xFFFFFF } else { v };
            Some((SqlValue::Int(v), 3))
        }
        4 => {
            let bytes = data.get(offset..offset + 4)?;
            let v = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
            Some((SqlValue::Int(v), 4))
        }
        5 => {
            let bytes = data.get(offset..offset + 6)?;
            let v = (bytes[0] as i64) << 40
                | (bytes[1] as i64) << 32
                | (bytes[2] as i64) << 24
                | (bytes[3] as i64) << 16
                | (bytes[4] as i64) << 8
                | bytes[5] as i64;
            // Sign-extend from 48 bits
            let v = if v & (1i64 << 47) != 0 {
                v | !0xFFFFFFFFFFFFi64
            } else {
                v
            };
            Some((SqlValue::Int(v), 6))
        }
        6 => {
            let bytes = data.get(offset..offset + 8)?;
            let v = i64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            Some((SqlValue::Int(v), 8))
        }
        7 => {
            let bytes = data.get(offset..offset + 8)?;
            let v = f64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            Some((SqlValue::Real(v), 8))
        }
        8 => Some((SqlValue::Int(0), 0)),
        9 => Some((SqlValue::Int(1), 0)),
        n if n >= 12 && n % 2 == 0 => {
            let len = ((n - 12) / 2) as usize;
            let bytes = data.get(offset..offset + len)?;
            Some((SqlValue::Blob(bytes.to_vec()), len))
        }
        n if n >= 13 && n % 2 == 1 => {
            let len = ((n - 13) / 2) as usize;
            let bytes = data.get(offset..offset + len)?;
            let text = String::from_utf8_lossy(bytes).into_owned();
            Some((SqlValue::Text(text), len))
        }
        _ => None,
    }
}

impl RecoveredRecord {
    pub fn int_val(&self, idx: usize) -> Option<i64> {
        match self.values.get(idx) {
            Some(SqlValue::Int(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn int_val_or(&self, idx: usize, default: i64) -> i64 {
        self.int_val(idx).unwrap_or(default)
    }

    pub fn text_val(&self, idx: usize) -> Option<String> {
        match self.values.get(idx) {
            Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    pub fn real_val(&self, idx: usize) -> Option<f64> {
        match self.values.get(idx) {
            Some(SqlValue::Real(f)) => Some(*f),
            _ => None,
        }
    }

    pub fn require_row_id(&self) -> Option<i64> {
        self.row_id
    }
}

/// Groups `RecoveredRecord` references by their `table` name.
pub fn partition_by_table(records: &[RecoveredRecord]) -> std::collections::HashMap<String, Vec<&RecoveredRecord>> {
    let mut map: std::collections::HashMap<String, Vec<&RecoveredRecord>> = std::collections::HashMap::new();
    for r in records {
        map.entry(r.table.clone()).or_default().push(r);
    }
    map
}

/// Reads the SQLite schema version from the user_version pragma field (bytes 60–63, big-endian).
pub fn read_schema_version(db_bytes: &[u8]) -> u32 {
    if db_bytes.len() >= 64 {
        u32::from_be_bytes([db_bytes[60], db_bytes[61], db_bytes[62], db_bytes[63]])
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::EvidenceSource;

    // -----------------------------------------------------------------------
    // SqlValue: equality, clone, debug
    // -----------------------------------------------------------------------

    #[test]
    fn sql_value_null_eq() {
        assert_eq!(SqlValue::Null, SqlValue::Null);
    }

    #[test]
    fn sql_value_int_eq() {
        assert_eq!(SqlValue::Int(42), SqlValue::Int(42));
        assert_ne!(SqlValue::Int(1), SqlValue::Int(2));
    }

    #[test]
    fn sql_value_real_eq() {
        assert_eq!(SqlValue::Real(3.14), SqlValue::Real(3.14));
        assert_ne!(SqlValue::Real(1.0), SqlValue::Real(2.0));
    }

    #[test]
    fn sql_value_text_eq() {
        assert_eq!(SqlValue::Text("hello".into()), SqlValue::Text("hello".into()));
        assert_ne!(SqlValue::Text("a".into()), SqlValue::Text("b".into()));
    }

    #[test]
    fn sql_value_blob_eq() {
        assert_eq!(SqlValue::Blob(vec![1, 2, 3]), SqlValue::Blob(vec![1, 2, 3]));
        assert_ne!(SqlValue::Blob(vec![1]), SqlValue::Blob(vec![2]));
    }

    #[test]
    fn sql_value_clone() {
        let orig = SqlValue::Text("forensics".into());
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn sql_value_debug() {
        // Just ensure Debug doesn't panic
        let _ = format!("{:?}", SqlValue::Null);
        let _ = format!("{:?}", SqlValue::Int(-1));
        let _ = format!("{:?}", SqlValue::Real(0.0));
        let _ = format!("{:?}", SqlValue::Text("t".into()));
        let _ = format!("{:?}", SqlValue::Blob(vec![0xDE, 0xAD]));
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: serial type 0 — NULL
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_0_null() {
        let (val, consumed) = decode_serial_type(0, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Null);
        assert_eq!(consumed, 0);
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: serial types 1-6 — integers
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_1_int8_positive() {
        let (val, consumed) = decode_serial_type(1, &[0x7F], 0).unwrap();
        assert_eq!(val, SqlValue::Int(127));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_1_int8_negative() {
        // 0x80 as i8 = -128
        let (val, consumed) = decode_serial_type(1, &[0x80], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-128));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_1_int8_with_offset() {
        // byte at offset 2 is 0x05
        let (val, consumed) = decode_serial_type(1, &[0x00, 0x00, 0x05], 2).unwrap();
        assert_eq!(val, SqlValue::Int(5));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_1_truncated() {
        assert!(decode_serial_type(1, &[], 0).is_none());
    }

    #[test]
    fn serial_type_2_int16_positive() {
        let (val, consumed) = decode_serial_type(2, &[0x01, 0x00], 0).unwrap();
        assert_eq!(val, SqlValue::Int(256));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn serial_type_2_int16_negative() {
        // 0xFF 0xFF = -1 as i16
        let (val, consumed) = decode_serial_type(2, &[0xFF, 0xFF], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn serial_type_2_truncated() {
        assert!(decode_serial_type(2, &[0x01], 0).is_none());
    }

    #[test]
    fn serial_type_3_int24_positive() {
        // 0x00 0x01 0x00 = 256
        let (val, consumed) = decode_serial_type(3, &[0x00, 0x01, 0x00], 0).unwrap();
        assert_eq!(val, SqlValue::Int(256));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn serial_type_3_int24_negative() {
        // 0xFF 0xFF 0xFF = -1 (sign-extended from 24 bits)
        let (val, consumed) = decode_serial_type(3, &[0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn serial_type_3_int24_min() {
        // 0x80 0x00 0x00 = -8388608
        let (val, consumed) = decode_serial_type(3, &[0x80, 0x00, 0x00], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-8_388_608));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn serial_type_3_truncated() {
        assert!(decode_serial_type(3, &[0x00, 0x01], 0).is_none());
    }

    #[test]
    fn serial_type_4_int32_positive() {
        let (val, consumed) = decode_serial_type(4, &[0x00, 0x00, 0x01, 0x00], 0).unwrap();
        assert_eq!(val, SqlValue::Int(256));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn serial_type_4_int32_negative() {
        let (val, consumed) = decode_serial_type(4, &[0xFF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn serial_type_4_truncated() {
        assert!(decode_serial_type(4, &[0x00, 0x00, 0x00], 0).is_none());
    }

    #[test]
    fn serial_type_5_int48_positive() {
        let (val, consumed) =
            decode_serial_type(5, &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00], 0).unwrap();
        assert_eq!(val, SqlValue::Int(256));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn serial_type_5_int48_negative() {
        // all 0xFF = -1 (sign-extended from 48 bits)
        let (val, consumed) =
            decode_serial_type(5, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn serial_type_5_truncated() {
        assert!(decode_serial_type(5, &[0x00, 0x00, 0x00, 0x00, 0x01], 0).is_none());
    }

    #[test]
    fn serial_type_6_int64_max() {
        let bytes = i64::MAX.to_be_bytes();
        let (val, consumed) = decode_serial_type(6, &bytes, 0).unwrap();
        assert_eq!(val, SqlValue::Int(i64::MAX));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_6_int64_min() {
        let bytes = i64::MIN.to_be_bytes();
        let (val, consumed) = decode_serial_type(6, &bytes, 0).unwrap();
        assert_eq!(val, SqlValue::Int(i64::MIN));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_6_int64_neg_one() {
        let (val, consumed) =
            decode_serial_type(6, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_6_truncated() {
        assert!(decode_serial_type(6, &[0x00; 7], 0).is_none());
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: serial type 7 — float64
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_7_float64_pi() {
        let bytes = std::f64::consts::PI.to_be_bytes();
        let (val, consumed) = decode_serial_type(7, &bytes, 0).unwrap();
        assert_eq!(val, SqlValue::Real(std::f64::consts::PI));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_7_float64_zero() {
        let (val, consumed) = decode_serial_type(7, &[0x00; 8], 0).unwrap();
        assert_eq!(val, SqlValue::Real(0.0));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_7_float64_negative() {
        let bytes = (-1.5f64).to_be_bytes();
        let (val, consumed) = decode_serial_type(7, &bytes, 0).unwrap();
        assert_eq!(val, SqlValue::Real(-1.5));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn serial_type_7_truncated() {
        assert!(decode_serial_type(7, &[0x00; 7], 0).is_none());
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: serial types 8 & 9 — integer constants
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_8_const_zero() {
        let (val, consumed) = decode_serial_type(8, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Int(0));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn serial_type_9_const_one() {
        let (val, consumed) = decode_serial_type(9, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Int(1));
        assert_eq!(consumed, 0);
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: serial types 10, 11 — reserved/invalid
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_10_invalid() {
        assert!(decode_serial_type(10, &[0x00; 8], 0).is_none());
    }

    #[test]
    fn serial_type_11_invalid() {
        assert!(decode_serial_type(11, &[0x00; 8], 0).is_none());
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: blob (>=12, even)
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_12_blob_empty() {
        // serial_type=12 => len=(12-12)/2=0 => empty blob
        let (val, consumed) = decode_serial_type(12, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![]));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn serial_type_14_blob_one_byte() {
        // serial_type=14 => len=(14-12)/2=1
        let (val, consumed) = decode_serial_type(14, &[0xAB], 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![0xAB]));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_16_blob_two_bytes() {
        // serial_type=16 => len=(16-12)/2=2
        let (val, consumed) = decode_serial_type(16, &[0xDE, 0xAD], 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![0xDE, 0xAD]));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn serial_type_blob_with_offset() {
        // serial_type=14 => len=1; data has padding before offset
        let data = &[0x00, 0x00, 0xBE, 0xEF];
        let (val, consumed) = decode_serial_type(14, data, 2).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![0xBE]));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_blob_truncated() {
        // serial_type=16 => needs 2 bytes, only 1 available
        assert!(decode_serial_type(16, &[0xAB], 0).is_none());
    }

    // -----------------------------------------------------------------------
    // decode_serial_type: text (>=13, odd)
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_13_text_empty() {
        // serial_type=13 => len=(13-13)/2=0 => empty string
        let (val, consumed) = decode_serial_type(13, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Text("".into()));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn serial_type_15_text_one_char() {
        // serial_type=15 => len=(15-13)/2=1
        let (val, consumed) = decode_serial_type(15, b"A", 0).unwrap();
        assert_eq!(val, SqlValue::Text("A".into()));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_17_text_two_chars() {
        // serial_type=17 => len=(17-13)/2=2
        let (val, consumed) = decode_serial_type(17, b"hi", 0).unwrap();
        assert_eq!(val, SqlValue::Text("hi".into()));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn serial_type_text_with_offset() {
        // serial_type=15 => len=1; read at offset 3
        let data = b"xxxY";
        let (val, consumed) = decode_serial_type(15, data, 3).unwrap();
        assert_eq!(val, SqlValue::Text("Y".into()));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_text_truncated() {
        // serial_type=17 => needs 2 bytes, only 1 available
        assert!(decode_serial_type(17, b"X", 0).is_none());
    }

    #[test]
    fn serial_type_text_invalid_utf8_replaced() {
        // Invalid UTF-8 is replaced via from_utf8_lossy
        // serial_type=15 => len=1
        let (val, _) = decode_serial_type(15, &[0xFF], 0).unwrap();
        // Should not panic; replacement char used
        if let SqlValue::Text(s) = val {
            assert!(s.contains('\u{FFFD}'));
        } else {
            panic!("expected SqlValue::Text");
        }
    }

    // -----------------------------------------------------------------------
    // RecoveredRecord: construction and field access
    // -----------------------------------------------------------------------

    fn make_record() -> RecoveredRecord {
        RecoveredRecord {
            table: "messages".into(),
            row_id: Some(42),
            values: vec![
                SqlValue::Int(1),
                SqlValue::Text("hello".into()),
                SqlValue::Null,
            ],
            source: EvidenceSource::Live,
            offset: 4096,
            confidence: 1.0,
        }
    }

    #[test]
    fn recovered_record_fields() {
        let rec = make_record();
        assert_eq!(rec.table, "messages");
        assert_eq!(rec.row_id, Some(42));
        assert_eq!(rec.values.len(), 3);
        assert_eq!(rec.source, EvidenceSource::Live);
        assert_eq!(rec.offset, 4096);
        assert!((rec.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn recovered_record_no_row_id() {
        let rec = RecoveredRecord {
            table: "orphan".into(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::CarvedUnalloc { confidence_pct: 75 },
            offset: 0,
            confidence: 0.75,
        };
        assert!(rec.row_id.is_none());
        assert_eq!(rec.values.len(), 0);
    }

    #[test]
    fn recovered_record_clone() {
        let rec = make_record();
        let cloned = rec.clone();
        assert_eq!(rec.table, cloned.table);
        assert_eq!(rec.row_id, cloned.row_id);
        assert_eq!(rec.values, cloned.values);
        assert_eq!(rec.offset, cloned.offset);
    }

    #[test]
    fn recovered_record_debug() {
        let rec = make_record();
        let s = format!("{:?}", rec);
        assert!(s.contains("messages"));
    }

    // -----------------------------------------------------------------------
    // Offset boundary: data large, read near the end
    // -----------------------------------------------------------------------

    #[test]
    fn serial_type_1_offset_at_last_byte() {
        let data = vec![0x00u8; 100];
        let mut d = data.clone();
        d[99] = 0x42;
        let (val, consumed) = decode_serial_type(1, &d, 99).unwrap();
        assert_eq!(val, SqlValue::Int(0x42));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn serial_type_1_offset_out_of_bounds() {
        let data = vec![0x00u8; 5];
        assert!(decode_serial_type(1, &data, 5).is_none());
    }
}
