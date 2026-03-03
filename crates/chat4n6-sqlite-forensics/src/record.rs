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
pub fn decode_serial_type(serial_type: u64, data: &[u8], offset: usize) -> Option<(SqlValue, usize)> {
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
            let v = if v & (1i64 << 47) != 0 { v | !0xFFFFFFFFFFFFi64 } else { v };
            Some((SqlValue::Int(v), 6))
        }
        6 => {
            let bytes = data.get(offset..offset + 8)?;
            let v = i64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3],
                                        bytes[4], bytes[5], bytes[6], bytes[7]]);
            Some((SqlValue::Int(v), 8))
        }
        7 => {
            let bytes = data.get(offset..offset + 8)?;
            let v = f64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3],
                                        bytes[4], bytes[5], bytes[6], bytes[7]]);
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
