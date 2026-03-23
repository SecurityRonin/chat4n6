use crate::record::{decode_serial_type, SqlValue};
use crate::varint::read_varint;

/// Column type hint derived from CREATE TABLE SQL.
#[derive(Debug, Clone, PartialEq)]
pub enum ColumnTypeHint {
    Integer,
    Real,
    Text,
    Blob,
    Null,
    Any,
}

/// Schema signature for a single table, used for carving deleted records.
#[derive(Debug, Clone)]
pub struct SchemaSignature {
    pub table_name: String,
    pub column_count: usize,
    pub type_hints: Vec<ColumnTypeHint>,
}

/// A candidate carved record with confidence score.
#[derive(Debug)]
pub struct CarvedCandidate {
    pub row_id: Option<i64>,
    pub values: Vec<SqlValue>,
    pub byte_offset: usize,
    pub bytes_consumed: usize,
    pub confidence: f32,
}

impl SchemaSignature {
    /// Build from a CREATE TABLE SQL statement.
    pub fn from_create_sql(table_name: &str, sql: &str) -> Option<Self> {
        let open = sql.find('(')?;
        let close = sql.rfind(')')?;
        let cols_str = &sql[open + 1..close];

        let mut type_hints = Vec::new();
        for col_def in cols_str.split(',') {
            let col_def = col_def.trim();
            if col_def.is_empty() {
                continue;
            }
            let upper = col_def.to_uppercase();
            // Skip INTEGER PRIMARY KEY — it's the rowid alias
            if upper.contains("INTEGER") && upper.contains("PRIMARY") && upper.contains("KEY") {
                continue;
            }
            // Skip table constraints
            if upper.starts_with("PRIMARY")
                || upper.starts_with("UNIQUE")
                || upper.starts_with("CHECK")
                || upper.starts_with("FOREIGN")
                || upper.starts_with("CONSTRAINT")
            {
                continue;
            }
            let hint = Self::sql_type_to_hint(&upper);
            type_hints.push(hint);
        }

        Some(Self {
            table_name: table_name.to_string(),
            column_count: type_hints.len(),
            type_hints,
        })
    }

    fn sql_type_to_hint(col_def_upper: &str) -> ColumnTypeHint {
        let tokens: Vec<&str> = col_def_upper.split_whitespace().collect();
        let type_str = tokens.get(1).copied().unwrap_or("");
        if type_str.starts_with("INT") || type_str == "BOOLEAN" || type_str == "TINYINT"
            || type_str == "SMALLINT" || type_str == "BIGINT" || type_str == "MEDIUMINT"
        {
            ColumnTypeHint::Integer
        } else if type_str.starts_with("TEXT") || type_str.starts_with("CHAR")
            || type_str.starts_with("VARCHAR") || type_str == "CLOB"
            || type_str.starts_with("NCHAR") || type_str.starts_with("NVARCHAR")
        {
            ColumnTypeHint::Text
        } else if type_str.starts_with("REAL") || type_str.starts_with("FLOAT")
            || type_str.starts_with("DOUBLE") || type_str.starts_with("NUMERIC")
            || type_str.starts_with("DECIMAL")
        {
            ColumnTypeHint::Real
        } else if type_str.starts_with("BLOB") || type_str == "BINARY"
            || type_str == "VARBINARY"
        {
            ColumnTypeHint::Blob
        } else if type_str.is_empty() {
            ColumnTypeHint::Any
        } else {
            ColumnTypeHint::Any
        }
    }

    /// Check if a serial type is compatible with a column type hint.
    pub fn is_compatible(hint: &ColumnTypeHint, serial_type: u64) -> bool {
        match hint {
            ColumnTypeHint::Any => true,
            ColumnTypeHint::Null => serial_type == 0,
            ColumnTypeHint::Integer => matches!(serial_type, 0 | 1..=6 | 8 | 9),
            ColumnTypeHint::Real => matches!(serial_type, 0 | 7),
            ColumnTypeHint::Text => serial_type == 0 || (serial_type >= 13 && serial_type % 2 == 1),
            ColumnTypeHint::Blob => serial_type == 0 || (serial_type >= 12 && serial_type % 2 == 0),
        }
    }

    /// Attempt to parse a record at `offset` in `data` and validate against this schema.
    pub fn try_parse_record(&self, data: &[u8], offset: usize) -> Option<CarvedCandidate> {
        if offset >= data.len() {
            return None;
        }
        let buf = &data[offset..];
        // Read header length varint
        let (header_len, hl_size) = read_varint(buf, 0)?;
        let header_len = header_len as usize;
        if header_len < 2 || header_len > buf.len() || header_len > 512 {
            return None;
        }

        // Parse serial types from header
        let mut serial_types = Vec::new();
        let mut pos = hl_size;
        while pos < header_len {
            let (st, st_size) = read_varint(buf, pos)?;
            serial_types.push(st);
            pos += st_size;
        }

        // Column count check
        if serial_types.len() != self.column_count {
            return None;
        }

        // Type compatibility check
        let mut compat_count = 0usize;
        for (i, &st) in serial_types.iter().enumerate() {
            if Self::is_compatible(&self.type_hints[i], st) {
                compat_count += 1;
            }
        }
        if compat_count == 0 {
            return None;
        }

        // Parse values — IMPORTANT: use decode_serial_type(st, buf, val_pos) with 3 args
        let mut values = Vec::with_capacity(serial_types.len());
        let mut val_pos = header_len;
        for &st in &serial_types {
            if val_pos > buf.len() {
                return None;
            }
            let (val, consumed) = decode_serial_type(st, buf, val_pos)?;
            values.push(val);
            val_pos += consumed;
        }

        // Size sanity: total record shouldn't exceed a page (65536)
        if val_pos > 65536 {
            return None;
        }

        let confidence = compat_count as f32 / self.column_count as f32;

        Some(CarvedCandidate {
            row_id: None,
            values,
            byte_offset: offset,
            bytes_consumed: val_pos,
            confidence,
        })
    }

    /// Scan a region of bytes for records matching this schema.
    pub fn scan_region(&self, data: &[u8]) -> Vec<CarvedCandidate> {
        let mut candidates = Vec::new();
        let mut offset = 0;
        while offset < data.len().saturating_sub(2) {
            if let Some(mut c) = self.try_parse_record(data, offset) {
                c.byte_offset = offset;
                let skip = c.bytes_consumed.max(1);
                candidates.push(c);
                offset += skip;
            } else {
                offset += 1;
            }
        }
        candidates
    }
}

/// Boyer-Moore bad-character search for a byte pattern in a haystack.
pub fn boyer_moore_search(haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    let mut skip = [pattern.len(); 256];
    for (i, &b) in pattern.iter().enumerate().take(pattern.len() - 1) {
        skip[b as usize] = pattern.len() - 1 - i;
    }

    let mut matches = Vec::new();
    let mut i = pattern.len() - 1;
    while i < haystack.len() {
        let mut j = pattern.len() - 1;
        let mut k = i;
        while haystack[k] == pattern[j] {
            if j == 0 {
                matches.push(k);
                break;
            }
            j -= 1;
            k -= 1;
        }
        let shift = skip[haystack[i] as usize];
        i += if shift == 0 { 1 } else { shift };
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create_table_simple() {
        let sig = SchemaSignature::from_create_sql(
            "messages",
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER)",
        )
        .unwrap();
        assert_eq!(sig.table_name, "messages");
        assert_eq!(sig.column_count, 2);
        assert_eq!(sig.type_hints, vec![ColumnTypeHint::Text, ColumnTypeHint::Integer]);
    }

    #[test]
    fn test_parse_create_table_mixed_types() {
        let sig = SchemaSignature::from_create_sql(
            "contacts",
            "CREATE TABLE contacts (name TEXT, age INTEGER, score REAL, photo BLOB)",
        )
        .unwrap();
        assert_eq!(sig.column_count, 4);
        assert_eq!(
            sig.type_hints,
            vec![
                ColumnTypeHint::Text,
                ColumnTypeHint::Integer,
                ColumnTypeHint::Real,
                ColumnTypeHint::Blob,
            ]
        );
    }

    #[test]
    fn test_parse_create_table_untyped_columns() {
        let sig = SchemaSignature::from_create_sql(
            "kv",
            "CREATE TABLE kv (key, value)",
        )
        .unwrap();
        assert_eq!(sig.column_count, 2);
        assert_eq!(sig.type_hints, vec![ColumnTypeHint::Any, ColumnTypeHint::Any]);
    }

    #[test]
    fn test_parse_create_table_with_constraints() {
        // INTEGER PRIMARY KEY is the rowid alias → skipped; NAME TEXT NOT NULL UNIQUE and
        // VAL REAL DEFAULT 0.0 are real columns.
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, val REAL DEFAULT 0.0)",
        )
        .unwrap();
        assert_eq!(sig.table_name, "t");
        assert_eq!(sig.column_count, 2);
        assert_eq!(
            sig.type_hints,
            vec![ColumnTypeHint::Text, ColumnTypeHint::Real]
        );
    }

    #[test]
    fn test_parse_all_text_columns() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (a TEXT, b TEXT, c TEXT)",
        )
        .unwrap();
        assert_eq!(sig.column_count, 3);
        assert_eq!(
            sig.type_hints,
            vec![ColumnTypeHint::Text, ColumnTypeHint::Text, ColumnTypeHint::Text]
        );
    }

    #[test]
    fn test_parse_no_columns_returns_none() {
        // An empty column list is pathological — from_create_sql should return None or
        // a zero-column signature. Either is acceptable; we just verify it doesn't panic.
        let result = SchemaSignature::from_create_sql("t", "CREATE TABLE t ()");
        // May return Some with 0 columns or None; must not panic.
        if let Some(sig) = result {
            assert_eq!(sig.column_count, 0);
        }
    }

    #[test]
    fn test_is_compatible_integer() {
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 0));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 1));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 4));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 8));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 9));
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 7));
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 13));
    }

    #[test]
    fn test_is_compatible_text() {
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 0));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 13));
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 35));
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Text, 1));
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Text, 12));
    }

    #[test]
    fn test_is_compatible_any() {
        for st in [0, 1, 4, 7, 8, 9, 12, 13, 35, 100] {
            assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Any, st));
        }
    }

    #[test]
    fn test_boyer_moore_finds_pattern() {
        let haystack = b"abcXYZdefXYZghi";
        let matches = boyer_moore_search(haystack, b"XYZ");
        assert_eq!(matches, vec![3, 9]);
    }

    #[test]
    fn test_boyer_moore_no_match() {
        let matches = boyer_moore_search(b"abcdef", b"xyz");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_boyer_moore_single_byte() {
        let matches = boyer_moore_search(b"abacaba", b"a");
        assert_eq!(matches, vec![0, 2, 4, 6]);
    }

    #[test]
    fn test_try_parse_record_valid() {
        // Hand-craft a SQLite record: header_len=3, serial_type 1 (1-byte int), serial_type 13 (0-byte text)
        // Record body: [0x03, 0x01, 0x0D, 0x2A]
        // header_len=3 (varint), serial types: 1 (1-byte int), 13 (0-len text)
        // values: 0x2A (42 as i8)
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 2,
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text],
        };
        let data = [0x03, 0x01, 0x0D, 0x2A];
        let candidate = sig.try_parse_record(&data, 0);
        assert!(candidate.is_some());
        let c = candidate.unwrap();
        assert_eq!(c.values.len(), 2);
        assert_eq!(c.values[0], SqlValue::Int(42));
        assert_eq!(c.values[1], SqlValue::Text(String::new()));
        assert!(c.confidence > 0.5);
    }

    #[test]
    fn test_try_parse_record_wrong_column_count() {
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 3,
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text, ColumnTypeHint::Integer],
        };
        let data = [0x03, 0x01, 0x0D, 0x2A];
        assert!(sig.try_parse_record(&data, 0).is_none());
    }

    #[test]
    fn test_scan_region_finds_embedded_record() {
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 2,
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text],
        };
        let mut data = vec![0xFF, 0x00, 0xAB];
        data.extend_from_slice(&[0x03, 0x01, 0x0D, 0x2A]); // valid record at offset 3
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let candidates = sig.scan_region(&data);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].byte_offset, 3);
    }
}
