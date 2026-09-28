use chat4n6_sqlite_forensics::record::{RecoveredRecord, SqlValue};
use std::collections::HashMap;

/// Seconds between the Unix epoch (1970-01-01) and the Apple / Cocoa Core Data
/// reference date (2001-01-01), both UTC.
pub const APPLE_EPOCH_OFFSET_SECS: i64 = 978_307_200;

/// Convert an iMessage `message.date` value to Unix milliseconds.
///
/// Since macOS 10.13 / iOS 11 the column holds NANOSECONDS since 2001-01-01 UTC;
/// older databases hold SECONDS. A magnitude above 1e12 marks the nanosecond
/// form (any plausible seconds-since-2001 value is far smaller). `0` maps to `0`
/// so a missing date renders as "no value", not 2001.
pub fn apple_date_to_unix_ms(date: i64) -> i64 {
    if date == 0 {
        return 0;
    }
    if date.abs() > 1_000_000_000_000 {
        // nanoseconds since 2001 → milliseconds since 1970
        date / 1_000_000 + APPLE_EPOCH_OFFSET_SECS * 1000
    } else {
        // seconds since 2001 → milliseconds since 1970
        date * 1000 + APPLE_EPOCH_OFFSET_SECS * 1000
    }
}

/// Parse a `CREATE TABLE` DDL into a `column name (lowercased) -> values[] index`
/// map. The b-tree walker stores the INTEGER PRIMARY KEY alias (`ROWID`) as a
/// Null at `values[0]` and real columns follow in declaration order, so a
/// column's index equals its 0-based position in the DDL column list.
///
/// Naive comma-split: iMessage's `message` / `handle` / `chat` / join tables
/// declare simple columns with no column-level `CHECK(a, b)` or table-level
/// constraints embedding commas.
pub fn ddl_column_indices(ddl: &str) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let (Some(start), Some(end)) = (ddl.find('('), ddl.rfind(')')) else {
        return map;
    };
    for (idx, col_def) in ddl[start + 1..end].split(',').enumerate() {
        if let Some(name) = col_def.split_whitespace().next() {
            let name = name.trim_matches('`').trim_matches('"').trim_matches('[');
            let name = name.trim_matches(']');
            if !name.is_empty() {
                map.entry(name.to_ascii_lowercase()).or_insert(idx);
            }
        }
    }
    map
}

/// Resolve the `name -> values[] index` map for one table from the DDL map.
pub fn cols_of(ddl_map: &HashMap<String, String>, table: &str) -> HashMap<String, usize> {
    ddl_map
        .get(table)
        .map(|ddl| ddl_column_indices(ddl))
        .unwrap_or_default()
}

/// Fetch a record value by resolved (lowercased) column name; `None` when the
/// column is absent from this schema or the record is too short (carved/partial).
pub fn val<'a>(
    r: &'a RecoveredRecord,
    cols: &HashMap<String, usize>,
    name: &str,
) -> Option<&'a SqlValue> {
    cols.get(name).and_then(|&i| r.values.get(i))
}

/// Best-effort plain-text extraction from an iMessage `attributedBody`
/// typedstream blob, used only when `message.text` is NULL (the modern default).
///
/// Locates the `NSString` class name, then the `+` (0x2B) payload-start marker,
/// reads the streamtyped length prefix (`<0x80` inline, `0x81`+u16, `0x82`+u32),
/// and returns the UTF-8 string when it decodes cleanly. Returns `None` rather
/// than guess: a body we cannot decode is reported as attributedBody-only, never
/// with fabricated text.
pub fn text_from_attributed_body(blob: &[u8]) -> Option<String> {
    let marker = b"NSString";
    let ns = find_subslice(blob, marker)?;
    let rel = blob[ns + marker.len()..].iter().position(|&b| b == b'+')?;
    let mut i = ns + marker.len() + rel + 1;
    let len = match *blob.get(i)? {
        b if b < 0x80 => {
            i += 1;
            b as usize
        }
        0x81 => {
            let l = u16::from_le_bytes([*blob.get(i + 1)?, *blob.get(i + 2)?]) as usize;
            i += 3;
            l
        }
        0x82 => {
            let l = u32::from_le_bytes([
                *blob.get(i + 1)?,
                *blob.get(i + 2)?,
                *blob.get(i + 3)?,
                *blob.get(i + 4)?,
            ]) as usize;
            i += 5;
            l
        }
        _ => return None,
    };
    let end = i.checked_add(len)?;
    let bytes = blob.get(i..end)?;
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_nanoseconds_2022() {
        // 2022-08-08 00:00:00 UTC = unix 1_659_916_800 s.
        // secs since 2001 = 1_659_916_800 - 978_307_200 = 681_609_600.
        let ns = 681_609_600i64 * 1_000_000_000;
        assert_eq!(apple_date_to_unix_ms(ns), 1_659_916_800_000);
    }

    #[test]
    fn test_apple_seconds_legacy() {
        let secs = 681_609_600i64; // seconds-since-2001 form
        assert_eq!(apple_date_to_unix_ms(secs), 1_659_916_800_000);
    }

    #[test]
    fn test_apple_zero_is_zero() {
        assert_eq!(apple_date_to_unix_ms(0), 0);
    }

    #[test]
    fn test_attributed_body_none_without_marker() {
        assert_eq!(text_from_attributed_body(b"no marker here"), None);
    }
}
