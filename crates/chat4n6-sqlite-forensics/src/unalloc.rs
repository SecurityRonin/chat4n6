use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::varint::read_varint;
use chat4n6_plugin_api::{EvidenceSource, UnallocatedRegion};
use std::collections::HashMap;

// ── Signature database ────────────────────────────────────────────────────────

/// A learned column pattern from live records.
#[derive(Debug, Clone)]
pub struct ColumnPattern {
    pub table: String,
    pub col_index: usize,
    /// Most common serial type seen for this column in live records.
    pub serial_type_hint: u64,
}

/// Database of column patterns learned from live records.
pub struct SignatureDb {
    patterns: Vec<ColumnPattern>,
}

impl SignatureDb {
    /// Return patterns for a given table, sorted by col_index.
    pub fn patterns_for(&self, table: &str) -> Vec<&ColumnPattern> {
        let mut v: Vec<&ColumnPattern> =
            self.patterns.iter().filter(|p| p.table == table).collect();
        v.sort_by_key(|p| p.col_index);
        v
    }
}

// ── learn_signatures ─────────────────────────────────────────────────────────

/// Analyse live records to learn the most common serial type per (table, col_index).
pub fn learn_signatures(records: &[RecoveredRecord]) -> SignatureDb {
    // (table, col_index) -> {serial_type -> count}
    let mut counts: HashMap<(String, usize), HashMap<u64, usize>> = HashMap::new();

    for rec in records {
        for (col_index, value) in rec.values.iter().enumerate() {
            let st = value_to_serial_type(value);
            *counts
                .entry((rec.table.clone(), col_index))
                .or_default()
                .entry(st)
                .or_insert(0) += 1;
        }
    }

    let mut patterns: Vec<ColumnPattern> = counts
        .into_iter()
        .map(|((table, col_index), type_counts)| {
            let serial_type_hint = type_counts
                .into_iter()
                .max_by_key(|&(_, c)| c)
                .map(|(st, _)| st)
                .unwrap_or(0);
            ColumnPattern {
                table,
                col_index,
                serial_type_hint,
            }
        })
        .collect();

    // Deterministic order for tests
    patterns.sort_by(|a, b| a.table.cmp(&b.table).then(a.col_index.cmp(&b.col_index)));

    SignatureDb { patterns }
}

/// Map a `SqlValue` to an approximate SQLite serial type for signature matching.
fn value_to_serial_type(value: &SqlValue) -> u64 {
    match value {
        SqlValue::Null => 0,
        SqlValue::Int(v) => {
            // Pick the smallest serial type that fits
            if *v == 0 || *v == 1 {
                8 // special single-byte literal 0/1 — approximate with 1-byte int
            } else if (-128..=127).contains(v) {
                1
            } else if (-32768..=32767).contains(v) {
                2
            } else if (-8388608..=8388607).contains(v) {
                3
            } else if (-2147483648..=2147483647).contains(v) {
                4
            } else {
                6
            }
        }
        SqlValue::Real(_) => 7,
        SqlValue::Text(s) => {
            let len = s.len() as u64;
            13 + len * 2
        }
        SqlValue::Blob(b) => {
            let len = b.len() as u64;
            12 + len * 2
        }
    }
}

// ── carve_unallocated ─────────────────────────────────────────────────────────

/// Scan an unallocated region byte-by-byte looking for SQLite record patterns that
/// match the learned signatures for `table_hint`.
pub fn carve_unallocated(
    region: &UnallocatedRegion,
    sig_db: &SignatureDb,
    table_hint: &str,
) -> Vec<RecoveredRecord> {
    let data = &region.data;
    let abs_base = region.offset;
    let patterns = sig_db.patterns_for(table_hint);

    let mut results = Vec::new();

    if data.is_empty() || patterns.is_empty() {
        // No signatures to match against — still try a plain structural scan
        // when there are no learned patterns; skip the region in that case.
        return results;
    }

    let col_count = patterns.iter().map(|p| p.col_index + 1).max().unwrap_or(0);

    if col_count == 0 {
        return results;
    }

    // Minimum bytes: 1 (header_len) + col_count (serial types, 1 byte each minimum) + 0 data
    let min_len = 1 + col_count;

    let mut pos = 0;
    while pos + min_len <= data.len() {
        if let Some((record, consumed)) = try_parse_record(
            &data[pos..],
            abs_base + pos as u64,
            table_hint,
            col_count,
            &patterns,
        ) {
            results.push(record);
            pos += consumed;
        } else {
            pos += 1;
        }
    }

    results
}

/// Try to parse a single SQLite record at the start of `data`.
/// Returns `(RecoveredRecord, bytes_consumed)` on success.
fn try_parse_record(
    data: &[u8],
    abs_offset: u64,
    table: &str,
    col_count: usize,
    patterns: &[&ColumnPattern],
) -> Option<(RecoveredRecord, usize)> {
    // Read header_len varint
    let (header_len, hl_consumed) = read_varint(data, 0)?;
    let header_end = header_len as usize;

    // Sanity checks: header must be plausible
    // header_end includes the header_len varint itself
    if header_end < hl_consumed || header_end > data.len() || header_end > 512
    // guard against huge garbage headers
    {
        return None;
    }

    // Read serial types from header
    let mut pos = hl_consumed;
    let mut serial_types: Vec<u64> = Vec::with_capacity(col_count);
    while pos < header_end {
        let (st, consumed) = read_varint(data, pos)?;
        serial_types.push(st);
        pos += consumed;
        if serial_types.len() >= col_count {
            break;
        }
    }

    if serial_types.is_empty() {
        return None;
    }

    // Validate that at least 1 column serial type matches the signature
    let matched = serial_types
        .iter()
        .enumerate()
        .filter(|&(i, &st)| {
            patterns
                .iter()
                .any(|p| p.col_index == i && serial_types_compatible(st, p.serial_type_hint))
        })
        .count();

    if matched == 0 {
        return None;
    }

    // Decode values — return None on any decode failure to avoid corrupting
    // the consumed-byte count (which would mis-advance the scanner).
    let mut data_pos = header_end;
    let mut values: Vec<SqlValue> = Vec::with_capacity(serial_types.len());
    for &st in &serial_types {
        match decode_serial_type(st, data, data_pos) {
            Some((val, consumed)) => {
                data_pos += consumed;
                values.push(val);
            }
            None => return None,
        }
    }

    let total_cols = serial_types.len().max(col_count);
    let confidence_pct = ((matched * 100) / total_cols.max(1)).min(100) as u8;
    let confidence = confidence_pct as f32 / 100.0;

    Some((
        RecoveredRecord {
            table: table.to_string(),
            row_id: None,
            values,
            source: EvidenceSource::CarvedUnalloc { confidence_pct },
            offset: abs_offset,
            confidence,
        },
        data_pos,
    ))
}

/// Determine whether a found serial type is "compatible" with the learned hint.
/// We use a class-based comparison: both must be the same broad type class
/// (integer, real, text, blob, null).
fn serial_types_compatible(found: u64, hint: u64) -> bool {
    if found == hint {
        return true;
    }
    // Both integer types (1-6 are fixed-size integers, 8-9 are literal 0/1)
    let int_class = |st: u64| matches!(st, 1..=6 | 8 | 9);
    if int_class(found) && int_class(hint) {
        return true;
    }
    // Both real
    if found == 7 && hint == 7 {
        return true;
    }
    // Both text (odd >= 13)
    if found >= 13 && found % 2 == 1 && hint >= 13 && hint % 2 == 1 {
        return true;
    }
    // Both blob (even >= 12)
    if found >= 12 && found.is_multiple_of(2) && hint >= 12 && hint.is_multiple_of(2) {
        return true;
    }
    false
}

// ── recover_layer6 ────────────────────────────────────────────────────────────

/// Layer 6: carve records from all unallocated regions.
pub fn recover_layer6(
    regions: &[UnallocatedRegion],
    sig_db: &SignatureDb,
    table_hint: &str,
) -> Vec<RecoveredRecord> {
    regions
        .iter()
        .flat_map(|r| carve_unallocated(r, sig_db, table_hint))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::EvidenceSource;

    fn make_record(table: &str, values: Vec<SqlValue>) -> RecoveredRecord {
        RecoveredRecord {
            table: table.to_string(),
            row_id: None,
            values,
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        }
    }

    // ── 1. test_learn_signatures_empty ────────────────────────────────────────

    #[test]
    fn test_learn_signatures_empty() {
        let db = learn_signatures(&[]);
        assert!(
            db.patterns.is_empty(),
            "Empty records should yield empty signature db"
        );
    }

    // ── 2. test_learn_signatures_basic ────────────────────────────────────────

    #[test]
    fn test_learn_signatures_basic() {
        let records = vec![
            make_record(
                "messages",
                vec![SqlValue::Int(1), SqlValue::Text("hello".into())],
            ),
            make_record(
                "messages",
                vec![SqlValue::Int(2), SqlValue::Text("world".into())],
            ),
            make_record(
                "messages",
                vec![SqlValue::Int(3), SqlValue::Text("foo".into())],
            ),
        ];
        let db = learn_signatures(&records);
        let pats = db.patterns_for("messages");
        assert_eq!(
            pats.len(),
            2,
            "Should have 2 column patterns for 'messages'"
        );

        // col 0 → int → serial type 1 (fits in 1 byte for 1-3)
        let col0 = pats
            .iter()
            .find(|p| p.col_index == 0)
            .expect("col 0 pattern");
        assert!(
            matches!(col0.serial_type_hint, 1..=6 | 8 | 9),
            "col 0 hint should be an int type, got {}",
            col0.serial_type_hint
        );

        // col 1 → text → odd serial type >= 13
        let col1 = pats
            .iter()
            .find(|p| p.col_index == 1)
            .expect("col 1 pattern");
        assert!(
            col1.serial_type_hint >= 13 && col1.serial_type_hint % 2 == 1,
            "col 1 hint should be text serial type, got {}",
            col1.serial_type_hint
        );
    }

    // ── 3. test_carve_unallocated_finds_record ────────────────────────────────

    #[test]
    fn test_carve_unallocated_finds_record() {
        // Build a minimal SQLite record:
        //   header_len=2 (varint: just 1 byte = 0x02, covers itself + 1 serial type byte)
        //   serial_type=1 (1-byte int)
        //   value=42 (0x2a)
        //
        // Teach the signature db that col 0 of "test_table" is an integer type.
        let live = vec![make_record("test_table", vec![SqlValue::Int(99)])];
        let sig_db = learn_signatures(&live);

        let record_bytes: Vec<u8> = vec![
            0x02, // header_len varint = 2 (includes itself)
            0x01, // serial type 1 = 1-byte int
            0x2a, // value = 42
        ];

        let region = UnallocatedRegion {
            offset: 1000,
            data: record_bytes,
        };

        let found = carve_unallocated(&region, &sig_db, "test_table");
        assert!(!found.is_empty(), "Should find the embedded record");
        assert!(found[0].values.contains(&SqlValue::Int(42)));
        assert_eq!(found[0].offset, 1000);
        // Confidence should be > 0
        assert!(found[0].confidence > 0.0);
        // Source should be CarvedUnalloc
        assert!(matches!(
            found[0].source,
            EvidenceSource::CarvedUnalloc { confidence_pct } if confidence_pct > 0
        ));
    }

    // ── 4. test_carve_unallocated_empty_region ────────────────────────────────

    #[test]
    fn test_carve_unallocated_empty_region() {
        let live = vec![make_record("test_table", vec![SqlValue::Int(1)])];
        let sig_db = learn_signatures(&live);

        let region = UnallocatedRegion {
            offset: 0,
            data: vec![],
        };

        let found = carve_unallocated(&region, &sig_db, "test_table");
        assert!(found.is_empty(), "Empty region should yield no results");
    }

    // ── 4b. test_carve_unallocated_all_zeros_region ───────────────────────────

    #[test]
    fn test_carve_unallocated_all_zeros_region() {
        // A region filled entirely with zero bytes cannot contain a valid SQLite
        // record (header_len varint of 0 is degenerate), so carve_unallocated
        // must return empty without panicking.
        let live = vec![make_record("test_table", vec![SqlValue::Int(1)])];
        let sig_db = learn_signatures(&live);

        let region = UnallocatedRegion {
            offset: 0,
            data: vec![0u8; 64],
        };

        let found = carve_unallocated(&region, &sig_db, "test_table");
        assert!(found.is_empty(), "All-zeros region should yield no results");
    }

    // ── 5. test_recover_layer6_combines_regions ───────────────────────────────

    #[test]
    fn test_recover_layer6_combines_regions() {
        let live = vec![make_record("tbl", vec![SqlValue::Int(0)])];
        let sig_db = learn_signatures(&live);

        // Two regions each containing one valid record
        let record_bytes: Vec<u8> = vec![0x02, 0x01, 0x07];

        let regions = vec![
            UnallocatedRegion {
                offset: 0,
                data: record_bytes.clone(),
            },
            UnallocatedRegion {
                offset: 5000,
                data: record_bytes.clone(),
            },
        ];

        let results = recover_layer6(&regions, &sig_db, "tbl");
        assert_eq!(results.len(), 2, "Should combine records from both regions");
        // Offsets should differ
        assert_ne!(results[0].offset, results[1].offset);
    }
}
