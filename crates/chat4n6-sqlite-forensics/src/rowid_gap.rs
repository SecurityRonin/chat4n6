use crate::record::RecoveredRecord;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RowidGap {
    pub table: String,
    pub gap_start: i64,
    pub gap_end: i64,
    pub gap_size: u64,
    pub neighbor_before: Option<RecoveredRecord>,
    pub neighbor_after: Option<RecoveredRecord>,
}

/// Detect gaps in ROWID sequences that indicate deleted records.
pub fn detect_rowid_gaps(
    live_records: &[RecoveredRecord],
    table_roots: &HashMap<String, u32>,
) -> Vec<RowidGap> {
    let mut gaps = Vec::new();

    // Group records by table name (only tables in table_roots)
    for table_name in table_roots.keys() {
        let mut table_records: Vec<_> = live_records
            .iter()
            .filter(|r| r.table == *table_name && r.row_id.is_some())
            .collect();

        if table_records.len() < 2 {
            continue;
        }

        // Sort by row_id
        table_records.sort_by_key(|r| r.row_id.unwrap());

        // Detect gaps > 1 between consecutive row_ids
        for window in table_records.windows(2) {
            let prev_id = window[0].row_id.unwrap();
            let next_id = window[1].row_id.unwrap();

            if next_id - prev_id > 1 {
                gaps.push(RowidGap {
                    table: table_name.clone(),
                    gap_start: prev_id + 1,
                    gap_end: next_id - 1,
                    gap_size: (next_id - prev_id - 1) as u64,
                    neighbor_before: Some(window[0].clone()),
                    neighbor_after: Some(window[1].clone()),
                });
            }
        }
    }

    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SqlValue;
    use chat4n6_plugin_api::EvidenceSource;

    fn make_record(table: &str, row_id: i64) -> RecoveredRecord {
        RecoveredRecord {
            table: table.to_string(),
            row_id: Some(row_id),
            values: vec![SqlValue::Int(row_id)],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_no_gaps_contiguous() {
        let records = vec![make_record("t", 1), make_record("t", 2), make_record("t", 3)];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert!(gaps.is_empty());
    }

    #[test]
    fn test_single_gap() {
        let records = vec![make_record("t", 1), make_record("t", 2), make_record("t", 5)];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_start, 3);
        assert_eq!(gaps[0].gap_end, 4);
        assert_eq!(gaps[0].gap_size, 2);
    }

    #[test]
    fn test_multiple_gaps() {
        let records = vec![
            make_record("t", 1),
            make_record("t", 5),
            make_record("t", 10),
        ];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn test_no_records_for_table() {
        let records = vec![make_record("other", 1)];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert!(gaps.is_empty());
    }

    #[test]
    fn test_single_record_no_gap() {
        let records = vec![make_record("t", 1)];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert!(gaps.is_empty());
    }

    #[test]
    fn test_neighbors_attached() {
        let records = vec![make_record("t", 1), make_record("t", 5)];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].neighbor_before.is_some());
        assert!(gaps[0].neighbor_after.is_some());
        assert_eq!(gaps[0].neighbor_before.as_ref().unwrap().row_id, Some(1));
        assert_eq!(gaps[0].neighbor_after.as_ref().unwrap().row_id, Some(5));
    }

    #[test]
    fn test_records_without_rowid_skipped() {
        let r = make_record("t", 1);
        let mut r2 = make_record("t", 0);
        r2.row_id = None;
        let r3 = make_record("t", 5);
        let records = vec![r, r2, r3];
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let gaps = detect_rowid_gaps(&records, &roots);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_start, 2);
        assert_eq!(gaps[0].gap_end, 4);
    }
}
