use crate::record::{RecoveredRecord, SqlValue};
use chat4n6_plugin_api::EvidenceSource;
use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of a record's values for deduplication.
pub fn record_hash(record: &RecoveredRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(record.table.as_bytes());
    hasher.update(b"|");
    for val in &record.values {
        match val {
            SqlValue::Null => hasher.update(b"N"),
            SqlValue::Int(n) => hasher.update(n.to_le_bytes()),
            SqlValue::Real(f) => hasher.update(f.to_le_bytes()),
            SqlValue::Text(s) => {
                hasher.update(b"T");
                hasher.update(s.as_bytes());
            }
            SqlValue::Blob(b) => {
                hasher.update(b"B");
                hasher.update(b);
            }
        }
        hasher.update(b"|");
    }
    hasher.finalize().into()
}

/// Remove non-live records that are exact duplicates of live records.
/// Among carved records, prefer higher confidence.
pub fn deduplicate(records: &mut Vec<RecoveredRecord>) {
    use std::collections::{HashMap, HashSet};

    // Build set of live record hashes
    let live_hashes: HashSet<[u8; 32]> = records
        .iter()
        .filter(|r| r.source == EvidenceSource::Live)
        .map(record_hash)
        .collect();

    // Group non-live records by hash, keep highest confidence per hash
    let mut best_by_hash: HashMap<[u8; 32], usize> = HashMap::new();
    let mut to_remove = Vec::new();

    for (i, record) in records.iter().enumerate() {
        if record.source == EvidenceSource::Live {
            continue;
        }
        let hash = record_hash(record);
        // Remove if it duplicates a live record
        if live_hashes.contains(&hash) {
            to_remove.push(i);
            continue;
        }
        // Among non-live duplicates, keep highest confidence
        if let Some(&prev_idx) = best_by_hash.get(&hash) {
            if record.confidence > records[prev_idx].confidence {
                to_remove.push(prev_idx);
                best_by_hash.insert(hash, i);
            } else {
                to_remove.push(i);
            }
        } else {
            best_by_hash.insert(hash, i);
        }
    }

    to_remove.sort_unstable();
    to_remove.dedup();
    for i in to_remove.into_iter().rev() {
        records.swap_remove(i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(table: &str, values: Vec<SqlValue>, source: EvidenceSource) -> RecoveredRecord {
        RecoveredRecord {
            table: table.to_string(),
            row_id: Some(1),
            values,
            source,
            offset: 0,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_same_values_produce_same_hash() {
        let r1 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Live);
        let r2 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Freelist);
        assert_eq!(record_hash(&r1), record_hash(&r2));
    }

    #[test]
    fn test_different_values_different_hash() {
        let r1 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Live);
        let r2 = make_record("t", vec![SqlValue::Text("world".into())], EvidenceSource::Live);
        assert_ne!(record_hash(&r1), record_hash(&r2));
    }

    #[test]
    fn test_deduplicate_removes_carved_duplicate_of_live() {
        let live = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Live);
        let carved = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Freelist);
        let unique = make_record("t", vec![SqlValue::Int(99)], EvidenceSource::Freelist);
        let mut records = vec![live, carved, unique];
        deduplicate(&mut records);
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.source == EvidenceSource::Live));
        assert!(records.iter().any(|r| matches!(r.values[0], SqlValue::Int(99))));
    }

    #[test]
    fn test_deduplicate_keeps_historical_version() {
        let live = make_record("t", vec![SqlValue::Text("new".into())], EvidenceSource::Live);
        let old = make_record("t", vec![SqlValue::Text("old".into())], EvidenceSource::Freelist);
        let mut records = vec![live, old];
        deduplicate(&mut records);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_deduplicate_prefers_higher_confidence() {
        let mut low = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::CarvedUnalloc { confidence_pct: 50 });
        low.confidence = 0.5;
        let mut high = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Freelist);
        high.confidence = 1.0;
        let mut records = vec![low, high];
        deduplicate(&mut records);
        assert_eq!(records.len(), 1);
        assert!(records[0].confidence > 0.9);
    }

    #[test]
    fn test_deduplicate_all_live_unchanged() {
        // All live records — none should be removed regardless of value equality.
        let r1 = make_record("t", vec![SqlValue::Int(1)], EvidenceSource::Live);
        let r2 = make_record("t", vec![SqlValue::Int(2)], EvidenceSource::Live);
        let r3 = make_record("t", vec![SqlValue::Int(3)], EvidenceSource::Live);
        let mut records = vec![r1, r2, r3];
        deduplicate(&mut records);
        assert_eq!(records.len(), 3, "all live records must survive dedup");
    }

    #[test]
    fn test_deduplicate_single_record_unchanged() {
        // A single record should never be removed.
        let r = make_record("t", vec![SqlValue::Text("only".into())], EvidenceSource::Freelist);
        let mut records = vec![r];
        deduplicate(&mut records);
        assert_eq!(records.len(), 1, "single record must survive dedup");
    }

    #[test]
    fn test_deduplicate_all_carved_same_hash_keeps_highest_confidence() {
        // Multiple carved records with identical values — highest confidence wins.
        let mut low = make_record("t", vec![SqlValue::Int(7)], EvidenceSource::Freelist);
        low.confidence = 0.3;
        let mut mid = make_record("t", vec![SqlValue::Int(7)], EvidenceSource::Freelist);
        mid.confidence = 0.6;
        let mut high = make_record("t", vec![SqlValue::Int(7)], EvidenceSource::Freelist);
        high.confidence = 0.9;
        let mut records = vec![low, mid, high];
        deduplicate(&mut records);
        assert_eq!(records.len(), 1, "only the highest-confidence carved record should survive");
        assert!(records[0].confidence > 0.8, "surviving record must be the highest-confidence one");
    }
}
