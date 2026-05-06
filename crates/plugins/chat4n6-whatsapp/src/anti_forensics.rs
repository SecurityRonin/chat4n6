//! Anti-forensics detection for WhatsApp msgstore.db.
//!
//! Detects evidence of tampering, selective deletion, timestamp anomalies,
//! and SQLite VACUUM operations that destroy deleted record remnants.

use chat4n6_plugin_api::{ExtractionResult, ForensicWarning};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AntiForensicsReport {
    pub warnings: Vec<ForensicWarning>,
}

// ── Header-level detectors ────────────────────────────────────────────────────

/// Detect VACUUM by checking free_page_count (bytes 36–39).
pub fn detect_vacuum(db_bytes: &[u8]) -> Vec<ForensicWarning> {
    if db_bytes.len() < 40 {
        return vec![];
    }
    if &db_bytes[..16] != b"SQLite format 3\0" {
        return vec![];
    }
    let free_pages = u32::from_be_bytes([db_bytes[36], db_bytes[37], db_bytes[38], db_bytes[39]]);
    if free_pages > 0 {
        vec![ForensicWarning::DatabaseVacuumed { freelist_page_count: free_pages }]
    } else {
        vec![]
    }
}

/// Analyse the SQLite file header for signs of external tampering.
///
/// Checks:
/// 1. write_counter ≠ read_counter (non-WAL) → HeaderTampered
/// 2. page_size × page_count ≠ file length   → HeaderTampered (size mismatch)
pub fn detect_header_tamper(db_bytes: &[u8]) -> Vec<ForensicWarning> {
    if db_bytes.len() < 100 {
        return vec![];
    }
    if &db_bytes[..16] != b"SQLite format 3\0" {
        return vec![];
    }

    let mut warnings = Vec::new();

    // Check 1: write_counter vs read_counter (bytes 92–95 vs 96–99).
    let write_version = db_bytes[18]; // 1=journal, 2=WAL
    let write_counter = u32::from_be_bytes([db_bytes[92], db_bytes[93], db_bytes[94], db_bytes[95]]);
    let read_counter  = u32::from_be_bytes([db_bytes[96], db_bytes[97], db_bytes[98], db_bytes[99]]);
    if write_counter != read_counter && write_version != 2 {
        warnings.push(ForensicWarning::HeaderTampered {
            change_counter: write_counter,
            expected_max: read_counter,
        });
    }

    // Check 2: declared page_size × page_count vs actual file length.
    let raw_page_size = u16::from_be_bytes([db_bytes[16], db_bytes[17]]);
    let page_size: u64 = if raw_page_size == 1 { 65536 } else { raw_page_size as u64 };
    let page_count = u32::from_be_bytes([db_bytes[28], db_bytes[29], db_bytes[30], db_bytes[31]]) as u64;
    let expected_size = page_size * page_count;
    let actual_size = db_bytes.len() as u64;
    if actual_size >= 100 && actual_size != expected_size {
        warnings.push(ForensicWarning::HeaderTampered {
            change_counter: actual_size as u32,
            expected_max: expected_size as u32,
        });
    }

    warnings
}

// ── Record-level detectors ────────────────────────────────────────────────────

/// Detect selective deletion by inspecting message ID gaps per chat.
pub fn detect_selective_deletion(result: &ExtractionResult) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();
    for chat in &result.chats {
        let mut ids: Vec<i64> = chat.messages.iter().map(|m| m.id).collect();
        if ids.len() < 3 {
            continue;
        }
        ids.sort_unstable();
        let gaps: Vec<i64> = ids.windows(2).map(|w| w[1] - w[0]).collect();
        // Use median gap as baseline — resistant to inflation by outliers.
        let mut sorted_gaps = gaps.clone();
        sorted_gaps.sort_unstable();
        let median_gap = sorted_gaps[sorted_gaps.len() / 2] as f64;
        let threshold = (median_gap * 5.0).max(10.0);
        let suspicious: Vec<_> = gaps.iter().filter(|&&g| g as f64 > threshold).collect();
        if !suspicious.is_empty() {
            let deletion_rate_pct = ((suspicious.len() * 100) / gaps.len()).min(100) as u8;
            warnings.push(ForensicWarning::SelectiveDeletion {
                suspect_jid: chat.jid.clone(),
                deletion_rate_pct,
            });
        }
    }
    warnings
}

/// Detect timestamp anomalies: messages where a later row_id has an earlier timestamp.
pub fn detect_timestamp_anomalies(result: &ExtractionResult) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();
    for chat in &result.chats {
        let mut prev_ts = DateTime::<Utc>::MIN_UTC;
        for msg in &chat.messages {
            if msg.timestamp.utc < prev_ts {
                warnings.push(ForensicWarning::TimestampAnomaly {
                    message_row_id: msg.id,
                    description: format!(
                        "timestamp {} precedes previous message timestamp {}",
                        msg.timestamp.utc, prev_ts
                    ),
                });
            }
            prev_ts = msg.timestamp.utc;
        }
    }
    warnings
}

// ── New detectors (§2.6) ─────────────────────────────────────────────────────

/// Detect duplicate XMPP stanza IDs (key_id column) in the message table.
///
/// Takes a map of key_id → list of message row_ids built from raw SQLite records.
/// Any key_id appearing more than once emits `DuplicateStanzaId`.
pub fn detect_duplicate_stanza_ids(
    key_id_map: &HashMap<String, Vec<i64>>,
) -> Vec<ForensicWarning> {
    key_id_map
        .iter()
        .filter(|(_, rows)| rows.len() > 1)
        .map(|(stanza_id, rows)| ForensicWarning::DuplicateStanzaId {
            stanza_id: stanza_id.clone(),
            occurrences: rows.len() as u32,
        })
        .collect()
}

/// Detect orphaned thumbnail rows (rows in message_thumbnails whose
/// message_row_id does not exist in the live message table).
///
/// Emits `ThumbnailOrphanHigh` when orphan_count * 100 / total_messages >= 30.
pub fn detect_thumbnail_orphans(
    thumbnail_row_ids: &[i64],
    live_message_ids: &std::collections::HashSet<i64>,
    total_messages: u32,
) -> Vec<ForensicWarning> {
    if total_messages == 0 {
        return vec![];
    }
    let orphan_count = thumbnail_row_ids
        .iter()
        .filter(|rid| !live_message_ids.contains(rid))
        .count() as u32;
    let ratio_pct = (orphan_count * 100 / total_messages).min(100) as u8;
    if ratio_pct >= 30 {
        vec![ForensicWarning::ThumbnailOrphanHigh {
            orphan_thumbnails: orphan_count,
            total_messages,
            ratio_pct,
        }]
    } else {
        vec![]
    }
}

/// Detect ROWID reuse across evidence source layers.
///
/// Walks `result.chats` collecting (message.id, message.timestamp.utc).
/// If the same message id appears with two different timestamps (one from a WAL
/// historic source and one from the live layer), it indicates ROWID reuse.
pub fn detect_rowid_reuse(result: &ExtractionResult) -> Vec<ForensicWarning> {
    use std::collections::HashMap as StdMap;
    let mut id_timestamps: StdMap<i64, Vec<DateTime<Utc>>> = StdMap::new();

    for chat in &result.chats {
        for msg in &chat.messages {
            id_timestamps
                .entry(msg.id)
                .or_default()
                .push(msg.timestamp.utc);
        }
    }

    let mut warnings = Vec::new();
    for (row_id, timestamps) in &id_timestamps {
        // Deduplicate timestamps; if two distinct values exist → reuse detected
        let mut unique_ts = timestamps.clone();
        unique_ts.sort();
        unique_ts.dedup();
        if unique_ts.len() > 1 {
            warnings.push(ForensicWarning::RowIdReuseDetected {
                table: "messages".to_string(),
                rowid: *row_id,
                conflicting_timestamps: unique_ts,
            });
        }
    }
    warnings
}

// ── Top-level analyser ────────────────────────────────────────────────────────

/// Run all anti-forensics checks and return a consolidated report.
pub fn analyse(result: &ExtractionResult, db_bytes: &[u8]) -> AntiForensicsReport {
    let mut warnings = Vec::new();
    warnings.extend(detect_vacuum(db_bytes));
    warnings.extend(detect_header_tamper(db_bytes));
    warnings.extend(detect_selective_deletion(result));
    warnings.extend(detect_timestamp_anomalies(result));
    AntiForensicsReport { warnings }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod header_tamper_tests {
    use super::*;

    fn valid_header(page_size: u16, page_count: u32, write_c: u32, read_c: u32) -> [u8; 100] {
        let mut h = [0u8; 100];
        h[..16].copy_from_slice(b"SQLite format 3\0");
        h[16..18].copy_from_slice(&page_size.to_be_bytes());
        h[18] = 1; // journal mode (non-WAL)
        h[28..32].copy_from_slice(&page_count.to_be_bytes());
        h[92..96].copy_from_slice(&write_c.to_be_bytes());
        h[96..100].copy_from_slice(&read_c.to_be_bytes());
        h
    }

    #[test]
    fn header_tamper_write_read_counter_mismatch_emits_warning() {
        let header = valid_header(4096, 1, 5, 3);
        let warnings = detect_header_tamper(&header);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::HeaderTampered { .. })),
            "write/read counter mismatch must emit HeaderTampered, got: {warnings:?}"
        );
    }

    #[test]
    fn header_tamper_page_size_mismatch_emits_warning() {
        // page_size=4096, page_count=2 → expected 8192, but header is only 100 bytes
        let header = valid_header(4096, 2, 1, 1);
        let warnings = detect_header_tamper(&header);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::HeaderTampered { .. })),
            "page size * count != file size must emit HeaderTampered, got: {warnings:?}"
        );
    }

    #[test]
    fn header_tamper_matching_counters_no_warning() {
        // page_size=4096, page_count=1 → expected 4096, actual=4096 (pad to match)
        let mut buf = vec![0u8; 4096];
        buf[..16].copy_from_slice(b"SQLite format 3\0");
        buf[16..18].copy_from_slice(&4096u16.to_be_bytes());
        buf[18] = 1;
        buf[28..32].copy_from_slice(&1u32.to_be_bytes()); // page_count=1 → 4096 bytes
        buf[92..96].copy_from_slice(&7u32.to_be_bytes()); // write=read=7
        buf[96..100].copy_from_slice(&7u32.to_be_bytes());
        let warnings = detect_header_tamper(&buf);
        assert!(
            warnings.is_empty(),
            "matching counters and correct size should emit no warnings, got: {warnings:?}"
        );
    }

    #[test]
    fn vacuum_detection_from_header() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\0");
        buf[36..40].copy_from_slice(&5u32.to_be_bytes()); // free_pages=5
        let warnings = detect_vacuum(&buf);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::DatabaseVacuumed { .. })),
            "non-zero free_pages must emit DatabaseVacuumed"
        );
    }

    #[test]
    fn selective_deletion_detected() {
        use chat4n6_plugin_api::{Chat, ExtractionResult, ForensicTimestamp, Message, MessageContent};
        let make_msg = |id: i64| Message {
            id,
            chat_id: 1,
            sender_jid: None,
            from_me: false,
            timestamp: ForensicTimestamp::from_millis(id * 1000, 0),
            content: MessageContent::Text(String::new()),
            reactions: vec![],
            quoted_message: None,
            source: chat4n6_plugin_api::EvidenceSource::Live,
            row_offset: 0,
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
            forwarded_from: None,
        };
        let chat = Chat {
            id: 1,
            jid: "suspect@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![
                make_msg(1), make_msg(2), make_msg(3),
                make_msg(100), make_msg(101), make_msg(102), // gap 3→100
            ],
            archived: false,
        };
        let result = ExtractionResult {
            chats: vec![chat],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
            forensic_warnings: vec![],
            group_participant_events: vec![],
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
        };
        let warnings = detect_selective_deletion(&result);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::SelectiveDeletion { .. })),
            "gap 3→100 should trigger SelectiveDeletion, got: {warnings:?}"
        );
    }

    #[test]
    fn timestamp_anomaly_pre_whatsapp() {
        use chat4n6_plugin_api::{Chat, ExtractionResult, ForensicTimestamp, Message, MessageContent};
        let make_msg = |id: i64, ts: i64| Message {
            id,
            chat_id: 1,
            sender_jid: None,
            from_me: false,
            timestamp: ForensicTimestamp::from_millis(ts, 0),
            content: MessageContent::Text(String::new()),
            reactions: vec![],
            quoted_message: None,
            source: chat4n6_plugin_api::EvidenceSource::Live,
            row_offset: 0,
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
            forwarded_from: None,
        };
        let chat = Chat {
            id: 1,
            jid: "test@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![
                make_msg(1, 1_710_000_000_000), // normal
                make_msg(2, 1_700_000_000_000), // earlier — anomaly
            ],
            archived: false,
        };
        let result = ExtractionResult {
            chats: vec![chat],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
            forensic_warnings: vec![],
            group_participant_events: vec![],
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
        };
        let warnings = detect_timestamp_anomalies(&result);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::TimestampAnomaly { .. })),
            "reversed timestamps should emit TimestampAnomaly, got: {warnings:?}"
        );
    }
}

// ── §2.6 new-detector tests ───────────────────────────────────────────────────

#[cfg(test)]
mod new_detector_tests {
    use super::*;

    // ── Detector 1: DuplicateStanzaId ─────────────────────────────────────────

    /// Build an in-memory msgstore.db with two messages sharing the same key_id
    /// and extract from it, asserting DuplicateStanzaId warning is emitted.
    #[test]
    fn duplicate_stanza_id_warning_from_extraction() {
        use crate::extractor::extract_from_msgstore;
        use crate::schema::SchemaVersion;

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0,
                key_id TEXT
            );
            INSERT INTO jid VALUES (1, 'test@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1);
            INSERT INTO message VALUES (1, 1, NULL, 0, 1710513127000, 'hello', 0, 'ABC123');
            INSERT INTO message VALUES (2, 1, NULL, 1, 1710513128000, 'world', 0, 'ABC123');
            INSERT INTO message VALUES (3, 1, NULL, 0, 1710513129000, 'foo',   0, 'XYZ999');
        "#).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();

        assert!(
            result.forensic_warnings.iter().any(|w| matches!(
                w,
                ForensicWarning::DuplicateStanzaId { stanza_id, occurrences: 2 }
                    if stanza_id == "ABC123"
            )),
            "expected DuplicateStanzaId {{ stanza_id: \"ABC123\", occurrences: 2 }}, got: {:?}",
            result.forensic_warnings
        );
    }

    // ── Detector 2: ThumbnailOrphanHigh ──────────────────────────────────────

    /// Build an in-memory msgstore.db with 10 messages and 5 orphan thumbnail
    /// rows, expect ThumbnailOrphanHigh warning (50% > 30% threshold).
    #[test]
    fn thumbnail_orphan_high_warning_from_extraction() {
        use crate::extractor::extract_from_msgstore;
        use crate::schema::SchemaVersion;

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE message_thumbnails (
                message_row_id INTEGER PRIMARY KEY,
                thumbnail BLOB
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1);
            INSERT INTO message VALUES (1,  1, NULL, 0, 1710513100000, 'msg1',  0);
            INSERT INTO message VALUES (2,  1, NULL, 0, 1710513101000, 'msg2',  0);
            INSERT INTO message VALUES (3,  1, NULL, 0, 1710513102000, 'msg3',  0);
            INSERT INTO message VALUES (4,  1, NULL, 0, 1710513103000, 'msg4',  0);
            INSERT INTO message VALUES (5,  1, NULL, 0, 1710513104000, 'msg5',  0);
            INSERT INTO message VALUES (6,  1, NULL, 0, 1710513105000, 'msg6',  0);
            INSERT INTO message VALUES (7,  1, NULL, 0, 1710513106000, 'msg7',  0);
            INSERT INTO message VALUES (8,  1, NULL, 0, 1710513107000, 'msg8',  0);
            INSERT INTO message VALUES (9,  1, NULL, 0, 1710513108000, 'msg9',  0);
            INSERT INTO message VALUES (10, 1, NULL, 0, 1710513109000, 'msg10', 0);
            -- thumbnail for live message 1 (not an orphan)
            INSERT INTO message_thumbnails VALUES (1,  x'ff');
            -- orphan thumbnails pointing to deleted messages 11-15
            INSERT INTO message_thumbnails VALUES (11, x'ff');
            INSERT INTO message_thumbnails VALUES (12, x'ff');
            INSERT INTO message_thumbnails VALUES (13, x'ff');
            INSERT INTO message_thumbnails VALUES (14, x'ff');
            INSERT INTO message_thumbnails VALUES (15, x'ff');
        "#).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();

        assert!(
            result.forensic_warnings.iter().any(|w| matches!(
                w,
                ForensicWarning::ThumbnailOrphanHigh { orphan_thumbnails: 5, total_messages: 10, ratio_pct: 50 }
            )),
            "expected ThumbnailOrphanHigh with 5 orphans / 10 messages = 50%, got: {:?}",
            result.forensic_warnings
        );
    }

    // ── Detector 3: RowIdReuseDetected ────────────────────────────────────────

    /// Build an ExtractionResult with two messages having the same id but
    /// different timestamps (simulating ROWID reuse across source layers).
    #[test]
    fn rowid_reuse_detected_from_extraction_result() {
        use chat4n6_plugin_api::{
            Chat, EvidenceSource, ExtractionResult, ForensicTimestamp, Message, MessageContent,
        };

        let make_msg = |id: i64, ts_ms: i64, source: EvidenceSource| Message {
            id,
            chat_id: 1,
            sender_jid: None,
            from_me: false,
            timestamp: ForensicTimestamp::from_millis(ts_ms, 0),
            content: MessageContent::Text("hello".into()),
            reactions: vec![],
            quoted_message: None,
            source,
            row_offset: 0,
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
            forwarded_from: None,
        };

        // Same row_id=42, two different timestamps from different source layers
        let chat = Chat {
            id: 1,
            jid: "suspect@s.whatsapp.net".into(),
            name: None,
            is_group: false,
            messages: vec![
                make_msg(42, 1_710_000_000_000, EvidenceSource::Live),
                make_msg(42, 1_700_000_000_000, EvidenceSource::WalHistoric),
            ],
            archived: false,
        };

        let result = ExtractionResult {
            chats: vec![chat],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
            forensic_warnings: vec![],
            group_participant_events: vec![],
            extraction_started_at: None,
            extraction_finished_at: None,
            wal_snapshots: vec![],
        };

        let warnings = detect_rowid_reuse(&result);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                ForensicWarning::RowIdReuseDetected { table, rowid: 42, .. }
                    if table == "messages"
            )),
            "expected RowIdReuseDetected for rowid=42, got: {warnings:?}"
        );
    }
}
