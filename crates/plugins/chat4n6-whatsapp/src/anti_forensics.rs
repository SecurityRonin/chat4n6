//! Anti-forensics detection for WhatsApp msgstore.db.
//!
//! Detects evidence of tampering, selective deletion, timestamp anomalies,
//! and SQLite VACUUM operations that destroy deleted record remnants.

use chat4n6_plugin_api::{ExtractionResult, ForensicWarning};

pub struct AntiForensicsReport {
    pub warnings: Vec<ForensicWarning>,
}

/// Parse the SQLite file header and return (page_size, freelist_page_count).
///
/// SQLite header layout (offset in bytes):
///   0-15  : magic string "SQLite format 3\0"
///   16-17 : page size big-endian u16 (value 1 = 65536)
///   36-39 : freelist page count big-endian u32
pub fn parse_sqlite_header(_db_bytes: &[u8]) -> Option<(u32, u32)> {
    todo!("implement header parsing")
}

/// Detect VACUUM: if freelist_page_count == 0, the database may have been
/// VACUUMed, destroying deleted record remnants.
pub fn detect_vacuum(_db_bytes: &[u8]) -> Option<ForensicWarning> {
    todo!("implement vacuum detection")
}

/// Detect selective deletion by checking for suspicious ROWID gaps per chat.
pub fn detect_selective_deletion(_result: &ExtractionResult) -> Vec<ForensicWarning> {
    todo!("implement selective deletion detection")
}

/// WhatsApp was founded 2009-01-01 in UTC.
pub const WHATSAPP_EPOCH_MS: i64 = 1_230_768_000_000;

/// Detect timestamp anomalies (pre-WhatsApp-founding or far future).
pub fn detect_timestamp_anomalies(
    _result: &ExtractionResult,
    _reference_now_ms: i64,
) -> Vec<ForensicWarning> {
    todo!("implement timestamp anomaly detection")
}

/// Run all anti-forensics checks on an ExtractionResult.
pub fn analyse(
    _result: &ExtractionResult,
    _db_bytes: &[u8],
    _reference_now_ms: i64,
) -> AntiForensicsReport {
    todo!("implement analyse")
}

#[cfg(test)]
mod anti_forensics_tests {
    use super::*;
    use chat4n6_plugin_api::{
        Chat, EvidenceSource, ExtractionResult, ForensicTimestamp, Message, MessageContent,
    };

    fn make_empty_result() -> ExtractionResult {
        ExtractionResult {
            chats: vec![],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
            forensic_warnings: vec![],
            group_participant_events: vec![],
        }
    }

    fn make_msg(id: i64, chat_id: i64, ts_ms: i64) -> Message {
        Message {
            id,
            chat_id,
            sender_jid: None,
            from_me: true,
            timestamp: ForensicTimestamp::from_millis(ts_ms, 0),
            content: MessageContent::Text("x".to_string()),
            reactions: vec![],
            quoted_message: None,
            source: EvidenceSource::Live,
            row_offset: 0,
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
        }
    }

    /// Build a minimal SQLite header with a known freelist_page_count.
    fn make_sqlite_header(freelist_count: u32) -> Vec<u8> {
        let mut header = vec![0u8; 100];
        // Magic
        header[0..16].copy_from_slice(b"SQLite format 3\0");
        // Page size = 4096 (big-endian u16)
        header[16] = 0x10;
        header[17] = 0x00;
        // freelist_page_count at offset 36 (big-endian u32)
        let fc = freelist_count.to_be_bytes();
        header[36..40].copy_from_slice(&fc);
        header
    }

    // ── Test 1: vacuum_detection_from_header ─────────────────────────────────

    #[test]
    fn vacuum_detection_from_header() {
        let header_zero = make_sqlite_header(0);
        let warning = detect_vacuum(&header_zero);
        assert!(
            warning.is_some(),
            "freelist_page_count=0 should emit DatabaseVacuumed"
        );
        assert!(matches!(
            warning.unwrap(),
            ForensicWarning::DatabaseVacuumed { freelist_page_count: 0 }
        ));
    }

    #[test]
    fn no_vacuum_when_freelist_nonzero() {
        let header = make_sqlite_header(5);
        let warning = detect_vacuum(&header);
        assert!(
            warning.is_none(),
            "freelist_page_count=5 should not emit DatabaseVacuumed"
        );
    }

    // ── Test 2: selective_deletion_detected ──────────────────────────────────

    #[test]
    fn selective_deletion_detected() {
        // Message IDs [1, 2, 3, 100, 101, 102] in a single chat.
        // Gap 3→100 is 97 — much larger than median gap of 1.
        let mut result = make_empty_result();
        let ts_base = 1_710_513_000_000i64;
        let messages: Vec<Message> = [1i64, 2, 3, 100, 101, 102]
            .iter()
            .enumerate()
            .map(|(i, &id)| make_msg(id, 1, ts_base + (i as i64) * 1000))
            .collect();
        result.chats.push(Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages,
            archived: false,
        });

        let warnings = detect_selective_deletion(&result);
        assert!(
            !warnings.is_empty(),
            "gap 3→100 should trigger SelectiveDeletion warning"
        );
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ForensicWarning::SelectiveDeletion { .. })),
            "expected SelectiveDeletion variant"
        );
    }

    #[test]
    fn no_selective_deletion_for_contiguous_ids() {
        let mut result = make_empty_result();
        let ts_base = 1_710_513_000_000i64;
        let messages: Vec<Message> = (1..=10i64)
            .map(|id| make_msg(id, 1, ts_base + id * 1000))
            .collect();
        result.chats.push(Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages,
            archived: false,
        });

        let warnings = detect_selective_deletion(&result);
        assert!(
            warnings.is_empty(),
            "contiguous IDs should not trigger SelectiveDeletion"
        );
    }

    // ── Test 3: timestamp_anomaly_pre_whatsapp ────────────────────────────────

    #[test]
    fn timestamp_anomaly_pre_whatsapp() {
        // Timestamp 0 = 1970-01-01, before WhatsApp founding
        let mut result = make_empty_result();
        result.chats.push(Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![make_msg(1, 1, 0)],
            archived: false,
        });

        let warnings = detect_timestamp_anomalies(&result, 0);
        assert!(
            !warnings.is_empty(),
            "timestamp=0 (Unix epoch) should emit TimestampAnomaly"
        );
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ForensicWarning::TimestampAnomaly { message_row_id: 1, .. })),
            "expected TimestampAnomaly for message_row_id=1"
        );
    }

    #[test]
    fn no_anomaly_for_valid_timestamp() {
        let mut result = make_empty_result();
        // 2024-03-15 — a valid modern WhatsApp timestamp
        result.chats.push(Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![make_msg(1, 1, 1_710_513_127_000)],
            archived: false,
        });

        let warnings = detect_timestamp_anomalies(&result, 0);
        assert!(
            warnings.is_empty(),
            "valid 2024 timestamp should not emit TimestampAnomaly"
        );
    }
}
