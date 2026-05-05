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
pub fn parse_sqlite_header(db_bytes: &[u8]) -> Option<(u32, u32)> {
    if db_bytes.len() < 40 {
        return None;
    }
    // Verify SQLite magic
    if &db_bytes[0..16] != b"SQLite format 3\0" {
        return None;
    }
    let page_size_raw = u16::from_be_bytes([db_bytes[16], db_bytes[17]]);
    let page_size: u32 = if page_size_raw == 1 { 65536 } else { page_size_raw as u32 };
    let freelist_count = u32::from_be_bytes([db_bytes[36], db_bytes[37], db_bytes[38], db_bytes[39]]);
    Some((page_size, freelist_count))
}

/// Detect VACUUM: if freelist_page_count == 0, the database may have been
/// VACUUMed, destroying deleted record remnants.
pub fn detect_vacuum(db_bytes: &[u8]) -> Option<ForensicWarning> {
    let (_page_size, freelist_count) = parse_sqlite_header(db_bytes)?;
    if freelist_count == 0 {
        Some(ForensicWarning::DatabaseVacuumed { freelist_page_count: 0 })
    } else {
        None
    }
}

/// Detect selective deletion by checking for suspicious ROWID gaps per chat.
/// A gap is suspicious if it is > 10× the median inter-message gap and > 10 rows.
pub fn detect_selective_deletion(result: &ExtractionResult) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();

    for chat in &result.chats {
        let mut ids: Vec<i64> = chat.messages.iter().map(|m| m.id).collect();
        if ids.len() < 3 {
            continue;
        }
        ids.sort_unstable();

        let gaps: Vec<i64> = ids.windows(2).map(|w| w[1] - w[0]).collect();

        // Median gap
        let mut sorted_gaps = gaps.clone();
        sorted_gaps.sort_unstable();
        let median = sorted_gaps[sorted_gaps.len() / 2];
        if median == 0 {
            continue;
        }

        // Count suspicious gaps (> 10× median, representing at least 10 missing messages)
        let suspicious_count = gaps.iter().filter(|&&g| g > 10 * median && g > 10).count();

        if suspicious_count > 0 {
            // Estimate deletion rate: total missing messages in suspicious gaps / span
            let total_span = ids.last().unwrap() - ids.first().unwrap();
            let missing: i64 = gaps
                .iter()
                .filter(|&&g| g > 10 * median && g > 10)
                .map(|&g| g - 1)
                .sum();
            let deletion_rate_pct = if total_span > 0 {
                ((missing * 100) / total_span).min(100) as u8
            } else {
                0
            };

            warnings.push(ForensicWarning::SelectiveDeletion {
                suspect_jid: chat.jid.clone(),
                deletion_rate_pct,
            });
        }
    }

    warnings
}

/// WhatsApp was founded 2009-01-01 in UTC. Any message timestamp before this
/// is forensically impossible on an authentic device.
pub const WHATSAPP_EPOCH_MS: i64 = 1_230_768_000_000;

/// Detect timestamp anomalies:
/// - timestamp before WhatsApp founding (2009-01-01)
/// - timestamp more than 1 day in the future (if reference_now_ms > 0)
pub fn detect_timestamp_anomalies(
    result: &ExtractionResult,
    reference_now_ms: i64,
) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();
    let one_day_ms: i64 = 86_400_000;
    let upper_bound = if reference_now_ms > 0 {
        reference_now_ms + one_day_ms
    } else {
        i64::MAX
    };

    for chat in &result.chats {
        for msg in &chat.messages {
            let ts_ms = msg.timestamp.utc.timestamp_millis();
            if ts_ms < WHATSAPP_EPOCH_MS {
                warnings.push(ForensicWarning::TimestampAnomaly {
                    message_row_id: msg.id,
                    description: format!(
                        "timestamp {} ms predates WhatsApp founding ({})",
                        ts_ms, WHATSAPP_EPOCH_MS
                    ),
                });
            } else if upper_bound != i64::MAX && ts_ms > upper_bound {
                warnings.push(ForensicWarning::TimestampAnomaly {
                    message_row_id: msg.id,
                    description: format!(
                        "timestamp {} ms is more than 1 day in the future (ref: {})",
                        ts_ms, reference_now_ms
                    ),
                });
            }
        }
    }
    warnings
}

/// Run all anti-forensics checks on an ExtractionResult.
///
/// `db_bytes` is the raw SQLite file (for header parsing).
/// `reference_now_ms` is Unix milliseconds for the upper timestamp bound
/// (0 = skip future-timestamp check).
pub fn analyse(
    result: &ExtractionResult,
    db_bytes: &[u8],
    reference_now_ms: i64,
) -> AntiForensicsReport {
    let mut warnings = Vec::new();

    if let Some(w) = detect_vacuum(db_bytes) {
        warnings.push(w);
    }
    warnings.extend(detect_selective_deletion(result));
    warnings.extend(detect_timestamp_anomalies(result, reference_now_ms));

    AntiForensicsReport { warnings }
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
