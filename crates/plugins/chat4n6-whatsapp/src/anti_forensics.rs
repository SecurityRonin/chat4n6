//! Anti-forensics detection for WhatsApp msgstore.db.
//!
//! Detects evidence of tampering, selective deletion, timestamp anomalies,
//! and SQLite VACUUM operations that destroy deleted record remnants.

use chat4n6_plugin_api::{ExtractionResult, ForensicWarning};
use chrono::{DateTime, Utc};

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
        };
        let warnings = detect_timestamp_anomalies(&result);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::TimestampAnomaly { .. })),
            "reversed timestamps should emit TimestampAnomaly, got: {warnings:?}"
        );
    }
}
