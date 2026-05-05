use crate::schema::{apple_epoch_to_utc_ms, default_mime_for_type, is_media_type, msg_type};
use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EvidenceSource, ExtractionResult, ForensicTimestamp,
    ForensicWarning, MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

/// Extract all forensic artifacts from a ChatStorage.sqlite byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
pub fn extract_from_chatstorage(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open ChatStorage.sqlite")?;

    // Build dynamic column map from the actual schema DDL.
    // Falls back to the hardcoded default if the DDL is unavailable.
    let ddl_map = engine.table_ddl();
    let msg_col_map = ddl_map
        .get("ZWAMESSAGE")
        .map(|ddl| parse_column_positions(ddl))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(default_msg_column_map);

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    let by_table = partition_by_table(&records);

    let media_map = build_media_map(
        by_table.get("ZWAMEDIAITEM").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    let mut chats: HashMap<i64, Chat> = HashMap::new();
    let session_records = by_table.get("ZWACHATSESSION").map(|v| v.as_slice()).unwrap_or(&[]);
    for r in session_records {
        if let Some(chat) = record_to_chat(r) {
            chats.insert(chat.id, chat);
        }
    }

    let msg_records = by_table.get("ZWAMESSAGE").map(|v| v.as_slice()).unwrap_or(&[]);

    // Collect ZSORT values per chat for gap-based selective deletion detection.
    let zsort_idx = msg_col_map.get("ZSORT").copied().unwrap_or(11);
    let chat_id_idx = msg_col_map.get("ZCHATSESSION").copied().unwrap_or(1);
    let mut zsort_by_chat: HashMap<i64, Vec<f64>> = HashMap::new();
    for r in msg_records {
        let chat_id = match r.values.get(chat_id_idx) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let zsort = match r.values.get(zsort_idx) {
            Some(SqlValue::Real(f)) => *f,
            Some(SqlValue::Int(n)) => *n as f64,
            _ => continue,
        };
        zsort_by_chat.entry(chat_id).or_default().push(zsort);
    }

    for r in msg_records {
        if let Some(msg) = record_to_message(r, &media_map, tz_offset_secs, &msg_col_map) {
            chats
                .entry(msg.chat_id)
                .or_insert_with(|| Chat {
                    id: msg.chat_id,
                    jid: String::new(),
                    name: None,
                    is_group: false,
                    messages: Vec::new(),
                    archived: false,
                })
                .messages
                .push(msg);
        }
    }

    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    let contacts = extract_contacts(
        by_table.get("ZWACONTACT").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    let calls = extract_calls(
        by_table.get("ZWACALLINFO").map(|v| v.as_slice()).unwrap_or(&[]),
        tz_offset_secs,
    );

    let forensic_warnings = detect_zsort_gaps(&zsort_by_chat, &chats);

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts,
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 32,
        forensic_warnings,
        group_participant_events: Vec::new(),
    })
}

// ── Column map ────────────────────────────────────────────────────────────────

/// Parse column positions from a CREATE TABLE DDL statement.
/// Returns column_name (uppercase) → values-array index.
/// Z_PK (INTEGER PRIMARY KEY) is included at index 0 (stored as Null by the btree walker).
fn parse_column_positions(ddl: &str) -> HashMap<String, usize> {
    let start = ddl.find('(').map(|i| i + 1).unwrap_or(0);
    let end = ddl.rfind(')').unwrap_or(ddl.len());
    let block = &ddl[start..end];

    let mut map = HashMap::new();
    let mut idx = 0usize;

    for part in block.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let upper = part.to_uppercase();
        // Skip table-level constraints — they don't consume a values slot.
        if upper.starts_with("PRIMARY")
            || upper.starts_with("UNIQUE")
            || upper.starts_with("CHECK")
            || upper.starts_with("FOREIGN")
            || upper.starts_with("CONSTRAINT")
        {
            continue;
        }
        if let Some(col_name) = part.split_whitespace().next() {
            map.insert(col_name.to_uppercase(), idx);
        }
        idx += 1;
    }

    map
}

/// Hardcoded fallback for the standard ZWAMESSAGE schema.
fn default_msg_column_map() -> HashMap<String, usize> {
    [
        ("Z_PK", 0),
        ("ZCHATSESSION", 1),
        ("ZMESSAGEDATE", 2),
        ("ZTEXT", 3),
        ("ZMESSAGETYPE", 4),
        ("ZMEDIAITEM", 5),
        ("ZISFROMME", 6),
        ("ZFROMJID", 7),
        ("ZSTARRED", 8),
        ("ZISFORWARDED", 9),
        ("ZDELETED", 10),
        ("ZSORT", 11),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), *v))
    .collect()
}

// ── ZSORT gap detection ───────────────────────────────────────────────────────

/// Detect selective deletion by analysing ZSORT sequence gaps per chat.
/// Emits SelectiveDeletion when a gap is >5× the median gap and ≥10 units.
fn detect_zsort_gaps(
    zsort_by_chat: &HashMap<i64, Vec<f64>>,
    chats: &HashMap<i64, Chat>,
) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();
    for (chat_id, zsort_vals) in zsort_by_chat {
        if zsort_vals.len() < 3 {
            continue;
        }
        let mut sorted = zsort_vals.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let gaps: Vec<f64> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
        let mut sorted_gaps = gaps.clone();
        sorted_gaps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_gap = sorted_gaps[sorted_gaps.len() / 2];
        let threshold = (median_gap * 5.0).max(10.0);
        let suspicious: Vec<_> = gaps.iter().filter(|&&g| g > threshold).collect();
        if !suspicious.is_empty() {
            let suspect_jid = chats
                .get(chat_id)
                .map(|c| c.jid.clone())
                .unwrap_or_default();
            if suspect_jid.is_empty() {
                continue;
            }
            let deletion_rate_pct = ((suspicious.len() * 100) / gaps.len()).min(100) as u8;
            warnings.push(ForensicWarning::SelectiveDeletion {
                suspect_jid,
                deletion_rate_pct,
            });
        }
    }
    warnings
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn partition_by_table(records: &[RecoveredRecord]) -> HashMap<String, Vec<&RecoveredRecord>> {
    let mut map: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
    for r in records {
        map.entry(r.table.clone()).or_default().push(r);
    }
    map
}

struct MediaInfo {
    mime_type: String,
    file_size: u64,
    local_path: String,
    cdn_url: Option<String>,
}

fn build_media_map(records: &[&RecoveredRecord]) -> HashMap<i64, MediaInfo> {
    let mut map = HashMap::new();
    for r in records {
        let Some(pk) = r.row_id else { continue };
        let mime = match r.values.get(2) {
            Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
            _ => "application/octet-stream".to_string(),
        };
        let file_size = match r.values.get(3) {
            Some(SqlValue::Int(n)) => *n as u64,
            _ => 0,
        };
        let local_path = match r.values.get(4) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let cdn_url = match r.values.get(5) {
            Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        map.insert(pk, MediaInfo { mime_type: mime, file_size, local_path, cdn_url });
    }
    map
}

/// ZWACHATSESSION → Chat (hardcoded — this table schema is stable).
fn record_to_chat(r: &RecoveredRecord) -> Option<Chat> {
    let id = r.row_id?;
    let archived = match r.values.get(1) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let jid = match r.values.get(2) {
        Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
        _ => return None,
    };
    let name = match r.values.get(3) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let is_group = match r.values.get(5) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    Some(Chat { id, jid, name, is_group, messages: Vec::new(), archived })
}

/// ZWAMESSAGE → Message using a dynamic column map.
fn record_to_message(
    r: &RecoveredRecord,
    media_map: &HashMap<i64, MediaInfo>,
    tz_offset_secs: i32,
    col: &HashMap<String, usize>,
) -> Option<Message> {
    let id = r.row_id?;

    let get_int = |name: &str| -> Option<i64> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Int(n) => Some(*n),
            _ => None,
        }
    };
    let get_real = |name: &str| -> Option<f64> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Real(f) => Some(*f),
            SqlValue::Int(n) => Some(*n as f64),
            _ => None,
        }
    };
    let get_text = |name: &str| -> Option<String> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Text(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    };

    let chat_id = get_int("ZCHATSESSION")?;
    let ts_ms = get_real("ZMESSAGEDATE").map(apple_epoch_to_utc_ms)?;
    let text = get_text("ZTEXT");
    let msg_type_val = get_int("ZMESSAGETYPE").unwrap_or(0) as i32;
    let media_item_pk = get_int("ZMEDIAITEM");
    let from_me = get_int("ZISFROMME").unwrap_or(0) != 0;
    let sender_jid = get_text("ZFROMJID");
    let starred = get_int("ZSTARRED").unwrap_or(0) != 0;
    let is_forwarded = get_int("ZISFORWARDED").unwrap_or(0) != 0;
    let deleted = get_int("ZDELETED").unwrap_or(0) != 0;

    let content = if deleted || msg_type_val == msg_type::DELETED {
        MessageContent::Deleted
    } else if msg_type_val == msg_type::SYSTEM {
        MessageContent::System(text.unwrap_or_default())
    } else if is_media_type(msg_type_val) {
        let media_info = media_item_pk.and_then(|pk| media_map.get(&pk));
        let mime = media_info
            .map(|m| m.mime_type.clone())
            .unwrap_or_else(|| default_mime_for_type(msg_type_val).to_string());
        let file_size = media_info.map(|m| m.file_size).unwrap_or(0);
        let file_path = media_info.map(|m| m.local_path.clone()).unwrap_or_default();
        let cdn_url = media_info.and_then(|m| m.cdn_url.clone());
        MessageContent::Media(MediaRef {
            file_path,
            mime_type: mime,
            file_size,
            extracted_name: text,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url,
            media_key_b64: None,
        })
    } else if let Some(t) = text {
        MessageContent::Text(t)
    } else {
        MessageContent::Unknown(msg_type_val)
    };

    Some(Message {
        id,
        chat_id,
        sender_jid,
        from_me,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        content,
        reactions: Vec::new(),
        quoted_message: None,
        source: r.source.clone(),
        row_offset: r.offset,
        starred,
        forward_score: None,
        is_forwarded,
        edit_history: Vec::new(),
        receipts: Vec::new(),
    })
}

/// ZWACONTACT → Contact
fn extract_contacts(records: &[&RecoveredRecord]) -> Vec<Contact> {
    records
        .iter()
        .filter_map(|r| {
            let jid = match r.values.get(1) {
                Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
                _ => return None,
            };
            let phone_number = match r.values.get(2) {
                Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
            let display_name = match r.values.get(3) {
                Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
            Some(Contact {
                jid,
                display_name,
                phone_number,
                source: r.source.clone(),
            })
        })
        .collect()
}

/// ZWACALLINFO → CallRecord
fn extract_calls(records: &[&RecoveredRecord], tz_offset_secs: i32) -> Vec<CallRecord> {
    records
        .iter()
        .filter_map(|r| {
            let call_id = r.row_id?;
            let ts_ms = match r.values.get(1)? {
                SqlValue::Real(f) => apple_epoch_to_utc_ms(*f),
                SqlValue::Int(n) => apple_epoch_to_utc_ms(*n as f64),
                _ => return None,
            };
            let duration_secs = match r.values.get(2) {
                Some(SqlValue::Int(n)) => *n as u32,
                _ => 0,
            };
            let video = match r.values.get(3) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            Some(CallRecord {
                call_id,
                participants: Vec::new(),
                from_me: false,
                video,
                group_call: false,
                duration_secs,
                call_result: CallResult::Unknown,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                source: EvidenceSource::Live,
                call_creator_device_jid: None,
            })
        })
        .collect()
}
