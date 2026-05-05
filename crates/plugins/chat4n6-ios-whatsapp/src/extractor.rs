use crate::schema::{apple_epoch_to_utc_ms, default_mime_for_type, is_media_type, msg_type};
use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EvidenceSource, ExtractionResult, ForensicTimestamp,
    MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

/// Extract all forensic artifacts from a ChatStorage.sqlite byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
///
/// NOTE on column indices: the btree walker stores INTEGER PRIMARY KEY (Z_PK) as
/// SqlValue::Null at values[0]. Real column data starts at values[1].
///
/// ZWACHATSESSION: [0]=Null(Z_PK), [1]=ZARCHIVED, [2]=ZCONTACTIDENTIFIER,
///                 [3]=ZPARTNERNAME, [4]=ZLASTMESSAGEDATE, [5]=ZSESSIONTYPE
///
/// ZWAMESSAGE: [0]=Null(Z_PK), [1]=ZCHATSESSION, [2]=ZMESSAGEDATE,
///             [3]=ZTEXT, [4]=ZMESSAGETYPE, [5]=ZMEDIAITEM,
///             [6]=ZISFROMME, [7]=ZFROMJID, [8]=ZSTARRED,
///             [9]=ZISFORWARDED, [10]=ZDELETED
///
/// ZWAMEDIAITEM: [0]=Null(Z_PK), [1]=ZMESSAGE, [2]=ZMIMETYPE,
///               [3]=ZFILESIZE, [4]=ZLOCALPATH, [5]=ZMEDIAURL
///
/// ZWACONTACT: [0]=Null(Z_PK), [1]=ZABUSEIDENTIFIER, [2]=ZPHONENUMBER, [3]=ZFULLNAME
///
/// ZWACALLINFO: [0]=Null(Z_PK), [1]=ZCALLDATE, [2]=ZDURATION,
///              [3]=ZISVIDEOCALL, [4]=ZPARTNERCONTACT, [5]=ZCALLTYPE
pub fn extract_from_chatstorage(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open ChatStorage.sqlite")?;

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    // Partition by table name
    let by_table = partition_by_table(&records);

    // Build media item lookup: Z_PK → (mime_type, file_size, local_path, cdn_url)
    let media_map = build_media_map(
        by_table.get("ZWAMEDIAITEM").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    // Build chat sessions
    let mut chats: HashMap<i64, Chat> = HashMap::new();
    let session_records = by_table.get("ZWACHATSESSION").map(|v| v.as_slice()).unwrap_or(&[]);
    for r in session_records {
        if let Some(chat) = record_to_chat(r) {
            chats.insert(chat.id, chat);
        }
    }

    // Map messages into chats
    let msg_records = by_table.get("ZWAMESSAGE").map(|v| v.as_slice()).unwrap_or(&[]);
    for r in msg_records {
        if let Some(msg) = record_to_message(r, &media_map, tz_offset_secs) {
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

    // Sort messages by timestamp within each chat
    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    // Extract contacts
    let contacts = extract_contacts(
        by_table.get("ZWACONTACT").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    // Extract calls
    let calls = extract_calls(
        by_table.get("ZWACALLINFO").map(|v| v.as_slice()).unwrap_or(&[]),
        tz_offset_secs,
    );

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts,
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 32,
        forensic_warnings: Vec::new(),
        group_participant_events: Vec::new(),
    })
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn partition_by_table(records: &[RecoveredRecord]) -> HashMap<String, Vec<&RecoveredRecord>> {
    let mut map: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
    for r in records {
        map.entry(r.table.clone()).or_default().push(r);
    }
    map
}

/// Build media item lookup: Z_PK → MediaRef fields.
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

/// ZWACHATSESSION → Chat
fn record_to_chat(r: &RecoveredRecord) -> Option<Chat> {
    let id = r.row_id?;
    // [1]=ZARCHIVED, [2]=ZCONTACTIDENTIFIER, [3]=ZPARTNERNAME, [4]=ZLASTMESSAGEDATE, [5]=ZSESSIONTYPE
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

/// ZWAMESSAGE → Message
fn record_to_message(
    r: &RecoveredRecord,
    media_map: &HashMap<i64, MediaInfo>,
    tz_offset_secs: i32,
) -> Option<Message> {
    let id = r.row_id?;
    // [1]=ZCHATSESSION, [2]=ZMESSAGEDATE, [3]=ZTEXT, [4]=ZMESSAGETYPE,
    // [5]=ZMEDIAITEM, [6]=ZISFROMME, [7]=ZFROMJID, [8]=ZSTARRED,
    // [9]=ZISFORWARDED, [10]=ZDELETED
    let chat_id = match r.values.get(1)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let ts_ms = match r.values.get(2)? {
        SqlValue::Real(f) => apple_epoch_to_utc_ms(*f),
        SqlValue::Int(n) => apple_epoch_to_utc_ms(*n as f64),
        _ => return None,
    };
    let text = match r.values.get(3) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let msg_type_val = match r.values.get(4) {
        Some(SqlValue::Int(n)) => *n as i32,
        _ => 0,
    };
    let media_item_pk = match r.values.get(5) {
        Some(SqlValue::Int(n)) => Some(*n),
        _ => None,
    };
    let from_me = match r.values.get(6) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let sender_jid = match r.values.get(7) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let starred = match r.values.get(8) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let is_forwarded = match r.values.get(9) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let deleted = match r.values.get(10) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };

    let content = if deleted || msg_type_val == msg_type::DELETED {
        MessageContent::Deleted
    } else if msg_type_val == msg_type::SYSTEM {
        MessageContent::System(text.unwrap_or_default())
    } else if is_media_type(msg_type_val) {
        // Look up media item if we have a FK
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
            extracted_name: text, // caption if any
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
    // [1]=ZABUSEIDENTIFIER (JID), [2]=ZPHONENUMBER, [3]=ZFULLNAME
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
    // [1]=ZCALLDATE, [2]=ZDURATION, [3]=ZISVIDEOCALL, [4]=ZPARTNERCONTACT, [5]=ZCALLTYPE
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
                from_me: false, // iOS call log doesn't directly expose this field in ZWACALLINFO
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
