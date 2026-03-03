use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, Chat, ExtractionResult, ForensicTimestamp, Message,
    MessageContent, WalDelta,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;
use crate::schema::SchemaVersion;

/// Extract all forensic artifacts from a msgstore.db byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
///
/// NOTE on column indices: the btree walker stores INTEGER PRIMARY KEY as
/// SqlValue::Null at values[0].  Real column data starts at values[1].
/// Schema layout (zero-based values[] index, after the leading Null):
///
///   jid:      [0]=Null(_id), [1]=raw_string
///   chat:     [0]=Null(_id), [1]=jid_row_id, [2]=subject
///   message:  [0]=Null(_id), [1]=chat_row_id, [2]=sender_jid_row_id,
///             [3]=from_me,   [4]=timestamp,   [5]=text_data, [6]=message_type
///   call_log: [0]=Null(_id), [1]=jid_row_id,  [2]=from_me,
///             [3]=video_call,[4]=duration,     [5]=timestamp
pub fn extract_from_msgstore(
    db_bytes: &[u8],
    tz_offset_secs: i32,
    _schema_version: SchemaVersion,
) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open msgstore.db")?;

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    // Partition by table
    let by_table = partition_by_table(&records);

    // Build JID lookup: id → raw_string
    let jid_map = build_jid_map(by_table.get("jid").map(|v| v.as_slice()).unwrap_or(&[]));

    // Build chat map: chat_id → Chat (populated with messages below)
    let mut chats = build_chats(
        by_table.get("chat").map(|v| v.as_slice()).unwrap_or(&[]),
        &jid_map,
    );

    // Map messages into chats
    let msg_records = by_table.get("message").map(|v| v.as_slice()).unwrap_or(&[]);
    for rec in msg_records {
        if let Some(msg) = record_to_message(rec, &jid_map, tz_offset_secs) {
            if let Some(chat) = chats.get_mut(&msg.chat_id) {
                chat.messages.push(msg);
            }
        }
    }

    // Sort messages by timestamp within each chat
    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    // Map call records
    let call_records = by_table.get("call_log").map(|v| v.as_slice()).unwrap_or(&[]);
    let calls: Vec<CallRecord> = call_records
        .iter()
        .filter_map(|r| record_to_call(r, &jid_map, tz_offset_secs))
        .collect();

    // WAL deltas (placeholder — WAL integration in CLI layer)
    let wal_deltas: Vec<WalDelta> = Vec::new();

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts: Vec::new(),
        calls,
        wal_deltas,
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 200,
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

/// jid table: row_id=_id, values[0]=Null(_id alias), values[1]=raw_string
fn build_jid_map(records: &[&RecoveredRecord]) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    for r in records {
        let id = match r.row_id { Some(id) => id, None => continue };
        let raw = match r.values.get(1) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => continue,
        };
        map.insert(id, raw);
    }
    map
}

/// chat table: row_id=_id, values[0]=Null, [1]=jid_row_id, [2]=subject
fn build_chats(records: &[&RecoveredRecord], jid_map: &HashMap<i64, String>) -> HashMap<i64, Chat> {
    let mut map = HashMap::new();
    for r in records {
        let id = match r.row_id { Some(id) => id, None => continue };
        let jid_row_id = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let jid = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
        let subject = match r.values.get(2) {
            Some(SqlValue::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let is_group = subject.is_some();
        map.insert(id, Chat { id, jid, name: subject, is_group, messages: Vec::new() });
    }
    map
}

/// message table: row_id=_id, values[0]=Null, [1]=chat_row_id,
/// [2]=sender_jid_row_id, [3]=from_me, [4]=timestamp, [5]=text_data, [6]=message_type
fn record_to_message(
    r: &RecoveredRecord,
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
) -> Option<Message> {
    let id = r.row_id?;
    let chat_id = match r.values.get(1)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let sender_jid = match r.values.get(2) {
        Some(SqlValue::Int(n)) => jid_map.get(n).cloned(),
        _ => None,
    };
    let from_me = match r.values.get(3) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let ts_ms = match r.values.get(4)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let msg_type = match r.values.get(6) {
        Some(SqlValue::Int(n)) => *n as i32,
        _ => 0,
    };
    let content = match r.values.get(5) {
        Some(SqlValue::Text(s)) if !s.is_empty() => MessageContent::Text(s.clone()),
        _ => if msg_type == 0 { MessageContent::Deleted } else { MessageContent::Unknown(msg_type) },
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
    })
}

/// call_log: row_id=_id, values[0]=Null, [1]=jid_row_id, [2]=from_me,
/// [3]=video_call, [4]=duration, [5]=timestamp
fn record_to_call(
    r: &RecoveredRecord,
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
) -> Option<CallRecord> {
    let id = r.row_id?;
    let jid_row_id = match r.values.get(1)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let participant = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
    let from_me = match r.values.get(2) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let video = match r.values.get(3) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let duration = match r.values.get(4) {
        Some(SqlValue::Int(n)) => *n as u32,
        _ => 0,
    };
    let ts_ms = match r.values.get(5)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    Some(CallRecord {
        call_id: id,
        participants: vec![participant],
        from_me,
        video,
        group_call: false,
        duration_secs: duration,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        source: r.source.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_modern_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extracts_messages() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert!(!result.chats.is_empty(), "should have at least one chat");
        let all_msgs: Vec<_> = result.chats.iter()
            .flat_map(|c| c.messages.iter()).collect();
        assert!(!all_msgs.is_empty(), "should have messages");
        assert!(
            all_msgs.iter().any(|m| matches!(&m.content, MessageContent::Text(s) if s == "Hello there")),
            "should contain text message 'Hello there'"
        );
    }

    #[test]
    fn test_extracts_call_records() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1, "should have 1 call record");
        assert!(result.calls[0].from_me);
        assert!(!result.calls[0].video);
        assert_eq!(result.calls[0].duration_secs, 120);
    }

    #[test]
    fn test_timezone_offset_preserved() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 8 * 3600, SchemaVersion::Modern).unwrap();
        assert_eq!(result.timezone_offset_seconds, Some(8 * 3600));
    }

    #[test]
    fn test_sender_jid_resolved() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1 missing");
        // message 2 is received (from_me=0), sender_jid_row_id=1
        let received = chat1.messages.iter().find(|m| !m.from_me).expect("received msg");
        assert_eq!(received.sender_jid.as_deref(), Some("4155550100@s.whatsapp.net"));
    }
}
