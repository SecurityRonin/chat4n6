use crate::schema::SchemaVersion;
use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, ExtractionResult, ForensicTimestamp, MediaRef,
    Message, MessageContent, WalDelta,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

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

    // Map messages into chats.  If the chat record was deleted/unrecovered,
    // create a stub so forensically-recovered messages are never silently dropped.
    let msg_records = by_table.get("message").map(|v| v.as_slice()).unwrap_or(&[]);
    for rec in msg_records {
        if let Some(msg) = record_to_message(rec, &jid_map, tz_offset_secs) {
            chats
                .entry(msg.chat_id)
                .or_insert_with(|| Chat {
                    id: msg.chat_id,
                    jid: String::new(),
                    name: None,
                    is_group: false,
                    messages: Vec::new(),
                })
                .messages
                .push(msg);
        }
    }

    // ── Quoted messages ──────────────────────────────────────────────────
    // Build a map of message_row_id → (text, sender_jid, from_me, timestamp)
    // from the message_quoted table, then attach to parent messages.
    let quoted_records = by_table
        .get("message_quoted")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    let quoted_map = build_quoted_map(quoted_records, &jid_map, tz_offset_secs);

    for chat in chats.values_mut() {
        for msg in &mut chat.messages {
            if let Some(quoted) = quoted_map.get(&msg.id) {
                msg.quoted_message = Some(Box::new(quoted.clone()));
            }
        }
    }

    // Sort messages by timestamp within each chat
    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    // Map call records
    let call_records = by_table
        .get("call_log")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
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

/// WhatsApp message types that represent media content.
fn is_media_type(msg_type: i32) -> bool {
    matches!(msg_type, 1 | 2 | 3 | 8 | 13 | 20)
}

/// Fallback MIME type when the DB doesn't store one.
fn default_mime_for_type(msg_type: i32) -> &'static str {
    match msg_type {
        1 => "image/jpeg",
        2 => "audio/ogg",
        3 => "video/mp4",
        8 => "application/octet-stream",
        13 => "image/gif",
        20 => "image/webp",
        _ => "application/octet-stream",
    }
}

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
        let id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
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
        let id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
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
        map.insert(
            id,
            Chat {
                id,
                jid,
                name: subject,
                is_group,
                messages: Vec::new(),
            },
        );
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
    let media_mime = match r.values.get(7) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let media_name = match r.values.get(8) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let text_data = match r.values.get(5) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let content = if is_media_type(msg_type) {
        let mime = media_mime.unwrap_or_else(|| default_mime_for_type(msg_type).to_string());
        MessageContent::Media(MediaRef {
            file_path: media_name.unwrap_or_default(),
            mime_type: mime,
            file_size: 0,
            extracted_name: text_data, // caption stored as extracted_name
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        })
    } else if let Some(text) = text_data {
        MessageContent::Text(text)
    } else if msg_type == 0 || msg_type == 15 {
        // msg_type=0 with no text: revoked/deleted message
        // msg_type=15: tombstone placeholder row — purged message, row exists but content is empty
        MessageContent::Deleted
    } else {
        MessageContent::Unknown(msg_type)
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
/// [3]=video_call, [4]=duration, [5]=timestamp, [6]=call_result
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
    let call_result = match r.values.get(6) {
        Some(SqlValue::Int(n)) => CallResult::from(*n),
        _ => CallResult::Unknown,
    };
    Some(CallRecord {
        call_id: id,
        participants: vec![participant],
        from_me,
        video,
        group_call: false,
        duration_secs: duration,
        call_result,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        source: r.source.clone(),
    })
}

// ── Quoted message support ───────────────────────────────────────────────────

/// message_quoted: [0]=Null(_id), [1]=message_row_id, [2]=chat_row_id,
/// [3]=sender_jid_row_id, [4]=from_me, [5]=timestamp, [6]=text_data, [7]=message_type
fn build_quoted_map(
    records: &[&RecoveredRecord],
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
) -> HashMap<i64, Message> {
    let mut map = HashMap::new();
    for r in records {
        let msg_row_id = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let chat_id = match r.values.get(2) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let sender_jid = match r.values.get(3) {
            Some(SqlValue::Int(n)) => jid_map.get(n).cloned(),
            _ => None,
        };
        let from_me = match r.values.get(4) {
            Some(SqlValue::Int(n)) => *n != 0,
            _ => false,
        };
        let ts_ms = match r.values.get(5) {
            Some(SqlValue::Int(n)) => *n,
            _ => 0,
        };
        let msg_type = match r.values.get(7) {
            Some(SqlValue::Int(n)) => *n as i32,
            _ => 0,
        };
        let content = match r.values.get(6) {
            Some(SqlValue::Text(s)) if !s.is_empty() => MessageContent::Text(s.clone()),
            _ => {
                if msg_type == 0 {
                    MessageContent::Deleted
                } else {
                    MessageContent::Unknown(msg_type)
                }
            }
        };

        map.insert(
            msg_row_id,
            Message {
                id: r.row_id.unwrap_or(0),
                chat_id,
                sender_jid,
                from_me,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                content,
                reactions: Vec::new(),
                quoted_message: None,
                source: r.source.clone(),
                row_offset: r.offset,
            },
        );
    }
    map
}

// ── wa.db contact extraction ─────────────────────────────────────────────────

/// Extract contacts from wa.db bytes using the forensic B-tree walker.
/// wa_contacts table: [0]=Null(_id), [1]=jid, [2]=display_name, [3]=status, [4]=number
pub fn extract_contacts(wa_db_bytes: &[u8]) -> Result<Vec<Contact>> {
    let engine = ForensicEngine::new(wa_db_bytes, None)
        .context("failed to open wa.db")?;
    let records = engine.recover_layer1().context("wa.db layer 1 recovery")?;
    let by_table = partition_by_table(&records);
    let contact_records = by_table
        .get("wa_contacts")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let mut contacts = Vec::new();
    for r in contact_records {
        let jid = match r.values.get(1) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => continue,
        };
        let display_name = match r.values.get(2) {
            Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        let phone_number = match r.values.get(4) {
            Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        contacts.push(Contact {
            jid,
            display_name,
            phone_number,
            source: r.source.clone(),
        });
    }
    Ok(contacts)
}

/// Build a JID → display name lookup from extracted contacts.
pub fn build_contact_names(contacts: &[Contact]) -> HashMap<String, String> {
    contacts
        .iter()
        .filter_map(|c| {
            c.display_name
                .as_ref()
                .map(|name| (c.jid.clone(), name.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_modern_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extracts_messages() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert!(!result.chats.is_empty(), "should have at least one chat");
        let all_msgs: Vec<_> = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .collect();
        assert!(!all_msgs.is_empty(), "should have messages");
        assert!(
            all_msgs
                .iter()
                .any(|m| matches!(&m.content, MessageContent::Text(s) if s == "Hello there")),
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
        let chat1 = result
            .chats
            .iter()
            .find(|c| c.id == 1)
            .expect("chat 1 missing");
        // message 2 is received (from_me=0), sender_jid_row_id=1
        let received = chat1
            .messages
            .iter()
            .find(|m| !m.from_me)
            .expect("received msg");
        assert_eq!(
            received.sender_jid.as_deref(),
            Some("4155550100@s.whatsapp.net")
        );
    }

    // ── E4: call_result tests ────────────────────────────────────────────

    #[test]
    fn test_call_result_extraction() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1);
        // Fixture inserts call_result=1 (Connected)
        assert_eq!(result.calls[0].call_result, chat4n6_plugin_api::CallResult::Connected);
    }

    // ── E5: quoted message tests ─────────────────────────────────────────

    #[test]
    fn test_quoted_message_attached() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 2 ("Hi back!") quotes message 1 ("Hello there")
        let msg2 = chat1.messages.iter().find(|m| m.id == 2).expect("msg 2");
        assert!(
            msg2.quoted_message.is_some(),
            "message 2 should have a quoted message"
        );
        let quoted = msg2.quoted_message.as_ref().unwrap();
        assert!(
            matches!(&quoted.content, MessageContent::Text(s) if s == "Hello there"),
            "quoted content should be 'Hello there'"
        );
    }

    #[test]
    fn test_unquoted_message_has_none() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 1 is not quoted by anyone; it itself has no quoted_message
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(msg1.quoted_message.is_none());
    }

    // ── E3: contact extraction tests ─────────────────────────────────────

    fn make_wa_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE wa_contacts (
                _id INTEGER PRIMARY KEY,
                jid TEXT NOT NULL,
                display_name TEXT,
                status TEXT,
                number TEXT
            );
            INSERT INTO wa_contacts VALUES (1, '4155550100@s.whatsapp.net', 'Alice Smith', 'Hey!', '+14155550100');
            INSERT INTO wa_contacts VALUES (2, '4155550200@s.whatsapp.net', 'Bob Jones', '', '+14155550200');
            INSERT INTO wa_contacts VALUES (3, '120363001234567890@g.us', NULL, NULL, NULL);"
        ).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extract_contacts_from_wa_db() {
        let wa_db = make_wa_db();
        let contacts = extract_contacts(&wa_db).unwrap();
        assert!(contacts.len() >= 2, "should have at least 2 contacts with names");
        let alice = contacts
            .iter()
            .find(|c| c.jid == "4155550100@s.whatsapp.net")
            .expect("Alice missing");
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(alice.phone_number.as_deref(), Some("+14155550100"));
    }

    #[test]
    fn test_build_contact_names_map() {
        let contacts = vec![
            Contact {
                jid: "a@s.whatsapp.net".into(),
                display_name: Some("Alice".into()),
                phone_number: None,
                source: chat4n6_plugin_api::EvidenceSource::Live,
            },
            Contact {
                jid: "b@s.whatsapp.net".into(),
                display_name: None,
                phone_number: None,
                source: chat4n6_plugin_api::EvidenceSource::Live,
            },
        ];
        let map = build_contact_names(&contacts);
        assert_eq!(map.get("a@s.whatsapp.net"), Some(&"Alice".to_string()));
        assert!(!map.contains_key("b@s.whatsapp.net"));
    }

    // ── E8: media type mapping tests ────────────────────────────────────

    #[test]
    fn test_image_message_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 3: message_type=1 (image), media_mime_type='image/jpeg'
        let msg3 = chat1.messages.iter().find(|m| m.id == 3).expect("msg 3");
        match &msg3.content {
            MessageContent::Media(ref m) => {
                assert_eq!(m.mime_type, "image/jpeg");
                assert_eq!(m.file_path, "Media/WhatsApp Images/IMG-20240315-001.jpg");
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    #[test]
    fn test_audio_message_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 4: message_type=2 (audio)
        let msg4 = chat1.messages.iter().find(|m| m.id == 4).expect("msg 4");
        match &msg4.content {
            MessageContent::Media(ref m) => {
                assert!(m.mime_type.starts_with("audio/"));
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    #[test]
    fn test_video_with_caption_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat2 = result.chats.iter().find(|c| c.id == 2).expect("chat 2");
        // Message 5: message_type=3 (video), text_data='Check this' (caption)
        let msg5 = chat2.messages.iter().find(|m| m.id == 5).expect("msg 5");
        match &msg5.content {
            MessageContent::Media(ref m) => {
                assert_eq!(m.mime_type, "video/mp4");
                assert_eq!(m.extracted_name.as_deref(), Some("Check this"));
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    // ── F2: tombstone type-15 tests ──────────────────────────────────────

    #[test]
    fn test_tombstone_type15_creates_deleted() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 6 has message_type=15 (tombstone) — should produce MessageContent::Deleted
        let msg6 = chat1.messages.iter().find(|m| m.id == 6).expect("msg 6 (tombstone)");
        assert!(
            matches!(&msg6.content, MessageContent::Deleted),
            "msg_type=15 tombstone should produce MessageContent::Deleted, got {:?}",
            msg6.content
        );
    }

    #[test]
    fn test_tombstone_preserved_not_dropped() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Tombstone message must appear in results, not be silently dropped
        let tombstone = chat1.messages.iter().find(|m| m.id == 6);
        assert!(
            tombstone.is_some(),
            "tombstone message (id=6, type=15) must be preserved in extraction results"
        );
    }

    #[test]
    fn test_is_media_type_helper() {
        assert!(is_media_type(1));  // image
        assert!(is_media_type(2));  // audio
        assert!(is_media_type(3));  // video
        assert!(is_media_type(8));  // document
        assert!(is_media_type(13)); // gif
        assert!(is_media_type(20)); // sticker
        assert!(!is_media_type(0)); // text
        assert!(!is_media_type(7)); // system
    }

    #[test]
    fn test_text_message_unchanged() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg1.content, MessageContent::Text(s) if s == "Hello there"),
            "text messages should still be Text"
        );
    }
}
