use crate::schema::{apple_date_to_unix_ms, cols_of, text_from_attributed_body, val};
use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    Chat, ExtractionResult, ForensicTimestamp, MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    partition_by_table,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

/// Extract chats, messages and handles from an iMessage `chat.db` / `sms.db`
/// byte slice. `tz_offset_secs` is seconds east of UTC for local-time display.
pub fn extract_from_chatdb(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine =
        ForensicEngine::new(db_bytes, Some(tz_offset_secs)).context("failed to open chat.db")?;
    let ddl_map = engine.table_ddl();
    let handle_cols = cols_of(&ddl_map, "handle");
    let chat_cols = cols_of(&ddl_map, "chat");
    let msg_cols = cols_of(&ddl_map, "message");
    let cmj_cols = cols_of(&ddl_map, "chat_message_join");
    let att_cols = cols_of(&ddl_map, "attachment");
    let maj_cols = cols_of(&ddl_map, "message_attachment_join");

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;
    let by_table = partition_by_table(&records);

    // handle ROWID → identifier (phone / email)
    let mut handle_map: HashMap<i64, String> = HashMap::new();
    for r in tbl(&by_table, "handle") {
        if let (Some(id), Some(SqlValue::Text(s))) = (r.row_id, val(r, &handle_cols, "id")) {
            handle_map.insert(id, s.clone());
        }
    }

    // message ROWID → chat ROWID (from chat_message_join)
    let mut msg_to_chat: HashMap<i64, i64> = HashMap::new();
    for r in tbl(&by_table, "chat_message_join") {
        let (Some(SqlValue::Int(chat_id)), Some(SqlValue::Int(msg_id))) = (
            val(r, &cmj_cols, "chat_id"),
            val(r, &cmj_cols, "message_id"),
        ) else {
            continue;
        };
        msg_to_chat.insert(*msg_id, *chat_id);
    }

    // attachment ROWID → MediaRef; message ROWID → [attachment ROWID]
    let mut att_map: HashMap<i64, MediaRef> = HashMap::new();
    for r in tbl(&by_table, "attachment") {
        if let Some(id) = r.row_id {
            att_map.insert(id, record_to_media(r, &att_cols));
        }
    }
    let mut msg_atts: HashMap<i64, Vec<i64>> = HashMap::new();
    for r in tbl(&by_table, "message_attachment_join") {
        let (Some(SqlValue::Int(msg_id)), Some(SqlValue::Int(att_id))) = (
            val(r, &maj_cols, "message_id"),
            val(r, &maj_cols, "attachment_id"),
        ) else {
            continue;
        };
        msg_atts.entry(*msg_id).or_default().push(*att_id);
    }

    // chat ROWID → Chat
    let mut chats: HashMap<i64, Chat> = HashMap::new();
    for r in tbl(&by_table, "chat") {
        if let Some(chat) = record_to_chat(r, &chat_cols) {
            chats.insert(chat.id, chat);
        }
    }

    // messages → chats
    for r in tbl(&by_table, "message") {
        let Some(id) = r.row_id else { continue };
        let chat_id = match msg_to_chat.get(&id) {
            Some(c) => *c,
            None => continue, // orphan message with no chat join — skip (kept out of a wrong chat)
        };
        let msg = record_to_message(r, id, chat_id, &msg_cols, &handle_map, &att_map, &msg_atts);
        chats
            .entry(chat_id)
            .or_insert_with(|| Chat {
                id: chat_id,
                jid: String::new(),
                name: None,
                is_group: false,
                messages: Vec::new(),
                archived: false,
            })
            .messages
            .push(msg);
    }

    // Deterministic total order: chats by id, messages by (timestamp, id).
    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| (m.timestamp.utc, m.id));
    }
    let mut chats_vec: Vec<Chat> = chats.into_values().collect();
    chats_vec.sort_by_key(|c| c.id);

    Ok(ExtractionResult {
        chats: chats_vec,
        timezone_offset_seconds: Some(tz_offset_secs),
        ..Default::default()
    })
}

fn record_to_chat(r: &RecoveredRecord, cols: &HashMap<String, usize>) -> Option<Chat> {
    let id = r.row_id?;
    let identifier = match val(r, cols, "chat_identifier") {
        Some(SqlValue::Text(s)) => s.clone(),
        _ => match val(r, cols, "guid") {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => String::new(),
        },
    };
    let name = match val(r, cols, "display_name") {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    // A group iMessage chat_identifier is a `chat<digits>` GUID; a 1:1 chat is a
    // phone/email. Group membership tables are not read in this pass.
    let is_group = identifier.starts_with("chat")
        && identifier.len() > 4
        && identifier[4..].chars().all(|c| c.is_ascii_digit());
    Some(Chat {
        id,
        jid: identifier,
        name,
        is_group,
        messages: Vec::new(),
        archived: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn record_to_message(
    r: &RecoveredRecord,
    id: i64,
    chat_id: i64,
    cols: &HashMap<String, usize>,
    handle_map: &HashMap<i64, String>,
    att_map: &HashMap<i64, MediaRef>,
    msg_atts: &HashMap<i64, Vec<i64>>,
) -> Message {
    let from_me = matches!(val(r, cols, "is_from_me"), Some(SqlValue::Int(n)) if *n != 0);
    let sender_jid = if from_me {
        None
    } else {
        match val(r, cols, "handle_id") {
            Some(SqlValue::Int(h)) => handle_map.get(h).cloned(),
            _ => None,
        }
    };
    let date = match val(r, cols, "date") {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };

    let text = match val(r, cols, "text") {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };

    let content = if let Some(att_ids) = msg_atts.get(&id) {
        // Attachment-bearing message: surface the first attachment's media.
        att_ids
            .iter()
            .find_map(|a| att_map.get(a).cloned())
            .map(MessageContent::Media)
            .unwrap_or_else(|| MessageContent::System("[attachment: metadata unavailable]".into()))
    } else if let Some(t) = text {
        MessageContent::Text(t)
    } else if let Some(SqlValue::Blob(b)) = val(r, cols, "attributedbody") {
        match text_from_attributed_body(b) {
            Some(t) if !t.is_empty() => MessageContent::Text(t),
            // A body we cannot decode is reported as such, never fabricated.
            _ => MessageContent::System(format!(
                "[attributedBody: {} bytes, text not decoded]",
                b.len()
            )),
        }
    } else {
        MessageContent::Deleted
    };

    Message {
        id,
        chat_id,
        sender_jid,
        from_me,
        timestamp: ForensicTimestamp::from_millis(apple_date_to_unix_ms(date), 0),
        content,
        reactions: Vec::new(),
        quoted_message: None,
        source: r.source.clone(),
        row_offset: r.offset,
        starred: false,
        forward_score: None,
        is_forwarded: false,
        edit_history: Vec::new(),
        receipts: Vec::new(),
        forwarded_from: None,
        composing_device: None,
    }
}

fn record_to_media(r: &RecoveredRecord, cols: &HashMap<String, usize>) -> MediaRef {
    let file_path = match val(r, cols, "filename") {
        Some(SqlValue::Text(s)) => s.clone(),
        _ => String::new(),
    };
    let mime_type = match val(r, cols, "mime_type") {
        Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
        _ => "application/octet-stream".to_string(),
    };
    let extracted_name = match val(r, cols, "transfer_name") {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let file_size = match val(r, cols, "total_bytes") {
        Some(SqlValue::Int(n)) if *n >= 0 => *n as u64,
        _ => 0,
    };
    MediaRef {
        file_path,
        mime_type,
        file_size,
        extracted_name,
        thumbnail_b64: None,
        duration_secs: None,
        file_hash: None,
        encrypted_hash: None,
        cdn_url: None,
        media_key_b64: None,
    }
}

/// Look up a table's recovered records; empty slice when the table is absent.
fn tbl<'a>(
    by: &'a HashMap<String, Vec<&'a RecoveredRecord>>,
    name: &str,
) -> &'a [&'a RecoveredRecord] {
    by.get(name).map(|v| v.as_slice()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chatdb() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, service TEXT, uncanonicalized_id TEXT);
            CREATE TABLE chat (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT, chat_identifier TEXT, service_name TEXT, display_name TEXT);
            CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT, text TEXT, handle_id INTEGER, service TEXT, date INTEGER, is_from_me INTEGER, cache_has_attachments INTEGER, attributedBody BLOB);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER, message_date INTEGER);
            CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, mime_type TEXT, transfer_name TEXT, total_bytes INTEGER);
            CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
            INSERT INTO handle VALUES (1, '+15551234567', 'iMessage', '+15551234567');
            INSERT INTO chat VALUES (1, 'iMessage;-;+15551234567', '+15551234567', 'iMessage', 'Alice');
            -- date 681609600000000000 ns since 2001 = 2022-08-08 UTC
            INSERT INTO message VALUES (10, 'G10', 'hello from alice', 1, 'iMessage', 681609600000000000, 0, 0, NULL);
            INSERT INTO message VALUES (11, 'G11', 'reply from me', NULL, 'iMessage', 681609601000000000, 1, 0, NULL);
            INSERT INTO chat_message_join VALUES (1, 10, 681609600000000000);
            INSERT INTO chat_message_join VALUES (1, 11, 681609601000000000);
        "#,
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extracts_chat_and_messages() {
        let result = extract_from_chatdb(&make_chatdb(), 0).unwrap();
        assert_eq!(result.chats.len(), 1, "one chat");
        let chat = &result.chats[0];
        assert_eq!(chat.jid, "+15551234567", "chat_identifier is the jid");
        assert_eq!(
            chat.name.as_deref(),
            Some("Alice"),
            "display_name is the name"
        );
        assert_eq!(chat.messages.len(), 2, "two messages");

        let m0 = &chat.messages[0];
        assert!(
            matches!(&m0.content, MessageContent::Text(t) if t == "hello from alice"),
            "incoming text resolved from the text column"
        );
        assert!(!m0.from_me);
        assert_eq!(
            m0.sender_jid.as_deref(),
            Some("+15551234567"),
            "incoming sender resolved via handle_id → handle.id"
        );
        assert_eq!(
            m0.timestamp.utc.format("%Y").to_string(),
            "2022",
            "Apple nanosecond date converts to 2022, not 2001/1970"
        );

        let m1 = &chat.messages[1];
        assert!(m1.from_me, "is_from_me=1 marks the outgoing message");
        assert!(matches!(&m1.content, MessageContent::Text(t) if t == "reply from me"));
        assert!(
            m1.sender_jid.is_none(),
            "outgoing message has no counterparty sender"
        );
    }

    /// Validation against a REAL `chat.db` with ground truth. Env-gated and
    /// `#[ignore]`d so CI (which lacks the corpus) skips it; run locally with
    /// `CHAT4N6_IMESSAGE_DB=/path/to/chat.db cargo test -p chat4n6-imessage -- --ignored`.
    /// The synthetic fixtures above cannot substitute for this: a parser tested
    /// only on data its author wrote inherits that author's blind spots.
    #[test]
    #[ignore = "requires CHAT4N6_IMESSAGE_DB pointing at a real chat.db (WAL checkpointed)"]
    fn validate_against_real_chatdb() {
        let Ok(path) = std::env::var("CHAT4N6_IMESSAGE_DB") else {
            eprintln!("CHAT4N6_IMESSAGE_DB unset — skipping real-data validation");
            return;
        };
        let bytes = std::fs::read(&path).expect("read real chat.db");
        let result = extract_from_chatdb(&bytes, 0).expect("extract real chat.db");
        let msgs: usize = result.chats.iter().map(|c| c.messages.len()).sum();
        let texts: usize = result
            .chats
            .iter()
            .flat_map(|c| &c.messages)
            .filter(|m| matches!(&m.content, MessageContent::Text(_)))
            .count();
        eprintln!(
            "real chat.db: {} chats, {} messages, {} with resolved text",
            result.chats.len(),
            msgs,
            texts
        );
        assert!(!result.chats.is_empty(), "real chat.db should yield chats");
        assert!(msgs > 0, "real chat.db should yield messages");
    }

    #[test]
    fn test_deterministic_repeatable() {
        let db = make_chatdb();
        let ids = |r: &ExtractionResult| -> Vec<i64> {
            r.chats
                .iter()
                .flat_map(|c| c.messages.iter().map(|m| m.id))
                .collect()
        };
        let a = extract_from_chatdb(&db, 0).unwrap();
        let b = extract_from_chatdb(&db, 0).unwrap();
        assert_eq!(ids(&a), vec![10, 11], "messages ordered by (timestamp, id)");
        assert_eq!(
            ids(&a),
            ids(&b),
            "two extractions of the same bytes agree exactly"
        );
    }
}
