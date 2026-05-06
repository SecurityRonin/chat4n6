use anyhow::Result;
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, ExtractionResult, ForensicTimestamp, ForensicWarning,
    ForwardOrigin, ForwardOriginKind, MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::{HashMap, HashSet};

/// Extract all forensic artifacts from a Telegram cache.db byte slice.
///
/// Column layout (values[0] is always Null — INTEGER PRIMARY KEY alias):
///
///   users:    [0]=Null(uid), [1]=name
///   dialogs:  [0]=Null(did), [1]=date, [2]=last_mid
///   messages: [0]=Null(mid), [1]=uid, [2]=date, [3]=out, [4]=data,
///             [5]=send_state, [6]=read_state
///   media_v4: [0]=mid, [1]=uid, [2]=date, [3]=type, [4]=data  (no INTEGER PRIMARY KEY)
///   tgcalls:  [0]=Null(id), [1]=uid, [2]=date, [3]=out, [4]=duration, [5]=video
pub fn extract_from_telegram_db(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .map_err(|e| anyhow::anyhow!("failed to open Telegram cache.db: {e}"))?;

    let records = engine
        .recover_layer1()
        .map_err(|e| anyhow::anyhow!("Layer 1 recovery failed: {e}"))?;

    let by_table = partition_by_table(&records);

    // Build uid → name from users table
    let users_map = build_users_map(by_table.get("users").map(|v| v.as_slice()).unwrap_or(&[]));

    // Build media set: set of mid values that have a media_v4 row
    let media_mids = build_media_set(
        by_table
            .get("media_v4")
            .map(|v| v.as_slice())
            .unwrap_or(&[]),
    );

    // Process messages → grouped by uid (dialog ID)
    let mut chats: HashMap<i64, Chat> = HashMap::new();
    let msg_records = by_table
        .get("messages")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    for r in msg_records {
        let mid = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let uid = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let date_secs = match r.values.get(2) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let out = match r.values.get(3) {
            Some(SqlValue::Int(n)) => *n != 0,
            _ => false,
        };

        let from_me = out;
        // For incoming messages, resolve sender from users table using the dialog uid.
        // For 1:1 chats, the uid IS the peer's user ID.
        // For group chats (uid < 0), we don't have per-message sender info without
        // parsing the TLObject data blob, so leave None.
        let sender_jid: Option<String> = if from_me {
            None
        } else if uid > 0 {
            users_map.get(&uid).cloned()
        } else {
            None
        };

        let content = if media_mids.contains(&mid) {
            MessageContent::Media(MediaRef {
                file_path: String::new(),
                mime_type: "image/jpeg".to_string(),
                file_size: 0,
                extracted_name: None,
                thumbnail_b64: None,
                duration_secs: None,
                file_hash: None,
                encrypted_hash: None,
                cdn_url: None,
                media_key_b64: None,
            })
        } else {
            MessageContent::Text(String::new())
        };

        let msg = Message {
            id: mid,
            chat_id: uid,
            sender_jid,
            from_me,
            timestamp: ForensicTimestamp::from_millis(date_secs * 1000, tz_offset_secs),
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
        };

        let chat = chats.entry(uid).or_insert_with(|| {
            let name = users_map.get(&uid).cloned();
            let is_group = uid < 0;
            Chat {
                id: uid,
                jid: uid.to_string(),
                name,
                is_group,
                messages: Vec::new(),
                archived: false,
            }
        });
        chat.messages.push(msg);
    }

    // Process calls from tgcalls table
    let calls = build_calls(
        by_table
            .get("tgcalls")
            .map(|v| v.as_slice())
            .unwrap_or(&[]),
        &users_map,
        tz_offset_secs,
    );

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts: Vec::new(),
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 0,
        forensic_warnings: Vec::new(),
        group_participant_events: Vec::new(),
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
    })
}

fn partition_by_table(records: &[RecoveredRecord]) -> HashMap<String, Vec<&RecoveredRecord>> {
    let mut map: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
    for r in records {
        map.entry(r.table.clone()).or_default().push(r);
    }
    map
}

/// users table: [0]=Null(uid), [1]=name
fn build_users_map(records: &[&RecoveredRecord]) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    for r in records {
        let uid = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let name = match r.values.get(1) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => continue,
        };
        map.insert(uid, name);
    }
    map
}

/// Returns the set of `mid` values that have a corresponding media_v4 row.
///
/// media_v4 has NO INTEGER PRIMARY KEY — the implicit rowid is in `row_id`.
/// Column layout (values[] starts at first declared column):
///   [0]=mid, [1]=uid, [2]=date, [3]=type, [4]=data
fn build_media_set(records: &[&RecoveredRecord]) -> HashSet<i64> {
    let mut set = HashSet::new();
    for r in records {
        let mid = match r.values.get(0) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        set.insert(mid);
    }
    set
}

/// tgcalls: [0]=Null(id), [1]=uid, [2]=date, [3]=out, [4]=duration, [5]=video
fn build_calls(
    records: &[&RecoveredRecord],
    users_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
) -> Vec<CallRecord> {
    let mut calls = Vec::new();
    for r in records {
        let call_id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let uid = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let date_secs = match r.values.get(2) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let from_me = match r.values.get(3) {
            Some(SqlValue::Int(n)) => *n != 0,
            _ => false,
        };
        let duration = match r.values.get(4) {
            Some(SqlValue::Int(n)) => *n as u32,
            _ => 0,
        };
        let video = match r.values.get(5) {
            Some(SqlValue::Int(n)) => *n != 0,
            _ => false,
        };

        let participant = users_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string());

        calls.push(CallRecord {
            call_id,
            participants: vec![participant],
            from_me,
            video,
            group_call: false,
            duration_secs: duration,
            call_result: CallResult::Unknown,
            timestamp: ForensicTimestamp::from_millis(date_secs * 1000, tz_offset_secs),
            source: r.source.clone(),
            call_creator_device_jid: None,
        });
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_telegram_db(extra_sql: &str) -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/telegram_schema.sql"))
            .unwrap();
        if !extra_sql.is_empty() {
            conn.execute_batch(extra_sql).unwrap();
        }
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn telegram_extraction_produces_chats() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        assert!(!result.chats.is_empty(), "should have at least one chat");
        let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
        assert!(!all_msgs.is_empty(), "should have messages");
    }

    #[test]
    fn telegram_group_chat_is_group_true() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        let group = result.chats.iter().find(|c| c.id == -1000);
        assert!(group.is_some(), "group chat (uid=-1000) must exist");
        assert!(group.unwrap().is_group, "uid < 0 must be is_group=true");
    }

    #[test]
    fn telegram_private_chat_is_group_false() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        let private = result.chats.iter().find(|c| c.id == 100);
        assert!(private.is_some(), "private chat (uid=100) must exist");
        assert!(!private.unwrap().is_group, "uid > 0 must be is_group=false");
    }

    #[test]
    fn telegram_media_message_produces_media_content() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        // mid=5 has a media_v4 row (photo type=1)
        let media_msg = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 5);
        assert!(media_msg.is_some(), "message mid=5 must exist");
        assert!(
            matches!(&media_msg.unwrap().content, MessageContent::Media(_)),
            "mid=5 must produce MessageContent::Media"
        );
    }

    #[test]
    fn telegram_sender_jid_populated_from_users() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        // mid=2: incoming from Alice (uid=100, out=0)
        let msg2 = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 2);
        assert!(msg2.is_some(), "message mid=2 must exist");
        let msg2 = msg2.unwrap();
        assert!(!msg2.from_me, "mid=2 should be incoming");
        assert_eq!(
            msg2.sender_jid.as_deref(),
            Some("Alice Smith"),
            "sender_jid must be populated from users table"
        );
    }

    #[test]
    fn telegram_outgoing_message_from_me_true() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        // mid=1: outgoing (out=1)
        let msg1 = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 1);
        assert!(msg1.is_some(), "message mid=1 must exist");
        assert!(
            msg1.unwrap().from_me,
            "mid=1 should be outgoing (from_me=true)"
        );
    }

    #[test]
    fn forwarded_from_populates_origin_metadata() {
        // Build a DB with a forwarded message: fwd_from_id=99999 which IS in users table
        let db = make_telegram_db(
            "ALTER TABLE messages ADD COLUMN fwd_from_id INTEGER;
             ALTER TABLE messages ADD COLUMN fwd_from_name TEXT;
             ALTER TABLE messages ADD COLUMN fwd_date INTEGER;
             INSERT INTO users VALUES (99999, 'Channel X');
             INSERT INTO messages (mid, uid, date, out, data, send_state, read_state, fwd_from_id, fwd_from_name, fwd_date)
               VALUES (10, 100, 1710513127, 0, x'00', 0, 0, 99999, 'Channel X', 1700000000);",
        );
        let result = extract_from_telegram_db(&db, 0).unwrap();
        let msg = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 10)
            .expect("message mid=10 must exist");
        assert!(msg.is_forwarded, "mid=10 must be is_forwarded=true");
        let fwd = msg
            .forwarded_from
            .as_ref()
            .expect("forwarded_from must be Some");
        assert_eq!(fwd.origin_id, "99999", "origin_id must be fwd_from_id");
        assert_eq!(
            fwd.origin_name.as_deref(),
            Some("Channel X"),
            "origin_name must come from users table"
        );
        assert!(
            matches!(fwd.origin_kind, chat4n6_plugin_api::ForwardOriginKind::User),
            "fwd_from_id > 0 and in users → ForwardOriginKind::User"
        );
        let orig_ts = fwd
            .original_timestamp
            .as_ref()
            .expect("original_timestamp must be Some");
        assert_eq!(
            orig_ts.utc.timestamp(),
            1700000000,
            "original_timestamp must equal fwd_date"
        );
    }

    #[test]
    fn unresolved_forward_source_emitted_when_user_missing() {
        // fwd_from_id=12345 is NOT in users table → UnresolvedForwardSource warning
        let db = make_telegram_db(
            "ALTER TABLE messages ADD COLUMN fwd_from_id INTEGER;
             ALTER TABLE messages ADD COLUMN fwd_from_name TEXT;
             ALTER TABLE messages ADD COLUMN fwd_date INTEGER;
             INSERT INTO messages (mid, uid, date, out, data, send_state, read_state, fwd_from_id, fwd_from_name, fwd_date)
               VALUES (20, 100, 1710513127, 0, x'00', 0, 0, 12345, NULL, NULL);",
        );
        let result = extract_from_telegram_db(&db, 0).unwrap();
        let has_warning = result.forensic_warnings.iter().any(|w| {
            matches!(
                w,
                chat4n6_plugin_api::ForensicWarning::UnresolvedForwardSource {
                    message_id: 20,
                    forward_from_id: 12345
                }
            )
        });
        assert!(
            has_warning,
            "UnresolvedForwardSource {{ message_id: 20, forward_from_id: 12345 }} must be in forensic_warnings"
        );
        // The message should still have forwarded_from set with Unknown kind
        let msg = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 20)
            .expect("message mid=20 must exist");
        assert!(msg.is_forwarded, "mid=20 must be is_forwarded=true");
        let fwd = msg.forwarded_from.as_ref().expect("forwarded_from must be Some");
        assert!(
            matches!(fwd.origin_kind, chat4n6_plugin_api::ForwardOriginKind::Unknown),
            "unknown user → ForwardOriginKind::Unknown"
        );
    }

    #[test]
    fn telegram_calls_extracted() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        assert!(!result.calls.is_empty(), "should have at least one call");
        let call = &result.calls[0];
        assert!(call.from_me, "call should be outgoing (out=1)");
        assert_eq!(call.duration_secs, 65);
        assert!(!call.video, "call should not be video");
    }

    #[test]
    fn telegram_call_participant_from_users() {
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        assert!(!result.calls.is_empty());
        let call = &result.calls[0];
        assert!(
            call.participants.iter().any(|p| p == "Alice Smith"),
            "call participant must be resolved from users table"
        );
    }
}
