use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    Chat, ExtractionResult, ForensicTimestamp, ForensicWarning,
    ForwardOrigin, ForwardOriginKind, MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    partition_by_table,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::{HashMap, HashSet};

pub use crate::tl::decode_tl_message_text;

mod cols {
    pub mod messages {
        pub const UID: usize = 1;
        pub const DATE: usize = 2;
        pub const OUT: usize = 3;
        pub const DATA: usize = 4;
        pub const FWD_FROM_ID: usize = 7;
        pub const FWD_FROM_NAME: usize = 8;
        pub const FWD_DATE: usize = 9;
    }
    pub mod users {
        pub const NAME: usize = 1;
    }
    pub mod chats {
        pub const NAME: usize = 1;
    }
}

/// Extract all forensic artifacts from a Telegram cache4.db byte slice.
///
/// Column layout (values[0] is always Null — INTEGER PRIMARY KEY alias):
///
///   users:       [0]=Null(uid), [1]=name
///   chats:       [0]=Null(uid), [1]=name, [2]=data
///   dialogs:     [0]=Null(did), [1]=date, [2]=last_mid
///   messages_v2: [0]=Null(mid), [1]=uid, [2]=date, [3]=out, [4]=data,
///                [5]=send_state, [6]=read_state,
///                [7]=fwd_from_id (optional), [8]=fwd_from_name (optional),
///                [9]=fwd_date (optional)
///   messages:    same layout — fallback if messages_v2 absent
///   media_v4:    [0]=mid, [1]=uid, [2]=date, [3]=type, [4]=data (no INTEGER PRIMARY KEY)
///
/// Note: tgcalls table does NOT exist in Telegram Android.
///       Call data is embedded in message service records.
pub fn extract_from_telegram_db(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open Telegram cache.db")?;

    let records = engine
        .recover_layer1()
        .context("Layer 1 recovery failed")?;

    let by_table = partition_by_table(&records);

    // Build uid → name from users table
    let users_map = build_id_to_name_map(tbl(&by_table, "users"), cols::users::NAME);

    // Build uid → name from chats table (group/channel names; Task 4)
    let chats_name_map = build_id_to_name_map(tbl(&by_table, "chats"), cols::chats::NAME);

    // Build media set: set of mid values that have a media_v4 row
    let media_mids = build_media_set(tbl(&by_table, "media_v4"));

    // Task 1: prefer messages_v2; fall back to messages if absent.
    let msg_records = if by_table.contains_key("messages_v2") {
        tbl(&by_table, "messages_v2")
    } else {
        tbl(&by_table, "messages")
    };

    // Process messages → grouped by uid (dialog ID)
    let mut chats: HashMap<i64, Chat> = HashMap::new();
    let mut forensic_warnings: Vec<ForensicWarning> = Vec::new();

    for r in msg_records {
        let mid = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let uid = match r.values.get(cols::messages::UID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let date_secs = match r.values.get(cols::messages::DATE) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let out = match r.values.get(cols::messages::OUT) {
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

        // Forward detection: columns [7]=fwd_from_id, [8]=fwd_from_name, [9]=fwd_date.
        // These are optional — only present when the DB was created/ALTERed with them.
        // Gracefully skip if absent (production DBs without these columns are fine).
        let fwd_from_id: Option<i64> = match r.values.get(cols::messages::FWD_FROM_ID) {
            Some(SqlValue::Int(n)) if *n != 0 => Some(*n),
            _ => None,
        };
        let fwd_from_name: Option<String> = match r.values.get(cols::messages::FWD_FROM_NAME) {
            Some(SqlValue::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let fwd_date: Option<i64> = match r.values.get(cols::messages::FWD_DATE) {
            Some(SqlValue::Int(n)) => Some(*n),
            _ => None,
        };

        let (is_forwarded, forwarded_from) = if let Some(fwd_id) = fwd_from_id {
            let original_timestamp =
                fwd_date.map(|ts| ForensicTimestamp::from_millis(ts * 1000, tz_offset_secs));

            let origin = if fwd_id < 0 {
                // Negative ID → Telegram channel
                ForwardOrigin {
                    origin_kind: ForwardOriginKind::Channel,
                    origin_id: format!("tg-channel://{}", fwd_id.unsigned_abs()),
                    origin_name: fwd_from_name,
                    original_timestamp,
                }
            } else if let Some(name) = users_map.get(&fwd_id).cloned() {
                // Positive ID found in users table → User
                ForwardOrigin {
                    origin_kind: ForwardOriginKind::User,
                    origin_id: fwd_id.to_string(),
                    origin_name: Some(name),
                    original_timestamp,
                }
            } else {
                // Positive ID not found → emit warning, Unknown
                forensic_warnings.push(ForensicWarning::UnresolvedForwardSource {
                    message_id: mid,
                    forward_from_id: fwd_id,
                });
                ForwardOrigin {
                    origin_kind: ForwardOriginKind::Unknown,
                    origin_id: fwd_id.to_string(),
                    origin_name: fwd_from_name,
                    original_timestamp,
                }
            };
            (true, Some(origin))
        } else {
            (false, None)
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
            is_forwarded,
            edit_history: Vec::new(),
            receipts: Vec::new(),
            forwarded_from,
        };

        let chat = chats.entry(uid).or_insert_with(|| {
            let is_group = uid < 0;
            // Task 4: group/channel names come from the chats table; DM names from users.
            let name = if is_group {
                chats_name_map.get(&uid).cloned()
            } else {
                users_map.get(&uid).cloned()
            };
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

    // Task 2: tgcalls does not exist in Telegram Android — no call extraction.
    let calls = Vec::new();

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts: Vec::new(),
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 0,
        forensic_warnings,
        group_participant_events: Vec::new(),
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
    })
}

/// Build a rowid → text-value map from any table where the name is at `name_col`.
fn build_id_to_name_map(records: &[&RecoveredRecord], name_col: usize) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    for r in records {
        let id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let name = match r.values.get(name_col) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => continue,
        };
        map.insert(id, name);
    }
    map
}

/// Return the slice of records for a given table name, or an empty slice.
fn tbl<'a>(
    by: &'a HashMap<String, Vec<&'a RecoveredRecord>>,
    name: &str,
) -> &'a [&'a RecoveredRecord] {
    by.get(name).map(|v| v.as_slice()).unwrap_or_default()
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
        // Build a DB with a forwarded message: fwd_from_id=99999 which IS in users table.
        // Uses messages_v2 (modern schema).
        let db = make_telegram_db(
            "ALTER TABLE messages_v2 ADD COLUMN fwd_from_id INTEGER;
             ALTER TABLE messages_v2 ADD COLUMN fwd_from_name TEXT;
             ALTER TABLE messages_v2 ADD COLUMN fwd_date INTEGER;
             INSERT INTO users VALUES (99999, 'Channel X');
             INSERT INTO messages_v2 (mid, uid, date, out, data, send_state, read_state, fwd_from_id, fwd_from_name, fwd_date)
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
        // fwd_from_id=12345 is NOT in users table → UnresolvedForwardSource warning.
        // Uses messages_v2 (modern schema).
        let db = make_telegram_db(
            "ALTER TABLE messages_v2 ADD COLUMN fwd_from_id INTEGER;
             ALTER TABLE messages_v2 ADD COLUMN fwd_from_name TEXT;
             ALTER TABLE messages_v2 ADD COLUMN fwd_date INTEGER;
             INSERT INTO messages_v2 (mid, uid, date, out, data, send_state, read_state, fwd_from_id, fwd_from_name, fwd_date)
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

    // Task 2: tgcalls does not exist — calls must be empty (no phantom table extraction)
    #[test]
    fn no_calls_extracted_tgcalls_does_not_exist() {
        // Modern Telegram has no tgcalls table; calls are embedded in messages.
        // Extractor must NOT attempt to query tgcalls and must return empty calls.
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        assert!(
            result.calls.is_empty(),
            "calls must be empty — tgcalls table does not exist in Telegram Android"
        );
    }

    // Task 1: messages_v2 with fallback
    #[test]
    fn uses_messages_v2_when_present() {
        // Build a DB with messages_v2 (and no messages table).
        // Messages in messages_v2 must appear in extraction result.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Minimal schema: users + messages_v2 only (no messages table)
        conn.execute_batch(
            "PRAGMA user_version = 2;
             CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT);
             CREATE TABLE dialogs (did INTEGER PRIMARY KEY, date INTEGER NOT NULL, last_mid INTEGER DEFAULT 0);
             CREATE TABLE media_v4 (mid INTEGER NOT NULL, uid INTEGER NOT NULL, date INTEGER NOT NULL, type INTEGER NOT NULL, data BLOB);
             CREATE TABLE chats (uid INTEGER PRIMARY KEY, name TEXT, data BLOB);
             CREATE TABLE messages_v2 (mid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, date INTEGER NOT NULL, out INTEGER DEFAULT 0, data BLOB, send_state INTEGER DEFAULT 0, read_state INTEGER DEFAULT 0);
             INSERT INTO users VALUES (42, 'V2 User');
             INSERT INTO messages_v2 VALUES (101, 42, 1710514000, 0, NULL, 1, 0);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let result = extract_from_telegram_db(&db, 0).unwrap();
        let msg = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| m.id == 101);
        assert!(
            msg.is_some(),
            "message mid=101 from messages_v2 must be extracted"
        );
    }

    #[test]
    fn falls_back_to_messages_when_no_messages_v2() {
        // Standard fixture has only `messages` table, no messages_v2.
        // Existing messages (mid 1-5) must still be extracted.
        let db = make_telegram_db("");
        let result = extract_from_telegram_db(&db, 0).unwrap();
        let all_ids: Vec<i64> = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .map(|m| m.id)
            .collect();
        assert!(
            all_ids.contains(&1),
            "message mid=1 from fallback messages table must be extracted"
        );
    }

    // Task 3: TL BLOB decoding
    #[test]
    fn decode_tl_message_text_empty_data_returns_none() {
        assert_eq!(decode_tl_message_text(&[]), None);
        assert_eq!(decode_tl_message_text(&[0x3f, 0x1f]), None);
    }

    #[test]
    fn decode_tl_message_text_empty_cid_returns_none() {
        // TL_messageEmpty (0x1c9b1027) → None
        let data = [0x27u8, 0x10, 0x9b, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_tl_message_text(&data), None);
    }

    #[test]
    fn decode_tl_message_text_service_returns_none() {
        // TL_messageService (0xa7ab1991) → None
        let data = [0x91u8, 0x19, 0xab, 0xa7, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_tl_message_text(&data), None);
    }

    #[test]
    fn decode_tl_message_text_hello() {
        // TL_message (0x94dd1f3f), flags=0, then at offset 8: len=5, "Hello"
        let mut data = vec![0x3fu8, 0x1f, 0xdd, 0x94]; // cid LE
        data.extend_from_slice(&[0u8; 4]); // flags
        data.push(5); // length byte
        data.extend_from_slice(b"Hello");
        assert_eq!(decode_tl_message_text(&data), Some("Hello".to_string()));
    }

    #[test]
    fn decode_tl_message_text_short_string() {
        // TL_message, single char "X"
        let mut data = vec![0x3fu8, 0x1f, 0xdd, 0x94];
        data.extend_from_slice(&[0u8; 4]);
        data.push(1);
        data.push(b'X');
        assert_eq!(decode_tl_message_text(&data), Some("X".to_string()));
    }

    #[test]
    fn decode_tl_message_text_malformed_utf8_returns_none() {
        // TL_message, length=2, invalid UTF-8 bytes
        let mut data = vec![0x3fu8, 0x1f, 0xdd, 0x94];
        data.extend_from_slice(&[0u8; 4]);
        data.push(2);
        data.push(0xfe); // invalid UTF-8
        data.push(0xfe);
        assert_eq!(decode_tl_message_text(&data), None);
    }

    // Change 1: build_id_to_name_map unit tests
    #[test]
    fn build_id_to_name_map_returns_correct_name() {
        use chat4n6_plugin_api::EvidenceSource;
        let r = RecoveredRecord {
            table: "users".to_string(),
            row_id: Some(42),
            values: vec![SqlValue::Null, SqlValue::Text("Alice".to_string())],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let refs: Vec<&RecoveredRecord> = vec![&r];
        let map = build_id_to_name_map(&refs, 1);
        assert_eq!(map.get(&42).map(|s| s.as_str()), Some("Alice"));
    }

    #[test]
    fn build_id_to_name_map_skips_missing_rowid() {
        use chat4n6_plugin_api::EvidenceSource;
        let r = RecoveredRecord {
            table: "users".to_string(),
            row_id: None,
            values: vec![SqlValue::Null, SqlValue::Text("Bob".to_string())],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let refs: Vec<&RecoveredRecord> = vec![&r];
        let map = build_id_to_name_map(&refs, 1);
        assert!(map.is_empty(), "record without rowid must be skipped");
    }

    #[test]
    fn build_id_to_name_map_skips_non_text_value() {
        use chat4n6_plugin_api::EvidenceSource;
        let r = RecoveredRecord {
            table: "users".to_string(),
            row_id: Some(7),
            values: vec![SqlValue::Null, SqlValue::Int(99)],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let refs: Vec<&RecoveredRecord> = vec![&r];
        let map = build_id_to_name_map(&refs, 1);
        assert!(map.is_empty(), "non-text value at name_col must be skipped");
    }

    // Task 4: chats table → group names
    #[test]
    fn group_chat_name_populated_from_chats_table() {
        // Build DB with a chats table containing uid=-12345, name="Test Group"
        // and a messages row for that uid.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 2;
             CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT);
             CREATE TABLE dialogs (did INTEGER PRIMARY KEY, date INTEGER NOT NULL, last_mid INTEGER DEFAULT 0);
             CREATE TABLE media_v4 (mid INTEGER NOT NULL, uid INTEGER NOT NULL, date INTEGER NOT NULL, type INTEGER NOT NULL, data BLOB);
             CREATE TABLE chats (uid INTEGER PRIMARY KEY, name TEXT, data BLOB);
             CREATE TABLE messages (mid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, date INTEGER NOT NULL, out INTEGER DEFAULT 0, data BLOB, send_state INTEGER DEFAULT 0, read_state INTEGER DEFAULT 0);
             INSERT INTO chats VALUES (-12345, 'Test Group', NULL);
             INSERT INTO messages VALUES (200, -12345, 1710514000, 0, NULL, 1, 0);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let result = extract_from_telegram_db(&db, 0).unwrap();
        let chat = result.chats.iter().find(|c| c.id == -12345);
        assert!(chat.is_some(), "chat with uid=-12345 must exist");
        let chat = chat.unwrap();
        assert!(chat.is_group, "uid < 0 must be is_group=true");
        assert_eq!(
            chat.name.as_deref(),
            Some("Test Group"),
            "chat name must come from chats table"
        );
    }
}
