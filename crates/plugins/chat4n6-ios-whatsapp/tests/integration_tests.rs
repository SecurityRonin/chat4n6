use chat4n6_ios_whatsapp::{
    extractor::extract_from_chatstorage,
    IosWhatsAppPlugin, DB_PATH, DB_ALT_PATH,
};
use chat4n6_plugin_api::{ForensicFs, ForensicPlugin, FsEntry, MessageContent, UnallocatedRegion};
use std::collections::HashMap;

// ── MockFs ────────────────────────────────────────────────────────────────────

struct MockFs {
    files: HashMap<String, Vec<u8>>,
}

impl MockFs {
    fn new() -> Self {
        Self { files: HashMap::new() }
    }
    fn add(mut self, path: &str, data: Vec<u8>) -> Self {
        self.files.insert(path.to_string(), data);
        self
    }
}

impl ForensicFs for MockFs {
    fn list(&self, _: &str) -> anyhow::Result<Vec<FsEntry>> { Ok(vec![]) }
    fn read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not found: {path}"))
    }
    fn exists(&self, path: &str) -> bool { self.files.contains_key(path) }
    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> { vec![] }
}

// ── Fixture builder ───────────────────────────────────────────────────────────

fn make_chatstorage_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("fixtures/chatstorage_schema.sql")).unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

// ── T1: detect() true when ChatStorage.sqlite exists ─────────────────────────

#[test]
fn test_detect_true_primary_path() {
    let db = make_chatstorage_db();
    let fs = MockFs::new().add(DB_PATH, db);
    let plugin = IosWhatsAppPlugin;
    assert!(plugin.detect(&fs), "detect() should be true when primary path exists");
}

// ── T2: detect() true for alternate path ─────────────────────────────────────

#[test]
fn test_detect_true_alt_path() {
    let db = make_chatstorage_db();
    let fs = MockFs::new().add(DB_ALT_PATH, db);
    let plugin = IosWhatsAppPlugin;
    assert!(plugin.detect(&fs), "detect() should be true for alt path");
}

// ── T3: detect() false when no iOS WA file ───────────────────────────────────

#[test]
fn test_detect_false_no_file() {
    let fs = MockFs::new();
    let plugin = IosWhatsAppPlugin;
    assert!(!plugin.detect(&fs), "detect() should be false when no file present");
}

// ── T4: chat count matches fixture (3 chats) ─────────────────────────────────

#[test]
fn test_chat_count() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");
    assert_eq!(result.chats.len(), 3, "should have exactly 3 chats");
}

// ── T5: archived chat has archived=true ──────────────────────────────────────

#[test]
fn test_archived_chat() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let archived_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550101@s.whatsapp.net")
        .expect("Bob's chat should exist");
    assert!(archived_chat.archived, "Bob's chat (ZARCHIVED=1) should be archived=true");
}

// ── T6: group chat has is_group=true ─────────────────────────────────────────

#[test]
fn test_group_chat_is_group() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let group = result
        .chats
        .iter()
        .find(|c| c.jid == "groupabc@g.us")
        .expect("group chat should exist");
    assert!(group.is_group, "ZSESSIONTYPE=1 should map to is_group=true");
}

// ── T7: sent message from_me=true ────────────────────────────────────────────

#[test]
fn test_sent_message_from_me() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg1 = alice_chat.messages.iter().find(|m| m.id == 1).expect("message 1");
    assert!(msg1.from_me, "ZISFROMME=1 should map to from_me=true");
}

// ── T8: received message from_me=false + sender_jid set ──────────────────────

#[test]
fn test_received_message_sender_jid() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg2 = alice_chat.messages.iter().find(|m| m.id == 2).expect("message 2");
    assert!(!msg2.from_me, "ZISFROMME=0 should map to from_me=false");
    assert_eq!(
        msg2.sender_jid.as_deref(),
        Some("4155550100@s.whatsapp.net"),
        "ZFROMJID should be preserved in sender_jid"
    );
}

// ── T9: deleted message → MessageContent::Deleted ────────────────────────────

#[test]
fn test_deleted_message_content() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg4 = alice_chat.messages.iter().find(|m| m.id == 4).expect("message 4 (deleted)");
    assert!(
        matches!(&msg4.content, MessageContent::Deleted),
        "ZDELETED=1 should produce MessageContent::Deleted, got {:?}",
        msg4.content
    );
}

// ── T10: media message → MessageContent::Media with correct mime ──────────────

#[test]
fn test_media_message_content() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg3 = alice_chat.messages.iter().find(|m| m.id == 3).expect("message 3 (media)");
    match &msg3.content {
        MessageContent::Media(ref m) => {
            assert_eq!(m.mime_type, "image/jpeg", "ZWAMEDIAITEM.ZMIMETYPE should map to mime_type");
            assert_eq!(m.file_size, 204800, "ZWAMEDIAITEM.ZFILESIZE should map to file_size");
        }
        other => panic!("expected MessageContent::Media, got {:?}", other),
    }
}

// ── T11: starred message → starred=true ──────────────────────────────────────

#[test]
fn test_starred_message() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg5 = alice_chat.messages.iter().find(|m| m.id == 5).expect("message 5 (starred)");
    assert!(msg5.starred, "ZSTARRED=1 should map to starred=true");
}

// ── T12: timestamp conversion from Apple epoch to UTC ────────────────────────

#[test]
fn test_apple_epoch_conversion() {
    // Apple epoch 732205927.0 → unix ms = (732205927 + 978307200) * 1000 = 1710513127000
    // = 2024-03-15T14:32:07Z
    use chat4n6_ios_whatsapp::schema::apple_epoch_to_utc_ms;
    let ms = apple_epoch_to_utc_ms(732205927.0);
    assert_eq!(ms, 1_710_513_127_000_i64, "Apple epoch → unix ms conversion incorrect");
}

#[test]
fn test_message_timestamp_utc_str() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    let msg1 = alice_chat.messages.iter().find(|m| m.id == 1).expect("message 1");
    assert_eq!(
        msg1.timestamp.utc_str(),
        "2024-03-15 14:32:07 UTC",
        "timestamp UTC string incorrect"
    );
}

// ── T13: contact extraction ───────────────────────────────────────────────────

#[test]
fn test_contact_extraction() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    assert_eq!(result.contacts.len(), 1, "should have 1 contact");
    let alice = &result.contacts[0];
    assert_eq!(alice.jid, "4155550100@s.whatsapp.net");
    assert_eq!(alice.phone_number.as_deref(), Some("+14155550100"));
    assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
}

// ── T14: call extraction with correct duration ────────────────────────────────

#[test]
fn test_call_extraction() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    assert_eq!(result.calls.len(), 1, "should have 1 call record");
    let call = &result.calls[0];
    assert_eq!(call.duration_secs, 120, "call duration should be 120s");
    assert!(!call.video, "ZISVIDEOCALL=0 should map to video=false");
}

// ── T15: JID mapping — chat.jid from ZCONTACTIDENTIFIER ─────────────────────

#[test]
fn test_chat_jid_from_contact_identifier() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let jids: Vec<&str> = result.chats.iter().map(|c| c.jid.as_str()).collect();
    assert!(jids.contains(&"4155550100@s.whatsapp.net"), "Alice JID should be present");
    assert!(jids.contains(&"groupabc@g.us"), "group JID should be present");
}

// ── T16: name mapping — chat.name from ZPARTNERNAME ─────────────────────────

#[test]
fn test_chat_name_from_partner_name() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    assert_eq!(alice_chat.name.as_deref(), Some("Alice"), "ZPARTNERNAME should map to chat.name");
}

// ── T17: non-archived chat has archived=false ─────────────────────────────────

#[test]
fn test_non_archived_chat() {
    let db = make_chatstorage_db();
    let result = extract_from_chatstorage(&db, 0).unwrap();
    let alice_chat = result
        .chats
        .iter()
        .find(|c| c.jid == "4155550100@s.whatsapp.net")
        .expect("Alice's chat");
    assert!(!alice_chat.archived, "ZARCHIVED=0 should map to archived=false");
}

// ── T18: plugin.extract() works end-to-end ────────────────────────────────────

#[test]
fn test_plugin_extract_end_to_end() {
    let db = make_chatstorage_db();
    let fs = MockFs::new().add(DB_PATH, db);
    let plugin = IosWhatsAppPlugin;
    let result = plugin.extract(&fs, Some(0)).expect("plugin.extract() should succeed");
    assert!(!result.chats.is_empty(), "extraction should yield chats");
    assert_eq!(result.timezone_offset_seconds, Some(0));
}

// ── Story 1: ZSORT gap detection ──────────────────────────────────────────────

mod zsort_gap_tests {
    use super::*;
    use chat4n6_plugin_api::ForensicWarning;

    /// Build a DB where ZWAMESSAGE ZSORT values for chat 1 are:
    /// 1.0, 2.0, 3.0, 100.0, 101.0 — the jump 3→100 is a suspicious gap.
    fn make_zsort_gap_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            PRAGMA user_version = 32;
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZARCHIVED INTEGER DEFAULT 0,
                ZCONTACTIDENTIFIER TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 0
            );
            CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                ZCHATSESSION INTEGER,
                ZMESSAGEDATE REAL NOT NULL,
                ZTEXT TEXT,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZMEDIAITEM INTEGER,
                ZISFROMME INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZSTARRED INTEGER DEFAULT 0,
                ZISFORWARDED INTEGER DEFAULT 0,
                ZDELETED INTEGER DEFAULT 0,
                ZSORT REAL
            );
            CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMIMETYPE TEXT, ZFILESIZE INTEGER DEFAULT 0, ZLOCALPATH TEXT, ZMEDIAURL TEXT);
            CREATE TABLE ZWACONTACT (Z_PK INTEGER PRIMARY KEY, ZABUSEIDENTIFIER TEXT, ZPHONENUMBER TEXT, ZFULLNAME TEXT);
            CREATE TABLE ZWACALLINFO (Z_PK INTEGER PRIMARY KEY, ZCALLDATE REAL NOT NULL, ZDURATION INTEGER DEFAULT 0, ZISVIDEOCALL INTEGER DEFAULT 0, ZPARTNERCONTACT INTEGER, ZCALLTYPE INTEGER DEFAULT 0);
            INSERT INTO ZWACHATSESSION VALUES (1, 0, 'alice@s.whatsapp.net', 'Alice', 732205927.0, 0);
            -- ZSORT: 1.0, 2.0, 3.0 then jump to 100.0, 101.0 — gap of 97 vs mean ~1
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 732205927.0, 'Msg1', 0, NULL, 1, NULL, 0, 0, 0, 1.0);
            INSERT INTO ZWAMESSAGE VALUES (2, 1, 732206000.0, 'Msg2', 0, NULL, 0, NULL, 0, 0, 0, 2.0);
            INSERT INTO ZWAMESSAGE VALUES (3, 1, 732206100.0, 'Msg3', 0, NULL, 0, NULL, 0, 0, 0, 3.0);
            INSERT INTO ZWAMESSAGE VALUES (4, 1, 732206200.0, 'Msg4', 0, NULL, 0, NULL, 0, 0, 0, 100.0);
            INSERT INTO ZWAMESSAGE VALUES (5, 1, 732206300.0, 'Msg5', 0, NULL, 0, NULL, 0, 0, 0, 101.0);
        ").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn zsort_gap_detection_emits_warning() {
        let db = make_zsort_gap_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        // Should have emitted at least one SelectiveDeletion warning for chat 1 (alice)
        let has_selective = result.forensic_warnings.iter().any(|w| {
            matches!(w, ForensicWarning::SelectiveDeletion { suspect_jid, .. }
                if suspect_jid == "alice@s.whatsapp.net")
        });
        assert!(
            has_selective,
            "Expected SelectiveDeletion warning for alice@s.whatsapp.net, got: {:?}",
            result.forensic_warnings
        );
    }

    #[test]
    fn zsort_no_gap_no_warning() {
        // Consecutive ZSORT values — no suspicious gap → no SelectiveDeletion
        let db = make_chatstorage_db(); // standard fixture has ZSORT 1..5 sequential
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");
        let has_selective = result.forensic_warnings.iter().any(|w| {
            matches!(w, ForensicWarning::SelectiveDeletion { .. })
        });
        assert!(
            !has_selective,
            "No gap in standard fixture — should not emit SelectiveDeletion, got: {:?}",
            result.forensic_warnings
        );
    }
}

// ── Story 2: Dynamic column ordering ─────────────────────────────────────────

mod dynamic_column_tests {
    use super::*;

    /// Build a DB where ZWAMESSAGE has ZTEXT before ZCHATSESSION (reordered columns).
    /// This simulates an older iOS WA schema version.
    fn make_reordered_schema_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            PRAGMA user_version = 32;
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZARCHIVED INTEGER DEFAULT 0,
                ZCONTACTIDENTIFIER TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 0
            );
            -- Reordered: ZTEXT is at position 2, ZCHATSESSION at 3, ZMESSAGEDATE at 4
            CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                ZTEXT TEXT,
                ZCHATSESSION INTEGER,
                ZMESSAGEDATE REAL NOT NULL,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZMEDIAITEM INTEGER,
                ZISFROMME INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZSTARRED INTEGER DEFAULT 0,
                ZISFORWARDED INTEGER DEFAULT 0,
                ZDELETED INTEGER DEFAULT 0,
                ZSORT REAL
            );
            CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMIMETYPE TEXT, ZFILESIZE INTEGER DEFAULT 0, ZLOCALPATH TEXT, ZMEDIAURL TEXT);
            CREATE TABLE ZWACONTACT (Z_PK INTEGER PRIMARY KEY, ZABUSEIDENTIFIER TEXT, ZPHONENUMBER TEXT, ZFULLNAME TEXT);
            CREATE TABLE ZWACALLINFO (Z_PK INTEGER PRIMARY KEY, ZCALLDATE REAL NOT NULL, ZDURATION INTEGER DEFAULT 0, ZISVIDEOCALL INTEGER DEFAULT 0, ZPARTNERCONTACT INTEGER, ZCALLTYPE INTEGER DEFAULT 0);
            INSERT INTO ZWACHATSESSION VALUES (1, 0, 'bob@s.whatsapp.net', 'Bob', 732205927.0, 0);
            -- Values match reordered schema: Z_PK, ZTEXT, ZCHATSESSION, ZMESSAGEDATE, ...
            INSERT INTO ZWAMESSAGE VALUES (10, 'Dynamic text', 1, 732205927.0, 0, NULL, 1, NULL, 0, 0, 0, 1.0);
        ").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn dynamic_column_order_handles_reordered_schema() {
        let db = make_reordered_schema_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        // Should have extracted 1 chat (bob) with 1 message
        assert_eq!(result.chats.len(), 1, "should have 1 chat");
        let bob_chat = result
            .chats
            .iter()
            .find(|c| c.jid == "bob@s.whatsapp.net")
            .expect("Bob's chat should exist");
        assert_eq!(bob_chat.messages.len(), 1, "should have 1 message in Bob's chat");

        let msg = &bob_chat.messages[0];
        assert_eq!(msg.id, 10, "message ID should be 10");
        // With dynamic column lookup, ZTEXT='Dynamic text' must be correctly extracted
        assert!(
            matches!(&msg.content, chat4n6_plugin_api::MessageContent::Text(t) if t == "Dynamic text"),
            "Expected Text('Dynamic text'), got: {:?}", msg.content
        );
        // ZISFROMME=1 must be correctly read despite reordered columns
        assert!(msg.from_me, "from_me should be true (ZISFROMME=1)");
    }
}
