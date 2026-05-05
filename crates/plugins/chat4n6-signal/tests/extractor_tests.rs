/// Signal Android extractor integration tests.
///
/// All tests run against the in-memory fixture database built from
/// `tests/fixtures/signal_schema.sql`.  The fixture is compiled into a
/// plaintext SQLite blob at test-time using rusqlite; no file I/O at runtime.
use chat4n6_signal::extractor::extract_from_signal_db;
use chat4n6_plugin_api::MessageContent;

// ── Fixture helpers ──────────────────────────────────────────────────────────

/// Build an in-memory SQLite database matching the Signal fixture schema and
/// return the raw bytes suitable for `extract_from_signal_db`.
fn make_signal_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("fixtures/signal_schema.sql"))
        .expect("fixture SQL failed");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
        .unwrap();
    std::fs::read(tmp.path()).unwrap()
}

/// Build an empty Signal-schema database (tables present, no data).
fn make_empty_signal_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0);
         CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER NOT NULL,
             content_type TEXT, name TEXT, file_size INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             is_mms INTEGER NOT NULL DEFAULT 0, author_id INTEGER NOT NULL,
             emoji TEXT NOT NULL, date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
        .unwrap();
    std::fs::read(tmp.path()).unwrap()
}

/// Build a database that only has the sms and recipient tables (no call, reaction, part).
fn make_sparse_signal_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0);
         INSERT INTO recipient VALUES (1, '+19995550001', 'uuid-x', NULL, 'Carol', 'Carol Brown', 0);
         INSERT INTO thread VALUES (1, 1, 0);
         INSERT INTO sms VALUES (1, 1, 1710513127000, 1710513127001, 87, 'sparse msg', 1, 1, 0);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
        .unwrap();
    std::fs::read(tmp.path()).unwrap()
}

// ── T1-T3: basic extraction ──────────────────────────────────────────────────

#[test]
fn t01_non_empty_chats() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert!(!result.chats.is_empty(), "should produce at least one chat");
}

#[test]
fn t02_message_count_matches_fixture() {
    // Fixture has 4 sms rows in thread 1.
    // remote_deleted row (id=4) must still appear (as Deleted).
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let total: usize = result.chats.iter().map(|c| c.messages.len()).sum();
    assert_eq!(total, 4, "expected 4 messages (including deleted), got {total}");
}

#[test]
fn t03_chat_count_matches_threads() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert_eq!(result.chats.len(), 2, "expected 2 chats (one per thread)");
}

// ── T4: archived thread ──────────────────────────────────────────────────────

#[test]
fn t04_archived_thread_sets_flag() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    // Thread 2 (recipient_id=2, Bob) is archived=1
    let chat2 = result
        .chats
        .iter()
        .find(|c| {
            // Bob's JID contains his e164 or aci
            c.jid.contains("14155550101") || c.jid.contains("bob")
        })
        .expect("chat for Bob (thread 2) missing");
    assert!(chat2.archived, "thread with archived=1 should set Chat.archived=true");
}

// ── T5-T6: sent vs received ──────────────────────────────────────────────────

#[test]
fn t05_sent_message_from_me_true() {
    // sms id=1: type=87, from_recipient_id=1 — outgoing (87 & 0x20 != 0)
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg1 = all_msgs.iter().find(|m| m.id == 1).expect("message id=1 missing");
    assert!(msg1.from_me, "sms type=87 should be from_me=true");
}

#[test]
fn t06_received_message_from_me_false() {
    // sms id=2: type=10485, from_recipient_id=2 — incoming
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg2 = all_msgs.iter().find(|m| m.id == 2).expect("message id=2 missing");
    assert!(!msg2.from_me, "sms type=10485 should be from_me=false (incoming)");
}

// ── T7: reaction attached to correct message ─────────────────────────────────

#[test]
fn t07_reaction_attached_to_correct_message() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg1 = all_msgs.iter().find(|m| m.id == 1).expect("message id=1 missing");
    assert_eq!(msg1.reactions.len(), 1, "message 1 should have 1 reaction");
    assert_eq!(msg1.reactions[0].emoji, "❤️");
}

#[test]
fn t08_reaction_reactor_jid() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg1 = all_msgs.iter().find(|m| m.id == 1).expect("message id=1 missing");
    // author_id=2 → Bob: +14155550101@signal or bob-uuid-002@signal
    let reactor = &msg1.reactions[0].reactor_jid;
    assert!(
        reactor.contains("14155550101") || reactor.contains("bob-uuid-002"),
        "reactor JID should identify Bob, got: {reactor}"
    );
}

// ── T9: remote_deleted ───────────────────────────────────────────────────────

#[test]
fn t09_remote_deleted_message_is_deleted_variant() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg4 = all_msgs.iter().find(|m| m.id == 4).expect("message id=4 (deleted) missing");
    assert!(
        matches!(msg4.content, MessageContent::Deleted),
        "remote_deleted=1 should produce MessageContent::Deleted, got {:?}", msg4.content
    );
}

// ── T10: media attachment ────────────────────────────────────────────────────

#[test]
fn t10_media_message_has_media_content() {
    // sms id=3: body=NULL, has matching part row (image/jpeg photo.jpg)
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg3 = all_msgs.iter().find(|m| m.id == 3).expect("message id=3 (media) missing");
    match &msg3.content {
        MessageContent::Media(m) => {
            assert_eq!(m.mime_type, "image/jpeg", "mime type should be image/jpeg");
        }
        other => panic!("expected MessageContent::Media, got {:?}", other),
    }
}

// ── T11-T12: contact extraction ──────────────────────────────────────────────

#[test]
fn t11_contact_display_name_resolved() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let alice = result
        .contacts
        .iter()
        .find(|c| c.jid.contains("14155550100") || c.jid.contains("alice"))
        .expect("Alice contact missing");
    assert_eq!(
        alice.display_name.as_deref(),
        Some("Alice Smith"),
        "display name should be profile_joined_name"
    );
}

#[test]
fn t12_contact_e164_phone() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let alice = result
        .contacts
        .iter()
        .find(|c| c.jid.contains("14155550100") || c.jid.contains("alice"))
        .expect("Alice contact missing");
    assert_eq!(alice.phone_number.as_deref(), Some("+14155550100"));
}

// ── T13: call extraction ─────────────────────────────────────────────────────

#[test]
fn t13_call_extracted() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert_eq!(result.calls.len(), 1, "expected 1 call record");
}

#[test]
fn t14_call_direction_incoming() {
    // call.direction=0 → incoming → from_me=false
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert!(!result.calls[0].from_me, "direction=0 should be from_me=false");
}

#[test]
fn t15_call_result_accepted() {
    // call.event=4 → accepted → CallResult::Connected
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert_eq!(
        result.calls[0].call_result,
        chat4n6_plugin_api::CallResult::Connected,
        "event=4 should map to CallResult::Connected"
    );
}

#[test]
fn t16_call_not_video() {
    // call.type=2 → audio outgoing (type 1/2 = audio, 3/4 = video)
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert!(!result.calls[0].video, "type=2 (audio) should not be video");
}

// ── T17: empty db ────────────────────────────────────────────────────────────

#[test]
fn t17_empty_db_returns_empty_result() {
    let db = make_empty_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    assert!(result.chats.is_empty(), "empty DB should produce no chats");
    assert!(result.calls.is_empty(), "empty DB should produce no calls");
    assert!(result.contacts.is_empty(), "empty DB should produce no contacts");
}

// ── T18: missing optional tables ─────────────────────────────────────────────

#[test]
fn t18_ok_when_optional_tables_missing() {
    // sparse DB has no call, reaction, or part tables
    let db = make_sparse_signal_db();
    let result = extract_from_signal_db(&db, 0);
    assert!(result.is_ok(), "extract should succeed even when optional tables are absent");
    let r = result.unwrap();
    assert_eq!(r.chats.len(), 1);
    assert!(r.calls.is_empty());
}

// ── T19: timezone offset preserved ───────────────────────────────────────────

#[test]
fn t19_timezone_offset_preserved() {
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 8 * 3600).unwrap();
    assert_eq!(
        result.timezone_offset_seconds,
        Some(8 * 3600),
        "timezone_offset_seconds should reflect the passed tz_offset"
    );
}
