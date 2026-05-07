/// Signal Android extractor integration tests.
///
/// All tests run against the in-memory fixture database built from
/// `tests/fixtures/signal_schema.sql`.  The fixture is compiled into a
/// plaintext SQLite blob at test-time using rusqlite; no file I/O at runtime.
use chat4n6_signal::extractor::{extract_from_signal_db, is_outgoing_base_type, attachment_table_name};
use chat4n6_plugin_api::{ForensicWarning, MessageContent};

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
    // sms id=1: type=87 → base = 87 & 0x1F = 23 ∈ OUTGOING_BASE_TYPES → outgoing
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg1 = all_msgs.iter().find(|m| m.id == 1).expect("message id=1 missing");
    assert!(msg1.from_me, "sms type=87 should be from_me=true");
}

#[test]
fn t06_received_message_from_me_false() {
    // sms id=2: type=20 → base=20 (BASE_INBOX_TYPE), from_recipient_id=2 — incoming
    let db = make_signal_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg2 = all_msgs.iter().find(|m| m.id == 2).expect("message id=2 missing");
    assert!(!msg2.from_me, "sms type=20 (base=20, BASE_INBOX_TYPE) should be from_me=false (incoming)");
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

// ── T20: DisappearingTimerActive warning ─────────────────────────────────────

/// Build a DB where thread 1 has expires_in=86400 and 3 vanished sms rows.
fn make_disappearing_timer_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0,
             expires_in INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0,
             expires_started INTEGER DEFAULT 0);
         CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER NOT NULL,
             content_type TEXT, name TEXT, file_size INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             is_mms INTEGER NOT NULL DEFAULT 0, author_id INTEGER NOT NULL,
             emoji TEXT NOT NULL, date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+14155551234', 'uuid-a', NULL, 'Tester', 'Tester A', 0);
         INSERT INTO thread VALUES (1, 1, 0, 4, 86400);
         -- 3 vanished: body empty, expires_started non-zero
         INSERT INTO sms VALUES (1, 1, 1710513127000, 1710513127001, 10485, '', 1, 1, 0, 1234567);
         INSERT INTO sms VALUES (2, 1, 1710513200000, 1710513200001, 10485, '', 1, 1, 0, 1234568);
         INSERT INTO sms VALUES (3, 1, 1710513300000, 1710513300001, 10485, '', 1, 1, 0, 1234569);
         -- 1 normal message: body present, expires_started=0
         INSERT INTO sms VALUES (4, 1, 1710513400000, 1710513400001, 10485, 'normal message', 1, 1, 0, 0);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
        .unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t20_disappearing_timer_active_warning() {
    let db = make_disappearing_timer_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let warning = result.forensic_warnings.iter().find(|w| {
        matches!(
            w,
            ForensicWarning::DisappearingTimerActive { chat_id: 1, timer_seconds: 86400, vanished_count: 3 }
        )
    });
    assert!(
        warning.is_some(),
        "expected DisappearingTimerActive {{ chat_id: 1, timer_seconds: 86400, vanished_count: 3 }}, got: {:?}",
        result.forensic_warnings
    );
}

// ── T21: SealedSenderUnresolved warning ──────────────────────────────────────

/// Build a DB where sms has an envelope_type column and a row with bit 0x10 set
/// from a from_recipient_id not in the recipient table.
fn make_sealed_sender_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0,
             expires_in INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0,
             expires_started INTEGER DEFAULT 0, envelope_type INTEGER DEFAULT 0);
         CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER NOT NULL,
             content_type TEXT, name TEXT, file_size INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             is_mms INTEGER NOT NULL DEFAULT 0, author_id INTEGER NOT NULL,
             emoji TEXT NOT NULL, date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+14155551234', 'uuid-alice', NULL, 'Alice', 'Alice A', 0);
         INSERT INTO thread VALUES (5, 1, 0, 1, 0);
         -- from_recipient_id=99 NOT in recipient table, envelope_type=16 (0x10 = sealed sender)
         INSERT INTO sms VALUES (100, 5, 1710513127000, 1710513127001, 10485, 'sealed msg', 99, 1, 0, 0, 16);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
        .unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t21_sealed_sender_unresolved_warning() {
    let db = make_sealed_sender_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let warning = result.forensic_warnings.iter().find(|w| {
        matches!(
            w,
            ForensicWarning::SealedSenderUnresolved { thread_id: 5, count: 1 }
        )
    });
    assert!(
        warning.is_some(),
        "expected SealedSenderUnresolved {{ thread_id: 5, count: 1 }}, got: {:?}",
        result.forensic_warnings
    );
}

// ── T22: direction heuristic — OUTGOING_BASE_TYPES membership ────────────────

/// Task 1: Signal's correct outgoing base types from Types.java.
/// BASE_TYPE_MASK = 0x1F; OUTGOING_BASE_TYPES = {2, 11, 21, 22, 23, 24, 25, 26, 28}.
#[test]
fn t22_is_outgoing_base_type_outgoing_values() {
    // All of these must be identified as outgoing.
    for &type_val in &[21i64, 22, 2, 11, 23, 24, 25, 26, 28] {
        assert!(
            is_outgoing_base_type(type_val),
            "base type {type_val} should be outgoing per Signal Types.java"
        );
    }
}

#[test]
fn t23_is_outgoing_base_type_incoming_values() {
    // All of these must be identified as incoming.
    for &type_val in &[0i64, 1, 10, 20, 31] {
        assert!(
            !is_outgoing_base_type(type_val),
            "base type {type_val} should be incoming, but is_outgoing_base_type returned true"
        );
    }
}

/// Fixture: sms id=1 has type=87 → base = 87 & 0x1F = 23 (outgoing).
#[test]
fn t24_is_outgoing_matches_fixture_type_87() {
    assert!(is_outgoing_base_type(87), "type=87 (base=23) must be outgoing");
}

/// Fixture: sms id=2 has type=20 → base = 20 & 0x1F = 20 (NOT in outgoing set).
/// (We update the fixture in the implementation phase so this base type is used.)
#[test]
fn t25_is_outgoing_matches_fixture_type_20() {
    assert!(!is_outgoing_base_type(20), "type=20 (base=20) must be incoming");
}

// ── T26: reaction post-v168 layout — 6 columns, no is_mms ───────────────────

/// Build a post-v168 DB: reaction table has NO is_mms column.
/// Layout: [0]=_id, [1]=message_id, [2]=author_id, [3]=emoji, [4]=date_sent, [5]=date_received
fn make_post_v168_reaction_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 185;
         CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0);
         -- post-v168: no is_mms column
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             author_id INTEGER NOT NULL, emoji TEXT NOT NULL,
             date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER NOT NULL,
             content_type TEXT, name TEXT, file_size INTEGER DEFAULT 0);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+19995550001', 'uuid-x', NULL, 'Tester', 'Tester X', 0);
         INSERT INTO recipient VALUES (2, '+19995550002', 'uuid-y', NULL, 'Reactor', 'Reactor Y', 0);
         INSERT INTO thread VALUES (1, 1, 0, 1);
         INSERT INTO sms VALUES (10, 1, 1710513127000, 1710513127001, 23, 'hello', 1, 1, 0);
         -- reaction: message_id=10, author_id=2, emoji=thumbsup
         INSERT INTO reaction VALUES (1, 10, 2, '👍', 1710513200000, 1710513200001);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t26_reaction_post_v168_emoji_correct() {
    let db = make_post_v168_reaction_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg = all_msgs.iter().find(|m| m.id == 10).expect("message id=10 missing");
    assert_eq!(msg.reactions.len(), 1, "post-v168 reaction should be parsed (1 reaction)");
    assert_eq!(msg.reactions[0].emoji, "👍", "post-v168 reaction emoji should be 👍 at column index 3");
}

#[test]
fn t27_reaction_post_v168_reactor_jid() {
    let db = make_post_v168_reaction_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg = all_msgs.iter().find(|m| m.id == 10).expect("message id=10 missing");
    assert_eq!(msg.reactions.len(), 1);
    // author_id=2 → Reactor Y: +19995550002@signal
    assert!(
        msg.reactions[0].reactor_jid.contains("19995550002"),
        "reactor JID should identify recipient 2, got: {}",
        msg.reactions[0].reactor_jid
    );
}

// ── T28: attachment table selection — schema-version-aware ───────────────────

#[test]
fn t28_attachment_table_pre_v168_uses_part() {
    assert_eq!(
        attachment_table_name(Some(167)),
        "part",
        "schema < 168 should use 'part' table"
    );
}

#[test]
fn t29_attachment_table_post_v168_uses_attachment() {
    assert_eq!(
        attachment_table_name(Some(168)),
        "attachment",
        "schema >= 168 should use 'attachment' table"
    );
}

#[test]
fn t30_attachment_table_none_version_uses_part() {
    assert_eq!(
        attachment_table_name(None),
        "part",
        "unknown schema version should fall back to 'part' (conservative)"
    );
}

/// Build a post-v168 DB that uses the `attachment` table with new column names.
fn make_post_v168_attachment_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 200;
         CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER,
             date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             author_id INTEGER NOT NULL, emoji TEXT NOT NULL,
             date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         -- post-v168: 'attachment' table with new column names
         CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             content_type TEXT, file_name TEXT, data_size INTEGER DEFAULT 0);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+19995550001', 'uuid-x', NULL, 'Tester', 'Tester X', 0);
         INSERT INTO thread VALUES (1, 1, 0, 1);
         INSERT INTO sms VALUES (20, 1, 1710513127000, 1710513127001, 23, NULL, 1, 1, 0);
         -- attachment row linking to sms id=20
         INSERT INTO attachment VALUES (1, 20, 'video/mp4', 'video.mp4', 512000);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t31_attachment_post_v168_media_resolved() {
    let db = make_post_v168_attachment_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg = all_msgs.iter().find(|m| m.id == 20).expect("message id=20 missing");
    match &msg.content {
        MessageContent::Media(m) => {
            assert_eq!(m.mime_type, "video/mp4", "post-v168 attachment mime type should be video/mp4");
        }
        other => panic!("expected MessageContent::Media for post-v168 attachment, got {:?}", other),
    }
}

// ── T32: timestamp priority — date_server > date_received > date_sent ────────

/// Build a DB where sms has date_server (> date_received > date_sent).
/// Expect the message timestamp to use date_server.
fn make_timestamp_priority_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 200;
         CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0);
         -- sms with expires_started (idx 9), envelope_type (idx 10), date_server (idx 11)
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER,
             date INTEGER, date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0,
             expires_started INTEGER DEFAULT 0, envelope_type INTEGER DEFAULT 0,
             date_server INTEGER);
         CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             content_type TEXT, file_name TEXT, data_size INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             author_id INTEGER NOT NULL, emoji TEXT NOT NULL,
             date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+19995550001', 'uuid-x', NULL, 'Tester', 'Tester X', 0);
         INSERT INTO thread VALUES (1, 1, 0, 1);
         -- date=1000, date_received=2000, expires_started=0, envelope_type=0, date_server=3000 → expect 3000
         INSERT INTO sms VALUES (30, 1, 1000, 2000, 23, 'priority test', 1, 1, 0, 0, 0, 3000);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t32_timestamp_prefers_date_server() {
    let db = make_timestamp_priority_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg = all_msgs.iter().find(|m| m.id == 30).expect("message id=30 missing");
    // date_server=3000ms → timestamp epoch_ms should be 3000
    assert_eq!(
        msg.timestamp.utc.timestamp_millis(), 3000,
        "timestamp should use date_server (3000), not date (1000) or date_received (2000)"
    );
}

/// When date_server is absent/NULL, fall back to date_received.
fn make_timestamp_fallback_db() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 200;
         CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, aci TEXT,
             group_id TEXT, system_display_name TEXT, profile_joined_name TEXT, type INTEGER DEFAULT 0);
         CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER NOT NULL UNIQUE,
             archived INTEGER DEFAULT 0, message_count INTEGER DEFAULT 0);
         CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER,
             date INTEGER, date_received INTEGER, type INTEGER DEFAULT 0, body TEXT,
             from_recipient_id INTEGER, read INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0,
             expires_started INTEGER DEFAULT 0, envelope_type INTEGER DEFAULT 0,
             date_server INTEGER);
         CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             content_type TEXT, file_name TEXT, data_size INTEGER DEFAULT 0);
         CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL,
             author_id INTEGER NOT NULL, emoji TEXT NOT NULL,
             date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
         CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL,
             message_id INTEGER NOT NULL, peer TEXT NOT NULL, type INTEGER NOT NULL,
             direction INTEGER NOT NULL, event INTEGER NOT NULL, timestamp INTEGER NOT NULL);
         INSERT INTO recipient VALUES (1, '+19995550001', 'uuid-x', NULL, 'Tester', 'Tester X', 0);
         INSERT INTO thread VALUES (1, 1, 0, 1);
         -- date_server=NULL → fall back to date_received=2000
         INSERT INTO sms VALUES (31, 1, 1000, 2000, 23, 'fallback test', 1, 1, 0, 0, 0, NULL);",
    )
    .unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[test]
fn t33_timestamp_fallback_date_received_when_no_server() {
    let db = make_timestamp_fallback_db();
    let result = extract_from_signal_db(&db, 0).unwrap();
    let all_msgs: Vec<_> = result.chats.iter().flat_map(|c| c.messages.iter()).collect();
    let msg = all_msgs.iter().find(|m| m.id == 31).expect("message id=31 missing");
    // date_server=NULL, date_received=2000 → expect 2000
    assert_eq!(
        msg.timestamp.utc.timestamp_millis(), 2000,
        "timestamp should fall back to date_received (2000) when date_server is absent"
    );
}
