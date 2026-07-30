-- Real-device WhatsApp Android msgstore.db schema (2023-era handset).
--
-- PROVENANCE
--   The CREATE TABLE shapes below reproduce the DDL read out of a real
--   `msgstore.db` acquired in a live forensic case.  DDL is not case data —
--   no identifiers, names, numbers, paths or message content from that device
--   appear here.  Every INSERT below is synthetic.
--
--   Column positions confirmed against that device:
--     message : chat_row_id(1) from_me(2) key_id(3) sender_jid_row_id(4)
--               timestamp(11) message_type(14) text_data(15) starred(16)
--     jid     : raw_string(5)
--     chat    : jid_row_id(1) hidden(2) subject(3) created_timestamp(4) archived(10)
--     call_log: jid_row_id(1) from_me(2) call_id(3) transaction_id(4)
--               timestamp(5) video_call(6) duration(7) call_result(8)
--   Columns at the intervening positions carry the names published in the
--   WhatsApp-schema forensic literature; they are position-preserving and are
--   never read by the extractor.  Correctness of this fixture depends only on
--   the confirmed names above sitting at the confirmed positions.
--
-- WHY THIS FIXTURE EXISTS
--   `modern_schema.sql` was authored to the same simplified layout the
--   extractor's hardcoded ordinals assumed, so it could never falsify them.
--   This fixture can: the values a positional reader picks up here are the
--   wrong columns, exactly as on the real device.
--
--   PRAGMA user_version is 1 on the real device — the modern schema is NOT
--   identified by a high user_version.

PRAGMA user_version = 1;

CREATE TABLE jid (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    server TEXT NOT NULL,
    agent INTEGER,
    type INTEGER,
    raw_string TEXT,
    device INTEGER
);

CREATE TABLE chat (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    jid_row_id INTEGER UNIQUE,
    hidden INTEGER,
    subject TEXT,
    created_timestamp INTEGER,
    display_message_row_id INTEGER,
    last_message_row_id INTEGER,
    last_read_message_row_id INTEGER,
    last_read_receipt_sent_message_row_id INTEGER,
    last_important_message_row_id INTEGER,
    archived INTEGER,
    sort_timestamp INTEGER,
    mod_tag INTEGER,
    gen TEXT,
    spam_detection INTEGER,
    unseen_earliest_message_received_time INTEGER,
    unseen_message_count INTEGER,
    unseen_missed_calls_count INTEGER,
    unseen_row_count INTEGER,
    plaintext_disabled INTEGER,
    vcard_ui_dismissed INTEGER,
    change_number_notified_message_row_id INTEGER,
    show_group_description INTEGER,
    ephemeral_expiration INTEGER,
    last_read_ephemeral_message_row_id INTEGER,
    ephemeral_setting_timestamp INTEGER,
    unseen_important_message_count INTEGER
);

CREATE TABLE message (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_row_id INTEGER NOT NULL,
    from_me INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    sender_jid_row_id INTEGER,
    status INTEGER,
    broadcast INTEGER,
    recipient_count INTEGER,
    participant_hash TEXT,
    origination_flags INTEGER,
    origin INTEGER,
    timestamp INTEGER,
    received_timestamp INTEGER,
    receipt_server_timestamp INTEGER,
    message_type INTEGER,
    text_data TEXT,
    starred INTEGER,
    lookup_tables INTEGER,
    sort_id INTEGER,
    message_add_on_flags INTEGER,
    view_mode INTEGER
);

CREATE TABLE call_log (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    jid_row_id INTEGER,
    from_me INTEGER,
    call_id TEXT,
    transaction_id INTEGER,
    timestamp INTEGER,
    video_call INTEGER,
    duration INTEGER,
    call_result INTEGER,
    is_dnd_mode_on INTEGER,
    bytes_transferred INTEGER,
    group_jid_row_id INTEGER,
    is_joinable_group_call INTEGER,
    call_creator_device_jid_row_id INTEGER,
    call_random_id TEXT
);

-- ── Synthetic rows ───────────────────────────────────────────────────────────
-- All timestamps are on 2022-09-15 UTC (1663243200000 = 2022-09-15T12:00:00Z).

INSERT INTO jid (_id, user, server, agent, type, raw_string, device) VALUES
    (1, '4155550100', 's.whatsapp.net', 0, 0, '4155550100@s.whatsapp.net', 0),
    (2, '120363001234567890', 'g.us', 0, 1, '120363001234567890@g.us', 0);

INSERT INTO chat (_id, jid_row_id, hidden, subject, created_timestamp, archived) VALUES
    (1, 1, 0, NULL, 1663200000000, 0),
    (2, 2, 0, 'Real Schema Group', 1663200000000, 1);

INSERT INTO message
    (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data, starred)
VALUES
    (1, 1, 1, 'AAAA1111', NULL, 1663243200000, 0, 'Outgoing real-schema message', 0),
    (2, 1, 0, 'BBBB2222',    1, 1663243260000, 0, 'Incoming real-schema message', 1),
    (3, 2, 0, 'CCCC3333',    1, 1663243320000, 0, 'Group real-schema message',    0);

-- Three distinct calls.  Calls 1 and 3 share a duration (137 s) but are
-- unrelated: a reader that mistakes `duration` for a group-call grouping key
-- collapses them into one record.
INSERT INTO call_log
    (_id, jid_row_id, from_me, call_id, transaction_id, timestamp, video_call, duration, call_result)
VALUES
    (1, 1, 1, 'CALL-AAAA', 11, 1663243400000, 0, 137, 1),
    (2, 1, 0, 'CALL-BBBB', 12, 1663243500000, 1,  42, 1),
    (3, 1, 1, 'CALL-CCCC', 13, 1663243600000, 0, 137, 1);
