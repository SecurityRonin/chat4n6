-- real_modern_schema.sql with every column order permuted.
--
-- Same table names, same column names, same rows, same values — only the
-- declaration order differs, and `_id` is deliberately not declared first.
--
-- WHY
--   A fixture built to the layout the code assumes cannot falsify that
--   assumption; that is how the ordinal bug shipped green. This fixture makes
--   position-independence a property under test rather than a claim: paired
--   with real_modern_schema.sql it asserts that two databases differing only in
--   column order extract identically. Any ordinal creeping back into the
--   extractor breaks one of the pair.
--
--   Declaring `_id` mid-table also exercises the record-layout invariant the
--   resolver rests on: SQLite writes the INTEGER PRIMARY KEY as a NULL at its
--   own declared position, not at position 0.
--
-- This is a deliberately synthetic permutation. No device ships these orders.

PRAGMA user_version = 1;

CREATE TABLE jid (
    raw_string TEXT,
    device INTEGER,
    _id INTEGER PRIMARY KEY,
    server TEXT NOT NULL,
    type INTEGER,
    user TEXT NOT NULL,
    agent INTEGER
);

CREATE TABLE chat (
    subject TEXT,
    sort_timestamp INTEGER,
    archived INTEGER,
    created_timestamp INTEGER,
    hidden INTEGER,
    display_message_row_id INTEGER,
    _id INTEGER PRIMARY KEY,
    jid_row_id INTEGER UNIQUE,
    mod_tag INTEGER
);

CREATE TABLE message (
    text_data TEXT,
    timestamp INTEGER,
    view_mode INTEGER,
    sender_jid_row_id INTEGER,
    sort_id INTEGER,
    from_me INTEGER NOT NULL,
    _id INTEGER PRIMARY KEY,
    status INTEGER,
    message_type INTEGER,
    key_id TEXT NOT NULL,
    received_timestamp INTEGER,
    starred INTEGER,
    chat_row_id INTEGER NOT NULL,
    origin INTEGER
);

CREATE TABLE call_log (
    duration INTEGER,
    call_result INTEGER,
    _id INTEGER PRIMARY KEY,
    video_call INTEGER,
    call_id TEXT,
    jid_row_id INTEGER,
    bytes_transferred INTEGER,
    timestamp INTEGER,
    transaction_id INTEGER,
    from_me INTEGER
);

-- Identical rows to real_modern_schema.sql, inserted by name.

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

INSERT INTO call_log
    (_id, jid_row_id, from_me, call_id, transaction_id, timestamp, video_call, duration, call_result)
VALUES
    (1, 1, 1, 'CALL-AAAA', 11, 1663243400000, 0, 137, 1),
    (2, 1, 0, 'CALL-BBBB', 12, 1663243500000, 1,  42, 1),
    (3, 1, 1, 'CALL-CCCC', 13, 1663243600000, 0, 137, 1);
