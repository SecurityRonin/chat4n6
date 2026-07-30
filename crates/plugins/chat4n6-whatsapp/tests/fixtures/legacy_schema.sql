-- Legacy WhatsApp Android msgstore schema (pre-2018 `messages` + `chat_list` era).
--
-- PROVENANCE
--   Column names and order follow the legacy schema published in the WhatsApp
--   forensic literature.  Unlike real_modern_schema.sql, this was NOT read off
--   the case device — nothing in the case is of this generation.  It exists so
--   the legacy branch has something concrete to classify and refuse, rather
--   than being reasoned about in the abstract.
--
--   A trimmed but faithful subset: the columns below sit in their published
--   relative order.  The extractor reads none of them, because it has no
--   legacy path.
--
-- WHAT THIS FIXTURE IS FOR
--   1. detect_schema_version must classify it Legacy.
--   2. Extraction must refuse it loudly.  A database of this generation has no
--      `message`, `jid` or `chat` table, so a modern extractor finds nothing —
--      and "nothing" is indistinguishable from a clean device.

PRAGMA user_version = 1;

CREATE TABLE messages (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_remote_jid TEXT NOT NULL,
    key_from_me INTEGER,
    key_id TEXT NOT NULL,
    status INTEGER,
    needs_push INTEGER,
    data TEXT,
    timestamp INTEGER,
    media_url TEXT,
    media_mime_type TEXT,
    media_wa_type TEXT,
    media_size INTEGER,
    media_name TEXT,
    media_caption TEXT,
    media_hash TEXT,
    media_duration INTEGER,
    origin INTEGER,
    latitude REAL,
    longitude REAL,
    thumb_image TEXT,
    remote_resource TEXT,
    received_timestamp INTEGER,
    send_timestamp INTEGER,
    starred INTEGER,
    quoted_row_id INTEGER,
    edit_version INTEGER,
    forwarded INTEGER
);

CREATE TABLE chat_list (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_remote_jid TEXT UNIQUE,
    message_table_id INTEGER,
    subject TEXT,
    creation INTEGER,
    archived INTEGER,
    sort_timestamp INTEGER
);

CREATE TABLE wa_contacts (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    jid TEXT UNIQUE NOT NULL,
    display_name TEXT,
    status TEXT,
    number TEXT
);

-- Synthetic rows.  Timestamps are 2016-06-01T12:00:00Z (1464782400000).
INSERT INTO chat_list (_id, key_remote_jid, message_table_id, subject, creation, archived)
VALUES (1, '4155550100@s.whatsapp.net', 2, NULL, 1464782400000, 0);

INSERT INTO messages (_id, key_remote_jid, key_from_me, key_id, data, timestamp, media_wa_type)
VALUES
    (1, '4155550100@s.whatsapp.net', 1, 'LEGACY0001', 'Outgoing legacy message', 1464782400000, '0'),
    (2, '4155550100@s.whatsapp.net', 0, 'LEGACY0002', 'Incoming legacy message', 1464782460000, '0');

INSERT INTO wa_contacts (_id, jid, display_name, status, number)
VALUES (1, '4155550100@s.whatsapp.net', 'Legacy Contact', NULL, '+14155550100');
