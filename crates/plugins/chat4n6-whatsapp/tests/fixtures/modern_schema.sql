-- Minimal modern WhatsApp Android msgstore schema + sample data
-- Column order matches what ForensicEngine/btree walker will emit

PRAGMA user_version = 200;

CREATE TABLE jid (
    _id INTEGER PRIMARY KEY,
    raw_string TEXT NOT NULL
);

CREATE TABLE chat (
    _id INTEGER PRIMARY KEY,
    jid_row_id INTEGER NOT NULL,
    subject TEXT
);

CREATE TABLE message (
    _id INTEGER PRIMARY KEY,
    chat_row_id INTEGER NOT NULL,
    sender_jid_row_id INTEGER,
    from_me INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    text_data TEXT,
    message_type INTEGER NOT NULL DEFAULT 0,
    media_mime_type TEXT,
    media_name TEXT
);

CREATE TABLE call_log (
    _id INTEGER PRIMARY KEY,
    jid_row_id INTEGER NOT NULL,
    from_me INTEGER NOT NULL DEFAULT 0,
    video_call INTEGER NOT NULL DEFAULT 0,
    duration INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    call_result INTEGER NOT NULL DEFAULT 0
);

-- Sample JIDs
INSERT INTO jid VALUES (1, '4155550100@s.whatsapp.net');
INSERT INTO jid VALUES (2, '4155550101@s.whatsapp.net');

-- Sample chats
INSERT INTO chat VALUES (1, 1, NULL);   -- 1:1 chat
INSERT INTO chat VALUES (2, 2, 'Test Group');  -- group

-- Sample messages (timestamp in ms since epoch)
INSERT INTO message VALUES (1, 1, NULL,   1, 1710513127000, 'Hello there', 0, NULL, NULL);  -- sent text
INSERT INTO message VALUES (2, 1, 1,      0, 1710513200000, 'Hi back!',    0, NULL, NULL);  -- received text
INSERT INTO message VALUES (3, 1, NULL,   1, 1710513300000, NULL,          1, 'image/jpeg', 'Media/WhatsApp Images/IMG-20240315-001.jpg');  -- sent image
INSERT INTO message VALUES (4, 1, 1,      0, 1710513400000, NULL,          2, 'audio/ogg; codecs=opus', 'Media/WhatsApp Audio/AUD-20240315-001.opus');  -- audio
INSERT INTO message VALUES (5, 2, NULL,   1, 1710513500000, 'Check this',  3, 'video/mp4', 'Media/WhatsApp Video/VID-20240315-001.mp4');  -- video with caption
INSERT INTO message VALUES (6, 1, 1,      0, 1710513600000, NULL,          15, NULL, NULL);  -- tombstone/deleted (msg_type=15)

-- Quoted-message cross-reference table
CREATE TABLE message_quoted (
    _id INTEGER PRIMARY KEY,
    message_row_id INTEGER NOT NULL,
    chat_row_id INTEGER NOT NULL,
    sender_jid_row_id INTEGER,
    from_me INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    text_data TEXT,
    message_type INTEGER NOT NULL DEFAULT 0,
    media_mime_type TEXT,
    media_name TEXT
);

-- Message 2 quotes message 1
INSERT INTO message_quoted VALUES (1, 2, 1, NULL, 1, 1710513127000, 'Hello there', 0, NULL, NULL);

-- Sample call
INSERT INTO call_log VALUES (1, 1, 1, 0, 120, 1710513400000, 1);  -- outgoing voice call, 120s, Connected
