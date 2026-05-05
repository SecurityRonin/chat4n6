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
    media_name TEXT,
    starred INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE call_log (
    _id INTEGER PRIMARY KEY,
    jid_row_id INTEGER NOT NULL,
    from_me INTEGER NOT NULL DEFAULT 0,
    video_call INTEGER NOT NULL DEFAULT 0,
    duration INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    call_result INTEGER NOT NULL DEFAULT 0,
    call_row_id INTEGER DEFAULT NULL,
    call_creator_device_jid_row_id INTEGER DEFAULT NULL
);

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

CREATE TABLE message_add_on (
    _id INTEGER PRIMARY KEY,
    message_row_id INTEGER NOT NULL,
    from_me INTEGER NOT NULL DEFAULT 0,
    sender_jid_row_id INTEGER,
    timestamp INTEGER NOT NULL,
    type INTEGER NOT NULL,
    text_data TEXT
);

CREATE TABLE message_add_on_reaction (
    _id INTEGER PRIMARY KEY,
    message_add_on_row_id INTEGER NOT NULL,
    reaction_text TEXT NOT NULL
);

CREATE TABLE message_edit_info (
    _id INTEGER PRIMARY KEY,
    message_row_id INTEGER NOT NULL,
    edited_timestamp INTEGER NOT NULL,
    original_text TEXT
);

CREATE TABLE receipt_user (
    _id INTEGER PRIMARY KEY,
    message_row_id INTEGER NOT NULL,
    receipt_user_jid_row_id INTEGER NOT NULL,
    status INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE TABLE group_participant_user (
    _id INTEGER PRIMARY KEY,
    group_jid_row_id INTEGER NOT NULL,
    jid_row_id INTEGER NOT NULL,
    user_action INTEGER NOT NULL,
    action_ts INTEGER NOT NULL,
    actor_jid_row_id INTEGER
);

CREATE TABLE message_forwarded (
    _id INTEGER PRIMARY KEY,
    message_row_id INTEGER NOT NULL,
    forward_score INTEGER NOT NULL DEFAULT 0
);

-- JIDs
INSERT INTO jid VALUES (1, '4155550100@s.whatsapp.net');
INSERT INTO jid VALUES (2, '4155550101@s.whatsapp.net');

-- Chats
INSERT INTO chat VALUES (1, 1, NULL);
INSERT INTO chat VALUES (2, 2, 'Test Group');

-- Messages (starred is column 9, 0-indexed)
INSERT INTO message VALUES (1, 1, NULL, 1, 1710513127000, 'Hello there', 0, NULL, NULL, 0);
INSERT INTO message VALUES (2, 1, 1,   0, 1710513200000, 'Hi back!',    0, NULL, NULL, 1);
INSERT INTO message VALUES (3, 1, NULL, 1, 1710513300000, NULL, 1, 'image/jpeg', 'Media/WhatsApp Images/IMG-20240315-001.jpg', 0);
INSERT INTO message VALUES (4, 1, 1,   0, 1710513400000, NULL, 2, 'audio/ogg; codecs=opus', 'Media/WhatsApp Audio/AUD-20240315-001.opus', 0);
INSERT INTO message VALUES (5, 2, NULL, 1, 1710513500000, 'Check this', 3, 'video/mp4', 'Media/WhatsApp Video/VID-20240315-001.mp4', 0);
INSERT INTO message VALUES (6, 1, 1,   0, 1710513600000, NULL, 15, NULL, NULL, 0);

-- Quoted: msg 2 quotes msg 1
INSERT INTO message_quoted VALUES (1, 2, 1, NULL, 1, 1710513127000, 'Hello there', 0, NULL, NULL);

-- Reaction: msg 2 got a thumbs up from jid 1
INSERT INTO message_add_on VALUES (1, 2, 0, 1, 1710513250000, 56, '👍');
INSERT INTO message_add_on_reaction VALUES (1, 1, '👍');

-- Edit: msg 2 was edited
INSERT INTO message_add_on VALUES (2, 2, 0, 1, 1710513300000, 74, 'Hi back! (edited)');
INSERT INTO message_edit_info VALUES (1, 2, 1710513300000, 'Hi back!');

-- Receipt: msg 1 read by jid 1
INSERT INTO receipt_user VALUES (1, 1, 1, 13, 1710513150000);

-- Group participant: jid 1 added to chat 2
INSERT INTO group_participant_user VALUES (1, 2, 1, 0, 1710510000000, NULL);

-- Forwarded: msg 5 forward_score=8
INSERT INTO message_forwarded VALUES (1, 5, 8);

-- Call: outgoing voice, 120s
INSERT INTO call_log VALUES (1, 1, 1, 0, 120, 1710513400000, 1, NULL, NULL);
