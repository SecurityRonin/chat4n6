PRAGMA user_version = 185;

CREATE TABLE recipient (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    e164 TEXT,
    aci TEXT,
    group_id TEXT,
    system_display_name TEXT,
    profile_joined_name TEXT,
    type INTEGER DEFAULT 0
);

CREATE TABLE thread (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL UNIQUE,
    archived INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0
);

CREATE TABLE sms (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    date INTEGER,
    date_received INTEGER,
    type INTEGER DEFAULT 0,
    body TEXT,
    from_recipient_id INTEGER,
    read INTEGER DEFAULT 0,
    remote_deleted INTEGER DEFAULT 0
);

-- post-v168: 'attachment' table replaces 'part'; column positions unchanged.
CREATE TABLE attachment (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    content_type TEXT,
    file_name TEXT,
    data_size INTEGER DEFAULT 0
);

-- post-v168: 'reaction' table has NO 'is_mms' column.
-- Layout: _id, message_id, author_id, emoji, date_sent, date_received
CREATE TABLE reaction (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    date_sent INTEGER NOT NULL,
    date_received INTEGER NOT NULL
);

CREATE TABLE call (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    peer TEXT NOT NULL,
    type INTEGER NOT NULL,
    direction INTEGER NOT NULL,
    event INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);

-- Sample data
INSERT INTO recipient VALUES (1, '+14155550100', 'alice-uuid-001', NULL, 'Alice', 'Alice Smith', 0);
INSERT INTO recipient VALUES (2, '+14155550101', 'bob-uuid-002',   NULL, 'Bob',   'Bob Jones',  0);

INSERT INTO thread VALUES (1, 1, 0, 2);
INSERT INTO thread VALUES (2, 2, 1, 0);  -- archived thread with Bob

INSERT INTO sms VALUES (1, 1, 1710513127000, 1710513127001, 87,    'Hello Signal!', 1, 1, 0);
INSERT INTO sms VALUES (2, 1, 1710513200000, 1710513200001, 20,    'Hi there!',     2, 1, 0);  -- type=20: base=20 (BASE_INBOX_TYPE, incoming)
INSERT INTO sms VALUES (3, 1, 1710513300000, 1710513300001, 87,    NULL,            1, 1, 0);  -- media msg
INSERT INTO sms VALUES (4, 1, 1710513400000, 1710513400001, 87,    'Deleted msg',   1, 1, 1);  -- remote_deleted

-- post-v168: use 'attachment' table; message_id links to sms._id=3
INSERT INTO attachment VALUES (1, 3, 'image/jpeg', 'photo.jpg', 102400);

-- post-v168: no is_mms; author_id=2=Bob
INSERT INTO reaction VALUES (1, 1, 2, '❤️', 1710513150000, 1710513150001);

INSERT INTO call VALUES (1, 9001, 5, '1', 2, 0, 4, 1710513500000);  -- incoming audio, accepted
