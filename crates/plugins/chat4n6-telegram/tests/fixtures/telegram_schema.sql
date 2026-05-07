PRAGMA user_version = 2;

-- Modern Telegram Android schema (cache4.db)
-- messages_v2 is the primary messages table; messages is legacy fallback.
-- tgcalls does NOT exist — call data is embedded in messages.

CREATE TABLE messages_v2 (
    mid INTEGER PRIMARY KEY,
    uid INTEGER NOT NULL,
    date INTEGER NOT NULL,
    out INTEGER DEFAULT 0,
    data BLOB,
    send_state INTEGER DEFAULT 0,
    read_state INTEGER DEFAULT 0
);

CREATE TABLE messages (
    mid INTEGER PRIMARY KEY,
    uid INTEGER NOT NULL,
    date INTEGER NOT NULL,
    out INTEGER DEFAULT 0,
    data BLOB,
    send_state INTEGER DEFAULT 0,
    read_state INTEGER DEFAULT 0
);

CREATE TABLE dialogs (
    did INTEGER PRIMARY KEY,
    date INTEGER NOT NULL,
    last_mid INTEGER DEFAULT 0
);

CREATE TABLE users (
    uid INTEGER PRIMARY KEY,
    name TEXT
);

CREATE TABLE chats (
    uid INTEGER PRIMARY KEY,
    name TEXT,
    data BLOB
);

CREATE TABLE media_v4 (
    mid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    date INTEGER NOT NULL,
    type INTEGER NOT NULL,
    data BLOB
);

-- Sample data
INSERT INTO users VALUES (100, 'Alice Smith');
INSERT INTO users VALUES (200, 'Bob Jones');
INSERT INTO dialogs VALUES (100, 1710513000, 3);    -- 1:1 with Alice
INSERT INTO dialogs VALUES (-1000, 1710513000, 5);  -- Group chat
INSERT INTO chats VALUES (-1000, 'Test Group Chat', NULL);  -- group name

-- Messages in messages_v2 (modern schema)
INSERT INTO messages_v2 VALUES (1, 100, 1710513000, 1, NULL, 1, 0);  -- outgoing to Alice
INSERT INTO messages_v2 VALUES (2, 100, 1710513100, 0, NULL, 1, 0);  -- incoming from Alice
INSERT INTO messages_v2 VALUES (3, -1000, 1710513200, 1, NULL, 1, 0); -- outgoing in group
INSERT INTO messages_v2 VALUES (4, -1000, 1710513300, 0, NULL, 1, 0); -- incoming in group

-- Media message (in messages_v2)
INSERT INTO media_v4 VALUES (5, 100, 1710513400, 1, NULL);  -- photo
INSERT INTO messages_v2 VALUES (5, 100, 1710513400, 0, NULL, 1, 0);
