PRAGMA user_version = 1;

CREATE VIRTUAL TABLE messages_fts USING fts5(content, tokenize='porter ascii');

-- FTS5 creates: messages_fts_data, messages_fts_idx, messages_fts_content,
--               messages_fts_docsize, messages_fts_config

INSERT INTO messages_fts(rowid, content) VALUES (1, 'hello forensics world');
INSERT INTO messages_fts(rowid, content) VALUES (2, 'secret deleted message');
