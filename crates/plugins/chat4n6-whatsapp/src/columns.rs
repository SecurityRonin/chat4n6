//! Name-based column resolution for msgstore.db tables.
//!
//! WhatsApp reorders, inserts and removes `message`/`chat`/`jid`/`call_log`
//! columns between app releases, so a fixed ordinal is only ever right for the
//! one schema it was written against.  Reading the wrong column produces a
//! structurally complete report full of wrong values — the failure class that
//! is indistinguishable from a correct one.
//!
//! Every ordinal used by the extractor is therefore derived at run time from
//! the database's own `CREATE TABLE` SQL (read out of `sqlite_master`), and a
//! column that the schema does not declare resolves to `None` rather than to a
//! neighbouring column's data.
//!
//! # Record layout invariant
//!
//! SQLite stores an `INTEGER PRIMARY KEY` column as a serial-type-0 NULL **at
//! its declared position** in the record body; the real value lives in the
//! cell's rowid varint.  The btree walker decodes serial types in order, so
//! `values[i]` is the column declared at DDL position `i` — including when the
//! rowid alias is not the first declared column.

use std::collections::HashMap;

/// Zero-based column positions for one table, keyed by lowercased column name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableColumns {
    by_name: HashMap<String, usize>,
}

impl TableColumns {
    /// Parse a `CREATE TABLE` statement into a name → position map.
    ///
    /// Table-level constraints (`PRIMARY KEY (…)`, `UNIQUE (…)`, `CHECK (…)`,
    /// `FOREIGN KEY (…)`, `CONSTRAINT …`) do not occupy a column position and
    /// are skipped.  Malformed input yields an empty map rather than a panic.
    pub fn from_ddl(ddl: &str) -> Self {
        let Some(body) = column_body(ddl) else {
            return Self::default();
        };
        let mut by_name = HashMap::new();
        let mut position = 0usize;
        for part in split_top_level(body) {
            let Some(name) = column_name(part) else {
                continue; // table-level constraint: occupies no column position
            };
            by_name.entry(name).or_insert(position);
            position += 1;
        }
        Self { by_name }
    }

    /// Zero-based position of `name`, or `None` when the table has no such column.
    pub fn get(&self, name: &str) -> Option<usize> {
        self.by_name.get(&name.to_ascii_lowercase()).copied()
    }

    /// Position of the first of `names` that the table declares.
    ///
    /// Used where one logical field is spelled differently across schema
    /// generations; the order of `names` is the preference order.
    pub fn first_of(&self, names: &[&str]) -> Option<usize> {
        names.iter().find_map(|n| self.get(n))
    }

    /// Number of declared columns.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// Column maps for every table in a database, built from `ForensicEngine::table_ddl`.
#[derive(Debug, Clone, Default)]
pub struct SchemaColumns {
    tables: HashMap<String, TableColumns>,
    empty: TableColumns,
}

impl SchemaColumns {
    /// Build from a `table name → CREATE TABLE SQL` map.
    pub fn from_ddl_map(ddl: &HashMap<String, String>) -> Self {
        Self {
            tables: ddl
                .iter()
                .map(|(name, sql)| (name.to_ascii_lowercase(), TableColumns::from_ddl(sql)))
                .collect(),
            empty: TableColumns::default(),
        }
    }

    /// Columns of `table`; an empty map when the database has no such table.
    ///
    /// Returning an empty map (rather than `Option`) keeps every downstream
    /// lookup on the same degrade-to-`None` path.
    pub fn table(&self, name: &str) -> &TableColumns {
        self.tables
            .get(&name.to_ascii_lowercase())
            .unwrap_or(&self.empty)
    }

    /// Whether any table DDL was resolved at all.
    ///
    /// A database whose schema could not be read is a bootstrap failure, not an
    /// empty database — callers must fail loudly rather than report no results.
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

// ── DDL parsing ──────────────────────────────────────────────────────────────

/// Closing delimiter for an opening quote/bracket, or `None` if `b` doesn't open one.
fn closing_delimiter(b: u8) -> Option<u8> {
    match b {
        b'\'' | b'"' | b'`' => Some(b),
        b'[' => Some(b']'),
        _ => None,
    }
}

/// The text between a `CREATE TABLE`'s outermost parentheses.
///
/// Returns `None` when the statement has no balanced parenthesised body.
fn column_body(ddl: &str) -> Option<&str> {
    let start = ddl.find('(')?;
    let mut depth = 0usize;
    let mut closing: Option<u8> = None;
    for (i, &b) in ddl.as_bytes().iter().enumerate().skip(start) {
        if let Some(c) = closing {
            if b == c {
                closing = None;
            }
            continue;
        }
        if let Some(c) = closing_delimiter(b) {
            closing = Some(c);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                // Both delimiters are ASCII, so these are char boundaries.
                return Some(&ddl[start + 1..i]);
            }
        }
    }
    None
}

/// Split a column body on commas that are neither nested nor quoted.
fn split_top_level(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut closing: Option<u8> = None;
    let mut start = 0usize;
    for (i, &b) in body.as_bytes().iter().enumerate() {
        if let Some(c) = closing {
            if b == c {
                closing = None;
            }
            continue;
        }
        if let Some(c) = closing_delimiter(b) {
            closing = Some(c);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth = depth.saturating_sub(1);
        } else if b == b',' && depth == 0 {
            parts.push(&body[start..i]);
            start = i + 1;
        }
    }
    parts.push(&body[start..]);
    parts
}

/// The lowercased column name a body part declares, or `None` when the part is
/// a table-level constraint.
///
/// SQLite reserves `PRIMARY`, `UNIQUE`, `CHECK`, `FOREIGN` and `CONSTRAINT`, so
/// a column that really carries one of those names has to be quoted — and a
/// quoted name skips the keyword test.
fn column_name(part: &str) -> Option<String> {
    const CONSTRAINT_KEYWORDS: [&str; 5] = ["primary", "unique", "check", "foreign", "constraint"];

    let s = part.trim();
    let first = s.chars().next()?;
    if let Some(close) = closing_delimiter(first as u8) {
        let rest = s.get(first.len_utf8()..)?;
        let end = rest.find(close as char)?;
        let name = rest.get(..end)?;
        return (!name.is_empty()).then(|| name.to_ascii_lowercase());
    }

    let end = s
        .find(|c: char| c.is_whitespace() || c == '(' || c == ',')
        .unwrap_or(s.len());
    let name = s.get(..end)?.to_ascii_lowercase();
    if name.is_empty() || CONSTRAINT_KEYWORDS.contains(&name.as_str()) {
        return None;
    }
    Some(name)
}

/// Resolved `message` column positions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageColumns {
    pub chat_row_id: Option<usize>,
    pub sender_jid_row_id: Option<usize>,
    pub from_me: Option<usize>,
    pub timestamp: Option<usize>,
    pub text_data: Option<usize>,
    pub message_type: Option<usize>,
    pub media_mime_type: Option<usize>,
    pub media_name: Option<usize>,
    pub starred: Option<usize>,
    pub edit_version: Option<usize>,
    pub key_id: Option<usize>,
}

impl MessageColumns {
    pub fn resolve(cols: &TableColumns) -> Self {
        Self {
            chat_row_id: cols.get("chat_row_id"),
            sender_jid_row_id: cols.get("sender_jid_row_id"),
            from_me: cols.get("from_me"),
            timestamp: cols.get("timestamp"),
            text_data: cols.get("text_data"),
            message_type: cols.get("message_type"),
            media_mime_type: cols.get("media_mime_type"),
            media_name: cols.get("media_name"),
            starred: cols.get("starred"),
            edit_version: cols.get("edit_version"),
            key_id: cols.get("key_id"),
        }
    }
}

/// Resolved `jid` column positions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JidColumns {
    pub raw_string: Option<usize>,
}

impl JidColumns {
    pub fn resolve(cols: &TableColumns) -> Self {
        Self {
            raw_string: cols.get("raw_string"),
        }
    }
}

/// Resolved `chat` column positions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatColumns {
    pub jid_row_id: Option<usize>,
    pub subject: Option<usize>,
    pub archived: Option<usize>,
}

impl ChatColumns {
    pub fn resolve(cols: &TableColumns) -> Self {
        Self {
            jid_row_id: cols.get("jid_row_id"),
            subject: cols.get("subject"),
            archived: cols.get("archived"),
        }
    }
}

/// Resolved `call_log` column positions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallLogColumns {
    pub jid_row_id: Option<usize>,
    pub from_me: Option<usize>,
    pub video_call: Option<usize>,
    pub duration: Option<usize>,
    pub timestamp: Option<usize>,
    pub call_result: Option<usize>,
    pub call_row_id: Option<usize>,
    pub call_creator_device_jid_row_id: Option<usize>,
}

impl CallLogColumns {
    pub fn resolve(cols: &TableColumns) -> Self {
        Self {
            jid_row_id: cols.get("jid_row_id"),
            from_me: cols.get("from_me"),
            video_call: cols.get("video_call"),
            duration: cols.get("duration"),
            timestamp: cols.get("timestamp"),
            call_result: cols.get("call_result"),
            call_row_id: cols.get("call_row_id"),
            call_creator_device_jid_row_id: cols.get("call_creator_device_jid_row_id"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `message` DDL read out of a real 2023-era Android device.
    const REAL_MESSAGE_DDL: &str = "CREATE TABLE message (\
        _id INTEGER PRIMARY KEY AUTOINCREMENT, chat_row_id INTEGER NOT NULL, \
        from_me INTEGER NOT NULL, key_id TEXT NOT NULL, sender_jid_row_id INTEGER, \
        status INTEGER, broadcast INTEGER, recipient_count INTEGER, \
        participant_hash TEXT, origination_flags INTEGER, origin INTEGER, \
        timestamp INTEGER, received_timestamp INTEGER, receipt_server_timestamp INTEGER, \
        message_type INTEGER, text_data TEXT, starred INTEGER, lookup_tables INTEGER, \
        sort_id INTEGER, message_add_on_flags INTEGER, view_mode INTEGER)";

    const REAL_JID_DDL: &str = "CREATE TABLE jid (_id INTEGER PRIMARY KEY AUTOINCREMENT, \
        user TEXT NOT NULL, server TEXT NOT NULL, agent INTEGER, type INTEGER, \
        raw_string TEXT, device INTEGER)";

    const REAL_CHAT_DDL: &str = "CREATE TABLE chat (_id INTEGER PRIMARY KEY AUTOINCREMENT, \
        jid_row_id INTEGER UNIQUE, hidden INTEGER, subject TEXT, created_timestamp INTEGER, \
        display_message_row_id INTEGER, last_message_row_id INTEGER, \
        last_read_message_row_id INTEGER, last_read_receipt_sent_message_row_id INTEGER, \
        last_important_message_row_id INTEGER, archived INTEGER, sort_timestamp INTEGER)";

    const REAL_CALL_LOG_DDL: &str = "CREATE TABLE call_log (\
        _id INTEGER PRIMARY KEY AUTOINCREMENT, jid_row_id INTEGER, from_me INTEGER, \
        call_id TEXT, transaction_id INTEGER, timestamp INTEGER, video_call INTEGER, \
        duration INTEGER, call_result INTEGER, is_dnd_mode_on INTEGER)";

    #[test]
    fn resolves_declared_column_positions() {
        let c =
            TableColumns::from_ddl("CREATE TABLE t (_id INTEGER PRIMARY KEY, b TEXT, c INTEGER)");
        assert_eq!(c.get("_id"), Some(0));
        assert_eq!(c.get("b"), Some(1));
        assert_eq!(c.get("c"), Some(2));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let c = TableColumns::from_ddl("CREATE TABLE t (_id INTEGER PRIMARY KEY, Text_Data TEXT)");
        assert_eq!(c.get("text_data"), Some(1));
        assert_eq!(c.get("TEXT_DATA"), Some(1));
    }

    #[test]
    fn absent_column_resolves_to_none() {
        let c = TableColumns::from_ddl("CREATE TABLE t (_id INTEGER PRIMARY KEY, b TEXT)");
        assert_eq!(
            c.get("media_mime_type"),
            None,
            "a column the schema does not declare must not resolve to a neighbour"
        );
    }

    #[test]
    fn table_level_constraints_do_not_occupy_positions() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE t (a INTEGER, b INTEGER, c TEXT, \
             PRIMARY KEY (a, b), UNIQUE (c), \
             FOREIGN KEY (b) REFERENCES other (id), \
             CHECK (a > 0), CONSTRAINT uq1 UNIQUE (a, c))",
        );
        assert_eq!(c.get("a"), Some(0));
        assert_eq!(c.get("b"), Some(1));
        assert_eq!(c.get("c"), Some(2));
        assert_eq!(
            c.len(),
            3,
            "table constraints must not be counted as columns"
        );
    }

    #[test]
    fn commas_inside_parentheses_do_not_split_columns() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b NUMERIC(10, 2), d TEXT)",
        );
        assert_eq!(c.get("b"), Some(1));
        assert_eq!(c.get("d"), Some(2));
    }

    #[test]
    fn commas_inside_string_defaults_do_not_split_columns() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT DEFAULT 'x,y', d TEXT)",
        );
        assert_eq!(c.get("b"), Some(1));
        assert_eq!(c.get("d"), Some(2));
    }

    #[test]
    fn quoted_identifiers_are_unwrapped() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE t (`_id` INTEGER PRIMARY KEY, \"text_data\" TEXT, [starred] INTEGER)",
        );
        assert_eq!(c.get("_id"), Some(0));
        assert_eq!(c.get("text_data"), Some(1));
        assert_eq!(c.get("starred"), Some(2));
    }

    #[test]
    fn quoted_table_name_and_if_not_exists_are_tolerated() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE IF NOT EXISTS \"message\" (_id INTEGER PRIMARY KEY, timestamp INTEGER)",
        );
        assert_eq!(c.get("timestamp"), Some(1));
    }

    #[test]
    fn malformed_ddl_yields_empty_map_without_panicking() {
        for ddl in ["", "CREATE TABLE t", "not sql at all", "CREATE TABLE t ("] {
            let c = TableColumns::from_ddl(ddl);
            assert!(
                c.is_empty(),
                "malformed DDL {ddl:?} must resolve to no columns"
            );
        }
    }

    #[test]
    fn first_of_returns_the_first_declared_alias() {
        let c = TableColumns::from_ddl(
            "CREATE TABLE t (_id INTEGER PRIMARY KEY, parent_message_row_id INTEGER)",
        );
        assert_eq!(
            c.first_of(&["message_row_id", "parent_message_row_id"]),
            Some(1)
        );
        assert_eq!(c.first_of(&["nope", "also_nope"]), None);
    }

    // ── Real-device DDL: the positions the extractor must resolve ────────────

    #[test]
    fn real_message_ddl_resolves_confirmed_positions() {
        let c = TableColumns::from_ddl(REAL_MESSAGE_DDL);
        assert_eq!(c.get("chat_row_id"), Some(1));
        assert_eq!(c.get("from_me"), Some(2));
        assert_eq!(c.get("key_id"), Some(3));
        assert_eq!(c.get("sender_jid_row_id"), Some(4));
        assert_eq!(c.get("timestamp"), Some(11));
        assert_eq!(c.get("message_type"), Some(14));
        assert_eq!(c.get("text_data"), Some(15));
        assert_eq!(c.get("starred"), Some(16));
    }

    #[test]
    fn real_message_ddl_has_no_media_columns() {
        let c = TableColumns::from_ddl(REAL_MESSAGE_DDL);
        let m = MessageColumns::resolve(&c);
        assert_eq!(
            m.media_mime_type, None,
            "modern schema moved media to message_media"
        );
        assert_eq!(m.media_name, None);
        assert_eq!(m.edit_version, None);
        assert_eq!(m.timestamp, Some(11));
        assert_eq!(m.text_data, Some(15));
    }

    #[test]
    fn real_jid_ddl_resolves_raw_string_not_user() {
        let c = TableColumns::from_ddl(REAL_JID_DDL);
        let j = JidColumns::resolve(&c);
        assert_eq!(
            j.raw_string,
            Some(5),
            "raw_string is at 5; `user` at 1 is the bare number"
        );
    }

    #[test]
    fn real_chat_ddl_resolves_subject_and_archived() {
        let c = TableColumns::from_ddl(REAL_CHAT_DDL);
        let ch = ChatColumns::resolve(&c);
        assert_eq!(ch.jid_row_id, Some(1));
        assert_eq!(ch.subject, Some(3), "subject is at 3; `hidden` sits at 2");
        assert_eq!(ch.archived, Some(10));
    }

    #[test]
    fn real_call_log_ddl_resolves_duration_and_video_call() {
        let c = TableColumns::from_ddl(REAL_CALL_LOG_DDL);
        let cl = CallLogColumns::resolve(&c);
        assert_eq!(cl.jid_row_id, Some(1));
        assert_eq!(cl.from_me, Some(2));
        assert_eq!(cl.timestamp, Some(5));
        assert_eq!(cl.video_call, Some(6));
        assert_eq!(cl.duration, Some(7));
        assert_eq!(cl.call_result, Some(8));
        assert_eq!(
            cl.call_row_id, None,
            "no call_row_id column: calls must not be grouped by a neighbouring value"
        );
    }

    // ── SchemaColumns ────────────────────────────────────────────────────────

    #[test]
    fn schema_columns_resolves_per_table() {
        let mut ddl = HashMap::new();
        ddl.insert("message".to_string(), REAL_MESSAGE_DDL.to_string());
        ddl.insert("jid".to_string(), REAL_JID_DDL.to_string());
        let sc = SchemaColumns::from_ddl_map(&ddl);
        assert!(!sc.is_empty());
        assert_eq!(sc.table("message").get("timestamp"), Some(11));
        assert_eq!(sc.table("jid").get("raw_string"), Some(5));
    }

    #[test]
    fn schema_columns_unknown_table_is_empty_not_a_panic() {
        let sc = SchemaColumns::from_ddl_map(&HashMap::new());
        assert!(sc.is_empty());
        assert!(sc.table("message").is_empty());
        assert_eq!(sc.table("message").get("timestamp"), None);
    }
}
