use crate::btree::walk_table_btree;
use crate::header::DbHeader;
use crate::record::{RecoveredRecord, SqlValue};
use chat4n6_plugin_api::EvidenceSource;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_sqlite_master_records(data: &[u8], page_size: u32) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    walk_table_btree(data, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut records);
    records
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return all virtual FTS table names (fts3/fts4/fts5) found in sqlite_master.
///
/// Matches entries where the `sql` column contains "USING fts" (case-insensitive).
pub fn find_fts_tables(db_bytes: &[u8]) -> Vec<String> {
    let page_size = match DbHeader::parse(db_bytes) {
        Some(h) => h.page_size,
        None => return Vec::new(),
    };

    let master_records = read_sqlite_master_records(db_bytes, page_size);
    let mut fts_tables = Vec::new();

    for record in &master_records {
        if record.values.len() < 5 {
            continue;
        }
        // col 0 = type — virtual tables are stored as "table" in sqlite_master
        let obj_type = match &record.values[0] {
            SqlValue::Text(s) => s.as_str(),
            _ => continue,
        };
        if obj_type != "table" {
            continue;
        }
        // col 1 = name
        let name = match &record.values[1] {
            SqlValue::Text(s) => s.clone(),
            _ => continue,
        };
        // col 4 = sql — check for "USING fts" (case-insensitive)
        let sql = match &record.values[4] {
            SqlValue::Text(s) => s.clone(),
            _ => continue,
        };
        if sql.to_ascii_lowercase().contains("using fts") {
            fts_tables.push(name);
        }
    }

    fts_tables
}

/// Traverse the `{fts_table_name}_content` shadow table B-tree and return all
/// records tagged as `EvidenceSource::FtsOnly`.
pub fn read_fts_content_shadow(
    db_bytes: &[u8],
    fts_table_name: &str,
    page_size: u32,
) -> Vec<RecoveredRecord> {
    let shadow_name = format!("{}_content", fts_table_name);

    // Find the root page of the shadow table in sqlite_master
    let master_records = read_sqlite_master_records(db_bytes, page_size);

    let mut shadow_root: Option<u32> = None;
    for record in &master_records {
        if record.values.len() < 5 {
            continue;
        }
        let obj_type = match &record.values[0] {
            SqlValue::Text(s) => s.as_str(),
            _ => continue,
        };
        if obj_type != "table" {
            continue;
        }
        let name = match &record.values[1] {
            SqlValue::Text(s) => s.as_str(),
            _ => continue,
        };
        if !name.eq_ignore_ascii_case(&shadow_name) {
            continue;
        }
        if let SqlValue::Int(n) = &record.values[3] {
            let rp = *n as u32;
            if rp > 0 {
                shadow_root = Some(rp);
                break;
            }
        }
    }

    let Some(root_page) = shadow_root else {
        return Vec::new();
    };

    let mut records = Vec::new();
    walk_table_btree(
        db_bytes,
        page_size,
        root_page,
        &shadow_name,
        EvidenceSource::FtsOnly,
        &mut records,
    );
    records
}

/// Layer 5: recover all records from FTS content shadow tables.
///
/// Performs a single sqlite_master scan to locate all FTS tables and their
/// content shadow table root pages, avoiding redundant repeated scans.
pub fn recover_layer5(db_bytes: &[u8], page_size: u32) -> Vec<RecoveredRecord> {
    let master_records = read_sqlite_master_records(db_bytes, page_size);

    // Single pass: collect FTS virtual table names + all table→root_page mappings
    let mut fts_names: Vec<String> = Vec::new();
    let mut table_roots: HashMap<String, u32> = HashMap::new();

    for record in &master_records {
        if record.values.len() < 5 {
            continue;
        }
        let obj_type = match &record.values[0] {
            SqlValue::Text(s) => s.as_str(),
            _ => continue,
        };
        if obj_type != "table" {
            continue;
        }
        let name = match &record.values[1] {
            SqlValue::Text(s) => s.clone(),
            _ => continue,
        };
        // Check FTS sql BEFORE the rootpage filter: virtual table rows have rootpage=0
        // but their sql column contains "USING fts". Shadow tables have real rootpages
        // but non-FTS sql.
        let sql = match &record.values[4] {
            SqlValue::Text(s) => s.clone(),
            _ => String::new(),
        };
        if sql.to_ascii_lowercase().contains("using fts") {
            fts_names.push(name.clone());
        }

        let root_page = match &record.values[3] {
            SqlValue::Int(n) => *n as u32,
            _ => continue,
        };
        if root_page == 0 {
            continue; // virtual table placeholder — no page to traverse
        }
        // Store with lowercase key for case-insensitive shadow table lookup
        table_roots.insert(name.to_ascii_lowercase(), root_page);
    }

    // Traverse each FTS content shadow table using the pre-built root map
    let mut all_records = Vec::new();
    for fts_name in &fts_names {
        let shadow_key = format!("{}_content", fts_name).to_ascii_lowercase();
        if let Some(&root_page) = table_roots.get(&shadow_key) {
            let shadow_display = format!("{}_content", fts_name);
            walk_table_btree(
                db_bytes,
                page_size,
                root_page,
                &shadow_display,
                EvidenceSource::FtsOnly,
                &mut all_records,
            );
        }
    }
    all_records
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DbHeader;

    fn create_plain_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT);
             INSERT INTO messages VALUES (1, 'hello world');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    /// FTS5 db for detection tests (find_fts_tables).
    fn create_fts5_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE msgs_fts USING fts5(body);
             INSERT INTO msgs_fts VALUES ('hello world');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    /// FTS4 db for shadow-table recovery tests.
    ///
    /// FTS4 creates a `_content` shadow table (a regular B-tree table) that our
    /// carver reads. FTS5 does not create `_content` — it stores content in `_data`
    /// using a different internal format.
    fn create_fts4_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE msgs_fts USING fts4(body);
             INSERT INTO msgs_fts(body) VALUES ('hello world');
             INSERT INTO msgs_fts(body) VALUES ('forensic evidence');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_find_fts_tables_empty_db() {
        let db_bytes = create_plain_db();
        let fts_tables = find_fts_tables(&db_bytes);
        assert!(fts_tables.is_empty(), "expected no FTS tables, got: {:?}", fts_tables);
    }

    #[test]
    fn test_find_fts_tables_detects_fts5() {
        let db_bytes = create_fts5_db();
        let fts_tables = find_fts_tables(&db_bytes);
        assert!(
            fts_tables.contains(&"msgs_fts".to_string()),
            "expected msgs_fts in {:?}",
            fts_tables
        );
    }

    #[test]
    fn test_recover_layer5_empty_when_no_fts() {
        let db_bytes = create_plain_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = recover_layer5(&db_bytes, page_size);
        assert!(records.is_empty(), "expected no records, got: {:?}", records.len());
    }

    #[test]
    fn test_recover_layer5_returns_fts4_shadow_records() {
        // FTS4 creates a msgs_fts_content shadow table (regular B-tree) with one
        // row per indexed document — this is the primary forensic target for Layer 5.
        let db_bytes = create_fts4_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = recover_layer5(&db_bytes, page_size);
        assert!(!records.is_empty(), "expected shadow table records from FTS4 _content table");
        assert!(
            records.iter().all(|r| r.source == EvidenceSource::FtsOnly),
            "all records must be tagged FtsOnly"
        );
    }
}
