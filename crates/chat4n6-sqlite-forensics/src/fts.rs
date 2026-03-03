use crate::btree::parse_table_leaf_page;
use crate::header::DbHeader;
use crate::page::PageType;
use crate::record::{RecoveredRecord, SqlValue};
use chat4n6_plugin_api::EvidenceSource;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Internal helpers (mirrors db.rs private helpers without requiring pub access)
// ---------------------------------------------------------------------------

fn page_data_fts<'a>(data: &'a [u8], page_number: u32, page_size: usize) -> Option<(&'a [u8], usize)> {
    if page_number == 0 {
        return None;
    }
    let page_start = (page_number as usize - 1) * page_size;
    let page_end = page_number as usize * page_size;
    let slice = data.get(page_start..page_end)?;
    let bhdr = if page_number == 1 { 100 } else { 0 };
    Some((slice, bhdr))
}

fn traverse_btree_fts(
    data: &[u8],
    page_size: u32,
    root_page: u32,
    table: &str,
    source: EvidenceSource,
    records: &mut Vec<RecoveredRecord>,
) {
    let mut stack = vec![root_page];
    let mut visited: HashSet<u32> = HashSet::new();
    while let Some(page_num) = stack.pop() {
        if !visited.insert(page_num) {
            continue;
        }
        let Some((page_data, bhdr)) = page_data_fts(data, page_num, page_size as usize) else {
            continue;
        };
        if page_data.len() <= bhdr {
            continue;
        }

        match PageType::from_byte(page_data[bhdr]) {
            Some(PageType::TableLeaf) => {
                let mut page_records =
                    parse_table_leaf_page(page_data, bhdr, page_num, page_size, table);
                // Override source to FtsOnly for all records from shadow tables
                for r in &mut page_records {
                    r.source = source.clone();
                }
                records.extend(page_records);
            }
            Some(PageType::TableInterior) => {
                let cell_count = if page_data.len() >= bhdr + 5 {
                    u16::from_be_bytes([page_data[bhdr + 3], page_data[bhdr + 4]]) as usize
                } else {
                    0
                };
                if page_data.len() >= bhdr + 12 {
                    let right = u32::from_be_bytes([
                        page_data[bhdr + 8],
                        page_data[bhdr + 9],
                        page_data[bhdr + 10],
                        page_data[bhdr + 11],
                    ]);
                    if right != 0 {
                        stack.push(right);
                    }
                }
                let ptr_array_start = bhdr + 12;
                for i in 0..cell_count {
                    let ptr_off = ptr_array_start + i * 2;
                    if ptr_off + 2 > page_data.len() {
                        break;
                    }
                    let cell_off = u16::from_be_bytes([
                        page_data[ptr_off],
                        page_data[ptr_off + 1],
                    ]) as usize;
                    if cell_off + 4 > page_data.len() {
                        continue;
                    }
                    let left = u32::from_be_bytes([
                        page_data[cell_off],
                        page_data[cell_off + 1],
                        page_data[cell_off + 2],
                        page_data[cell_off + 3],
                    ]);
                    if left != 0 {
                        stack.push(left);
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Read sqlite_master page 1 and return all records
// ---------------------------------------------------------------------------

fn read_sqlite_master_records(data: &[u8], page_size: u32) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    traverse_btree_fts(data, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut records);
    records
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return all virtual FTS table names (fts3/fts4/fts5) found in sqlite_master.
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
        // col 0 = type — must be "table" (virtual tables are stored as "table")
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
    traverse_btree_fts(
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
pub fn recover_layer5(db_bytes: &[u8], page_size: u32) -> Vec<RecoveredRecord> {
    let fts_tables = find_fts_tables(db_bytes);
    let mut all_records = Vec::new();
    for fts_table in &fts_tables {
        let shadow_records = read_fts_content_shadow(db_bytes, fts_table, page_size);
        all_records.extend(shadow_records);
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

    fn create_fts5_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE msgs_fts USING fts5(body);
             INSERT INTO msgs_fts VALUES ('hello world');
             INSERT INTO msgs_fts VALUES ('forensic evidence');",
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
}
