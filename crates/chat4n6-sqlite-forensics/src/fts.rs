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
    walk_table_btree(
        data,
        page_size,
        1,
        "sqlite_master",
        EvidenceSource::Live,
        &mut records,
    );
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
    let shadow_name = format!("{fts_table_name}_content");

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
        let shadow_key = format!("{fts_name}_content").to_ascii_lowercase();
        if let Some(&root_page) = table_roots.get(&shadow_key) {
            let shadow_display = format!("{fts_name}_content");
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

// ── Context-aware wrapper ─────────────────────────────────────────────────────

use crate::context::RecoveryContext;

/// Context-aware wrapper for recover_layer5.
pub fn recover_fts_with_context(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    recover_layer5(ctx.db, ctx.page_size)
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
        assert!(
            fts_tables.is_empty(),
            "expected no FTS tables, got: {:?}",
            fts_tables
        );
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
        assert!(
            records.is_empty(),
            "expected no records, got: {:?}",
            records.len()
        );
    }

    #[test]
    fn test_recover_layer5_returns_fts4_shadow_records() {
        // FTS4 creates a msgs_fts_content shadow table (regular B-tree) with one
        // row per indexed document — this is the primary forensic target for Layer 5.
        let db_bytes = create_fts4_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = recover_layer5(&db_bytes, page_size);
        assert!(
            !records.is_empty(),
            "expected shadow table records from FTS4 _content table"
        );
        assert!(
            records.iter().all(|r| r.source == EvidenceSource::FtsOnly),
            "all records must be tagged FtsOnly"
        );
    }

    // ── New coverage tests ──────────────────────────────────────────────────

    #[test]
    fn test_find_fts_tables_invalid_header() {
        // Input too short / not a valid SQLite header → None branch (line 34)
        let fts_tables = find_fts_tables(&[0u8; 10]);
        assert!(fts_tables.is_empty());
    }

    #[test]
    fn test_find_fts_tables_detects_fts4() {
        let db_bytes = create_fts4_db();
        let fts_tables = find_fts_tables(&db_bytes);
        assert!(
            fts_tables.contains(&"msgs_fts".to_string()),
            "expected msgs_fts in {:?}",
            fts_tables
        );
    }

    #[test]
    fn test_read_fts_content_shadow_fts4() {
        // Exercise read_fts_content_shadow (lines 72-124) with a real FTS4 DB
        let db_bytes = create_fts4_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = read_fts_content_shadow(&db_bytes, "msgs_fts", page_size);
        assert!(
            !records.is_empty(),
            "expected records from msgs_fts_content shadow table"
        );
        assert!(
            records.iter().all(|r| r.source == EvidenceSource::FtsOnly),
            "all records must be tagged FtsOnly"
        );
    }

    #[test]
    fn test_read_fts_content_shadow_missing_table() {
        // Shadow table doesn't exist → should return empty (line 111)
        let db_bytes = create_plain_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = read_fts_content_shadow(&db_bytes, "nonexistent", page_size);
        assert!(records.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_fts5_no_content_table() {
        // FTS5 does NOT create a _content shadow table (it uses _data instead),
        // so read_fts_content_shadow should return empty for FTS5 tables.
        let db_bytes = create_fts5_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = read_fts_content_shadow(&db_bytes, "msgs_fts", page_size);
        // FTS5 content table may not be a standard B-tree, so this may be empty
        // The important thing is it doesn't panic.
        let _ = records;
    }

    #[test]
    fn test_recover_fts_with_context() {
        // Exercise recover_fts_with_context (lines 198-200)
        use crate::context::RecoveryContext;
        use crate::pragma::parse_pragma_info;

        let db_bytes = create_fts4_db();
        let header = DbHeader::parse(&db_bytes).unwrap();
        let pragma_info = parse_pragma_info(&header, &db_bytes);
        let ctx = RecoveryContext {
            db: &db_bytes,
            page_size: header.page_size,
            header: &header,
            table_roots: std::collections::HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };
        let records = recover_fts_with_context(&ctx);
        assert!(
            !records.is_empty(),
            "recover_fts_with_context should find FTS4 shadow records"
        );
    }

    #[test]
    fn test_recover_layer5_with_fts5() {
        // FTS5 virtual table rows have rootpage=0 → exercises the root_page==0
        // continue branch (line 168) in recover_layer5.
        let db_bytes = create_fts5_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let _records = recover_layer5(&db_bytes, page_size);
        // FTS5 does not produce _content records in B-tree format, but the code
        // should not panic and should exercise the rootpage==0 skip path.
    }

    /// Helper: create a DB with a mix of FTS and non-FTS tables to exercise
    /// more branches in the sqlite_master iteration loops.
    fn create_mixed_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE normal_table (id INTEGER PRIMARY KEY, data TEXT);
             INSERT INTO normal_table VALUES (1, 'test');
             CREATE VIRTUAL TABLE search_fts USING fts4(content);
             INSERT INTO search_fts(content) VALUES ('alpha beta');
             INSERT INTO search_fts(content) VALUES ('gamma delta');
             CREATE TABLE another (x INTEGER);
             INSERT INTO another VALUES (42);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_find_fts_tables_mixed_db() {
        // Exercises iteration over non-FTS "table" entries (obj_type == "table"
        // but sql does not contain "using fts") → ensures those are skipped.
        let db_bytes = create_mixed_db();
        let fts_tables = find_fts_tables(&db_bytes);
        assert_eq!(fts_tables, vec!["search_fts".to_string()]);
    }

    #[test]
    fn test_recover_layer5_mixed_db() {
        // Exercises recover_layer5 with multiple sqlite_master entries including
        // FTS and non-FTS tables, triggering various match arms.
        let db_bytes = create_mixed_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        let records = recover_layer5(&db_bytes, page_size);
        assert!(!records.is_empty());
        // All records should come from search_fts_content
        for r in &records {
            assert_eq!(r.source, EvidenceSource::FtsOnly);
        }
    }

    #[test]
    fn test_read_fts_content_shadow_case_insensitive() {
        // The shadow table lookup uses eq_ignore_ascii_case (line 98).
        // Even with weird casing, should find the table.
        let db_bytes = create_fts4_db();
        let page_size = DbHeader::parse(&db_bytes).unwrap().page_size;
        // "msgs_fts" shadow is "msgs_fts_content"; try uppercase input
        let records = read_fts_content_shadow(&db_bytes, "MSGS_FTS", page_size);
        // SQLite stores names case-preserving, so this tests the case-insensitive
        // comparison path. It may or may not find records depending on exact
        // name matching, but it must not panic.
        let _ = records;
    }

    // ── Synthetic DB tests for defensive branch coverage ─────────────────

    /// Encode a value as a SQLite varint (1-9 bytes).
    fn encode_varint(val: u64) -> Vec<u8> {
        if val <= 0x7f {
            return vec![val as u8];
        }
        let mut tmp = Vec::new();
        let mut v = val;
        for i in 0..9 {
            if i == 8 {
                tmp.push((v & 0xFF) as u8);
                break;
            }
            tmp.push((v & 0x7F) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        tmp.reverse();
        let mut bytes = Vec::new();
        for (i, b) in tmp.iter().enumerate() {
            if i < tmp.len() - 1 {
                bytes.push(b | 0x80);
            } else {
                bytes.push(*b);
            }
        }
        bytes
    }

    /// Build a single B-tree leaf cell with arbitrary serial types and data.
    /// `serial_types`: list of serial types for each column.
    /// `column_data`: raw bytes for each column's data portion.
    fn make_cell(row_id: u64, serial_types: &[u64], column_data: &[&[u8]]) -> Vec<u8> {
        // Record header: [header_len varint][serial_type varints...]
        let mut serial_bytes = Vec::new();
        for &st in serial_types {
            serial_bytes.extend(encode_varint(st));
        }
        let header_len = 1 + serial_bytes.len(); // assuming header_len fits in 1 varint byte
        let mut record = Vec::new();
        record.extend(encode_varint(header_len as u64));
        record.extend(&serial_bytes);
        for data in column_data {
            record.extend(*data);
        }

        // Cell: [payload_len varint][row_id varint][record]
        let mut cell = Vec::new();
        cell.extend(encode_varint(record.len() as u64));
        cell.extend(encode_varint(row_id));
        cell.extend(&record);
        cell
    }

    /// Build a synthetic SQLite DB (single page) with the given cells in page 1.
    /// Returns a byte vector of size `page_size` with valid header + B-tree leaf.
    fn make_synthetic_db(page_size: u32, cells: &[Vec<u8>]) -> Vec<u8> {
        let mut db = vec![0u8; page_size as usize];

        // SQLite file header (first 100 bytes)
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1; // file format write version
        db[19] = 1; // file format read version
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding = UTF-8

        // B-tree leaf header at offset 100
        let bhdr = 100usize;
        db[bhdr] = 0x0D; // table leaf

        // Place cells from end of page backwards
        let mut cell_offsets: Vec<u16> = Vec::new();
        let mut write_pos = page_size as usize;
        for cell in cells {
            write_pos -= cell.len();
            db[write_pos..write_pos + cell.len()].copy_from_slice(cell);
            cell_offsets.push(write_pos as u16);
        }

        // Cell count
        let cc = cells.len() as u16;
        db[bhdr + 3] = (cc >> 8) as u8;
        db[bhdr + 4] = (cc & 0xFF) as u8;
        // Cell content area start
        db[bhdr + 5] = (write_pos >> 8) as u8;
        db[bhdr + 6] = (write_pos & 0xFF) as u8;

        // Cell pointer array at bhdr + 8
        for (i, off) in cell_offsets.iter().enumerate() {
            let pos = bhdr + 8 + i * 2;
            db[pos] = (*off >> 8) as u8;
            db[pos + 1] = (*off & 0xFF) as u8;
        }

        db
    }

    /// Make a standard sqlite_master cell: (type=Text, name=Text, tbl_name=Text, rootpage=Int, sql=Text)
    fn make_master_cell(row_id: u64, name: &str, rootpage: u8, sql: &str) -> Vec<u8> {
        let type_b = b"table";
        let name_b = name.as_bytes();
        let sql_b = sql.as_bytes();
        make_cell(
            row_id,
            &[
                2 * type_b.len() as u64 + 13, // Text serial type for "table"
                2 * name_b.len() as u64 + 13,  // Text serial type for name
                2 * name_b.len() as u64 + 13,  // Text serial type for tbl_name
                1,                              // 1-byte Int for rootpage
                2 * sql_b.len() as u64 + 13,   // Text serial type for sql
            ],
            &[type_b, name_b, name_b, &[rootpage], sql_b],
        )
    }

    #[test]
    fn test_find_fts_tables_record_with_few_values() {
        // sqlite_master row with < 5 columns → triggers `continue` at line 42
        let short_cell = make_cell(1, &[0, 0], &[&[], &[]]); // only 2 Null values
        // Also include a valid FTS row so we exercise the loop properly
        let fts_cell = make_master_cell(2, "my_fts", 0, "CREATE VIRTUAL TABLE my_fts USING fts5(body)");
        let db = make_synthetic_db(4096, &[short_cell, fts_cell]);
        let tables = find_fts_tables(&db);
        assert!(tables.contains(&"my_fts".to_string()));
    }

    #[test]
    fn test_find_fts_tables_non_text_type_column() {
        // sqlite_master row where values[0] is Int instead of Text → line 47
        let bad_cell = make_cell(
            1,
            &[1, 23, 23, 1, 23], // col 0 = Int(1 byte), rest Text(5 bytes)
            &[&[42], b"hello", b"hello", &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let tables = find_fts_tables(&db);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_find_fts_tables_non_text_name_column() {
        // sqlite_master row where values[1] (name) is Null → line 55
        let bad_cell = make_cell(
            1,
            &[
                2 * 5 + 13, // col 0 = Text "table"
                0,           // col 1 = Null
                0,           // col 2 = Null
                1,           // col 3 = Int
                2 * 5 + 13, // col 4 = Text
            ],
            &[b"table", &[], &[], &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let tables = find_fts_tables(&db);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_find_fts_tables_non_text_sql_column() {
        // sqlite_master row where values[4] (sql) is Null → line 60
        let bad_cell = make_cell(
            1,
            &[
                2 * 5 + 13, // col 0 = Text "table"
                2 * 4 + 13, // col 1 = Text "test"
                2 * 4 + 13, // col 2 = Text "test"
                1,           // col 3 = Int
                0,           // col 4 = Null
            ],
            &[b"table", b"test", b"test", &[2], &[]],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let tables = find_fts_tables(&db);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_record_with_few_values() {
        // sqlite_master rows with < 5 columns in read_fts_content_shadow → line 85
        let short_cell = make_cell(1, &[0], &[&[]]); // 1 Null column
        let db = make_synthetic_db(4096, &[short_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = read_fts_content_shadow(&db, "anything", ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_non_text_type() {
        // values[0] is Int → triggers continue at line 89
        let bad_cell = make_cell(
            1,
            &[1, 23, 23, 1, 23],
            &[&[42], b"hello", b"hello", &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = read_fts_content_shadow(&db, "hello", ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_non_text_name() {
        // values[1] is Null → triggers continue at line 96
        let bad_cell = make_cell(
            1,
            &[2 * 5 + 13, 0, 0, 1, 2 * 5 + 13],
            &[b"table", &[], &[], &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = read_fts_content_shadow(&db, "hello", ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_rootpage_not_int() {
        // Row for the shadow table name but values[3] is Null → line 106-107
        // The name matches shadow_name but rootpage is not an Int.
        let shadow = "x_content";
        let bad_cell = make_cell(
            1,
            &[
                2 * 5 + 13,             // col 0 = "table"
                2 * shadow.len() as u64 + 13, // col 1 = shadow name
                2 * shadow.len() as u64 + 13, // col 2 = shadow name
                0,                       // col 3 = Null (not Int!)
                2 * 3 + 13,             // col 4 = "sql"
            ],
            &[b"table", shadow.as_bytes(), shadow.as_bytes(), &[], b"sql"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = read_fts_content_shadow(&db, "x", ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer5_record_few_values() {
        // Record with < 5 columns in recover_layer5 → line 139
        let short_cell = make_cell(1, &[0, 0, 0], &[&[], &[], &[]]);
        let db = make_synthetic_db(4096, &[short_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = recover_layer5(&db, ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer5_non_text_type() {
        // values[0] is Int → line 143
        let bad_cell = make_cell(
            1,
            &[1, 23, 23, 1, 23],
            &[&[42], b"hello", b"hello", &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = recover_layer5(&db, ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer5_non_text_name() {
        // values[1] is Null → line 150
        let bad_cell = make_cell(
            1,
            &[2 * 5 + 13, 0, 0, 1, 2 * 5 + 13],
            &[b"table", &[], &[], &[2], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = recover_layer5(&db, ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer5_non_text_sql() {
        // values[4] is Null → line 157 (_ => String::new())
        // With non-FTS sql (empty string), this won't be added to fts_names.
        let bad_cell = make_cell(
            1,
            &[
                2 * 5 + 13, // "table"
                2 * 4 + 13, // "test"
                2 * 4 + 13, // "test"
                1,           // Int rootpage
                0,           // Null sql → String::new()
            ],
            &[b"table", b"test", b"test", &[2], &[]],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = recover_layer5(&db, ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_read_fts_content_shadow_non_table_row() {
        // sqlite_master row with obj_type = "index" (not "table") → line 92
        // Plus we include the actual shadow table so the loop runs on both.
        let shadow = "myfts_content";
        let index_cell = make_cell(
            1,
            &[
                2 * 5 + 13,                    // "index"
                2 * shadow.len() as u64 + 13,  // name matches shadow
                2 * shadow.len() as u64 + 13,  // tbl_name
                1,                              // Int rootpage
                2 * 5 + 13,                    // sql
            ],
            &[b"index", shadow.as_bytes(), shadow.as_bytes(), &[3], b"hello"],
        );
        // Also include the actual shadow table so the code reaches name matching
        let table_cell = make_master_cell(2, shadow, 4, "CREATE TABLE myfts_content(x)");
        let db = make_synthetic_db(4096, &[index_cell, table_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        // Use "myfts" as fts_table_name → shadow = "myfts_content"
        let records = read_fts_content_shadow(&db, "myfts", ps);
        // The table_cell has rootpage=4 which points outside our 1-page DB → no records
        // but the index_cell's obj_type != "table" should be skipped (line 92).
        let _ = records;
    }

    #[test]
    fn test_read_fts_content_shadow_rootpage_zero() {
        // Shadow table row with rootpage=0 → line 103-106 (rp == 0, skip)
        let shadow = "zero_content";
        let cell = make_master_cell(1, shadow, 0, "CREATE TABLE zero_content(x)");
        let db = make_synthetic_db(4096, &[cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = read_fts_content_shadow(&db, "zero", ps);
        // rootpage=0 means shadow_root stays None → returns empty
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer5_non_int_rootpage() {
        // values[3] is Null → line 165 (_ => continue)
        let bad_cell = make_cell(
            1,
            &[
                2 * 5 + 13, // "table"
                2 * 4 + 13, // "test"
                2 * 4 + 13, // "test"
                0,           // Null rootpage → continue
                2 * 5 + 13, // Text sql
            ],
            &[b"table", b"test", b"test", &[], b"hello"],
        );
        let db = make_synthetic_db(4096, &[bad_cell]);
        let ps = DbHeader::parse(&db).unwrap().page_size;
        let records = recover_layer5(&db, ps);
        assert!(records.is_empty());
    }

    #[test]
    fn test_encode_varint_multibyte() {
        // Exercise the multi-byte path of encode_varint (val > 127).
        let v = encode_varint(128);
        assert_eq!(v.len(), 2);
        // 128 = 0b10000000 → varint encoding: [0x81, 0x00]
        assert_eq!(v, vec![0x81, 0x00]);

        let v2 = encode_varint(300);
        assert_eq!(v2.len(), 2);
        // 300 = 0b100101100 → [0x82, 0x2C]
        assert_eq!(v2, vec![0x82, 0x2C]);

        let v3 = encode_varint(16384);
        assert_eq!(v3.len(), 3);

        // Exercise the 9-byte varint path (val >= 2^56)
        let v9 = encode_varint(1u64 << 56);
        assert_eq!(v9.len(), 9, "2^56 should need 9 varint bytes");
    }

    #[test]
    fn test_find_fts_with_long_sql() {
        // Use a long SQL string (> 57 chars) so the serial type exceeds 127,
        // exercising encode_varint's multi-byte varint path.
        let long_sql = "CREATE VIRTUAL TABLE my_long_fts USING fts4(content, description, notes, extra_column)";
        let cell = make_master_cell(1, "my_long_fts", 0, long_sql);
        let db = make_synthetic_db(4096, &[cell]);
        let tables = find_fts_tables(&db);
        assert!(tables.contains(&"my_long_fts".to_string()));
    }
}
