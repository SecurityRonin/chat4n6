use crate::page::PageType;
use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::varint::read_varint;
use chat4n6_plugin_api::EvidenceSource;
use std::collections::{HashMap, HashSet};

/// Return the page data slice and B-tree header offset for a 1-based page number.
///
/// For page 1 the B-tree header starts at byte 100 (after the SQLite file header).
/// For all other pages it starts at byte 0.
/// Returns `None` if the page number is 0 or the slice is out of bounds.
pub(crate) fn get_page_data(
    db: &[u8],
    page_number: u32,
    page_size: usize,
) -> Option<(&[u8], usize)> {
    if page_number == 0 {
        return None;
    }
    let page_start = (page_number as usize - 1) * page_size;
    let page_end = page_number as usize * page_size;
    let slice = db.get(page_start..page_end)?;
    let bhdr = if page_number == 1 { 100 } else { 0 };
    Some((slice, bhdr))
}

/// Walk a table B-tree rooted at `root_page`, collecting all leaf records into `records`.
///
/// `source` is applied to every record (use `EvidenceSource::Live` for live tables,
/// `EvidenceSource::FtsOnly` for FTS shadow tables, etc.).
/// Includes a cycle guard to handle corrupt page pointer loops.
pub(crate) fn walk_table_btree(
    db: &[u8],
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
            continue; // cycle guard
        }
        let Some((page_data, bhdr)) = get_page_data(db, page_num, page_size as usize) else {
            continue;
        };
        if page_data.len() <= bhdr {
            continue;
        }
        match PageType::from_byte(page_data[bhdr]) {
            Some(PageType::TableLeaf) => {
                let mut page_records =
                    parse_table_leaf_page(db, page_data, bhdr, page_num, page_size, table);
                for r in &mut page_records {
                    r.source = source.clone();
                }
                records.extend(page_records);
            }
            Some(PageType::TableInterior) => {
                // Interior B-tree page header is 12 bytes from bhdr:
                //   +0: page type (0x05)
                //   +1-2: first freeblock
                //   +3-4: cell count
                //   +5-6: cell content area
                //   +7: fragmented bytes
                //   +8-11: right-most child page number
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
                    let cell_off =
                        u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
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

/// Get page data, checking the WAL overlay first.
/// Returns owned data for overlay pages, borrowed (cloned to owned) for DB pages.
pub(crate) fn get_overlay_page(
    db: &[u8],
    page_number: u32,
    page_size: usize,
    overlay: &HashMap<u32, Vec<u8>>,
) -> Option<(Vec<u8>, usize)> {
    if let Some(page_data) = overlay.get(&page_number) {
        let bhdr_offset = if page_number == 1 { 100 } else { 0 };
        Some((page_data.clone(), bhdr_offset))
    } else {
        let (slice, bhdr) = get_page_data(db, page_number, page_size)?;
        Some((slice.to_vec(), bhdr))
    }
}

/// Walk a table B-tree using WAL overlay for page data.
/// The overlay provides WAL-version pages; DB provides baseline pages for non-overridden pages.
pub(crate) fn walk_table_btree_with_overlay(
    db: &[u8],
    page_size: u32,
    root_page: u32,
    table: &str,
    overlay: &HashMap<u32, Vec<u8>>,
    records: &mut Vec<RecoveredRecord>,
) {
    let mut stack = vec![root_page];
    let mut visited: HashSet<u32> = HashSet::new();
    while let Some(page_num) = stack.pop() {
        if !visited.insert(page_num) {
            continue;
        }
        let Some((page_data, bhdr)) = get_overlay_page(db, page_num, page_size as usize, overlay)
        else {
            continue;
        };
        if page_data.len() <= bhdr {
            continue;
        }
        match PageType::from_byte(page_data[bhdr]) {
            Some(PageType::TableLeaf) => {
                let mut page_records =
                    parse_table_leaf_page(db, &page_data, bhdr, page_num, page_size, table);
                for r in &mut page_records {
                    r.source = EvidenceSource::Live;
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
                    let cell_off =
                        u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
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

/// Follow an overflow page chain and collect all overflow payload data.
///
/// `first_overflow_page` is the 1-based page number of the first overflow page.
/// `remaining` is the number of payload bytes still to be collected from overflow.
/// Returns a Vec containing the overflow bytes (up to `remaining` bytes).
fn follow_overflow_chain(
    db: &[u8],
    first_overflow_page: u32,
    page_size: usize,
    remaining: usize,
) -> Vec<u8> {
    let mut result = Vec::with_capacity(remaining);
    let mut current_page = first_overflow_page;
    let mut left = remaining;
    let mut visited = std::collections::HashSet::new();

    while current_page != 0 && left > 0 {
        if !visited.insert(current_page) {
            break; // cycle guard
        }
        let page_start = (current_page as usize - 1) * page_size;
        let page_end = page_start + page_size;
        let Some(page_data) = db.get(page_start..page_end) else {
            break;
        };
        if page_data.len() < 4 {
            break;
        }

        let next_page =
            u32::from_be_bytes([page_data[0], page_data[1], page_data[2], page_data[3]]);
        let usable_on_overflow = page_size - 4;
        let to_copy = left.min(usable_on_overflow);
        if let Some(overflow_data) = page_data.get(4..4 + to_copy) {
            result.extend_from_slice(overflow_data);
            left -= to_copy;
        } else {
            break;
        }

        current_page = next_page;
    }

    result
}

/// Parse all cells from a table leaf page (0x0D).
///
/// `db` is the full database byte slice, used to follow overflow page chains.
/// `page_data` is the full page slice from byte 0 of the page.
/// `bhdr` is the offset within `page_data` where the B-tree page header starts
/// (100 for page 1 due to the SQLite file header, 0 for all other pages).
/// Cell offsets in the pointer array are always relative to byte 0 of `page_data`.
pub fn parse_table_leaf_page(
    db: &[u8],
    page_data: &[u8],
    bhdr: usize,
    page_number: u32,
    page_size: u32,
    table: &str,
) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();

    // B-tree page header layout (leaf, 8 bytes from bhdr):
    //   bhdr+0: page type
    //   bhdr+1-2: first freeblock offset
    //   bhdr+3-4: cell count
    //   bhdr+5-6: cell content area offset
    //   bhdr+7: fragmented free bytes
    if page_data.len() < bhdr + 8 {
        return records;
    }

    let cell_count = u16::from_be_bytes([page_data[bhdr + 3], page_data[bhdr + 4]]) as usize;
    // Cell pointer array starts immediately after the 8-byte leaf header
    let ptr_array_start = bhdr + 8;

    // Overflow thresholds for a table B-tree leaf page.
    // From SQLite file format spec section 2.3.1:
    //   X = U - 35  (max bytes stored inline before overflowing)
    //   M = ((U-12)*32/255) - 23  (minimum inline bytes when overflow occurs)
    //   K = M + ((P-M) % (U-4))  where P = total payload size
    //   If K <= X: store K bytes inline; else store M bytes inline.
    // where U = usable page size (assuming 0 reserved bytes).
    let usable = page_size as usize;
    let max_local = usable - 35; // X: table leaf threshold
    let min_local = (usable - 12) * 32 / 255 - 23; // M

    for i in 0..cell_count {
        let ptr_offset = ptr_array_start + i * 2;
        if ptr_offset + 2 > page_data.len() {
            break;
        }
        // Cell offset is relative to byte 0 of the page (not bhdr)
        let cell_offset =
            u16::from_be_bytes([page_data[ptr_offset], page_data[ptr_offset + 1]]) as usize;
        if cell_offset == 0 || cell_offset >= page_data.len() {
            continue;
        }

        // Parse cell: [payload_length varint][row_id varint][payload]
        let mut pos = cell_offset;
        let (payload_len, pl_consumed) = match read_varint(page_data, pos) {
            Some(v) => v,
            None => continue,
        };
        pos += pl_consumed;

        let (row_id_raw, rid_consumed) = match read_varint(page_data, pos) {
            Some(v) => v,
            None => continue,
        };
        pos += rid_consumed;
        let row_id = row_id_raw as i64;

        // Determine whether this cell spills to overflow pages.
        // If so, assemble the full payload into an owned Vec and parse from that.
        // Otherwise parse directly from page_data at `pos`.
        let payload_len_usize = payload_len as usize;
        let owned_payload: Option<Vec<u8>>;

        if payload_len_usize > max_local {
            // Calculate how many bytes are stored inline on this page (K or M).
            let mut local_size = min_local + (payload_len_usize - min_local) % (usable - 4);
            if local_size > max_local {
                local_size = min_local;
            }

            // Inline payload is page_data[pos .. pos+local_size].
            // The 4-byte overflow page pointer immediately follows in the cell body.
            let local_end = pos + local_size;
            let overflow_ptr_pos = local_end;

            if overflow_ptr_pos + 4 <= page_data.len() {
                let overflow_page = u32::from_be_bytes([
                    page_data[overflow_ptr_pos],
                    page_data[overflow_ptr_pos + 1],
                    page_data[overflow_ptr_pos + 2],
                    page_data[overflow_ptr_pos + 3],
                ]);

                let local_end_clamped = local_end.min(page_data.len());
                let local_bytes = &page_data[pos..local_end_clamped];
                // Bytes still needed from overflow chain = total payload minus inline bytes.
                let overflow_remaining = payload_len_usize - local_size;

                let overflow_data = follow_overflow_chain(
                    db,
                    overflow_page,
                    page_size as usize,
                    overflow_remaining,
                );

                let mut full = Vec::with_capacity(payload_len_usize);
                full.extend_from_slice(local_bytes);
                full.extend(overflow_data);
                owned_payload = Some(full);
            } else {
                // Can't read overflow pointer — fall back to inline-only parsing.
                owned_payload = None;
            }
        } else {
            owned_payload = None;
        }

        // payload_slice points into the assembled payload (owned) or page_data (inline).
        // record_start is where the SQLite record format begins within payload_slice.
        let payload_slice: &[u8] = match owned_payload.as_deref() {
            Some(s) => s,
            None => page_data,
        };
        let record_start = if owned_payload.is_some() { 0 } else { pos };

        // Parse the record header: [header_len varint][serial_type varints...]
        let payload_start = record_start;
        let (header_len, hl_consumed) = match read_varint(payload_slice, record_start) {
            Some(v) => v,
            None => continue,
        };
        let mut hdr_pos = record_start + hl_consumed;

        let header_end = payload_start + header_len as usize;
        if header_end > payload_slice.len() {
            continue; // truncated/malformed cell — skip rather than emit null-filled record
        }

        // Parse serial types
        let mut serial_types = Vec::new();
        while hdr_pos < header_end && hdr_pos < payload_slice.len() {
            let (st, consumed) = match read_varint(payload_slice, hdr_pos) {
                Some(v) => v,
                None => break,
            };
            serial_types.push(st);
            hdr_pos += consumed;
        }

        // Decode values
        let mut values = Vec::new();
        let mut data_pos = header_end;
        for &st in &serial_types {
            match decode_serial_type(st, payload_slice, data_pos) {
                Some((val, consumed)) => {
                    data_pos += consumed;
                    values.push(val);
                }
                None => {
                    values.push(SqlValue::Null);
                }
            }
        }

        // Absolute file offset of this cell
        let abs_offset = (page_number as u64 - 1) * page_size as u64 + cell_offset as u64;

        records.push(RecoveredRecord {
            table: table.to_string(),
            row_id: Some(row_id),
            values,
            source: EvidenceSource::Live,
            offset: abs_offset,
            confidence: 1.0,
        });
    }

    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::EvidenceSource;

    // ---------------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------------

    fn create_simple_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
             INSERT INTO items VALUES (1, 'alpha');
             INSERT INTO items VALUES (2, 'beta');",
        )
        .unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    fn create_empty_table_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE empty_tbl (id INTEGER PRIMARY KEY, val TEXT);",
        )
        .unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    fn create_multi_page_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=1024;").unwrap();
        conn.execute_batch("CREATE TABLE big (id INTEGER PRIMARY KEY, data TEXT);")
            .unwrap();
        for i in 0..200i64 {
            conn.execute(
                "INSERT INTO big VALUES (?, ?)",
                rusqlite::params![i, format!("record_{:04}_padding_to_make_it_longer", i)],
            )
            .unwrap();
        }
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree tests
    // ---------------------------------------------------------------------------

    /// Walk sqlite_master (page 1) on a simple DB and find the "items" table entry.
    #[test]
    fn test_walk_table_btree_simple() {
        let db = create_simple_db();
        // Read page_size from header bytes 16-17 (big-endian u16)
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let page_size = if page_size == 1 { 65536u32 } else { page_size };

        // sqlite_master is at root page 1; walk it for the "sqlite_master" table name
        let mut records = Vec::new();
        walk_table_btree(&db, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut records);

        // There should be at least one entry for the "items" table definition
        assert!(
            !records.is_empty(),
            "Expected at least one sqlite_master record, got 0"
        );
        // At least one record's values should contain a Text("items") somewhere
        let found = records.iter().any(|r| {
            r.values.iter().any(|v| {
                if let crate::record::SqlValue::Text(s) = v {
                    s == "items"
                } else {
                    false
                }
            })
        });
        assert!(found, "Expected to find 'items' entry in sqlite_master records");
    }

    /// Walking an empty table returns 0 records.
    #[test]
    fn test_walk_table_btree_empty_table() {
        let db = create_empty_table_db();
        let page_size = {
            let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };

        // Find empty_tbl root page from sqlite_master
        let mut master_records = Vec::new();
        walk_table_btree(
            &db,
            page_size,
            1,
            "sqlite_master",
            EvidenceSource::Live,
            &mut master_records,
        );

        // Locate the rootpage (values[3] in sqlite_master: type, name, tbl_name, rootpage, sql)
        let root_page = master_records
            .iter()
            .find(|r| {
                r.values.get(1).map_or(false, |v| {
                    matches!(v, crate::record::SqlValue::Text(s) if s == "empty_tbl")
                })
            })
            .and_then(|r| {
                if let Some(crate::record::SqlValue::Int(n)) = r.values.get(3) {
                    Some(*n as u32)
                } else {
                    None
                }
            })
            .expect("empty_tbl not found in sqlite_master");

        let mut records = Vec::new();
        walk_table_btree(&db, page_size, root_page, "empty_tbl", EvidenceSource::Live, &mut records);
        assert_eq!(records.len(), 0, "Empty table should yield 0 records");
    }

    /// Walk a 200-row table with 1024-byte pages — all 200 records are recovered.
    #[test]
    fn test_walk_table_btree_multi_page() {
        let db = create_multi_page_db();
        let page_size = {
            let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };

        // Get big table root page from sqlite_master
        let mut master_records = Vec::new();
        walk_table_btree(
            &db,
            page_size,
            1,
            "sqlite_master",
            EvidenceSource::Live,
            &mut master_records,
        );

        let root_page = master_records
            .iter()
            .find(|r| {
                r.values.get(1).map_or(false, |v| {
                    matches!(v, crate::record::SqlValue::Text(s) if s == "big")
                })
            })
            .and_then(|r| {
                if let Some(crate::record::SqlValue::Int(n)) = r.values.get(3) {
                    Some(*n as u32)
                } else {
                    None
                }
            })
            .expect("big table not found in sqlite_master");

        let mut records = Vec::new();
        walk_table_btree(&db, page_size, root_page, "big", EvidenceSource::Live, &mut records);
        assert_eq!(records.len(), 200, "Expected all 200 records, got {}", records.len());
    }

    /// Requesting a non-existent root page must not panic and must yield empty results.
    #[test]
    fn test_walk_table_btree_invalid_root_page() {
        let db = create_simple_db();
        let page_size = {
            let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };

        let mut records = Vec::new();
        walk_table_btree(&db, page_size, 9999, "ghost", EvidenceSource::Live, &mut records);
        assert_eq!(records.len(), 0, "Out-of-range root page must yield empty results");
    }

    // ---------------------------------------------------------------------------
    // get_overlay_page tests
    // ---------------------------------------------------------------------------

    /// A page not present in the overlay is fetched from the DB bytes.
    #[test]
    fn test_get_overlay_page_not_in_overlay() {
        let db = create_simple_db();
        let page_size = {
            let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };
        let overlay: HashMap<u32, Vec<u8>> = HashMap::new();
        // Page 1 exists in DB; overlay has nothing — should return Some from DB
        let result = get_overlay_page(&db, 1, page_size as usize, &overlay);
        assert!(result.is_some(), "Page 1 should be found in DB even without overlay");
        let (data, bhdr) = result.unwrap();
        assert_eq!(bhdr, 100, "Page 1 bhdr must be 100");
        assert_eq!(data.len(), page_size as usize);
    }

    /// A page present in the overlay is returned from the overlay (not DB).
    #[test]
    fn test_get_overlay_page_in_overlay() {
        let db = create_simple_db();
        let page_size = {
            let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };
        // Build a fake overlay page with a recognizable sentinel byte pattern
        let mut fake_page = vec![0xAAu8; page_size as usize];
        fake_page[0] = 0xBB;
        let mut overlay: HashMap<u32, Vec<u8>> = HashMap::new();
        overlay.insert(2, fake_page.clone());

        let result = get_overlay_page(&db, 2, page_size as usize, &overlay);
        assert!(result.is_some(), "Page 2 should be returned from overlay");
        let (data, bhdr) = result.unwrap();
        assert_eq!(bhdr, 0, "Non-page-1 bhdr must be 0");
        assert_eq!(data[0], 0xBB, "Overlay data should take precedence");
        assert_eq!(data.len(), page_size as usize);
    }

    // ---------------------------------------------------------------------------
    // follow_overflow_chain — tested indirectly via parse_table_leaf_page
    // (the function is private; direct access from this module is possible because
    //  this mod is inline in btree.rs, so we call super::follow_overflow_chain)
    // ---------------------------------------------------------------------------

    /// first_overflow_page == 0 → empty result (loop doesn't execute).
    #[test]
    fn test_follow_overflow_chain_no_overflow() {
        let db = vec![0u8; 4096];
        let result = follow_overflow_chain(&db, 0, 4096, 100);
        assert!(result.is_empty(), "first_page=0 must yield empty vec");
    }

    /// Overflow page number beyond DB EOF → graceful empty result, no panic.
    #[test]
    fn test_follow_overflow_chain_beyond_db() {
        let db = vec![0u8; 4096]; // only 1 page
        // Ask for page 9999 which is well past EOF
        let result = follow_overflow_chain(&db, 9999, 4096, 100);
        assert!(result.is_empty(), "Out-of-bounds overflow page must yield empty vec");
    }
}

#[cfg(test)]
mod overflow_tests {
    fn make_db_with_overflow() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;")
            .unwrap();
        conn.execute_batch("CREATE TABLE docs (body TEXT);").unwrap();
        let big_text = "X".repeat(8000); // exceeds table leaf X threshold (4061) for 4096 page
        conn.execute("INSERT INTO docs VALUES (?)", rusqlite::params![big_text])
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_overflow_record_reassembly() {
        let db = make_db_with_overflow();
        let engine = crate::db::ForensicEngine::new(&db, None).unwrap();
        let records = engine.recover_layer1().unwrap();
        let docs: Vec<_> = records.iter().filter(|r| r.table == "docs").collect();
        assert_eq!(docs.len(), 1, "should have one docs record");
        if let crate::record::SqlValue::Text(s) = &docs[0].values[0] {
            assert_eq!(
                s.len(),
                8000,
                "overflow text should be fully reassembled, got {} bytes",
                s.len()
            );
            assert!(s.chars().all(|c| c == 'X'), "text should be all X's");
        } else {
            panic!("expected Text value, got {:?}", docs[0].values[0]);
        }
    }

    #[test]
    fn test_non_overflow_records_still_work() {
        // Ensure normal records (no overflow) still parse correctly.
        // Table has id INTEGER PRIMARY KEY (stored as rowid, NULL sentinel in payload)
        // and text TEXT as values[1].
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, text TEXT);
             INSERT INTO msgs VALUES (1, 'short text');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();
        let engine = crate::db::ForensicEngine::new(&db, None).unwrap();
        let records = engine.recover_layer1().unwrap();
        let msgs: Vec<_> = records.iter().filter(|r| r.table == "msgs").collect();
        assert_eq!(msgs.len(), 1);
        // id INTEGER PRIMARY KEY is stored as NULL in the payload (rowid alias);
        // the text column is at values[1].
        assert_eq!(
            msgs[0].values[1],
            crate::record::SqlValue::Text("short text".into())
        );
    }
}
