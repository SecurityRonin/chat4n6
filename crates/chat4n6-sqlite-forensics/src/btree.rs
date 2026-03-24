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

    // ---------------------------------------------------------------------------
    // get_page_data edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_get_page_data_page_zero() {
        let db = vec![0u8; 4096];
        assert!(get_page_data(&db, 0, 4096).is_none(), "page 0 is invalid");
    }

    #[test]
    fn test_get_page_data_out_of_bounds() {
        let db = vec![0u8; 4096]; // 1 page
        assert!(get_page_data(&db, 2, 4096).is_none(), "page 2 beyond EOF");
    }

    #[test]
    fn test_get_page_data_page1_bhdr_100() {
        let db = vec![0u8; 4096];
        let (data, bhdr) = get_page_data(&db, 1, 4096).unwrap();
        assert_eq!(bhdr, 100);
        assert_eq!(data.len(), 4096);
    }

    #[test]
    fn test_get_page_data_page2_bhdr_0() {
        let db = vec![0u8; 8192]; // 2 pages
        let (data, bhdr) = get_page_data(&db, 2, 4096).unwrap();
        assert_eq!(bhdr, 0);
        assert_eq!(data.len(), 4096);
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: cycle guard (line 44)
    // ---------------------------------------------------------------------------

    /// Construct a synthetic DB where an interior page's child pointer points
    /// back to the root, forming a cycle. walk_table_btree must not infinite-loop.
    #[test]
    fn test_walk_table_btree_cycle_guard() {
        let page_size = 4096usize;
        // Build a 2-page DB. Page 1 is file header + unrelated. Page 2 is an
        // interior page whose right-child pointer points back to page 2 (cycle).
        let mut db = vec![0u8; page_size * 2];
        // Minimal file header so page_size is 4096
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());

        // Page 2 starts at byte 4096. bhdr=0.
        let p2 = page_size; // offset of page 2
        db[p2] = 0x05; // TableInterior
        // first freeblock = 0
        db[p2 + 1] = 0;
        db[p2 + 2] = 0;
        // cell count = 0
        db[p2 + 3] = 0;
        db[p2 + 4] = 0;
        // cell content area
        db[p2 + 5] = 0x0F;
        db[p2 + 6] = 0xFF;
        // fragmented bytes
        db[p2 + 7] = 0;
        // right-most child = page 2 (CYCLE!)
        db[p2 + 8..p2 + 12].copy_from_slice(&2u32.to_be_bytes());

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        // Should terminate without panic — cycle guard prevents infinite loop.
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: page_data.len() <= bhdr (line 50)
    // ---------------------------------------------------------------------------

    /// A page whose data length is <= bhdr offset should be skipped.
    #[test]
    fn test_walk_table_btree_page_too_small_for_bhdr() {
        // Page 1 has bhdr=100. If page_size is tiny (say 64, which is < 100),
        // then page_data.len() <= bhdr and we hit line 50.
        let page_size = 64usize;
        let mut db = vec![0u8; page_size];
        db[..16].copy_from_slice(b"SQLite format 3\x00");

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 1, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty(), "Too-small page should produce no records");
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: interior page with children (lines 61-105)
    // ---------------------------------------------------------------------------

    /// Synthetic interior page with one cell pointing to a leaf page.
    #[test]
    fn test_walk_table_btree_interior_with_leaf_child() {
        let page_size = 512usize;
        // 3 pages: page 1 (file header junk), page 2 (interior), page 3 (leaf with 1 record)
        let mut db = vec![0u8; page_size * 3];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        // --- Page 2 (interior, root) at offset page_size ---
        let p2 = page_size;
        db[p2] = 0x05; // TableInterior
        // cell count = 1
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        // cell content area (doesn't matter much, use 100)
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        // right-most child = 0 (no right child, covers right==0 branch)
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes());
        // Cell pointer array at p2+12: one cell pointer
        let cell_off: u16 = 100; // cell at offset 100 within the page
        db[p2 + 12] = (cell_off >> 8) as u8;
        db[p2 + 13] = (cell_off & 0xFF) as u8;
        // Cell at page2[100]: 4-byte left child page number = 3, then a varint key
        let cell_abs = p2 + cell_off as usize;
        db[cell_abs..cell_abs + 4].copy_from_slice(&3u32.to_be_bytes());
        // rowid varint after child pointer (just 1 for key)
        db[cell_abs + 4] = 0x01;

        // --- Page 3 (leaf) at offset page_size*2 ---
        let p3 = page_size * 2;
        db[p3] = 0x0D; // TableLeaf
        // cell count = 1
        db[p3 + 3] = 0;
        db[p3 + 4] = 1;
        // cell content area
        let content_off: u16 = 50;
        db[p3 + 5] = (content_off >> 8) as u8;
        db[p3 + 6] = (content_off & 0xFF) as u8;
        // Cell pointer array at p3+8: one cell pointer at offset 50
        db[p3 + 8] = (content_off >> 8) as u8;
        db[p3 + 9] = (content_off & 0xFF) as u8;
        // Cell at page3[50]:
        //   payload_len varint = 3 (0x03)
        //   row_id varint = 1 (0x01)
        //   record: header_len=2 (0x02), serial_type=1 (1-byte int)
        //   value: 0x2A (42)
        let c3 = p3 + content_off as usize;
        db[c3] = 0x03; // payload_len
        db[c3 + 1] = 0x01; // row_id
        db[c3 + 2] = 0x02; // header_len
        db[c3 + 3] = 0x01; // serial_type 1
        db[c3 + 4] = 0x2A; // value = 42

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert_eq!(records.len(), 1, "Should find 1 record in leaf child");
        assert_eq!(records[0].values[0], crate::record::SqlValue::Int(42));
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: interior page cell_off + 4 > page_data.len() (line 93-94)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_walk_table_btree_interior_cell_off_out_of_bounds() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        let p2 = page_size;
        db[p2] = 0x05; // TableInterior
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // cell count = 1
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes()); // right=0
        // Cell pointer at p2+12 points to offset 510, which means cell_off+4=514 > 512
        db[p2 + 12] = 0x01;
        db[p2 + 13] = 0xFE; // cell_off = 510

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty(), "OOB cell pointer should be skipped");
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: interior page ptr_off + 2 > page_data.len() (line 88-89)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_walk_table_btree_interior_ptr_off_out_of_bounds() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        let p2 = page_size;
        db[p2] = 0x05; // TableInterior
        // Set absurdly high cell count so ptr_off exceeds page boundary
        db[p2 + 3] = 0x0F;
        db[p2 + 4] = 0xFF; // cell count = 4095
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes()); // right=0

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: cell_count=0 fallback for short interior page (line 72)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_walk_table_btree_interior_page_too_short_for_cell_count() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        let p2 = page_size;
        db[p2] = 0x05; // TableInterior
        // Truncate effective page by setting all to 0; page_data.len() >= bhdr + 5 is true
        // but we want bhdr + 5 > len. Since bhdr=0 and len=512, that won't work for a normal page.
        // Instead, test cell_count=0: set cell count bytes to 0.
        db[p2 + 3] = 0;
        db[p2 + 4] = 0; // cell count = 0
        // right-most child = 0
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes());

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: unknown page type (line 107: _ => {})
    // ---------------------------------------------------------------------------

    #[test]
    fn test_walk_table_btree_unknown_page_type() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        let p2 = page_size;
        db[p2] = 0xFF; // Unknown page type

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree_with_overlay tests (lines 131-202)
    // ---------------------------------------------------------------------------

    /// Basic overlay walk: leaf page in overlay produces records.
    #[test]
    fn test_walk_with_overlay_leaf_from_overlay() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        // Create a leaf page in the overlay for page 2
        let mut leaf_page = vec![0u8; page_size];
        leaf_page[0] = 0x0D; // TableLeaf
        // cell count = 1
        leaf_page[3] = 0;
        leaf_page[4] = 1;
        // cell content area
        let content_off: u16 = 50;
        leaf_page[5] = (content_off >> 8) as u8;
        leaf_page[6] = (content_off & 0xFF) as u8;
        // Cell pointer at offset 8
        leaf_page[8] = (content_off >> 8) as u8;
        leaf_page[9] = (content_off & 0xFF) as u8;
        // Cell at offset 50: payload_len=3, rowid=1, record: hlen=2, st=1, val=0x07
        let c = content_off as usize;
        leaf_page[c] = 0x03;
        leaf_page[c + 1] = 0x01;
        leaf_page[c + 2] = 0x02;
        leaf_page[c + 3] = 0x01;
        leaf_page[c + 4] = 0x07;

        let mut overlay = HashMap::new();
        overlay.insert(2u32, leaf_page);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, page_size as u32, 2, "test", &overlay, &mut records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].values[0], crate::record::SqlValue::Int(7));
        assert_eq!(records[0].source, EvidenceSource::Live);
    }

    /// Overlay walk: cycle guard triggers (revisiting the same page).
    #[test]
    fn test_walk_with_overlay_cycle_guard() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        // Interior page in overlay whose right-child points back to itself
        let mut interior = vec![0u8; page_size];
        interior[0] = 0x05; // TableInterior
        interior[3] = 0;
        interior[4] = 0; // cell count = 0
        // right-most child = 2 (self)
        interior[8..12].copy_from_slice(&2u32.to_be_bytes());

        let mut overlay = HashMap::new();
        overlay.insert(2u32, interior);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, page_size as u32, 2, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: page not found in overlay or DB → skipped.
    #[test]
    fn test_walk_with_overlay_page_not_found() {
        let db = vec![0u8; 512];
        let overlay: HashMap<u32, Vec<u8>> = HashMap::new();

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, 512, 999, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: page_data.len() <= bhdr → skipped.
    #[test]
    fn test_walk_with_overlay_page_too_small() {
        let db = vec![0u8; 512];
        // Overlay page 1 with tiny data (bhdr=100, len must be > 100)
        let tiny_page = vec![0u8; 50]; // len=50 < bhdr=100
        let mut overlay = HashMap::new();
        overlay.insert(1u32, tiny_page);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, 512, 1, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: interior page with children — exercises full interior handling.
    #[test]
    fn test_walk_with_overlay_interior_with_children() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 4];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());

        // Page 2 (interior) in overlay: 1 cell pointing left to page 3, right to page 4
        let mut interior = vec![0u8; page_size];
        interior[0] = 0x05;
        interior[3] = 0;
        interior[4] = 1; // cell count = 1
        interior[5] = 0;
        interior[6] = 100;
        // right child = 4
        interior[8..12].copy_from_slice(&4u32.to_be_bytes());
        // Cell pointer at offset 12 → cell at offset 100
        interior[12] = 0;
        interior[13] = 100;
        // Cell: left child = 3
        interior[100..104].copy_from_slice(&3u32.to_be_bytes());
        interior[104] = 0x01; // key varint

        // Page 3 (leaf) in DB
        let p3 = page_size * 2;
        db[p3] = 0x0D;
        db[p3 + 3] = 0;
        db[p3 + 4] = 1;
        let co: u16 = 50;
        db[p3 + 5] = (co >> 8) as u8;
        db[p3 + 6] = (co & 0xFF) as u8;
        db[p3 + 8] = (co >> 8) as u8;
        db[p3 + 9] = (co & 0xFF) as u8;
        let c3 = p3 + co as usize;
        db[c3] = 0x03;
        db[c3 + 1] = 0x01;
        db[c3 + 2] = 0x02;
        db[c3 + 3] = 0x01;
        db[c3 + 4] = 0x0A; // value = 10

        // Page 4 (leaf) in DB
        let p4 = page_size * 3;
        db[p4] = 0x0D;
        db[p4 + 3] = 0;
        db[p4 + 4] = 1;
        db[p4 + 5] = (co >> 8) as u8;
        db[p4 + 6] = (co & 0xFF) as u8;
        db[p4 + 8] = (co >> 8) as u8;
        db[p4 + 9] = (co & 0xFF) as u8;
        let c4 = p4 + co as usize;
        db[c4] = 0x03;
        db[c4 + 1] = 0x02;
        db[c4 + 2] = 0x02;
        db[c4 + 3] = 0x01;
        db[c4 + 4] = 0x14; // value = 20

        let mut overlay = HashMap::new();
        overlay.insert(2u32, interior);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, page_size as u32, 2, "test", &overlay, &mut records);
        assert_eq!(records.len(), 2);
    }

    /// Overlay walk: unknown page type → skipped (_ => {}).
    #[test]
    fn test_walk_with_overlay_unknown_page_type() {
        let db = vec![0u8; 1024];
        let mut page = vec![0u8; 512];
        page[0] = 0x0A; // IndexLeaf — not TableLeaf or TableInterior, hits _ branch
        let mut overlay = HashMap::new();
        overlay.insert(2u32, page);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, 512, 2, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: interior page cell_off + 4 > page_data.len() → skipped.
    #[test]
    fn test_walk_with_overlay_interior_cell_oob() {
        let page_size = 512usize;
        let db = vec![0u8; page_size * 2];

        let mut interior = vec![0u8; page_size];
        interior[0] = 0x05;
        interior[3] = 0;
        interior[4] = 1; // cell count = 1
        interior[5] = 0;
        interior[6] = 100;
        interior[8..12].copy_from_slice(&0u32.to_be_bytes()); // right=0
        // Cell pointer → cell at offset 510 (510+4=514 > 512)
        interior[12] = 0x01;
        interior[13] = 0xFE;

        let mut overlay = HashMap::new();
        overlay.insert(2u32, interior);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, page_size as u32, 2, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: interior page ptr_off + 2 > page_data.len() → break.
    #[test]
    fn test_walk_with_overlay_interior_ptr_off_oob() {
        let page_size = 512usize;
        let db = vec![0u8; page_size * 2];

        let mut interior = vec![0u8; page_size];
        interior[0] = 0x05;
        // Absurdly high cell count
        interior[3] = 0x0F;
        interior[4] = 0xFF;
        interior[5] = 0;
        interior[6] = 100;
        interior[8..12].copy_from_slice(&0u32.to_be_bytes());

        let mut overlay = HashMap::new();
        overlay.insert(2u32, interior);

        let mut records = Vec::new();
        walk_table_btree_with_overlay(&db, page_size as u32, 2, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    /// Overlay walk: interior page too short for cell count field → cell_count=0.
    #[test]
    fn test_walk_with_overlay_interior_short_page() {
        let db = vec![0u8; 1024];
        // Page 2 with only 4 bytes in overlay (bhdr=0, bhdr+5=5 > 4)
        let mut short = vec![0u8; 4];
        short[0] = 0x05; // TableInterior
        let mut overlay = HashMap::new();
        overlay.insert(2u32, short);

        let mut records = Vec::new();
        // This tests page_data.len() >= bhdr + 5 being false → cell_count = 0
        // AND page_data.len() >= bhdr + 12 being false → no right child
        walk_table_btree_with_overlay(&db, 4, 2, "test", &overlay, &mut records);
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // follow_overflow_chain: cycle guard (line 223)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_follow_overflow_chain_cycle() {
        let page_size = 512usize;
        // 2-page DB: page 1 is an overflow page that points to itself
        let mut db = vec![0u8; page_size * 2];
        // Page 1: next_page pointer = 1 (self-referential cycle)
        db[0..4].copy_from_slice(&1u32.to_be_bytes());
        // Put some data after the 4-byte header
        for i in 4..page_size {
            db[i] = 0xAA;
        }

        let result = follow_overflow_chain(&db, 1, page_size, page_size * 4);
        // Should collect data from page 1 once, then detect cycle and stop
        assert_eq!(result.len(), page_size - 4, "Should collect one page's worth");
    }

    // ---------------------------------------------------------------------------
    // follow_overflow_chain: multi-page chain
    // ---------------------------------------------------------------------------

    #[test]
    fn test_follow_overflow_chain_multi_page() {
        let page_size = 512usize;
        // 3 pages: page 1 → page 2 → page 3 (end)
        let mut db = vec![0u8; page_size * 3];

        // Page 1: next=2, data = 0xAA * (page_size - 4)
        db[0..4].copy_from_slice(&2u32.to_be_bytes());
        for i in 4..page_size {
            db[i] = 0xAA;
        }

        // Page 2: next=3, data = 0xBB * (page_size - 4)
        let p2 = page_size;
        db[p2..p2 + 4].copy_from_slice(&3u32.to_be_bytes());
        for i in (p2 + 4)..(p2 + page_size) {
            db[i] = 0xBB;
        }

        // Page 3: next=0 (end), data = 0xCC * (page_size - 4)
        let p3 = page_size * 2;
        db[p3..p3 + 4].copy_from_slice(&0u32.to_be_bytes());
        for i in (p3 + 4)..(p3 + page_size) {
            db[i] = 0xCC;
        }

        // Request more data than all 3 pages can provide
        let result = follow_overflow_chain(&db, 1, page_size, page_size * 10);
        let usable = page_size - 4;
        assert_eq!(result.len(), usable * 3);
        assert!(result[..usable].iter().all(|&b| b == 0xAA));
        assert!(result[usable..usable * 2].iter().all(|&b| b == 0xBB));
        assert!(result[usable * 2..].iter().all(|&b| b == 0xCC));
    }

    // ---------------------------------------------------------------------------
    // follow_overflow_chain: overflow data get fails (line 242)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_follow_overflow_chain_short_page() {
        // A page that is smaller than 4 bytes → page_data.len() < 4 → break (line 231)
        let db = vec![0u8; 3]; // Entire DB is only 3 bytes
        let result = follow_overflow_chain(&db, 1, 3, 100);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // parse_table_leaf_page edge cases
    // ---------------------------------------------------------------------------

    /// Page too small for header (line 275).
    #[test]
    fn test_parse_leaf_page_too_small() {
        let db = vec![0u8; 100];
        let page_data = &db[..6]; // < bhdr + 8 = 108 for page 1 (bhdr=100, impossible)
        // Use bhdr=0 with short data
        let records = parse_table_leaf_page(&db, &db[..6], 0, 1, 4096, "t");
        assert!(records.is_empty());
    }

    /// Cell offset == 0 → skip (line 301-302).
    #[test]
    fn test_parse_leaf_cell_offset_zero() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D; // TableLeaf
        page[3] = 0;
        page[4] = 1; // cell count = 1
        page[5] = 0;
        page[6] = 50;
        // Cell pointer at offset 8 points to 0 (invalid)
        page[8] = 0;
        page[9] = 0;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty());
    }

    /// Cell offset >= page_data.len() → skip (line 301).
    #[test]
    fn test_parse_leaf_cell_offset_past_end() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1; // cell count = 1
        page[5] = 0;
        page[6] = 50;
        // Cell pointer points to 600 which is >= 512
        page[8] = 0x02;
        page[9] = 0x58; // 600

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty());
    }

    /// Truncated payload_len varint → skip (line 309).
    #[test]
    fn test_parse_leaf_truncated_payload_varint() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0x01;
        page[6] = 0xFF; // cell content area = 511
        // Cell pointer → offset 511 (last byte)
        page[8] = 0x01;
        page[9] = 0xFF;
        // Byte at 511 is a continuation byte with no following byte
        page[511] = 0x81;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty());
    }

    /// Truncated row_id varint → skip (line 315).
    #[test]
    fn test_parse_leaf_truncated_rowid_varint() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0x01;
        page[6] = 0xFE; // cell content area = 510
        // Cell pointer → offset 510
        page[8] = 0x01;
        page[9] = 0xFE;
        // payload_len varint at 510 = 0x05 (1-byte, valid)
        page[510] = 0x05;
        // row_id varint at 511 = 0x81 (continuation, needs another byte, but EOF)
        page[511] = 0x81;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty());
    }

    /// Header extends beyond payload → skip (line 388).
    /// When the payload is parsed inline (no overflow), payload_slice is page_data
    /// and record_start = pos. header_end = pos + header_len. If header_end > page_data.len(),
    /// the record is skipped.
    #[test]
    fn test_parse_leaf_header_beyond_payload() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        // Put cell near end of page so header_end exceeds page length
        let cell_off: u16 = 505;
        page[5] = (cell_off >> 8) as u8;
        page[6] = (cell_off & 0xFF) as u8;
        page[8] = (cell_off >> 8) as u8;
        page[9] = (cell_off & 0xFF) as u8;
        // Cell at 505: payload_len=100, rowid=1
        // payload_len < max_local(477) so no overflow path taken
        // Wait, 100 < 477, so it's inline.
        // Record starts at 507. header_len = large.
        page[505] = 0x64; // payload_len = 100
        page[506] = 0x01; // rowid = 1
        // Record at 507: header_len = 0x81, 0x00 = 128 as varint
        // header_end = 507 + 128 = 635 > 512 → skip
        page[507] = 0x81;
        page[508] = 0x00; // header_len = 128
        // payload_start = 507, header_end = 507 + 128 = 635 > 512 → continue

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty(), "Header extending beyond page should skip the record");
    }

    /// Truncated record header varint → skip (line 382).
    #[test]
    fn test_parse_leaf_truncated_header_varint() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0x01;
        page[6] = 0xFC; // cell content = 508
        page[8] = 0x01;
        page[9] = 0xFC;
        // Cell at 508: payload_len=10 (non-overflow), rowid=1,
        // then record starts at 510 but the header_len varint is a continuation at EOF
        page[508] = 0x0A; // payload_len = 10
        page[509] = 0x01; // rowid = 1
        // payload starts at 510. We need header_len varint to fail.
        // Fill 510-511 with continuation bytes (truncated varint)
        page[510] = 0x81;
        page[511] = 0x81;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert!(records.is_empty());
    }

    /// Serial type varint fails → break (line 396).
    #[test]
    fn test_parse_leaf_serial_type_varint_break() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0;
        page[6] = 50;
        page[8] = 0;
        page[9] = 50;
        // Cell: payload_len=200, rowid=1
        // Record: header_len=20 (large header), then serial types should follow
        // but we put continuation bytes that don't terminate
        let c = 50;
        page[c] = 0x81; // payload_len varint, high byte
        page[c + 1] = 0x48; // payload_len = 200
        page[c + 2] = 0x01; // rowid = 1
        // Record starts at c+3:
        page[c + 3] = 20; // header_len = 20 (means serial types from c+4 to c+22)
        // Put a serial type varint that extends beyond the data
        page[c + 4] = 0x01; // valid serial type
        // Then fill with continuation bytes that hit EOF before terminating
        for i in (c + 5)..(c + 20) {
            page[i] = 0xFF; // continuation bytes
        }

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        // Should produce a record with whatever values parsed (partial parse)
        // The break at line 396 stops parsing serial types, then decode proceeds.
        // This is a partial parse — we just verify it doesn't panic.
        // May produce a record with the single valid serial type.
    }

    /// decode_serial_type returns None → pushes SqlValue::Null (line 411).
    #[test]
    fn test_parse_leaf_decode_serial_type_returns_null() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0;
        page[6] = 50;
        page[8] = 0;
        page[9] = 50;
        // Cell at offset 50: we need the record payload to have a serial type
        // that requires more bytes than available in the payload.
        //
        // payload_len = 3. rowid = 1.
        // Record payload at c+2: header_len=2, serial_type=6 (needs 8 bytes for value)
        // But payload is only 3 bytes total (hlen byte + serial_type byte + 1 data byte)
        // So header is fine but value decode for type 6 needs 8 bytes, only 1 available.
        let c = 50;
        page[c] = 0x03; // payload_len = 3
        page[c + 1] = 0x01; // rowid = 1
        // Record at c+2 (3 bytes: c+2, c+3, c+4):
        page[c + 2] = 0x02; // header_len = 2
        page[c + 3] = 0x06; // serial_type = 6 (needs 8 bytes)
        // Value area starts at c+4 but only 1 byte in payload (c+4 is the last payload byte)
        page[c + 4] = 0x42;
        // header_end = (c+2) + 2 = c+4. data_pos = c+4.
        // decode_serial_type(6, page, c+4) needs 8 bytes from c+4..c+12.
        // The page has 512 bytes so page_data[c+4..c+12] exists (it's zeros).
        // It will NOT return None — it will just read zeros from the page.
        //
        // To truly trigger decode returning None, we need the value to be at
        // the very end of page_data. Let's put the cell near the end.
        // Use an owned_payload (overflow) scenario where the assembled payload
        // is short. Actually, let's just make the record at the end of the page.

        // Reset and rebuild at end of page
        page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        // cell content at offset 507
        page[5] = 0x01;
        page[6] = 0xFB; // 507
        page[8] = 0x01;
        page[9] = 0xFB;
        // Cell at 507: payload_len=3, rowid=1
        page[507] = 0x03; // payload_len = 3
        page[508] = 0x01; // rowid = 1
        // Record at 509: header_len=2, serial_type=6 (needs 8 bytes)
        page[509] = 0x02; // header_len = 2
        page[510] = 0x06; // serial_type = 6
        // Value area starts at 511. But payload_len=3 means payload is 509..512,
        // and 509+2=511 is header_end. data_pos=511. Needs 8 bytes from 511.
        // page_data is 512 bytes, so page_data[511..519] is out of range.
        // Since owned_payload is None, payload_slice is page_data.
        // decode_serial_type(6, page_data, 511) needs data[511..519] — fails.
        page[511] = 0x42;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].values[0], crate::record::SqlValue::Null);
    }

    // ---------------------------------------------------------------------------
    // Overflow: local_size > max_local → local_size = min_local (line 330)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_leaf_overflow_local_size_clamp() {
        // We need payload_len > max_local, and also
        // min_local + (payload_len - min_local) % (usable - 4) > max_local
        // so that local_size gets clamped to min_local.
        //
        // For page_size=512: usable=512, max_local=477, min_local=23
        // We need: 23 + (P - 23) % 508 > 477 → (P - 23) % 508 > 454
        // So (P - 23) % 508 needs to be in [455..507]
        // Try P = 23 + 455 = 478: (478-23)%508 = 455 → 23+455 = 478 > 477 ✓
        // But P must be > max_local=477, and P=478 > 477 ✓
        let page_size = 512usize;
        let payload_len = 478usize;
        let usable = page_size;
        let max_local = usable - 35;  // 477
        let min_local = (usable - 12) * 32 / 255 - 23; // 23 (approx)

        // Verify our math
        let mut local_size = min_local + (payload_len - min_local) % (usable - 4);
        assert!(local_size > max_local, "Need local_size > max_local to trigger clamp");
        local_size = min_local; // this is what the code will do

        // Build the page with this payload
        let mut page = vec![0u8; page_size];
        let mut db = vec![0u8; page_size * 3]; // extra pages for overflow
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0;
        page[6] = 50;
        page[8] = 0;
        page[9] = 50;

        // Cell at offset 50
        let c = 50;
        // payload_len = 478 as varint: 0x83, 0x5E
        page[c] = 0x83;
        page[c + 1] = 0x5E; // = 478
        page[c + 2] = 0x01; // rowid = 1
        // Record starts at c+3. Write header_len=2, serial_type=0 (NULL)
        page[c + 3] = 0x02; // header_len = 2
        page[c + 4] = 0x00; // serial_type = 0 (NULL, 0 bytes)
        // local payload goes from c+3 for local_size bytes.
        // Overflow pointer is at c+3 + local_size
        let overflow_ptr_pos = c + 3 + local_size;
        if overflow_ptr_pos + 4 <= page_size {
            // Point to page 2 for overflow
            page[overflow_ptr_pos] = 0;
            page[overflow_ptr_pos + 1] = 0;
            page[overflow_ptr_pos + 2] = 0;
            page[overflow_ptr_pos + 3] = 2;
        }

        // Copy page into db at page 2 position (offset page_size)
        db[page_size..page_size * 2].copy_from_slice(&page);
        // Page 2 (overflow): next=0, data=zeros
        db[page_size * 2..page_size * 2 + 4].copy_from_slice(&0u32.to_be_bytes());

        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        // Should produce a record (possibly with NULL value from the overflow parse)
        assert_eq!(records.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // Overflow: can't read overflow pointer (line 363-365)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_leaf_overflow_ptr_unreadable() {
        // payload_len > max_local but the overflow pointer position exceeds page_data.len()
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        page[5] = 0x01;
        page[6] = 0xF0; // cell content at 496
        page[8] = 0x01;
        page[9] = 0xF0; // cell pointer at 496

        // Cell at 496: payload_len needs to be > max_local = 477
        // But the cell starts close to page end so overflow ptr can't fit.
        // payload_len = 500 as 2-byte varint: 0x83, 0x74
        page[496] = 0x83;
        page[497] = 0x74; // = 500
        page[498] = 0x01; // rowid = 1
        // Record at 499: header_len=2, serial_type=0 (NULL)
        page[499] = 0x02;
        page[500] = 0x00;
        // local_size computation for page_size=512, payload=500:
        // min_local = (512-12)*32/255 - 23 = 500*32/255 - 23 ≈ 62.7 - 23 = 39 (int div)
        // Actually: (500)*32 = 16000, 16000/255 = 62, 62 - 23 = 39
        // local_size = 39 + (500 - 39) % (512-4) = 39 + 461 % 508 = 39 + 461 = 500
        // 500 > max_local(477) → local_size = min_local = 39
        // overflow_ptr at 499 + 39 = 538 > 512 → can't read overflow pointer!

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        // Should produce a record with inline-only parsing
        assert_eq!(records.len(), 1);
    }

    /// Cell pointer array extends past page boundary (line 295-296).
    #[test]
    fn test_parse_leaf_ptr_off_exceeds_page() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        // Set cell count to a large value so cell pointer array exceeds page
        page[3] = 0x00;
        page[4] = 0xFF; // cell count = 255 → ptr_array needs 255*2 = 510 bytes from offset 8
        // ptr_array_start = 8, last ptr_off = 8 + 254*2 = 516 which > 512
        page[5] = 0;
        page[6] = 120;

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        // Should break out of cell pointer loop without panic
        // Some early pointers (all zeros) will be skipped (cell_offset == 0)
    }

    // ---------------------------------------------------------------------------
    // walk_table_btree: interior page too short for cell_count field (line 72)
    // and too short for right-child pointer (line 84 closing brace)
    // ---------------------------------------------------------------------------

    /// Interior page with only 3 bytes of content (bhdr=0, len=3).
    /// page_data.len() < bhdr + 5, so cell_count defaults to 0.
    /// page_data.len() < bhdr + 12, so no right-child read either.
    #[test]
    fn test_walk_table_btree_interior_very_short() {
        // We can't use get_page_data since it requires full page_size bytes.
        // But walk_table_btree calls get_page_data which slices db into page_size chunks.
        // So if page_size=4 and page starts with 0x05, we get len=4, bhdr=0.
        // len(4) >= bhdr(0) + 5 = 5? No, 4 < 5 → cell_count = 0 (line 72!)
        // len(4) >= bhdr(0) + 12? No → skip right child read (line 84 branch not entered)
        let page_size = 4usize;
        let mut db = vec![0u8; page_size * 2]; // 2 pages of 4 bytes each
        // Page 2 at offset 4: interior page type
        db[4] = 0x05;

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    /// Interior page with 8 bytes (bhdr=0). len(8) >= bhdr+5 → reads cell_count.
    /// len(8) < bhdr+12 → does NOT read right-child (line 84 brace is the end of the
    /// `if` block that is NOT entered).
    #[test]
    fn test_walk_table_btree_interior_short_no_right_child() {
        let page_size = 8usize;
        let mut db = vec![0u8; page_size * 2];
        // Page 2 at offset 8:
        db[8] = 0x05; // interior
        db[11] = 0;
        db[12] = 0; // cell_count = 0

        let mut records = Vec::new();
        walk_table_btree(&db, page_size as u32, 2, "test", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    // ---------------------------------------------------------------------------
    // parse_table_leaf_page: serial type varint fails mid-header (line 396)
    // ---------------------------------------------------------------------------

    /// Craft a cell where a serial-type varint in the record header is truncated
    /// at the page boundary, causing read_varint to return None and triggering
    /// the `None => break` at line 396.
    #[test]
    fn test_parse_leaf_serial_type_varint_truncated() {
        let page_size = 512usize;
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 1;
        // Cell near end of page.
        // We need: header_end within page bounds (passes line 387 check),
        // but a serial-type varint that extends past the page boundary.
        //
        // Cell at offset 490: payload_len, rowid, then record.
        // payload_len = 100 (well under max_local=477, so inline).
        // rowid = 1.
        // Record starts at 492. header_len = 30 → header_end = 492 + 30 = 522 > 512.
        // That would fail the header_end check. So header_end must be <= 512.
        // header_len = 20 → header_end = 492 + 20 = 512 = page_data.len(). That's <=.
        // Serial types from 493 to 512. Put a valid one at 493, then continuation
        // bytes from 494 to 511. read_varint at 494 reads 0xFF * 8 bytes (494..502),
        // then byte 502 (still 0xFF), etc. After 9 bytes (494..503) it would complete
        // the varint (9th byte uses all 8 bits). So that won't return None.
        //
        // Better approach: make header_end = 512 (last byte of page).
        // Put a continuation byte at 511 (the very last byte). read_varint at 511
        // reads 0x81, needs next byte at 512 → past page end → returns None.
        let cell_off: u16 = 480;
        page[5] = (cell_off >> 8) as u8;
        page[6] = (cell_off & 0xFF) as u8;
        page[8] = (cell_off >> 8) as u8;
        page[9] = (cell_off & 0xFF) as u8;

        let c = cell_off as usize;
        page[c] = 100;     // payload_len = 100 (inline, no overflow)
        page[c + 1] = 1;   // rowid = 1
        // Record at c+2=482. We need header_end = 512 → header_len = 512 - 482 = 30.
        page[c + 2] = 30;  // header_len = 30 → header_end = 482 + 30 = 512
        // 512 > payload_slice.len()=512? No, 512 is not > 512. Check is >, not >=. ✓
        // First serial type at 483: valid
        page[c + 3] = 0x01; // serial type 1
        // Fill 484..511 with zeros (valid 1-byte serial types = NULL)
        // Then put a continuation byte at 511
        for i in (c + 4)..511 {
            page[i] = 0x00; // serial type 0 (NULL)
        }
        page[511] = 0x81; // continuation byte at last position
        // hdr_pos reaches 511 (still < 512 = header_end), reads varint at 511.
        // Byte 511 = 0x81 (continuation), tries to read byte 512 → out of bounds → None → break!

        let db = page.clone();
        let records = parse_table_leaf_page(&db, &page, 0, 2, page_size as u32, "t");
        // Record should be produced with partial serial types (those parsed before break).
        assert_eq!(records.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // get_overlay_page: page 1 from overlay (bhdr=100)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_get_overlay_page_page1_from_overlay() {
        let db = vec![0u8; 4096];
        let page1_overlay = vec![0xABu8; 4096];
        let mut overlay = HashMap::new();
        overlay.insert(1u32, page1_overlay);

        let result = get_overlay_page(&db, 1, 4096, &overlay);
        assert!(result.is_some());
        let (data, bhdr) = result.unwrap();
        assert_eq!(bhdr, 100, "Page 1 in overlay must have bhdr=100");
        assert_eq!(data[0], 0xAB);
    }

    // ---------------------------------------------------------------------------
    // get_overlay_page: page 0 → None
    // ---------------------------------------------------------------------------

    #[test]
    fn test_get_overlay_page_page_zero() {
        let db = vec![0u8; 4096];
        let overlay: HashMap<u32, Vec<u8>> = HashMap::new();
        let result = get_overlay_page(&db, 0, 4096, &overlay);
        assert!(result.is_none());
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
