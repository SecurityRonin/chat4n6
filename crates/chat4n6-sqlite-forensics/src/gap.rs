use crate::btree::get_page_data;
use crate::record::RecoveredRecord;
use crate::schema_sig::SchemaSignature;
use crate::varint::read_varint;
use chat4n6_plugin_api::EvidenceSource;

/// Scan intra-page gaps in all leaf pages of a table's B-tree.
/// The gap is the region between the cell pointer array end and cell_content_start.
pub fn scan_page_gaps(
    db: &[u8],
    page_size: u32,
    table_roots: &[(String, u32)],
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    let mut results = Vec::new();

    for (table_name, root_page) in table_roots {
        let sig = signatures.iter().find(|s| s.table_name == *table_name);

        // Walk B-tree to find all leaf pages
        let leaf_pages = collect_leaf_pages(db, page_size, *root_page);

        for page_num in leaf_pages {
            // CORRECT parameter order: (db, page_number, page_size)
            if let Some((page_data, bhdr_offset)) = get_page_data(db, page_num, page_size as usize) {
                let page_abs = (page_num as u64 - 1) * page_size as u64;
                results.extend(scan_single_page_gap(
                    page_data,
                    bhdr_offset,
                    table_name,
                    sig,
                    page_abs,
                ));
            }
        }
    }

    results
}

/// Scan the unallocated gap within a single page.
///
/// Scans two regions:
/// 1. The gap between the cell pointer array end and `cell_content_start`
///    (unallocated space that may retain stale data from previously deleted cells).
/// 2. The freeblock chain within the cell content area — when SQLite deletes a
///    cell it links the freed region into a freeblock list. The payload bytes
///    beyond the 4-byte freeblock header are often intact deleted record data.
fn scan_single_page_gap(
    page_data: &[u8],
    bhdr_offset: usize,
    table_name: &str,
    signature: Option<&SchemaSignature>,
    page_abs_offset: u64,
) -> Vec<RecoveredRecord> {
    // B-tree leaf page header is 8 bytes from bhdr_offset
    if page_data.len() < bhdr_offset + 8 {
        return Vec::new();
    }

    let first_freeblock = u16::from_be_bytes([
        page_data[bhdr_offset + 1],
        page_data[bhdr_offset + 2],
    ]) as usize;

    let cell_count = u16::from_be_bytes([
        page_data[bhdr_offset + 3],
        page_data[bhdr_offset + 4],
    ]) as usize;

    let cell_content_start = u16::from_be_bytes([
        page_data[bhdr_offset + 5],
        page_data[bhdr_offset + 6],
    ]) as usize;
    // 0 means 65536
    let cell_content_start = if cell_content_start == 0 { 65536 } else { cell_content_start };

    let ptr_array_start = bhdr_offset + 8;
    let ptr_array_end = ptr_array_start + cell_count * 2;

    let sig = match signature {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut results = Vec::new();

    // Region 1: gap between pointer array end and cell_content_start
    if ptr_array_end < cell_content_start && cell_content_start <= page_data.len() {
        let gap = &page_data[ptr_array_end..cell_content_start];
        if !gap.is_empty() && !gap.iter().all(|&b| b == 0) {
            for c in sig.scan_region(gap) {
                results.push(RecoveredRecord {
                    table: table_name.to_string(),
                    row_id: c.row_id,
                    values: c.values,
                    source: EvidenceSource::CarvedIntraPage {
                        confidence_pct: (c.confidence * 100.0) as u8,
                    },
                    offset: page_abs_offset + ptr_array_end as u64 + c.byte_offset as u64,
                    confidence: c.confidence,
                });
            }
        }
    }

    // Region 2: freeblock chain.
    // When SQLite deletes a leaf cell it links the freed region into the page's freeblock
    // list.  Each freeblock is: 2-byte next-pointer + 2-byte size, followed by the
    // original cell bytes (payload_len varint + rowid varint + record payload).
    // We strip the cell wrapper and pass the inner record payload to try_parse_record.
    let mut fb_offset = first_freeblock;
    let mut iterations = 0usize;
    while fb_offset != 0 && fb_offset + 4 <= page_data.len() && iterations < 1024 {
        iterations += 1;
        let next_fb = u16::from_be_bytes([
            page_data[fb_offset],
            page_data[fb_offset + 1],
        ]) as usize;
        let fb_size = u16::from_be_bytes([
            page_data[fb_offset + 2],
            page_data[fb_offset + 3],
        ]) as usize;

        // Sanity: freeblock size >= 4 and must fit within the page.
        if fb_size >= 4 && fb_offset + fb_size <= page_data.len() {
            let cell_bytes = &page_data[fb_offset + 4..fb_offset + fb_size];
            // Parse packed cells from the freeblock payload.
            // A leaf table cell begins with: payload_len(varint) rowid(varint) record…
            // Multiple cells can be packed back-to-back inside a single freeblock.
            results.extend(parse_cells_from_freeblock(
                cell_bytes,
                sig,
                table_name,
                page_abs_offset + (fb_offset + 4) as u64,
            ));
        }

        // Guard against cycles: next pointer must be strictly greater than current.
        if next_fb <= fb_offset {
            break;
        }
        fb_offset = next_fb;
    }

    results
}

/// Parse deleted leaf cells from freeblock payload bytes.
///
/// When SQLite frees a leaf cell, it overwrites the first 4 bytes of the freed region
/// with the freeblock list header (2-byte next-pointer + 2-byte size).  For a typical
/// leaf cell those 4 bytes are: payload_len(1) + rowid(1) + record_hlen(1) + first_serial_type(1).
/// The remaining bytes — starting from the second serial type — are intact.
///
/// Recovery strategy:
/// 1. First, try to interpret the freeblock data as a complete cell (payload_len + rowid +
///    record_payload).  This succeeds when the original cell was large enough that its
///    payload_len / rowid each occupied more than one byte, OR when it's not the first
///    cell in a coalesced freeblock.
/// 2. Fall back to "partial reconstruction": prepend a synthetic record header whose
///    serial-type count matches `sig.column_count`, then try every byte offset.
fn parse_cells_from_freeblock(
    data: &[u8],
    sig: &SchemaSignature,
    table_name: &str,
    base_abs_offset: u64,
) -> Vec<RecoveredRecord> {
    let mut results = Vec::new();

    // --- Strategy 1: full cell parse (payload_len + rowid + record) ---
    let mut pos = 0usize;
    while pos < data.len() {
        let (payload_len, pl_size) = match read_varint(data, pos) {
            Some(v) if v.0 > 0 && v.1 > 0 => v,
            _ => { pos += 1; continue; }
        };
        let payload_len = payload_len as usize;

        let rowid_pos = pos + pl_size;
        let (rowid_raw, rid_size) = match read_varint(data, rowid_pos) {
            Some(v) if v.1 > 0 => v,
            _ => { pos += 1; continue; }
        };

        let record_start = rowid_pos + rid_size;
        let record_end = record_start + payload_len;

        if record_end <= data.len() {
            let record_payload = &data[record_start..record_end];
            if let Some(mut c) = sig.try_parse_record(record_payload, 0) {
                c.row_id = Some(rowid_raw as i64);
                results.push(RecoveredRecord {
                    table: table_name.to_string(),
                    row_id: c.row_id,
                    values: c.values,
                    source: EvidenceSource::CarvedIntraPage {
                        confidence_pct: (c.confidence * 100.0) as u8,
                    },
                    offset: base_abs_offset + record_start as u64,
                    confidence: c.confidence,
                });
                pos = record_end;
                continue;
            }
        }
        pos += 1;
    }

    // --- Strategy 2: partial reconstruction ---
    //
    // Always run this even if Strategy 1 found something, since Strategy 1 can only
    // recover cells that fit fully within the freeblock.  Strategy 2 recovers partial
    // cells whose cell-header bytes (plen + rowid + hlen + first-serial-type) were
    // wiped by the freeblock list header.  We deduplicate by offset below.
    let strategy1_offsets: std::collections::HashSet<u64> =
        results.iter().map(|r| r.offset).collect();
    //
    // When a cell's first 4 bytes (plen + rowid + hlen + first-serial-type) are wiped
    // by the freeblock header, the surviving bytes start at the second serial type:
    //
    //   data[0] = serial_type for column 1 (TEXT/INT/…)
    //   data[1] = serial_type for column 2 …
    //   data[N-1] = serial_type for column N-1  (N = sig.column_count)
    //   data[N..] = column values
    //
    // We reconstruct a synthetic record by prepending the missing header_len byte.
    // header_len = 1 (for hlen itself) + (column_count - 1) serial-type bytes
    //            = column_count  (the first serial type is missing; hlen counts itself)
    //
    // Then we try that synthetic record at every byte offset within the freeblock data.

    // The SQLite record header length includes the hlen varint itself plus one byte
    // per serial type.  For `column_count` columns whose serial types each fit in one
    // byte: hlen = 1 (hlen byte) + column_count (serial-type bytes) = column_count + 1.
    let hlen_byte = (sig.column_count + 1) as u8;

    for start in 0..data.len() {
        if start + (sig.column_count - 1) > data.len() {
            break;
        }
        // Build synthetic record: [hlen_byte] + data[start..]
        let mut synthetic: Vec<u8> = Vec::with_capacity(1 + data.len() - start);
        synthetic.push(hlen_byte);
        synthetic.extend_from_slice(&data[start..]);

        if let Some(c) = sig.try_parse_record(&synthetic, 0) {
            let abs_offset = base_abs_offset + start as u64;
            // Skip if Strategy 1 already found a record at the same absolute offset.
            if !strategy1_offsets.contains(&abs_offset) {
                results.push(RecoveredRecord {
                    table: table_name.to_string(),
                    row_id: c.row_id,
                    values: c.values,
                    source: EvidenceSource::CarvedIntraPage {
                        confidence_pct: ((c.confidence * 0.9 * 100.0) as u8).min(99),
                    },
                    offset: abs_offset,
                    confidence: c.confidence * 0.9,
                });
            }
        }
    }

    results
}

/// Collect all leaf page numbers in a B-tree.
fn collect_leaf_pages(db: &[u8], page_size: u32, root_page: u32) -> Vec<u32> {
    use std::collections::HashSet;

    let mut leaves = Vec::new();
    let mut stack = vec![root_page];
    let mut visited = HashSet::new();

    while let Some(page_num) = stack.pop() {
        if !visited.insert(page_num) {
            continue;
        }
        // CORRECT parameter order: (db, page_number, page_size)
        if let Some((page_data, bhdr_offset)) = get_page_data(db, page_num, page_size as usize) {
            if bhdr_offset >= page_data.len() {
                continue;
            }
            let page_type = page_data[bhdr_offset];
            match page_type {
                0x0D => leaves.push(page_num), // table leaf
                0x05 => {
                    // table interior — extract child page numbers
                    let cell_count = u16::from_be_bytes([
                        page_data[bhdr_offset + 3],
                        page_data[bhdr_offset + 4],
                    ]) as usize;
                    // Right-most pointer at bhdr_offset+8
                    if bhdr_offset + 12 <= page_data.len() {
                        let right_child = u32::from_be_bytes([
                            page_data[bhdr_offset + 8],
                            page_data[bhdr_offset + 9],
                            page_data[bhdr_offset + 10],
                            page_data[bhdr_offset + 11],
                        ]);
                        stack.push(right_child);
                    }
                    let ptr_start = bhdr_offset + 12;
                    for i in 0..cell_count {
                        let ptr_off = ptr_start + i * 2;
                        if ptr_off + 2 > page_data.len() { break; }
                        let cell_off = u16::from_be_bytes([
                            page_data[ptr_off], page_data[ptr_off + 1],
                        ]) as usize;
                        if cell_off + 4 <= page_data.len() {
                            let child = u32::from_be_bytes([
                                page_data[cell_off], page_data[cell_off + 1],
                                page_data[cell_off + 2], page_data[cell_off + 3],
                            ]);
                            stack.push(child);
                        }
                    }
                }
                _ => {} // skip index pages etc.
            }
        }
    }

    leaves
}

// ── Context-aware wrapper ─────────────────────────────────────────────────────

use crate::context::RecoveryContext;

/// Context-aware wrapper for scan_page_gaps.
pub fn scan_gaps_with_context(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    let roots_vec: Vec<_> = ctx.table_roots.iter().map(|(k, v)| (k.clone(), *v)).collect();
    scan_page_gaps(ctx.db, ctx.page_size, &roots_vec, &ctx.schema_signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ForensicEngine;
    use crate::record::SqlValue;

    /// Create a DB, insert records, delete one, return the raw bytes.
    ///
    /// We delete only a single record so that its freeblock is not coalesced with
    /// a neighbouring cell's freeblock.  Coalescing overwrites the first 4 bytes of
    /// *both* original cells, which makes reconstruction harder.  With a single
    /// deletion the freeblock covers exactly one original cell: only its first 4 bytes
    /// (payload_len + rowid + record_hlen + first_serial_type) are overwritten by the
    /// freeblock header, leaving the remaining serial-type bytes and all value bytes
    /// intact for partial-reconstruction carving.
    fn make_db_with_deletions() -> Vec<u8> {
        // Open directly on a file (not in-memory + backup) so that SQLite does NOT
        // zero out freed cell data.  The backup API wipes freeblock payloads, which
        // destroys the very data we want to carve.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        // Keep the NamedTempFile alive until after close so the path is valid,
        // but we need an owned path for Connection::open, so we drop tmp after
        // reading the bytes at the end.
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Disable secure_delete so SQLite does NOT zero freed cell bytes.
        // The macOS system SQLite is compiled with SQLITE_SECURE_DELETE=1 by default,
        // which would wipe the freeblock payloads we want to carve.
        conn.execute_batch("PRAGMA secure_delete=OFF; PRAGMA journal_mode=DELETE;").unwrap();
        conn.execute_batch(
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER);
             INSERT INTO msgs VALUES (1, 'alpha message', 1000);
             INSERT INTO msgs VALUES (2, 'beta message', 2000);
             INSERT INTO msgs VALUES (3, 'gamma message', 3000);
             INSERT INTO msgs VALUES (4, 'delta message', 4000);
             DELETE FROM msgs WHERE id = 2;",
        ).unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn test_gap_scan_empty_table_roots() {
        // With an empty table_roots slice, scan_page_gaps has nothing to iterate
        // and must return empty without panicking.
        let db = make_db_with_deletions();
        let recovered = scan_page_gaps(&db, 4096, &[], &[]);
        assert!(recovered.is_empty(), "empty table_roots must yield no results");
    }

    #[test]
    fn test_gap_scan_recovers_deleted_records() {
        let db = make_db_with_deletions();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let live = engine.recover_layer1().unwrap();

        // Should have 3 live records (id=1, id=3, id=4)
        let live_msgs: Vec<_> = live.iter().filter(|r| r.table == "msgs").collect();
        assert_eq!(live_msgs.len(), 3);

        // Build signatures from sqlite_master
        let sig = SchemaSignature::from_create_sql(
            "msgs",
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER)",
        ).unwrap();

        // Scan gaps — should find deleted records (id=2 "beta", id=3 "gamma")
        let table_roots = vec![("msgs".to_string(), 2u32)]; // typical root page
        let recovered = scan_page_gaps(&db, 4096, &table_roots, &[sig]);

        // Should recover at least the text content of deleted records
        let recovered_texts: Vec<String> = recovered
            .iter()
            .filter_map(|r| {
                r.values.iter().find_map(|v| {
                    if let SqlValue::Text(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        assert!(
            recovered_texts.iter().any(|t| t.contains("beta")),
            "should recover 'beta message' from gap. Got: {:?}",
            recovered_texts
        );
    }

    #[test]
    fn test_gap_scan_tags_source_correctly() {
        let db = make_db_with_deletions();
        let sig = SchemaSignature::from_create_sql(
            "msgs",
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER)",
        ).unwrap();
        let table_roots = vec![("msgs".to_string(), 2u32)];
        let recovered = scan_page_gaps(&db, 4096, &table_roots, &[sig]);
        for r in &recovered {
            assert!(
                matches!(r.source, EvidenceSource::CarvedIntraPage { .. }),
                "gap-scanned records should be tagged CarvedIntraPage"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: page too small (line 58)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_page_too_small() {
        let page_data = [0u8; 6]; // < bhdr_offset(0) + 8
        let result = scan_single_page_gap(&page_data, 0, "t", None, 0);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: no signature (line 83)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_no_signature() {
        // A valid leaf page header but no signature → return empty
        let mut page = vec![0u8; 512];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 0; // cell count 0
        page[5] = 0x01;
        page[6] = 0x00; // cell content start = 256
        let result = scan_single_page_gap(&page, 0, "t", None, 0);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: gap region with matching records (lines 89-105)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_finds_records_in_gap() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D; // TableLeaf
        // cell count = 0 (no live cells)
        page[3] = 0;
        page[4] = 0;
        // cell content start = 256 (gap from ptr_array_end=8 to 256)
        page[5] = 0x01;
        page[6] = 0x00; // 256

        // Plant a valid record in the gap region at offset 8 (ptr_array_end)
        // Record format: header_len=2, serial_type 1 (1-byte int), value = 42
        page[8] = 0x02;  // header_len = 2
        page[9] = 0x01;  // serial_type 1 (1-byte integer)
        page[10] = 0x2A; // value = 42

        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        assert!(!result.is_empty(), "Should find carved record in gap region");
        // Verify source is CarvedIntraPage
        for r in &result {
            assert!(matches!(r.source, EvidenceSource::CarvedIntraPage { .. }));
        }
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: gap region all zeros → skipped (line 91)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_all_zeros() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 0;
        page[5] = 0x01;
        page[6] = 0x00; // cell_content_start = 256
        // Gap from 8..256 is all zeros → should be skipped

        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        assert!(result.is_empty(), "All-zero gap should be skipped");
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: cell_content_start == 0 → 65536 (line 76)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_cell_content_start_zero() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D;
        page[3] = 0;
        page[4] = 0;
        // cell_content_start = 0 → interpreted as 65536
        page[5] = 0;
        page[6] = 0;

        // Since cell_content_start=65536 > page.len()=512, the condition
        // ptr_array_end < cell_content_start && cell_content_start <= page_data.len()
        // fails (65536 > 512), so no gap is scanned.
        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: freeblock chain traversal (lines 112-144)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_freeblock_chain() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D; // TableLeaf
        // first freeblock offset = 100
        page[1] = 0;
        page[2] = 100;
        // cell count = 0
        page[3] = 0;
        page[4] = 0;
        // cell content start = 8 (no gap region)
        page[5] = 0;
        page[6] = 8;

        // Freeblock at 100: next_fb=200, size=20
        page[100] = 0;
        page[101] = 200; // next_fb = 200
        page[102] = 0;
        page[103] = 20;  // fb_size = 20
        // Freeblock payload (data after 4-byte header): at 104..120
        // Plant a cell: payload_len(varint)=3, rowid(varint)=5, then record
        // Record: header_len=2, serial_type=1 (1-byte int), value=0x07
        page[104] = 0x03; // payload_len = 3
        page[105] = 0x05; // rowid = 5
        page[106] = 0x02; // header_len = 2
        page[107] = 0x01; // serial_type 1
        page[108] = 0x07; // value = 7

        // Freeblock at 200: next_fb=0 (end), size=10
        page[200] = 0;
        page[201] = 0;   // next_fb = 0 (end of chain)
        page[202] = 0;
        page[203] = 10;  // fb_size = 10
        // Some junk data
        page[204] = 0xFF;

        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        // Should have found records from freeblock chain
        // The full cell parse (strategy 1) should find the record at fb 100
        let strat1: Vec<_> = result.iter().filter(|r| {
            r.row_id == Some(5)
        }).collect();
        assert!(!strat1.is_empty(), "Should find record with rowid 5 from freeblock");
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: freeblock with next <= current → break (line 140-141)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_freeblock_cycle_guard() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D;
        page[1] = 0;
        page[2] = 100; // first freeblock = 100
        page[3] = 0;
        page[4] = 0;
        page[5] = 0;
        page[6] = 8;

        // Freeblock at 100: next=50 (< 100, backwards → triggers break), size=10
        page[100] = 0;
        page[101] = 50;  // next_fb = 50 (< 100)
        page[102] = 0;
        page[103] = 10;

        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        // Should terminate without infinite loop — the backwards pointer triggers break
        // We don't care about specific records, just that it doesn't hang.
    }

    // ---------------------------------------------------------------------------
    // scan_single_page_gap: freeblock with fb_size < 4 → skipped (line 126)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_single_page_gap_freeblock_too_small() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        let mut page = vec![0u8; 512];
        page[0] = 0x0D;
        page[1] = 0;
        page[2] = 100; // first freeblock = 100
        page[3] = 0;
        page[4] = 0;
        page[5] = 0;
        page[6] = 8;

        // Freeblock at 100: next=0, size=3 (too small, < 4)
        page[100] = 0;
        page[101] = 0;
        page[102] = 0;
        page[103] = 3;   // fb_size = 3 → skipped

        let result = scan_single_page_gap(&page, 0, "t", Some(&sig), 0);
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------------------
    // parse_cells_from_freeblock: strategy 2 break when insufficient data (line 239-240)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_cells_from_freeblock_strategy2_break() {
        // Use a schema with 3 columns so column_count=3. Then data of length 1:
        // strategy 2: start=0, 0 + (3-1) = 2 > 1 → break immediately (line 240).
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b INTEGER, c TEXT)",
        ).unwrap();
        assert_eq!(sig.column_count, 3);

        let data = [0xFFu8; 1]; // Only 1 byte
        let _result = parse_cells_from_freeblock(&data, &sig, "t", 0);
        // The break at line 240 should fire on the very first iteration
        // (0 + 2 = 2 > 1). No panic is the main assertion.
    }

    // ---------------------------------------------------------------------------
    // parse_cells_from_freeblock: strategy 1 finds a full cell (lines 192-204)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_cells_from_freeblock_strategy1_full_cell() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        // Build a cell: payload_len=3, rowid=42, record: header_len=2, st=1, value=0x07
        let data = [
            0x03, // payload_len = 3
            0x2A, // rowid = 42
            0x02, // header_len = 2
            0x01, // serial_type 1 (1-byte int)
            0x07, // value = 7
        ];

        let result = parse_cells_from_freeblock(&data, &sig, "t", 1000);
        let strat1: Vec<_> = result.iter().filter(|r| r.row_id == Some(42)).collect();
        assert!(!strat1.is_empty(), "Strategy 1 should find the full cell");
        assert_eq!(strat1[0].values[0], SqlValue::Int(7));
        assert!(matches!(strat1[0].source, EvidenceSource::CarvedIntraPage { .. }));
    }

    // ---------------------------------------------------------------------------
    // parse_cells_from_freeblock: strategy 2 dedup (line 250)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_cells_from_freeblock_strategy2_dedup() {
        let sig = SchemaSignature::from_create_sql(
            "t",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val INTEGER)",
        ).unwrap();

        // Build data that strategy 1 finds, then strategy 2 should skip the same offset
        let data = [
            0x03, 0x01, // payload_len=3, rowid=1
            0x02, 0x01, 0x07, // record: hlen=2, st=1, val=7
        ];

        let result = parse_cells_from_freeblock(&data, &sig, "t", 5000);
        // Count how many records are at the strategy-1 offset
        let at_offset: Vec<_> = result.iter().filter(|r| r.offset == 5000 + 2).collect();
        // Strategy 1 should find one at record_start=2, strategy 2 should skip it (dedup)
        assert!(at_offset.len() <= 1, "Should not have duplicate records at same offset");
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: cycle guard (line 277-278)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_cycle() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        // Page 2: interior that points right-child to itself
        let p2 = page_size;
        db[p2] = 0x05;
        db[p2 + 3] = 0;
        db[p2 + 4] = 0;
        db[p2 + 8..p2 + 12].copy_from_slice(&2u32.to_be_bytes()); // cycle

        let leaves = collect_leaf_pages(&db, page_size as u32, 2);
        assert!(leaves.is_empty(), "Cycle should not produce leaf pages");
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: interior page with children (lines 288-319)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_interior_with_children() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 4];

        // Page 2 (interior): 1 cell pointing to page 3, right-child = page 4
        let p2 = page_size;
        db[p2] = 0x05;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // cell count = 1
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        db[p2 + 8..p2 + 12].copy_from_slice(&4u32.to_be_bytes()); // right = 4
        // Cell pointer at offset 12 → cell at 100
        db[p2 + 12] = 0;
        db[p2 + 13] = 100;
        // Cell at 100: child page = 3
        db[p2 + 100..p2 + 104].copy_from_slice(&3u32.to_be_bytes());

        // Page 3 (leaf)
        let p3 = page_size * 2;
        db[p3] = 0x0D;

        // Page 4 (leaf)
        let p4 = page_size * 3;
        db[p4] = 0x0D;

        let leaves = collect_leaf_pages(&db, page_size as u32, 2);
        assert!(leaves.contains(&3), "Should find leaf page 3");
        assert!(leaves.contains(&4), "Should find leaf page 4");
        assert_eq!(leaves.len(), 2);
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: bhdr_offset >= page_data.len() (line 282-283)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_bhdr_exceeds_page() {
        // Page 1 has bhdr_offset=100. If page_size < 101, bhdr >= len → skip.
        let page_size = 64usize;
        let db = vec![0u8; page_size];
        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        assert!(leaves.is_empty());
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: unknown page type (line 320)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_unknown_type() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        // Page 2: index leaf (0x0A) — not table leaf or interior
        db[page_size] = 0x0A;

        let leaves = collect_leaf_pages(&db, page_size as u32, 2);
        assert!(leaves.is_empty());
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: interior page with cell_off+4 > len (line 311)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_interior_cell_oob() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        let p2 = page_size;
        db[p2] = 0x05;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // cell count = 1
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes());
        // Cell pointer → offset 510 (510+4=514 > 512)
        db[p2 + 12] = 0x01;
        db[p2 + 13] = 0xFE;

        let leaves = collect_leaf_pages(&db, page_size as u32, 2);
        assert!(leaves.is_empty());
    }

    // ---------------------------------------------------------------------------
    // collect_leaf_pages: interior page ptr_off+2 > len (line 307)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_interior_ptr_oob() {
        let page_size = 512usize;
        let mut db = vec![0u8; page_size * 2];
        let p2 = page_size;
        db[p2] = 0x05;
        db[p2 + 3] = 0x0F;
        db[p2 + 4] = 0xFF; // cell count = 4095
        db[p2 + 5] = 0;
        db[p2 + 6] = 100;
        db[p2 + 8..p2 + 12].copy_from_slice(&0u32.to_be_bytes());

        let leaves = collect_leaf_pages(&db, page_size as u32, 2);
        assert!(leaves.is_empty());
    }

    // ---------------------------------------------------------------------------
    // scan_page_gaps with multi-page B-tree (covers collect_leaf_pages interior)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_page_gaps_multi_page_btree() {
        // Create a real DB with enough rows to cause interior pages.
        // Use a file-based connection (not backup) so SQLite doesn't wipe freeblocks.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=1024; PRAGMA secure_delete=OFF; PRAGMA journal_mode=DELETE;").unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, score INTEGER);").unwrap();
        // Insert enough rows to span multiple pages
        for i in 0..200i64 {
            conn.execute(
                "INSERT INTO items VALUES (?, ?, ?)",
                rusqlite::params![i, format!("item_{:04}", i), i * 10],
            ).unwrap();
        }
        // Delete some records to create freeblocks
        conn.execute_batch("DELETE FROM items WHERE id BETWEEN 50 AND 60;").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();

        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let page_size = if page_size == 1 { 65536 } else { page_size };

        let sig = SchemaSignature::from_create_sql(
            "items",
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)",
        ).unwrap();

        // Get root page from sqlite_master by querying it via rusqlite
        let conn2 = rusqlite::Connection::open(&path).unwrap();
        let root: u32 = conn2.query_row(
            "SELECT rootpage FROM sqlite_master WHERE name = 'items'",
            [],
            |row| row.get(0),
        ).unwrap();
        drop(conn2);

        let table_roots = vec![("items".to_string(), root)];
        let recovered = scan_page_gaps(&db, page_size, &table_roots, &[sig]);
        // With secure_delete=OFF, we should recover at least some deleted records.
        // The exact number depends on SQLite's behavior, but we exercise the
        // collect_leaf_pages interior page path and the gap scanning code.
    }

    // ---------------------------------------------------------------------------
    // scan_gaps_with_context: basic smoke test
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_gaps_with_context() {
        use crate::context::RecoveryContext;
        use crate::header::DbHeader;
        use crate::pragma::parse_pragma_info;
        use std::collections::HashMap;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA secure_delete=OFF; PRAGMA journal_mode=DELETE;").unwrap();
        conn.execute_batch(
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER);
             INSERT INTO msgs VALUES (1, 'hello', 100);
             INSERT INTO msgs VALUES (2, 'world', 200);
             DELETE FROM msgs WHERE id = 1;",
        ).unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();

        let header = DbHeader::parse(&db).unwrap();
        let pragma_info = parse_pragma_info(&header, &db);
        let sig = SchemaSignature::from_create_sql(
            "msgs",
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER)",
        ).unwrap();

        let mut roots = HashMap::new();
        roots.insert("msgs".to_string(), 2u32);

        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: roots,
            schema_signatures: vec![sig],
            pragma_info,
        };

        let recovered = scan_gaps_with_context(&ctx);
        // Just exercise the code path — no crash is the main assertion
        for r in &recovered {
            assert!(matches!(r.source, EvidenceSource::CarvedIntraPage { .. }));
        }
    }

    // ---------------------------------------------------------------------------
    // scan_page_gaps: table name not in signatures → no signature → returns empty
    // ---------------------------------------------------------------------------

    #[test]
    fn test_scan_page_gaps_no_matching_signature() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
                            INSERT INTO t VALUES (1, 'a');").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();

        // Signature for a DIFFERENT table name
        let sig = SchemaSignature::from_create_sql(
            "other_table",
            "CREATE TABLE other_table (x TEXT)",
        ).unwrap();

        let table_roots = vec![("t".to_string(), 2u32)];
        let recovered = scan_page_gaps(&db, 4096, &table_roots, &[sig]);
        assert!(recovered.is_empty(), "No matching sig should yield empty");
    }
}
