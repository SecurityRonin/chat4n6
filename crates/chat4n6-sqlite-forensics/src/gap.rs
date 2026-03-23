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
}
