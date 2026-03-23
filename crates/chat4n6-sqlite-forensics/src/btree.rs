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
                    parse_table_leaf_page(page_data, bhdr, page_num, page_size, table);
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
                    parse_table_leaf_page(&page_data, bhdr, page_num, page_size, table);
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

/// Parse all cells from a table leaf page (0x0D).
///
/// `page_data` is the full page slice from byte 0 of the page.
/// `bhdr` is the offset within `page_data` where the B-tree page header starts
/// (100 for page 1 due to the SQLite file header, 0 for all other pages).
/// Cell offsets in the pointer array are always relative to byte 0 of `page_data`.
pub fn parse_table_leaf_page(
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
        let (_payload_len, pl_consumed) = match read_varint(page_data, pos) {
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

        // Parse the record header
        let payload_start = pos;
        let (header_len, hl_consumed) = match read_varint(page_data, pos) {
            Some(v) => v,
            None => continue,
        };
        pos += hl_consumed;

        // Parse serial types from header
        let header_end = payload_start + header_len as usize;
        if header_end > page_data.len() {
            continue; // truncated/malformed cell — skip rather than emit null-filled record
        }
        let mut serial_types = Vec::new();
        while pos < header_end && pos < page_data.len() {
            let (st, consumed) = match read_varint(page_data, pos) {
                Some(v) => v,
                None => break,
            };
            serial_types.push(st);
            pos += consumed;
        }

        // Parse values
        let mut values = Vec::new();
        let mut data_pos = header_end;
        for &st in &serial_types {
            match decode_serial_type(st, page_data, data_pos) {
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
