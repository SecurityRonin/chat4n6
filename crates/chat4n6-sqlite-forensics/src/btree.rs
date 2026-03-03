use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::varint::read_varint;
use chat4n6_plugin_api::EvidenceSource;

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
