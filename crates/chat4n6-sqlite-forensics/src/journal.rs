use crate::btree::parse_table_leaf_page;
use crate::page::PageType;
use crate::record::RecoveredRecord;
use crate::schema_sig::SchemaSignature;
use chat4n6_plugin_api::EvidenceSource;

pub const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
pub const JOURNAL_HEADER_SIZE: usize = 28;

pub fn is_journal_header(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == JOURNAL_MAGIC
}

#[derive(Debug)]
pub struct JournalHeader {
    pub page_count: i32,  // -1 means read until end
    pub nonce: u32,
    pub initial_db_size: u32,
    pub sector_size: u32,
    pub page_size: u32,
}

impl JournalHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < JOURNAL_HEADER_SIZE || !is_journal_header(data) {
            return None;
        }
        Some(Self {
            page_count: i32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            nonce: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            initial_db_size: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            sector_size: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
            page_size: u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
        })
    }
}

/// Parse a rollback journal and recover records from pre-modification page snapshots.
/// Handles multi-section journals (multiple transaction snapshots).
pub fn parse_journal(
    journal: &[u8],
    db_page_size: u32,
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    let mut results = Vec::new();
    let mut offset = 0;

    // Process each journal section
    while offset + JOURNAL_HEADER_SIZE <= journal.len() {
        let header = match JournalHeader::parse(&journal[offset..]) {
            Some(h) => h,
            None => break,
        };

        let page_size = if header.page_size > 0 {
            header.page_size
        } else {
            db_page_size
        } as usize;

        let sector_size = if header.sector_size > 0 {
            header.sector_size as usize
        } else {
            512 // default sector size
        };

        // Page record size: 4 (page number) + page_size + 4 (checksum)
        let record_size = 4 + page_size + 4;

        // Start reading page records after the header
        // Header is padded to sector boundary
        let data_start = if sector_size > JOURNAL_HEADER_SIZE {
            // Round up to sector boundary
            ((offset + JOURNAL_HEADER_SIZE + sector_size - 1) / sector_size) * sector_size
        } else {
            offset + JOURNAL_HEADER_SIZE
        };

        let page_count = if header.page_count < 0 {
            // -1 means read until end of journal
            (journal.len().saturating_sub(data_start)) / record_size
        } else {
            header.page_count as usize
        };

        for i in 0..page_count {
            let rec_offset = data_start + i * record_size;
            if rec_offset + record_size > journal.len() {
                break;
            }

            let page_number = u32::from_be_bytes([
                journal[rec_offset],
                journal[rec_offset + 1],
                journal[rec_offset + 2],
                journal[rec_offset + 3],
            ]);

            if page_number == 0 {
                break; // end marker
            }

            let page_data = &journal[rec_offset + 4..rec_offset + 4 + page_size];

            // Try parsing as B-tree table leaf
            let bhdr = if page_number == 1 { 100 } else { 0 };
            if bhdr < page_data.len() {
                if let Some(PageType::TableLeaf) = PageType::from_byte(page_data[bhdr]) {
                    // For journal pages, pass page_data as the "db" too since
                    // overflow chains won't be in the journal
                    let mut leaf_records = parse_table_leaf_page(
                        page_data, page_data, bhdr, page_number, page_size as u32, "journal_unknown",
                    );
                    if !leaf_records.is_empty() {
                        for r in &mut leaf_records {
                            r.source = EvidenceSource::Journal;
                        }
                        results.extend(leaf_records);
                        continue;
                    }
                }
            }

            // Fall back to schema-aware carving
            for sig in signatures {
                for c in sig.scan_region(page_data) {
                    results.push(RecoveredRecord {
                        table: sig.table_name.clone(),
                        row_id: c.row_id,
                        values: c.values,
                        source: EvidenceSource::Journal,
                        offset: rec_offset as u64 + 4 + c.byte_offset as u64,
                        confidence: c.confidence,
                    });
                }
            }
        }

        // Move to next section: advance past all page records to next sector boundary
        let section_end = data_start + page_count * record_size;
        offset = if sector_size > 0 {
            ((section_end + sector_size - 1) / sector_size) * sector_size
        } else {
            section_end
        };

        // If we're not at a valid journal header, stop
        if offset + JOURNAL_HEADER_SIZE > journal.len() {
            break;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_magic_detection() {
        assert!(is_journal_header(&JOURNAL_MAGIC));
        assert!(!is_journal_header(b"not a journal"));
        assert!(!is_journal_header(&[0xd9, 0xd5])); // too short
    }

    #[test]
    fn test_journal_header_parse() {
        let mut header = vec![0u8; 28];
        header[..8].copy_from_slice(&JOURNAL_MAGIC);
        header[8..12].copy_from_slice(&5u32.to_be_bytes()); // page_count = 5
        header[12..16].copy_from_slice(&12345u32.to_be_bytes()); // nonce
        header[16..20].copy_from_slice(&100u32.to_be_bytes()); // initial_db_size
        header[20..24].copy_from_slice(&512u32.to_be_bytes()); // sector_size
        header[24..28].copy_from_slice(&4096u32.to_be_bytes()); // page_size
        let h = JournalHeader::parse(&header).unwrap();
        assert_eq!(h.page_count, 5);
        assert_eq!(h.nonce, 12345);
        assert_eq!(h.initial_db_size, 100);
        assert_eq!(h.sector_size, 512);
        assert_eq!(h.page_size, 4096);
    }

    #[test]
    fn test_parse_journal_synthetic() {
        // Build a synthetic journal with one page containing a table leaf
        let page_size: usize = 4096;
        let sector_size: usize = 512;

        // Build journal header
        let mut journal = vec![0u8; sector_size]; // pad header to sector
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes()); // 1 page
        journal[12..16].copy_from_slice(&0u32.to_be_bytes()); // nonce
        journal[16..20].copy_from_slice(&2u32.to_be_bytes()); // initial db size
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Build a page record: page_number(4) + page_data(4096) + checksum(4)
        // Page number = 2
        journal.extend_from_slice(&2u32.to_be_bytes());

        // Create a minimal table leaf page with one record
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D; // table leaf
        // cell count = 1
        page[3] = 0x00;
        page[4] = 0x01;
        // cell content start (somewhere after cell pointer array)
        let cell_start: u16 = 100;
        page[5] = (cell_start >> 8) as u8;
        page[6] = (cell_start & 0xFF) as u8;
        // Cell pointer array starts at offset 8
        // First cell pointer = cell_start
        page[8] = (cell_start >> 8) as u8;
        page[9] = (cell_start & 0xFF) as u8;
        // At cell_start: payload_len(varint) + rowid(varint) + record
        // Simple record: header_len=3, serial_type=1(1-byte int), serial_type=13(0-len text)
        // payload_len = 4 (header + values)
        page[cell_start as usize] = 0x04; // payload_len = 4
        page[cell_start as usize + 1] = 0x01; // rowid = 1
        page[cell_start as usize + 2] = 0x03; // header_len = 3
        page[cell_start as usize + 3] = 0x01; // serial_type 1 (1-byte int)
        page[cell_start as usize + 4] = 0x0D; // serial_type 13 (0-len text)
        page[cell_start as usize + 5] = 0x2A; // value = 42

        journal.extend_from_slice(&page);
        // Checksum (4 bytes, we won't validate it)
        journal.extend_from_slice(&[0, 0, 0, 0]);

        let sig = SchemaSignature {
            table_name: "test".into(),
            column_count: 2,
            type_hints: vec![
                crate::schema_sig::ColumnTypeHint::Integer,
                crate::schema_sig::ColumnTypeHint::Text,
            ],
        };

        let results = parse_journal(&journal, page_size as u32, &[sig]);
        assert!(!results.is_empty(), "should recover records from journal page");
        for r in &results {
            assert_eq!(r.source, EvidenceSource::Journal);
        }
    }

    #[test]
    fn test_parse_empty_journal() {
        let results = parse_journal(&[], 4096, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_journal_invalid_magic() {
        let results = parse_journal(b"not a journal at all", 4096, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_journal_valid_header_page_count_zero() {
        // A valid journal header with page_count=0 — no page records follow, so
        // parse_journal must return empty without panicking.
        let mut journal = vec![0u8; JOURNAL_HEADER_SIZE];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        // page_count = 0 (bytes 8-11)
        journal[8..12].copy_from_slice(&0u32.to_be_bytes());
        // sector_size = 512 (bytes 20-23)
        journal[20..24].copy_from_slice(&512u32.to_be_bytes());
        // page_size = 4096 (bytes 24-27)
        journal[24..28].copy_from_slice(&4096u32.to_be_bytes());
        let results = parse_journal(&journal, 4096, &[]);
        assert!(results.is_empty(), "page_count=0 should yield no records");
    }
}
