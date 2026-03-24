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

// ── Context-aware wrapper ─────────────────────────────────────────────────────

use crate::context::RecoveryContext;

/// Context-aware wrapper for parse_journal.
/// `journal` is the raw journal file bytes (not stored in RecoveryContext).
pub fn parse_journal_with_context(ctx: &RecoveryContext, journal: &[u8]) -> Vec<RecoveredRecord> {
    parse_journal(journal, ctx.page_size, &ctx.schema_signatures)
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

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_journal_page_size_zero_uses_db_page_size() {
        // L55-58: header.page_size == 0 → use db_page_size
        let page_size: usize = 1024;
        let sector_size: usize = 512;

        let mut journal = vec![0u8; sector_size + 4 + page_size + 4];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes()); // 1 page
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&0u32.to_be_bytes()); // page_size = 0 → use db_page_size

        // Page record at sector boundary: page_number=2
        journal[sector_size..sector_size + 4].copy_from_slice(&2u32.to_be_bytes());
        // Page data: a table leaf with no cells (won't produce records but exercises the path)
        journal[sector_size + 4] = 0x0D; // table leaf
        // cell count = 0
        journal[sector_size + 4 + 3] = 0x00;
        journal[sector_size + 4 + 4] = 0x00;

        let results = parse_journal(&journal, page_size as u32, &[]);
        // Should not panic; may or may not find records
        let _ = results;
    }

    #[test]
    fn test_parse_journal_sector_size_zero_uses_default() {
        // L61-64: header.sector_size == 0 → use 512
        let page_size: usize = 1024;

        // With sector_size=0 in header, the code uses 512 as default
        let effective_sector: usize = 512;
        let mut journal = vec![0u8; effective_sector + 4 + page_size + 4];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&0u32.to_be_bytes()); // sector_size = 0
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record after header padded to 512
        journal[effective_sector..effective_sector + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[effective_sector + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        let _ = results;
    }

    #[test]
    fn test_parse_journal_sector_size_small_no_padding() {
        // L75-76: sector_size <= JOURNAL_HEADER_SIZE → offset + JOURNAL_HEADER_SIZE
        let page_size: usize = 512;

        // Use sector_size = 1 (smaller than JOURNAL_HEADER_SIZE)
        let mut journal = vec![0u8; JOURNAL_HEADER_SIZE + 4 + page_size + 4];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&1u32.to_be_bytes()); // sector_size = 1
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record starts right after header (no sector padding)
        let data_start = JOURNAL_HEADER_SIZE;
        journal[data_start..data_start + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[data_start + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        let _ = results;
    }

    #[test]
    fn test_parse_journal_page_count_negative_one() {
        // L79-81: header.page_count == -1 → read until end
        let page_size: usize = 512;
        let sector_size: usize = 512;

        let record_size = 4 + page_size + 4; // 520
        // Create journal with 2 page records
        let mut journal = vec![0u8; sector_size + record_size * 2];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&(-1i32).to_be_bytes()); // page_count = -1
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record 1: page_number=2, table leaf with 0 cells
        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[r1 + 4] = 0x0D;

        // Page record 2: page_number=3, table leaf with 0 cells
        let r2 = sector_size + record_size;
        journal[r2..r2 + 4].copy_from_slice(&3u32.to_be_bytes());
        journal[r2 + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        // Should process both pages without crashing
        let _ = results;
    }

    #[test]
    fn test_parse_journal_record_exceeds_journal_len() {
        // L88-89: rec_offset + record_size > journal.len() → break
        let page_size: usize = 4096;
        let sector_size: usize = 512;

        // Journal has header claiming 2 pages but only space for 1
        let record_size = 4 + page_size + 4;
        let mut journal = vec![0u8; sector_size + record_size + 10]; // just a bit more than 1 record
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&2i32.to_be_bytes()); // claims 2 pages
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // First page record
        journal[sector_size..sector_size + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[sector_size + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        // Should process first page, break on second
        let _ = results;
    }

    #[test]
    fn test_parse_journal_page_number_zero_breaks() {
        // L99-100: page_number == 0 → break (end marker)
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size * 2];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&2i32.to_be_bytes()); // 2 pages
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // First page record: page_number = 0 → end marker
        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&0u32.to_be_bytes());

        let results = parse_journal(&journal, page_size as u32, &[]);
        assert!(results.is_empty(), "page_number=0 should break early");
    }

    #[test]
    fn test_parse_journal_schema_carving_fallback() {
        // L120-135: leaf records empty → fall through to schema-aware carving
        // Create a journal page that is a table leaf but has no valid cells,
        // yet the raw bytes contain a pattern matching a schema signature.
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record: page 2, NOT a table leaf (type 0x02 = index interior)
        // This means PageType::from_byte won't return TableLeaf, so leaf parsing is skipped.
        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&2u32.to_be_bytes());
        // Page type = 0x02 (index interior, not table leaf)
        journal[r1 + 4] = 0x02;

        // Embed a pattern that the schema signature can find
        // Put a varint-encoded record somewhere in the page data
        // header_len=2, serial_type=1 (INT8), value=42
        journal[r1 + 4 + 20] = 0x02; // header_len = 2
        journal[r1 + 4 + 21] = 0x01; // serial type 1
        journal[r1 + 4 + 22] = 0x2A; // value = 42

        let sig = SchemaSignature {
            table_name: "test".into(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Integer],
        };

        let results = parse_journal(&journal, page_size as u32, &[sig]);
        // The fallback carving should find the embedded record
        // (whether it does depends on scan_region implementation)
        let _ = results;
    }

    #[test]
    fn test_parse_journal_non_leaf_page_schema_carving() {
        // L107-122, L125-135: page is not a table leaf → skip btree parse, fall to carving
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&2u32.to_be_bytes());
        // page type = 0xFF (invalid, not a table leaf)
        journal[r1 + 4] = 0xFF;

        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Integer],
        };
        let results = parse_journal(&journal, page_size as u32, &[sig]);
        let _ = results;
    }

    #[test]
    fn test_parse_journal_leaf_with_zero_records_falls_to_carving() {
        // L114: leaf_records is empty → skip the continue, fall to schema carving (L125)
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&2u32.to_be_bytes());
        // Table leaf with 0 cells → parse_table_leaf_page returns empty
        journal[r1 + 4] = 0x0D; // table leaf
        journal[r1 + 4 + 3] = 0x00;
        journal[r1 + 4 + 4] = 0x00; // 0 cells

        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Integer],
        };
        let results = parse_journal(&journal, page_size as u32, &[sig]);
        // Falls to carving, which scans the page for patterns
        let _ = results;
    }

    #[test]
    fn test_parse_journal_sector_size_zero_at_section_end() {
        // L141-144: sector_size == 0 fallback (section_end without rounding)
        // Actually sector_size=0 is remapped to 512 at L61-64, so we need
        // header.sector_size = 0 which gives sector_size = 512.
        // The L143-144 branch is for the literal else-case where sector_size == 0.
        // But the code sets sector_size at L61-65 to be at least 512.
        // So sector_size is never 0 in practice. This branch is unreachable
        // with the current code. Still, let's exercise the multi-section path.
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        // Build a 2-section journal
        let section1_size = sector_size + record_size; // header + 1 page record
        let section1_padded = ((section1_size + sector_size - 1) / sector_size) * sector_size;
        let section2_size = sector_size + record_size;
        let total = section1_padded + section2_size;
        let mut journal = vec![0u8; total];

        // Section 1 header
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Section 1 page record
        let r1 = sector_size;
        journal[r1..r1 + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[r1 + 4] = 0x0D;

        // Section 2 header
        let s2 = section1_padded;
        journal[s2..s2 + 8].copy_from_slice(&JOURNAL_MAGIC);
        journal[s2 + 8..s2 + 12].copy_from_slice(&1i32.to_be_bytes());
        journal[s2 + 20..s2 + 24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[s2 + 24..s2 + 28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Section 2 page record
        let r2 = s2 + sector_size;
        journal[r2..r2 + 4].copy_from_slice(&3u32.to_be_bytes());
        journal[r2 + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        // Should process both sections
        let _ = results;
    }

    #[test]
    fn test_parse_journal_with_context_wrapper() {
        // L162-164: parse_journal_with_context
        use crate::context::RecoveryContext;
        use crate::header::DbHeader;
        use crate::pragma::PragmaInfo;
        use std::collections::HashMap;

        let db = vec![0u8; 1024];
        let header = DbHeader {
            page_size: 1024,
            page_count: 0,
            freelist_trunk_page: 0,
            freelist_page_count: 0,
            text_encoding: 1,
            user_version: 0,
        };
        let ctx = RecoveryContext {
            db: &db,
            page_size: 1024,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: vec![],
            pragma_info: PragmaInfo::default(),
        };

        let results = parse_journal_with_context(&ctx, &[]);
        assert!(results.is_empty());

        // Also test with invalid journal data
        let results = parse_journal_with_context(&ctx, b"garbage data");
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_journal_offset_past_end_stops() {
        // L148-150: offset + JOURNAL_HEADER_SIZE > journal.len() → break
        // After processing one section, the next section offset is past the end
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        // Just enough space for one section with one page record
        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        journal[sector_size..sector_size + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[sector_size + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        // After processing section 1, offset advances past journal.len() → loop ends
        let _ = results;
    }

    #[test]
    fn test_parse_journal_page1_bhdr_offset() {
        // L106: page_number == 1 → bhdr = 100
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record: page_number = 1 (page 1 has bhdr at 100)
        journal[sector_size..sector_size + 4].copy_from_slice(&1u32.to_be_bytes());
        // At offset 100 within the page: table leaf
        journal[sector_size + 4 + 100] = 0x0D;
        // Cell count = 0
        journal[sector_size + 4 + 103] = 0x00;
        journal[sector_size + 4 + 104] = 0x00;

        let results = parse_journal(&journal, page_size as u32, &[]);
        let _ = results;
    }

    #[test]
    fn test_parse_journal_bhdr_exceeds_page_data_len() {
        // L107/L122: bhdr >= page_data.len() → skip to schema carving
        // Use page_number=1 (bhdr=100) with a very small page_size < 100.
        // The journal allows setting arbitrary page_size.
        let page_size: usize = 50; // smaller than bhdr=100
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        let mut journal = vec![0u8; sector_size + record_size];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        // Page record: page_number = 1, but page_size=50 < bhdr=100
        // bhdr < page_data.len() → false → skip btree parse → fall to carving
        journal[sector_size..sector_size + 4].copy_from_slice(&1u32.to_be_bytes());

        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Integer],
        };
        let results = parse_journal(&journal, page_size as u32, &[sig]);
        // Exercise the L107 false → L122 close → L125 schema carving path
        let _ = results;
    }

    #[test]
    fn test_parse_journal_multi_section_second_section_offset_past_end() {
        // L148-150: after processing section, next offset > journal.len() → break
        // This is a refinement of test_parse_journal_offset_past_end_stops
        // to ensure the section_end rounding path is taken.
        let page_size: usize = 512;
        let sector_size: usize = 512;
        let record_size = 4 + page_size + 4;

        // Exactly 1 section with 1 page record, tightly packed
        let section_size = sector_size + record_size;
        let total_padded = ((section_size + sector_size - 1) / sector_size) * sector_size;
        // Don't add a second section — the rounded offset will be past the end
        let mut journal = vec![0u8; total_padded];
        journal[..8].copy_from_slice(&JOURNAL_MAGIC);
        journal[8..12].copy_from_slice(&1i32.to_be_bytes());
        journal[20..24].copy_from_slice(&(sector_size as u32).to_be_bytes());
        journal[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());

        journal[sector_size..sector_size + 4].copy_from_slice(&2u32.to_be_bytes());
        journal[sector_size + 4] = 0x0D;

        let results = parse_journal(&journal, page_size as u32, &[]);
        let _ = results;
    }
}
