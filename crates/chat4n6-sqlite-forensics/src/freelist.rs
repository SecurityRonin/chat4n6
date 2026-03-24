use crate::btree::{get_page_data, parse_table_leaf_page};
use crate::page::PageType;
use crate::record::RecoveredRecord;
use crate::schema_sig::SchemaSignature;
use chat4n6_plugin_api::EvidenceSource;

pub struct Freeblock {
    pub offset: usize,
    pub size: usize,
    pub data: Vec<u8>,
}

/// Walk the freeblock linked list within a single page.
///
/// The B-tree page header for a leaf page (8 bytes) has:
///   +0: page type
///   +1-2: first freeblock offset (0 = none)
///   +3-4: cell count
///   +5-6: cell content area start
///   +7: fragmented bytes count
///
/// Each freeblock starts with: [next: u16][size: u16][data: size-4 bytes]
/// The chain ends when next == 0.
pub fn parse_freeblock_chain(page: &[u8], page_size: usize) -> Vec<Freeblock> {
    if page.len() < 4 {
        return Vec::new();
    }
    let first_fb = u16::from_be_bytes([page[1], page[2]]) as usize;

    let mut freeblocks = Vec::new();
    let mut fb_offset = first_fb;
    let mut visited = std::collections::HashSet::new();

    while fb_offset != 0 && fb_offset + 4 <= page.len() {
        if fb_offset >= page_size {
            break; // freeblock cannot start outside the declared page bounds
        }
        if !visited.insert(fb_offset) {
            break; // cycle guard
        }
        let next = u16::from_be_bytes([page[fb_offset], page[fb_offset + 1]]) as usize;
        let size = u16::from_be_bytes([page[fb_offset + 2], page[fb_offset + 3]]) as usize;

        // size must include its own 4-byte header and must fit within the page
        if size < 4 || fb_offset + size > page.len() {
            break;
        }

        let data = page[fb_offset + 4..fb_offset + size].to_vec();
        freeblocks.push(Freeblock {
            offset: fb_offset,
            size,
            data,
        });
        fb_offset = next;
    }

    freeblocks
}

/// Walk the freelist trunk→leaf chain.
///
/// SQLite freelist format:
///   Trunk page layout (from byte 0 of page):
///     +0-3: next trunk page number (0 = last trunk)
///     +4-7: number of leaf page numbers on this trunk
///     +8..: leaf page numbers (4 bytes each)
///
/// Returns all freed page numbers (trunk and leaf pages included).
pub fn walk_freelist_chain(db: &[u8], trunk_page: u32, page_size: u32) -> Vec<u32> {
    let mut pages = Vec::new();
    if trunk_page == 0 || db.is_empty() {
        return pages;
    }

    let mut current = trunk_page;
    let mut visited = std::collections::HashSet::new();

    while current != 0 {
        if !visited.insert(current) {
            break; // cycle guard
        }
        let page_start = (current as usize - 1) * page_size as usize;
        let page_end = page_start + page_size as usize;
        let Some(page) = db.get(page_start..page_end) else {
            break;
        };

        if page.len() < 8 {
            break;
        }

        let next_trunk = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let leaf_count = u32::from_be_bytes([page[4], page[5], page[6], page[7]]) as usize;

        pages.push(current); // trunk page itself is a freed page

        // Read leaf page numbers
        for i in 0..leaf_count {
            let leaf_off = 8 + i * 4;
            if leaf_off + 4 > page.len() {
                break;
            }
            let leaf_page = u32::from_be_bytes([
                page[leaf_off],
                page[leaf_off + 1],
                page[leaf_off + 2],
                page[leaf_off + 3],
            ]);
            if leaf_page != 0 {
                pages.push(leaf_page);
            }
        }

        current = next_trunk;
    }

    pages
}

/// Recover records from freelist pages.
/// Strategy 1: try parsing freed page as B-tree leaf (preserves rowid).
/// Strategy 2: schema-aware carving on raw page bytes.
pub fn recover_freelist_content(
    db: &[u8],
    page_size: u32,
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    // Read freelist trunk page from DB header bytes 32-35
    if db.len() < 36 {
        return Vec::new();
    }
    let trunk_page = u32::from_be_bytes([db[32], db[33], db[34], db[35]]);
    let free_pages = walk_freelist_chain(db, trunk_page, page_size);
    let mut results = Vec::new();

    for page_num in free_pages {
        let Some((page_data, bhdr_offset)) = get_page_data(db, page_num, page_size as usize) else {
            continue;
        };

        // Strategy 1: try parsing as B-tree table leaf (0x0D)
        if bhdr_offset < page_data.len() {
            if let Some(PageType::TableLeaf) = PageType::from_byte(page_data[bhdr_offset]) {
                let mut leaf_records = parse_table_leaf_page(
                    db, page_data, bhdr_offset, page_num, page_size, "unknown",
                );
                if !leaf_records.is_empty() {
                    for r in &mut leaf_records {
                        r.source = EvidenceSource::Freelist;
                    }
                    results.extend(leaf_records);
                    continue;
                }
            }
        }

        // Strategy 2: schema-aware carving on the raw page bytes
        let page_abs = (page_num as u64 - 1) * page_size as u64;
        for sig in signatures {
            for c in sig.scan_region(page_data) {
                results.push(RecoveredRecord {
                    table: sig.table_name.clone(),
                    row_id: c.row_id,
                    values: c.values,
                    source: EvidenceSource::Freelist,
                    offset: page_abs + c.byte_offset as u64,
                    confidence: c.confidence,
                });
            }
        }
    }

    results
}

// ── Context-aware wrapper ─────────────────────────────────────────────────────

use crate::context::RecoveryContext;

/// Context-aware wrapper for recover_freelist_content.
pub fn recover_freelist_with_context(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    recover_freelist_content(ctx.db, ctx.page_size, &ctx.schema_signatures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_sig::SchemaSignature;

    #[test]
    fn test_freelist_chain_empty() {
        let pages = walk_freelist_chain(&[], 0, 4096);
        assert!(pages.is_empty());
    }

    #[test]
    fn test_walk_freelist_chain_with_trunk_and_leaves() {
        let page_size: usize = 4096;
        // 3 pages: page 1 unused, page 2 = trunk, pages 3+4 = leaves (not in db slice)
        let mut db = vec![0u8; page_size * 2];
        let trunk_start = page_size; // (page 2 - 1) * page_size
                                     // next_trunk = 0
        db[trunk_start..trunk_start + 4].copy_from_slice(&0u32.to_be_bytes());
        // leaf_count = 2
        db[trunk_start + 4..trunk_start + 8].copy_from_slice(&2u32.to_be_bytes());
        // leaf pages: 3 and 4
        db[trunk_start + 8..trunk_start + 12].copy_from_slice(&3u32.to_be_bytes());
        db[trunk_start + 12..trunk_start + 16].copy_from_slice(&4u32.to_be_bytes());

        let pages = walk_freelist_chain(&db, 2, 4096);
        assert_eq!(pages, vec![2, 3, 4]);
    }

    #[test]
    fn test_freelist_chain_cycle_guard() {
        let page_size: usize = 4096;
        // Two trunk pages that point to each other: page 2 → page 3 → page 2 (cycle)
        let mut db = vec![0u8; page_size * 3];
        let p2 = page_size;
        let p3 = page_size * 2;
        // Page 2: next_trunk = 3, leaf_count = 0
        db[p2..p2 + 4].copy_from_slice(&3u32.to_be_bytes());
        db[p2 + 4..p2 + 8].copy_from_slice(&0u32.to_be_bytes());
        // Page 3: next_trunk = 2 (cycle), leaf_count = 0
        db[p3..p3 + 4].copy_from_slice(&2u32.to_be_bytes());
        db[p3 + 4..p3 + 8].copy_from_slice(&0u32.to_be_bytes());

        let pages = walk_freelist_chain(&db, 2, 4096);
        assert_eq!(pages, vec![2, 3]); // cycle stops after visiting both once
    }

    #[test]
    fn test_freeblock_chain_parse() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d; // table leaf page type
                        // first freeblock at offset 200
        page[1] = 0x00;
        page[2] = 0xc8;
        // freeblock at 200: next=0, size=20
        page[200] = 0x00;
        page[201] = 0x00; // next = 0
        page[202] = 0x00;
        page[203] = 0x14; // size = 20
        for i in 204..220 {
            page[i] = (i % 256) as u8;
        }

        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert_eq!(freeblocks.len(), 1);
        assert_eq!(freeblocks[0].offset, 200);
        assert_eq!(freeblocks[0].size, 20);
        assert_eq!(freeblocks[0].data.len(), 16); // size - 4 header bytes
    }

    #[test]
    fn test_freeblock_chain_two_blocks() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d;
        // first freeblock at 200
        page[1] = 0x00;
        page[2] = 0xc8; // first_fb = 200
                        // freeblock at 200: next=300, size=10
        page[200] = 0x01;
        page[201] = 0x2c; // next = 300
        page[202] = 0x00;
        page[203] = 0x0a; // size = 10
                          // freeblock at 300: next=0, size=8
        page[300] = 0x00;
        page[301] = 0x00; // next = 0
        page[302] = 0x00;
        page[303] = 0x08; // size = 8

        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert_eq!(freeblocks.len(), 2);
        assert_eq!(freeblocks[0].offset, 200);
        assert_eq!(freeblocks[0].size, 10);
        assert_eq!(freeblocks[1].offset, 300);
        assert_eq!(freeblocks[1].size, 8);
    }

    #[test]
    fn test_freeblock_chain_self_cycle() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d;
        // first freeblock at 100
        page[1] = 0x00;
        page[2] = 0x64; // first_fb = 100
                        // freeblock at 100: next=100 (self-referential cycle), size=8
        page[100] = 0x00;
        page[101] = 0x64; // next = 100 (cycle!)
        page[102] = 0x00;
        page[103] = 0x08; // size = 8

        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert_eq!(freeblocks.len(), 1); // parse one block, then stop on cycle
    }

    #[test]
    fn test_freelist_content_recovery() {
        let db = make_db_with_freed_pages();
        let sig = SchemaSignature::from_create_sql(
            "items",
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)",
        ).unwrap();
        let recovered = recover_freelist_content(&db, 1024, &[sig]);
        // Should find records from freed pages
        assert!(!recovered.is_empty(), "should recover records from freelist pages");
        for r in &recovered {
            assert_eq!(r.source, EvidenceSource::Freelist);
        }
    }

    #[test]
    fn test_recover_freelist_content_clean_db() {
        // A clean DB with no freelist: db[32..36] == 0 (no trunk page).
        // recover_freelist_content must not panic and must return empty.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO t VALUES (1, 'hello');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();
        // Verify there really is no freelist trunk in this clean DB.
        assert!(db.len() >= 36);
        let trunk = u32::from_be_bytes([db[32], db[33], db[34], db[35]]);
        assert_eq!(trunk, 0, "expected clean DB to have no freelist trunk");
        let recovered = recover_freelist_content(&db, 4096, &[]);
        assert!(recovered.is_empty(), "clean DB should yield no freelist records");
    }

    #[test]
    fn test_recover_freelist_trunk_beyond_db() {
        // Craft a DB header where the trunk page number (bytes 32-35) points
        // far beyond the actual slice.  The walker must not panic.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let mut db = std::fs::read(tmp.path()).unwrap();
        // Overwrite trunk page pointer with 9999 — well beyond db.len().
        db[32..36].copy_from_slice(&9999u32.to_be_bytes());
        let recovered = recover_freelist_content(&db, 4096, &[]);
        // Should return empty without panicking.
        assert!(recovered.is_empty(), "out-of-bounds trunk should yield no records");
    }

    fn make_db_with_freed_pages() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA page_size=1024; PRAGMA journal_mode=DELETE; PRAGMA auto_vacuum=NONE; PRAGMA secure_delete=OFF;"
        ).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER);"
        ).unwrap();
        // Insert enough records to fill multiple pages, then delete them all
        for i in 0..200 {
            conn.execute(
                "INSERT INTO items VALUES (?, ?, ?)",
                rusqlite::params![i, format!("item_{:04}", i), i * 10],
            ).unwrap();
        }
        conn.execute_batch("DELETE FROM items;").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_freeblock_chain_tiny_page() {
        // Covers line 26: return Vec::new() when page.len() < 4.
        let page = vec![0u8; 3];
        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert!(freeblocks.is_empty());
    }

    #[test]
    fn test_freeblock_chain_offset_beyond_page_size() {
        // Covers line 36: break when fb_offset >= page_size.
        // page_size = 100 but page buffer is larger (200 bytes).
        // fb_offset = 150, which is >= page_size but < page.len().
        // The while condition (fb_offset + 4 <= page.len()) passes, then line 36 triggers.
        let mut page = vec![0u8; 200];
        page[0] = 0x0d;
        // First freeblock offset = 150 (0x0096)
        page[1] = 0x00;
        page[2] = 0x96; // first_fb = 150
        let freeblocks = parse_freeblock_chain(&page, 100);
        assert!(freeblocks.is_empty());
    }

    #[test]
    fn test_freeblock_chain_size_too_small() {
        // Covers line 46: break when size < 4.
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d;
        page[1] = 0x00;
        page[2] = 0x64; // first_fb = 100
        // freeblock at 100: next=0, size=3 (< 4 → invalid)
        page[100] = 0x00;
        page[101] = 0x00;
        page[102] = 0x00;
        page[103] = 0x03; // size = 3
        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert!(freeblocks.is_empty());
    }

    #[test]
    fn test_walk_freelist_page_too_small() {
        // Covers line 90: break when page.len() < 8.
        // Create a tiny "page" that's less than 8 bytes. page_size must match.
        let db = vec![0u8; 4]; // 1 page of size 4 (less than 8)
        let pages = walk_freelist_chain(&db, 1, 4);
        assert!(pages.is_empty());
    }

    #[test]
    fn test_walk_freelist_leaf_offset_overflow() {
        // Covers line 102: break when leaf_off + 4 > page.len().
        // Create a trunk page that claims to have many leaves, but the page is too short.
        let page_size: usize = 32; // very small page
        let mut db = vec![0u8; page_size];
        // Page 1 (offset 0): trunk page
        db[0..4].copy_from_slice(&0u32.to_be_bytes()); // next_trunk = 0
        db[4..8].copy_from_slice(&100u32.to_be_bytes()); // leaf_count = 100 (way more than fits)
        // Only room for (32 - 8) / 4 = 6 leaf entries.
        // Leaf entries at offsets 8, 12, 16, 20, 24, 28 — then offset 32 overflows.
        for i in 0..6 {
            let off = 8 + i * 4;
            db[off..off + 4].copy_from_slice(&((i as u32) + 2).to_be_bytes());
        }
        let pages = walk_freelist_chain(&db, 1, page_size as u32);
        // Should get trunk page (1) + 6 leaf pages, then break at leaf_off overflow.
        assert_eq!(pages[0], 1);
        assert!(pages.len() <= 7);
    }

    #[test]
    fn test_recover_freelist_db_too_small() {
        // Covers line 131: return Vec::new() when db.len() < 36.
        let db = vec![0u8; 35]; // too small to read trunk page pointer
        let results = recover_freelist_content(&db, 4096, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freelist_page_not_table_leaf() {
        // Covers line 156: page is found but page type is not TableLeaf.
        // Falls through to Strategy 2 (carving). With no signatures, nothing is carved.
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 3];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        // Freelist trunk page = 2
        db[32..36].copy_from_slice(&2u32.to_be_bytes());
        let p2 = page_size;
        db[p2..p2 + 4].copy_from_slice(&0u32.to_be_bytes());
        db[p2 + 4..p2 + 8].copy_from_slice(&1u32.to_be_bytes());
        db[p2 + 8..p2 + 12].copy_from_slice(&3u32.to_be_bytes());
        // Page 3: all zeros — page type 0x00 != 0x0D.
        let results = recover_freelist_content(&db, page_size as u32, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freelist_get_page_data_none() {
        // Covers line 139: continue when get_page_data returns None.
        // Freelist references a page number beyond the DB.
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        // Trunk page = 2
        db[32..36].copy_from_slice(&2u32.to_be_bytes());
        let p2 = page_size;
        db[p2..p2 + 4].copy_from_slice(&0u32.to_be_bytes());
        db[p2 + 4..p2 + 8].copy_from_slice(&1u32.to_be_bytes());
        // Leaf page = 99 (far beyond DB)
        db[p2 + 8..p2 + 12].copy_from_slice(&99u32.to_be_bytes());
        let results = recover_freelist_content(&db, page_size as u32, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freelist_leaf_page_empty_records() {
        // Covers lines 154-156: page IS a TableLeaf (0x0D) but parse_table_leaf_page
        // returns empty records (no cells). Falls through to Strategy 2.
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 3];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[32..36].copy_from_slice(&2u32.to_be_bytes());
        let p2 = page_size;
        db[p2..p2 + 4].copy_from_slice(&0u32.to_be_bytes());
        db[p2 + 4..p2 + 8].copy_from_slice(&1u32.to_be_bytes());
        db[p2 + 8..p2 + 12].copy_from_slice(&3u32.to_be_bytes());
        // Page 3: set page type to 0x0D (TableLeaf) but with 0 cells.
        let p3 = page_size * 2;
        db[p3] = 0x0D; // table leaf page type
        db[p3 + 1] = 0x00; // first freeblock = 0
        db[p3 + 2] = 0x00;
        db[p3 + 3] = 0x00; // cell count = 0
        db[p3 + 4] = 0x00;
        db[p3 + 5] = 0x00; // cell content area start
        db[p3 + 6] = 0x00;
        db[p3 + 7] = 0x00; // fragmented bytes
        let results = recover_freelist_content(&db, page_size as u32, &[]);
        // parse_table_leaf_page returns empty (0 cells) → falls through to Strategy 2.
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freelist_with_context_wrapper() {
        // Covers lines 182-184: recover_freelist_with_context.
        use crate::context::RecoveryContext;
        use crate::header::DbHeader;
        use crate::pragma::parse_pragma_info;
        use std::collections::HashMap;

        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10; // page_size = 4096
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8

        let header = DbHeader::parse(&db).expect("valid header");
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };
        let results = recover_freelist_with_context(&ctx);
        // Clean DB with no freelist → empty results
        assert!(results.is_empty());
    }
}
