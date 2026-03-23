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
                    page_data, bhdr_offset, page_num, page_size, "unknown",
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
}
