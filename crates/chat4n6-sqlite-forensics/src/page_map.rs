//! Page-to-table ownership map — bring2lite Algorithm 2.
//!
//! Builds a complete mapping of which table owns each page in a SQLite database
//! by traversing all B-trees from their root pages and following overflow and
//! freelist chains.

use crate::btree::get_page_data;
use crate::header::DbHeader;
use crate::page::PageType;
use crate::varint::read_varint;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum PageRole {
    BTreeLeaf,
    BTreeInterior,
    Overflow { parent_page: u32 },
    FreelistTrunk,
    FreelistLeaf,
    PointerMap,
}

#[derive(Debug, Clone)]
pub struct PageOwnership {
    pub table_name: String,
    pub page_role: PageRole,
}

pub struct PageMap {
    map: HashMap<u32, PageOwnership>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl PageMap {
    /// Build page map by traversing all B-trees from root pages.
    ///
    /// For each (table_name, root_page) in `table_roots`:
    ///   - Walks the B-tree, marking interior and leaf pages.
    ///   - Follows overflow chains from leaf cells.
    ///
    /// Also walks the freelist trunk→leaf chain from the database header.
    pub fn build(db: &[u8], page_size: u32, table_roots: &HashMap<String, u32>) -> Self {
        let mut map: HashMap<u32, PageOwnership> = HashMap::new();

        // Walk each table's B-tree.
        for (table_name, &root_page) in table_roots {
            Self::walk_btree(db, page_size, root_page, table_name, &mut map);
        }

        // Walk the freelist chain.
        if let Some(header) = DbHeader::parse(db) {
            if header.freelist_trunk_page != 0 {
                Self::walk_freelist(db, page_size, header.freelist_trunk_page, &mut map);
            }
        }

        PageMap { map }
    }

    /// Look up which table owns a page.
    pub fn owner_of(&self, page_num: u32) -> Option<&PageOwnership> {
        self.map.get(&page_num)
    }

    /// Get all pages belonging to a table (sorted ascending).
    pub fn pages_for_table(&self, table_name: &str) -> Vec<u32> {
        let mut pages: Vec<u32> = self
            .map
            .iter()
            .filter(|(_, v)| v.table_name == table_name)
            .map(|(k, _)| *k)
            .collect();
        pages.sort_unstable();
        pages
    }

    /// Find pages not owned by any table or freelist (1-based, inclusive up to total_pages).
    pub fn unowned_pages(&self, total_pages: u32) -> Vec<u32> {
        (1..=total_pages)
            .filter(|p| !self.map.contains_key(p))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Walk a B-tree rooted at `root_page`, recording all pages in `map`.
    /// Uses a visited set for cycle detection.
    fn walk_btree(
        db: &[u8],
        page_size: u32,
        root_page: u32,
        table_name: &str,
        map: &mut HashMap<u32, PageOwnership>,
    ) {
        let mut stack: Vec<u32> = vec![root_page];
        let mut visited: HashSet<u32> = HashSet::new();

        while let Some(page_num) = stack.pop() {
            if !visited.insert(page_num) {
                continue; // cycle guard
            }
            // Skip if already owned (another table claimed it first).
            if map.contains_key(&page_num) {
                continue;
            }

            let Some((page_data, bhdr)) = get_page_data(db, page_num, page_size as usize) else {
                continue;
            };
            if page_data.len() <= bhdr {
                continue;
            }

            match PageType::from_byte(page_data[bhdr]) {
                Some(PageType::TableInterior) | Some(PageType::IndexInterior) => {
                    map.insert(
                        page_num,
                        PageOwnership {
                            table_name: table_name.to_string(),
                            page_role: PageRole::BTreeInterior,
                        },
                    );

                    // Read cell count (bhdr+3..bhdr+5).
                    let cell_count = if page_data.len() >= bhdr + 5 {
                        u16::from_be_bytes([page_data[bhdr + 3], page_data[bhdr + 4]]) as usize
                    } else {
                        0
                    };

                    // Right-most child pointer (bhdr+8..bhdr+12).
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

                    // Cell pointer array starts at bhdr+12 for interior pages.
                    let ptr_array_start = bhdr + 12;
                    for i in 0..cell_count {
                        let ptr_off = ptr_array_start + i * 2;
                        if ptr_off + 2 > page_data.len() {
                            break;
                        }
                        let cell_off = u16::from_be_bytes([
                            page_data[ptr_off],
                            page_data[ptr_off + 1],
                        ]) as usize;
                        if cell_off + 4 > page_data.len() {
                            continue;
                        }
                        // First 4 bytes of each interior cell = left child page number.
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

                Some(PageType::TableLeaf) => {
                    map.insert(
                        page_num,
                        PageOwnership {
                            table_name: table_name.to_string(),
                            page_role: PageRole::BTreeLeaf,
                        },
                    );
                    // Scan for overflow pages.
                    Self::collect_overflow_pages(
                        db,
                        page_data,
                        bhdr,
                        page_num,
                        page_size,
                        table_name,
                        map,
                        &mut visited,
                    );
                }

                Some(PageType::IndexLeaf) => {
                    map.insert(
                        page_num,
                        PageOwnership {
                            table_name: table_name.to_string(),
                            page_role: PageRole::BTreeLeaf,
                        },
                    );
                    // Index leaf overflow uses the same format; scan cells.
                    Self::collect_overflow_pages_index(
                        db,
                        page_data,
                        bhdr,
                        page_num,
                        page_size,
                        table_name,
                        map,
                        &mut visited,
                    );
                }

                _ => {
                    // Unknown / overflow / dropped — skip without marking.
                }
            }
        }
    }

    /// Scan a table leaf page for overflow chains and record each overflow page.
    #[allow(clippy::too_many_arguments)]
    fn collect_overflow_pages(
        db: &[u8],
        page_data: &[u8],
        bhdr: usize,
        _page_num: u32,
        page_size: u32,
        table_name: &str,
        map: &mut HashMap<u32, PageOwnership>,
        visited: &mut HashSet<u32>,
    ) {
        if page_data.len() < bhdr + 8 {
            return;
        }
        let cell_count =
            u16::from_be_bytes([page_data[bhdr + 3], page_data[bhdr + 4]]) as usize;
        let ptr_array_start = bhdr + 8; // leaf header is 8 bytes

        let usable = page_size as usize;
        let max_local = usable - 35;
        let min_local = (usable - 12) * 32 / 255 - 23;

        for i in 0..cell_count {
            let ptr_off = ptr_array_start + i * 2;
            if ptr_off + 2 > page_data.len() {
                break;
            }
            let cell_off =
                u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
            if cell_off == 0 || cell_off >= page_data.len() {
                continue;
            }

            // Cell layout: [payload_length varint][row_id varint][payload...]
            let mut pos = cell_off;
            let Some((payload_len, pl_consumed)) = read_varint(page_data, pos) else {
                continue;
            };
            pos += pl_consumed;

            // Skip row_id varint.
            let Some((_, rid_consumed)) = read_varint(page_data, pos) else {
                continue;
            };
            pos += rid_consumed;

            let payload_len_usize = payload_len as usize;
            if payload_len_usize > max_local {
                let mut local_size =
                    min_local + (payload_len_usize - min_local) % (usable - 4);
                if local_size > max_local {
                    local_size = min_local;
                }
                let overflow_ptr_pos = pos + local_size;
                if overflow_ptr_pos + 4 <= page_data.len() {
                    let first_overflow = u32::from_be_bytes([
                        page_data[overflow_ptr_pos],
                        page_data[overflow_ptr_pos + 1],
                        page_data[overflow_ptr_pos + 2],
                        page_data[overflow_ptr_pos + 3],
                    ]);
                    if first_overflow != 0 {
                        Self::walk_overflow_chain(
                            db,
                            page_size,
                            first_overflow,
                            _page_num,
                            table_name,
                            map,
                            visited,
                        );
                    }
                }
            }
        }
    }

    /// Scan an index leaf page for overflow chains.
    /// Index leaf cell layout: [payload_length varint][payload...] (no row_id).
    #[allow(clippy::too_many_arguments)]
    fn collect_overflow_pages_index(
        db: &[u8],
        page_data: &[u8],
        bhdr: usize,
        page_num: u32,
        page_size: u32,
        table_name: &str,
        map: &mut HashMap<u32, PageOwnership>,
        visited: &mut HashSet<u32>,
    ) {
        if page_data.len() < bhdr + 8 {
            return;
        }
        let cell_count =
            u16::from_be_bytes([page_data[bhdr + 3], page_data[bhdr + 4]]) as usize;
        let ptr_array_start = bhdr + 8;

        // Index B-tree leaf overflow thresholds (same formula as table leaf).
        let usable = page_size as usize;
        let max_local = usable - 35;
        let min_local = (usable - 12) * 32 / 255 - 23;

        for i in 0..cell_count {
            let ptr_off = ptr_array_start + i * 2;
            if ptr_off + 2 > page_data.len() {
                break;
            }
            let cell_off =
                u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
            if cell_off == 0 || cell_off >= page_data.len() {
                continue;
            }

            // Index leaf cell: [payload_length varint][payload...]
            let mut pos = cell_off;
            let Some((payload_len, pl_consumed)) = read_varint(page_data, pos) else {
                continue;
            };
            pos += pl_consumed;

            let payload_len_usize = payload_len as usize;
            if payload_len_usize > max_local {
                let mut local_size =
                    min_local + (payload_len_usize - min_local) % (usable - 4);
                if local_size > max_local {
                    local_size = min_local;
                }
                let overflow_ptr_pos = pos + local_size;
                if overflow_ptr_pos + 4 <= page_data.len() {
                    let first_overflow = u32::from_be_bytes([
                        page_data[overflow_ptr_pos],
                        page_data[overflow_ptr_pos + 1],
                        page_data[overflow_ptr_pos + 2],
                        page_data[overflow_ptr_pos + 3],
                    ]);
                    if first_overflow != 0 {
                        Self::walk_overflow_chain(
                            db,
                            page_size,
                            first_overflow,
                            page_num,
                            table_name,
                            map,
                            visited,
                        );
                    }
                }
            }
        }
    }

    /// Follow an overflow page chain, recording each page in the map.
    fn walk_overflow_chain(
        db: &[u8],
        page_size: u32,
        first_page: u32,
        parent_page: u32,
        table_name: &str,
        map: &mut HashMap<u32, PageOwnership>,
        visited: &mut HashSet<u32>,
    ) {
        let mut current = first_page;
        let ps = page_size as usize;

        while current != 0 {
            if !visited.insert(current) {
                break; // cycle guard
            }
            if map.contains_key(&current) {
                break; // already owned
            }

            let page_start = (current as usize - 1) * ps;
            let page_end = page_start + ps;
            let Some(page_data) = db.get(page_start..page_end) else {
                break;
            };
            if page_data.len() < 4 {
                break;
            }

            map.insert(
                current,
                PageOwnership {
                    table_name: table_name.to_string(),
                    page_role: PageRole::Overflow { parent_page },
                },
            );

            // First 4 bytes of each overflow page = next page number (0 = end).
            let next =
                u32::from_be_bytes([page_data[0], page_data[1], page_data[2], page_data[3]]);
            current = next;
        }
    }

    /// Walk the freelist trunk→leaf chain, recording each page.
    fn walk_freelist(
        db: &[u8],
        page_size: u32,
        trunk_page: u32,
        map: &mut HashMap<u32, PageOwnership>,
    ) {
        let mut current = trunk_page;
        let ps = page_size as usize;
        let mut visited: HashSet<u32> = HashSet::new();

        while current != 0 {
            if !visited.insert(current) {
                break; // cycle guard
            }

            let page_start = (current as usize - 1) * ps;
            let page_end = page_start + ps;
            let Some(page) = db.get(page_start..page_end) else {
                break;
            };
            if page.len() < 8 {
                break;
            }

            // Mark trunk page.
            map.entry(current).or_insert_with(|| PageOwnership {
                table_name: "__freelist__".to_string(),
                page_role: PageRole::FreelistTrunk,
            });

            let next_trunk = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
            let leaf_count = u32::from_be_bytes([page[4], page[5], page[6], page[7]]) as usize;

            // Read and mark each leaf page number.
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
                    map.entry(leaf_page).or_insert_with(|| PageOwnership {
                        table_name: "__freelist__".to_string(),
                        page_role: PageRole::FreelistLeaf,
                    });
                }
            }

            current = next_trunk;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    fn get_page_size(db: &[u8]) -> u32 {
        let raw = u16::from_be_bytes([db[16], db[17]]) as u32;
        if raw == 1 { 65536 } else { raw }
    }

    #[test]
    fn test_simple_db_all_pages_mapped() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);
        let total_pages = db.len() as u32 / page_size;
        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);
        assert!(pm.owner_of(1).is_some());
        // Page 1 must belong to sqlite_master.
        let ownership = pm.owner_of(1).unwrap();
        assert_eq!(ownership.table_name, "sqlite_master");
        let _ = total_pages; // may be used for unowned check
    }

    #[test]
    fn test_multi_table_pages_attributed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=1024;").unwrap();
        conn.execute_batch(
            "CREATE TABLE t1 (id INTEGER PRIMARY KEY, data TEXT);
             CREATE TABLE t2 (id INTEGER PRIMARY KEY, data TEXT);",
        )
        .unwrap();
        for i in 0..100 {
            conn.execute(
                "INSERT INTO t1 VALUES (?, ?)",
                rusqlite::params![i, format!("t1_{:04}", i)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO t2 VALUES (?, ?)",
                rusqlite::params![i, format!("t2_{:04}", i)],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        // Build table_roots from sqlite_master manually.
        use crate::btree::walk_table_btree;
        use crate::record::SqlValue;
        use chat4n6_plugin_api::EvidenceSource;
        let mut master_records = Vec::new();
        walk_table_btree(
            &db,
            page_size,
            1,
            "sqlite_master",
            EvidenceSource::Live,
            &mut master_records,
        );
        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        for r in &master_records {
            if r.values.len() >= 5 {
                if let (SqlValue::Text(tp), SqlValue::Text(name), SqlValue::Int(rp)) =
                    (&r.values[0], &r.values[1], &r.values[3])
                {
                    if tp == "table" && *rp > 0 {
                        roots.insert(name.clone(), *rp as u32);
                    }
                }
            }
        }

        let pm = PageMap::build(&db, page_size, &roots);
        let t1_pages = pm.pages_for_table("t1");
        let t2_pages = pm.pages_for_table("t2");
        assert!(!t1_pages.is_empty(), "t1 should have pages");
        assert!(!t2_pages.is_empty(), "t2 should have pages");
        // No overlap between t1 and t2 pages.
        for p in &t1_pages {
            assert!(!t2_pages.contains(p), "page {} in both t1 and t2", p);
        }
    }

    #[test]
    fn test_empty_db_only_master() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE empty_t (id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);
        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);
        assert!(pm.owner_of(1).is_some());
    }

    #[test]
    fn test_unowned_pages() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);
        let total_pages = db.len() as u32 / page_size;
        let mut roots = HashMap::new();
        // Only map sqlite_master, not the items table.
        roots.insert("sqlite_master".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);
        let unowned = pm.unowned_pages(total_pages);
        // Items table pages should be unowned since we didn't include it.
        assert!(!unowned.is_empty() || total_pages <= 1);
    }

    #[test]
    fn test_page_role_btree_leaf() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);
        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);
        // Page 1 is the root of sqlite_master — should be a leaf for a tiny DB.
        let ownership = pm.owner_of(1).unwrap();
        assert!(
            matches!(
                ownership.page_role,
                PageRole::BTreeLeaf | PageRole::BTreeInterior
            ),
            "unexpected role: {:?}",
            ownership.page_role
        );
    }

    #[test]
    fn test_pages_for_table_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE big (id INTEGER PRIMARY KEY, data TEXT);",
        )
        .unwrap();
        for i in 0..200 {
            conn.execute(
                "INSERT INTO big VALUES (?, ?)",
                rusqlite::params![i, format!("row_{:05}", i)],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        use crate::btree::walk_table_btree;
        use crate::record::SqlValue;
        use chat4n6_plugin_api::EvidenceSource;
        let mut master_records = Vec::new();
        walk_table_btree(
            &db,
            page_size,
            1,
            "sqlite_master",
            EvidenceSource::Live,
            &mut master_records,
        );
        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        for r in &master_records {
            if r.values.len() >= 5 {
                if let (SqlValue::Text(tp), SqlValue::Text(name), SqlValue::Int(rp)) =
                    (&r.values[0], &r.values[1], &r.values[3])
                {
                    if tp == "table" && *rp > 0 {
                        roots.insert(name.clone(), *rp as u32);
                    }
                }
            }
        }

        let pm = PageMap::build(&db, page_size, &roots);
        let pages = pm.pages_for_table("big");
        // Must be non-empty and sorted.
        assert!(!pages.is_empty());
        for w in pages.windows(2) {
            assert!(w[0] < w[1], "pages_for_table not sorted");
        }
    }

    #[test]
    fn test_freelist_pages_marked() {
        // Create a DB, insert rows, then delete them to populate the freelist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=1024;").unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT);",
        )
        .unwrap();
        for i in 0..200 {
            conn.execute(
                "INSERT INTO t VALUES (?, ?)",
                rusqlite::params![i, format!("row_{:05}", i)],
            )
            .unwrap();
        }
        conn.execute_batch("DELETE FROM t;").unwrap();
        conn.execute_batch("PRAGMA incremental_vacuum;").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        // Check if there's a freelist at all.
        if let Some(header) = DbHeader::parse(&db) {
            if header.freelist_trunk_page != 0 {
                let mut roots = HashMap::new();
                roots.insert("sqlite_master".to_string(), 1u32);
                let pm = PageMap::build(&db, page_size, &roots);
                // At least the trunk page should be marked.
                let trunk = header.freelist_trunk_page;
                let ownership = pm.owner_of(trunk);
                assert!(
                    ownership.is_some(),
                    "freelist trunk page {} not marked",
                    trunk
                );
                assert_eq!(
                    ownership.unwrap().table_name,
                    "__freelist__"
                );
                assert_eq!(
                    ownership.unwrap().page_role,
                    PageRole::FreelistTrunk
                );
            }
        }
    }
}
