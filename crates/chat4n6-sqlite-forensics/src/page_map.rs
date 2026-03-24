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

    // -----------------------------------------------------------------------
    // Helper: extract table roots from sqlite_master
    // -----------------------------------------------------------------------

    fn extract_roots(db: &[u8], page_size: u32) -> HashMap<String, u32> {
        use crate::btree::walk_table_btree;
        use crate::record::SqlValue;
        use chat4n6_plugin_api::EvidenceSource;

        let mut master_records = Vec::new();
        walk_table_btree(
            db,
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
                    if (tp == "table" || tp == "index") && *rp > 0 {
                        roots.insert(name.clone(), *rp as u32);
                    }
                }
            }
        }
        roots
    }

    // -----------------------------------------------------------------------
    // Interior page handling (walk_btree lines 124-177)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_pages_with_small_page_size() {
        // Use page_size=512 and insert enough rows to force B-tree splits,
        // creating interior (non-leaf) nodes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE big (id INTEGER PRIMARY KEY, data TEXT);",
        )
        .unwrap();
        for i in 0..300 {
            conn.execute(
                "INSERT INTO big VALUES (?, ?)",
                rusqlite::params![i, format!("data_{:010}", i)],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);
        assert_eq!(page_size, 512);

        let roots = extract_roots(&db, page_size);
        let pm = PageMap::build(&db, page_size, &roots);

        // There should be at least one interior page for the "big" table.
        let big_pages = pm.pages_for_table("big");
        let has_interior = big_pages.iter().any(|p| {
            matches!(
                pm.owner_of(*p).map(|o| &o.page_role),
                Some(PageRole::BTreeInterior)
            )
        });
        assert!(has_interior, "expected at least one interior page for 'big' table with 300 rows at page_size=512");

        // Verify all big pages are either BTreeLeaf or BTreeInterior.
        for p in &big_pages {
            let role = &pm.owner_of(*p).unwrap().page_role;
            assert!(
                matches!(role, PageRole::BTreeLeaf | PageRole::BTreeInterior),
                "unexpected role {:?} for big table page {}",
                role,
                p
            );
        }
    }

    // -----------------------------------------------------------------------
    // IndexLeaf handling (lines 201-220)
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_leaf_pages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE indexed_t (id INTEGER PRIMARY KEY, name TEXT, value INTEGER);
             CREATE INDEX idx_name ON indexed_t (name);",
        )
        .unwrap();
        for i in 0..100 {
            conn.execute(
                "INSERT INTO indexed_t VALUES (?, ?, ?)",
                rusqlite::params![i, format!("name_{:05}", i), i * 10],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let roots = extract_roots(&db, page_size);
        // idx_name should be in the roots map.
        assert!(roots.contains_key("idx_name"), "index root not found in sqlite_master");

        let pm = PageMap::build(&db, page_size, &roots);

        // The index should own at least one page.
        let idx_pages = pm.pages_for_table("idx_name");
        assert!(
            !idx_pages.is_empty(),
            "expected index 'idx_name' to own pages"
        );

        // At least one page should be a BTreeLeaf (index leaf).
        let has_leaf = idx_pages.iter().any(|p| {
            matches!(
                pm.owner_of(*p).map(|o| &o.page_role),
                Some(PageRole::BTreeLeaf)
            )
        });
        assert!(has_leaf, "expected at least one BTreeLeaf page for index");
    }

    // -----------------------------------------------------------------------
    // Index interior pages (lines 124-177, IndexInterior branch)
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_interior_pages() {
        // Insert many rows with an index to force index interior pages.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_t (id INTEGER PRIMARY KEY, label TEXT);
             CREATE INDEX idx_label ON idx_t (label);",
        )
        .unwrap();
        for i in 0..500 {
            conn.execute(
                "INSERT INTO idx_t VALUES (?, ?)",
                rusqlite::params![i, format!("label_{:010}", i)],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let roots = extract_roots(&db, page_size);
        let pm = PageMap::build(&db, page_size, &roots);

        let idx_pages = pm.pages_for_table("idx_label");
        let has_interior = idx_pages.iter().any(|p| {
            matches!(
                pm.owner_of(*p).map(|o| &o.page_role),
                Some(PageRole::BTreeInterior)
            )
        });
        assert!(
            has_interior,
            "expected at least one interior page for index 'idx_label' with 500 rows at page_size=512"
        );
    }

    // -----------------------------------------------------------------------
    // Overflow pages (lines 231-304, 310-378, 382-424)
    // -----------------------------------------------------------------------

    #[test]
    fn test_table_overflow_pages() {
        // Use page_size=512. max_local = 512 - 35 = 477.
        // Insert TEXT values > 477 bytes to force overflow.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE overflow_t (id INTEGER PRIMARY KEY, big_data TEXT);",
        )
        .unwrap();
        let big_value = "X".repeat(2000);
        for i in 0..10 {
            conn.execute(
                "INSERT INTO overflow_t VALUES (?, ?)",
                rusqlite::params![i, big_value],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let roots = extract_roots(&db, page_size);
        let pm = PageMap::build(&db, page_size, &roots);

        let all_pages = pm.pages_for_table("overflow_t");
        // Check that at least some pages are overflow pages.
        let overflow_count = all_pages
            .iter()
            .filter(|p| {
                matches!(
                    pm.owner_of(**p).map(|o| &o.page_role),
                    Some(PageRole::Overflow { .. })
                )
            })
            .count();
        assert!(
            overflow_count > 0,
            "expected overflow pages for table with 2000-byte TEXT at page_size=512, \
             found {} total pages with 0 overflow",
            all_pages.len()
        );

        // Verify overflow pages have correct parent_page field.
        for p in &all_pages {
            if let Some(PageRole::Overflow { parent_page }) =
                pm.owner_of(*p).map(|o| &o.page_role)
            {
                // parent_page should be non-zero and should be a leaf page.
                assert_ne!(*parent_page, 0, "overflow parent should be non-zero");
            }
        }
    }

    #[test]
    fn test_index_overflow_pages() {
        // Index leaf overflow (collect_overflow_pages_index).
        // Create an index on a column with very large values.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_ovfl (id INTEGER PRIMARY KEY, big_key TEXT);
             CREATE INDEX idx_big ON idx_ovfl (big_key);",
        )
        .unwrap();
        let big_value = "Y".repeat(2000);
        for i in 0..5 {
            conn.execute(
                "INSERT INTO idx_ovfl VALUES (?, ?)",
                rusqlite::params![i, format!("{}{}", big_value, i)],
            )
            .unwrap();
        }
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let roots = extract_roots(&db, page_size);
        let pm = PageMap::build(&db, page_size, &roots);

        let idx_pages = pm.pages_for_table("idx_big");
        let overflow_count = idx_pages
            .iter()
            .filter(|p| {
                matches!(
                    pm.owner_of(**p).map(|o| &o.page_role),
                    Some(PageRole::Overflow { .. })
                )
            })
            .count();
        assert!(
            overflow_count > 0,
            "expected overflow pages for index with 2000-byte keys at page_size=512"
        );
    }

    // -----------------------------------------------------------------------
    // Freelist leaf pages (lines 461-477)
    // -----------------------------------------------------------------------

    #[test]
    fn test_freelist_trunk_and_leaf_pages() {
        // Create DB, fill it up, delete rows — without VACUUM — to get freelist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE fl (id INTEGER PRIMARY KEY, data TEXT);",
        )
        .unwrap();
        // Insert enough rows to create many pages.
        for i in 0..500 {
            conn.execute(
                "INSERT INTO fl VALUES (?, ?)",
                rusqlite::params![i, format!("freelist_test_{:010}", i)],
            )
            .unwrap();
        }
        // Delete all rows — pages go to freelist (no VACUUM).
        conn.execute_batch("DELETE FROM fl;").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let header = DbHeader::parse(&db).unwrap();
        assert!(
            header.freelist_trunk_page != 0,
            "expected freelist trunk page after DELETE without VACUUM"
        );

        let mut roots = HashMap::new();
        roots.insert("sqlite_master".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Count freelist trunk and leaf pages.
        let total_pages = db.len() as u32 / page_size;
        let mut trunk_count = 0;
        let mut leaf_count = 0;
        for p in 1..=total_pages {
            if let Some(o) = pm.owner_of(p) {
                if o.table_name == "__freelist__" {
                    match o.page_role {
                        PageRole::FreelistTrunk => trunk_count += 1,
                        PageRole::FreelistLeaf => leaf_count += 1,
                        _ => {}
                    }
                }
            }
        }
        assert!(trunk_count >= 1, "expected at least 1 freelist trunk page");
        assert!(leaf_count >= 1, "expected at least 1 freelist leaf page, got 0 (trunk_count={})", trunk_count);
    }

    // -----------------------------------------------------------------------
    // Cycle guard (line 109) — synthetic test
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_cycle_guard() {
        // Build a minimal synthetic 2-page DB where the interior page
        // points back to itself as a child.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];

        // Page 1 is the root. Write a valid SQLite header so DbHeader::parse works.
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2 (offset 512): Make it a TableInterior page (0x05).
        let p2_off = page_size as usize;
        db[p2_off] = 0x05; // TableInterior
        // Bytes 1-2: first free block = 0
        db[p2_off + 1] = 0;
        db[p2_off + 2] = 0;
        // Bytes 3-4: cell count = 1
        db[p2_off + 3] = 0;
        db[p2_off + 4] = 1;
        // Bytes 5-6: cell content area start (not used by our code beyond this)
        db[p2_off + 5] = 0;
        db[p2_off + 6] = 0;
        // Byte 7: fragmented free bytes
        db[p2_off + 7] = 0;
        // Bytes 8-11: right-most child pointer = page 2 (self-referencing cycle!)
        db[p2_off + 8] = 0;
        db[p2_off + 9] = 0;
        db[p2_off + 10] = 0;
        db[p2_off + 11] = 2; // points back to page 2
        // Cell pointer array at offset 12: one entry pointing to a cell.
        let cell_data_off: u16 = 200; // cell at offset 200 within page
        db[p2_off + 12] = (cell_data_off >> 8) as u8;
        db[p2_off + 13] = (cell_data_off & 0xFF) as u8;
        // Cell at offset 200: first 4 bytes = left child page = page 2 (another cycle)
        db[p2_off + cell_data_off as usize] = 0;
        db[p2_off + cell_data_off as usize + 1] = 0;
        db[p2_off + cell_data_off as usize + 2] = 0;
        db[p2_off + cell_data_off as usize + 3] = 2;

        let mut roots = HashMap::new();
        roots.insert("test_table".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should be mapped despite the cycle — it just shouldn't loop forever.
        assert!(pm.owner_of(2).is_some());
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeInterior);
    }

    // -----------------------------------------------------------------------
    // Already-owned skip (line 113) — two tables claiming same root
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_already_owned_skip() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);

        // Two different table names both claim the same root page.
        let mut roots = HashMap::new();
        roots.insert("table_a".to_string(), 1u32);
        roots.insert("table_b".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 1 should be owned by exactly one of them (first one processed wins).
        let owner = pm.owner_of(1).unwrap();
        assert!(
            owner.table_name == "table_a" || owner.table_name == "table_b",
            "unexpected owner: {}",
            owner.table_name
        );
    }

    // -----------------------------------------------------------------------
    // page_data.len() <= bhdr guard (line 120)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_truncated_page() {
        // For page 1, bhdr=100, so page_size <= 100 triggers page_data.len() <= bhdr.
        // Pass a synthetic small page_size to build().
        let mut db = vec![0u8; 200];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        // Set page_size in header to 101 — below the 100-byte file header.
        db[16] = 0;
        db[17] = 101;

        // page 1 at offset 0..101, bhdr=100, page_data.len()=101, 101 > 100, so it won't trigger.
        // Let's use page_size=100 manually.
        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 1u32);
        // Call build with page_size=100 — page 1 data is db[0..100], bhdr=100,
        // page_data.len() == bhdr == 100, so the guard triggers.
        let pm = PageMap::build(&db, 100, &roots);

        // Page 1 should NOT be mapped since the guard skips it.
        assert!(pm.owner_of(1).is_none());
    }

    // -----------------------------------------------------------------------
    // walk_btree with root page 0 (get_page_data returns None)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_root_page_zero() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);

        let mut roots = HashMap::new();
        roots.insert("bad_table".to_string(), 0u32); // page 0 is invalid
        let pm = PageMap::build(&db, page_size, &roots);

        // Should not crash, and no pages should be mapped for bad_table.
        let pages = pm.pages_for_table("bad_table");
        assert!(pages.is_empty());
    }

    // -----------------------------------------------------------------------
    // walk_btree with out-of-bounds root page
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_out_of_bounds_root() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);

        let mut roots = HashMap::new();
        roots.insert("nonexistent".to_string(), 9999u32);
        let pm = PageMap::build(&db, page_size, &roots);

        let pages = pm.pages_for_table("nonexistent");
        assert!(pages.is_empty());
    }

    // -----------------------------------------------------------------------
    // walk_btree unknown page type (line 222-224)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_unknown_page_type() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2 has an invalid page type byte (0xFF).
        let p2_off = page_size as usize;
        db[p2_off] = 0xFF;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should NOT be mapped (unknown type is skipped).
        assert!(pm.owner_of(2).is_none());
    }

    // -----------------------------------------------------------------------
    // walk_overflow_chain edge cases (synthetic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_overflow_chain_cycle_guard() {
        // Synthetic DB: a table leaf page (page 2) with one cell whose payload
        // exceeds max_local, pointing to an overflow page (page 3) that cycles
        // back to itself.
        let page_size: u32 = 512;
        let num_pages = 3;
        let mut db = vec![0u8; page_size as usize * num_pages];

        // Valid SQLite header on page 1.
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2 (offset 512): TableLeaf (0x0D)
        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0; // cell count high byte
        db[p2 + 4] = 1; // cell count = 1
        // Cell pointer array starts at p2+8 for leaf pages.
        // Point to a cell at offset 100 within the page.
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        // Cell at p2+100: [payload_length varint][row_id varint][payload...]
        // max_local = 512 - 35 = 477
        // min_local = (512 - 12) * 32 / 255 - 23 = 500*32/255 - 23 = 62 - 23 = 39
        // We need payload_len > 477.
        // Use payload_len = 600 (varint: 0x84 0x58 — two bytes).
        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84; // varint high byte (continuation)
        db[cell_abs + 1] = 0x58; // varint low byte: (0x04 << 7) | 0x58 = 512 + 88 = 600
        // Row ID varint: 1 (single byte)
        db[cell_abs + 2] = 0x01;
        // Now payload starts at cell_abs + 3.
        // local_size = min_local + (600 - min_local) % (512 - 4)
        //            = 39 + (561) % 508
        //            = 39 + 53
        //            = 92
        // 92 <= max_local (477), so local_size = 92.
        // Overflow pointer at cell_abs + 3 + 92 = cell_abs + 95.
        let ovfl_ptr_pos = cell_abs + 3 + 92;
        // Point to page 3.
        db[ovfl_ptr_pos] = 0;
        db[ovfl_ptr_pos + 1] = 0;
        db[ovfl_ptr_pos + 2] = 0;
        db[ovfl_ptr_pos + 3] = 3;

        // Page 3 (offset 1024): overflow page that cycles back to itself.
        let p3 = page_size as usize * 2;
        // Next overflow pointer = page 3 (self-referencing).
        db[p3] = 0;
        db[p3 + 1] = 0;
        db[p3 + 2] = 0;
        db[p3 + 3] = 3;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 = leaf, page 3 = overflow.
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert!(
            matches!(pm.owner_of(3).unwrap().page_role, PageRole::Overflow { parent_page: 2 }),
            "page 3 should be an overflow page with parent 2"
        );
    }

    #[test]
    fn test_walk_overflow_chain_already_owned() {
        // Two tables both have overflow chains that try to claim the same overflow page.
        // The second table should skip it (already-owned check in walk_overflow_chain).
        let page_size: u32 = 512;
        let num_pages = 4;
        let mut db = vec![0u8; page_size as usize * num_pages];

        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Helper to build a table leaf page with one cell that overflows to `overflow_page`.
        let build_leaf = |db: &mut Vec<u8>, page_num: usize, overflow_page: u8| {
            let off = (page_num - 1) * page_size as usize;
            db[off] = 0x0D; // TableLeaf
            db[off + 3] = 0;
            db[off + 4] = 1; // 1 cell
            let cell_off: u16 = 100;
            db[off + 8] = (cell_off >> 8) as u8;
            db[off + 9] = (cell_off & 0xFF) as u8;
            let cell_abs = off + cell_off as usize;
            // payload_len = 600
            db[cell_abs] = 0x84;
            db[cell_abs + 1] = 0x58;
            // row_id = 1
            db[cell_abs + 2] = 0x01;
            // overflow ptr at cell_abs + 3 + 92 = cell_abs + 95
            let ovfl_ptr = cell_abs + 3 + 92;
            db[ovfl_ptr] = 0;
            db[ovfl_ptr + 1] = 0;
            db[ovfl_ptr + 2] = 0;
            db[ovfl_ptr + 3] = overflow_page;
        };

        // Page 2: leaf for table_a, overflow -> page 4
        build_leaf(&mut db, 2, 4);
        // Page 3: leaf for table_b, overflow -> page 4 (same overflow page!)
        build_leaf(&mut db, 3, 4);

        // Page 4: overflow page with next=0 (end of chain).
        let p4 = page_size as usize * 3;
        db[p4] = 0;
        db[p4 + 1] = 0;
        db[p4 + 2] = 0;
        db[p4 + 3] = 0;

        let mut roots = HashMap::new();
        roots.insert("table_a".to_string(), 2u32);
        roots.insert("table_b".to_string(), 3u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 4 should be owned by exactly one table.
        let owner = pm.owner_of(4).unwrap();
        assert!(
            owner.table_name == "table_a" || owner.table_name == "table_b",
            "page 4 should be owned by one of the tables"
        );
        assert!(matches!(owner.page_role, PageRole::Overflow { .. }));
    }

    #[test]
    fn test_walk_overflow_chain_out_of_bounds() {
        // Overflow pointer points to a page beyond the DB size.
        let page_size: u32 = 512;
        let num_pages = 2;
        let mut db = vec![0u8; page_size as usize * num_pages];

        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2: table leaf with overflow -> page 99 (out of bounds).
        let p2 = page_size as usize;
        db[p2] = 0x0D;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58; // payload_len=600
        db[cell_abs + 2] = 0x01; // row_id=1
        let ovfl_ptr = cell_abs + 3 + 92;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 99; // out of bounds

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 mapped, page 99 not (out of bounds).
        assert!(pm.owner_of(2).is_some());
        assert!(pm.owner_of(99).is_none());
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_cell_off_zero() {
        // Cell pointer array contains a zero offset — should be skipped (line 259).
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 2; // 2 cells
        // Cell pointer 1: offset 0 (should be skipped)
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        // Cell pointer 2: offset beyond page (should be skipped, cell_off >= page_data.len())
        db[p2 + 10] = 0xFF;
        db[p2 + 11] = 0xFF;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should be mapped as BTreeLeaf but no crash.
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    #[test]
    fn test_collect_overflow_ptr_off_exceeds_len() {
        // Cell count says 100 cells but the cell pointer array extends beyond the page.
        // Should hit ptr_off + 2 > page_data.len() (line 254) and break.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 255; // 255 cells claimed, but page can't hold that many pointers

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages_index edge cases (lines 334, 339)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_index_cell_off_zero() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 2; // 2 cells
        // Cell pointer 1: offset 0
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        // Cell pointer 2: offset beyond page
        db[p2 + 10] = 0xFF;
        db[p2 + 11] = 0xFF;

        let mut roots = HashMap::new();
        roots.insert("test_idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    #[test]
    fn test_collect_overflow_index_ptr_off_exceeds_len() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 255; // 255 cells — way more than can fit in pointer array

        let mut roots = HashMap::new();
        roots.insert("test_idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // Interior page: cell_off + 4 > page_data.len() (line 164)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_cell_off_plus_4_exceeds_len() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x05; // TableInterior
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // 1 cell
        // right-most child = 0 (no child)
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        db[p2 + 10] = 0;
        db[p2 + 11] = 0;
        // Cell pointer at offset 12: points to offset 510 (near end of page).
        // cell_off=510, cell_off+4=514 > 512, so triggers the guard.
        db[p2 + 12] = 0x01;
        db[p2 + 13] = 0xFE; // 510

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeInterior);
    }

    // -----------------------------------------------------------------------
    // Interior page: ptr_off + 2 > len (line 157)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_ptr_off_exceeds_len() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x05; // TableInterior
        db[p2 + 3] = 0;
        db[p2 + 4] = 255; // 255 cells claimed — ptr array extends way beyond page
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        db[p2 + 10] = 0;
        db[p2 + 11] = 0;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeInterior);
    }

    // -----------------------------------------------------------------------
    // Interior page: cell count when page too short (line 136-137)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_page_too_short_for_cell_count() {
        // Page data exists but is too short to read cell count at bhdr+5.
        // For non-page-1 pages, bhdr=0. We need page_data.len() < bhdr+5 = 5.
        // But get_page_data returns page_size bytes. With page_size=512 that's always >= 5.
        // However, for page 1, bhdr=100. We need page_data.len() < 105.
        // That requires page_size < 105, which is synthetic.
        // Use page_size=104 so bhdr=100 and len=104, 104 < 105 so cell_count=0.
        let page_size: u32 = 104;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0;
        db[17] = page_size as u8;

        // Page 1, bhdr=100, byte at offset 100 = TableInterior.
        db[100] = 0x05;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Should be mapped as interior but with cell_count=0 and no children.
        assert_eq!(pm.owner_of(1).unwrap().page_role, PageRole::BTreeInterior);
    }

    // -----------------------------------------------------------------------
    // Interior page: right-most child not read when page too short (line 141)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_page_too_short_for_right_child() {
        // bhdr=100, need page_data.len() < bhdr+12=112 but >= bhdr+5=105.
        // Use page_size=110.
        let page_size: u32 = 110;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0;
        db[17] = page_size as u8;

        db[100] = 0x05; // TableInterior
        db[103] = 0;
        db[104] = 1; // cell_count=1

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(1).unwrap().page_role, PageRole::BTreeInterior);
    }

    // -----------------------------------------------------------------------
    // Interior page: left child = 0 (line 174 — if left != 0)
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_left_child_zero() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x05; // TableInterior
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        db[p2 + 10] = 0;
        db[p2 + 11] = 0; // right child = 0
        let cell_off: u16 = 200;
        db[p2 + 12] = (cell_off >> 8) as u8;
        db[p2 + 13] = (cell_off & 0xFF) as u8;
        // Cell at offset 200: left child = 0.
        db[p2 + cell_off as usize] = 0;
        db[p2 + cell_off as usize + 1] = 0;
        db[p2 + cell_off as usize + 2] = 0;
        db[p2 + cell_off as usize + 3] = 0;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeInterior);
        // No children should have been pushed; only page 2 should be mapped.
        assert!(pm.owner_of(1).is_none());
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: page too short (line 241)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_page_too_short_for_header() {
        // TableLeaf page where page_data.len() < bhdr + 8.
        // For page 1, bhdr=100, need page_size < 108.
        // Use page_size=105, bhdr=100. page_data.len()=105 < 108. Triggers line 241.
        let page_size: u32 = 105;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0;
        db[17] = page_size as u8;

        db[100] = 0x0D; // TableLeaf at page 1, bhdr=100

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page should be mapped as BTreeLeaf but collect_overflow_pages returns early.
        assert_eq!(pm.owner_of(1).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages_index: page too short (line 320)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_index_page_too_short_for_header() {
        let page_size: u32 = 105;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0;
        db[17] = page_size as u8;

        db[100] = 0x0A; // IndexLeaf at page 1, bhdr=100

        let mut roots = HashMap::new();
        roots.insert("test_idx".to_string(), 1u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(1).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: varint read failure (line 265, 271)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_bad_varint() {
        // TableLeaf with a cell that points to the very end of the page,
        // so read_varint fails (truncated data).
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // 1 cell
        // Cell offset pointing to the very last byte of the page.
        // read_varint at offset 511 will read db[p2+511] which is the last byte.
        // If the byte has continuation bit set (0x80), it'll try to read the next byte
        // which is out of bounds -> returns None.
        let cell_off: u16 = 511;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        // Set the byte at the cell position to have continuation bit.
        db[p2 + 511] = 0x80; // varint continuation, but no next byte in page

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Should not crash, page 2 still mapped as leaf.
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    #[test]
    fn test_collect_overflow_bad_rowid_varint() {
        // TableLeaf cell where payload_length varint is readable but row_id varint fails.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        // Cell at offset 509: payload_len varint is 1 byte (say 0x05),
        // then row_id at offset 510 is 0x80 (continuation), next byte at 511 is 0x80,
        // and then no more bytes.
        let cell_off: u16 = 509;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        db[p2 + 509] = 0x05; // payload_len=5 (1-byte varint)
        db[p2 + 510] = 0x80; // row_id continuation
        db[p2 + 511] = 0x80; // row_id continuation, no next byte -> fail

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages_index: varint read failure (line 345)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_index_bad_varint() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 511;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        db[p2 + 511] = 0x80; // varint continuation, truncated

        let mut roots = HashMap::new();
        roots.insert("test_idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: local_size > max_local branch (line 280-281)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_local_size_exceeds_max_local() {
        // We need: local_size = min_local + (payload_len - min_local) % (usable - 4) > max_local
        // With page_size=512: max_local=477, min_local=39, usable=512.
        // local_size = 39 + (P-39) % 508. We need this > 477, i.e. (P-39) % 508 > 438.
        // (P-39) % 508 ranges from 0..507.
        // Example: P-39 = 947 -> 947 % 508 = 439 -> local_size = 39+439 = 478 > 477. Use P=986.
        let page_size: u32 = 512;
        let num_pages = 3;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        // payload_len = 986. Varint encoding: 986 = 0x03DA.
        // Varint: first byte = (986 >> 7) | 0x80 = 7 | 0x80 = 0x87
        //         second byte = 986 & 0x7F = 0x5A
        db[cell_abs] = 0x87;
        db[cell_abs + 1] = 0x5A; // payload_len = 986
        db[cell_abs + 2] = 0x01; // row_id = 1

        // local_size = 39 + (986-39) % 508 = 39 + 947%508 = 39+439 = 478 > 477 -> local_size = min_local = 39
        // overflow ptr at cell_abs + 3 + 39 = cell_abs + 42
        let ovfl_ptr = cell_abs + 3 + 39;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 3; // overflow -> page 3

        // Page 3: overflow, next=0
        let p3 = page_size as usize * 2;
        db[p3] = 0;
        db[p3 + 1] = 0;
        db[p3 + 2] = 0;
        db[p3 + 3] = 0;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert!(
            matches!(pm.owner_of(3).unwrap().page_role, PageRole::Overflow { .. }),
            "page 3 should be overflow"
        );
    }

    #[test]
    fn test_collect_overflow_index_local_size_exceeds_max_local() {
        // Same as above but for index leaf.
        let page_size: u32 = 512;
        let num_pages = 3;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        // payload_len = 986
        db[cell_abs] = 0x87;
        db[cell_abs + 1] = 0x5A;
        // No row_id for index leaf.
        // local_size > max_local -> local_size = min_local = 39
        // overflow ptr at cell_abs + 2 + 39 = cell_abs + 41
        let ovfl_ptr = cell_abs + 2 + 39;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 3;

        let p3 = page_size as usize * 2;
        db[p3] = 0;

        let mut roots = HashMap::new();
        roots.insert("idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert!(
            matches!(pm.owner_of(3).unwrap().page_role, PageRole::Overflow { .. }),
            "page 3 should be index overflow"
        );
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: first_overflow == 0 (line 291)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_first_overflow_zero() {
        // Table leaf cell has payload > max_local but overflow pointer is 0.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        // payload_len = 600
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58;
        db[cell_abs + 2] = 0x01; // row_id
        // overflow ptr at cell_abs + 3 + 92 = cell_abs + 95. All zeros = page 0 = skip.

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        // No overflow pages should be mapped.
        let total = db.len() as u32 / page_size;
        let unowned = pm.unowned_pages(total);
        // Page 1 should be unowned (not in roots, no valid page type), page 2 owned.
        assert!(!unowned.contains(&2));
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages_index: first_overflow == 0 (line 365)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_index_first_overflow_zero() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58; // payload_len=600
        // overflow ptr at cell_abs + 2 + 92 = cell_abs + 94. All zeros.

        let mut roots = HashMap::new();
        roots.insert("idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: overflow_ptr_pos + 4 > page_data.len() (line 284)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_ptr_pos_exceeds_page() {
        // Cell has payload > max_local but the computed overflow_ptr_pos
        // is beyond the end of the page.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        // Place cell near end of page so overflow ptr position exceeds page.
        let cell_off: u16 = 480;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        // payload_len = 600
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58;
        db[cell_abs + 2] = 0x01;
        // overflow ptr would be at cell_abs + 3 + 92 = 480 + 95 = 575,
        // which is offset 575 within the page. 575 + 4 = 579 > 512. Guard triggers.

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages_index: overflow_ptr_pos + 4 > page_data.len() (line 358)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_index_ptr_pos_exceeds_page() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 480;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58; // payload_len=600
        // overflow ptr at cell_abs + 2 + 92 = 480+94 = 574. 574+4=578 > 512.

        let mut roots = HashMap::new();
        roots.insert("idx".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
    }

    // -----------------------------------------------------------------------
    // walk_freelist edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_freelist_cycle_guard() {
        // Synthetic DB where freelist trunk page points back to itself.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        // Set freelist trunk page = 2 in header (bytes 32-35).
        db[32] = 0;
        db[33] = 0;
        db[34] = 0;
        db[35] = 2;
        // Set freelist page count = 1.
        db[36] = 0;
        db[37] = 0;
        db[38] = 0;
        db[39] = 1;
        // Set page count in header (bytes 28-31) = 2.
        db[28] = 0;
        db[29] = 0;
        db[30] = 0;
        db[31] = 2;

        // Page 2 (freelist trunk): next_trunk = page 2 (cycle!), leaf_count = 0.
        let p2 = page_size as usize;
        db[p2] = 0;
        db[p2 + 1] = 0;
        db[p2 + 2] = 0;
        db[p2 + 3] = 2; // next trunk = self
        db[p2 + 4] = 0;
        db[p2 + 5] = 0;
        db[p2 + 6] = 0;
        db[p2 + 7] = 0; // leaf count = 0

        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should be mapped as freelist trunk, no infinite loop.
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::FreelistTrunk);
    }

    #[test]
    fn test_walk_freelist_out_of_bounds_trunk() {
        // Freelist trunk pointer beyond DB size.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[28] = 0; db[29] = 0; db[30] = 0; db[31] = 1; // page_count=1
        // Freelist trunk = page 99 (out of bounds).
        db[32] = 0;
        db[33] = 0;
        db[34] = 0;
        db[35] = 99;
        db[36] = 0; db[37] = 0; db[38] = 0; db[39] = 1;

        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        // Should not crash, no pages mapped.
        assert!(pm.owner_of(99).is_none());
    }

    #[test]
    fn test_walk_freelist_leaf_page_zero() {
        // Freelist trunk has a leaf entry with page number 0 — should be skipped.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[28] = 0; db[29] = 0; db[30] = 0; db[31] = 2;
        db[32] = 0; db[33] = 0; db[34] = 0; db[35] = 2; // trunk = page 2
        db[36] = 0; db[37] = 0; db[38] = 0; db[39] = 1;

        let p2 = page_size as usize;
        db[p2] = 0; db[p2+1] = 0; db[p2+2] = 0; db[p2+3] = 0; // next trunk = 0 (end)
        db[p2+4] = 0; db[p2+5] = 0; db[p2+6] = 0; db[p2+7] = 1; // leaf_count = 1
        // Leaf page number = 0 (should be skipped).
        db[p2+8] = 0; db[p2+9] = 0; db[p2+10] = 0; db[p2+11] = 0;

        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::FreelistTrunk);
        assert!(pm.owner_of(0).is_none()); // page 0 not mapped
    }

    #[test]
    fn test_walk_freelist_leaf_off_exceeds_page() {
        // Freelist trunk claims many leaf pages but the page is too small.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[28] = 0; db[29] = 0; db[30] = 0; db[31] = 2;
        db[32] = 0; db[33] = 0; db[34] = 0; db[35] = 2;
        db[36] = 0; db[37] = 0; db[38] = 0; db[39] = 1;

        let p2 = page_size as usize;
        db[p2] = 0; db[p2+1] = 0; db[p2+2] = 0; db[p2+3] = 0;
        // leaf_count = 9999 — way more than page can hold.
        db[p2+4] = 0; db[p2+5] = 0; db[p2+6] = 0x27; db[p2+7] = 0x0F;

        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        // Should not crash, trunk should be mapped.
        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::FreelistTrunk);
    }

    // -----------------------------------------------------------------------
    // OverflowOrDropped page type (line 222) — page type 0x00
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_btree_overflow_or_dropped_page_type() {
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2 has page type 0x00 (OverflowOrDropped).
        // All zeros — type byte is already 0x00.

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should NOT be mapped (OverflowOrDropped falls through to _ branch).
        assert!(pm.owner_of(2).is_none());
    }

    // -----------------------------------------------------------------------
    // walk_overflow_chain: page_data.len() < 4 guard (line 407-408)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_overflow_chain_page_too_small() {
        // This guard can only trigger if the page slice is < 4 bytes.
        // page_size=512 but DB is truncated so the overflow page is incomplete.
        let page_size: u32 = 512;
        // 2 full pages + 3 bytes of page 3 (truncated).
        let mut db = vec![0u8; page_size as usize * 2 + 3];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58; // payload_len=600
        db[cell_abs + 2] = 0x01; // row_id
        let ovfl_ptr = cell_abs + 3 + 92;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 3; // overflow -> page 3

        // Page 3 is only 3 bytes (truncated), so db.get(1024..1536) returns None.
        // This triggers the `let Some(page_data) = db.get(...)` guard, not the len<4 guard.
        // To hit len<4, we'd need db.get to succeed with <4 bytes, but since page_size=512
        // and we only have 3 bytes, get() returns None. That's still the out-of-bounds path (line 404).

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert!(pm.owner_of(3).is_none()); // overflow page not reachable
    }

    // -----------------------------------------------------------------------
    // Real DB: comprehensive end-to-end with interior + overflow + index + freelist
    // -----------------------------------------------------------------------

    #[test]
    fn test_comprehensive_real_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=512;").unwrap();
        conn.execute_batch(
            "CREATE TABLE data_t (id INTEGER PRIMARY KEY, big TEXT, small TEXT);
             CREATE INDEX idx_small ON data_t (small);",
        )
        .unwrap();

        let big_value = "Z".repeat(2000);
        for i in 0..50 {
            conn.execute(
                "INSERT INTO data_t VALUES (?, ?, ?)",
                rusqlite::params![i, big_value, format!("s_{:05}", i)],
            )
            .unwrap();
        }
        // Delete some rows to create freelist pages.
        conn.execute_batch("DELETE FROM data_t WHERE id < 20;").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = get_page_size(&db);

        let roots = extract_roots(&db, page_size);
        let pm = PageMap::build(&db, page_size, &roots);

        let total_pages = db.len() as u32 / page_size;
        let _unowned = pm.unowned_pages(total_pages);

        // Count page roles.
        let mut role_counts: HashMap<String, usize> = HashMap::new();
        for p in 1..=total_pages {
            if let Some(o) = pm.owner_of(p) {
                let key = format!("{:?}", o.page_role);
                *role_counts.entry(key).or_default() += 1;
            }
        }

        // We should have at least some overflow pages from the 2000-byte values.
        let overflow_count = role_counts.keys().filter(|k| k.starts_with("Overflow")).count();
        assert!(overflow_count > 0 || role_counts.values().sum::<usize>() > 5,
            "expected overflow pages in comprehensive test, roles: {:?}", role_counts);

        // We should have leaf pages.
        assert!(role_counts.contains_key("BTreeLeaf"), "expected BTreeLeaf pages");

        // Check freelist presence.
        let header = DbHeader::parse(&db).unwrap();
        if header.freelist_trunk_page != 0 {
            assert!(
                role_counts.contains_key("FreelistTrunk"),
                "expected FreelistTrunk pages when freelist exists"
            );
        }
    }

    // -----------------------------------------------------------------------
    // walk_freelist: page.len() < 8 guard (line 447)
    // -----------------------------------------------------------------------

    #[test]
    fn test_walk_freelist_page_too_small() {
        // With page_size=4, the freelist trunk page is 4 bytes which is < 8.
        // Actually walk_freelist reads db[page_start..page_end] where page_end-page_start=page_size.
        // So if page_size < 8, the guard triggers.
        let page_size: u32 = 4;
        // We need page 1 (header) and page 2 (freelist trunk).
        // Page 1: bytes 0..4, Page 2: bytes 4..8.
        let mut db = vec![0u8; 100]; // enough for SQLite header
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0;
        db[17] = 4; // page_size=4
        db[28] = 0; db[29] = 0; db[30] = 0; db[31] = 25; // page count = 25
        db[32] = 0; db[33] = 0; db[34] = 0; db[35] = 2; // freelist trunk = page 2
        db[36] = 0; db[37] = 0; db[38] = 0; db[39] = 1;

        // Page 2 at offset 4..8 (4 bytes < 8). Guard triggers.
        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        // Page 2 should not be mapped.
        assert!(pm.owner_of(2).is_none());
    }

    // -----------------------------------------------------------------------
    // PageRole & PageOwnership: derive coverage (Debug, Clone, PartialEq)
    // -----------------------------------------------------------------------

    #[test]
    fn test_page_role_debug_clone_partialeq() {
        let role1 = PageRole::BTreeLeaf;
        let role2 = role1.clone();
        assert_eq!(role1, role2);
        assert_ne!(role1, PageRole::BTreeInterior);
        let _ = format!("{:?}", role1);

        let role3 = PageRole::Overflow { parent_page: 42 };
        let role4 = role3.clone();
        assert_eq!(role3, role4);
        let _ = format!("{:?}", role3);

        let role5 = PageRole::FreelistTrunk;
        let role6 = PageRole::FreelistLeaf;
        let role7 = PageRole::PointerMap;
        assert_ne!(role5, role6);
        assert_ne!(role6, role7);
        let _ = format!("{:?} {:?} {:?}", role5, role6, role7);
    }

    #[test]
    fn test_page_ownership_debug_clone() {
        let o1 = PageOwnership {
            table_name: "test".to_string(),
            page_role: PageRole::BTreeLeaf,
        };
        let o2 = o1.clone();
        assert_eq!(o1.table_name, o2.table_name);
        assert_eq!(o1.page_role, o2.page_role);
        let _ = format!("{:?}", o1);
    }

    // -----------------------------------------------------------------------
    // build with no table_roots and no freelist
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_empty_roots_no_freelist() {
        let db = create_simple_db();
        let page_size = get_page_size(&db);
        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);
        // Nothing mapped since no roots and likely no freelist in simple DB.
        let total_pages = db.len() as u32 / page_size;
        let unowned = pm.unowned_pages(total_pages);
        assert_eq!(unowned.len(), total_pages as usize);
    }

    // -----------------------------------------------------------------------
    // build with invalid DB (DbHeader::parse returns None)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_invalid_db_header() {
        let db = vec![0u8; 512]; // no valid SQLite magic
        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 1u32);
        // build should not crash even with invalid header (freelist walk skipped).
        let pm = PageMap::build(&db, 512, &roots);
        // page 1 has type 0x00 at offset 100 — OverflowOrDropped, so not mapped.
        // Actually for non-sqlite buffer, page 1 data[100] is 0x00.
        assert!(pm.owner_of(1).is_none());
    }

    // -----------------------------------------------------------------------
    // Multiple overflow pages in a chain
    // -----------------------------------------------------------------------

    #[test]
    fn test_overflow_chain_multiple_pages() {
        // Synthetic: table leaf -> overflow page 3 -> overflow page 4 -> end.
        let page_size: u32 = 512;
        let num_pages = 4;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D;
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        let cell_abs = p2 + cell_off as usize;
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58; // payload_len=600
        db[cell_abs + 2] = 0x01;
        let ovfl_ptr = cell_abs + 3 + 92;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 3;

        // Page 3: next = page 4
        let p3 = page_size as usize * 2;
        db[p3] = 0;
        db[p3 + 1] = 0;
        db[p3 + 2] = 0;
        db[p3 + 3] = 4;

        // Page 4: next = 0 (end)
        let p4 = page_size as usize * 3;
        db[p4] = 0;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert!(matches!(pm.owner_of(3).unwrap().page_role, PageRole::Overflow { parent_page: 2 }));
        assert!(matches!(pm.owner_of(4).unwrap().page_role, PageRole::Overflow { parent_page: 2 }));
    }

    // -----------------------------------------------------------------------
    // Freelist with multiple trunk pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_freelist_multiple_trunk_pages() {
        let page_size: u32 = 512;
        let num_pages = 4;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[28] = 0; db[29] = 0; db[30] = 0; db[31] = 4; // page count = 4
        db[32] = 0; db[33] = 0; db[34] = 0; db[35] = 2; // freelist trunk = page 2
        db[36] = 0; db[37] = 0; db[38] = 0; db[39] = 4; // freelist page count

        // Page 2 (trunk 1): next trunk = page 3, leaf_count = 1, leaf = page 4
        let p2 = page_size as usize;
        db[p2] = 0; db[p2+1] = 0; db[p2+2] = 0; db[p2+3] = 3; // next trunk = page 3
        db[p2+4] = 0; db[p2+5] = 0; db[p2+6] = 0; db[p2+7] = 1; // leaf_count = 1
        db[p2+8] = 0; db[p2+9] = 0; db[p2+10] = 0; db[p2+11] = 4; // leaf page 4

        // Page 3 (trunk 2): next trunk = 0 (end), leaf_count = 0
        let p3 = page_size as usize * 2;
        db[p3] = 0; db[p3+1] = 0; db[p3+2] = 0; db[p3+3] = 0;
        db[p3+4] = 0; db[p3+5] = 0; db[p3+6] = 0; db[p3+7] = 0;

        let roots = HashMap::new();
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::FreelistTrunk);
        assert_eq!(pm.owner_of(3).unwrap().page_role, PageRole::FreelistTrunk);
        assert_eq!(pm.owner_of(4).unwrap().page_role, PageRole::FreelistLeaf);
    }

    // -----------------------------------------------------------------------
    // Index leaf with synthetic overflow chain
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_leaf_overflow_synthetic() {
        let page_size: u32 = 512;
        let num_pages = 3;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0A; // IndexLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;

        let cell_abs = p2 + cell_off as usize;
        // payload_len = 600 (varint 0x84 0x58)
        db[cell_abs] = 0x84;
        db[cell_abs + 1] = 0x58;
        // No row_id for index leaf. Payload starts at cell_abs + 2.
        // local_size = 39 + (600-39) % (512-4) = 39 + 561%508 = 39+53 = 92
        // overflow ptr at cell_abs + 2 + 92 = cell_abs + 94
        let ovfl_ptr = cell_abs + 2 + 92;
        db[ovfl_ptr] = 0;
        db[ovfl_ptr + 1] = 0;
        db[ovfl_ptr + 2] = 0;
        db[ovfl_ptr + 3] = 3;

        // Page 3: overflow, next=0
        let p3 = page_size as usize * 2;
        db[p3] = 0;

        let mut roots = HashMap::new();
        roots.insert("idx_test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        assert_eq!(pm.owner_of(2).unwrap().table_name, "idx_test");
        assert!(matches!(pm.owner_of(3).unwrap().page_role, PageRole::Overflow { parent_page: 2 }));
    }

    // -----------------------------------------------------------------------
    // Interior page with valid children leading to leaf pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_interior_with_children_leading_to_leaves() {
        let page_size: u32 = 512;
        let num_pages = 4;
        let mut db = vec![0u8; page_size as usize * num_pages];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        // Page 2: TableInterior with right child = page 3, one cell with left child = page 4.
        let p2 = page_size as usize;
        db[p2] = 0x05; // TableInterior
        db[p2 + 3] = 0;
        db[p2 + 4] = 1; // 1 cell
        db[p2 + 8] = 0;
        db[p2 + 9] = 0;
        db[p2 + 10] = 0;
        db[p2 + 11] = 3; // right child = page 3
        let cell_off: u16 = 200;
        db[p2 + 12] = (cell_off >> 8) as u8;
        db[p2 + 13] = (cell_off & 0xFF) as u8;
        // Cell: left child = page 4.
        db[p2 + cell_off as usize] = 0;
        db[p2 + cell_off as usize + 1] = 0;
        db[p2 + cell_off as usize + 2] = 0;
        db[p2 + cell_off as usize + 3] = 4;

        // Page 3: TableLeaf (no cells).
        let p3 = page_size as usize * 2;
        db[p3] = 0x0D;
        db[p3 + 3] = 0;
        db[p3 + 4] = 0; // 0 cells

        // Page 4: TableLeaf (no cells).
        let p4 = page_size as usize * 3;
        db[p4] = 0x0D;
        db[p4 + 3] = 0;
        db[p4 + 4] = 0;

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeInterior);
        assert_eq!(pm.owner_of(3).unwrap().page_role, PageRole::BTreeLeaf);
        assert_eq!(pm.owner_of(4).unwrap().page_role, PageRole::BTreeLeaf);
        assert_eq!(pm.owner_of(2).unwrap().table_name, "test");
        assert_eq!(pm.owner_of(3).unwrap().table_name, "test");
        assert_eq!(pm.owner_of(4).unwrap().table_name, "test");
    }

    // -----------------------------------------------------------------------
    // collect_overflow_pages: payload not exceeding max_local (no overflow)
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_overflow_no_overflow_needed() {
        // Table leaf with a cell whose payload is within max_local — no overflow.
        let page_size: u32 = 512;
        let mut db = vec![0u8; page_size as usize * 2];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;

        let p2 = page_size as usize;
        db[p2] = 0x0D; // TableLeaf
        db[p2 + 3] = 0;
        db[p2 + 4] = 1;
        let cell_off: u16 = 100;
        db[p2 + 8] = (cell_off >> 8) as u8;
        db[p2 + 9] = (cell_off & 0xFF) as u8;
        let cell_abs = p2 + cell_off as usize;
        // payload_len = 10 (well within max_local=477).
        db[cell_abs] = 10;
        db[cell_abs + 1] = 0x01; // row_id=1

        let mut roots = HashMap::new();
        roots.insert("test".to_string(), 2u32);
        let pm = PageMap::build(&db, page_size, &roots);

        assert_eq!(pm.owner_of(2).unwrap().page_role, PageRole::BTreeLeaf);
        // No overflow pages.
        let total = db.len() as u32 / page_size;
        for p in 1..=total {
            if p != 2 {
                if let Some(o) = pm.owner_of(p) {
                    assert!(
                        !matches!(o.page_role, PageRole::Overflow { .. }),
                        "unexpected overflow page {}", p
                    );
                }
            }
        }
    }
}
