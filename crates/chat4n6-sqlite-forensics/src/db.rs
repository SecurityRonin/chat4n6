use anyhow::{bail, Result};
use crate::btree::parse_table_leaf_page;
use crate::header::{DbHeader, is_sqlite_header};
use crate::page::PageType;
use crate::record::RecoveredRecord;
use std::collections::{HashMap, HashSet};

pub struct ForensicEngine<'a> {
    data: &'a [u8],
    header: DbHeader,
}

impl<'a> ForensicEngine<'a> {
    pub fn new(data: &'a [u8], _timezone_offset: Option<i32>) -> Result<Self> {
        if !is_sqlite_header(data) {
            bail!("not a SQLite database");
        }
        let header = DbHeader::parse(data).ok_or_else(|| anyhow::anyhow!("invalid DB header"))?;
        Ok(Self { data, header })
    }

    /// Layer 1: traverse B-tree and recover all live records.
    pub fn recover_layer1(&self) -> Result<Vec<RecoveredRecord>> {
        let mut records = Vec::new();

        // Build table name → root page mapping from sqlite_master
        let table_roots = self.read_sqlite_master()?;

        for (table_name, root_page) in &table_roots {
            self.traverse_btree(*root_page, table_name, &mut records);
        }

        Ok(records)
    }

    /// Return the full page slice (from byte 0 of the page) and the B-tree header
    /// offset within that slice. Cell offsets in the pointer array are always
    /// relative to byte 0 of the page slice.
    ///
    /// For page 1: the SQLite file header occupies the first 100 bytes of the file
    /// (which is the first 100 bytes of page 1). The B-tree header starts at byte 100.
    fn page_data(&self, page_number: u32) -> Option<(&[u8], usize)> {
        if page_number == 0 {
            return None;
        }
        let page_size = self.header.page_size as usize;
        let page_start = (page_number as usize - 1) * page_size;
        let page_end = page_number as usize * page_size;
        let slice = self.data.get(page_start..page_end)?;
        // B-tree header offset: 100 bytes into page 1 (SQLite file header), 0 elsewhere
        let bhdr = if page_number == 1 { 100 } else { 0 };
        Some((slice, bhdr))
    }

    fn traverse_btree(&self, root_page: u32, table: &str, records: &mut Vec<RecoveredRecord>) {
        let mut stack = vec![root_page];
        let mut visited: HashSet<u32> = HashSet::new();
        while let Some(page_num) = stack.pop() {
            if !visited.insert(page_num) {
                continue; // cycle guard: skip already-visited pages
            }
            let Some((page_data, bhdr)) = self.page_data(page_num) else {
                continue;
            };
            if page_data.len() <= bhdr {
                continue;
            }

            match PageType::from_byte(page_data[bhdr]) {
                Some(PageType::TableLeaf) => {
                    let page_records = parse_table_leaf_page(
                        page_data,
                        bhdr,
                        page_num,
                        self.header.page_size,
                        table,
                    );
                    records.extend(page_records);
                }
                Some(PageType::TableInterior) => {
                    // Interior B-tree page header is 12 bytes (4 extra for right-most child ptr).
                    // Layout from bhdr:
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
                    // Right-most child pointer
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
                    // Cell pointer array starts at bhdr + 12 for interior pages
                    let ptr_array_start = bhdr + 12;
                    for i in 0..cell_count {
                        let ptr_off = ptr_array_start + i * 2;
                        if ptr_off + 2 > page_data.len() {
                            break;
                        }
                        // Cell offset relative to byte 0 of page
                        let cell_off = u16::from_be_bytes([
                            page_data[ptr_off],
                            page_data[ptr_off + 1],
                        ]) as usize;
                        if cell_off + 4 > page_data.len() {
                            continue;
                        }
                        // Left child pointer = first 4 bytes of cell
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

    /// Read sqlite_master (page 1) to get table name → root page mappings.
    fn read_sqlite_master(&self) -> Result<HashMap<String, u32>> {
        let mut tables = HashMap::new();
        let mut temp_records = Vec::new();
        // sqlite_master is always rooted at page 1
        self.traverse_btree(1, "sqlite_master", &mut temp_records);

        for record in temp_records {
            // sqlite_master columns: type, name, tbl_name, rootpage, sql
            if record.values.len() < 5 {
                continue;
            }
            use crate::record::SqlValue;
            let obj_type = match &record.values[0] {
                SqlValue::Text(s) => s.as_str(),
                _ => continue,
            };
            if obj_type != "table" {
                continue;
            }
            // col 1 = name (the object's own name — not tbl_name at col 2)
            let name = match &record.values[1] {
                SqlValue::Text(s) => s.clone(),
                _ => continue,
            };
            let root_page = match &record.values[3] {
                SqlValue::Int(n) => *n as u32,
                _ => continue,
            };
            if root_page > 0 {
                tables.insert(name, root_page);
            }
        }

        Ok(tables)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SqlValue;

    fn create_test_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER);
             INSERT INTO messages VALUES (1, 'hello world', 1710000000000);
             INSERT INTO messages VALUES (2, 'foo bar', 1710000001000);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_layer1_reads_live_records() {
        let db_bytes = create_test_db();
        let engine = ForensicEngine::new(&db_bytes, None).unwrap();
        let results = engine.recover_layer1().unwrap();
        let msgs: Vec<_> = results.iter().filter(|r| r.table == "messages").collect();
        assert_eq!(msgs.len(), 2);
        assert!(msgs
            .iter()
            .any(|r| r.values.get(1) == Some(&SqlValue::Text("hello world".into()))));
    }

    #[test]
    fn test_layer1_rejects_non_sqlite() {
        assert!(ForensicEngine::new(b"not a database", None).is_err());
    }
}
