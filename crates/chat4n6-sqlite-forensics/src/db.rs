use crate::btree::walk_table_btree;
use crate::header::{is_sqlite_header, DbHeader};
use crate::record::RecoveredRecord;
use anyhow::{bail, Result};
use chat4n6_plugin_api::EvidenceSource;
use std::collections::HashMap;

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

    fn traverse_btree(&self, root_page: u32, table: &str, records: &mut Vec<RecoveredRecord>) {
        walk_table_btree(
            self.data,
            self.header.page_size,
            root_page,
            table,
            EvidenceSource::Live,
            records,
        );
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
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
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
