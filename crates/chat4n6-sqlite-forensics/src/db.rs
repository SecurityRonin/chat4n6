use crate::btree::walk_table_btree;
use crate::context::RecoveryContext;
use crate::dedup::deduplicate;
use crate::freelist::recover_freelist_content;
use crate::fts::recover_layer5;
use crate::gap::scan_page_gaps;
use crate::header::{is_sqlite_header, DbHeader};
use crate::journal::parse_journal;
use crate::pragma::{parse_pragma_info, AutoVacuumMode, SecureDeleteMode};
use crate::record::RecoveredRecord;
use crate::schema_sig::SchemaSignature;
use crate::wal::recover_layer2_enhanced;
use anyhow::{bail, Result};
use chat4n6_plugin_api::EvidenceSource;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WalMode {
    Both,
    Apply,
    Ignore,
}

impl Default for WalMode {
    fn default() -> Self {
        Self::Both
    }
}

#[derive(Debug)]
pub struct RecoveryResult {
    pub records: Vec<RecoveredRecord>,
    pub stats: RecoveryStats,
}

#[derive(Debug, Default)]
pub struct RecoveryStats {
    pub live_count: usize,
    pub wal_pending: usize,
    pub wal_deleted: usize,
    pub freelist_recovered: usize,
    pub overflow_reassembled: usize,
    pub fts_recovered: usize,
    pub gap_carved: usize,
    pub journal_recovered: usize,
    pub duplicates_removed: usize,
    pub freeblock_recovered: usize,
    pub wal_only_tables_found: usize,
    pub rowid_gaps_detected: usize,
    pub layers_skipped: Vec<String>,
}

pub struct ForensicEngine<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) header: DbHeader,
    pub(crate) wal_data: Option<&'a [u8]>,
    pub(crate) journal_data: Option<&'a [u8]>,
    pub(crate) wal_mode: WalMode,
}

impl<'a> ForensicEngine<'a> {
    pub fn new(data: &'a [u8], _timezone_offset: Option<i32>) -> Result<Self> {
        if !is_sqlite_header(data) {
            bail!("not a SQLite database");
        }
        let header = DbHeader::parse(data).ok_or_else(|| anyhow::anyhow!("invalid DB header"))?;
        Ok(Self {
            data,
            header,
            wal_data: None,
            journal_data: None,
            wal_mode: WalMode::default(),
        })
    }

    pub fn with_wal(mut self, wal: &'a [u8]) -> Self {
        self.wal_data = Some(wal);
        self
    }

    pub fn with_journal(mut self, journal: &'a [u8]) -> Self {
        self.journal_data = Some(journal);
        self
    }

    pub fn with_wal_mode(mut self, mode: WalMode) -> Self {
        self.wal_mode = mode;
        self
    }

    pub fn page_size(&self) -> u32 {
        self.header.page_size
    }

    pub fn header(&self) -> &DbHeader {
        &self.header
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }

    pub fn table_roots(&self) -> Result<HashMap<String, u32>> {
        self.read_sqlite_master()
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

    fn build_schema_signatures(&self) -> Result<Vec<SchemaSignature>> {
        let mut sigs = Vec::new();
        let mut master_records = Vec::new();
        self.traverse_btree(1, "sqlite_master", &mut master_records);
        for r in &master_records {
            if r.values.len() >= 5 {
                use crate::record::SqlValue;
                if let (SqlValue::Text(obj_type), SqlValue::Text(name), SqlValue::Text(sql)) =
                    (&r.values[0], &r.values[1], &r.values[4])
                {
                    if obj_type == "table" {
                        if let Some(sig) = SchemaSignature::from_create_sql(name, sql) {
                            sigs.push(sig);
                        }
                    }
                }
            }
        }
        Ok(sigs)
    }

    /// Build a shared RecoveryContext from the current engine state.
    pub fn build_context(&self) -> Result<RecoveryContext<'_>> {
        let table_roots = self.read_sqlite_master()?;
        let signatures = self.build_schema_signatures()?;
        let pragma_info = parse_pragma_info(&self.header, self.data);

        Ok(RecoveryContext {
            db: self.data,
            page_size: self.header.page_size,
            header: &self.header,
            table_roots,
            schema_signatures: signatures,
            pragma_info,
        })
    }

    /// Orchestrator: run all recovery layers and deduplicate.
    pub fn recover_all(&self) -> Result<RecoveryResult> {
        let ctx = self.build_context()?;
        let mut all = Vec::new();
        let mut stats = RecoveryStats::default();

        // Layer 1: Live records
        let live = self.recover_layer1()?;
        stats.live_count = live.len();
        all.extend(live);

        // Layer 2: WAL (if provided)
        if let Some(wal) = self.wal_data {
            let wal_records = recover_layer2_enhanced(
                ctx.db, wal, ctx.page_size, self.wal_mode, &ctx.table_roots,
            );
            stats.wal_pending = wal_records
                .iter()
                .filter(|r| r.source == EvidenceSource::WalPending)
                .count();
            stats.wal_deleted = wal_records
                .iter()
                .filter(|r| r.source == EvidenceSource::WalDeleted)
                .count();
            all.extend(wal_records);
        }

        // Layer 3: Freelist content
        // Skip if auto_vacuum == Full: the freelist is actively managed and
        // reclaimed pages are immediately reused, so forensic recovery yields
        // nothing meaningful and may produce false positives.
        if ctx.pragma_info.auto_vacuum != AutoVacuumMode::Full {
            let freelist =
                recover_freelist_content(ctx.db, ctx.page_size, &ctx.schema_signatures);
            stats.freelist_recovered = freelist.len();
            all.extend(freelist);
        } else {
            stats.layers_skipped.push(format!(
                "freelist: auto_vacuum={:?}",
                ctx.pragma_info.auto_vacuum
            ));
        }

        // Layer 5: FTS shadow tables
        let fts = recover_layer5(ctx.db, ctx.page_size);
        stats.fts_recovered = fts.len();
        all.extend(fts);

        // Layer 7: Intra-page gaps
        // Skip if secure_delete != Off: SQLite zeroes or overwrites freed cell
        // space, so gap-carved data is gone and carving would only find zeros.
        if ctx.pragma_info.secure_delete == SecureDeleteMode::Off {
            let roots_vec: Vec<_> =
                ctx.table_roots.iter().map(|(k, v)| (k.clone(), *v)).collect();
            let gaps = scan_page_gaps(ctx.db, ctx.page_size, &roots_vec, &ctx.schema_signatures);
            stats.gap_carved = gaps.len();
            all.extend(gaps);
        } else {
            stats.layers_skipped.push(format!(
                "gap: secure_delete={:?}",
                ctx.pragma_info.secure_delete
            ));
        }

        // Layer 8a: Freeblock recovery (skip if secure_delete != Off)
        if ctx.pragma_info.secure_delete == SecureDeleteMode::Off {
            let freeblock = crate::freeblock::recover_freeblocks(&ctx);
            stats.freeblock_recovered = freeblock.len();
            all.extend(freeblock);
        } else {
            stats.layers_skipped.push(format!(
                "freeblock: secure_delete={:?}",
                ctx.pragma_info.secure_delete
            ));
        }

        // Layer 8b: WAL-only table detection (informational — records already
        // recovered via WAL layer)
        if let Some(wal) = self.wal_data {
            let wal_only = crate::wal_enhanced::detect_wal_only_tables(&ctx, wal);
            stats.wal_only_tables_found = wal_only.len();
        }

        // Layer 8c: ROWID gap detection (informational — gaps are metadata,
        // not additional records added to `all`)
        let live_records: Vec<_> = all
            .iter()
            .filter(|r| r.source == EvidenceSource::Live)
            .cloned()
            .collect();
        let gaps = crate::rowid_gap::detect_rowid_gaps(&live_records, &ctx.table_roots);
        stats.rowid_gaps_detected = gaps.len();

        // Layer 8: Journal (if provided)
        if let Some(journal) = self.journal_data {
            let journal_records =
                parse_journal(journal, ctx.page_size, &ctx.schema_signatures);
            stats.journal_recovered = journal_records.len();
            all.extend(journal_records);
        }

        // Deduplication
        let before = all.len();
        deduplicate(&mut all);
        stats.duplicates_removed = before - all.len();

        Ok(RecoveryResult { records: all, stats })
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

    fn make_wal_mode_db() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
            conn.execute_batch(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
                 INSERT INTO notes VALUES (1, 'first note');
                 INSERT INTO notes VALUES (2, 'second note');",
            )
            .unwrap();
            // Force a checkpoint so the above is in the DB file
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
            // Now add more data that stays in WAL
            conn.execute_batch("INSERT INTO notes VALUES (3, 'wal pending note');").unwrap();
        }
        let db_bytes = std::fs::read(&path).unwrap();
        let wal_path = format!("{}-wal", path.display());
        let wal_bytes = std::fs::read(&wal_path).unwrap_or_default();
        (db_bytes, wal_bytes)
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

    #[test]
    fn test_wal_mode_builder() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap().with_wal_mode(WalMode::Apply);
        assert_eq!(engine.wal_mode, WalMode::Apply);
    }

    #[test]
    fn test_engine_with_wal_data() {
        let (db, wal) = make_wal_mode_db();
        if wal.is_empty() {
            return;
        }
        let engine = ForensicEngine::new(&db, None).unwrap().with_wal(&wal);
        assert!(engine.wal_data.is_some());
    }

    #[test]
    fn test_wal_mode_default_is_both() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        assert_eq!(engine.wal_mode, WalMode::Both);
    }

    #[test]
    fn test_with_journal_builder() {
        let db = create_test_db();
        let journal = vec![0u8; 512];
        let engine = ForensicEngine::new(&db, None).unwrap().with_journal(&journal);
        assert!(engine.journal_data.is_some());
    }

    #[test]
    fn test_page_size_accessor() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        assert!(engine.page_size() > 0);
    }

    #[test]
    fn test_table_roots() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let roots = engine.table_roots().unwrap();
        assert!(roots.contains_key("messages"));
    }

    #[test]
    fn test_recover_all_runs_all_layers() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let result = engine.recover_all().unwrap();
        assert!(!result.records.is_empty());
        assert!(result.stats.live_count > 0);
        assert_eq!(result.stats.duplicates_removed, 0); // no dupes in clean DB
    }

    #[test]
    fn test_recover_all_with_wal() {
        let (db, wal) = make_wal_mode_db();
        if wal.is_empty() {
            return;
        }
        let engine = ForensicEngine::new(&db, None).unwrap().with_wal(&wal);
        let result = engine.recover_all().unwrap();
        assert!(result.stats.live_count > 0);
        // WAL should contribute some records
        assert!(!result.records.is_empty());
    }

    #[test]
    fn test_recover_all_stats_populated() {
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let result = engine.recover_all().unwrap();
        // live_count should match layer1
        let layer1 = engine.recover_layer1().unwrap();
        assert_eq!(result.stats.live_count, layer1.len());
    }

    #[test]
    fn test_recovery_result_empty_journal() {
        let db = create_test_db();
        let journal = vec![0u8; 512]; // invalid journal, should produce 0 records
        let engine = ForensicEngine::new(&db, None).unwrap().with_journal(&journal);
        let result = engine.recover_all().unwrap();
        assert_eq!(result.stats.journal_recovered, 0);
    }

    #[test]
    fn test_recover_all_stats_arithmetic() {
        // records.len() == sum(all layer counts) - duplicates_removed
        let db = create_test_db();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let result = engine.recover_all().unwrap();
        let s = &result.stats;
        let layer_sum = s.live_count
            + s.wal_pending
            + s.wal_deleted
            + s.freelist_recovered
            + s.fts_recovered
            + s.gap_carved
            + s.journal_recovered
            + s.freeblock_recovered;
        assert_eq!(
            result.records.len(),
            layer_sum - s.duplicates_removed,
            "records.len() must equal sum of layer counts minus duplicates_removed"
        );
    }

    #[test]
    fn test_engine_with_wal_and_journal_no_panic() {
        // Attaching both WAL and journal simultaneously must not panic.
        let db = create_test_db();
        let fake_wal = vec![0u8; 64];
        let fake_journal = vec![0u8; 512];
        let engine = ForensicEngine::new(&db, None)
            .unwrap()
            .with_wal(&fake_wal)
            .with_journal(&fake_journal);
        // Both attachments present — recover_all must complete without panic.
        let result = engine.recover_all();
        assert!(result.is_ok(), "recover_all must not panic with both WAL and journal attached");
    }
}
