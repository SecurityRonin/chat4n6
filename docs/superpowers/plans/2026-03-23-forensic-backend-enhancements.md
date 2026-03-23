# Forensic Backend Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance chat4n6-sqlite-forensics with comprehensive test coverage, a shared RecoveryContext, and 7 new forensic features stolen from bring2lite, sqlite-gui-analyzer, and Sanderson Forensics.

**Architecture:** Three sequential phases. Phase 1 locks down all existing behavior with unit + integration tests (no production changes). Phase 2 introduces `RecoveryContext` and `PragmaInfo` as shared state, refactoring all recovery layers. Phase 3 adds page-to-table mapping, freeblock brute-force recovery, WAL frame classification, ROWID gap detection, verification reports, and Nemetz corpus benchmarks.

**Tech Stack:** Rust, chat4n6-sqlite-forensics crate, sha2, rusqlite (test fixtures), tempfile (test fixtures)

**Spec:** `docs/superpowers/specs/2026-03-23-forensic-backend-enhancements-design.md`

---

## File Structure

### Existing files (modify)
- `crates/chat4n6-sqlite-forensics/src/db.rs` — ForensicEngine, recover_all(), RecoveryResult, RecoveryStats
- `crates/chat4n6-sqlite-forensics/src/freelist.rs` — recover_freelist_content()
- `crates/chat4n6-sqlite-forensics/src/gap.rs` — scan_page_gaps()
- `crates/chat4n6-sqlite-forensics/src/journal.rs` — parse_journal()
- `crates/chat4n6-sqlite-forensics/src/wal.rs` — recover_layer2_enhanced()
- `crates/chat4n6-sqlite-forensics/src/btree.rs` — walk_table_btree(), parse_table_leaf_page()
- `crates/chat4n6-sqlite-forensics/src/fts.rs` — recover_layer5()
- `crates/chat4n6-sqlite-forensics/src/unalloc.rs` — recover_layer6()
- `crates/chat4n6-sqlite-forensics/src/lib.rs` — module exports

### New files (create)
- `crates/chat4n6-sqlite-forensics/src/context.rs` — RecoveryContext, build_context()
- `crates/chat4n6-sqlite-forensics/src/pragma.rs` — PragmaInfo, parse_pragma_info(), viability_report()
- `crates/chat4n6-sqlite-forensics/src/page_map.rs` — PageMap, PageOwnership, PageRole
- `crates/chat4n6-sqlite-forensics/src/freeblock.rs` — recover_freeblocks() (bring2lite Algorithm 3)
- `crates/chat4n6-sqlite-forensics/src/wal_enhanced.rs` — WalFrameStatus, classify_wal_frames(), detect_wal_only_tables()
- `crates/chat4n6-sqlite-forensics/src/rowid_gap.rs` — RowidGap, detect_rowid_gaps()
- `crates/chat4n6-sqlite-forensics/src/verify.rs` — VerifiableFinding, VerificationReport, build_verification_report()
- `crates/chat4n6-sqlite-forensics/tests/robustness.rs` — Tier 4 robustness integration tests

### Test command convention

All test commands use:
```bash
CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1
```

For specific tests:
```bash
CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics <test_name> -- --test-threads=1
```

---

# Phase 1: Test Coverage Lock-down

No production code changes in this phase. Only add tests.

---

### Task 0: record.rs Unit Tests (Tier 1)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/record.rs`

Add comprehensive unit tests for `SqlValue`, `RecoveredRecord`, and `decode_serial_type()`.

**Current state:** record.rs has 98 lines, 0 tests. Contains `SqlValue` enum (Null/Int/Real/Text/Blob), `RecoveredRecord` struct (table, row_id, values, source, offset, confidence), and `decode_serial_type(serial_type: u64, data: &[u8], offset: usize) -> Option<(SqlValue, usize)>`.

- [ ] **Step 1: Add tests module and SqlValue tests**

Add at the bottom of `crates/chat4n6-sqlite-forensics/src/record.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlvalue_null() {
        assert_eq!(SqlValue::Null, SqlValue::Null);
        assert_ne!(SqlValue::Null, SqlValue::Int(0));
    }

    #[test]
    fn test_sqlvalue_int() {
        assert_eq!(SqlValue::Int(42), SqlValue::Int(42));
        assert_ne!(SqlValue::Int(42), SqlValue::Int(43));
        assert_eq!(SqlValue::Int(i64::MAX), SqlValue::Int(i64::MAX));
        assert_eq!(SqlValue::Int(i64::MIN), SqlValue::Int(i64::MIN));
    }

    #[test]
    fn test_sqlvalue_real() {
        assert_eq!(SqlValue::Real(3.14), SqlValue::Real(3.14));
        assert_ne!(SqlValue::Real(3.14), SqlValue::Real(2.71));
    }

    #[test]
    fn test_sqlvalue_text() {
        assert_eq!(SqlValue::Text("hello".into()), SqlValue::Text("hello".into()));
        assert_ne!(SqlValue::Text("a".into()), SqlValue::Text("b".into()));
        // Empty text
        assert_eq!(SqlValue::Text(String::new()), SqlValue::Text(String::new()));
    }

    #[test]
    fn test_sqlvalue_blob() {
        assert_eq!(SqlValue::Blob(vec![1, 2, 3]), SqlValue::Blob(vec![1, 2, 3]));
        assert_ne!(SqlValue::Blob(vec![1]), SqlValue::Blob(vec![2]));
        // Empty blob
        assert_eq!(SqlValue::Blob(vec![]), SqlValue::Blob(vec![]));
    }

    #[test]
    fn test_sqlvalue_cross_type_inequality() {
        assert_ne!(SqlValue::Int(0), SqlValue::Null);
        assert_ne!(SqlValue::Int(0), SqlValue::Real(0.0));
        assert_ne!(SqlValue::Text("0".into()), SqlValue::Int(0));
    }

    #[test]
    fn test_sqlvalue_clone() {
        let original = SqlValue::Text("test".into());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_sqlvalue_debug() {
        let val = SqlValue::Int(42);
        let debug = format!("{:?}", val);
        assert!(debug.contains("42"));
    }

    // decode_serial_type tests

    #[test]
    fn test_decode_null() {
        let (val, consumed) = decode_serial_type(0, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Null);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_decode_int8() {
        let data = [0x7F]; // 127
        let (val, consumed) = decode_serial_type(1, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(127));
        assert_eq!(consumed, 1);
        // Negative
        let data = [0xFF]; // -1 as i8
        let (val, _) = decode_serial_type(1, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
    }

    #[test]
    fn test_decode_int16() {
        let data = [0x01, 0x00]; // 256
        let (val, consumed) = decode_serial_type(2, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(256));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_int24() {
        let data = [0x01, 0x00, 0x00]; // 65536
        let (val, consumed) = decode_serial_type(3, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(65536));
        assert_eq!(consumed, 3);
        // Negative: -1 = 0xFFFFFF sign-extended
        let data = [0xFF, 0xFF, 0xFF];
        let (val, _) = decode_serial_type(3, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(-1));
    }

    #[test]
    fn test_decode_int32() {
        let data = 1000000i32.to_be_bytes();
        let (val, consumed) = decode_serial_type(4, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(1000000));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_decode_int48() {
        let data = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00]; // 2^32 = 4294967296
        let (val, consumed) = decode_serial_type(5, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(4294967296));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_decode_int64() {
        let data = i64::MAX.to_be_bytes();
        let (val, consumed) = decode_serial_type(6, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Int(i64::MAX));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_decode_float64() {
        let data = 3.14f64.to_be_bytes();
        let (val, consumed) = decode_serial_type(7, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Real(3.14));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_decode_const_zero() {
        let (val, consumed) = decode_serial_type(8, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Int(0));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_decode_const_one() {
        let (val, consumed) = decode_serial_type(9, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Int(1));
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_decode_blob() {
        // serial type 12 → blob of length (12-12)/2 = 0 (empty blob)
        let (val, consumed) = decode_serial_type(12, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![]));
        assert_eq!(consumed, 0);
        // serial type 14 → blob of length 1
        let data = [0xAB];
        let (val, consumed) = decode_serial_type(14, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![0xAB]));
        assert_eq!(consumed, 1);
        // serial type 20 → blob of length 4
        let data = [1, 2, 3, 4];
        let (val, consumed) = decode_serial_type(20, &data, 0).unwrap();
        assert_eq!(val, SqlValue::Blob(vec![1, 2, 3, 4]));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_decode_text() {
        // serial type 13 → text of length (13-13)/2 = 0 (empty string)
        let (val, consumed) = decode_serial_type(13, &[], 0).unwrap();
        assert_eq!(val, SqlValue::Text(String::new()));
        assert_eq!(consumed, 0);
        // serial type 23 → text of length 5
        let data = b"hello";
        let (val, consumed) = decode_serial_type(23, data, 0).unwrap();
        assert_eq!(val, SqlValue::Text("hello".into()));
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_decode_invalid_serial_types() {
        // serial types 10, 11 are reserved/invalid
        assert!(decode_serial_type(10, &[], 0).is_none());
        assert!(decode_serial_type(11, &[], 0).is_none());
    }

    #[test]
    fn test_decode_truncated_data() {
        // int16 needs 2 bytes, only 1 available
        assert!(decode_serial_type(2, &[0x01], 0).is_none());
        // int32 needs 4 bytes, only 2 available
        assert!(decode_serial_type(4, &[0x01, 0x02], 0).is_none());
        // float64 needs 8 bytes, only 4 available
        assert!(decode_serial_type(7, &[0; 4], 0).is_none());
        // text needs 5 bytes, only 3 available
        assert!(decode_serial_type(23, b"hel", 0).is_none());
    }

    #[test]
    fn test_decode_with_offset() {
        let data = [0x00, 0x00, 0x7F]; // offset=2 → read 0x7F
        let (val, consumed) = decode_serial_type(1, &data, 2).unwrap();
        assert_eq!(val, SqlValue::Int(127));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_recovered_record_construction() {
        let record = RecoveredRecord {
            table: "messages".to_string(),
            row_id: Some(42),
            values: vec![SqlValue::Int(42), SqlValue::Text("hello".into())],
            source: EvidenceSource::Live,
            offset: 1024,
            confidence: 1.0,
        };
        assert_eq!(record.table, "messages");
        assert_eq!(record.row_id, Some(42));
        assert_eq!(record.values.len(), 2);
        assert_eq!(record.confidence, 1.0);
    }

    #[test]
    fn test_recovered_record_no_rowid() {
        let record = RecoveredRecord {
            table: "test".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::Freelist,
            offset: 0,
            confidence: 0.5,
        };
        assert!(record.row_id.is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics record::tests -- --test-threads=1`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/record.rs
git commit -m "test: comprehensive unit tests for record.rs (SqlValue, decode_serial_type)"
```

---

### Task 1: page.rs + header.rs Unit Tests (Tier 1+2)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/page.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/header.rs`

**Current state:** page.rs has 1 test covering from_byte for 5 values. header.rs has 3 tests covering magic, valid parse, and invalid parse.

- [ ] **Step 1: Add page.rs tests**

Add inside the existing `mod tests` in `crates/chat4n6-sqlite-forensics/src/page.rs`, after the existing test:

```rust
    #[test]
    fn test_page_type_index_interior() {
        assert_eq!(PageType::from_byte(0x02), Some(PageType::IndexInterior));
    }

    #[test]
    fn test_page_type_invalid_bytes() {
        assert_eq!(PageType::from_byte(0x01), None);
        assert_eq!(PageType::from_byte(0x03), None);
        assert_eq!(PageType::from_byte(0xFF), None);
        assert_eq!(PageType::from_byte(0x0B), None);
        assert_eq!(PageType::from_byte(0x0E), None);
    }

    #[test]
    fn test_is_leaf_table_leaf() {
        assert!(PageType::TableLeaf.is_leaf());
    }

    #[test]
    fn test_is_leaf_index_leaf() {
        assert!(PageType::IndexLeaf.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_table_interior() {
        assert!(!PageType::TableInterior.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_index_interior() {
        assert!(!PageType::IndexInterior.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_overflow() {
        assert!(!PageType::OverflowOrDropped.is_leaf());
    }
```

- [ ] **Step 2: Add header.rs tests**

Add inside the existing `mod tests` in `crates/chat4n6-sqlite-forensics/src/header.rs`, after the existing tests:

```rust
    #[test]
    fn test_page_size_65536() {
        // page_size=1 in header means 65536
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x00;
        buf[17] = 0x01; // raw value 1 → 65536
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.page_size, 65536);
    }

    #[test]
    fn test_page_size_512() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x02;
        buf[17] = 0x00; // 512
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.page_size, 512);
    }

    #[test]
    fn test_header_truncated_99_bytes() {
        let mut buf = vec![0u8; 99];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        assert!(DbHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_header_exactly_100_bytes() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // 4096
        assert!(DbHeader::parse(&buf).is_some());
    }

    #[test]
    fn test_is_sqlite_header_empty() {
        assert!(!is_sqlite_header(&[]));
    }

    #[test]
    fn test_is_sqlite_header_15_bytes() {
        assert!(!is_sqlite_header(b"SQLite format 3"));
    }

    #[test]
    fn test_is_sqlite_header_near_miss() {
        // Wrong last byte
        assert!(!is_sqlite_header(b"SQLite format 3\x01"));
    }

    #[test]
    fn test_header_freelist_fields() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // page_size 4096
        // freelist_trunk_page at offset 32
        buf[32..36].copy_from_slice(&5u32.to_be_bytes());
        // freelist_page_count at offset 36
        buf[36..40].copy_from_slice(&3u32.to_be_bytes());
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.freelist_trunk_page, 5);
        assert_eq!(hdr.freelist_page_count, 3);
    }

    #[test]
    fn test_header_text_encoding() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10;
        // text_encoding at offset 56: 1=UTF-8, 2=UTF-16le, 3=UTF-16be
        buf[56..60].copy_from_slice(&2u32.to_be_bytes());
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.text_encoding, 2);
    }
```

- [ ] **Step 3: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/page.rs crates/chat4n6-sqlite-forensics/src/header.rs
git commit -m "test: page.rs and header.rs edge case coverage (page sizes, truncation, encoding)"
```

---

### Task 2: btree.rs Unit Tests (Tier 1)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/btree.rs`

**Current state:** btree.rs has ~220 lines, 2 tests. Key public functions: `walk_table_btree(db, page_size, root_page, table, source, records)`, `parse_table_leaf_page(db, page_data, page_size, table, source, records)`, `follow_overflow_chain(db, first_page, page_size, remaining) -> Vec<u8>`, `get_overlay_page(db, page_num, page_size, overlay) -> Option<(Vec<u8>, usize)>`, `walk_table_btree_with_overlay(db, page_size, root_page, table, overlay, records)`.

- [ ] **Step 1: Add btree.rs unit tests**

Add tests using real SQLite databases created with rusqlite to ensure correct B-tree parsing. Key scenarios:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SqlValue;
    use chat4n6_plugin_api::EvidenceSource;
    use std::collections::HashMap;

    fn create_simple_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
             INSERT INTO items VALUES (1, 'alpha');
             INSERT INTO items VALUES (2, 'beta');",
        ).unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    fn create_empty_table_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE empty_tbl (id INTEGER PRIMARY KEY, val TEXT);").unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    fn create_multi_page_db() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA page_size=1024;").unwrap();
        conn.execute_batch("CREATE TABLE big (id INTEGER PRIMARY KEY, data TEXT);").unwrap();
        for i in 0..200 {
            conn.execute(
                "INSERT INTO big VALUES (?, ?)",
                rusqlite::params![i, format!("record_{:04}_padding_to_make_it_longer", i)],
            ).unwrap();
        }
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn test_walk_table_btree_simple() {
        let db = create_simple_db();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let mut records = Vec::new();
        // sqlite_master root is page 1
        walk_table_btree(&db, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut records);
        assert!(!records.is_empty());
        // Should find at least one table entry
        assert!(records.iter().any(|r| r.values.iter().any(|v| matches!(v, SqlValue::Text(s) if s == "items"))));
    }

    #[test]
    fn test_walk_table_btree_empty_table() {
        let db = create_empty_table_db();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        // Find root page for empty_tbl from sqlite_master
        let mut master_records = Vec::new();
        walk_table_btree(&db, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut master_records);
        // Find root page
        let root_page = master_records.iter().find_map(|r| {
            if r.values.get(1) == Some(&SqlValue::Text("empty_tbl".into())) {
                if let Some(SqlValue::Int(rp)) = r.values.get(3) {
                    return Some(*rp as u32);
                }
            }
            None
        }).unwrap();

        let mut records = Vec::new();
        walk_table_btree(&db, page_size, root_page, "empty_tbl", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    #[test]
    fn test_walk_table_btree_multi_page() {
        let db = create_multi_page_db();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let mut master_records = Vec::new();
        walk_table_btree(&db, page_size, 1, "sqlite_master", EvidenceSource::Live, &mut master_records);
        let root_page = master_records.iter().find_map(|r| {
            if r.values.get(1) == Some(&SqlValue::Text("big".into())) {
                if let Some(SqlValue::Int(rp)) = r.values.get(3) {
                    return Some(*rp as u32);
                }
            }
            None
        }).unwrap();

        let mut records = Vec::new();
        walk_table_btree(&db, page_size, root_page, "big", EvidenceSource::Live, &mut records);
        assert_eq!(records.len(), 200);
    }

    #[test]
    fn test_walk_table_btree_invalid_root_page() {
        let db = create_simple_db();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let mut records = Vec::new();
        // Page 9999 doesn't exist — should not panic
        walk_table_btree(&db, page_size, 9999, "fake", EvidenceSource::Live, &mut records);
        assert!(records.is_empty());
    }

    #[test]
    fn test_follow_overflow_chain_no_overflow() {
        // first_page=0 means no overflow
        let result = follow_overflow_chain(&[0u8; 4096], 0, 4096, 100);
        assert!(result.is_empty());
    }

    #[test]
    fn test_follow_overflow_chain_beyond_db() {
        // Overflow page points beyond database
        let db = vec![0u8; 4096];
        let result = follow_overflow_chain(&db, 999, 4096, 100);
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_overlay_page_not_in_overlay() {
        let db = vec![0u8; 8192]; // 2 pages of 4096
        let overlay: HashMap<u32, Vec<u8>> = HashMap::new();
        let result = get_overlay_page(&db, 1, 4096, &overlay);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_overlay_page_in_overlay() {
        let db = vec![0u8; 8192];
        let mut overlay = HashMap::new();
        let page_data = vec![0xAB; 4096];
        overlay.insert(2, page_data.clone());
        let result = get_overlay_page(&db, 2, 4096, &overlay);
        assert!(result.is_some());
        let (data, offset) = result.unwrap();
        assert_eq!(data.len(), 4096);
        assert_eq!(data[0], 0xAB);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics btree::tests -- --test-threads=1`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/btree.rs
git commit -m "test: btree.rs unit tests (walk, empty table, multi-page, overflow, overlay)"
```

---

### Task 3: Tier 2 Module Tests (freelist, gap, journal, fts, unalloc)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/freelist.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/gap.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/journal.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/fts.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/unalloc.rs`

Add edge case tests to each module. Each module already has some tests; add the missing edge cases.

- [ ] **Step 1: Add freelist edge case tests**

In `freelist.rs` existing test module, add:

```rust
    #[test]
    fn test_empty_freelist_no_crash() {
        // DB with freelist_trunk_page = 0 means no freelist
        let db = create_test_db(); // uses helper from existing tests
        // The test DB should have no freelist if nothing was deleted
        let sigs = vec![];
        let result = recover_freelist_content(&db, 4096, &sigs);
        // May or may not find records, but should not panic
        let _ = result;
    }

    #[test]
    fn test_freelist_trunk_beyond_db() {
        // Craft a DB where freelist_trunk_page points past EOF
        let mut db = create_test_db();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        // Set freelist_trunk_page to 9999 (beyond DB)
        db[32..36].copy_from_slice(&9999u32.to_be_bytes());
        let sigs = vec![];
        let result = recover_freelist_content(&db, page_size, &sigs);
        assert!(result.is_empty()); // Should handle gracefully
    }
```

- [ ] **Step 2: Add journal edge case tests**

In `journal.rs` existing test module, add:

```rust
    #[test]
    fn test_journal_zero_length() {
        let result = parse_journal(&[], 4096, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_journal_invalid_magic() {
        let data = vec![0u8; 512];
        let result = parse_journal(&data, 4096, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_journal_valid_header_no_pages() {
        let mut data = vec![0u8; 512];
        // Write valid magic
        data[..8].copy_from_slice(&[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
        // page_count = 0 at offset 8
        data[8..12].copy_from_slice(&0i32.to_be_bytes());
        // sector_size at offset 20
        data[20..24].copy_from_slice(&512u32.to_be_bytes());
        // page_size at offset 24
        data[24..28].copy_from_slice(&4096u32.to_be_bytes());
        let result = parse_journal(&data, 4096, &[]);
        assert!(result.is_empty());
    }
```

- [ ] **Step 3: Add fts edge case tests**

In `fts.rs` existing test module, add:

```rust
    #[test]
    fn test_fts_no_tables() {
        // DB with no FTS tables
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE plain (id INTEGER PRIMARY KEY, text TEXT);").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let result = recover_layer5(&db, page_size);
        assert!(result.is_empty());
    }
```

- [ ] **Step 4: Add gap.rs edge case test**

In `gap.rs` existing test module, add:

```rust
    #[test]
    fn test_scan_page_gaps_empty_roots() {
        let db = create_test_db_with_deletion(); // existing helper
        let page_size = u16::from_be_bytes([db[16], db[17]]) as u32;
        let empty_roots: Vec<(String, u32)> = vec![];
        let sigs = vec![];
        let result = scan_page_gaps(&db, page_size, &empty_roots, &sigs);
        assert!(result.is_empty());
    }
```

- [ ] **Step 5: Add unalloc.rs edge case tests**

In `unalloc.rs` test module, add:

```rust
    #[test]
    fn test_recover_empty_region() {
        let empty: Vec<u8> = vec![];
        let result = recover_layer6(&empty, &[], None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recover_all_zeros() {
        let zeros = vec![0u8; 4096];
        let result = recover_layer6(&zeros, &[], None);
        assert!(result.is_empty());
    }
```

- [ ] **Step 6: Run all tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/freelist.rs crates/chat4n6-sqlite-forensics/src/journal.rs crates/chat4n6-sqlite-forensics/src/fts.rs crates/chat4n6-sqlite-forensics/src/gap.rs crates/chat4n6-sqlite-forensics/src/unalloc.rs
git commit -m "test: Tier 2 edge case tests for freelist, journal, fts, gap, unalloc"
```

---

### Task 4: Tier 3 Edge Cases + Tier 4 Robustness Integration Tests

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/wal.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/schema_sig.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/dedup.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`
- Create: `crates/chat4n6-sqlite-forensics/tests/robustness.rs`

- [ ] **Step 1: Add Tier 3 edge case tests to wal.rs, schema_sig.rs, dedup.rs, db.rs**

Add to each module's test section the edge cases specified in the spec:

**wal.rs** — empty WAL, WalMode::Ignore fast-path
**schema_sig.rs** — CREATE TABLE with constraints, reserved keywords, all-TEXT table
**dedup.rs** — all-live input, all-carved input, single record
**db.rs** — recover_all stats arithmetic, WAL + journal simultaneously

- [ ] **Step 2: Create robustness.rs integration tests**

Create `crates/chat4n6-sqlite-forensics/tests/robustness.rs`:

```rust
//! Tier 4: Robustness integration tests.
//! Tests that the recovery pipeline handles edge cases without panicking.

use chat4n6_sqlite_forensics::db::ForensicEngine;

fn make_db_with_page_size_pragma(page_size: u32) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(&format!("PRAGMA page_size={page_size};")).unwrap();
    conn.execute_batch(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO items VALUES (1, 'test');",
    ).unwrap();
    drop(conn);
    std::fs::read(&path).unwrap()
}

#[test]
fn test_page_size_512() {
    let db = make_db_with_page_size_pragma(512);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0);
}

#[test]
fn test_page_size_8192() {
    let db = make_db_with_page_size_pragma(8192);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0);
}

#[test]
fn test_page_size_32768() {
    let db = make_db_with_page_size_pragma(32768);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0);
}

#[test]
fn test_page_size_65536() {
    let db = make_db_with_page_size_pragma(65536);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0);
}

#[test]
fn test_db_only_sqlite_master() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    // Create and drop a table to force a valid DB file with no user tables
    conn.execute_batch("CREATE TABLE tmp (x); DROP TABLE tmp;").unwrap();
    drop(conn);
    let db = std::fs::read(&path).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert_eq!(result.stats.live_count, 0);
}

#[test]
fn test_truncated_db_at_page_boundary() {
    let db = make_db_with_page_size_pragma(4096);
    // Truncate to exactly 1 page (header + sqlite_master only)
    let truncated = db[..4096].to_vec();
    let engine = ForensicEngine::new(&truncated, None).unwrap();
    // Should not panic, may or may not recover anything
    let _result = engine.recover_all();
}

#[test]
fn test_garbage_db_rejected() {
    let garbage = vec![0xFF; 4096];
    assert!(ForensicEngine::new(&garbage, None).is_err());
}

#[test]
fn test_too_small_db_rejected() {
    assert!(ForensicEngine::new(&[0u8; 50], None).is_err());
}

#[test]
fn test_auto_vacuum_full_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA auto_vacuum=FULL;").unwrap();
    conn.execute_batch(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO items VALUES (1, 'auto_vacuum_test');",
    ).unwrap();
    drop(conn);
    let db = std::fs::read(&path).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0);
}

#[test]
fn test_non_degradation() {
    // Live records from recover_layer1 must be identical to live records from recover_all
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA secure_delete=OFF; PRAGMA page_size=1024;").unwrap();
    conn.execute_batch(
        "CREATE TABLE msgs (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER);
         INSERT INTO msgs VALUES (1, 'hello', 1710000000);
         INSERT INTO msgs VALUES (2, 'world', 1710000001);
         INSERT INTO msgs VALUES (3, 'deleted', 1710000002);
         DELETE FROM msgs WHERE id = 3;",
    ).unwrap();
    drop(conn);
    let db = std::fs::read(&path).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let layer1 = engine.recover_layer1().unwrap();
    let full = engine.recover_all().unwrap();

    // Every layer1 record must appear in recover_all
    let live_in_full: Vec<_> = full.records.iter()
        .filter(|r| r.source == chat4n6_plugin_api::EvidenceSource::Live)
        .collect();
    assert_eq!(layer1.len(), live_in_full.len(), "non-degradation: live record count must match");
    assert_eq!(full.stats.live_count, layer1.len());
}
```

- [ ] **Step 3: Run all tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/wal.rs crates/chat4n6-sqlite-forensics/src/schema_sig.rs crates/chat4n6-sqlite-forensics/src/dedup.rs crates/chat4n6-sqlite-forensics/src/db.rs crates/chat4n6-sqlite-forensics/tests/robustness.rs
git commit -m "test: Tier 3 edge cases + Tier 4 robustness integration tests"
```

---

# Phase 2: RecoveryContext Refactor

---

### Task 5: pragma.rs + context.rs (New Modules)

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/pragma.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/context.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Write failing tests for pragma.rs**

Create `crates/chat4n6-sqlite-forensics/src/pragma.rs`:

```rust
use crate::header::DbHeader;

#[derive(Debug, Clone, PartialEq)]
pub enum SecureDeleteMode {
    Off,
    On,
    Fast,
}

impl Default for SecureDeleteMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AutoVacuumMode {
    None,
    Full,
    Incremental,
}

impl Default for AutoVacuumMode {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum JournalMode {
    Wal,
    NonWal,
}

impl Default for JournalMode {
    fn default() -> Self {
        Self::NonWal
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TextEncoding {
    Utf8,
    Utf16le,
    Utf16be,
}

impl Default for TextEncoding {
    fn default() -> Self {
        Self::Utf8
    }
}

#[derive(Debug, Clone)]
pub struct PragmaInfo {
    pub secure_delete: SecureDeleteMode,
    pub auto_vacuum: AutoVacuumMode,
    pub journal_mode: JournalMode,
    pub text_encoding: TextEncoding,
    pub schema_format: u32,
    pub user_version: u32,
}

impl Default for PragmaInfo {
    fn default() -> Self {
        Self {
            secure_delete: SecureDeleteMode::Off,
            auto_vacuum: AutoVacuumMode::None,
            journal_mode: JournalMode::NonWal,
            text_encoding: TextEncoding::Utf8,
            schema_format: 0,
            user_version: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViabilityEntry {
    pub layer: String,
    pub viable: bool,
    pub explanation: String,
}

/// Parse forensic-relevant pragma settings from raw DB header bytes.
/// Does not require an active SQLite connection.
pub fn parse_pragma_info(_header: &DbHeader, db: &[u8]) -> PragmaInfo {
    if db.len() < 100 {
        return PragmaInfo::default();
    }

    let text_encoding = match u32::from_be_bytes([db[56], db[57], db[58], db[59]]) {
        2 => TextEncoding::Utf16le,
        3 => TextEncoding::Utf16be,
        _ => TextEncoding::Utf8,
    };

    let user_version = u32::from_be_bytes([db[60], db[61], db[62], db[63]]);
    let schema_format = u32::from_be_bytes([db[44], db[45], db[46], db[47]]);

    // auto_vacuum: offset 52 = largest root b-tree page (0 = disabled)
    // offset 64 = incremental vacuum flag (0 = Full, non-zero = Incremental)
    let auto_vacuum_enabled = u32::from_be_bytes([db[52], db[53], db[54], db[55]]);
    let incremental_flag = u32::from_be_bytes([db[64], db[65], db[66], db[67]]);
    let auto_vacuum = if auto_vacuum_enabled == 0 {
        AutoVacuumMode::None
    } else if incremental_flag == 0 {
        AutoVacuumMode::Full
    } else {
        AutoVacuumMode::Incremental
    };

    // journal_mode: offsets 18-19, both=2 → WAL
    let write_version = db[18];
    let read_version = db[19];
    let journal_mode = if write_version == 2 && read_version == 2 {
        JournalMode::Wal
    } else {
        JournalMode::NonWal
    };

    PragmaInfo {
        secure_delete: SecureDeleteMode::Off, // runtime-only, default to Off
        auto_vacuum,
        journal_mode,
        text_encoding,
        schema_format,
        user_version,
    }
}

/// Produce a viability report for which recovery layers are worth running.
pub fn viability_report(info: &PragmaInfo) -> Vec<ViabilityEntry> {
    let mut entries = Vec::new();

    entries.push(ViabilityEntry {
        layer: "Live B-tree".into(),
        viable: true,
        explanation: "Always viable.".into(),
    });

    entries.push(ViabilityEntry {
        layer: "WAL replay".into(),
        viable: info.journal_mode == JournalMode::Wal,
        explanation: if info.journal_mode == JournalMode::Wal {
            "Database uses WAL journal mode.".into()
        } else {
            "Database does not use WAL mode; WAL file unlikely to exist.".into()
        },
    });

    let freelist_viable = info.auto_vacuum != AutoVacuumMode::Full;
    entries.push(ViabilityEntry {
        layer: "Freelist content".into(),
        viable: freelist_viable,
        explanation: if freelist_viable {
            "Freelist pages may contain recoverable data.".into()
        } else {
            "auto_vacuum=FULL truncates freelist pages after each commit.".into()
        },
    });

    let freeblock_viable = info.secure_delete == SecureDeleteMode::Off;
    entries.push(ViabilityEntry {
        layer: "Freeblock recovery".into(),
        viable: freeblock_viable,
        explanation: if freeblock_viable {
            "secure_delete=OFF (default); deleted cell bytes survive.".into()
        } else {
            format!("secure_delete={:?}; deleted cell bytes are zeroed.", info.secure_delete)
        },
    });

    let gap_viable = info.secure_delete == SecureDeleteMode::Off;
    entries.push(ViabilityEntry {
        layer: "Intra-page gap scanning".into(),
        viable: gap_viable,
        explanation: if gap_viable {
            "Unallocated page gaps may contain deleted records.".into()
        } else {
            "secure_delete zeroes deleted data within pages.".into()
        },
    });

    entries.push(ViabilityEntry {
        layer: "FTS shadow tables".into(),
        viable: true,
        explanation: "FTS content tables may retain deleted text.".into(),
    });

    entries.push(ViabilityEntry {
        layer: "Journal".into(),
        viable: info.journal_mode == JournalMode::NonWal,
        explanation: if info.journal_mode == JournalMode::NonWal {
            "Non-WAL mode; rollback journal may exist.".into()
        } else {
            "WAL mode; rollback journal not used.".into()
        },
    });

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DbHeader;

    fn make_test_header_bytes(overrides: &[(usize, &[u8])]) -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // page_size = 4096
        buf[18] = 1; // write version
        buf[19] = 1; // read version
        buf[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        for (offset, bytes) in overrides {
            buf[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        buf
    }

    #[test]
    fn test_parse_pragma_default_db() {
        let db = make_test_header_bytes(&[]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::None);
        assert_eq!(info.journal_mode, JournalMode::NonWal);
        assert_eq!(info.text_encoding, TextEncoding::Utf8);
        assert_eq!(info.secure_delete, SecureDeleteMode::Off);
    }

    #[test]
    fn test_parse_pragma_wal_mode() {
        let db = make_test_header_bytes(&[(18, &[2]), (19, &[2])]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.journal_mode, JournalMode::Wal);
    }

    #[test]
    fn test_parse_pragma_auto_vacuum_full() {
        // offset 52 = non-zero (auto_vacuum enabled), offset 64 = 0 (Full)
        let db = make_test_header_bytes(&[(52, &1u32.to_be_bytes()), (64, &0u32.to_be_bytes())]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::Full);
    }

    #[test]
    fn test_parse_pragma_auto_vacuum_incremental() {
        let db = make_test_header_bytes(&[(52, &1u32.to_be_bytes()), (64, &1u32.to_be_bytes())]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::Incremental);
    }

    #[test]
    fn test_parse_pragma_utf16le() {
        let db = make_test_header_bytes(&[(56, &2u32.to_be_bytes())]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.text_encoding, TextEncoding::Utf16le);
    }

    #[test]
    fn test_parse_pragma_utf16be() {
        let db = make_test_header_bytes(&[(56, &3u32.to_be_bytes())]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.text_encoding, TextEncoding::Utf16be);
    }

    #[test]
    fn test_parse_pragma_user_version() {
        let db = make_test_header_bytes(&[(60, &42u32.to_be_bytes())]);
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.user_version, 42);
    }

    #[test]
    fn test_parse_pragma_too_short() {
        let info = parse_pragma_info(&DbHeader { page_size: 4096, page_count: 0, freelist_trunk_page: 0, freelist_page_count: 0, user_version: 0, text_encoding: 1 }, &[0u8; 50]);
        assert_eq!(info, PragmaInfo::default());
    }

    #[test]
    fn test_viability_report_default() {
        let info = PragmaInfo::default();
        let report = viability_report(&info);
        // Live B-tree always viable
        assert!(report.iter().any(|e| e.layer == "Live B-tree" && e.viable));
        // WAL not viable in non-WAL mode
        assert!(report.iter().any(|e| e.layer == "WAL replay" && !e.viable));
        // Freelist viable when no auto_vacuum
        assert!(report.iter().any(|e| e.layer == "Freelist content" && e.viable));
        // Freeblock viable when secure_delete=Off
        assert!(report.iter().any(|e| e.layer == "Freeblock recovery" && e.viable));
    }

    #[test]
    fn test_viability_report_auto_vacuum_full() {
        let info = PragmaInfo { auto_vacuum: AutoVacuumMode::Full, ..Default::default() };
        let report = viability_report(&info);
        assert!(report.iter().any(|e| e.layer == "Freelist content" && !e.viable));
    }

    #[test]
    fn test_viability_report_secure_delete_on() {
        let info = PragmaInfo { secure_delete: SecureDeleteMode::On, ..Default::default() };
        let report = viability_report(&info);
        assert!(report.iter().any(|e| e.layer == "Freeblock recovery" && !e.viable));
        assert!(report.iter().any(|e| e.layer == "Intra-page gap scanning" && !e.viable));
    }

    #[test]
    fn test_viability_report_wal_mode() {
        let info = PragmaInfo { journal_mode: JournalMode::Wal, ..Default::default() };
        let report = viability_report(&info);
        assert!(report.iter().any(|e| e.layer == "WAL replay" && e.viable));
        assert!(report.iter().any(|e| e.layer == "Journal" && !e.viable));
    }

    #[test]
    fn test_parse_pragma_real_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t (x);").unwrap();
        drop(conn);
        let db = std::fs::read(&path).unwrap();
        let header = DbHeader::parse(&db).unwrap();
        let info = parse_pragma_info(&header, &db);
        assert_eq!(info.text_encoding, TextEncoding::Utf8);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::None);
    }
}
```

- [ ] **Step 2: Create context.rs with RecoveryContext**

Create `crates/chat4n6-sqlite-forensics/src/context.rs`:

```rust
use crate::header::DbHeader;
use crate::pragma::PragmaInfo;
use crate::schema_sig::SchemaSignature;
use std::collections::HashMap;

/// Shared immutable state for all recovery layers.
/// Built once by ForensicEngine::build_context(), read by all layers.
pub struct RecoveryContext<'a> {
    pub db: &'a [u8],
    pub page_size: u32,
    pub header: &'a DbHeader,
    pub table_roots: HashMap<String, u32>,
    pub schema_signatures: Vec<SchemaSignature>,
    pub pragma_info: PragmaInfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_context_construction() {
        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10; // page_size 4096
        let header = DbHeader::parse(&db).unwrap();
        let ctx = RecoveryContext {
            db: &db,
            page_size: 4096,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: vec![],
            pragma_info: PragmaInfo::default(),
        };
        assert_eq!(ctx.page_size, 4096);
        assert!(ctx.table_roots.is_empty());
    }
}
```

- [ ] **Step 3: Update lib.rs**

Add to `crates/chat4n6-sqlite-forensics/src/lib.rs`:

```rust
pub mod context;
pub mod pragma;
```

- [ ] **Step 4: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/pragma.rs crates/chat4n6-sqlite-forensics/src/context.rs crates/chat4n6-sqlite-forensics/src/lib.rs
git commit -m "feat: add pragma.rs (PragmaInfo, viability_report) and context.rs (RecoveryContext)"
```

---

### Task 6: Refactor Recovery Layers to Accept RecoveryContext

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/freelist.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/gap.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/journal.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/fts.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/unalloc.rs`

For each module, add a new function that accepts `&RecoveryContext` and delegates to the existing function. This is the safest migration path — existing functions stay intact, new context-aware wrappers are added alongside.

**Note:** `btree.rs` and `wal.rs` are intentionally omitted here. They are more tightly coupled to `recover_all()` and are migrated as part of Task 7's `recover_all()` rewrite, where the overlay and WAL logic is restructured to use `RecoveryContext` directly.

- [ ] **Step 1: Add context-aware wrapper to freelist.rs**

```rust
use crate::context::RecoveryContext;

/// Context-aware wrapper for recover_freelist_content.
pub fn recover_freelist_with_context(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    recover_freelist_content(ctx.db, ctx.page_size, &ctx.schema_signatures)
}
```

- [ ] **Step 2: Add context-aware wrapper to gap.rs**

```rust
use crate::context::RecoveryContext;

pub fn scan_gaps_with_context(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    let roots_vec: Vec<_> = ctx.table_roots.iter().map(|(k, v)| (k.clone(), *v)).collect();
    scan_page_gaps(ctx.db, ctx.page_size, &roots_vec, &ctx.schema_signatures)
}
```

- [ ] **Step 3: Add context-aware wrappers to journal.rs, fts.rs, unalloc.rs**

Same pattern: new function accepting `&RecoveryContext`, delegating to existing function.

- [ ] **Step 4: Run all tests — zero regressions**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS (no existing test broken)

- [ ] **Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/freelist.rs crates/chat4n6-sqlite-forensics/src/gap.rs crates/chat4n6-sqlite-forensics/src/journal.rs crates/chat4n6-sqlite-forensics/src/fts.rs crates/chat4n6-sqlite-forensics/src/unalloc.rs
git commit -m "refactor: add RecoveryContext-aware wrappers for all recovery layers"
```

---

### Task 7: Update recover_all() to Use RecoveryContext + build_context()

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`

- [ ] **Step 1: Add build_context() to ForensicEngine**

Add method to `impl ForensicEngine`:

```rust
use crate::context::RecoveryContext;
use crate::pragma::parse_pragma_info;

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
```

- [ ] **Step 2: Rewrite recover_all() to use build_context()**

Replace the existing `recover_all()` body:

```rust
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
        stats.wal_pending = wal_records.iter().filter(|r| r.source == EvidenceSource::WalPending).count();
        stats.wal_deleted = wal_records.iter().filter(|r| r.source == EvidenceSource::WalDeleted).count();
        all.extend(wal_records);
    }

    // Layer 3: Freelist content (skip if auto_vacuum=Full)
    use crate::pragma::AutoVacuumMode;
    if ctx.pragma_info.auto_vacuum != AutoVacuumMode::Full {
        let freelist = recover_freelist_content(ctx.db, ctx.page_size, &ctx.schema_signatures);
        stats.freelist_recovered = freelist.len();
        all.extend(freelist);
    }

    // Layer 5: FTS shadow tables
    let fts = recover_layer5(ctx.db, ctx.page_size);
    stats.fts_recovered = fts.len();
    all.extend(fts);

    // Layer 7: Intra-page gaps (skip if secure_delete=On)
    use crate::pragma::SecureDeleteMode;
    if ctx.pragma_info.secure_delete == SecureDeleteMode::Off {
        let roots_vec: Vec<_> = ctx.table_roots.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let gaps = scan_page_gaps(ctx.db, ctx.page_size, &roots_vec, &ctx.schema_signatures);
        stats.gap_carved = gaps.len();
        all.extend(gaps);
    }

    // Layer 8: Journal (if provided)
    if let Some(journal) = self.journal_data {
        let journal_records = parse_journal(journal, ctx.page_size, &ctx.schema_signatures);
        stats.journal_recovered = journal_records.len();
        all.extend(journal_records);
    }

    // Deduplication
    let before = all.len();
    deduplicate(&mut all);
    stats.duplicates_removed = before - all.len();

    Ok(RecoveryResult { records: all, stats })
}
```

- [ ] **Step 3: Run all tests — zero regressions**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/db.rs
git commit -m "refactor: recover_all() uses RecoveryContext with pragma-aware layer skipping"
```

---

# Phase 3: New Features

---

### Task 8: page_map.rs — Page-to-Table Ownership Map

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/page_map.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Implement PageMap with full B-tree traversal**

Create `crates/chat4n6-sqlite-forensics/src/page_map.rs` with:
- `PageMap`, `PageOwnership`, `PageRole` structs/enums per spec
- `PageMap::build()` that recursively walks B-trees from all root pages
- `owner_of()`, `pages_for_table()`, `unowned_pages()` methods
- Follow overflow chains to map overflow pages
- Read freelist trunk chain to map freelist pages
- Cycle detection to prevent infinite loops

Tests:
- Simple DB: all pages owned by one table
- Multi-table DB: pages correctly attributed
- DB with overflow: overflow pages mapped with parent reference
- Empty DB: only sqlite_master pages mapped
- `unowned_pages()`: returns pages not in any B-tree or freelist

- [ ] **Step 2: Add module to lib.rs, run tests, commit**

```bash
git commit -m "feat: page_map.rs — page-to-table ownership mapping (bring2lite Algorithm 2)"
```

---

### Task 9: freeblock.rs — Varint Brute-Force Recovery

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/freeblock.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Implement bring2lite Algorithm 3**

Create `crates/chat4n6-sqlite-forensics/src/freeblock.rs` with:
- `recover_freeblocks(ctx: &RecoveryContext) -> Vec<RecoveredRecord>`
- Walk all leaf pages (using table_roots), find freeblock chains within each page
- For each freeblock: skip first 4 destroyed bytes, brute-force varint combinations
- Validate candidates against schema_signatures
- Scan entire freeblock for multi-record recovery
- Use `EvidenceSource::Freelist` for recovered records

Tests:
- Create DB with `secure_delete=OFF`, insert, delete — verify freeblock recovery
- Multi-record freeblock (delete multiple small records from same page)
- No freeblocks present (clean DB) — empty result
- Freeblock with corrupt data — no false positives

- [ ] **Step 2: Add module to lib.rs, run tests, commit**

```bash
git commit -m "feat: freeblock.rs — varint brute-force deleted record recovery (bring2lite Algorithm 3)"
```

---

### Task 10: wal_enhanced.rs — WAL Frame Classification + WAL-Only Tables

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/wal_enhanced.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Implement WAL frame classification**

Create `crates/chat4n6-sqlite-forensics/src/wal_enhanced.rs` with:
- `WalFrameStatus` enum (Committed, Uncommitted, Superseded)
- `ClassifiedFrame` struct (frame_index, page_number, status, page_data_offset)
- `classify_wal_frames(wal: &[u8], page_size: u32) -> Vec<ClassifiedFrame>`
- Algorithm: parse frames, group by salt pair, identify commit frames, mark superseded pages

- [ ] **Step 2: Implement WAL-only table detection**

- `WalOnlyTable` struct
- `detect_wal_only_tables(ctx: &RecoveryContext, wal: &[u8]) -> Vec<WalOnlyTable>`
- Find page 1 frames in WAL, parse as sqlite_master, diff against main DB's sqlite_master

Tests:
- WAL with committed transaction — frames classified as Committed
- WAL with uncommitted data — last frames classified as Uncommitted
- Same page in multiple frames — earlier ones Superseded
- WAL-mode DB where table was created but never checkpointed
- Empty WAL — no frames, no tables
- Non-WAL DB — graceful handling

- [ ] **Step 3: Add module to lib.rs, run tests, commit**

```bash
git commit -m "feat: wal_enhanced.rs — WAL frame classification and WAL-only table detection"
```

---

### Task 11: rowid_gap.rs — ROWID Gap Detection

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/rowid_gap.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Implement ROWID gap detection**

Create `crates/chat4n6-sqlite-forensics/src/rowid_gap.rs` with:
- `RowidGap` struct per spec
- `detect_rowid_gaps(live_records: &[RecoveredRecord], table_roots: &HashMap<String, u32>) -> Vec<RowidGap>`
- Group by table, filter `row_id.is_some()`, sort, detect gaps > 1
- Attach neighbor records for timestamp estimation
- Skip WITHOUT ROWID tables

Tests:
- DB with deleted rows 3,4 out of 1-5 → gap [3,4]
- DB with no deletions → no gaps
- DB with non-contiguous inserts (1, 5, 10) → gaps [2-4], [6-9]
- Empty table → no gaps
- Table with only one record → no gaps

- [ ] **Step 2: Add module to lib.rs, run tests, commit**

```bash
git commit -m "feat: rowid_gap.rs — ROWID gap detection for deletion evidence"
```

---

### Task 12: verify.rs — Verification Report Generation

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/verify.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs`

- [ ] **Step 1: Implement verification report generation**

Create `crates/chat4n6-sqlite-forensics/src/verify.rs` with:
- `VerifiableFinding`, `VerificationReport` structs per spec
- `build_verification_report(ctx: &RecoveryContext, result: &RecoveryResult) -> VerificationReport`
- SHA-256 hash of input database
- Per-finding: page number, byte offset, hex context, verification command
- Verification command generation (sqlite3 for live, xxd for recovered)

Tests:
- Report for a clean DB — all findings are live, verification commands use sqlite3
- Report for DB with deletions — recovered findings have xxd commands
- Evidence hash is consistent across runs
- Empty result — report has hash but no findings

- [ ] **Step 2: Add module to lib.rs, run tests, commit**

```bash
git commit -m "feat: verify.rs — verification report with hex offsets and shell commands"
```

---

### Task 13: Extended RecoveryStats + Updated recover_all()

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`

- [ ] **Step 1: Add new RecoveryStats fields**

Add to `RecoveryStats`:
```rust
pub freeblock_recovered: usize,
pub wal_only_tables_found: usize,
pub rowid_gaps_detected: usize,
pub layers_skipped: Vec<String>,
```

- [ ] **Step 2: Integrate new features into recover_all()**

Update `recover_all()` to call:
- `recover_freeblocks(&ctx)` → stats.freeblock_recovered
- `detect_wal_only_tables(&ctx, wal)` → stats.wal_only_tables_found
- `detect_rowid_gaps(&live, &ctx.table_roots)` → stats.rowid_gaps_detected
- Log skipped layers into `stats.layers_skipped`

- [ ] **Step 3: Run all tests — zero regressions**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics -- --test-threads=1`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: integrate freeblock, WAL classification, ROWID gaps into recover_all()"
```

---

### Task 14: Nemetz Corpus Integration

**Files:**
- Create: `tests/fixtures/nemetz/` (Git LFS, download corpus)
- Create: `.gitattributes` entry for LFS
- Create: `crates/chat4n6-sqlite-forensics/tests/nemetz_benchmark.rs`

- [ ] **Step 1: Set up Git LFS and download corpus**

```bash
git lfs install
echo 'tests/fixtures/nemetz/**/*.db filter=lfs diff=lfs merge=lfs -text' >> .gitattributes
```

Download corpus from https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/ into `tests/fixtures/nemetz/`.

- [ ] **Step 2: Create benchmark test file**

Create `crates/chat4n6-sqlite-forensics/tests/nemetz_benchmark.rs` with the 4 tests from the spec:
- `benchmark_recovery_rate` (#[ignore] — requires LFS)
- `non_degradation_guarantee` (runs unconditionally with generated DB)
- `no_false_positives_on_clean_db` (runs unconditionally)
- `anti_forensic_corpus_no_crash` (#[ignore] — requires LFS)

- [ ] **Step 3: Run non-ignored tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics --test nemetz_benchmark -- --test-threads=1`
Expected: non-degradation and no-false-positives PASS

- [ ] **Step 4: Commit**

```bash
git add .gitattributes tests/fixtures/nemetz/ crates/chat4n6-sqlite-forensics/tests/nemetz_benchmark.rs
git commit -m "test: Nemetz corpus benchmarks with non-degradation guarantee"
```

---

## Full Workspace Verification

After all tasks complete:

```bash
CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test --workspace -- --test-threads=1
```

Expected: all tests PASS, 0 failures.
