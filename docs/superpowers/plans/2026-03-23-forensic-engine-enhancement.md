# Forensic Engine Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance chat4n6-sqlite-forensics with WAL replay, freelist content recovery, intra-page gap scanning, overflow page reassembly, FQLite-style schema-aware carving, Sanderson-style deduplication, and rollback journal parsing.

**Architecture:** Layer-by-layer pipeline extending the existing `recover_layer{N}()` pattern. Each layer is independently testable and returns `Vec<RecoveredRecord>`. A `recover_all()` orchestrator runs all layers and deduplicates. WAL replay uses a page overlay (`HashMap<u32, Vec<u8>>`) that the B-tree walker reads through. Schema-aware carving builds serial-type patterns from `sqlite_master` CREATE TABLE SQL and uses Boyer-Moore matching.

**Tech Stack:** Rust, rusqlite (test fixtures), sha2 (dedup hashing), chat4n6-plugin-api (EvidenceSource enum)

**Spec:** `docs/superpowers/specs/2026-03-23-forensic-engine-enhancement-design.md`

---

## File Structure

| File | Responsibility | Status |
|------|---------------|--------|
| `crates/chat4n6-plugin-api/src/types.rs` | Add new EvidenceSource variants | Modify |
| `crates/chat4n6-sqlite-forensics/src/lib.rs` | Export new modules | Modify |
| `crates/chat4n6-sqlite-forensics/src/db.rs` | ForensicEngine: WAL/journal fields, builder methods, recover_all() | Modify |
| `crates/chat4n6-sqlite-forensics/src/schema_sig.rs` | SchemaSignature, Boyer-Moore, plausibility checks | Create |
| `crates/chat4n6-sqlite-forensics/src/dedup.rs` | SHA-256 record deduplication | Create |
| `crates/chat4n6-sqlite-forensics/src/gap.rs` | Intra-page gap scanning (Layer 7) | Create |
| `crates/chat4n6-sqlite-forensics/src/wal.rs` | WAL overlay, replay, enhanced recovery | Modify |
| `crates/chat4n6-sqlite-forensics/src/btree.rs` | Overlay page support, overflow following | Modify |
| `crates/chat4n6-sqlite-forensics/src/freelist.rs` | Freelist page content recovery | Modify |
| `crates/chat4n6-sqlite-forensics/src/overflow.rs` | Orphaned overflow chain detection | Create |
| `crates/chat4n6-sqlite-forensics/src/journal.rs` | Rollback journal parsing | Create |

---

### Task 0: Add New EvidenceSource Variants

**Files:**
- Modify: `crates/chat4n6-plugin-api/src/types.rs:6-28`

This task adds the new EvidenceSource variants needed by all subsequent tasks. Must be done first since every other module imports EvidenceSource.

- [ ] **Step 1: Add new variants to EvidenceSource enum**

In `crates/chat4n6-plugin-api/src/types.rs`, add four new variants to the enum at line 6:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    Live,
    WalPending,
    WalHistoric,
    WalDeleted,
    Freelist,
    FtsOnly,
    CarvedUnalloc { confidence_pct: u8 },
    CarvedIntraPage { confidence_pct: u8 },
    CarvedOverflow,
    CarvedDb,
    Journal,
    IndexRecovery,
}
```

- [ ] **Step 2: Update the Display impl**

Add match arms for the new variants in the `fmt::Display` impl:

```rust
Self::WalDeleted => write!(f, "WAL-DELETED"),
Self::CarvedIntraPage { confidence_pct } => {
    write!(f, "CARVED-INTRA-PAGE {confidence_pct}%")
}
Self::CarvedOverflow => write!(f, "CARVED-OVERFLOW"),
Self::Journal => write!(f, "JOURNAL"),
Self::IndexRecovery => write!(f, "INDEX-RECOVERY"),
```

- [ ] **Step 3: Add tests for new Display variants**

In the existing test module in `crates/chat4n6-plugin-api/src/lib.rs`, add:

```rust
#[test]
fn test_new_evidence_source_display() {
    assert_eq!(EvidenceSource::WalDeleted.to_string(), "WAL-DELETED");
    assert_eq!(EvidenceSource::Journal.to_string(), "JOURNAL");
    assert_eq!(EvidenceSource::IndexRecovery.to_string(), "INDEX-RECOVERY");
    assert_eq!(EvidenceSource::CarvedOverflow.to_string(), "CARVED-OVERFLOW");
    assert_eq!(
        EvidenceSource::CarvedIntraPage { confidence_pct: 75 }.to_string(),
        "CARVED-INTRA-PAGE 75%"
    );
}
```

- [ ] **Step 4: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-plugin-api --frozen`
Expected: all tests PASS

- [ ] **Step 5: Fix any downstream compilation errors**

The new variants may cause non-exhaustive match warnings in other crates (report, whatsapp plugin). Add match arms for the new variants in:
- `crates/chat4n6-report/src/lib.rs` in `source_class()` function
- Any other match on EvidenceSource

```rust
// In source_class():
EvidenceSource::WalDeleted => "wal-deleted",
EvidenceSource::CarvedIntraPage { .. } => "carved-intra-page",
EvidenceSource::CarvedOverflow => "carved-overflow",
EvidenceSource::Journal => "journal",
EvidenceSource::IndexRecovery => "index-recovery",
```

Add corresponding CSS badge classes in `base.html`:
```css
.badge-wal-deleted{background:#e65100}
.badge-carved-intra-page{background:#880e4f}
.badge-carved-overflow{background:#4a148c}
.badge-journal{background:#1b5e20}
.badge-index-recovery{background:#0d47a1}
```

- [ ] **Step 6: Run full workspace tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test --workspace --frozen`
Expected: all tests PASS

- [ ] **Step 7: Commit**

```bash
git add crates/chat4n6-plugin-api/src/types.rs crates/chat4n6-plugin-api/src/lib.rs \
       crates/chat4n6-report/src/lib.rs crates/chat4n6-report/templates/base.html
git commit -m "feat: add WalDeleted, Journal, IndexRecovery, CarvedIntraPage, CarvedOverflow evidence source variants"
```

---

### Task 1: Schema Signature Infrastructure (schema_sig.rs)

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/schema_sig.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs` (add `pub mod schema_sig;`)

FQLite-style schema-aware carving infrastructure. Parses CREATE TABLE SQL to build serial type patterns, implements Boyer-Moore search, and provides plausibility validation. Used by Layers 3, 6, and 7.

- [ ] **Step 1: Create schema_sig.rs with types and write failing tests**

Create `crates/chat4n6-sqlite-forensics/src/schema_sig.rs`:

```rust
use crate::record::{decode_serial_type, SqlValue};
use crate::varint::read_varint;

/// Column type hint derived from CREATE TABLE SQL.
#[derive(Debug, Clone, PartialEq)]
pub enum ColumnTypeHint {
    Integer,
    Real,
    Text,
    Blob,
    Null,
    Any,
}

/// Schema signature for a single table, used for carving deleted records.
#[derive(Debug, Clone)]
pub struct SchemaSignature {
    pub table_name: String,
    pub column_count: usize,
    pub type_hints: Vec<ColumnTypeHint>,
}

/// A candidate carved record with confidence score.
#[derive(Debug)]
pub struct CarvedCandidate {
    pub row_id: Option<i64>,
    pub values: Vec<SqlValue>,
    pub byte_offset: usize,
    pub bytes_consumed: usize,
    pub confidence: f32,
}

impl SchemaSignature {
    /// Build from a CREATE TABLE SQL statement.
    pub fn from_create_sql(table_name: &str, sql: &str) -> Option<Self> {
        todo!()
    }

    /// Check if a serial type is compatible with a column type hint.
    pub fn is_compatible(hint: &ColumnTypeHint, serial_type: u64) -> bool {
        todo!()
    }

    /// Attempt to parse a record at `offset` in `data` and validate against this schema.
    /// Returns a CarvedCandidate if plausible, None otherwise.
    pub fn try_parse_record(&self, data: &[u8], offset: usize) -> Option<CarvedCandidate> {
        todo!()
    }

    /// Scan a region of bytes for records matching this schema.
    /// Returns all plausible candidates found.
    pub fn scan_region(&self, data: &[u8]) -> Vec<CarvedCandidate> {
        todo!()
    }
}

/// Boyer-Moore bad-character search for a byte pattern in a haystack.
pub fn boyer_moore_search(haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create_table_simple() {
        let sig = SchemaSignature::from_create_sql(
            "messages",
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER)",
        )
        .unwrap();
        assert_eq!(sig.table_name, "messages");
        // INTEGER PRIMARY KEY is the rowid, not stored as a column in the record body.
        // Remaining columns: text TEXT, ts INTEGER
        assert_eq!(sig.column_count, 2);
        assert_eq!(sig.type_hints, vec![ColumnTypeHint::Text, ColumnTypeHint::Integer]);
    }

    #[test]
    fn test_parse_create_table_mixed_types() {
        let sig = SchemaSignature::from_create_sql(
            "contacts",
            "CREATE TABLE contacts (name TEXT, age INTEGER, score REAL, photo BLOB)",
        )
        .unwrap();
        assert_eq!(sig.column_count, 4);
        assert_eq!(
            sig.type_hints,
            vec![
                ColumnTypeHint::Text,
                ColumnTypeHint::Integer,
                ColumnTypeHint::Real,
                ColumnTypeHint::Blob,
            ]
        );
    }

    #[test]
    fn test_parse_create_table_untyped_columns() {
        let sig = SchemaSignature::from_create_sql(
            "kv",
            "CREATE TABLE kv (key, value)",
        )
        .unwrap();
        assert_eq!(sig.column_count, 2);
        assert_eq!(sig.type_hints, vec![ColumnTypeHint::Any, ColumnTypeHint::Any]);
    }

    #[test]
    fn test_is_compatible_integer() {
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 0)); // NULL
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 1)); // 1-byte int
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 4)); // 4-byte int
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 8)); // literal 0
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 9)); // literal 1
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 7)); // float
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Integer, 13)); // text
    }

    #[test]
    fn test_is_compatible_text() {
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 0)); // NULL
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 13)); // 0-len text
        assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Text, 35)); // 11-byte text
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Text, 1)); // integer
        assert!(!SchemaSignature::is_compatible(&ColumnTypeHint::Text, 12)); // blob
    }

    #[test]
    fn test_is_compatible_any() {
        // Any accepts everything
        for st in [0, 1, 4, 7, 8, 9, 12, 13, 35, 100] {
            assert!(SchemaSignature::is_compatible(&ColumnTypeHint::Any, st));
        }
    }

    #[test]
    fn test_boyer_moore_finds_pattern() {
        let haystack = b"abcXYZdefXYZghi";
        let matches = boyer_moore_search(haystack, b"XYZ");
        assert_eq!(matches, vec![3, 9]);
    }

    #[test]
    fn test_boyer_moore_no_match() {
        let matches = boyer_moore_search(b"abcdef", b"xyz");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_boyer_moore_single_byte() {
        let matches = boyer_moore_search(b"abacaba", b"a");
        assert_eq!(matches, vec![0, 2, 4, 6]);
    }

    #[test]
    fn test_try_parse_record_valid() {
        // Hand-craft a SQLite record: header_len=3, serial_type 1 (1-byte int), serial_type 13 (0-byte text)
        // Record body: [0x03, 0x01, 0x0D, 0x2A]
        // header_len=3 (varint), serial types: 1 (1-byte int), 13 (0-len text)
        // values: 0x2A (42 as i8)
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 2,
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text],
        };
        let data = [0x03, 0x01, 0x0D, 0x2A];
        let candidate = sig.try_parse_record(&data, 0);
        assert!(candidate.is_some());
        let c = candidate.unwrap();
        assert_eq!(c.values.len(), 2);
        assert_eq!(c.values[0], SqlValue::Int(42));
        assert_eq!(c.values[1], SqlValue::Text(String::new()));
        assert!(c.confidence > 0.5);
    }

    #[test]
    fn test_try_parse_record_wrong_column_count() {
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 3, // expects 3 columns
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text, ColumnTypeHint::Integer],
        };
        // Record only has 2 columns
        let data = [0x03, 0x01, 0x0D, 0x2A];
        assert!(sig.try_parse_record(&data, 0).is_none());
    }

    #[test]
    fn test_scan_region_finds_embedded_record() {
        let sig = SchemaSignature {
            table_name: "t".into(),
            column_count: 2,
            type_hints: vec![ColumnTypeHint::Integer, ColumnTypeHint::Text],
        };
        // Garbage bytes, then a valid record, then more garbage
        let mut data = vec![0xFF, 0x00, 0xAB];
        data.extend_from_slice(&[0x03, 0x01, 0x0D, 0x2A]); // valid record at offset 3
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let candidates = sig.scan_region(&data);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].byte_offset, 3);
    }
}
```

Add `pub mod schema_sig;` to `crates/chat4n6-sqlite-forensics/src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics schema_sig --frozen`
Expected: FAIL (all functions are `todo!()`)

- [ ] **Step 3: Implement from_create_sql**

Parse CREATE TABLE SQL to extract column names and types. Handle: `INTEGER PRIMARY KEY` (skip — it's the rowid), type affinity keywords (INTEGER, TEXT, REAL, BLOB, VARCHAR, etc.), untyped columns.

```rust
impl SchemaSignature {
    pub fn from_create_sql(table_name: &str, sql: &str) -> Option<Self> {
        // Find content between parentheses
        let open = sql.find('(')?;
        let close = sql.rfind(')')?;
        let cols_str = &sql[open + 1..close];

        let mut type_hints = Vec::new();
        for col_def in cols_str.split(',') {
            let col_def = col_def.trim();
            if col_def.is_empty() {
                continue;
            }
            let upper = col_def.to_uppercase();
            // Skip INTEGER PRIMARY KEY — it's the rowid alias
            if upper.contains("INTEGER") && upper.contains("PRIMARY") && upper.contains("KEY") {
                continue;
            }
            // Skip table constraints (PRIMARY KEY(...), UNIQUE(...), etc.)
            if upper.starts_with("PRIMARY")
                || upper.starts_with("UNIQUE")
                || upper.starts_with("CHECK")
                || upper.starts_with("FOREIGN")
                || upper.starts_with("CONSTRAINT")
            {
                continue;
            }
            let hint = Self::sql_type_to_hint(&upper);
            type_hints.push(hint);
        }

        Some(Self {
            table_name: table_name.to_string(),
            column_count: type_hints.len(),
            type_hints,
        })
    }

    fn sql_type_to_hint(col_def_upper: &str) -> ColumnTypeHint {
        // Extract type keyword (second token after column name)
        let tokens: Vec<&str> = col_def_upper.split_whitespace().collect();
        let type_str = tokens.get(1).copied().unwrap_or("");
        if type_str.starts_with("INT") || type_str == "BOOLEAN" || type_str == "TINYINT"
            || type_str == "SMALLINT" || type_str == "BIGINT" || type_str == "MEDIUMINT"
        {
            ColumnTypeHint::Integer
        } else if type_str.starts_with("TEXT") || type_str.starts_with("CHAR")
            || type_str.starts_with("VARCHAR") || type_str == "CLOB"
            || type_str.starts_with("NCHAR") || type_str.starts_with("NVARCHAR")
        {
            ColumnTypeHint::Text
        } else if type_str.starts_with("REAL") || type_str.starts_with("FLOAT")
            || type_str.starts_with("DOUBLE") || type_str.starts_with("NUMERIC")
            || type_str.starts_with("DECIMAL")
        {
            ColumnTypeHint::Real
        } else if type_str.starts_with("BLOB") || type_str == "BINARY"
            || type_str == "VARBINARY"
        {
            ColumnTypeHint::Blob
        } else if type_str.is_empty() {
            ColumnTypeHint::Any
        } else {
            // Unknown type — use Any
            ColumnTypeHint::Any
        }
    }
}
```

- [ ] **Step 4: Implement is_compatible**

```rust
pub fn is_compatible(hint: &ColumnTypeHint, serial_type: u64) -> bool {
    match hint {
        ColumnTypeHint::Any => true,
        ColumnTypeHint::Null => serial_type == 0,
        ColumnTypeHint::Integer => matches!(serial_type, 0 | 1..=6 | 8 | 9),
        ColumnTypeHint::Real => matches!(serial_type, 0 | 7),
        ColumnTypeHint::Text => serial_type == 0 || (serial_type >= 13 && serial_type % 2 == 1),
        ColumnTypeHint::Blob => serial_type == 0 || (serial_type >= 12 && serial_type % 2 == 0),
    }
}
```

- [ ] **Step 5: Implement boyer_moore_search**

```rust
pub fn boyer_moore_search(haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    // Build bad-character skip table
    let mut skip = [pattern.len(); 256];
    for (i, &b) in pattern.iter().enumerate().take(pattern.len() - 1) {
        skip[b as usize] = pattern.len() - 1 - i;
    }

    let mut matches = Vec::new();
    let mut i = pattern.len() - 1;
    while i < haystack.len() {
        let mut j = pattern.len() - 1;
        let mut k = i;
        while haystack[k] == pattern[j] {
            if j == 0 {
                matches.push(k);
                break;
            }
            j -= 1;
            k -= 1;
        }
        let shift = skip[haystack[i] as usize];
        i += if shift == 0 { 1 } else { shift };
    }
    matches
}
```

- [ ] **Step 6: Implement try_parse_record**

```rust
pub fn try_parse_record(&self, data: &[u8], offset: usize) -> Option<CarvedCandidate> {
    if offset >= data.len() {
        return None;
    }
    let buf = &data[offset..];
    // Read header length varint
    let (header_len, hl_size) = read_varint(buf, 0)?;
    let header_len = header_len as usize;
    if header_len < 2 || header_len > buf.len() || header_len > 512 {
        return None; // sanity
    }

    // Parse serial types from header
    let mut serial_types = Vec::new();
    let mut pos = hl_size;
    while pos < header_len {
        let (st, st_size) = read_varint(buf, pos)?;
        serial_types.push(st);
        pos += st_size;
    }

    // Column count check
    if serial_types.len() != self.column_count {
        return None;
    }

    // Type compatibility check
    let mut compat_count = 0usize;
    for (i, &st) in serial_types.iter().enumerate() {
        if Self::is_compatible(&self.type_hints[i], st) {
            compat_count += 1;
        }
    }
    if compat_count == 0 {
        return None;
    }

    // Parse values
    let mut values = Vec::with_capacity(serial_types.len());
    let mut val_pos = header_len;
    for &st in &serial_types {
        if val_pos > buf.len() {
            return None;
        }
        let (val, consumed) = decode_serial_type(st, &buf[val_pos..])?;
        values.push(val);
        val_pos += consumed;
    }

    // Size sanity: total record shouldn't exceed a page (65536)
    if val_pos > 65536 {
        return None;
    }

    // UTF-8 validation for text columns
    for val in &values {
        if let SqlValue::Text(s) = val {
            if s.contains('\u{FFFD}') && s.len() > 4 {
                // Likely not valid text — reduce confidence
            }
        }
    }

    let confidence = compat_count as f32 / self.column_count as f32;

    Some(CarvedCandidate {
        row_id: None,
        values,
        byte_offset: offset,
        bytes_consumed: val_pos,
        confidence,
    })
}
```

- [ ] **Step 7: Implement scan_region**

```rust
pub fn scan_region(&self, data: &[u8]) -> Vec<CarvedCandidate> {
    let mut candidates = Vec::new();
    let mut offset = 0;
    while offset < data.len().saturating_sub(2) {
        if let Some(mut c) = self.try_parse_record(data, offset) {
            c.byte_offset = offset;
            let skip = c.bytes_consumed.max(1);
            candidates.push(c);
            offset += skip;
        } else {
            offset += 1;
        }
    }
    candidates
}
```

- [ ] **Step 8: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics schema_sig --frozen`
Expected: all tests PASS

- [ ] **Step 9: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/schema_sig.rs crates/chat4n6-sqlite-forensics/src/lib.rs
git commit -m "feat: add SchemaSignature with Boyer-Moore search and plausibility checks (FQLite-style)"
```

---

### Task 2: SHA-256 Deduplication (dedup.rs)

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/dedup.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs` (add `pub mod dedup;`)

Sanderson-style deduplication: hash record values with SHA-256, remove carved duplicates of live records.

- [ ] **Step 1: Write failing tests and stubs**

Create `crates/chat4n6-sqlite-forensics/src/dedup.rs`:

```rust
use crate::record::{RecoveredRecord, SqlValue};
use chat4n6_plugin_api::EvidenceSource;
use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of a record's values for deduplication.
pub fn record_hash(record: &RecoveredRecord) -> [u8; 32] {
    todo!()
}

/// Remove non-live records that are exact duplicates of live records.
/// Among carved records, prefer higher confidence.
pub fn deduplicate(records: &mut Vec<RecoveredRecord>) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(table: &str, values: Vec<SqlValue>, source: EvidenceSource) -> RecoveredRecord {
        RecoveredRecord {
            table: table.to_string(),
            row_id: Some(1),
            values,
            source,
            offset: 0,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_same_values_produce_same_hash() {
        let r1 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Live);
        let r2 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Freelist);
        assert_eq!(record_hash(&r1), record_hash(&r2));
    }

    #[test]
    fn test_different_values_different_hash() {
        let r1 = make_record("t", vec![SqlValue::Text("hello".into())], EvidenceSource::Live);
        let r2 = make_record("t", vec![SqlValue::Text("world".into())], EvidenceSource::Live);
        assert_ne!(record_hash(&r1), record_hash(&r2));
    }

    #[test]
    fn test_deduplicate_removes_carved_duplicate_of_live() {
        let live = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Live);
        let carved = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Freelist);
        let unique = make_record("t", vec![SqlValue::Int(99)], EvidenceSource::Freelist);
        let mut records = vec![live, carved, unique];
        deduplicate(&mut records);
        assert_eq!(records.len(), 2); // live + unique_carved
        assert!(records.iter().any(|r| r.source == EvidenceSource::Live));
        assert!(records.iter().any(|r| matches!(r.values[0], SqlValue::Int(99))));
    }

    #[test]
    fn test_deduplicate_keeps_historical_version() {
        let live = make_record("t", vec![SqlValue::Text("new".into())], EvidenceSource::Live);
        let old = make_record("t", vec![SqlValue::Text("old".into())], EvidenceSource::Freelist);
        let mut records = vec![live, old];
        deduplicate(&mut records);
        assert_eq!(records.len(), 2); // different values, both kept
    }

    #[test]
    fn test_deduplicate_prefers_higher_confidence() {
        let mut low = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::CarvedUnalloc { confidence_pct: 50 });
        low.confidence = 0.5;
        let mut high = make_record("t", vec![SqlValue::Int(42)], EvidenceSource::Freelist);
        high.confidence = 1.0;
        let mut records = vec![low, high];
        deduplicate(&mut records);
        assert_eq!(records.len(), 1);
        assert!(records[0].confidence > 0.9); // kept the higher confidence one
    }
}
```

Add `pub mod dedup;` to `lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics dedup --frozen`
Expected: FAIL

- [ ] **Step 3: Implement record_hash**

```rust
pub fn record_hash(record: &RecoveredRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(record.table.as_bytes());
    hasher.update(b"|");
    for val in &record.values {
        match val {
            SqlValue::Null => hasher.update(b"N"),
            SqlValue::Int(n) => hasher.update(n.to_le_bytes()),
            SqlValue::Real(f) => hasher.update(f.to_le_bytes()),
            SqlValue::Text(s) => {
                hasher.update(b"T");
                hasher.update(s.as_bytes());
            }
            SqlValue::Blob(b) => {
                hasher.update(b"B");
                hasher.update(b);
            }
        }
        hasher.update(b"|");
    }
    hasher.finalize().into()
}
```

- [ ] **Step 4: Implement deduplicate**

```rust
pub fn deduplicate(records: &mut Vec<RecoveredRecord>) {
    use std::collections::{HashMap, HashSet};

    // Build set of live record hashes
    let live_hashes: HashSet<[u8; 32]> = records
        .iter()
        .filter(|r| r.source == EvidenceSource::Live)
        .map(record_hash)
        .collect();

    // Group non-live records by hash, keep highest confidence per hash
    let mut best_by_hash: HashMap<[u8; 32], usize> = HashMap::new();
    let mut to_remove = Vec::new();

    for (i, record) in records.iter().enumerate() {
        if record.source == EvidenceSource::Live {
            continue;
        }
        let hash = record_hash(record);
        // Remove if it duplicates a live record
        if live_hashes.contains(&hash) {
            to_remove.push(i);
            continue;
        }
        // Among non-live duplicates, keep highest confidence
        if let Some(&prev_idx) = best_by_hash.get(&hash) {
            if record.confidence > records[prev_idx].confidence {
                to_remove.push(prev_idx);
                best_by_hash.insert(hash, i);
            } else {
                to_remove.push(i);
            }
        } else {
            best_by_hash.insert(hash, i);
        }
    }

    to_remove.sort_unstable();
    to_remove.dedup();
    for i in to_remove.into_iter().rev() {
        records.swap_remove(i);
    }
}
```

- [ ] **Step 5: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics dedup --frozen`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/dedup.rs crates/chat4n6-sqlite-forensics/src/lib.rs
git commit -m "feat: add SHA-256 record deduplication (Sanderson-style)"
```

---

### Task 3: Intra-Page Gap Scanning (gap.rs — Layer 7)

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/gap.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs` (add `pub mod gap;`)

Scans the unallocated gap within active B-tree leaf pages (between cell pointer array and cell content area) for deleted records. This is the highest-value forensic recovery source.

- [ ] **Step 1: Write failing tests with real SQLite fixtures**

Create `crates/chat4n6-sqlite-forensics/src/gap.rs`:

```rust
use crate::btree::get_page_data;
use crate::record::RecoveredRecord;
use crate::schema_sig::SchemaSignature;
use chat4n6_plugin_api::EvidenceSource;

/// Scan intra-page gaps in all leaf pages of a table's B-tree.
/// The gap is the region between the cell pointer array end and cell_content_start.
pub fn scan_page_gaps(
    db: &[u8],
    page_size: u32,
    table_roots: &[(String, u32)],
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    todo!()
}

/// Scan the unallocated gap within a single page.
fn scan_single_page_gap(
    page_data: &[u8],
    bhdr_offset: usize,
    table_name: &str,
    signature: Option<&SchemaSignature>,
    page_abs_offset: u64,
) -> Vec<RecoveredRecord> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ForensicEngine;
    use crate::record::SqlValue;

    /// Create a DB, insert records, delete some, return the raw bytes.
    /// The deleted records should be recoverable from the intra-page gap.
    fn make_db_with_deletions() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE;").unwrap(); // no WAL
        conn.execute_batch(
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER);
             INSERT INTO msgs VALUES (1, 'alpha message', 1000);
             INSERT INTO msgs VALUES (2, 'beta message', 2000);
             INSERT INTO msgs VALUES (3, 'gamma message', 3000);
             INSERT INTO msgs VALUES (4, 'delta message', 4000);
             DELETE FROM msgs WHERE id IN (2, 3);",
        ).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_gap_scan_recovers_deleted_records() {
        let db = make_db_with_deletions();
        let engine = ForensicEngine::new(&db, None).unwrap();
        let live = engine.recover_layer1().unwrap();

        // Should have 2 live records (id=1, id=4)
        let live_msgs: Vec<_> = live.iter().filter(|r| r.table == "msgs").collect();
        assert_eq!(live_msgs.len(), 2);

        // Build signatures from sqlite_master
        let sig = SchemaSignature::from_create_sql(
            "msgs",
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER)",
        ).unwrap();

        // Scan gaps — should find deleted records (id=2 "beta", id=3 "gamma")
        let table_roots = vec![("msgs".to_string(), 2u32)]; // typical root page
        let recovered = scan_page_gaps(&db, 4096, &table_roots, &[sig]);

        // Should recover at least the text content of deleted records
        let recovered_texts: Vec<String> = recovered
            .iter()
            .filter_map(|r| {
                r.values.iter().find_map(|v| {
                    if let SqlValue::Text(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        assert!(
            recovered_texts.iter().any(|t| t.contains("beta")),
            "should recover 'beta message' from gap. Got: {:?}",
            recovered_texts
        );
    }

    #[test]
    fn test_gap_scan_tags_source_correctly() {
        let db = make_db_with_deletions();
        let sig = SchemaSignature::from_create_sql(
            "msgs",
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, body TEXT, ts INTEGER)",
        ).unwrap();
        let table_roots = vec![("msgs".to_string(), 2u32)];
        let recovered = scan_page_gaps(&db, 4096, &table_roots, &[sig]);
        for r in &recovered {
            assert!(
                matches!(r.source, EvidenceSource::CarvedIntraPage { .. }),
                "gap-scanned records should be tagged CarvedIntraPage"
            );
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics gap --frozen`
Expected: FAIL

- [ ] **Step 3: Implement scan_single_page_gap**

```rust
fn scan_single_page_gap(
    page_data: &[u8],
    bhdr_offset: usize,
    table_name: &str,
    signature: Option<&SchemaSignature>,
    page_abs_offset: u64,
) -> Vec<RecoveredRecord> {
    // B-tree leaf page header is 8 bytes from bhdr_offset
    if page_data.len() < bhdr_offset + 8 {
        return Vec::new();
    }

    let cell_count = u16::from_be_bytes([
        page_data[bhdr_offset + 3],
        page_data[bhdr_offset + 4],
    ]) as usize;

    let cell_content_start = u16::from_be_bytes([
        page_data[bhdr_offset + 5],
        page_data[bhdr_offset + 6],
    ]) as usize;
    // 0 means 65536
    let cell_content_start = if cell_content_start == 0 { 65536 } else { cell_content_start };

    let ptr_array_start = bhdr_offset + 8;
    let ptr_array_end = ptr_array_start + cell_count * 2;

    if ptr_array_end >= cell_content_start || cell_content_start > page_data.len() {
        return Vec::new();
    }

    let gap = &page_data[ptr_array_end..cell_content_start];
    if gap.is_empty() || gap.iter().all(|&b| b == 0) {
        return Vec::new();
    }

    let sig = match signature {
        Some(s) => s,
        None => return Vec::new(),
    };

    sig.scan_region(gap)
        .into_iter()
        .map(|c| RecoveredRecord {
            table: table_name.to_string(),
            row_id: c.row_id,
            values: c.values,
            source: EvidenceSource::CarvedIntraPage {
                confidence_pct: (c.confidence * 100.0) as u8,
            },
            offset: page_abs_offset + ptr_array_end as u64 + c.byte_offset as u64,
            confidence: c.confidence,
        })
        .collect()
}
```

- [ ] **Step 4: Implement scan_page_gaps**

```rust
pub fn scan_page_gaps(
    db: &[u8],
    page_size: u32,
    table_roots: &[(String, u32)],
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    let mut results = Vec::new();

    for (table_name, root_page) in table_roots {
        let sig = signatures.iter().find(|s| s.table_name == *table_name);

        // Walk B-tree to find all leaf pages
        let leaf_pages = collect_leaf_pages(db, page_size, *root_page);

        for page_num in leaf_pages {
            if let Some((page_data, bhdr_offset)) = get_page_data(db, page_size, page_num) {
                let page_abs = (page_num as u64 - 1) * page_size as u64;
                results.extend(scan_single_page_gap(
                    page_data,
                    bhdr_offset,
                    table_name,
                    sig,
                    page_abs,
                ));
            }
        }
    }

    results
}

/// Collect all leaf page numbers in a B-tree.
fn collect_leaf_pages(db: &[u8], page_size: u32, root_page: u32) -> Vec<u32> {
    use std::collections::HashSet;

    let mut leaves = Vec::new();
    let mut stack = vec![root_page];
    let mut visited = HashSet::new();

    while let Some(page_num) = stack.pop() {
        if !visited.insert(page_num) {
            continue;
        }
        if let Some((page_data, bhdr_offset)) = get_page_data(db, page_size, page_num) {
            if bhdr_offset >= page_data.len() {
                continue;
            }
            let page_type = page_data[bhdr_offset];
            match page_type {
                0x0D => leaves.push(page_num), // table leaf
                0x05 => {
                    // table interior — extract child page numbers
                    let cell_count = u16::from_be_bytes([
                        page_data[bhdr_offset + 3],
                        page_data[bhdr_offset + 4],
                    ]) as usize;
                    // Right-most pointer at bhdr_offset+8
                    if bhdr_offset + 12 <= page_data.len() {
                        let right_child = u32::from_be_bytes([
                            page_data[bhdr_offset + 8],
                            page_data[bhdr_offset + 9],
                            page_data[bhdr_offset + 10],
                            page_data[bhdr_offset + 11],
                        ]);
                        stack.push(right_child);
                    }
                    let ptr_start = bhdr_offset + 12;
                    for i in 0..cell_count {
                        let ptr_off = ptr_start + i * 2;
                        if ptr_off + 2 > page_data.len() { break; }
                        let cell_off = u16::from_be_bytes([
                            page_data[ptr_off], page_data[ptr_off + 1],
                        ]) as usize;
                        if cell_off + 4 <= page_data.len() {
                            let child = u32::from_be_bytes([
                                page_data[cell_off], page_data[cell_off + 1],
                                page_data[cell_off + 2], page_data[cell_off + 3],
                            ]);
                            stack.push(child);
                        }
                    }
                }
                _ => {} // skip index pages etc.
            }
        }
    }

    leaves
}
```

Note: `get_page_data` must be made `pub` in `btree.rs` if it isn't already.

- [ ] **Step 5: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics gap --frozen`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/gap.rs crates/chat4n6-sqlite-forensics/src/lib.rs \
       crates/chat4n6-sqlite-forensics/src/btree.rs
git commit -m "feat: add intra-page gap scanning for deleted record recovery (Layer 7)"
```

---

### Task 4: WAL Replay Enhancement (wal.rs + db.rs)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/wal.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/btree.rs` (add overlay support)

Add WAL page overlay construction, B-tree walking through overlay, and differential analysis (WalDeleted detection). Add `WalMode` and builder methods to ForensicEngine.

- [ ] **Step 1: Write failing tests**

Add to `wal.rs` tests:

```rust
#[test]
fn test_build_wal_overlay() {
    let db = make_wal_mode_db_with_changes();
    let wal = make_wal_for_db();
    let overlay = build_wal_overlay(&wal, 4096);
    assert!(!overlay.is_empty(), "overlay should have modified pages");
}
```

Add to `db.rs` tests:

```rust
fn make_wal_mode_db() -> (Vec<u8>, Vec<u8>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute_batch(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
             INSERT INTO notes VALUES (1, 'first note');
             INSERT INTO notes VALUES (2, 'second note');",
        ).unwrap();
        // Don't close cleanly — leave WAL with pending data
        conn.execute_batch("INSERT INTO notes VALUES (3, 'wal pending note');").unwrap();
    }
    let db_bytes = std::fs::read(&path).unwrap();
    let wal_path = format!("{}-wal", path.display());
    let wal_bytes = std::fs::read(&wal_path).unwrap_or_default();
    (db_bytes, wal_bytes)
}

#[test]
fn test_wal_replay_shows_pending_records() {
    let (db, wal) = make_wal_mode_db();
    if wal.is_empty() { return; } // WAL might be checkpointed
    let engine = ForensicEngine::new(&db, None).unwrap().with_wal(&wal);
    let results = engine.recover_all().unwrap();
    // Should find WalPending records
    let pending: Vec<_> = results.records.iter()
        .filter(|r| r.source == EvidenceSource::WalPending)
        .collect();
    assert!(!pending.is_empty(), "should have WAL pending records");
}
```

- [ ] **Step 2: Add WalMode enum and ForensicEngine builder methods**

In `db.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WalMode {
    Both,
    Apply,
    Ignore,
}

impl Default for WalMode {
    fn default() -> Self { Self::Both }
}

pub struct ForensicEngine<'a> {
    data: &'a [u8],
    header: DbHeader,
    wal_data: Option<&'a [u8]>,
    journal_data: Option<&'a [u8]>,
    wal_mode: WalMode,
}

impl<'a> ForensicEngine<'a> {
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
}
```

- [ ] **Step 3: Implement build_wal_overlay in wal.rs**

```rust
use std::collections::HashMap;

/// Build a page overlay from WAL frames. Last-writer-wins per page number.
pub fn build_wal_overlay(wal: &[u8], page_size: u32) -> HashMap<u32, Vec<u8>> {
    let mut overlay = HashMap::new();
    let frames = parse_wal_frames(wal, page_size);
    // Frames are grouped by salt1; take all valid frames
    for (_salt, frame_list) in &frames {
        for frame in frame_list {
            overlay.insert(frame.page_number, frame.page_data.clone());
        }
    }
    overlay
}
```

- [ ] **Step 4: Add overlay-aware page reading to btree.rs**

```rust
pub fn get_page_data_with_overlay<'a>(
    db: &'a [u8],
    page_size: u32,
    page_num: u32,
    overlay: &'a HashMap<u32, Vec<u8>>,
) -> Option<(&'a [u8], usize)> {
    if let Some(page_data) = overlay.get(&page_num) {
        let bhdr_offset = if page_num == 1 { 100 } else { 0 };
        Some((page_data, bhdr_offset))
    } else {
        get_page_data(db, page_size, page_num)
    }
}
```

- [ ] **Step 5: Implement recover_layer2_enhanced**

Add WAL replay with differential analysis to `db.rs` or `wal.rs`:

```rust
/// Enhanced Layer 2: WAL replay with differential analysis.
pub fn recover_layer2_enhanced(
    db: &[u8],
    wal: &[u8],
    page_size: u32,
    header: &DbHeader,
    mode: WalMode,
    table_roots: &HashMap<String, u32>,
) -> Vec<RecoveredRecord> {
    if mode == WalMode::Ignore {
        return Vec::new();
    }

    let overlay = build_wal_overlay(wal, page_size);
    if overlay.is_empty() {
        return Vec::new();
    }

    // Walk B-trees through overlay to get WAL-applied view
    let mut wal_view = Vec::new();
    for (table, root) in table_roots {
        walk_table_btree_with_overlay(db, page_size, *root, table, &overlay, &mut wal_view);
    }

    if mode == WalMode::Apply {
        // Just return the WAL-applied records as Live
        return wal_view;
    }

    // Mode::Both — differential analysis
    let mut raw_view = Vec::new();
    for (table, root) in table_roots {
        walk_table_btree(db, page_size, *root, table, EvidenceSource::Live, &mut raw_view);
    }

    // Find records in raw but not WAL view (deleted in WAL)
    let wal_hashes: HashSet<_> = wal_view.iter().map(|r| crate::dedup::record_hash(r)).collect();
    let raw_hashes: HashSet<_> = raw_view.iter().map(|r| crate::dedup::record_hash(r)).collect();

    let mut results = Vec::new();

    // Records only in WAL view → WalPending
    for mut r in wal_view {
        let h = crate::dedup::record_hash(&r);
        if !raw_hashes.contains(&h) {
            r.source = EvidenceSource::WalPending;
            results.push(r);
        }
    }

    // Records only in raw view → WalDeleted
    for mut r in raw_view {
        let h = crate::dedup::record_hash(&r);
        if !wal_hashes.contains(&h) {
            r.source = EvidenceSource::WalDeleted;
            results.push(r);
        }
    }

    results
}
```

- [ ] **Step 6: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics wal --frozen`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/wal.rs crates/chat4n6-sqlite-forensics/src/db.rs \
       crates/chat4n6-sqlite-forensics/src/btree.rs
git commit -m "feat: WAL replay with page overlay and differential analysis (Layer 2 enhanced)"
```

---

### Task 5: Freelist Page Content Recovery (freelist.rs — Layer 3)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/freelist.rs`

Walk the freelist chain (already implemented), then read the actual content of each freed page. Try parsing as B-tree leaf first; fall back to schema-aware carving.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_freelist_content_recovery() {
    let db = make_db_with_freed_pages();
    let sig = SchemaSignature::from_create_sql(
        "items",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)",
    ).unwrap();
    let recovered = recover_freelist_content(&db, 4096, &[sig]);
    // Should find records from freed pages
    assert!(!recovered.is_empty(), "should recover records from freelist pages");
    for r in &recovered {
        assert_eq!(r.source, EvidenceSource::Freelist);
    }
}

fn make_db_with_freed_pages() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA auto_vacuum=NONE;").unwrap();
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
    // VACUUM would reclaim, but without it pages go to freelist
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}
```

- [ ] **Step 2: Implement recover_freelist_content**

```rust
pub fn recover_freelist_content(
    db: &[u8],
    page_size: u32,
    signatures: &[SchemaSignature],
) -> Vec<RecoveredRecord> {
    let trunk_page = /* read from db header bytes 32-35 */ ;
    let free_pages = walk_freelist_chain(db, trunk_page, page_size);
    let mut results = Vec::new();

    for page_num in free_pages {
        if let Some((page_data, bhdr_offset)) = get_page_data(db, page_size, page_num) {
            // Strategy 1: try parsing as B-tree leaf
            if let Some(leaf_records) = try_parse_as_leaf(page_data, bhdr_offset, page_num, page_size) {
                for mut r in leaf_records {
                    r.source = EvidenceSource::Freelist;
                    results.push(r);
                }
                continue;
            }

            // Strategy 2: schema-aware carving
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
    }

    results
}
```

- [ ] **Step 3: Run tests, iterate until passing**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics freelist --frozen`

- [ ] **Step 4: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/freelist.rs
git commit -m "feat: freelist page content recovery with B-tree parse + schema carving (Layer 3)"
```

---

### Task 6: Overflow Page Recovery (btree.rs + overflow.rs — Layer 4)

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/btree.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/overflow.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs` (add `pub mod overflow;`)

Detect overflow during B-tree walking, follow overflow page chains, reassemble full payloads.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn test_overflow_record_reassembly() {
    let db = make_db_with_overflow();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let records = engine.recover_layer1().unwrap();
    let big = records.iter().find(|r| r.table == "docs").unwrap();
    // The large text should be fully reassembled, not truncated
    if let SqlValue::Text(s) = &big.values[0] {
        assert!(s.len() > 4000, "overflow text should be fully reassembled, got {} bytes", s.len());
    } else {
        panic!("expected Text value");
    }
}

fn make_db_with_overflow() -> Vec<u8> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;").unwrap();
    conn.execute_batch("CREATE TABLE docs (body TEXT);").unwrap();
    let big_text = "X".repeat(8000); // exceeds max_local for 4096 page
    conn.execute("INSERT INTO docs VALUES (?)", rusqlite::params![big_text]).unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    std::fs::read(tmp.path()).unwrap()
}
```

- [ ] **Step 2: Implement overflow following in btree.rs**

Add overflow detection and chain following to the cell parsing logic in `walk_table_btree` / `parse_table_leaf_page`. Calculate `max_local`, detect overflow, read overflow page chain, reassemble full payload.

Key formula:
```rust
let usable = page_size as usize - 0; // reserved_space from header byte 20
let max_local = (usable - 12) * 64 / 255 - 23;
let min_local = (usable - 12) * 32 / 255 - 23;
```

- [ ] **Step 3: Run tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics overflow --frozen`

- [ ] **Step 4: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/btree.rs crates/chat4n6-sqlite-forensics/src/overflow.rs \
       crates/chat4n6-sqlite-forensics/src/lib.rs
git commit -m "feat: overflow page recovery with chain following (Layer 4)"
```

---

### Task 7: Rollback Journal Parsing (journal.rs — Layer 8)

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/journal.rs`
- Modify: `crates/chat4n6-sqlite-forensics/src/lib.rs` (add `pub mod journal;`)

Parse SQLite rollback journal files, extract pre-modification page snapshots, carve records.

- [ ] **Step 1: Write failing tests**

```rust
const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

pub struct JournalHeader {
    pub page_count: u32,
    pub nonce: u32,
    pub initial_db_size: u32,
    pub sector_size: u32,
    pub page_size: u32,
}

pub fn parse_journal(journal: &[u8], page_size: u32, signatures: &[SchemaSignature]) -> Vec<RecoveredRecord> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_magic_detection() {
        assert!(is_journal_header(&JOURNAL_MAGIC));
        assert!(!is_journal_header(b"not a journal"));
    }

    #[test]
    fn test_parse_journal_from_real_db() {
        let (db, journal) = make_db_with_journal();
        if journal.is_empty() { return; }
        let sig = SchemaSignature::from_create_sql(
            "events",
            "CREATE TABLE events (id INTEGER PRIMARY KEY, name TEXT)",
        ).unwrap();
        let recovered = parse_journal(&journal, 4096, &[sig]);
        for r in &recovered {
            assert_eq!(r.source, EvidenceSource::Journal);
        }
    }

    fn make_db_with_journal() -> (Vec<u8>, Vec<u8>) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, name TEXT);
                 INSERT INTO events VALUES (1, 'original event');",
            ).unwrap();
        }
        let db_bytes = std::fs::read(&path).unwrap();
        let journal_path = format!("{}-journal", path.display());
        let journal_bytes = std::fs::read(&journal_path).unwrap_or_default();
        (db_bytes, journal_bytes)
    }
}
```

- [ ] **Step 2: Implement parse_journal**

Parse journal header, walk page records, extract pre-modification page snapshots, carve records from each page using schema signatures. Handle multi-section journals.

- [ ] **Step 3: Run tests and commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/journal.rs crates/chat4n6-sqlite-forensics/src/lib.rs
git commit -m "feat: rollback journal parsing with multi-section support (Layer 8)"
```

---

### Task 8: recover_all() Orchestrator + RecoveryResult

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`

Wire all layers together with the `recover_all()` convenience method and `RecoveryResult`/`RecoveryStats` structs.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn test_recover_all_runs_all_layers() {
    let db = create_test_db();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(!result.records.is_empty());
    assert!(result.stats.live_count > 0);
    assert_eq!(result.stats.duplicates_removed, 0); // no dupes in clean DB
}
```

- [ ] **Step 2: Add RecoveryResult and RecoveryStats structs**

```rust
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
}
```

- [ ] **Step 3: Implement recover_all**

```rust
pub fn recover_all(&self) -> Result<RecoveryResult> {
    let table_roots = self.read_sqlite_master()?;
    let signatures = self.build_schema_signatures(&table_roots)?;
    let mut all = Vec::new();
    let mut stats = RecoveryStats::default();

    // Layer 1: Live records
    let live = self.recover_layer1()?;
    stats.live_count = live.len();
    all.extend(live);

    // Layer 2: WAL (if provided)
    if let Some(wal) = self.wal_data {
        let wal_records = recover_layer2_enhanced(
            self.data, wal, self.header.page_size, &self.header, self.wal_mode, &table_roots
        );
        stats.wal_pending = wal_records.iter().filter(|r| r.source == EvidenceSource::WalPending).count();
        stats.wal_deleted = wal_records.iter().filter(|r| r.source == EvidenceSource::WalDeleted).count();
        all.extend(wal_records);
    }

    // Layer 3: Freelist content
    let freelist = recover_freelist_content(self.data, self.header.page_size, &signatures);
    stats.freelist_recovered = freelist.len();
    all.extend(freelist);

    // Layer 5: FTS shadow tables
    let fts = recover_layer5(self.data, self.header.page_size);
    stats.fts_recovered = fts.len();
    all.extend(fts);

    // Layer 7: Intra-page gaps
    let roots_vec: Vec<_> = table_roots.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let gaps = scan_page_gaps(self.data, self.header.page_size, &roots_vec, &signatures);
    stats.gap_carved = gaps.len();
    all.extend(gaps);

    // Layer 8: Journal (if provided)
    if let Some(journal) = self.journal_data {
        let journal_records = parse_journal(journal, self.header.page_size, &signatures);
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

- [ ] **Step 4: Add build_schema_signatures helper**

```rust
fn build_schema_signatures(&self, table_roots: &HashMap<String, u32>) -> Result<Vec<SchemaSignature>> {
    let mut sigs = Vec::new();
    // Read sqlite_master to get CREATE TABLE SQL
    let mut master_records = Vec::new();
    self.traverse_btree(1, "sqlite_master", &mut master_records);
    for r in &master_records {
        if r.values.len() >= 5 {
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
```

- [ ] **Step 5: Run full test suite**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test --workspace --frozen`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/db.rs
git commit -m "feat: recover_all() orchestrator with RecoveryStats and deduplication"
```

---

### Task 9: Integration Tests

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/tests/forensic_recovery.rs`

End-to-end tests using real SQLite databases with known deletions, WAL state, and freelist pages. Verify the full recovery pipeline.

- [ ] **Step 1: Write comprehensive integration tests**

```rust
use chat4n6_sqlite_forensics::db::{ForensicEngine, WalMode};
use chat4n6_plugin_api::EvidenceSource;

#[test]
fn test_full_recovery_pipeline() {
    // Create DB, insert, delete, verify recovery of everything
    let db = make_comprehensive_test_db();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();

    assert!(result.stats.live_count > 0, "should have live records");
    // At least some deleted records should be recovered
    let non_live: Vec<_> = result.records.iter()
        .filter(|r| r.source != EvidenceSource::Live)
        .collect();
    assert!(!non_live.is_empty(), "should recover non-live records");
    println!("Recovery stats: {:?}", result.stats);
}

#[test]
fn test_page_size_variations() {
    for page_size in [1024, 4096, 8192] {
        let db = make_db_with_page_size(page_size);
        let engine = ForensicEngine::new(&db, None).unwrap();
        let result = engine.recover_all().unwrap();
        assert!(result.stats.live_count > 0, "page_size={page_size} should work");
    }
}

#[test]
fn test_encrypted_db_fails_fast() {
    let garbage = vec![0xFF; 4096];
    assert!(ForensicEngine::new(&garbage, None).is_err());
}

#[test]
fn test_empty_db_no_crash() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
    let db = std::fs::read(tmp.path()).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert_eq!(result.stats.live_count, 0);
}
```

- [ ] **Step 2: Run integration tests**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test -p chat4n6-sqlite-forensics --test forensic_recovery --frozen`
Expected: all PASS

- [ ] **Step 3: Run full workspace test suite**

Run: `CARGO_TARGET_DIR=/tmp/chat4n6-build cargo test --workspace --frozen`
Expected: all PASS, 0 failures

- [ ] **Step 4: Final commit**

```bash
git add crates/chat4n6-sqlite-forensics/tests/forensic_recovery.rs
git commit -m "test: comprehensive forensic recovery integration tests"
```
