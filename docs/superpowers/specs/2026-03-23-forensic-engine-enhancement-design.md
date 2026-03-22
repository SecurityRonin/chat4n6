# Forensic Engine Enhancement Design

**Date**: 2026-03-23
**Crate**: `chat4n6-sqlite-forensics`
**Status**: Approved

## Overview

Comprehensive enhancement of the SQLite forensic recovery engine, drawing from
FQLite (schema-aware heuristic carving), Sanderson Forensic Toolkit (three-type
deleted record recovery with deduplication), and Belkasoft (WAL replay, freelist
content recovery). Implements all missing recovery layers to achieve
state-of-the-art SQLite forensic capability.

## Architecture: Layer-by-Layer Pipeline

Extends the existing `recover_layer{N}()` pattern. Each layer runs independently,
returns `Vec<RecoveredRecord>`, and `recover_all()` orchestrates them with
deduplication.

```
ForensicEngine::new(db, wal?, journal?)
  +-- recover_layer1()          Live B-tree walking              [existing]
  +-- recover_layer2_enhanced() WAL replay + delta comparison    [enhanced]
  +-- recover_layer3()          Freelist page content recovery   [NEW]
  +-- recover_layer4()          Overflow page reassembly         [NEW]
  +-- recover_layer5()          FTS shadow tables                [existing]
  +-- recover_layer6()          Unallocated space carving        [existing, enhanced]
  +-- recover_layer7()          Intra-page gap scanning          [NEW]
  +-- recover_layer8()          Rollback journal parsing         [NEW]
  +-- recover_all(WalMode)      All layers + deduplication
```

### WalMode

Default behavior: run both WAL-applied and raw DB passes (`Both`). Caller may
override for performance.

```rust
pub enum WalMode {
    Both,    // Default: both passes, maximum forensic value
    Apply,   // WAL-applied view only (current state as SQLite sees it)
    Ignore,  // Raw DB only (reveals pre-WAL records)
}
```

## Layer 2 Enhanced: WAL Replay

### Current State
Parses WAL frames and reports delta status but never applies frames to
reconstruct the database state.

### Design

**Phase A - Page Overlay Construction:**
- Parse WAL header (32 bytes): magic, format version, page_size, checkpoint_seq,
  salt1, salt2, checksum1, checksum2
- Walk frames (24-byte header + page_size data each): page_number, db_size_after,
  checkpoint_seq, salt1, salt2, frame_checksum
- Validate frame checksums (cumulative, per SQLite spec)
- Group by salt1 (transaction boundary)
- Build `HashMap<u32, Vec<u8>>` — last-writer-wins per page number
- Preserve all historical frames for timeline reconstruction

**Phase B - Overlay B-tree Walking:**
- `get_page_with_overlay()` checks overlay first, falls back to main DB
- Walk all table B-trees using overlaid pages
- Tag records as `EvidenceSource::Live`

**Phase C - Differential Analysis:**
- Compare WAL-applied record set vs raw DB record set
- Records in raw but absent from WAL view: `EvidenceSource::WalDeleted`
- Records in WAL view but absent from raw: `EvidenceSource::WalPending`
- Records present in both with different values: both versions retained,
  WAL version tagged `WalPending`, raw version tagged `WalHistoric`

**Multi-transaction timeline:**
- Group frames by salt1 to identify transaction boundaries
- Optionally reconstruct DB state at each transaction checkpoint
- Enables timeline analysis ("this record was modified in transaction N")

**Checksum validation:**
- Verify cumulative frame checksums per SQLite WAL spec
- Invalid frames logged and skipped (do not fail the whole recovery)

### New EvidenceSource Variant

```rust
pub enum EvidenceSource {
    Live,
    WalPending,
    WalHistoric,
    WalDeleted,     // NEW: in raw DB but deleted in WAL-applied view
    Freelist,
    FtsOnly,
    CarvedUnalloc { confidence_pct: u8 },
    CarvedDb,
    Journal,        // NEW: from rollback journal
}
```

## Layer 3: Freelist Page Content Recovery

### Current State
`walk_freelist_chain()` traverses trunk/leaf chain and lists freed page numbers.
Page content is never read or carved.

### Design

**Two-strategy recovery per freed page:**

1. **Try B-tree parse**: Freed pages often retain intact B-tree headers because
   SQLite only adds them to the free chain without zeroing content. Parse as a
   leaf page; if cell pointer array and records parse cleanly, extract all records.
   Tag as `EvidenceSource::Freelist`, confidence 1.0.

2. **Schema-aware carving fallback**: If B-tree parse fails (header corrupted),
   carve the entire page using `SchemaSignature` patterns. Confidence based on
   plausibility score.

**Freelist structure (from SQLite docs):**
- Trunk page: `[next_trunk:u32][leaf_count:u32][leaf_pages:u32...]`
- Leaf pages: simply listed by trunk; no internal structure (full pages of data)
- Trunk pages themselves may also contain records in their unused space

## Layer 4: Overflow Page Recovery

### Current State
Not implemented. Records with payloads exceeding `max_local` are silently
truncated.

### Design

**Overflow detection during B-tree walking:**
- Calculate `max_local = (usable_size - 12) * 64 / 255 - 23`
- If cell payload_size > bytes available in the local cell, last 4 bytes of
  local storage = first overflow page number
- Follow chain: each overflow page has `[next_overflow:u32][content...]`
- Reassemble full payload, re-parse record with complete data

**Orphaned overflow recovery (Layer 4 proper):**
- Scan for overflow pages not referenced by any live cell
- Overflow pages have a distinctive structure: `[next:u32]` followed by data
- Attempt to reassemble chains and parse as record payloads
- Tag as `EvidenceSource::CarvedUnalloc` with lower confidence

**Integration with Layer 1:**
- `walk_table_btree()` gains overflow-following capability
- Returns complete records instead of truncated ones
- No change to caller API

## Layer 7: Intra-Page Gap Scanning

### Current State
Not implemented. The gap between the cell pointer array and cell content area
start is never examined.

### Design

**Page layout (per SQLite file format):**
```
[B-tree header (8 or 12 bytes)]
[Cell pointer array (2 bytes per cell)]
[--- UNALLOCATED GAP ---]        <-- deleted records hide here
[Cell content area]
[Page end]
```

When SQLite deletes a record, it either:
1. Adds it to the freeblock chain (first 4 bytes become `[next:u16][size:u16]`)
2. Adjusts `cell_content_start` downward, leaving the deleted record in the gap

**Algorithm:**
1. For each leaf page in every table B-tree:
   - Calculate gap boundaries: `[ptr_array_end .. cell_content_start]`
   - Also scan freeblock chain regions (already partially implemented)
2. Carve the gap using the table's `SchemaSignature` (we know which table owns
   each page from the B-tree walk)
3. Validate candidates with plausibility checks
4. Deduplicate against live records from the same page

**This is the single most productive recovery source** per Sanderson's research.
Most recently deleted records are found here because the page hasn't been reused
yet.

## FQLite-Style Schema-Aware Carving

Shared infrastructure used by Layers 3, 6, and 7.

### SchemaSignature

```rust
pub struct SchemaSignature {
    pub table_name: String,
    pub column_count: usize,
    pub type_hints: Vec<ColumnTypeHint>,
    pub patterns: Vec<SerialTypePattern>,
}

pub enum ColumnTypeHint {
    Integer,    // serial types 1-6, 8, 9
    Real,       // serial type 7
    Text,       // serial types >= 13, odd
    Blob,       // serial types >= 12, even
    Null,       // serial type 0
    Any,        // any serial type (untyped column)
}

pub struct SerialTypePattern {
    pub bytes: Vec<u8>,           // compiled pattern for matching
    pub skip_table: [usize; 256], // Boyer-Moore bad character table
}
```

### Pattern Generation

From `CREATE TABLE t(a INTEGER, b TEXT, c BLOB)`:
1. Parse SQL to extract column types
2. Map each column to possible serial type ranges
3. Generate candidate header byte sequences (header_length varint + serial types)
4. Compile Boyer-Moore skip tables for each pattern

### Boyer-Moore Search

```rust
fn boyer_moore_search(haystack: &[u8], pattern: &SerialTypePattern) -> Vec<usize>
```

Scans raw bytes for matches. Much faster than byte-by-byte comparison for
repeated searches across large regions.

### Plausibility Checks (from FQLite paper)

Applied to every candidate match to reduce false positives:

1. **Column count**: parsed header must have correct number of serial types
2. **Type compatibility**: serial types must be compatible with declared column
   types (e.g., TEXT column shouldn't have integer serial type 4)
3. **Size sanity**: total record size (header + payload) must not exceed page size
4. **Varint validity**: header_length and payload_length varints must parse
   successfully and agree
5. **UTF-8 validation**: TEXT values must be valid UTF-8
6. **Row ID plausibility**: if parseable, row_id should be positive and
   reasonable (< 2^48)

Confidence score = (checks passed / total checks) * base_confidence_for_mode

## Sanderson-Style Deduplication

Final pass after all layers complete.

```rust
fn deduplicate(records: &mut Vec<RecoveredRecord>) {
    // 1. Compute SHA-256 of each record's serialized values
    // 2. Build HashSet of live record hashes (EvidenceSource::Live)
    // 3. Remove any non-live record whose hash matches a live record
    //    (it's a duplicate, not a recovered deletion)
    // 4. Keep non-live records with DIFFERENT values (historical versions)
    // 5. Among carved records, prefer higher confidence
}
```

Uses SHA-256 (not MD5) because this is a forensic tool.

## Layer 8: Rollback Journal Parsing

### Design

Parse SQLite rollback journal files (`.db-journal`).

**Journal structure:**
- Header (28 bytes): magic (`0xd9d505f920a163d7`), page_count, nonce,
  initial_db_size, sector_size, page_size
- Records: `[page_number:u32][page_data:page_size bytes][checksum:u32]`

**Recovery:**
- Each journal page is a **pre-modification snapshot** (data BEFORE the
  transaction that was in progress)
- Parse each journal page as a B-tree leaf page
- Extract records, tag as `EvidenceSource::Journal`
- These represent the state before an uncommitted transaction

**Checksum validation:**
- Verify per-page checksums using the journal header nonce
- Invalid pages logged and skipped

## ForensicEngine API Changes

```rust
impl<'a> ForensicEngine<'a> {
    // Enhanced constructor
    pub fn new(data: &'a [u8], timezone_offset: Option<i32>) -> Result<Self>;
    pub fn with_wal(self, wal_data: &'a [u8]) -> Self;
    pub fn with_journal(self, journal_data: &'a [u8]) -> Self;
    pub fn with_wal_mode(self, mode: WalMode) -> Self;

    // Existing layers (unchanged API)
    pub fn recover_layer1(&self) -> Result<Vec<RecoveredRecord>>;
    pub fn recover_layer5(&self) -> Result<Vec<RecoveredRecord>>;
    pub fn recover_layer6(&self) -> Result<Vec<RecoveredRecord>>;

    // Enhanced layer
    pub fn recover_layer2_enhanced(&self) -> Result<Vec<RecoveredRecord>>;

    // New layers
    pub fn recover_layer3(&self) -> Result<Vec<RecoveredRecord>>;
    pub fn recover_layer4(&self) -> Result<Vec<RecoveredRecord>>;
    pub fn recover_layer7(&self) -> Result<Vec<RecoveredRecord>>;
    pub fn recover_layer8(&self) -> Result<Vec<RecoveredRecord>>;

    // Convenience: runs all layers + dedup
    pub fn recover_all(&self) -> Result<RecoveryResult>;

    // Schema signature building
    pub fn build_schema_signatures(&self) -> Result<Vec<SchemaSignature>>;
}

pub struct RecoveryResult {
    pub records: Vec<RecoveredRecord>,
    pub stats: RecoveryStats,
}

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

## File Changes

| File | Change |
|------|--------|
| `db.rs` | Add WAL/journal fields, `with_wal()`, `with_journal()`, `with_wal_mode()`, `recover_all()` |
| `wal.rs` | Add `build_wal_overlay()`, `WalMode`, checksum validation, overlay B-tree walking |
| `freelist.rs` | Add `recover_layer3()` — content recovery from freed pages |
| `btree.rs` | Add overflow page following in `walk_table_btree()`, `get_page_with_overlay()` |
| `overflow.rs` | **NEW** — orphaned overflow chain detection and reassembly |
| `gap.rs` | **NEW** — intra-page gap scanning (Layer 7) |
| `journal.rs` | **NEW** — rollback journal parsing (Layer 8) |
| `schema_sig.rs` | **NEW** — `SchemaSignature`, pattern generation, Boyer-Moore, plausibility checks |
| `dedup.rs` | **NEW** — Sanderson-style SHA-256 deduplication |
| `carver.rs` | Enhance with `SchemaSignature` integration |
| `unalloc.rs` | Enhance with `SchemaSignature` integration |
| `record.rs` | No changes |
| `types.rs` (plugin-api) | Add `WalDeleted`, `Journal` to `EvidenceSource` |

## Testing Strategy

TDD throughout. Each layer gets:
1. Unit tests with hand-crafted binary fixtures (known page layouts)
2. Integration tests with SQLite databases created via `rusqlite` (insert, delete, verify recovery)
3. Round-trip tests: create DB → delete records → recover → verify all deleted records found

**Key test scenarios:**
- WAL: create DB in WAL mode, insert, delete, verify both states visible
- Freelist: delete enough records to trigger page freeing, verify content recovery
- Gap: delete single records, verify intra-page gap carving finds them
- Overflow: insert large BLOBs, verify full reassembly
- Journal: create DB in journal mode, begin transaction, verify pre-image recovery
- Dedup: verify carved records matching live records are removed
- FQLite patterns: verify schema-to-pattern compilation, Boyer-Moore correctness
- Plausibility: verify false positive rejection

## Implementation Order

1. `schema_sig.rs` + `dedup.rs` (shared infrastructure)
2. Layer 7: intra-page gap scanning (highest forensic value)
3. Layer 2 enhanced: WAL replay
4. Layer 3: freelist content recovery
5. Layer 4: overflow page recovery
6. Layer 8: rollback journal
7. `recover_all()` orchestrator
8. Integration tests with real-world-like databases

## References

- [FQLite](https://github.com/pawlaszczyk/fqlite) — Pawlaszczyk & Hummert (2021),
  "Making the Invisible Visible"
- [Sanderson Forensics](https://sqliteforensictoolkit.com/) — Paul Sanderson,
  "SQLite Forensics" (2018)
- [Belkasoft](https://belkasoft.com/sqlite-analysis) — "Forensic Analysis of
  SQLite Databases"
- [DC3 sqlite-dissect](https://github.com/dod-cyber-crime-center/sqlite-dissect) —
  DoD Cyber Crime Center
- [SQLite File Format](https://www.sqlite.org/fileformat2.html) — Official spec
