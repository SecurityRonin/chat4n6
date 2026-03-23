# Sub-project A: Backend Forensic Enhancements — Design Spec

## Goal

Enhance chat4n6-sqlite-forensics with features stolen from sqlite-gui-analyzer, bring2lite, Sanderson Forensics, and the DFRWS research corpus. Improve recovery rates, add forensic provenance, and produce independently verifiable findings.

## Scope

This is Sub-project A of three: **(A) Backend enhancements** → (B) Cross-cutting utilities (timestamps, BLOB signatures) → (C) Interactive forensic GUI. This spec covers only A.

## Architecture

Three sequential phases:

1. **Phase 1: Test Coverage Lock-down** — Comprehensive unit + e2e tests for all existing modules. No production code changes. Creates regression safety net.
2. **Phase 2: RecoveryContext Refactor** — Introduce shared `RecoveryContext` struct, refactor all recovery layers to accept it. All Phase 1 tests must still pass.
3. **Phase 3: New Features** — Seven new modules plugging into RecoveryContext, plus Nemetz corpus CI benchmarks.

## Phase 1: Test Coverage Lock-down

### Objective

Every public function in chat4n6-sqlite-forensics has at least one direct unit test plus one edge case test. Coverage measured with `cargo-llvm-cov`.

### Tier 1 — Critical Gaps (0-30% coverage)

#### record.rs (0 tests → target: 15+)
- `SqlValue` enum: equality, Display, clone for all variants (Null, Int, Float, Text, Blob)
- `decode_serial_type`: all 12+ serial types (NULL=0, int8=1, int16=2, int24=3, int32=4, int48=5, int64=6, float64=7, const-0=8, const-1=9, text≥13-odd, blob≥12-even)
- `RecoveredRecord` construction and field access
- Edge cases: empty text, empty blob, max-size integers, negative values

#### btree.rs (2 tests → target: 20+)
- `parse_table_leaf_page`: valid leaf page, empty page (0 cells), page with overflow-triggering records, page 1 with 100-byte header offset
- `walk_table_btree`: single-page tree, multi-level tree (interior + leaves), empty tree (root is empty leaf)
- `follow_overflow_chain`: single overflow page, multi-page chain, cycle detection (page points to itself), chain pointing beyond DB
- `get_overlay_page`: page in overlay, page not in overlay, overlay with modified content
- `walk_table_btree_with_overlay`: overlay replaces a leaf page

#### page.rs (1 test → target: 8+)
- `PageType::from_byte`: all valid values (0x02, 0x05, 0x0A, 0x0D) plus invalid bytes (0x00, 0xFF, 0x01)
- `is_leaf()`: true for TableLeaf/IndexLeaf, false for TableInterior/IndexInterior

#### gap.rs (2 tests → target: 10+)
- `scan_single_page_gap`: page with no gap (cell_content_start == pointer array end), page with large gap containing multiple records, corrupt page header
- `collect_leaf_pages`: single leaf (root is leaf), interior node with multiple leaves, deep tree
- `scan_page_gaps`: empty table_roots, table with no leaf pages

### Tier 2 — High Gaps (50-70% coverage)

#### header.rs
- Boundary page sizes: 512 (minimum), 65536 (maximum, stored as 1 in header)
- Truncated input (< 100 bytes)
- `is_sqlite_header` with exact 16-byte magic match and near-misses

#### fts.rs
- Database with no FTS tables
- Malformed FTS shadow table (content table exists but content_rowid table missing)
- Empty FTS content table

#### journal.rs
- Truncated journal (valid header but no page records)
- Journal with invalid magic bytes
- Zero-length input
- Multi-section journal with different page counts

#### unalloc.rs
- Empty region input
- Region with no valid records found
- Region with all-zero bytes

#### freelist.rs
- Empty freelist (first_trunk_page = 0 in header)
- Trunk page pointing beyond database size
- Corrupt trunk chain (cycle detection)

### Tier 3 — Edge Case Hardening

#### wal.rs
- Empty WAL (valid header, zero frames)
- WAL with salt mismatch (indicates checkpoint occurred)
- `recover_layer2_enhanced` with WalMode::Ignore (should return empty)

#### schema_sig.rs
- CREATE TABLE with constraints (UNIQUE, NOT NULL, DEFAULT, CHECK)
- Reserved SQL keywords as column names
- Empty table (zero columns after INTEGER PRIMARY KEY filtering)
- Table with all TEXT columns (worst case for false positive carving)

#### dedup.rs
- Input with all-live records (nothing should be removed)
- Input with all-carved records (highest confidence wins)
- Single record (no dedup possible)

#### db.rs
- `recover_all` with every layer contributing at least one record
- Stats arithmetic: `records.len() == sum(layer_counts) - duplicates_removed`
- Engine with both WAL and journal attached simultaneously

### Tier 4 — Robustness Integration Tests

New file: `tests/robustness.rs`

- Truncated DB at page boundary
- DB with only sqlite_master (no user tables)
- UTF-16LE encoded database
- UTF-16BE encoded database
- Non-standard page sizes: 512, 8192, 32768, 65536
- DB with `auto_vacuum=FULL` (pointer-map pages present)
- Maximum-size record triggering overflow at exact threshold (`U - 35`)
- Circular freelist reference (anti-forensic scenario)
- DB larger than available memory (memmap-friendly — ensure no full-copy)

---

## Phase 2: RecoveryContext Refactor

### RecoveryContext Struct

```rust
/// Shared immutable state for all recovery layers.
/// Built once by ForensicEngine::build_context(), read by all layers.
/// All fields are populated during build_context() — no lazy/staged construction.
pub struct RecoveryContext<'a> {
    /// Raw database bytes
    pub db: &'a [u8],
    /// Page size from DB header
    pub page_size: u32,
    /// Parsed DB header
    pub header: &'a DbHeader,
    /// Table name → root page number mapping from sqlite_master
    pub table_roots: HashMap<String, u32>,
    /// Schema signatures for schema-aware carving
    pub schema_signatures: Vec<SchemaSignature>,
    /// Forensic pragma information parsed from header bytes
    pub pragma_info: PragmaInfo,
    /// Page-to-table ownership map (built via full B-tree traversal in build_context)
    pub page_map: PageMap,
    /// WAL page overlay for non-destructive replay (empty HashMap if no WAL attached)
    pub wal_overlay: HashMap<u32, Vec<u8>>,
}
```

### PragmaInfo Struct

```rust
/// Forensic-relevant pragma settings parsed from DB header bytes.
/// No SQL connection needed — pure byte parsing.
pub struct PragmaInfo {
    /// secure_delete setting: Off (default), On (zeroes records), Fast (zeroes in-page only)
    pub secure_delete: SecureDeleteMode,
    /// auto_vacuum setting: None (freelist grows), Full (freelist truncated), Incremental
    pub auto_vacuum: AutoVacuumMode,
    /// Journal mode inferred from header fields
    pub journal_mode: JournalMode,
    /// Text encoding for TEXT values
    pub text_encoding: TextEncoding,
    /// Schema format number (header offset 44)
    pub schema_format: u32,
    /// User version (header offset 60) — some apps store metadata here
    pub user_version: u32,
}

pub enum SecureDeleteMode { Off, On, Fast }
pub enum AutoVacuumMode { None, Full, Incremental }
pub enum JournalMode { Wal, NonWal }
pub enum TextEncoding { Utf8, Utf16le, Utf16be }
```

#### Header byte mapping for PragmaInfo

| Field | Header offset | Bytes | Notes |
|-------|--------------|-------|-------|
| text_encoding | 56 | 4 | 1=UTF-8, 2=UTF-16le, 3=UTF-16be |
| user_version | 60 | 4 | Big-endian u32 |
| auto_vacuum (enabled) | 52 | 4 | Largest root b-tree page number. 0 = auto_vacuum disabled. Non-zero = enabled. |
| auto_vacuum (mode) | 64 | 4 | Incremental vacuum flag. Only meaningful when offset 52 is non-zero. 0 = Full, non-zero = Incremental. |
| schema_format | 44 | 4 | 1-4, controls rowid storage |
| secure_delete | — | — | Cannot be read from header alone; runtime-only setting. Defaulted to Off. |
| journal_mode | 18-19 | 2 | Read/write version numbers. Both=2 → WAL mode. Both=1 → non-WAL (default to Delete). Other combinations → unknown, default to Delete. |

**Note on secure_delete**: SQLite does not persist this pragma in the header. It's a runtime-only setting. We default to `Off` (the SQLite default) and allow the user to override via `ForensicEngine::with_secure_delete_mode()`. The verification report should note this assumption.

**Note on journal_mode**: Only WAL vs non-WAL is detectable from the header (offsets 18-19). For non-WAL databases, the specific mode (Delete/Truncate/Persist/Off) cannot be determined from the header alone. We default to `Delete` and document the limitation. The JournalMode enum is reduced to `Wal` and `NonWal` to avoid false precision.

**Note on DbHeader extension**: `parse_pragma_info()` reads raw `db` bytes directly at the needed offsets rather than extending DbHeader. This keeps DbHeader focused on its current responsibility (page geometry and freelist pointers) and avoids touching existing code in Phase 2.

### Migration Strategy

1. Add `RecoveryContext`, `PragmaInfo`, and `build_context()` to a new `context.rs` module
2. Add a `RecoveryLayer` trait (optional, for future plugin architecture):
   ```rust
   pub trait RecoveryLayer {
       fn name(&self) -> &str;
       fn recover(&self, ctx: &RecoveryContext) -> Vec<RecoveredRecord>;
       fn is_viable(&self, pragma: &PragmaInfo) -> bool;
   }
   ```
3. Refactor one layer at a time, in order: freelist → gap → journal → wal → btree → fts → unalloc
4. After each layer migration, run the full Phase 1 test suite — zero regressions allowed
5. Update `recover_all()` to use context throughout
6. Remove old function signatures (no deprecation period — this is pre-1.0)

### Pragma-Aware Recovery Skipping

`recover_all()` uses PragmaInfo to skip impossible recovery sources:

| Pragma state | Skip layers | Reason |
|-------------|-------------|--------|
| `secure_delete = On` | Freeblock, gap scanning | Deleted cell bytes are zeroed |
| `secure_delete = Fast` | Freeblock (in-page) | In-page freeblocks zeroed, but freelist pages survive |
| `auto_vacuum = Full` | Freelist content | Pages truncated after each commit |
| `auto_vacuum = Incremental` | — | Freelist may have pages pending vacuum |

Skipped layers log a message explaining why and record it in `RecoveryStats`.

### Extended RecoveryStats

Phase 3 adds new fields to the existing `RecoveryStats` struct:

```rust
#[derive(Debug, Default)]
pub struct RecoveryStats {
    // Existing fields (Phase 2 preserves these)
    pub live_count: usize,
    pub wal_pending: usize,
    pub wal_deleted: usize,
    pub freelist_recovered: usize,
    pub overflow_reassembled: usize,
    pub fts_recovered: usize,
    pub gap_carved: usize,
    pub journal_recovered: usize,
    pub duplicates_removed: usize,
    // New fields (Phase 3)
    pub freeblock_recovered: usize,
    pub wal_only_tables_found: usize,
    pub rowid_gaps_detected: usize,
    pub layers_skipped: Vec<String>,  // e.g., ["freelist: secure_delete=On"]
}
```

---

## Phase 3: New Features

### 3.1 pragma.rs — Forensic Pragma Fingerprinting

**Purpose**: Parse header bytes to determine which recovery sources are viable.

**Public API**:
```rust
pub fn parse_pragma_info(header: &DbHeader, db: &[u8]) -> PragmaInfo
pub fn viability_report(info: &PragmaInfo) -> Vec<ViabilityEntry>
```

`ViabilityEntry` contains layer name, viable (bool), and explanation string. Used in verification reports.

**Header byte sources**:
- Offset 18: file format write version (2 = WAL mode)
- Offset 19: file format read version (2 = WAL mode)
- Offset 44: schema format number
- Offset 52: largest root b-tree page for auto_vacuum (0 = no auto_vacuum)
- Offset 56: text encoding
- Offset 60: user version

### 3.2 page_map.rs — Page-to-Table Ownership Map

**Purpose**: Build a complete mapping of every page in the database to its owning table and role.

**Algorithm**: bring2lite Algorithm 2 — recursive B-tree traversal from each table's root page.

**Public API**:
```rust
pub struct PageMap {
    map: HashMap<u32, PageOwnership>,
}

pub struct PageOwnership {
    pub table_name: String,
    pub page_role: PageRole,
}

pub enum PageRole {
    BTreeLeaf,
    BTreeInterior,
    Overflow { parent_page: u32 },
    FreelistTrunk,
    FreelistLeaf,
    PointerMap,
}

impl PageMap {
    pub fn build(db: &[u8], page_size: u32, table_roots: &HashMap<String, u32>) -> Self;
    pub fn owner_of(&self, page_num: u32) -> Option<&PageOwnership>;
    pub fn pages_for_table(&self, table_name: &str) -> Vec<u32>;
    pub fn unowned_pages(&self, total_pages: u32) -> Vec<u32>;
}
```

**Key behaviors**:
- Traverses interior B-tree pages recursively, collecting all leaf and interior page numbers
- Follows overflow chains from leaf page cells to map overflow pages
- Reads freelist trunk chain to map freelist pages
- `unowned_pages()` identifies pages not in any B-tree or freelist — candidates for raw carving

### 3.3 freeblock.rs — Varint Brute-Force Freeblock Recovery

**Purpose**: Recover deleted records from freeblocks within active B-tree leaf pages using bring2lite Algorithm 3.

**Algorithm**: When a cell becomes a freeblock, SQLite overwrites the first 4 bytes with (2-byte next-freeblock-offset + 2-byte freeblock-size). The original varints (payload length, rowid, header length) are destroyed. This module brute-forces the destroyed values:

1. For each freeblock in a leaf page, extract the freeblock data (skip first 4 destroyed bytes)
2. For `v` in 3..27 (sum of first 3 varint lengths): try interpreting bytes starting at offset `v` as a record header
3. For each candidate `v`, read serial type varints, validate against schema from page_map
4. If serial types are schema-compatible, decode the record values
5. Scan the remaining freeblock for additional sequential records (multi-record freeblocks)

**Public API**:
```rust
pub fn recover_freeblocks(ctx: &RecoveryContext) -> Vec<RecoveredRecord>;
```

**Improvement over bring2lite**: We scan the entire freeblock for multiple records, not just the first one. bring2lite acknowledged this limitation.

**Relationship with existing carver.rs**: The existing `carver.rs` module performs generic byte-pattern carving without schema awareness. `freeblock.rs` is a specialized replacement for freeblock-specific recovery that uses schema validation (from `schema_sig.rs`'s existing `SchemaSignature::try_parse_record()` and `is_compatible()`) for higher accuracy. The existing `carver.rs` remains for non-freeblock carving (e.g., unallocated regions). `freeblock.rs` does NOT reimplement schema validation — it reuses `SchemaSignature` from `schema_sig.rs`.

### 3.4 wal_enhanced.rs — WAL Frame Classification + WAL-Only Tables

**Purpose**: Two capabilities in one module.

**A. Frame Classification**:

Every WAL frame gets a `WalFrameStatus`:
```rust
pub enum WalFrameStatus {
    /// Part of a committed transaction (commit frame has non-zero db-size)
    Committed { transaction_id: u32 },
    /// After the last commit but before next checkpoint — uncommitted data
    Uncommitted,
    /// Same page appears in a later frame — this is a historical version
    Superseded { superseded_by_frame: u32 },
}
```

Classification algorithm:
1. Parse all frames, group by salt pair (same salt = same checkpoint epoch)
2. Walk frames forward; frames in a group ending with a commit frame (non-zero db-size in frame header) are `Committed`
3. Frames after the last commit frame are `Uncommitted`
4. When the same page number appears in multiple frames, earlier ones are `Superseded`

**B. WAL-Only Table Detection**:

```rust
pub fn detect_wal_only_tables(
    ctx: &RecoveryContext,
    wal: &[u8],
) -> Vec<WalOnlyTable>;

pub struct WalOnlyTable {
    pub name: String,
    pub create_sql: String,
    pub root_page: u32,
    pub frame_status: WalFrameStatus,
}
```

Checks WAL frames for page 1 copies. Parses each WAL copy of page 1 as sqlite_master. Any table in the WAL's sqlite_master that is absent from the main DB's sqlite_master is a WAL-only table (created in a crashed or uncommitted transaction).

### 3.5 rowid_gap.rs — ROWID Gap Detection

**Purpose**: Detect missing ROWIDs that indicate deleted records, even when physical recovery is impossible.

**Public API**:
```rust
pub struct RowidGap {
    pub table: String,
    pub gap_start: i64,       // first missing ROWID
    pub gap_end: i64,         // last missing ROWID
    pub gap_size: u64,        // number of missing ROWIDs
    pub neighbor_before: Option<RecoveredRecord>,
    pub neighbor_after: Option<RecoveredRecord>,
}

pub fn detect_rowid_gaps(
    live_records: &[RecoveredRecord],
    table_roots: &HashMap<String, u32>,
) -> Vec<RowidGap>;
```

**Algorithm**:
1. Group live records by table name
2. Filter to records where `record.row_id.is_some()` (skip records without rowid)
3. Sort by `row_id` (from `RecoveredRecord.row_id: Option<i64>`)
4. Detect gaps > 1 between consecutive row_id values
5. Attach neighboring records for timestamp estimation
6. Skip tables using `WITHOUT ROWID` (detectable from schema SQL containing "WITHOUT ROWID")

### 3.6 verify.rs — Verification Report Generation

**Purpose**: Produce independently verifiable findings for expert testimony.

**Public API**:
```rust
pub struct VerifiableFinding {
    /// The recovered record
    pub record: RecoveredRecord,
    /// Database page containing this record
    pub page_number: u32,
    /// Byte offset within the database file
    pub byte_offset: usize,
    /// 32 bytes of hex context around the finding
    pub hex_context: String,
    /// Human-readable description of recovery technique
    pub recovery_technique: String,
    /// Shell command to verify with standard tools
    pub verification_command: String,
    /// Cross-validation note (if verifiable via another method)
    pub cross_validation: Option<String>,
}

pub struct VerificationReport {
    /// SHA-256 hash of the input database file
    pub evidence_hash: String,
    /// SHA-256 hash of WAL file (if provided)
    pub wal_hash: Option<String>,
    /// SHA-256 hash of journal file (if provided)
    pub journal_hash: Option<String>,
    /// chat4n6 version used
    pub tool_version: String,
    /// Pragma viability assessment
    pub viability: Vec<ViabilityEntry>,
    /// Per-finding verification data
    pub findings: Vec<VerifiableFinding>,
    /// ROWID gaps detected
    pub rowid_gaps: Vec<RowidGap>,
    /// Recovery statistics
    pub stats: RecoveryStats,
    /// Nemetz corpus benchmark score for this tool version
    pub benchmark_score: Option<f64>,
}

pub fn build_verification_report(
    ctx: &RecoveryContext,
    result: &RecoveryResult,
) -> VerificationReport;
```

**Verification commands generated**:
- For live records: `sqlite3 evidence.db "SELECT * FROM table WHERE rowid=N"`
- For WAL records: `xxd -s OFFSET -l LEN evidence.db-wal`
- For freelist/gap records: `xxd -s OFFSET -l LEN evidence.db`
- For journal records: `xxd -s OFFSET -l LEN evidence.db-journal`

### 3.7 Nemetz Corpus Integration

**Location**: `tests/fixtures/nemetz/` (Git LFS)

**Contents**: 77 SQLite databases from DFRWS 2018 corpus + anti-forensic extension (~50-60 DBs) from IMF 2018. Total size approximately 5-10 MB. Downloaded from https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/ (public domain).

**Git LFS setup**: Add `tests/fixtures/nemetz/**/*.db` to `.gitattributes` with `filter=lfs diff=lfs merge=lfs -text`. CI runners must have `git lfs` installed.

**Test file**: `tests/nemetz_benchmark.rs`

**Tests**:
```rust
#[test]
fn benchmark_recovery_rate() {
    // Run recover_all() on every corpus DB
    // Compare recovered records against ground truth XML
    // Assert recovery_rate >= MINIMUM_THRESHOLD (initially 50%, increase as we improve)
    // Print detailed per-category breakdown
}

#[test]
fn non_degradation_guarantee() {
    // For every corpus DB:
    // 1. Run recover_layer1() (live only)
    // 2. Run recover_all() (full recovery)
    // 3. Assert live records are IDENTICAL in both
    // No recovery feature may reduce live-data extraction.
}

#[test]
fn no_false_positives_on_clean_db() {
    // Create a fresh DB with known content, no deletions
    // Run recover_all()
    // Assert zero non-live records recovered
}

#[test]
fn anti_forensic_corpus_no_crash() {
    // Run recover_all() on every anti-forensic DB
    // Must not panic or hang
    // Recovery rate may be 0% — that's fine, robustness is the goal
}
```

**Test gating**: Nemetz benchmark tests are gated with `#[ignore]` by default (they require Git LFS checkout). Run explicitly with `cargo test -- --ignored` or in CI where LFS is available. The non-degradation and no-false-positives tests use programmatically generated DBs and run unconditionally.

**CI integration**: Recovery rate printed in CI output. Future: track as a metric over time to detect regressions.

---

## Feature Interaction Summary

```
Phase 1: Tests ──► Regression safety net (must pass through Phases 2-3)
Phase 2: RecoveryContext ──► Shared state for all layers
Phase 3:
  pragma.rs ──► RecoveryContext.pragma_info (decides which layers to run)
  page_map.rs ──► RecoveryContext.page_map (used by wal, freeblock, freelist, gap)
  freeblock.rs ──► uses page_map + schema_signatures + pragma_info
  wal_enhanced.rs ──► uses page_map for table attribution
  rowid_gap.rs ──► uses live records from Layer 1
  verify.rs ──► wraps RecoveryResult with hex offsets + commands
  nemetz corpus ──► benchmarks recover_all() against ground truth
```

## Testing Strategy

- **Phase 1**: Pure test additions, no production changes. Measured by `cargo-llvm-cov`.
- **Phase 2**: Every refactored layer must pass all Phase 1 tests. One layer at a time.
- **Phase 3**: Each new module has its own unit tests. Integration via Nemetz corpus benchmark. Non-degradation test ensures new features don't break live recovery.

## Dependencies

- No new external crate dependencies required (sha2 already available for hashing)
- Git LFS required for Nemetz corpus (one-time setup)
- `cargo-llvm-cov` for coverage measurement (dev dependency only)

## Out of Scope

- Sub-project B: Timestamp auto-detection, BLOB signature detection (separate spec)
- Sub-project C: Interactive GUI (separate spec)
- `RecoveryLayer` trait implementation (optional future work, interfaces defined but not enforced in Phase 2)
