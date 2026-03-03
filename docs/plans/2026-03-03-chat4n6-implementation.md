# chat4n6 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust forensic tool that extracts WhatsApp artifacts from Android DAR images with 6-layer SQLite recovery and paginated HTML reports.

**Architecture:** Cargo workspace with plugin architecture — `chat4n6-core` (DAR parsing + ForensicFs), `chat4n6-sqlite-forensics` (6-layer recovery engine), `chat4n6-plugin-api` (traits + types), `plugins/chat4n6-whatsapp` (WhatsApp extraction), `chat4n6-report` (HTML generator), `cli/` (clap CLI).

**Tech Stack:** Rust 1.75+, nom (binary parsing), tera (HTML templates), clap (CLI), aes-gcm/cbc (decryption), chrono-tz (timestamps), rayon (parallel carving), serde_json (carve-results.json), indicatif (progress bars).

---

## Phase 1: Workspace & Plugin API

### Task 1: Initialize Cargo workspace

**Files:**
- Create: `Cargo.toml`
- Create: `crates/chat4n6-plugin-api/Cargo.toml`
- Create: `crates/chat4n6-core/Cargo.toml`
- Create: `crates/chat4n6-sqlite-forensics/Cargo.toml`
- Create: `crates/plugins/chat4n6-whatsapp/Cargo.toml`
- Create: `crates/chat4n6-report/Cargo.toml`
- Create: `cli/Cargo.toml`

**Step 1: Write workspace Cargo.toml**

```toml
# Cargo.toml
[workspace]
members = [
    "crates/chat4n6-plugin-api",
    "crates/chat4n6-core",
    "crates/chat4n6-sqlite-forensics",
    "crates/plugins/chat4n6-whatsapp",
    "crates/chat4n6-report",
    "cli",
]
resolver = "2"

[workspace.dependencies]
anyhow = "1"
thiserror = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
nom = "7"
bytes = "1"
chrono = { version = "0.4", features = ["serde"] }
chrono-tz = "0.9"
sha2 = "0.10"
base64 = "0.22"
rayon = "1"
log = "0.4"
env_logger = "0.11"
```

**Step 2: Create each crate skeleton**

```bash
mkdir -p crates/chat4n6-plugin-api/src
mkdir -p crates/chat4n6-core/src
mkdir -p crates/chat4n6-sqlite-forensics/src
mkdir -p crates/plugins/chat4n6-whatsapp/src
mkdir -p crates/chat4n6-report/src
mkdir -p cli/src
```

Write `crates/chat4n6-plugin-api/Cargo.toml`:
```toml
[package]
name = "chat4n6-plugin-api"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
chrono = { workspace = true }
```

Write stubs: each `src/lib.rs` contains just `// TODO`.

**Step 3: Verify workspace compiles**

```bash
cargo build
```
Expected: all crates compile (empty).

**Step 4: Commit**

```bash
git add Cargo.toml crates/ cli/
git commit -m "chore: initialize cargo workspace with crate skeletons"
```

---

### Task 2: Define plugin API types

**Files:**
- Create: `crates/chat4n6-plugin-api/src/lib.rs`
- Create: `crates/chat4n6-plugin-api/src/types.rs`
- Create: `crates/chat4n6-plugin-api/src/fs.rs`

**Step 1: Write failing test**

```rust
// crates/chat4n6-plugin-api/src/lib.rs
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_evidence_source_display() {
        assert_eq!(format!("{}", EvidenceSource::Live), "LIVE");
        assert_eq!(format!("{}", EvidenceSource::FtsOnly), "FTS-ONLY");
        assert_eq!(format!("{}", EvidenceSource::CarvedUnalloc { confidence: 0.94 }),
                   "CARVED-UNALLOC 94%");
    }

    #[test]
    fn test_timestamp_display_utc_plus_local() {
        let ts = ForensicTimestamp {
            utc: DateTime::parse_from_rfc3339("2024-03-15T14:32:07Z").unwrap().into(),
            local_offset_seconds: 8 * 3600,
        };
        assert_eq!(ts.utc_str(), "2024-03-15 14:32:07 UTC");
        assert_eq!(ts.local_str(), "2024-03-15 22:32:07 UTC+8");
    }
}
```

**Step 2: Run test — expect FAIL**

```bash
cargo test -p chat4n6-plugin-api
```
Expected: compile error — types not defined.

**Step 3: Implement types**

`crates/chat4n6-plugin-api/src/types.rs`:
```rust
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceSource {
    Live,
    WalPending,
    WalHistoric,
    Freelist,
    FtsOnly,
    CarvedUnalloc { confidence: f32 },
    CarvedDb,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "LIVE"),
            Self::WalPending => write!(f, "WAL-PENDING"),
            Self::WalHistoric => write!(f, "WAL-HISTORIC"),
            Self::Freelist => write!(f, "FREELIST"),
            Self::FtsOnly => write!(f, "FTS-ONLY"),
            Self::CarvedUnalloc { confidence } =>
                write!(f, "CARVED-UNALLOC {:.0}%", confidence * 100.0),
            Self::CarvedDb => write!(f, "CARVED-DB"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicTimestamp {
    pub utc: DateTime<Utc>,
    pub local_offset_seconds: i32,
}

impl ForensicTimestamp {
    pub fn from_millis(ms: i64, local_offset_seconds: i32) -> Self {
        let utc = Utc.timestamp_millis_opt(ms).single()
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        Self { utc, local_offset_seconds }
    }

    pub fn utc_str(&self) -> String {
        self.utc.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    pub fn local_str(&self) -> String {
        let offset = FixedOffset::east_opt(self.local_offset_seconds).unwrap();
        let local = self.utc.with_timezone(&offset);
        let hours = self.local_offset_seconds / 3600;
        let sign = if hours >= 0 { "+" } else { "" };
        format!("{} UTC{}{}", local.format("%Y-%m-%d %H:%M:%S"), sign, hours)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaRef {
    pub file_path: String,      // path within DAR filesystem
    pub mime_type: String,
    pub file_size: u64,
    pub extracted_name: Option<String>, // name in media/ output folder
    pub thumbnail_b64: Option<String>,  // base64 thumbnail for inline display
    pub duration_secs: Option<u32>,     // for audio/video
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub reactor_jid: String,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub call_id: i64,
    pub participants: Vec<String>,  // JIDs
    pub from_me: bool,
    pub video: bool,
    pub group_call: bool,
    pub duration_secs: u32,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Media(MediaRef),
    Location { lat: f64, lon: f64, name: Option<String> },
    VCard(String),
    Deleted,
    System(String),
    Unknown(i32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: i64,
    pub chat_id: i64,
    pub sender_jid: Option<String>,
    pub from_me: bool,
    pub timestamp: ForensicTimestamp,
    pub content: MessageContent,
    pub reactions: Vec<Reaction>,
    pub quoted_message: Option<Box<Message>>,
    pub source: EvidenceSource,
    pub row_offset: u64,  // byte offset in DB file for provenance
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub jid: String,
    pub display_name: Option<String>,
    pub phone_number: Option<String>,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub id: i64,
    pub jid: String,
    pub name: Option<String>,
    pub is_group: bool,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalDelta {
    pub table: String,
    pub row_id: i64,
    pub status: WalDeltaStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalDeltaStatus {
    AddedInWal,
    DeletedInWal,
    ModifiedInWal,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub chats: Vec<Chat>,
    pub contacts: Vec<Contact>,
    pub calls: Vec<CallRecord>,
    pub wal_deltas: Vec<WalDelta>,
    pub timezone_offset_seconds: Option<i32>,
    pub schema_version: u32,
}
```

`crates/chat4n6-plugin-api/src/fs.rs`:
```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnallocatedRegion {
    pub offset: u64,   // offset within the source image
    pub data: Vec<u8>,
}

pub trait ForensicFs: Send + Sync {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>>;
    fn read(&self, path: &str) -> Result<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
    fn unallocated_regions(&self) -> &[UnallocatedRegion];
}

pub trait ForensicPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, fs: &dyn ForensicFs) -> bool;
    fn extract(&self, fs: &dyn ForensicFs, local_offset_seconds: Option<i32>)
        -> Result<ExtractionResult>;
}

// re-export for convenience
pub use crate::types::ExtractionResult;
```

`crates/chat4n6-plugin-api/src/lib.rs`:
```rust
pub mod fs;
pub mod types;
pub use fs::*;
pub use types::*;
```

**Step 4: Run test — expect PASS**

```bash
cargo test -p chat4n6-plugin-api
```

**Step 5: Commit**

```bash
git add crates/chat4n6-plugin-api/
git commit -m "feat: define plugin API types, traits, and ForensicFs abstraction"
```

---

## Phase 2: Core / DAR Parser

### Task 3: PlaintextDirFs (test harness)

**Files:**
- Create: `crates/chat4n6-core/src/lib.rs`
- Create: `crates/chat4n6-core/src/plaintext_fs.rs`

**Step 1: Write failing test**

```rust
// crates/chat4n6-core/src/plaintext_fs.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_temp_tree() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("data/data/com.whatsapp/databases")).unwrap();
        fs::write(dir.path().join("data/data/com.whatsapp/databases/msgstore.db"),
                  b"SQLite format 3\x00").unwrap();
        dir
    }

    #[test]
    fn test_list_finds_db() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        let entries = fs.list("data/data/com.whatsapp/databases").unwrap();
        assert!(entries.iter().any(|e| e.path.ends_with("msgstore.db")));
    }

    #[test]
    fn test_read_returns_bytes() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        let bytes = fs.read("data/data/com.whatsapp/databases/msgstore.db").unwrap();
        assert_eq!(&bytes[..7], b"SQLite ");
    }

    #[test]
    fn test_unallocated_empty_for_plain_dir() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        assert!(fs.unallocated_regions().is_empty());
    }
}
```

**Step 2: Add tempfile to dev-dependencies, run — expect FAIL**

Add to `crates/chat4n6-core/Cargo.toml`:
```toml
[dev-dependencies]
tempfile = "3"
```

```bash
cargo test -p chat4n6-core
```

**Step 3: Implement PlaintextDirFs**

```rust
// crates/chat4n6-core/src/plaintext_fs.rs
use anyhow::{Context, Result};
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use std::path::{Path, PathBuf};

pub struct PlaintextDirFs {
    root: PathBuf,
}

impl PlaintextDirFs {
    pub fn new(root: &Path) -> Result<Self> {
        anyhow::ensure!(root.is_dir(), "not a directory: {}", root.display());
        Ok(Self { root: root.to_path_buf() })
    }
}

impl ForensicFs for PlaintextDirFs {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let full = self.root.join(path);
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&full)
            .with_context(|| format!("reading dir {}", full.display()))? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let rel = entry.path().strip_prefix(&self.root)
                .unwrap().to_string_lossy().to_string();
            entries.push(FsEntry {
                path: rel,
                size: meta.len(),
                is_dir: meta.is_dir(),
            });
        }
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let full = self.root.join(path);
        std::fs::read(&full).with_context(|| format!("reading {}", full.display()))
    }

    fn exists(&self, path: &str) -> bool {
        self.root.join(path).exists()
    }

    fn unallocated_regions(&self) -> &[UnallocatedRegion] {
        &[]
    }
}
```

**Step 4: Run test — expect PASS**

```bash
cargo test -p chat4n6-core plaintext
```

**Step 5: Commit**

```bash
git add crates/chat4n6-core/
git commit -m "feat: implement PlaintextDirFs for testing and direct-dir input"
```

---

### Task 4: DAR v8/v9 parser

**Files:**
- Create: `crates/chat4n6-core/src/dar/mod.rs`
- Create: `crates/chat4n6-core/src/dar/header.rs`
- Create: `crates/chat4n6-core/src/dar/catalog.rs`
- Create: `crates/chat4n6-core/src/dar/fs.rs`
- Create: `tests/fixtures/` (test DAR files)

**Step 1: Write failing tests**

```rust
// crates/chat4n6-core/src/dar/mod.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dar_magic() {
        // DAR slice header starts with magic bytes
        let magic_v8 = DarVersion::from_magic(b"\xd2\xab\xea\x18\x00\x08").unwrap();
        assert_eq!(magic_v8, DarVersion::V8);
    }

    #[test]
    fn test_infinint_decode_single_byte() {
        // Single byte infinint: 1 zero byte + value byte
        // \x00\x05 = 5
        let result = decode_infinint(&[0x00, 0x05]).unwrap();
        assert_eq!(result, (5u64, 2));
    }

    #[test]
    fn test_infinint_decode_multi_byte() {
        // 2 zero bytes + 2 value bytes (big-endian within value group)
        let result = decode_infinint(&[0x00, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(result, (256u64, 4));
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-core dar
```

**Step 3: Implement DAR header parsing and infinint decoder**

```rust
// crates/chat4n6-core/src/dar/mod.rs
pub mod catalog;
pub mod fs;
pub mod header;

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum DarVersion { V8, V9 }

impl DarVersion {
    pub fn from_magic(bytes: &[u8]) -> Result<Self> {
        // DAR magic is in the archive header after the slice header.
        // Version byte is at a known offset in the archive header.
        // V8: format version 8, V9: format version 9
        // Detect from the "dar_version" field in the archive header.
        // For MVP: detect V9 if magic indicates format >= 9, else V8.
        if bytes.len() < 2 { bail!("too short for magic") }
        // Simplified: check version nibble
        match bytes[0] {
            0xd2 if bytes[1] == 0xab => Ok(DarVersion::V8),
            0xd3 if bytes[1] == 0xab => Ok(DarVersion::V9),
            _ => Ok(DarVersion::V8), // default to V8 for unknown
        }
    }
}

/// Decode a DAR infinint (variable-length integer).
/// Format: N zero bytes followed by N non-zero bytes (big-endian value).
/// Returns (value, bytes_consumed).
pub fn decode_infinint(data: &[u8]) -> Result<(u64, usize)> {
    let mut zero_count = 0;
    for &b in data {
        if b == 0 { zero_count += 1; } else { break; }
    }
    if zero_count == 0 {
        // single-byte encoding: value is in bits 6:0 of first byte
        return Ok((data[0] as u64 & 0x7f, 1));
    }
    let value_bytes = &data[zero_count..zero_count + zero_count];
    if value_bytes.len() < zero_count {
        bail!("truncated infinint");
    }
    let mut value = 0u64;
    for &b in value_bytes {
        value = (value << 8) | b as u64;
    }
    Ok((value, zero_count * 2))
}
```

Note: Full DAR parsing (catalog walk, slice stitching, file extraction) is complex.
Implement `DarFs` in `dar/fs.rs` as a struct that:
1. Opens the DAR file (memory-mapped with `memmap2`)
2. Reads the terminator from EOF to locate catalog offset
3. Walks the catalog to build a `HashMap<String, (offset, size)>` file index
4. Implements `ForensicFs` using the file index

For the MVP, target the subset of the DAR format that Passware Kit Mobile produces.
Consult the DAR v8 spec at `https://darbinding.sourceforge.net/specs/dar5.html`.

**Step 4: Run tests — expect PASS for infinint + magic**

```bash
cargo test -p chat4n6-core dar
```

**Step 5: Integration test with a real DAR**

```rust
// crates/chat4n6-core/tests/dar_integration.rs
// Skip if no fixture file available
#[test]
#[ignore = "requires test DAR fixture"]
fn test_dar_lists_whatsapp_databases() {
    let fs = DarFs::open("tests/fixtures/sample.dar").unwrap();
    let entries = fs.list("data/data/com.whatsapp/databases").unwrap();
    assert!(entries.iter().any(|e| e.path.contains("msgstore.db")));
}
```

**Step 6: Commit**

```bash
git add crates/chat4n6-core/src/dar/
git commit -m "feat: DAR v8/v9 parser with infinint decoder and ForensicFs impl"
```

---

## Phase 3: SQLite Forensics Engine

### Task 5: SQLite page infrastructure

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/lib.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/page.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/varint.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/header.rs`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-sqlite-forensics/src/varint.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_single_byte() {
        assert_eq!(read_varint(&[0x07], 0), (7, 1));
    }

    #[test]
    fn test_varint_two_bytes() {
        // 0x81 0x01 = 129
        assert_eq!(read_varint(&[0x81, 0x01], 0), (129, 2));
    }

    #[test]
    fn test_varint_max_9bytes() {
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let (val, len) = read_varint(&bytes, 0);
        assert_eq!(len, 9);
        assert!(val > 0);
    }

    #[test]
    fn test_page_type_detection() {
        assert_eq!(PageType::from_byte(0x0d), Some(PageType::TableLeaf));
        assert_eq!(PageType::from_byte(0x0a), Some(PageType::IndexLeaf));
        assert_eq!(PageType::from_byte(0x05), Some(PageType::TableInterior));
        assert_eq!(PageType::from_byte(0x00), Some(PageType::OverflowOrDropped));
        assert_eq!(PageType::from_byte(0x99), None);
    }

    #[test]
    fn test_sqlite_header_magic() {
        let header = b"SQLite format 3\x00" as &[u8];
        assert!(is_sqlite_header(header));
        assert!(!is_sqlite_header(b"not sqlite"));
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics page varint header
```

**Step 3: Implement**

```rust
// crates/chat4n6-sqlite-forensics/src/varint.rs
/// Read a SQLite variable-length integer from `data` at `offset`.
/// Returns (value, bytes_consumed). Panics if data is too short.
pub fn read_varint(data: &[u8], offset: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut i = offset;
    for n in 0..9 {
        let b = data[i];
        i += 1;
        if n == 8 {
            result = (result << 8) | b as u64;
            return (result, 9);
        }
        result = (result << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 { return (result, i - offset); }
    }
    unreachable!()
}

/// Decode a varint walking backwards from `offset` (exclusive).
/// Returns (value, start_offset) or None if invalid.
pub fn read_varint_reverse(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let max_len = std::cmp::min(9, offset);
    for len in 1..=max_len {
        let start = offset - len;
        // Last byte of a varint must have MSB=0
        if data[offset - 1] & 0x80 != 0 { continue; }
        // All prior bytes must have MSB=1
        let all_continuation = (start..offset-1).all(|i| data[i] & 0x80 != 0);
        if !all_continuation && len > 1 { continue; }
        let (val, consumed) = read_varint(data, start);
        if consumed == len { return Some((val, start)); }
    }
    None
}

// crates/chat4n6-sqlite-forensics/src/page.rs
#[derive(Debug, Clone, PartialEq)]
pub enum PageType {
    TableLeaf,        // 0x0D
    TableInterior,    // 0x05
    IndexLeaf,        // 0x0A
    IndexInterior,    // 0x02
    OverflowOrDropped,// 0x00
}

impl PageType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x0d => Some(Self::TableLeaf),
            0x05 => Some(Self::TableInterior),
            0x0a => Some(Self::IndexLeaf),
            0x02 => Some(Self::IndexInterior),
            0x00 => Some(Self::OverflowOrDropped),
            _ => None,
        }
    }
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::TableLeaf | Self::IndexLeaf)
    }
}

// crates/chat4n6-sqlite-forensics/src/header.rs
pub const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

pub fn is_sqlite_header(data: &[u8]) -> bool {
    data.len() >= 16 && &data[..16] == SQLITE_MAGIC
}

#[derive(Debug)]
pub struct DbHeader {
    pub page_size: u32,
    pub page_count: u32,
    pub freelist_trunk_page: u32,
    pub freelist_page_count: u32,
    pub user_version: u32,
    pub text_encoding: u32,
}

impl DbHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !is_sqlite_header(data) || data.len() < 100 { return None; }
        let page_size = {
            let raw = u16::from_be_bytes([data[16], data[17]]) as u32;
            if raw == 1 { 65536 } else { raw }
        };
        Some(Self {
            page_size,
            page_count: u32::from_be_bytes([data[28],data[29],data[30],data[31]]),
            freelist_trunk_page: u32::from_be_bytes([data[32],data[33],data[34],data[35]]),
            freelist_page_count: u32::from_be_bytes([data[36],data[37],data[38],data[39]]),
            user_version: u32::from_be_bytes([data[60],data[61],data[62],data[63]]),
            text_encoding: u32::from_be_bytes([data[56],data[57],data[58],data[59]]),
        })
    }
}
```

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/
git commit -m "feat: SQLite page infrastructure — varint, page types, DB header parsing"
```

---

### Task 6: Layer 1 — Live record B-tree traversal

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/btree.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/record.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/db.rs`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-sqlite-forensics/src/db.rs
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection; // used only to create test fixtures

    fn create_test_db() -> Vec<u8> {
        // Create in-memory SQLite, write some records, export bytes
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("
            CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER);
            INSERT INTO messages VALUES (1, 'hello world', 1710000000000);
            INSERT INTO messages VALUES (2, 'foo bar', 1710000001000);
        ").unwrap();
        // Write to temp file and read back
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_layer1_reads_live_records() {
        let db_bytes = create_test_db();
        let engine = ForensicEngine::new(&db_bytes, None).unwrap();
        let results = engine.recover_layer1().unwrap();
        let msgs: Vec<_> = results.iter()
            .filter(|r| r.table == "messages")
            .collect();
        assert_eq!(msgs.len(), 2);
        assert!(msgs.iter().any(|r| r.values[1] == SqlValue::Text("hello world".into())));
    }
}
```

**Step 2: Add rusqlite to dev-deps, run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics layer1
```

**Step 3: Implement B-tree traversal and record parsing**

Create `ForensicEngine` struct in `db.rs` that:
- Holds `&[u8]` of full DB
- Parses `DbHeader`
- Implements `recover_layer1()`: traverse B-tree from root pages, parse all table leaf cells into `RecoveredRecord { table, row_id, values, source, offset }`.

`RecoveredRecord` and `SqlValue` types in `record.rs`:
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RecoveredRecord {
    pub table: String,
    pub row_id: Option<i64>,
    pub values: Vec<SqlValue>,
    pub source: EvidenceSource,
    pub offset: u64,
    pub confidence: f32,
}
```

Serial type decoding (per SQLite spec):
- 0 → Null, 1→INT8, 2→INT16, 3→INT24, 4→INT32, 5→INT48, 6→INT64
- 7 → REAL (8-byte IEEE 754)
- 8 → INT 0, 9 → INT 1
- N≥12, N even → BLOB of (N-12)/2 bytes
- N≥13, N odd → TEXT of (N-13)/2 bytes

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics layer1
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/btree.rs \
        crates/chat4n6-sqlite-forensics/src/record.rs \
        crates/chat4n6-sqlite-forensics/src/db.rs
git commit -m "feat: Layer 1 — live B-tree record traversal with serial type decoding"
```

---

### Task 7: Layer 2 & 3 — WAL parsing

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/wal.rs`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-sqlite-forensics/src/wal.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_magic_detection() {
        let magic1 = 0x377f0682u32.to_be_bytes();
        let magic2 = 0x377f0683u32.to_be_bytes();
        assert!(is_wal_header(&magic1));
        assert!(is_wal_header(&magic2));
        assert!(!is_wal_header(b"\x00\x00\x00\x00"));
    }

    #[test]
    fn test_wal_frame_offset_calculation() {
        // WAL header = 32 bytes, frame = header(24) + page_data
        let page_size = 4096u32;
        let frame_0_offset = wal_frame_offset(0, page_size);
        assert_eq!(frame_0_offset, 32); // right after WAL header
        let frame_1_offset = wal_frame_offset(1, page_size);
        assert_eq!(frame_1_offset, 32 + 24 + 4096);
    }

    #[test]
    fn test_parse_wal_header() {
        let mut header = vec![0u8; 32];
        // magic
        header[0..4].copy_from_slice(&0x377f0682u32.to_be_bytes());
        // file format version
        header[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        // page size
        header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        // salt1
        header[16..20].copy_from_slice(&42u32.to_be_bytes());

        let wh = WalHeader::parse(&header).unwrap();
        assert_eq!(wh.page_size, 4096);
        assert_eq!(wh.salt1, 42);
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics wal
```

**Step 3: Implement WAL parser**

```rust
// crates/chat4n6-sqlite-forensics/src/wal.rs
use std::collections::BTreeMap;
use crate::record::RecoveredRecord;
use chat4n6_plugin_api::{EvidenceSource, WalDelta, WalDeltaStatus};

pub const WAL_MAGIC_1: u32 = 0x377f0682;
pub const WAL_MAGIC_2: u32 = 0x377f0683;
pub const WAL_HEADER_SIZE: usize = 32;
pub const WAL_FRAME_HEADER_SIZE: usize = 24;

pub fn is_wal_header(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == WAL_MAGIC_1 || magic == WAL_MAGIC_2
}

pub fn wal_frame_offset(frame_index: usize, page_size: u32) -> u64 {
    (WAL_HEADER_SIZE + frame_index * (WAL_FRAME_HEADER_SIZE + page_size as usize)) as u64
}

#[derive(Debug)]
pub struct WalHeader {
    pub page_size: u32,
    pub checkpoint_seq: u32,
    pub salt1: u32,
    pub salt2: u32,
}

impl WalHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 || !is_wal_header(data) { return None; }
        Some(Self {
            page_size: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            checkpoint_seq: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            salt1: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            salt2: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }
}

#[derive(Debug)]
pub struct WalFrame {
    pub page_number: u32,
    pub db_size_after_commit: u32, // non-zero = commit frame
    pub salt1: u32,
    pub salt2: u32,
    pub page_data_offset: usize,   // offset of page data within wal bytes
}

/// Parse all frames from a WAL file, grouped by salt1 (transaction).
pub fn parse_wal_frames(wal: &[u8], page_size: u32)
    -> BTreeMap<u32, Vec<WalFrame>>
{
    let mut map: BTreeMap<u32, Vec<WalFrame>> = BTreeMap::new();
    if !is_wal_header(wal) { return map; }
    let mut idx = 0;
    loop {
        let frame_off = WAL_HEADER_SIZE
            + idx * (WAL_FRAME_HEADER_SIZE + page_size as usize);
        if frame_off + WAL_FRAME_HEADER_SIZE > wal.len() { break; }
        let fh = &wal[frame_off..frame_off + WAL_FRAME_HEADER_SIZE];
        let page_number = u32::from_be_bytes([fh[0],fh[1],fh[2],fh[3]]);
        let db_size = u32::from_be_bytes([fh[4],fh[5],fh[6],fh[7]]);
        let salt1 = u32::from_be_bytes([fh[8],fh[9],fh[10],fh[11]]);
        let salt2 = u32::from_be_bytes([fh[12],fh[13],fh[14],fh[15]]);
        if page_number == 0 { break; }
        map.entry(salt1).or_default().push(WalFrame {
            page_number, db_size_after_commit: db_size,
            salt1, salt2,
            page_data_offset: frame_off + WAL_FRAME_HEADER_SIZE,
        });
        idx += 1;
    }
    map
}
```

Layer 2 (`recover_layer2`): extract records from WAL frames not yet in main DB (no corresponding page with matching content). Tag `EvidenceSource::WalPending`.

Layer 3 (`recover_layer3_deltas`): for each WAL frame, compare the WAL version of the page with the main DB version. Differences become `WalDelta` entries.

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics wal
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/wal.rs
git commit -m "feat: Layer 2/3 — WAL frame parsing, pending/historic record recovery, delta reporting"
```

---

### Task 8: Layer 4 — Freelist & freeblock carving

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/freelist.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/carver.rs`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-sqlite-forensics/src/freelist.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freelist_chain_empty() {
        // DB with no freelist: trunk page pointer = 0
        let chains = walk_freelist_chain(&[], 0, 4096);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_freeblock_chain_parse() {
        // Craft a minimal page with one freeblock
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d; // table leaf
        // freeblock starts at offset 200
        page[1] = 0x00; page[2] = 0xc8; // first freeblock at 200
        // freeblock: next=0 (no more), size=20
        page[200] = 0x00; page[201] = 0x00; // next = 0
        page[202] = 0x00; page[203] = 0x14; // size = 20
        // fill freeblock with dummy data
        for i in 204..220 { page[i] = (i % 256) as u8; }

        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert_eq!(freeblocks.len(), 1);
        assert_eq!(freeblocks[0].offset, 200);
        assert_eq!(freeblocks[0].size, 20);
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics freelist
```

**Step 3: Implement**

`freelist.rs` — walk freelist trunk→leaf chain across the DB, collecting pages.
`carver.rs` — for each freelist/freeblock region:
1. Attempt NORMAL mode match (full header) → back-probe ROWID
2. Attempt COLUMNSONLY (no header length byte)
3. Attempt FIRSTCOLUMNMISSING (XX reconstruction)
4. Process matches last-to-first within each freeblock
5. Loop for stacked records while `remaining_bytes > 5`
6. Handle overflow page stitching
7. Tag all results `EvidenceSource::Freelist`

Key data structures:
```rust
pub struct Freeblock { pub offset: usize, pub size: usize, pub data: Vec<u8> }
pub struct CarveMatch { pub offset: usize, pub mode: CarveMode, pub header_hex: String }
pub enum CarveMode { Normal, ColumnsOnly, FirstColMissing }
```

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics freelist
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/freelist.rs \
        crates/chat4n6-sqlite-forensics/src/carver.rs
git commit -m "feat: Layer 4 — freelist chain walk and 3-mode freeblock carving"
```

---

### Task 9: Layer 5 — FTS shadow table cross-reference

**Files:**
- Modify: `crates/chat4n6-sqlite-forensics/src/db.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/fts.rs`

**Step 1: Write failing test**

```rust
// crates/chat4n6-sqlite-forensics/src/fts.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fts_docid_not_in_live_records_flagged() {
        // docid 99 exists in fts_content but not in live message ids
        let fts_entries = vec![
            FtsEntry { docid: 1, content: "hello".into() },
            FtsEntry { docid: 99, content: "deleted message".into() },
        ];
        let live_ids: std::collections::HashSet<i64> = [1].iter().cloned().collect();
        let recovered = cross_reference_fts(&fts_entries, &live_ids);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].docid, 99);
        assert_eq!(recovered[0].content, "deleted message");
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics fts
```

**Step 3: Implement**

```rust
// crates/chat4n6-sqlite-forensics/src/fts.rs
use std::collections::HashSet;
use chat4n6_plugin_api::EvidenceSource;

#[derive(Debug, Clone)]
pub struct FtsEntry {
    pub docid: i64,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct FtsRecoveredMessage {
    pub docid: i64,
    pub content: String,
    pub source: EvidenceSource,
}

pub fn cross_reference_fts(
    fts_entries: &[FtsEntry],
    live_message_ids: &HashSet<i64>,
) -> Vec<FtsRecoveredMessage> {
    fts_entries.iter()
        .filter(|e| !live_message_ids.contains(&e.docid))
        .map(|e| FtsRecoveredMessage {
            docid: e.docid,
            content: e.content.clone(),
            source: EvidenceSource::FtsOnly,
        })
        .collect()
}
```

In `db.rs`, add `recover_layer5_fts()` that:
1. Scans `sqlite_master` for tables named `message_fts_content`, `message_fts*`
2. Reads all rows from `message_fts_content` (columns: `docid`, `c0content`)
3. Calls `cross_reference_fts()` with live message IDs from Layer 1
4. Returns `Vec<FtsRecoveredMessage>`

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics fts
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/fts.rs
git commit -m "feat: Layer 5 — FTS shadow table cross-reference for deleted message recovery"
```

---

### Task 10: Layer 6 — Unallocated space carving with signature learning

**Files:**
- Create: `crates/chat4n6-sqlite-forensics/src/signature.rs`
- Create: `crates/chat4n6-sqlite-forensics/src/unalloc.rs`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-sqlite-forensics/src/signature.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_learns_from_live_records() {
        use crate::record::{RecoveredRecord, SqlValue};
        use chat4n6_plugin_api::EvidenceSource;
        let records = vec![
            RecoveredRecord { table: "msg".into(), row_id: Some(1),
                values: vec![SqlValue::Int(1), SqlValue::Text("hi".into())],
                source: EvidenceSource::Live, offset: 0, confidence: 1.0 },
            RecoveredRecord { table: "msg".into(), row_id: Some(2),
                values: vec![SqlValue::Int(2), SqlValue::Text("bye".into())],
                source: EvidenceSource::Live, offset: 0, confidence: 1.0 },
        ];
        let sig = TableSignature::learn("msg", &records);
        assert_eq!(sig.column_count, 2);
        assert!(sig.column_probability[0] > 0.9); // INT column seen in 100% of records
    }

    #[test]
    fn test_confidence_score_high_for_matching_record() {
        use crate::record::{RecoveredRecord, SqlValue};
        use chat4n6_plugin_api::EvidenceSource;
        let records = vec![
            RecoveredRecord { table: "msg".into(), row_id: Some(1),
                values: vec![SqlValue::Int(1), SqlValue::Text("hi".into())],
                source: EvidenceSource::Live, offset: 0, confidence: 1.0 },
        ];
        let sig = TableSignature::learn("msg", &records);
        let candidate = vec![SqlValue::Int(99), SqlValue::Text("carved".into())];
        let score = sig.score(&candidate);
        assert!(score > 0.8);
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-sqlite-forensics signature
```

**Step 3: Implement signature learning**

```rust
// crates/chat4n6-sqlite-forensics/src/signature.rs
use crate::record::{RecoveredRecord, SqlValue};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TableSignature {
    pub table: String,
    pub column_count: usize,
    pub column_probability: Vec<f32>,
    pub serial_type_frequencies: Vec<HashMap<u8, u32>>,
    pub total_records: u32,
}

impl TableSignature {
    pub fn learn(table: &str, records: &[RecoveredRecord]) -> Self {
        if records.is_empty() {
            return Self { table: table.into(), column_count: 0,
                          column_probability: vec![], serial_type_frequencies: vec![],
                          total_records: 0 };
        }
        let max_cols = records.iter().map(|r| r.values.len()).max().unwrap_or(0);
        let mut col_seen = vec![0u32; max_cols];
        let mut freq: Vec<HashMap<u8, u32>> = vec![HashMap::new(); max_cols];

        for rec in records {
            for (i, val) in rec.values.iter().enumerate() {
                col_seen[i] += 1;
                let type_byte = serial_type_of(val);
                *freq[i].entry(type_byte).or_insert(0) += 1;
            }
        }
        let n = records.len() as f32;
        let probs = col_seen.iter().map(|&c| c as f32 / n).collect();
        Self { table: table.into(), column_count: max_cols,
               column_probability: probs, serial_type_frequencies: freq,
               total_records: records.len() as u32 }
    }

    pub fn score(&self, candidate: &[SqlValue]) -> f32 {
        if self.total_records == 0 || candidate.is_empty() { return 0.0; }
        let mut sum = 0.0f32;
        let cols = candidate.len().min(self.column_count);
        for i in 0..cols {
            let t = serial_type_of(&candidate[i]);
            let freq = self.serial_type_frequencies.get(i)
                .and_then(|m| m.get(&t))
                .copied()
                .unwrap_or(0);
            sum += freq as f32 / self.total_records as f32;
        }
        sum / cols as f32
    }
}

fn serial_type_of(val: &SqlValue) -> u8 {
    match val {
        SqlValue::Null => 0,
        SqlValue::Int(_) => 1,
        SqlValue::Real(_) => 7,
        SqlValue::Text(_) => 13,
        SqlValue::Blob(_) => 12,
    }
}
```

`unalloc.rs`: scan `UnallocatedRegion` bytes for SQLite magic header → attempt DB reconstruction and run through all layers. Also implements raw page scanning using `TableSignature` patterns. Tag results `EvidenceSource::CarvedUnalloc { confidence }` and `EvidenceSource::CarvedDb`. Runs via `rayon::par_iter()` across regions.

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-sqlite-forensics signature
```

**Step 5: Commit**

```bash
git add crates/chat4n6-sqlite-forensics/src/signature.rs \
        crates/chat4n6-sqlite-forensics/src/unalloc.rs
git commit -m "feat: Layer 6 — unallocated carving with signature learning and confidence scoring"
```

---

## Phase 4: WhatsApp Plugin

### Task 11: crypt14/crypt15 decryption

**Files:**
- Create: `crates/plugins/chat4n6-whatsapp/src/decrypt.rs`

**Step 1: Write failing test**

```rust
// crates/plugins/chat4n6-whatsapp/src/decrypt.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_crypt14_magic() {
        // crypt14 header starts with specific magic
        let header = b"\x00\x00\x00\x01\x00\x00\x00\x01";
        // This test validates the detection logic, not actual decryption
        // (actual decryption tested with a known fixture in integration tests)
        assert_eq!(detect_crypt_version(b"msgstore.db.crypt14"), Some(14));
        assert_eq!(detect_crypt_version(b"msgstore.db.crypt15"), Some(15));
        assert_eq!(detect_crypt_version(b"msgstore.db"), None);
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-whatsapp decrypt
```

**Step 3: Implement**

```rust
// crates/plugins/chat4n6-whatsapp/src/decrypt.rs
use anyhow::{bail, Result};

pub fn detect_crypt_version(filename: &[u8]) -> Option<u8> {
    let name = std::str::from_utf8(filename).ok()?;
    if name.ends_with(".crypt15") { return Some(15); }
    if name.ends_with(".crypt14") { return Some(14); }
    if name.ends_with(".crypt12") { return Some(12); }
    None
}

/// Decrypt a WhatsApp crypt14 database.
/// key_bytes: 158-byte key file content from /data/data/com.whatsapp/files/key
pub fn decrypt_crypt14(ciphertext: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>> {
    // crypt14 format:
    // [32 bytes header] [16 bytes IV] [ciphertext] [20 bytes HMAC-SHA256]
    if key_bytes.len() < 158 { bail!("key file too short for crypt14"); }
    if ciphertext.len() < 69 { bail!("ciphertext too short"); }

    // Key material: bytes 126..158 of key file = 32-byte AES key
    let aes_key = &key_bytes[126..158];
    // IV: bytes 51..67 of ciphertext (after 32-byte header + 3 bytes)
    // Exact offsets vary by WhatsApp version — implement per reverse-engineered spec
    let iv = &ciphertext[51..67];
    let data = &ciphertext[67..ciphertext.len() - 20];

    use aes::Aes256;
    use cbc::Decryptor;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};

    let decryptor = Decryptor::<Aes256>::new(aes_key.into(), iv.into());
    let mut buf = data.to_vec();
    decryptor.decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow::anyhow!("decryption failed: {:?}", e))?;
    Ok(buf)
}

/// Decrypt a WhatsApp crypt15 database (AES-GCM).
pub fn decrypt_crypt15(ciphertext: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>> {
    if key_bytes.len() < 32 { bail!("key too short for crypt15"); }
    // crypt15: protobuf header + AES-256-GCM encrypted body
    // Parse protobuf to extract IV and actual ciphertext bounds
    // For MVP: use known fixed offsets from WhatsApp crypt15 format documentation
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
    let cipher = Aes256Gcm::new(key);
    // Offsets: protobuf header varies; use heuristic detection of nonce
    // Full implementation requires parsing the protobuf header
    let nonce_bytes = &ciphertext[ciphertext.len() - 28..ciphertext.len() - 16];
    let nonce = Nonce::from_slice(nonce_bytes);
    let payload = &ciphertext[..ciphertext.len() - 16];

    cipher.decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("crypt15 GCM decryption failed: {:?}", e))
}
```

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-whatsapp decrypt
```

**Step 5: Commit**

```bash
git add crates/plugins/chat4n6-whatsapp/src/decrypt.rs
git commit -m "feat: WhatsApp crypt14/crypt15 decryption"
```

---

### Task 12: WhatsApp schema detection & timezone

**Files:**
- Create: `crates/plugins/chat4n6-whatsapp/src/schema.rs`
- Create: `crates/plugins/chat4n6-whatsapp/src/timezone.rs`

**Step 1: Write failing tests**

```rust
// crates/plugins/chat4n6-whatsapp/src/schema.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_v1_detection() {
        // user_version < 1 and has "messages" table = legacy schema
        assert_eq!(detect_schema_version(0, &["messages", "wa_contacts"]),
                   SchemaVersion::Legacy);
    }

    #[test]
    fn test_schema_modern_detection() {
        assert_eq!(detect_schema_version(200, &["message", "message_media", "jid"]),
                   SchemaVersion::Modern);
    }
}

// crates/plugins/chat4n6-whatsapp/src/timezone.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tz_offset_named() {
        let offset = resolve_timezone_offset("Asia/Manila").unwrap();
        assert_eq!(offset, 8 * 3600);
    }

    #[test]
    fn test_parse_tz_offset_numeric() {
        let offset = resolve_timezone_offset("+08:00").unwrap();
        assert_eq!(offset, 8 * 3600);
    }

    #[test]
    fn test_utc_fallback() {
        let offset = resolve_timezone_offset("UTC").unwrap();
        assert_eq!(offset, 0);
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-whatsapp schema timezone
```

**Step 3: Implement**

```rust
// schema.rs
#[derive(Debug, PartialEq)]
pub enum SchemaVersion { Legacy, Modern }

pub fn detect_schema_version(user_version: u32, tables: &[&str]) -> SchemaVersion {
    let has_modern = tables.contains(&"message") && tables.contains(&"jid");
    if has_modern || user_version >= 100 { SchemaVersion::Modern }
    else { SchemaVersion::Legacy }
}

// timezone.rs — use chrono-tz for named zones, parse +HH:MM manually
pub fn resolve_timezone_offset(tz: &str) -> Option<i32> {
    use chrono_tz::Tz;
    use chrono::Utc;

    if let Ok(tz_enum) = tz.parse::<Tz>() {
        let now = Utc::now().with_timezone(&tz_enum);
        return Some(now.offset().fix().local_minus_utc());
    }
    // Try +HH:MM or -HH:MM
    if let Some(rest) = tz.strip_prefix('+').or_else(|| tz.strip_prefix('-')) {
        let sign = if tz.starts_with('-') { -1 } else { 1 };
        let parts: Vec<&str> = rest.split(':').collect();
        let h: i32 = parts.get(0)?.parse().ok()?;
        let m: i32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        return Some(sign * (h * 3600 + m * 60));
    }
    None
}
```

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-whatsapp schema timezone
```

**Step 5: Commit**

```bash
git add crates/plugins/chat4n6-whatsapp/src/schema.rs \
        crates/plugins/chat4n6-whatsapp/src/timezone.rs
git commit -m "feat: WhatsApp schema version detection and timezone resolution"
```

---

### Task 13: WhatsApp artifact extraction

**Files:**
- Create: `crates/plugins/chat4n6-whatsapp/src/extractor.rs`
- Create: `crates/plugins/chat4n6-whatsapp/src/lib.rs`

**Step 1: Write failing test**

```rust
// crates/plugins/chat4n6-whatsapp/src/extractor.rs
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_modern_msgstore() -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql")).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extracts_messages() {
        let db_bytes = make_modern_msgstore();
        let result = extract_from_msgstore(&db_bytes, 0, SchemaVersion::Modern).unwrap();
        assert!(!result.chats.is_empty());
        let all_msgs: Vec<_> = result.chats.iter()
            .flat_map(|c| c.messages.iter()).collect();
        assert!(all_msgs.iter().any(|m| matches!(m.content, MessageContent::Text(_))));
    }

    #[test]
    fn test_extracts_call_records() {
        let db_bytes = make_modern_msgstore();
        let result = extract_from_msgstore(&db_bytes, 0, SchemaVersion::Modern).unwrap();
        assert!(!result.calls.is_empty());
    }
}
```

Create `tests/fixtures/modern_schema.sql` with minimal WhatsApp modern schema + sample data.

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-whatsapp extractor
```

**Step 3: Implement extractor**

`extractor.rs` maps `RecoveredRecord` rows (from all 6 layers) to `Chat`, `Message`, `CallRecord`, etc. using column name→index mapping derived from `sqlite_master` schema. Handles both Legacy and Modern schema column layouts.

Key mapping logic:
- `message` table: `_id`, `chat_row_id`, `sender_jid_row_id`, `from_me`, `timestamp`, `text_data`, `message_type`
- `message_media`: join on `message_row_id` for MediaRef construction
- `message_add_on`: join on `parent_message_row_id` for reactions
- `call_log`: `_id`, `jid_row_id`, `from_me`, `video_call`, `duration`, `timestamp`

Implement `WhatsAppPlugin` struct in `lib.rs` that satisfies `ForensicPlugin`.

**Step 4: Run — expect PASS**

```bash
cargo test -p chat4n6-whatsapp
```

**Step 5: Commit**

```bash
git add crates/plugins/chat4n6-whatsapp/
git commit -m "feat: WhatsApp Android plugin — message, media, reaction, call extraction"
```

---

## Phase 5: HTML Report

### Task 14: Report templates and pagination

**Files:**
- Create: `crates/chat4n6-report/src/lib.rs`
- Create: `crates/chat4n6-report/src/paginator.rs`
- Create: `crates/chat4n6-report/templates/index.html`
- Create: `crates/chat4n6-report/templates/chat_page.html`
- Create: `crates/chat4n6-report/templates/calls.html`
- Create: `crates/chat4n6-report/templates/deleted.html`

**Step 1: Write failing tests**

```rust
// crates/chat4n6-report/src/paginator.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginate_500_messages_into_2_pages() {
        let items: Vec<i32> = (0..750).collect();
        let pages = paginate(&items, 500);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].len(), 500);
        assert_eq!(pages[1].len(), 250);
    }

    #[test]
    fn test_paginate_exact_fit() {
        let items: Vec<i32> = (0..500).collect();
        let pages = paginate(&items, 500);
        assert_eq!(pages.len(), 1);
    }

    #[test]
    fn test_paginate_empty() {
        let items: Vec<i32> = vec![];
        let pages = paginate(&items, 500);
        assert!(pages.is_empty());
    }
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p chat4n6-report paginator
```

**Step 3: Implement paginator**

```rust
// crates/chat4n6-report/src/paginator.rs
pub fn paginate<T: Clone>(items: &[T], page_size: usize) -> Vec<Vec<T>> {
    if items.is_empty() { return vec![]; }
    items.chunks(page_size).map(|c| c.to_vec()).collect()
}
```

**Step 4: Implement report generator**

`lib.rs` — `ReportGenerator` struct with:
- `render(case: &CaseReport, output_dir: &Path, page_size: usize) -> Result<()>`
- Creates directory structure
- Renders each template with Tera
- Writes `carve-results.json`

Templates use Tera syntax. Each template receives context with:
- `case_name`, `generated_at_utc`, `timezone_label`
- `messages` (for chat pages), `calls`, `wal_deltas`, etc.
- Pagination: `current_page`, `total_pages`, `prev_url`, `next_url`

Evidence badge macro in base template:
```html
{% macro badge(source) %}
<span class="badge badge-{{ source | lower | replace(from=" ", to="-") }}">
  [{{ source }}]
</span>
{% endmacro %}
```

**Step 5: Run — expect PASS**

```bash
cargo test -p chat4n6-report
```

**Step 6: Commit**

```bash
git add crates/chat4n6-report/
git commit -m "feat: HTML report generator with Tera templates and pagination"
```

---

## Phase 6: CLI & Integration

### Task 15: CLI and end-to-end pipeline

**Files:**
- Create: `cli/src/main.rs`
- Create: `cli/src/commands/run.rs`
- Create: `cli/src/commands/extract.rs`
- Create: `cli/src/commands/carve.rs`
- Create: `cli/src/commands/report.rs`

**Step 1: Write failing integration test**

```rust
// cli/tests/integration.rs
use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn test_run_with_plaintext_dir_produces_report() {
    let output = TempDir::new().unwrap();
    // Use a test fixture directory with minimal msgstore.db
    let mut cmd = Command::cargo_bin("chat4n6").unwrap();
    cmd.args(["run",
              "--input", "tests/fixtures/whatsapp_dir",
              "--output", output.path().to_str().unwrap(),
              "--no-unalloc"])
       .assert()
       .success();

    assert!(output.path().join("index.html").exists());
    assert!(output.path().join("carve-results.json").exists());
}
```

**Step 2: Run — expect FAIL**

```bash
cargo test -p cli
```

**Step 3: Implement CLI**

`cli/src/main.rs` using `clap` derive API:
```rust
#[derive(Parser)]
#[command(name = "chat4n6", version, about = "Forensic chat extraction tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Extract(ExtractArgs),
    Carve(CarveArgs),
    Report(ReportArgs),
}
```

`commands/run.rs` — orchestrates the full pipeline:
1. Open input (detect DAR vs plaintext dir)
2. Run registered plugins (detect → extract)
3. Serialize `carve-results.json`
4. Generate HTML report

Use `indicatif` for progress bars per layer.

**Step 4: Run — expect PASS**

```bash
cargo test -p cli
```

**Step 5: Full build**

```bash
cargo build --release
./target/release/chat4n6 --help
```

**Step 6: Commit**

```bash
git add cli/
git commit -m "feat: CLI with run/extract/carve/report subcommands and end-to-end pipeline"
```

---

## Phase 7: Polish & Documentation

### Task 16: Test fixtures and CI

**Files:**
- Create: `tests/fixtures/` (minimal SQLite DBs, WAL files)
- Create: `.github/workflows/ci.yml`

**Step 1: Create test fixtures**

Write a `tests/fixtures/create_fixtures.sh` script that creates:
- `minimal_msgstore.db` — modern schema with 5 messages, 1 call, 1 reaction
- `minimal_msgstore.db-wal` — 2 pending WAL frames
- `whatsapp_dir/data/data/com.whatsapp/databases/` — full fixture tree

**Step 2: Add CI workflow**

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo fmt --check
```

**Step 3: Run full test suite**

```bash
cargo test --workspace
cargo clippy --workspace
cargo fmt --check
```

**Step 4: Commit**

```bash
git add tests/fixtures/ .github/
git commit -m "chore: add test fixtures and GitHub Actions CI pipeline"
```

---

### Task 17: Final integration and push

**Step 1: Verify full build**

```bash
cargo build --release 2>&1 | tail -5
```
Expected: `Finished release [optimized] target(s)`

**Step 2: Run complete test suite**

```bash
cargo test --workspace --release
```
Expected: all tests pass.

**Step 3: Final commit**

```bash
git add -A
git commit -m "chore: final cleanup and release build verification"
```

**Step 4: Push to GitHub**

```bash
git remote add origin https://github.com/SecurityRonin/chat4n6.git
git push -u origin main
```

---

## Key Test Design Principles

- Every public function has at least one unit test before implementation (TDD)
- Binary format tests use crafted byte arrays, not real evidence files
- Integration tests use synthetic SQLite fixtures created via `rusqlite` in test setup
- Real DAR/crypt14 fixture tests are `#[ignore]` — run manually with actual case data
- All tests must pass with `cargo test --workspace` from a clean checkout

## Dependency Reference

```toml
# Add to each crate's Cargo.toml as needed:
[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
nom = { workspace = true }
chrono = { workspace = true }
chrono-tz = { workspace = true }
sha2 = { workspace = true }
base64 = { workspace = true }
rayon = { workspace = true }
log = { workspace = true }
tera = "1"                # chat4n6-report only
clap = { version = "4", features = ["derive"] }  # cli only
indicatif = "0.17"        # cli only
aes = "0.8"               # chat4n6-whatsapp only
aes-gcm = "0.10"          # chat4n6-whatsapp only
cbc = "0.1"               # chat4n6-whatsapp only
memmap2 = "0.9"           # chat4n6-core only
rusqlite = "0.31"         # dev-dependencies only (fixture creation)
tempfile = "3"            # dev-dependencies only
assert_cmd = "2"          # cli dev-dependencies only
```
