# DAR + iOS Backup Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add native DAR archive reading and iOS backup reading to chat4n6 by introducing `dar-archive`, `ios-backup`, and `chat4n6-fs` crates, then updating the CLI to auto-detect input type.

**Architecture:** Two standalone generic crates (`dar-archive`, `ios-backup`) provide format-specific reading with no forensic dependencies. A third crate (`chat4n6-fs`) adapts both into the `ForensicFs` trait and replaces `chat4n6-core`. The CLI auto-detects `.dar` files, iOS backup directories, and plaintext directories.

**Tech Stack:** Rust, memmap2 (mmap), rusqlite (iOS Manifest.db), thiserror, anyhow, chat4n6-plugin-api (ForensicFs/ForensicPlugin traits).

---

### Task 1: Bootstrap `dar-archive` crate and migrate infinint

**Files:**
- Create: `crates/dar-archive/Cargo.toml`
- Create: `crates/dar-archive/src/lib.rs`
- Create: `crates/dar-archive/src/infinint.rs`
- Create: `crates/dar-archive/src/scanner.rs`
- Modify: `Cargo.toml` (workspace root — add member)

**Step 1: Add member to workspace**

In `Cargo.toml` (root), add `"crates/dar-archive"` to the `[workspace] members` array.

**Step 2: Create `crates/dar-archive/Cargo.toml`**

```toml
[package]
name = "dar-archive"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Pure-Rust reader for DAR (Disk ARchive) archives"
readme = "README.md"
keywords = ["dar", "archive", "forensics"]
categories = ["parser-implementations"]

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
memmap2 = "0.9"

[dev-dependencies]
tempfile = "3"
```

**Step 3: Create `crates/dar-archive/src/lib.rs`**

```rust
pub mod infinint;
pub mod scanner;
pub mod archive;

pub use archive::{DarArchive, DarEntry};
```

**Step 4: Create `crates/dar-archive/src/infinint.rs`**

Copy the `decode_infinint` function and its tests verbatim from
`crates/chat4n6-core/src/dar/mod.rs` lines 31–124. Do NOT copy `DarVersion`
(the bad magic bytes) — only `decode_infinint` and its `#[cfg(test)]` block.

```rust
use anyhow::{bail, Result};

/// Decode a DAR infinint (variable-length integer).
/// Format: N zero bytes followed by N non-zero bytes (big-endian value).
/// Special case: single non-zero byte encodes that value directly (N=0).
/// Returns (value, bytes_consumed).
pub fn decode_infinint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        bail!("empty infinint");
    }
    let all_zero = data.iter().all(|&b| b == 0);
    let zero_count = if all_zero {
        data.len() / 2
    } else {
        let mut n = 0usize;
        for &b in data {
            if b == 0 { n += 1; } else { break; }
        }
        n
    };
    if zero_count == 0 {
        return Ok((data[0] as u64, 1));
    }
    let end = zero_count * 2;
    if data.len() < end {
        bail!("truncated infinint: need {} bytes, have {}", end, data.len());
    }
    let value_bytes = &data[zero_count..end];
    let mut value = 0u64;
    for &b in value_bytes {
        value = (value << 8) | b as u64;
    }
    Ok((value, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_nonzero_byte() {
        assert_eq!(decode_infinint(&[0x05]).unwrap(), (5u64, 1));
    }

    #[test]
    fn test_one_zero_prefix() {
        // 1 zero + 1 value byte: value = 5
        assert_eq!(decode_infinint(&[0x00, 0x05]).unwrap(), (5u64, 2));
    }

    #[test]
    fn test_two_zero_prefix() {
        // 2 zero + 2 value bytes: 0x01 0x00 = 256
        assert_eq!(decode_infinint(&[0x00, 0x00, 0x01, 0x00]).unwrap(), (256u64, 4));
    }

    #[test]
    fn test_zero_value() {
        assert_eq!(decode_infinint(&[0x00, 0x00]).unwrap(), (0u64, 2));
    }

    #[test]
    fn test_truncated_error() {
        assert!(decode_infinint(&[0x00, 0x00, 0x01]).is_err());
    }
}
```

**Step 5: Create `crates/dar-archive/src/scanner.rs`**

```rust
/// Find the byte offset of the first `zzzzz` (five 0x7a bytes) in `data`.
pub fn find_zzzzz(data: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = &[0x7a, 0x7a, 0x7a, 0x7a, 0x7a];
    data.windows(5).position(|w| w == MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finds_marker() {
        let data = b"\x00\x01\x7a\x7a\x7a\x7a\x7a\xff";
        assert_eq!(find_zzzzz(data), Some(2));
    }

    #[test]
    fn test_absent() {
        assert_eq!(find_zzzzz(b"\x00\x01\x02"), None);
    }

    #[test]
    fn test_at_start() {
        let data = b"\x7a\x7a\x7a\x7a\x7a\x00";
        assert_eq!(find_zzzzz(data), Some(0));
    }
}
```

**Step 6: Create stub `crates/dar-archive/src/archive.rs`**

```rust
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use memmap2::Mmap;

#[derive(Debug, Clone)]
pub struct DarEntry {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub permissions: u32,
    pub slice_index: usize,
    pub data_offset: u64,
}

pub struct DarArchive {
    mmaps: Vec<Mmap>,
    entries: Vec<DarEntry>,
}

impl DarArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        // SAFETY: file is read-only and not modified while mapped.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("cannot mmap {}", path.display()))?;
        let mut archive = Self { mmaps: vec![mmap], entries: Vec::new() };
        archive.load_catalog(0)?;
        Ok(archive)
    }

    pub fn entries(&self) -> &[DarEntry] {
        &self.entries
    }

    pub fn read<'a>(&'a self, entry: &DarEntry) -> Result<Cow<'a, [u8]>> {
        let mmap = &self.mmaps[entry.slice_index];
        let start = entry.data_offset as usize;
        let end = start + entry.size as usize;
        anyhow::ensure!(end <= mmap.len(), "entry data out of bounds: {}", entry.path.display());
        Ok(Cow::Borrowed(&mmap[start..end]))
    }

    fn load_catalog(&mut self, _slice_index: usize) -> Result<()> {
        // Stub — implemented in Task 3
        Ok(())
    }
}
```

**Step 7: Run tests**

```
cargo test -p dar-archive
```

Expected: 8 tests pass (5 infinint + 3 scanner).

**Step 8: Commit**

```bash
git add crates/dar-archive/ Cargo.toml
git -c commit.gpgsign=false commit -m "feat(dar-archive): bootstrap crate, migrate infinint, scanner"
```

---

### Task 2: Add format-discovery test for DAR catalog

This task writes an `#[ignore]` test that dumps catalog bytes from a real `.dar`
file. Run it locally to study the binary format before implementing the parser in Task 3.

**Files:**
- Create: `crates/dar-archive/tests/discovery.rs`

**Step 1: Create the test**

```rust
//! Run locally against a real .dar file to analyze catalog structure:
//!   cargo test -p dar-archive --test discovery -- --nocapture --ignored
//!
//! Update DAR_PATH before running.

use dar_archive::scanner::find_zzzzz;
use memmap2::Mmap;
use std::fs::File;

const DAR_PATH: &str = "/path/to/userdata.1.dar"; // ← update this

#[test]
#[ignore = "requires real .dar fixture; run manually for format discovery"]
fn dump_catalog_bytes() {
    let file = File::open(DAR_PATH).expect("open dar file");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap");
    let data: &[u8] = &mmap;

    let pos = find_zzzzz(data).expect("no zzzzz found in file");
    println!("zzzzz at offset {pos} (0x{pos:08x}), file size = {}", data.len());

    let after = &data[pos + 5..];
    println!("\nFirst 512 bytes after zzzzz (catalog start):");
    for (i, chunk) in after[..512.min(after.len())].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        println!("  {:04x}: {:48}  |{}|", i * 16, hex.join(" "), ascii);
    }

    if let Some(pos2) = find_zzzzz(&after[5..]) {
        let catalog_size = pos2 + 5;
        println!("\nSecond zzzzz at +{} from catalog start", pos2 + 5);
        println!("Catalog section size: {catalog_size} bytes");
    } else {
        println!("\nNo second zzzzz found — catalog may extend to EOF");
    }

    // Print a 16-byte window around each printable ASCII run
    println!("\n--- Named entries near start of catalog ---");
    let search_len = 4096.min(after.len());
    let mut i = 0;
    let mut shown = 0;
    while i < search_len && shown < 20 {
        // Look for runs of printable ASCII >= 4 chars (likely filenames)
        if after[i].is_ascii_alphanumeric() || after[i] == b'/' || after[i] == b'.' {
            let start = i.saturating_sub(4);
            let end = (i + 32).min(after.len());
            let hex: Vec<String> = after[start..end].iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = after[start..end]
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect();
            println!("  offset {:04x}: {:48}  |{}|", start, hex.join(" "), ascii);
            i += 32;
            shown += 1;
        } else {
            i += 1;
        }
    }
}
```

**Step 2: Update `DAR_PATH` and run**

```bash
# Edit tests/discovery.rs to set DAR_PATH to the real file, then:
cargo test -p dar-archive --test discovery -- --nocapture --ignored
```

Study the output. Key things to identify in the hex dump:
- The type byte pattern (first byte of each entry)
- How names are length-prefixed (infinint before name, or NUL-terminated?)
- How file sizes and data offsets are stored (look for recognisable values)
- How directory entries differ from file entries

Record your findings — you will use them to write the catalog parser in Task 3.

**Step 3: Run non-ignored tests to confirm nothing is broken**

```bash
cargo test -p dar-archive
```

**Step 4: Commit**

```bash
git add crates/dar-archive/tests/
git -c commit.gpgsign=false commit -m "test(dar-archive): add format-discovery test"
```

---

### Task 3: Implement DAR catalog parser

> **Before starting:** Run the Task 2 discovery test and study the hex output.
> The `parse_entry` function below uses placeholder format assumptions — adjust
> the type byte constants and attribute layout to match what you observe.
>
> The known facts about DAR format v9 ("090\0"):
> - The first `zzzzz` (5 × 0x7a) separates file data from the catalog section.
> - The catalog section ends at the second `zzzzz`.
> - Entry names are stored as length-prefixed strings (infinint length + UTF-8 bytes).
> - File sizes and data offsets are stored as infinints.
> - Directory entries have no data offset/size.

**Files:**
- Create: `crates/dar-archive/src/catalog.rs`
- Modify: `crates/dar-archive/src/lib.rs` (add `pub mod catalog;`)
- Modify: `crates/dar-archive/src/archive.rs` (wire up catalog parser)

**Step 1: Create `crates/dar-archive/src/catalog.rs` with tests first**

```rust
use std::path::PathBuf;
use anyhow::{bail, Result};
use crate::infinint::decode_infinint;
use crate::archive::DarEntry;

// ── Type byte constants ──────────────────────────────────────────────────────
// Adjust these after studying the discovery test output.
// These are initial guesses based on the DAR format specification.
const TYPE_FILE: u8      = 0x02;  // regular file
const TYPE_DIR: u8       = 0x04;  // directory
const TYPE_END: u8       = 0x00;  // end of catalog

/// Parse all catalog entries from `data` (the bytes immediately after the first zzzzz).
/// `slice_index` is stored in every returned DarEntry.
pub fn parse_catalog(data: &[u8], slice_index: usize) -> Result<Vec<DarEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // End-of-catalog: second zzzzz or explicit terminator
        if pos + 5 <= data.len() && &data[pos..pos + 5] == b"zzzzz" {
            break;
        }
        let type_byte = data[pos];
        if type_byte == TYPE_END {
            break;
        }
        match parse_one_entry(&data[pos..], slice_index) {
            Ok((entry, consumed)) => {
                pos += consumed;
                if let Some(e) = entry {
                    entries.push(e);
                }
            }
            Err(e) => {
                // Graceful degradation: stop at parse error rather than returning Err.
                // This lets partial catalogs still yield results.
                eprintln!("catalog parse stopped at offset 0x{pos:x}: {e}");
                break;
            }
        }
    }

    Ok(entries)
}

/// Parse one catalog entry starting at `data[0]`.
/// Returns `(Some(DarEntry), bytes_consumed)` for file/dir entries,
/// or `(None, bytes_consumed)` for other entry types (symlinks, etc.).
fn parse_one_entry(data: &[u8], slice_index: usize) -> Result<(Option<DarEntry>, usize)> {
    if data.is_empty() {
        bail!("empty entry data at parse_one_entry");
    }
    let type_byte = data[0];
    let mut pos = 1;

    // ── Entry name ──────────────────────────────────────────────────────────
    // DAR stores: infinint(name_len) + name_bytes
    let (name_len, consumed) = decode_infinint(&data[pos..])
        .map_err(|e| anyhow::anyhow!("name_len infinint: {e}"))?;
    pos += consumed;
    let name_end = pos + name_len as usize;
    anyhow::ensure!(name_end <= data.len(), "truncated entry name (need {name_end}, have {})", data.len());
    let name = std::str::from_utf8(&data[pos..name_end])
        .map_err(|_| anyhow::anyhow!("non-UTF8 entry name"))?
        .to_owned();
    pos = name_end;

    // ── TODO: skip over attribute fields ────────────────────────────────────
    // After the name, DAR stores various attribute blocs (permissions, UID, GID,
    // dates, etc.) depending on flags embedded in the type byte.
    // Adjust this section based on what you see in the discovery test output.
    //
    // For now: assume a fixed-size attribute block of 0 bytes (NO attributes saved).
    // If entries don't parse correctly, add attribute-skipping logic here.

    match type_byte & 0x7F {  // mask off high bit if used as a flag
        t if t == TYPE_DIR => {
            // Directories have no data offset/size
            Ok((Some(DarEntry {
                path: PathBuf::from(&name),
                size: 0,
                is_dir: true,
                permissions: 0o755,
                slice_index,
                data_offset: 0,
            }), pos))
        }
        t if t == TYPE_FILE => {
            // File: size (infinint) + data_offset (infinint)
            let (size, c) = decode_infinint(&data[pos..])
                .map_err(|e| anyhow::anyhow!("file size infinint for '{name}': {e}"))?;
            pos += c;
            let (data_offset, c) = decode_infinint(&data[pos..])
                .map_err(|e| anyhow::anyhow!("data_offset infinint for '{name}': {e}"))?;
            pos += c;
            Ok((Some(DarEntry {
                path: PathBuf::from(&name),
                size,
                is_dir: false,
                permissions: 0o644,
                slice_index,
                data_offset,
            }), pos))
        }
        _ => {
            // Unknown type — skip by trying to advance past the name only.
            // This is a best-effort: may de-sync if the entry has extra fields.
            Ok((None, pos))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic catalog using the same encoding as decode_infinint:
    /// - Non-zero bytes < 128 encode their value directly (1 byte).
    /// - Zero-prefixed: N zero bytes + N value bytes.
    fn encode_infinint(value: u64) -> Vec<u8> {
        if value < 128 && value != 0 {
            return vec![value as u8];
        }
        if value == 0 {
            return vec![0x00, 0x00]; // 1 zero prefix + 1 zero value byte
        }
        // 2-byte value: 1 zero prefix + 2 value bytes
        if value <= 0xFFFF {
            return vec![0x00, (value >> 8) as u8, value as u8];
        }
        // 3-byte value
        vec![0x00, 0x00, 0x00, (value >> 16) as u8, (value >> 8) as u8, value as u8]
    }

    fn synthetic_catalog() -> Vec<u8> {
        let mut buf = Vec::new();
        // Directory entry: type=TYPE_DIR, name="testdir"
        buf.push(TYPE_DIR);
        buf.extend(encode_infinint(7)); // name_len = 7
        buf.extend_from_slice(b"testdir");

        // File entry: type=TYPE_FILE, name="hello.txt", size=13, offset=512
        buf.push(TYPE_FILE);
        buf.extend(encode_infinint(9)); // name_len = 9
        buf.extend_from_slice(b"hello.txt");
        buf.extend(encode_infinint(13));  // size
        buf.extend(encode_infinint(512)); // data_offset

        // End of catalog
        buf.push(TYPE_END);
        buf
    }

    #[test]
    fn test_parse_synthetic_catalog_counts() {
        let data = synthetic_catalog();
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 2, "expected 2 entries (1 dir + 1 file)");
    }

    #[test]
    fn test_parse_synthetic_catalog_dir_entry() {
        let data = synthetic_catalog();
        let entries = parse_catalog(&data, 0).unwrap();
        let dir = entries.iter().find(|e| e.is_dir).expect("directory entry");
        assert_eq!(dir.path.to_str().unwrap(), "testdir");
    }

    #[test]
    fn test_parse_synthetic_catalog_file_entry() {
        let data = synthetic_catalog();
        let entries = parse_catalog(&data, 0).unwrap();
        let file = entries.iter().find(|e| !e.is_dir).expect("file entry");
        assert_eq!(file.path.to_str().unwrap(), "hello.txt");
        assert_eq!(file.size, 13);
        assert_eq!(file.data_offset, 512);
    }

    #[test]
    fn test_parse_stops_at_second_zzzzz() {
        let mut data = synthetic_catalog();
        // Append a second zzzzz — parser should stop here
        data.extend_from_slice(b"zzzzz");
        data.push(TYPE_FILE); // garbage after zzzzz — should be ignored
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
```

**Step 2: Run the tests — they should pass for the synthetic catalog**

```bash
cargo test -p dar-archive -- catalog
```

Expected: 4 tests pass. If they fail, fix `TYPE_FILE`, `TYPE_DIR`, or `encode_infinint`
to match the actual format observed in the discovery test.

**Step 3: Wire up the catalog parser in `archive.rs`**

Add `pub mod catalog;` to `lib.rs` (it's already in lib.rs if you followed Task 1).

Replace the stub `load_catalog` in `archive.rs`:

```rust
fn load_catalog(&mut self, slice_index: usize) -> Result<()> {
    let data: &[u8] = &self.mmaps[slice_index];
    let pos = crate::scanner::find_zzzzz(data)
        .ok_or_else(|| anyhow::anyhow!("no zzzzz terminator found in slice {slice_index}"))?;
    let catalog_data = &data[pos + 5..];
    let mut new_entries = crate::catalog::parse_catalog(catalog_data, slice_index)?;
    self.entries.append(&mut new_entries);
    Ok(())
}
```

**Step 4: Run all dar-archive tests**

```bash
cargo test -p dar-archive
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add crates/dar-archive/src/catalog.rs crates/dar-archive/src/lib.rs crates/dar-archive/src/archive.rs
git -c commit.gpgsign=false commit -m "feat(dar-archive): implement catalog parser"
```

---

### Task 4: Implement `open_slices()` and real-file integration tests

**Files:**
- Modify: `crates/dar-archive/src/archive.rs`
- Create: `crates/dar-archive/tests/integration.rs`

**Step 1: Write a failing test for `open_slices()`**

Create `crates/dar-archive/tests/integration.rs`:

```rust
use dar_archive::DarArchive;
use std::path::Path;

// Update these paths before running integration tests locally.
const SINGLE_SLICE_PATH: &str = "/path/to/userdata.1.dar";
const MULTI_SLICE_BASENAME: &str = "/path/to/userdata";

fn fixture_present() -> bool {
    Path::new(SINGLE_SLICE_PATH).exists()
}

#[test]
fn test_open_single_slice_has_entries() {
    if !fixture_present() {
        eprintln!("Skipping: real .dar fixture not present at {SINGLE_SLICE_PATH}");
        return;
    }
    let archive = DarArchive::open(Path::new(SINGLE_SLICE_PATH))
        .expect("DarArchive::open");
    let count = archive.entries().len();
    println!("entries: {count}");
    assert!(count > 0, "expected entries in catalog");
}

#[test]
fn test_open_single_slice_contains_whatsapp() {
    if !fixture_present() { return; }
    let archive = DarArchive::open(Path::new(SINGLE_SLICE_PATH)).unwrap();
    let found = archive.entries().iter().any(|e| {
        e.path.to_str().map_or(false, |p| p.contains("com.whatsapp"))
    });
    assert!(found, "expected a com.whatsapp entry in the catalog");
}

#[test]
fn test_open_slices_finds_first_slice() {
    if !fixture_present() { return; }
    let archive = DarArchive::open_slices(Path::new(MULTI_SLICE_BASENAME))
        .expect("DarArchive::open_slices");
    assert!(!archive.entries().is_empty());
}
```

**Step 2: Run — tests should skip gracefully without the fixture**

```bash
cargo test -p dar-archive --test integration
```

Expected: tests print "Skipping" and pass (no fixture in CI).

**Step 3: Implement `open_slices()` in `archive.rs`**

```rust
/// Open a multi-slice archive given the basename (no slice number, no extension).
/// Example: `open_slices(Path::new("/path/to/userdata"))` opens
/// `userdata.1.dar`, `userdata.2.dar`, … until no next slice is found.
pub fn open_slices(basename: &Path) -> Result<Self> {
    let parent = basename.parent().unwrap_or(Path::new("."));
    let stem = basename
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid basename: {}", basename.display()))?;

    let mut mmaps = Vec::new();
    let mut slice_num = 1usize;
    loop {
        let slice_path = parent.join(format!("{stem}.{slice_num}.dar"));
        if !slice_path.exists() {
            break;
        }
        let file = std::fs::File::open(&slice_path)
            .with_context(|| format!("cannot open {}", slice_path.display()))?;
        // SAFETY: read-only mapping; file not modified while mapped.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("cannot mmap {}", slice_path.display()))?;
        mmaps.push(mmap);
        slice_num += 1;
    }
    anyhow::ensure!(
        !mmaps.is_empty(),
        "no slices found for basename: {}",
        basename.display()
    );

    let mut archive = Self { mmaps, entries: Vec::new() };
    for i in 0..archive.mmaps.len() {
        archive.load_catalog(i)?;
    }
    Ok(archive)
}
```

**Step 4: Run all dar-archive tests**

```bash
cargo test -p dar-archive
```

Expected: all unit tests pass; integration tests skip.

**Step 5: Run integration tests with real file (local only)**

Update the paths in `tests/integration.rs` and run:

```bash
cargo test -p dar-archive --test integration -- --nocapture
```

Verify entries count > 0 and WhatsApp paths appear.

**Step 6: Commit**

```bash
git add crates/dar-archive/src/archive.rs crates/dar-archive/tests/
git -c commit.gpgsign=false commit -m "feat(dar-archive): add open_slices, integration tests"
```

---

### Task 5: Bootstrap `ios-backup` crate

**Files:**
- Create: `crates/ios-backup/Cargo.toml`
- Create: `crates/ios-backup/src/lib.rs`
- Modify: `Cargo.toml` (workspace root)

**Step 1: Add ios-backup to workspace**

In root `Cargo.toml`, add `"crates/ios-backup"` to members.

**Step 2: Create `crates/ios-backup/Cargo.toml`**

```toml
[package]
name = "ios-backup"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Pure-Rust reader for iOS device backups (unencrypted)"
readme = "README.md"
keywords = ["ios", "backup", "itunes", "forensics"]
categories = ["parser-implementations"]

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
rusqlite = { version = "0.31", features = ["bundled"] }
```

**Step 3: Write failing tests and implementation in `crates/ios-backup/src/lib.rs`**

Write the tests first (`#[cfg(test)]` block), run to confirm they fail, then implement.

```rust
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BackupEntry {
    pub domain: String,
    pub relative_path: String,
    pub file_id: String, // 40-char SHA-1 hex string
    pub flags: u32,
}

pub struct IosBackup {
    backup_dir: PathBuf,
    entries: Vec<BackupEntry>,
}

impl IosBackup {
    /// Open a backup directory. Reads `Manifest.db` once and builds an in-memory index.
    pub fn open(backup_dir: &Path) -> Result<Self> {
        let manifest = backup_dir.join("Manifest.db");
        anyhow::ensure!(
            manifest.exists(),
            "Manifest.db not found in {}",
            backup_dir.display()
        );
        let conn = Connection::open(&manifest)
            .with_context(|| format!("cannot open {}", manifest.display()))?;
        let mut stmt = conn
            .prepare(
                "SELECT fileID, domain, relativePath, flags \
                 FROM Files WHERE relativePath != '' AND relativePath IS NOT NULL",
            )
            .context("prepare Files query")?;
        let entries: Vec<BackupEntry> = stmt
            .query_map([], |row| {
                Ok(BackupEntry {
                    file_id: row.get(0)?,
                    domain: row.get(1)?,
                    relative_path: row.get(2)?,
                    flags: row.get::<_, u32>(3)?,
                })
            })
            .context("query Files")?
            .collect::<Result<_, _>>()
            .context("collect entries")?;
        Ok(Self {
            backup_dir: backup_dir.to_path_buf(),
            entries,
        })
    }

    pub fn entries(&self) -> &[BackupEntry] {
        &self.entries
    }

    /// Find an entry by domain + relative_path.
    pub fn get(&self, domain: &str, relative_path: &str) -> Option<&BackupEntry> {
        self.entries
            .iter()
            .find(|e| e.domain == domain && e.relative_path == relative_path)
    }

    /// Read the backing file for an entry.
    /// Backing file path: `<backup_dir>/<file_id[0..2]>/<file_id>`
    pub fn read(&self, entry: &BackupEntry) -> Result<Vec<u8>> {
        let sub = &entry.file_id[..2];
        let path = self.backup_dir.join(sub).join(&entry.file_id);
        std::fs::read(&path)
            .with_context(|| format!("cannot read backup file {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_backup(tmp: &TempDir) -> PathBuf {
        let dir = tmp.path().to_path_buf();
        let conn = Connection::open(dir.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (
                fileID TEXT PRIMARY KEY,
                domain TEXT,
                relativePath TEXT,
                flags INTEGER,
                file BLOB
            );
            INSERT INTO Files VALUES (
                'aabbccdd1122334455667788990011223344556677',
                'AppDomain-net.whatsapp.WhatsApp',
                'Documents/ChatStorage.sqlite',
                1, NULL
            );",
        )
        .unwrap();
        let sub = dir.join("aa");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("aabbccdd1122334455667788990011223344556677"),
            b"fake-sqlite-content",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_open_reads_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        assert_eq!(backup.entries().len(), 1);
    }

    #[test]
    fn test_get_finds_by_domain_and_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        let entry = backup.get(
            "AppDomain-net.whatsapp.WhatsApp",
            "Documents/ChatStorage.sqlite",
        );
        assert!(entry.is_some());
        assert_eq!(
            entry.unwrap().file_id,
            "aabbccdd1122334455667788990011223344556677"
        );
    }

    #[test]
    fn test_get_returns_none_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        assert!(backup.get("AppDomain-net.whatsapp.WhatsApp", "no-such-file").is_none());
    }

    #[test]
    fn test_read_returns_file_content() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        let entry = backup
            .get("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite")
            .unwrap();
        let content = backup.read(entry).unwrap();
        assert_eq!(content, b"fake-sqlite-content");
    }
}
```

**Step 4: Run tests**

```bash
cargo test -p ios-backup
```

Expected: 4 tests pass.

**Step 5: Commit**

```bash
git add crates/ios-backup/ Cargo.toml
git -c commit.gpgsign=false commit -m "feat(ios-backup): bootstrap crate, implement Manifest.db reading"
```

---

### Task 6: Bootstrap `chat4n6-fs` crate and migrate `PlaintextDirFs`

**Files:**
- Create: `crates/chat4n6-fs/Cargo.toml`
- Create: `crates/chat4n6-fs/src/lib.rs`
- Create: `crates/chat4n6-fs/src/plaintext_fs.rs`
- Modify: `Cargo.toml` (workspace root)

**Step 1: Add chat4n6-fs to workspace**

In root `Cargo.toml`, add `"crates/chat4n6-fs"` to members.

**Step 2: Create `crates/chat4n6-fs/Cargo.toml`**

```toml
[package]
name = "chat4n6-fs"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "ForensicFs adapters (plaintext dir, DAR archive, iOS backup) for chat4n6"
readme = "README.md"
keywords = ["forensics", "filesystem", "dar", "ios"]
categories = ["filesystem"]

[dependencies]
anyhow = { workspace = true }
chat4n6-plugin-api = { path = "../chat4n6-plugin-api", version = "0.1" }
dar-archive = { path = "../dar-archive", version = "0.1" }
ios-backup = { path = "../ios-backup", version = "0.1" }

[dev-dependencies]
tempfile = "3"
rusqlite = { version = "0.31", features = ["bundled"] }
```

**Step 3: Create `crates/chat4n6-fs/src/lib.rs`**

```rust
pub mod plaintext_fs;
pub use plaintext_fs::PlaintextDirFs;
```

**Step 4: Copy `PlaintextDirFs` verbatim**

Copy the full content of `crates/chat4n6-core/src/plaintext_fs.rs` to
`crates/chat4n6-fs/src/plaintext_fs.rs`. Do not change a single line —
the tests in that file should pass as-is.

**Step 5: Run tests**

```bash
cargo test -p chat4n6-fs
```

Expected: 4 tests pass (list_finds_db, read_returns_bytes, unallocated_empty_for_plain_dir, path_traversal_rejected).

**Step 6: Commit**

```bash
git add crates/chat4n6-fs/ Cargo.toml
git -c commit.gpgsign=false commit -m "feat(chat4n6-fs): bootstrap crate, migrate PlaintextDirFs"
```

---

### Task 7: Add `DarFs` adapter to `chat4n6-fs`

**Files:**
- Create: `crates/chat4n6-fs/src/dar_fs.rs`
- Modify: `crates/chat4n6-fs/src/lib.rs`

**Step 1: Create `crates/chat4n6-fs/src/dar_fs.rs`**

Write the test first — it uses a real file if present, skips otherwise.

```rust
use anyhow::Result;
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use dar_archive::DarArchive;
use std::path::Path;

pub struct DarFs(DarArchive);

impl DarFs {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self(DarArchive::open(path)?))
    }

    pub fn open_slices(basename: &Path) -> Result<Self> {
        Ok(Self(DarArchive::open_slices(basename)?))
    }
}

impl ForensicFs for DarFs {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else {
            format!("{}/", path.trim_start_matches('/'))
        };
        let entries = self
            .0
            .entries()
            .iter()
            .filter(|e| {
                let p = e.path.to_string_lossy();
                p.starts_with(&prefix) && {
                    let remainder = &p[prefix.len()..];
                    !remainder.is_empty() && !remainder.contains('/')
                }
            })
            .map(|e| FsEntry {
                path: e.path.to_string_lossy().into_owned(),
                size: e.size,
                is_dir: e.is_dir,
            })
            .collect();
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let entry = self
            .0
            .entries()
            .iter()
            .find(|e| e.path.to_str() == Some(key))
            .ok_or_else(|| anyhow::anyhow!("file not found in DAR: {path}"))?;
        Ok(self.0.read(entry)?.into_owned())
    }

    fn exists(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        self.0.entries().iter().any(|e| e.path.to_str() == Some(key))
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAR_PATH: &str = "/path/to/userdata.1.dar"; // update for local testing

    #[test]
    fn test_darfs_with_real_file() {
        if !std::path::Path::new(DAR_PATH).exists() {
            eprintln!("Skipping DarFs test: no real .dar fixture at {DAR_PATH}");
            return;
        }
        let fs = DarFs::open(std::path::Path::new(DAR_PATH)).expect("DarFs::open");
        assert!(!fs.list("").unwrap().is_empty(), "root listing should be non-empty");
        assert!(
            fs.exists("data/data/com.whatsapp/databases/msgstore.db"),
            "msgstore.db should exist in archive"
        );
        let bytes = fs.read("data/data/com.whatsapp/databases/msgstore.db").unwrap();
        assert_eq!(&bytes[..7], b"SQLite ", "msgstore.db should start with SQLite header");
    }
}
```

**Step 2: Add to `lib.rs`**

```rust
pub mod dar_fs;
pub use dar_fs::DarFs;
```

**Step 3: Run tests**

```bash
cargo test -p chat4n6-fs
```

Expected: 5 tests pass (4 PlaintextDirFs + 1 DarFs that skips).

**Step 4: Commit**

```bash
git add crates/chat4n6-fs/
git -c commit.gpgsign=false commit -m "feat(chat4n6-fs): add DarFs ForensicFs adapter"
```

---

### Task 8: Add `IosBackupFs` adapter to `chat4n6-fs`

**Files:**
- Create: `crates/chat4n6-fs/src/ios_backup_fs.rs`
- Modify: `crates/chat4n6-fs/src/lib.rs`

**Step 1: Create `crates/chat4n6-fs/src/ios_backup_fs.rs`**

```rust
use anyhow::Result;
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use ios_backup::IosBackup;
use std::path::Path;

pub struct IosBackupFs(IosBackup);

impl IosBackupFs {
    pub fn open(backup_dir: &Path) -> Result<Self> {
        Ok(Self(IosBackup::open(backup_dir)?))
    }
}

impl ForensicFs for IosBackupFs {
    /// Virtual path: `<domain>/<relative_path>`
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else {
            format!("{}/", path.trim_start_matches('/'))
        };
        let entries = self
            .0
            .entries()
            .iter()
            .map(|e| format!("{}/{}", e.domain, e.relative_path))
            .filter(|vp| {
                vp.starts_with(&prefix) && {
                    let remainder = &vp[prefix.len()..];
                    !remainder.is_empty() && !remainder.contains('/')
                }
            })
            .map(|vp| FsEntry { path: vp, size: 0, is_dir: false })
            .collect();
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let (domain, relative_path) = key.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("invalid IosBackupFs path (expected domain/path): {path}")
        })?;
        let entry = self
            .0
            .get(domain, relative_path)
            .ok_or_else(|| anyhow::anyhow!("file not found in iOS backup: {path}"))?;
        self.0.read(entry)
    }

    fn exists(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        key.split_once('/')
            .map(|(domain, rel)| self.0.get(domain, rel).is_some())
            .unwrap_or(false)
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_backup(tmp: &TempDir) -> std::path::PathBuf {
        let dir = tmp.path().to_path_buf();
        let conn = Connection::open(dir.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (
                fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT,
                flags INTEGER, file BLOB
            );
            INSERT INTO Files VALUES (
                'aabbccdd1122334455667788990011223344556677',
                'AppDomain-net.whatsapp.WhatsApp',
                'Documents/ChatStorage.sqlite',
                1, NULL
            );",
        )
        .unwrap();
        let sub = dir.join("aa");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("aabbccdd1122334455667788990011223344556677"),
            b"sqlite3-magic",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_exists_by_virtual_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = IosBackupFs::open(&make_backup(&tmp)).unwrap();
        assert!(fs.exists(
            "AppDomain-net.whatsapp.WhatsApp/Documents/ChatStorage.sqlite"
        ));
        assert!(!fs.exists("AppDomain-net.whatsapp.WhatsApp/no-such-file"));
    }

    #[test]
    fn test_read_by_virtual_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = IosBackupFs::open(&make_backup(&tmp)).unwrap();
        let data = fs
            .read("AppDomain-net.whatsapp.WhatsApp/Documents/ChatStorage.sqlite")
            .unwrap();
        assert_eq!(data, b"sqlite3-magic");
    }
}
```

**Step 2: Add to `lib.rs`**

```rust
pub mod ios_backup_fs;
pub use ios_backup_fs::IosBackupFs;
```

**Step 3: Run tests**

```bash
cargo test -p chat4n6-fs
```

Expected: 7 tests pass (4 PlaintextDirFs + 1 DarFs skip + 2 IosBackupFs).

**Step 4: Commit**

```bash
git add crates/chat4n6-fs/
git -c commit.gpgsign=false commit -m "feat(chat4n6-fs): add IosBackupFs ForensicFs adapter"
```

---

### Task 9: CLI auto-detection and dissolve `chat4n6-core`

**Files:**
- Modify: `Cargo.toml` (workspace root — remove chat4n6-core from members)
- Modify: `cli/Cargo.toml` — replace chat4n6-core dep with chat4n6-fs
- Modify: `cli/src/commands/run.rs` — add `open_fs()`, remove DAR unsupported error
- Delete: `crates/chat4n6-core/` (remove from filesystem)

**Step 1: Update `cli/Cargo.toml`**

Remove:
```toml
chat4n6-core = { path = "../crates/chat4n6-core", version = "0.1" }
```

Add:
```toml
chat4n6-fs = { path = "../crates/chat4n6-fs", version = "0.1" }
```

**Step 2: Rewrite `cli/src/commands/run.rs`**

Replace the top of the file (imports + the file-detection block + `PlaintextDirFs::new()` call)
with the version below. The key changes:
- Add `use chat4n6_fs::{DarFs, IosBackupFs, PlaintextDirFs};`
- Remove `use chat4n6_core::PlaintextDirFs;`
- Replace the `if args.input.is_file() { ... bail! }` block + `PlaintextDirFs::new()`
  with a call to the new `open_fs()` helper.

```rust
use anyhow::{Context, Result};
use chat4n6_fs::{DarFs, IosBackupFs, PlaintextDirFs};
use chat4n6_plugin_api::ForensicPlugin;
use chat4n6_report::ReportGenerator;
use chat4n6_whatsapp::WhatsAppPlugin;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct RunArgs {
    /// Input: extracted Android filesystem directory, iOS backup directory, or .dar archive file
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output directory for report files
    #[arg(short, long)]
    pub output: PathBuf,
    /// Case name for the report
    #[arg(long, default_value = "Unnamed Case")]
    pub case_name: String,
    /// Timezone offset string (e.g. "+08:00" or "Asia/Manila")
    #[arg(long)]
    pub timezone: Option<String>,
    /// Skip unallocated space carving (faster)
    #[arg(long)]
    pub no_unalloc: bool,
}

pub fn run(args: RunArgs) -> Result<()> {
    let fs = open_fs(&args.input)?;
    let plugins: Vec<Box<dyn ForensicPlugin>> = vec![Box::new(WhatsAppPlugin)];

    let bar = ProgressBar::new(plugins.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner} [{bar:40}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> "),
    );

    let tz_offset = resolve_tz_arg(args.timezone.as_deref())?;
    let mut combined = chat4n6_plugin_api::ExtractionResult::default();

    for plugin in &plugins {
        bar.set_message(plugin.name().to_string());
        if plugin.detect(&*fs) {
            let result = plugin
                .extract(&*fs, tz_offset)
                .with_context(|| format!("plugin '{}' extraction failed", plugin.name()))?;
            merge_results(&mut combined, result);
        }
        bar.inc(1);
    }
    bar.finish_with_message("extraction complete");

    if combined.chats.is_empty() && combined.calls.is_empty() {
        eprintln!("Warning: no artifacts found in {:?}", args.input);
    }

    let generator = ReportGenerator::new().context("failed to load report templates")?;
    generator
        .render(&args.case_name, &combined, &args.output)
        .context("report generation failed")?;

    println!("Report written to: {}", args.output.display());
    println!("  index.html");
    println!("  carve-results.json");
    Ok(())
}

/// Open the correct filesystem abstraction for `input`.
///
/// Detection order:
/// 1. File with `.dar` extension → DarFs (slice number stripped from basename)
/// 2. Directory containing `Manifest.db` → IosBackupFs
/// 3. Directory → PlaintextDirFs
fn open_fs(input: &Path) -> Result<Box<dyn chat4n6_plugin_api::ForensicFs>> {
    if input.is_file() {
        let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "dar" {
            // Strip trailing slice number: "userdata.1" → "userdata"
            let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let base_name = stem
                .rsplit_once('.')
                .map(|(b, _)| b)
                .unwrap_or(stem);
            let basename = input
                .parent()
                .unwrap_or(Path::new("."))
                .join(base_name);
            return Ok(Box::new(
                DarFs::open_slices(&basename)
                    .with_context(|| format!("cannot open DAR archive: {}", input.display()))?,
            ));
        }
        anyhow::bail!(
            "{} is a file, not a directory. \
             --input must be a .dar archive, an iOS backup directory, \
             or an extracted Android filesystem tree.",
            input.display()
        );
    }
    if input.join("Manifest.db").exists() {
        return Ok(Box::new(
            IosBackupFs::open(input)
                .with_context(|| format!("cannot open iOS backup: {}", input.display()))?,
        ));
    }
    Ok(Box::new(
        PlaintextDirFs::new(input)
            .with_context(|| format!("cannot open input: {}", input.display()))?,
    ))
}

fn resolve_tz_arg(tz: Option<&str>) -> Result<Option<i32>> {
    match tz {
        None => Ok(None),
        Some(s) => chat4n6_whatsapp::timezone::resolve_timezone_offset(s)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("unrecognised timezone: '{s}'")),
    }
}

fn merge_results(
    dst: &mut chat4n6_plugin_api::ExtractionResult,
    src: chat4n6_plugin_api::ExtractionResult,
) {
    dst.chats.extend(src.chats);
    dst.contacts.extend(src.contacts);
    dst.calls.extend(src.calls);
    dst.wal_deltas.extend(src.wal_deltas);
    if dst.timezone_offset_seconds.is_none() {
        dst.timezone_offset_seconds = src.timezone_offset_seconds;
    }
}
```

**Step 3: Remove `chat4n6-core` from workspace root `Cargo.toml`**

Remove `"crates/chat4n6-core"` from the `[workspace] members` array.

**Step 4: Delete the `chat4n6-core` crate directory**

```bash
rm -rf crates/chat4n6-core
```

**Step 5: Run all workspace tests**

```bash
cargo test --workspace
```

Expected: all tests pass. No reference to `chat4n6-core` should remain.

**Step 6: Build release binary**

```bash
cargo build -p chat4n6 --release
```

Expected: compiles without warnings.

**Step 7: Smoke-test the CLI**

```bash
# Should print a "not a directory" error (not a DAR error):
./target/release/chat4n6 run --input /etc/hosts --output /tmp/out

# Should detect .dar and attempt to open:
./target/release/chat4n6 run --input /path/to/userdata.1.dar --output /tmp/out
```

**Step 8: Commit**

```bash
git add Cargo.toml cli/Cargo.toml cli/src/commands/run.rs
git -c commit.gpgsign=false commit -m "feat(cli): auto-detect dar/ios-backup/plaintext, dissolve chat4n6-core"
```

**Step 9: Yank `chat4n6-core` on crates.io (after publishing new crates)**

```bash
cargo yank --version 0.1.0 chat4n6-core
cargo yank --version 0.1.1 chat4n6-core
cargo yank --version 0.1.2 chat4n6-core
```

---

## Publishing checklist (after all tasks complete)

```bash
cargo publish -p dar-archive
cargo publish -p ios-backup
cargo publish -p chat4n6-fs
# Bump version to 0.1.3 in workspace Cargo.toml, then:
cargo publish -p chat4n6-plugin-api
cargo publish -p chat4n6-sqlite-forensics
cargo publish -p chat4n6-whatsapp
cargo publish -p chat4n6-report
cargo publish -p chat4n6
```
