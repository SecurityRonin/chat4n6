# DAR + iOS Backup Refactor Design

## Date
2026-03-05

## Goal
Add native DAR archive reading and iOS backup reading to chat4n6 by introducing two
standalone generic crates (`dar-archive`, `ios-backup`) and a new adapter crate
(`chat4n6-fs`) that replaces `chat4n6-core`. The CLI auto-detects input type from the
path supplied to `--input`.

---

## 1. Workspace Structure

### New crates
| Crate | Path | Role |
|---|---|---|
| `dar-archive` | `crates/dar-archive` | Pure-Rust DAR archive reader (no forensic deps) |
| `ios-backup` | `crates/ios-backup` | iOS/iTunes backup reader (no forensic deps) |
| `chat4n6-fs` | `crates/chat4n6-fs` | ForensicFs adapters: DarFs, IosBackupFs, PlaintextDirFs |

### Removed crates
| Crate | Action |
|---|---|
| `chat4n6-core` | Removed from workspace; yanked on crates.io after successor published |

### Unchanged crates
`chat4n6-plugin-api`, `chat4n6-sqlite-forensics`, `chat4n6-whatsapp`, `chat4n6-report`, `cli`

---

## 2. `dar-archive` Crate

### Purpose
Read DAR (Disk ARchive) v2/v3 files. Provides file listing and random-access content
reading. No knowledge of forensics, WhatsApp, or the `ForensicFs` trait.

### API
```rust
pub struct DarArchive { /* mmap'd slices */ }

impl DarArchive {
    /// Open a single-slice or first-slice archive (auto-discovers remaining slices).
    pub fn open(path: &Path) -> Result<Self>;
    /// Open a multi-slice archive given the basename (no extension, no slice number).
    /// E.g. basename = "userdata" opens userdata.1.dar, userdata.2.dar, …
    pub fn open_slices(basename: &Path) -> Result<Self>;
}

pub struct DarEntry {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub permissions: u32,
    /// Byte offset into the owning slice file where file data begins.
    pub slice_index: usize,
    pub data_offset: u64,
}

impl DarArchive {
    pub fn entries(&self) -> &[DarEntry];
    pub fn read(&self, entry: &DarEntry) -> Result<Cow<[u8]>>;
}
```

### Parsing strategy: catalog-first
DAR archives store a catalog (index) after the file data, terminated by five `z` bytes
(`0x7a 0x7a 0x7a 0x7a 0x7a`). The catalog contains every entry's path, size,
permissions and data offset. Parsing proceeds:

1. `mmap` the slice file (or files).
2. Scan backwards for the `zzzzz` terminator to locate the catalog.
3. Parse catalog entries using the DAR infinint encoding.
4. Build a `HashMap<PathBuf, DarEntry>` for O(1) lookup.
5. For `read()`, seek to `data_offset` in the appropriate slice and return the bytes.

### Infinint encoding
Already implemented in the existing `chat4n6-core/src/dar/mod.rs`:
- N zero bytes prefix indicates the number of additional value bytes that follow.
- Migrate `decode_infinint()` to this crate.

### Dependencies
- `memmap2` for zero-copy mmap reads
- `thiserror` for error types
- `anyhow` for `Result<T>` in tests

---

## 3. `ios-backup` Crate

### Purpose
Read iOS device backups created by iTunes/Finder/Apple Devices on macOS/Windows.
Provides file listing and content reading. No knowledge of forensics or `ForensicFs`.

### Backup format overview
An iOS backup directory contains:
- `Manifest.db` — SQLite3 database; table `Files` with columns:
  `fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB`
- SHA-1 hash-named files arranged in 256 two-hex-char subdirectories:
  `<backup_dir>/<fileID[0:2]>/<fileID>` (e.g. `ab/abcdef1234…`)

### API
```rust
pub struct IosBackup { /* path + in-memory index */ }

impl IosBackup {
    /// Open a backup directory. Reads Manifest.db once; builds index in memory.
    pub fn open(backup_dir: &Path) -> Result<Self>;
}

pub struct BackupEntry {
    pub domain: String,
    pub relative_path: String,
    pub file_id: String,   // SHA-1 hex string
    pub flags: u32,
}

impl IosBackup {
    pub fn entries(&self) -> &[BackupEntry];
    pub fn read(&self, entry: &BackupEntry) -> Result<Vec<u8>>;
    /// Convenience: find an entry by domain + relative path.
    pub fn get(&self, domain: &str, relative_path: &str) -> Option<&BackupEntry>;
}
```

### Dependencies
- `rusqlite` (bundled feature) for Manifest.db reading
- `thiserror`, `anyhow`

---

## 4. `chat4n6-fs` Crate

### Purpose
Adapts `dar-archive`, `ios-backup`, and the existing `PlaintextDirFs` into the
`ForensicFs` trait from `chat4n6-plugin-api`. This is the only crate that depends on
both generic data-access crates and the forensic plugin API.

### Structs

```rust
/// Wraps a DarArchive.
pub struct DarFs(DarArchive);

/// Wraps an IosBackup.
pub struct IosBackupFs(IosBackup);

/// Wraps a plain directory (moved from chat4n6-core).
pub struct PlaintextDirFs { root: PathBuf }
```

All three implement `ForensicFs` from `chat4n6-plugin-api`.

### `ForensicFs` implementation notes
- `DarFs::list()` — iterate `DarArchive::entries()`, return paths.
- `DarFs::read(path)` — look up entry by path, call `DarArchive::read()`.
- `IosBackupFs::list()` — iterate `IosBackup::entries()`, reconstruct virtual paths as
  `<domain>/<relative_path>`.
- `IosBackupFs::read(path)` — split path to recover domain + relative_path, call
  `IosBackup::read()`.
- `unallocated_regions()` — return empty `Vec` for `DarFs` and `IosBackupFs`;
  `PlaintextDirFs` implementation stays the same.

---

## 5. CLI Auto-Detection

`cli/src/commands/run.rs` replaces the current `PlaintextDirFs::new()` call with:

```rust
fn open_fs(input: &Path) -> Result<Box<dyn ForensicPlugin>> { ... }
```

Detection order:
1. **`input` is a file with `.dar` extension** → `DarFs::open_slices(basename)` (strip
   slice number suffix, e.g. `userdata.1.dar` → basename `userdata`).
2. **`input` is a directory containing `Manifest.db`** → `IosBackupFs::open(input)`.
3. **`input` is a directory** → `PlaintextDirFs::new(input)` (existing behavior).
4. Anything else → actionable error.

The existing DAR error message (added in v0.1.2) is replaced by actual support.

---

## 6. `chat4n6-core` Dissolution

1. Move `PlaintextDirFs` into `chat4n6-fs`.
2. Remove `chat4n6-core` from `[workspace.members]`.
3. Update `cli/Cargo.toml`, `chat4n6-whatsapp/Cargo.toml` — replace
   `chat4n6-core` dep with `chat4n6-fs`.
4. After publishing new crates, run `cargo yank --version 0.1.2 chat4n6-core` (and
   earlier versions).

---

## 7. TDD Approach

### `dar-archive`
- Keep existing `decode_infinint` unit tests (migrate from `chat4n6-core`).
- Add catalog-parsing unit tests using a synthetic in-memory byte buffer.
- Add integration test using a real `userdata.1.dar` file (skipped in CI if absent;
  use `#[cfg(feature = "integration")]` or file-existence guard).

### `ios-backup`
- Unit tests use a temporary `Manifest.db` created with `rusqlite` in the test.
- Integration test uses a real backup directory (skipped if absent).

### `chat4n6-fs`
- `DarFs` and `IosBackupFs` adapter tests assert `ForensicFs::list()` and
  `ForensicFs::read()` behave correctly against the synthetic archives from the
  sub-crate tests.
- `PlaintextDirFs` tests are migrated from `chat4n6-core` unchanged.

---

## 8. Publishing Plan

After implementation is complete and all tests pass:

1. Publish `dar-archive` (new crate, no dependents).
2. Publish `ios-backup` (new crate, no dependents).
3. Publish `chat4n6-fs` (depends on 1 + 2).
4. Bump all dependent crates (whatsapp, report, cli) to v0.1.3 and publish.
5. Yank `chat4n6-core` all versions.
