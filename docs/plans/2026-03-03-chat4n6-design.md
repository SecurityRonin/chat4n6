# chat4n6 — Design Document

**Date:** 2026-03-03
**Status:** Approved
**MVP Scope:** Android / WhatsApp / DAR archives (v8 and v9)

---

## 1. Overview

`chat4n6` is a Rust forensic tool for extracting chat artifacts from mobile device
forensic images. It parses DAR archives produced by acquisition tools (e.g. Passware
Kit Mobile), performs deep SQLite forensic recovery across six layers, and generates
paginated HTML case reports suitable for court presentation.

**MVP targets:** Android, WhatsApp, DAR v8/v9.
**Future:** iOS, Signal, Telegram.

---

## 2. Architecture

Cargo workspace with a plugin architecture:

```
chat4n6/                          ← Cargo workspace root
├── crates/
│   ├── chat4n6-core/             ← DAR v8/v9 parser, ForensicFs abstraction,
│   │                               unallocated region exposure, streaming I/O
│   ├── chat4n6-sqlite-forensics/ ← 6-layer SQLite recovery engine
│   │                               (pure Rust, binary page level)
│   ├── chat4n6-plugin-api/       ← ForensicPlugin trait, canonical artifact types
│   ├── plugins/
│   │   └── chat4n6-whatsapp/     ← WhatsApp Android plugin
│   └── chat4n6-report/           ← Tera-based HTML report generator
└── cli/                          ← clap CLI, progress bars, pipeline orchestration
```

### Plugin Trait

Defined in `chat4n6-plugin-api`:

```rust
pub trait ForensicPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, fs: &dyn ForensicFs) -> bool;
    fn extract(&self, ctx: &ExtractionCtx) -> Result<ExtractionResult>;
}
```

Plugins register at startup. The pipeline calls `detect()` on each registered plugin,
runs matched ones, and merges results into a unified `CaseReport`.

---

## 3. DAR Parsing (`chat4n6-core`)

### Format Support
- DAR v8 and v9
- Version detected from archive header magic field
- v9 adds extended attributes and richer metadata; dispatched via version enum

### Parsing Strategy
```
Layout (per slice):
  [slice header 16B] [archive header] [file entries...] [catalog] [terminator]
                                                                      ↑ EOF-anchored

1. Read terminator backwards from EOF
2. Decode catalog offset (infinint variable-length encoding)
3. Walk catalog to build file index
4. Stream file content on demand (memory-mapped or BufReader)
```

### Unallocated Space
Passware Kit Mobile DAR images include unallocated regions. These are exposed as:
```rust
pub trait ForensicFs: Send + Sync {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>>;
    fn read(&self, path: &str) -> Result<Bytes>;
    fn unallocated_regions(&self) -> &[UnallocatedRegion];
}
```

Also implemented: `PlaintextDirFs` (for testing with extracted directories).

---

## 4. SQLite Forensics Engine (`chat4n6-sqlite-forensics`)

Operates entirely at the binary page level. Never uses the SQLite C library. Uses
`sqlite-parser-nom` for structured page parsing.

### Six Recovery Layers (in execution order)

**Layer 1 — Live Records**
Standard B-tree traversal of active pages. Reads cell pointer array, parses
table leaf pages (0x0D) and index leaf pages (0x0A, WITHOUT ROWID tables).

**Layer 2 — WAL Unapplied Frames**
Parse `-wal` file. Group frames by `salt1` value into `BTreeMap<u32, Vec<WalFrame>>`.
Extract records from frames not yet checkpointed into the main DB.
Tag: `[WAL-PENDING]`

**Layer 3 — WAL Historic Frames**
Compare WAL frames against corresponding main DB pages. Frames that were
checkpointed but represent superseded page versions contain deleted/modified records.
Emit `WalDelta { row_id, table, status: Added|Deleted|Modified, source }` per diff.
Tag: `[WAL-HISTORIC]`

**Layer 4 — Freelist Pages**
Walk freelist trunk→leaf chain. For each freelist leaf page:
- Parse freeblock linked list (2B next ptr + 2B size at block start)
- Traverse freeblock matches **last-to-first** (SQLite reallocates from block end)
- Handle stacked records: loop while `remaining_bytes > 5`
- Reconstruct missing first column from freeblock size arithmetic
- Attempt ROWID recovery by walking back from header start (reverse varint decode)
- Stitch overflow page chains for large deleted records
- Tag: `[FREELIST]`

Also parse rollback journals (`-journal`) when present. Recover frames even when
journal header is zeroed (use main DB page size for frame layout).

**Layer 5 — FTS Shadow Table Cross-Reference**
Read `message_fts_content`, `message_fts_segments`, `message_fts_segdir` tables
from `msgstore.db`. Cross-reference FTS `docid` against `message._id`.
Records present in FTS but absent from `message` table were deleted after indexing.
Tag: `[FTS-ONLY]`

**Layer 6 — Unallocated Space Carving (slowest)**
Scan `UnallocatedRegion` byte arrays:
- First pass: locate SQLite DB headers (magic: `53 51 4C 69 74 65 20 66 6F 72 6D 61
  74 20 33 00`) → attempt full DB reconstruction → process through layers 1-5
  Tag: `[CARVED-DB]`
- Second pass: per-page carving with 3-mode header matching:
  - NORMAL: full record header intact; attempt ROWID back-probe
  - COLUMNSONLY: header length byte missing; heuristic column type matching
  - FIRSTCOLUMNMISSING: first column's serial type overwritten by freeblock pointer
- Per-page `BitSet` for visited-byte tracking (prevents double-counting)
- Ptrmap page exploitation for auto-vacuum DBs
- Cell pointer array inconsistency detection → emit `[CORRUPTED-PAGE]` tag
- Page type disambiguation: type 0x00 + first 4 bytes == 0 → dropped table; else overflow
- WITHOUT ROWID table handling on index leaf pages (0x0A)
- Tag: `[CARVED-UNALLOC]`

### Signature Learning & Confidence Scoring
Before carving, scan all live records per table and build frequency map of serial type
header patterns. Most common pattern = "simplified signature" used for carving.
Per-column probability derived from appearance frequency. Carved records scored:
- `[HIGH-CONFIDENCE N%]` — all columns match high-probability serial types
- `[LOW-CONFIDENCE N%]` — one or more columns match low-probability serial types

### ALTER TABLE Detection
Detect varying column counts across live records. Records with fewer columns than
current schema are from older schema versions and annotated with schema generation.
Applied specifically to WhatsApp `msgstore.db` which has evolved across app versions.

### Per-Table Magic Patterns
Known binary patterns at known offsets within freeblocks for WhatsApp tables
(derived from live record analysis). Reduces false positives during carving.

### Hash-Based Deduplication
SHA-256 of recovered record content used to deduplicate records found across
multiple recovery layers.

---

## 5. WhatsApp Android Plugin (`chat4n6-whatsapp`)

### Database Targets

| Database | Contents |
|---|---|
| `msgstore.db` + `-wal` | Messages, media, reactions, edits, quotes, stickers, voice notes, locations, vcards, call log |
| `wa.db` + `-wal` | Contacts, JIDs, display names |
| `companion_devices.db` | Linked devices |
| FTS shadow tables (in `msgstore.db`) | Deleted message text recovery |
| Carved DBs from unallocated | Any of the above, tagged `[CARVED-DB]` |

### Schema Version Detection
Read `PRAGMA user_version` and `sqlite_master`. Apply correct column mapping:
- Legacy schema: monolithic `messages` table
- Modern schema (WhatsApp 2.22+): split `message` + `message_media` + `message_add_on`

### Artifact Extraction

| Source table | Artifacts |
|---|---|
| `message` | Text, system messages, deleted (type=15), all types by `message_type` |
| `message_media` | Images, video, audio, voice notes (audio/ogg MIME), stickers (`is_animated_sticker`), documents |
| `message_add_on` | Reactions (emoji + JID), edit history, disappearing message flags |
| `message_quoted` | Quoted messages — preserves content of subsequently deleted originals |
| `message_location` | Location shares |
| `message_vcard` | Contact cards |
| `call_log` | Direction (`from_me`), type (`video_call`), duration (seconds), group calls |
| `message_fts_content` | Deleted message text (Layer 5 FTS recovery) |

### Encryption
Auto-detect crypt14/crypt15 databases. Decryption key from:
1. `--key-file <path>` flag
2. Auto-located at `files/key` within the DAR filesystem

AES-GCM (crypt15) / AES-CBC (crypt14). Decrypted in-memory before page parsing.

### Timestamp Handling
All DB timestamps are Unix milliseconds (UTC).

Timezone resolution order:
1. Android `settings.db` → `time_zone` key (TZ database name, e.g. `"Asia/Manila"`)
2. `--timezone` flag override
3. Fallback: UTC-only with warning in report

Display format on every record:
```
2024-03-15 14:32:07 UTC  |  2024-03-15 22:32:07 UTC+8
```

### Evidence Tags
Every record carries a `source` field:
`Live | WalPending | WalHistoric | Freelist | FtsOnly | CarvedUnalloc | CarvedDb`

---

## 6. HTML Report (`chat4n6-report`)

### Structure
```
<output-dir>/
├── index.html                  ← Case dashboard: stats, timezone, acquisition info
├── media/                      ← Extracted media files
├── chats/
│   ├── chat_NNN_<name>/
│   │   ├── index.html          ← Chat summary
│   │   ├── page_001.html       ← Up to --page-size messages (default 500)
│   │   └── page_NNN.html
│   └── ...
├── calls/
│   └── index.html              ← Full call log, paginated
├── media_gallery/
│   └── page_NNN.html           ← Thumbnail grid, 100 per page
├── deleted/
│   ├── index.html              ← Deleted records summary across all sources
│   ├── freelist.html
│   ├── wal_delta.html          ← WalDelta table by table/status
│   ├── fts_recovered.html      ← FTS-only recovered messages
│   └── carved_unalloc.html     ← Carved records with confidence scores
├── carved_dbs/
│   └── db_NNN/                 ← Sub-report per carved DB
└── carve-results.json          ← Intermediate: re-run `chat4n6 report` without re-carving
```

### Rendering
- Pure HTML + CSS, no JavaScript required (court/lab environment safe)
- Tera templates in `chat4n6-report/templates/`
- Inline base64 thumbnails (images, stickers) in message view
- Audio/video linked to `media/` folder
- Navigation header/footer on every page with prev/next and breadcrumb

### Evidence Badges (colour-coded)
- `[LIVE]` green
- `[WAL-PENDING]` blue / `[WAL-HISTORIC]` grey
- `[FREELIST]` amber
- `[FTS-ONLY]` purple
- `[CARVED-UNALLOC]` red + confidence %
- `[CARVED-DB]` dark red
- `[CORRUPTED-PAGE]` orange (structural anomaly noted)

---

## 7. CLI

```
USAGE:
  chat4n6 <COMMAND>

COMMANDS:
  run       Full pipeline end-to-end
  extract   Parse DAR, locate and decrypt databases
  carve     Run 6-layer SQLite forensic recovery
  report    Generate HTML report from carve-results.json

SHARED OPTIONS:
  --input <path>          DAR archive or plaintext directory
  --output <dir>          Output directory [default: ./chat4n6-out]
  --timezone <tz>         Override timezone ("Asia/Manila", "+08:00")
  --key-file <path>       crypt14/crypt15 decryption key
  --plugin <name>         Run specific plugin only [default: all]
  --no-unalloc            Skip Layer 6 (fast mode)
  --confidence <0.0-1.0>  Minimum confidence for carved records [default: 0.5]
  --page-size <n>         Messages per HTML page [default: 500]
  --verbose / -v          Per-page progress output
```

---

## 8. Key Dependencies (Rust)

| Crate | Purpose |
|---|---|
| `sqlite-parser-nom` | Binary SQLite page parsing (no C deps) |
| `nom` | Binary format parsing (DAR, WAL, page structures) |
| `tera` | HTML report templating |
| `clap` | CLI argument parsing |
| `indicatif` | Progress bars |
| `aes-gcm` / `aes` / `cbc` | crypt14/crypt15 decryption |
| `sha2` | Record deduplication hashing |
| `chrono` / `chrono-tz` | Timestamp conversion with TZ database |
| `base64` | Media thumbnail embedding |
| `memmap2` | Memory-mapped DAR file access |
| `rayon` | Parallel page processing (Layer 6) |
| `serde` / `serde_json` | `carve-results.json` serialization |

---

## 9. MVP Scope & Explicitly Out of Scope

**In scope (MVP):**
- Android forensic images in DAR v8/v9 format
- WhatsApp extraction (all artifact types listed above)
- All 6 recovery layers
- HTML report with paginated multi-file structure
- crypt14/crypt15 decryption

**Out of scope (future):**
- iOS support
- Signal, Telegram, other chat apps
- GUI
- Network capture analysis
- Cloud backup decryption (Google Drive backups)
- Real-time / live device acquisition

---

## 10. Research References

- [Belkasoft: Android WhatsApp Forensics Part II](https://belkasoft.com/android-whatsapp-forensics-analysis)
- [Belkasoft: SQLite Forensic Analysis](https://belkasoft.com/sqlite-analysis)
- [FQLite — SQLite Forensic Toolkit](https://github.com/pawlaszczyk/fqlite)
- [DC3 sqlite-dissect](https://github.com/dod-cyber-crime-center/sqlite-dissect)
- [SQBrite](https://github.com/mattboyer/sqbrite)
- [bring2lite — DFRWS 2019](https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-bring2lite_a_structural_concept_and_tool_for_forensic_data_analysis_and_recovery_of_deleted_sqlite_records.pdf)
- [DAR format specification](https://darbinding.sourceforge.net/specs/darK06.html)
- [Forensic Focus: WhatsApp ChatSearchV3](https://www.forensicfocus.com/forums/general/whatsapp-chatsearchv3-sqlite-database/)
- Pawlaszczyk & Hummert (2021): Making the Invisible Visible — Techniques for Recovering Deleted SQLite Data Records
