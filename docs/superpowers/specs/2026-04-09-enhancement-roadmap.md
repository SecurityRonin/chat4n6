# Enhancement Roadmap — Findings & Competitive Analysis

**Date:** 2026-04-09
**Status:** Pre-design — for review before brainstorming individual sub-projects

---

## 1. Scope Decomposition

The 11 requested features span 6 independent sub-projects. Each produces working, testable software and gets its own spec → plan → implementation cycle.

| Sub-project | Features | Crates Affected | Dependencies |
|-------------|----------|-----------------|--------------|
| **A: Forensic Engine** | Timestamp auto-detect (#4), BLOB signatures (#5), Parallel recovery (#8) | `chat4n6-sqlite-forensics` | None — foundation layer |
| **B: iOS + WhatsApp** | iOS schema (#2), Cloud backup (#11) | `chat4n6-whatsapp`, `ios-backup` | None |
| **C: Report Enhancements** | Timeline (#3), Media extraction (#9), Differential reporting (#10) | `chat4n6-report`, `cli` | A (timestamps), B (iOS data feeds into reports) |
| **D: Search** | Natural language search (#12) | New module in `chat4n6-report` or standalone crate | C (needs extracted data) |
| **E: Interop** | CASE/UCO output (#6) | New crate `chat4n6-case` | C (needs report data model) |
| **F: Interactive Viewer** | Forensic hex viewer (#7) | New crate, HTML/JS/WASM | A (page map, WAL frames) |

### Recommended Build Order

```
A (Forensic Engine) ──┐
                      ├──→ C (Report Enhancements) ──→ D (Search)
B (iOS + WhatsApp) ───┘                            ──→ E (Interop)
                                                   ──→ F (Viewer)
```

A and B can be built in parallel (no shared state). C depends on both. D/E/F are independent of each other but depend on C.

---

## 2. Competitive Analysis: whatsapp-forensic-exporter

**Repo:** [fdelorenzi/whatsapp-forensic-exporter](https://github.com/fdelorenzi/whatsapp-forensic-exporter)
**Language:** Python | **License:** MIT | **Stars:** 23 | **Last updated:** 2026-04-07

### What It Does

CLI tool for exporting and filtering WhatsApp messages from iOS `ChatStorage.db` and WhatsApp Web (ZAPiXWEB JSON takeouts). Produces CSV, PDF (landscape A4), and ASCII table output. **No deleted data recovery** — reads only live records via standard SQLite queries.

### Features Worth Stealing

| Feature | Their Implementation | Our Opportunity |
|---------|---------------------|-----------------|
| **iOS schema handling** | Full SQL query against `ZWAMESSAGE`, `ZWAMEDIAITEM`, `ZWAPROFILEPUSHNAME`, `ZWACHATSESSION` tables | Critical for Sub-project B — exact schema reference |
| **Phone number obfuscation** | `--obfuscate-number` / `--obfuscate-me` — masks middle digits (`15**...11`) | Useful for law firm reports — add as report option |
| **Multi-language reports** | `--language en/es/fr/pt/de/it` — translates column headers, labels, footnotes | Nice-to-have for Sub-project C |
| **Keyword range filtering** | `--start-keyword` / `--end-keyword` — bookend search within conversations | Useful for Sub-project D (search) |
| **Media type mapping** | `ZMESSAGETYPE` integer → media type string with MIME fallback | Needed for iOS media extraction |
| **Filter summary footer** | PDF footer showing exact CLI args used to generate report | Good for forensic reproducibility — add to our HTML reports |
| **Forwarded message detection** | Labels forwarded messages in output | Add to WhatsApp plugin metadata |
| **PDF with inline images** | Stickers and images embedded inline in PDF table cells | Consider PDF output format alongside HTML |

### Features We Already Beat Them On

| Capability | Theirs | Ours |
|------------|--------|------|
| Deleted data recovery | None | 8 recovery layers |
| Evidence provenance | None | 13 EvidenceSource tags |
| Confidence scoring | None | Schema-aware % scoring |
| WAL analysis | None | Full WAL replay + delta analysis |
| Android support | Planned | Fully implemented |
| Binary format parsing | Uses `sqlite3` library | Pure Rust, no C dependency |
| Verification commands | None | SHA-256 hashes + `sqlite3`/`xxd` commands |

### Key Technical Details Extracted

#### iOS WhatsApp Database Schema (`ChatStorage.db`)

```sql
-- Core query structure from ios_sqlite_handler.py
SELECT
  m.Z_PK,
  datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
  COALESCE(pn_from.ZPUSHNAME, m.ZFROMJID) AS sender_nickname,
  COALESCE(pn_to.ZPUSHNAME, m.ZTOJID) AS receiver_nickname,
  -- Direction: ZFROMJID IS NULL means outgoing
  CASE WHEN m.ZFROMJID IS NULL THEN 'OUT' ELSE 'IN' END AS message_direction,
  mi.ZMEDIALOCALPATH AS media_local_path,
  m.ZMESSAGETYPE AS message_type_id,
  mi.ZVCARDSTRING AS media_mime_type
FROM ZWAMESSAGE m
LEFT JOIN ZWAPROFILEPUSHNAME pn_from ON ...
LEFT JOIN ZWAPROFILEPUSHNAME pn_to ON ...
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
LEFT JOIN ZWACHATSESSION cs ON m.ZCHATSESSION = cs.Z_PK
```

#### Key Schema Differences: iOS vs Android

| Aspect | Android (`msgstore.db`) | iOS (`ChatStorage.db`) |
|--------|------------------------|------------------------|
| Message table | `messages` | `ZWAMESSAGE` |
| Primary key | `_id` | `Z_PK` |
| Timestamp | Unix milliseconds (`timestamp` column) | Mac Cocoa seconds (`ZMESSAGEDATE` + 978307200) |
| Sender | `key_remote_jid` | `ZFROMJID` / `ZTOJID` |
| Direction | `key_from_me` (0/1) | `ZFROMJID IS NULL` = outgoing |
| Message text | `data` column | `ZTEXT` |
| Media info | `message_media` table | `ZWAMEDIAITEM` table |
| Media path | `media_wa_type` / `media_name` | `ZMEDIALOCALPATH` |
| Media type | `media_wa_type` integer | `ZMESSAGETYPE` integer |
| Contacts | `wa.db` → `wa_contacts` | `ZWAPROFILEPUSHNAME` |
| Chat sessions | `chat` table | `ZWACHATSESSION` |
| JID format | `@s.whatsapp.net` / `@g.us` | Same |
| WAL file | `msgstore.db-wal` | `ChatStorage.db-wal` (if present in backup) |
| FTS index | `message_ftsv2_*` tables | Different FTS structure (needs research) |

#### ZMESSAGETYPE → Media Type Mapping

```
1 → image
2 → video
3 → ptt (voice note)
8 → document
```

Fallback: parse `ZVCARDSTRING` MIME type from `ZWAMEDIAITEM`:
```
image/webp → sticker
image/*    → image
video/*    → video
audio/*    → ptt
application/* → document
```

#### Mac Cocoa Timestamp

```
Unix epoch:      1970-01-01 00:00:00 UTC
Mac Cocoa epoch: 2001-01-01 00:00:00 UTC
Offset:          978307200 seconds

Conversion: unix_timestamp = cocoa_timestamp + 978307200
```

This is one of the 7 timestamp formats for Sub-project A's auto-detection.

---

## 3. Sub-project Detail — Features to Implement

### Sub-project A: Forensic Engine Enhancements

#### A.1 — Timestamp Auto-Detection

**Seven epoch formats:**

| Format | Epoch | Unit | Range (1990–2040) | Used By |
|--------|-------|------|-------------------|---------|
| Unix seconds | 1970-01-01 | seconds | 631,152,000 – 2,208,988,800 | Most Linux/Android apps |
| Unix milliseconds | 1970-01-01 | milliseconds | 631,152,000,000 – 2,208,988,800,000 | WhatsApp Android, Java apps |
| Unix microseconds | 1970-01-01 | microseconds | 631,152,000,000,000 – 2,208,988,800,000,000 | High-precision logs |
| Mac Cocoa | 2001-01-01 | seconds | -347,155,200 – 1,230,681,600 | WhatsApp iOS, macOS apps |
| Chrome/WebKit | 1601-01-01 | microseconds | 12,274,387,200,000,000 – 13,852,224,000,000,000 | Chrome, Chromium-based apps |
| Windows FILETIME | 1601-01-01 | 100-nanoseconds | 122,743,872,000,000,000 – 138,522,240,000,000,000 | Windows registry, NTFS |
| GPS | 1980-01-06 | seconds | 315,532,800 – 1,893,369,600 (adjusted) | GPS devices, location data |

**Implementation approach:** Given an integer value, test which formats produce a date in a plausible range (1990–2040). If exactly one format matches → use it. If multiple match → rank by specificity (narrower range wins). Return `Vec<TimestampInterpretation>` so the caller can choose.

#### A.2 — BLOB Signature Detection

**29+ magic byte signatures:**

| Category | Signatures |
|----------|-----------|
| Images | JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`47 49 46 38`), BMP (`42 4D`), WebP (`52 49 46 46...57 45 42 50`), HEIF/HEIC (`66 74 79 70`), TIFF (`49 49 2A 00` / `4D 4D 00 2A`) |
| Video/Audio | MP4/M4A (`66 74 79 70` subtypes), AVI (`52 49 46 46...41 56 49`), OGG (`4F 67 67 53`), FLAC (`66 4C 61 43`), MP3 (`FF FB` / `49 44 33`) |
| Documents | PDF (`25 50 44 46`), ZIP/DOCX/XLSX (`50 4B 03 04`), SQLite (`53 51 4C 69 74 65`), XML (`3C 3F 78 6D`) |
| Apple | bplist (`62 70 6C 69 73 74`), DMG (`78 01 73`) |
| Android | DEX (`64 65 78 0A`), APK (ZIP with specific entries) |
| Crypto | Protobuf (varint-prefixed), ASN.1/DER (`30 82`) |
| Archives | GZIP (`1F 8B`), BZIP2 (`42 5A 68`), XZ (`FD 37 7A 58 5A`), 7z (`37 7A BC AF`), RAR (`52 61 72 21`) |

**Implementation approach:** `identify_blob(data: &[u8]) -> Option<BlobSignature>` — check magic bytes, return struct with `format_name`, `mime_type`, `confidence`. Integrate into carver.rs to annotate BLOB values in carved records.

#### A.3 — Parallel Recovery

**Current:** Layers run sequentially in `recover_all()`.
**Target:** Layers 1-5 share read-only `RecoveryContext` and can run concurrently via `rayon`. Layer 8 (unallocated carving) is embarrassingly parallel (each region independent).

**Implementation approach:** Add `rayon` dependency. Wrap layer dispatch in `rayon::scope`. Collect results into `Mutex<Vec<RecoveredRecord>>` or use `par_iter` for unallocated regions. Deduplication runs after all layers complete (already the case).

---

### Sub-project B: iOS WhatsApp Support

#### B.1 — iOS Schema Support

**Key tasks:**
1. Add `ChatStorage.db` detection in `IosBackupFs` (file_id lookup from `Manifest.db`)
2. New iOS extraction module in `chat4n6-whatsapp` handling `ZWAMESSAGE` schema
3. Mac Cocoa timestamp conversion (+ 978307200)
4. `ZMESSAGETYPE` → `MessageContent` mapping
5. `ZWAMEDIAITEM` → `MediaRef` mapping
6. `ZWAPROFILEPUSHNAME` → `Contact` mapping
7. `ZWACHATSESSION` → `Chat` mapping
8. Direction detection (`ZFROMJID IS NULL` = outgoing)
9. Group chat detection (`@g.us` JID suffix)

**iOS-specific paths:**
```
# In iOS backup (via Manifest.db file_id lookup):
AppDomainGroup-group.net.whatsapp.WhatsApp.shared/
  ChatStorage.sqlite           # Main message database
  ChatStorage.sqlite-wal       # WAL file (if present)
  ContactsV2.sqlite            # Contacts database
```

**Note:** iOS uses Core Data (`Z_PK`, `Z_ENT`, `Z_OPT` columns), which means the integer primary keys follow Core Data conventions, not SQLite ROWID conventions. Our forensics engine's ROWID gap detection will need awareness of this.

#### B.2 — Cloud Backup Analysis

**WhatsApp Google Drive `.crypt15` format:**
- AES-256-GCM encrypted
- Key derived from 64-byte key file + backup token
- Multi-DB bundles (msgstore, axolotl, stickers, etc.)
- Backup metadata in protobuf format

**Implementation:** Extend existing crypt14/15 decryption in `chat4n6-whatsapp` to handle multi-DB bundles and extract backup metadata (account info, backup timestamp, size).

---

### Sub-project C: Report Enhancements

#### C.1 — Timeline Generation

**Unified chronological view** interleaving all artifact types:

```
2026-03-15 09:14:23 UTC  [LIVE]         Alice → Bob: "Meeting at 3pm"
2026-03-15 09:15:01 UTC  [LIVE]         Bob → Alice: "Confirmed"
2026-03-15 09:30:00 UTC  [LIVE]         Alice ↔ Bob: Voice call (2m14s, Connected)
2026-03-15 10:22:45 UTC  [FREELIST]     Alice → Bob: "Delete the files before audit"
2026-03-15 10:23:12 UTC  [FTS-ONLY]     Alice → Bob: "shred everything"
2026-03-15 11:00:00 UTC  [WAL-DELETED]  Alice → Bob: [Message deleted]
```

**Implementation:** New `timeline.html` template. Merge `messages` + `calls` sorted by timestamp. Color-code by evidence source. Filter controls: date range, source type, participant.

#### C.2 — Media Extraction

Extract actual media files from the forensic image into the report directory.

**Tasks:**
1. During extraction, copy referenced media files via `ForensicFs::read()`
2. Store in `report/media/` subdirectory with original filenames
3. Generate thumbnails for images (via `image` crate, pure Rust)
4. Update report templates to embed thumbnails inline
5. Add `--extract-media` CLI flag (default: off, to keep reports lightweight)

#### C.3 — Differential Reporting

**Given two acquisitions**, produce a diff showing evidence spoliation:

```
report-diff/
├── index.html           ← Summary: what changed between acquisitions
├── new_deletions.html   ← Messages present in acq1 but absent in acq2
├── new_messages.html    ← Messages in acq2 not in acq1
├── timestamp_changes.html ← Same message_id, different timestamps
└── diff.json            ← Machine-readable diff
```

**Implementation:** New `chat4n6 diff --before ./acq1 --after ./acq2 --output ./diff-report` subcommand. Match records by `(chat_jid, message_id)` or `(table, row_id)`. Classify as Added/Removed/Modified.

---

### Sub-project D: Search

#### Full-Text Search Over Recovered Messages

**Approach:** Not "natural language" / semantic search (that requires embeddings). Instead: **full-text keyword search with context**, which is what law firms actually need for document review.

**Tasks:**
1. Add `--search "keyword"` flag to CLI
2. Search across all recovered messages (all evidence sources)
3. Output: matching messages with surrounding context (N messages before/after)
4. Highlight matches in HTML report
5. Support regex patterns and boolean operators (AND/OR/NOT)
6. Optional: export search results as filtered report

**Implementation:** Build in-memory index from `ExtractionResult.chats[].messages[]`. Use `regex` crate for pattern matching. No external search engine needed for the typical case volume (thousands to low millions of messages).

---

### Sub-project E: CASE/UCO Interop

#### CASE/UCO JSON-LD Output

**[Cyber-investigation Analysis Standard Expression](https://caseontology.org/)** — W3C-style ontology for digital forensic tool interoperability.

**Key CASE object types to emit:**
- `case-investigation:InvestigativeAction` — the chat4n6 run itself
- `observable:ObservableObject` (subtype: `Message`) — each recovered message
- `observable:ObservableObject` (subtype: `PhoneCall`) — each call record
- `observable:ObservableObject` (subtype: `Contact`) — each contact
- `observable:Relationship` — sender/receiver relationships
- `observable:ObservableObject` (subtype: `File`) — the source database files
- `core:Provenance` — evidence source tags mapped to CASE provenance vocabulary

**Implementation:** New crate `chat4n6-case`. Takes `ExtractionResult` → produces JSON-LD conforming to CASE 1.3.0 schema. Add `--case-output ./case.jsonld` CLI flag.

---

### Sub-project F: Interactive Forensic Viewer

#### Web-Based Hex Viewer and Evidence Explorer

**Components:**
1. **Hex byte viewer** — shows raw database bytes with record overlay highlighting
2. **B-tree structure browser** — interactive tree showing page hierarchy
3. **WAL frame timeline** — visual timeline of WAL frames (committed/uncommitted/superseded)
4. **Page map visualization** — color-coded page ownership grid
5. **Record inspector** — click a record → see raw hex, decoded values, evidence source

**Implementation:** Likely a separate web application (Rust backend via `axum` + HTML/JS frontend). Could also be a static HTML report with embedded JS (like the current report but interactive). Consider WASM for client-side hex parsing.

**Note:** This is the most complex sub-project and may warrant its own decomposition.

---

## 4. Features to Steal from whatsapp-forensic-exporter

### Immediate (add to existing sub-projects)

| Feature | Steal Into | Priority | Effort |
|---------|-----------|----------|--------|
| iOS `ChatStorage.db` schema + SQL queries | Sub-project B | Critical | Medium |
| Mac Cocoa timestamp offset (978307200) | Sub-project A | Critical | Trivial |
| `ZMESSAGETYPE` → media type mapping | Sub-project B | High | Small |
| Phone number obfuscation (`--obfuscate-number`) | Sub-project C | Medium | Small |
| Filter summary footer in reports | Sub-project C | Medium | Small |
| Forwarded message detection | Sub-project B | Low | Small |
| Multi-language report support | Sub-project C | Low | Medium |

### Not Worth Stealing (we already do better)

| Feature | Why Skip |
|---------|----------|
| CSV output format | Our HTML + JSON is more forensically useful |
| ASCII table output | Niche, low ROI |
| ZAPiXWEB JSON support | Niche format, low case volume |
| `sqlite3` library dependency | We parse raw bytes — strictly better for forensics |
| PDF output | Consider later, but HTML-to-PDF via browser print is sufficient |

---

## 5. Recommended Execution Sequence

### Phase 1 (parallel — no dependencies)

**Sub-project A:** Timestamp auto-detect + BLOB signatures + parallel recovery
**Sub-project B:** iOS `ChatStorage.db` schema + cloud backup

### Phase 2 (depends on A + B)

**Sub-project C:** Timeline + media extraction + differential reporting + obfuscation

### Phase 3 (independent, in priority order)

**Sub-project D:** Full-text search
**Sub-project E:** CASE/UCO output
**Sub-project F:** Interactive viewer (longest lead time, consider separate decomposition)

---

## 6. Open Questions for Review

1. **PDF output format** — Should we add PDF alongside HTML, or is browser Print-to-PDF sufficient? (whatsapp-forensic-exporter's PDF embedding is nice for law firms who want a single file)
2. **Phone number obfuscation** — Is this needed for IR/DF firms, or only law firms? Should it be opt-in or opt-out?
3. **Multi-language** — Is this worth the effort for v1? Our primary market is English-speaking firms.
4. **Interactive viewer scope** — Full web app (axum server) vs. enhanced static HTML with JS? The web app is more powerful but harder to distribute.
5. **CASE/UCO version** — Target CASE 1.3.0 (current stable) or track the draft 2.0 spec?
6. **Search scale** — For cases with millions of messages, do we need a proper index (tantivy/meilisearch), or is in-memory regex sufficient?
