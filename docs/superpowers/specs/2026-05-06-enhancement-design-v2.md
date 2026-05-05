# Enhancement Design v2 — Competitive Closure & Forensic Differentiation

**Date:** 2026-05-06
**Status:** Design document — feeds individual brainstorm/spec/plan cycles
**Supersedes parts of:** `2026-04-09-enhancement-roadmap.md` (sub-projects B, C, F deepened; A retained; new sub-projects G, H, I added)
**Audience:** Senior forensic software architect / implementation lead

This document is a precise, actionable design for the next ~6 months of `chat4n6` development. It is grounded in the actual repo state as of HEAD (`384d78f`), the published code of two competitors (Whapa, whatsapp-forensic-exporter / "wfe"), and the user-stated goal of forensic differentiation rather than feature parity.

Reading order: (1) Gap matrix — locates us competitively. (2) Enhancement specs — concrete implementation. (3) Prioritization — defends the order. (4) Cross-cutting architecture observations.

---

## 1. Gap Analysis Matrix

Legend: ● = full / strong, ◐ = partial / scaffolded, ○ = absent. Bold rows = where chat4n6 already wins; italic rows = where we are still behind.

| Capability | Whapa | wfe | chat4n6 today | chat4n6 target |
|---|---|---|---|---|
| **Android msgstore.db parsing** | ● | ○ | ● | ● |
| *iOS ChatStorage.db parsing* | ○ | ● | ◐ scaffold (extractor + 459 test lines, no orchestration / no contacts JOIN / no media JOIN / no calls / not in CLI registry) | ● production |
| iOS ContactsV2.sqlite | ○ | ◐ via ZWAPROFILEPUSHNAME only | ○ | ● |
| Crypt12/14/15 decrypt (Android) | ● | ○ | ● | ● |
| Cloud backup (.crypt15 GDrive bundles) | ○ | ○ | ◐ single-DB only | ● multi-DB bundle |
| **WAL replay + delta** | ○ | ○ | ● | ● |
| **Freelist recovery** | ○ | ○ | ● | ● |
| **Rollback journal recovery** | ○ | ○ | ● | ● |
| **FTS5 shadow recovery** | ○ | ○ | ● | ● |
| **Carved unallocated** | ○ | ○ | ● | ● |
| **Ghost message recovery** | ○ | ○ | ● | ● |
| **Provenance per record (`EvidenceSource`)** | ○ | ○ | ● 13 variants | ● |
| **Anti-forensic warnings** | ○ | ◐ ZSORT only | ● 6 variants | ● 14 variants (see §2.6) |
| WAL snapshot timeline (per-frame state) | ○ | ○ | ◐ data captured (`WalFrame(u32)`), not exposed | ● `snapshots.html` |
| Group statistics (member frequency) | ● | ○ | ○ | ● in `stats.html` |
| Hourly activity heatmap | ● | ○ | ○ | ● |
| Word/emoji frequency | ● | ○ | ○ | ● |
| Deletion-rate-per-chat metric | ○ | ○ | ◐ used in warning, not surfaced | ● in `stats.html` |
| Response-time distribution | ○ | ○ | ○ | ● |
| Cross-platform contact intersection | ○ | ○ | ○ | ● |
| GPS location extraction | ● from msgs | ○ | ◐ `MessageContent::Location` exists, not surfaced on map | ● leaflet `locations.html` |
| Orphaned media detection | ● | ○ | ● `orphaned_media.rs` | ● |
| Media inventory (audio/video/image counts) | ● | ○ | ◐ gallery.html exists, no aggregate metrics | ● |
| **Media file export to report** | ● | ◐ embedded in PDF | ○ | ● `--export-media` |
| Hash chain on exported media | ○ | ○ | ◐ `MediaRef.file_hash` field; not enforced via export | ● dual hash (plain + encrypted) |
| Forwarded-message detection | ○ | ● label only | ● `forward_score` + `is_forwarded` | ● |
| Forward-chain dedup via `encrypted_hash` | ○ | ○ | ● | ● |
| View-once capture | ○ | ○ | ● `MessageContent::ViewOnce` | ● |
| Edit history | ○ | ○ | ● `edit_history` | ● |
| Per-device receipts | ○ | ○ | ● `receipts` | ● |
| Cross-chat timeline | ○ | ○ | ● `timeline.html` | ● |
| Phone-number obfuscation | ○ | ● `--obfuscate-*` | ◐ flag wired, render-side incomplete | ● |
| Filter / argv footer in report | ○ | ● | ○ | ● in base.html |
| Multi-language report headers | ○ | ● 6 langs | ○ | ◐ defer (see §3) |
| Signal extraction | ○ | ○ | ◐ 439 lines extractor, 297 test lines, no sealed-sender / disappearing-msg awareness | ● |
| Telegram extraction | ○ | ○ | ◐ 369 lines, no channel provenance / no forward-from | ● |
| **CASE/UCO JSON-LD** | ○ | ○ | ● `chat4n6-case` | ● + iOS / Signal / Telegram coverage |
| **UFDR output** | ○ | ○ | ● | ● |
| **Chain-of-custody manifest** | ○ | ○ | ● `manifest.json` SHA-256 | ● + signed PDF chain |
| **DAR archive read** | ○ | ○ | ● `dar-archive` v8/v9 | ● |
| iTunes/Finder backup read | ○ | ◐ assumes flat dir | ● `IosBackupFs` | ● |
| Differential acquisition reporting | ○ | ○ | ○ | ● `chat4n6 diff` (in v1 roadmap) |
| Natural-keyword search | ○ | ● keyword range | ○ | ● `--search` |
| Confidence scoring on recovered records | ○ | ○ | ● schema-aware % | ● |

**Where we already win decisively:** SQLite forensic recovery layers, provenance, anti-forensics warning vocabulary, multi-format I/O (DAR + iOS backup + plaintext), interop outputs (CASE / UFDR / signed PDF), edit / receipt / view-once metadata.

**Where we are behind or scaffold-only:** iOS WhatsApp orchestration (Sub-project B), media export (Sub-project C2), Signal/Telegram completeness (G/H), forensic statistics (Sub-project I), report-side polish (obfuscation, argv footer).

---

## 2. Enhancement Specifications

Each spec has the structure the task asked for: What, Why, Crates, Data model, Implementation, User stories.

User-story format follows the existing convention in `docs/user-stories/**/*.json`:

```json
[ { "description": "...", "steps": [ "...", "..." ], "passes": false } ]
```

`passes: false` is the RED-state assertion that the story is not yet implemented. Implementations flip it to `true` after the GREEN commit lands. This matches the global TDD directive in `~/.claude/CLAUDE.md`.

### 2.1 — iOS WhatsApp: scaffold → production

**What.** Promote `crates/plugins/chat4n6-ios-whatsapp` from a parser-on-bytes prototype to a fully orchestrated `ForensicPlugin` registered in the CLI, producing parity with the Android plugin on every dimension that iOS ChatStorage.db actually exposes.

**Why.** Today wfe is the only credible iOS WA tool, and it does not recover deleted records. By shipping iOS *with* our 9-layer recovery stack, we own the iOS WhatsApp forensic niche outright. wfe-equivalent live-extraction is a prerequisite — if our iOS output is poorer than wfe on live messages, our recovery story is moot.

**Crates affected.**

- `crates/plugins/chat4n6-ios-whatsapp` — completion
- `crates/chat4n6-fs/src/ios_backup.rs` — verify ChatStorage and ContactsV2 file_id resolution
- `crates/chat4n6-plugin-api/src/types.rs` — three new `ForensicWarning` variants (see §2.6)
- `cli/src/commands/run.rs` — register `IosWhatsAppPlugin` alongside `WhatsAppPlugin`, `SignalPlugin`, `TelegramPlugin`

**Data model changes.** None to existing public types. Add private types within the crate:

```rust
struct IosColumnMap {
    pk: usize, msg_date: usize, text: usize, type_: usize,
    media_item: usize, from_jid: usize, to_jid: usize, is_from_me: usize,
    chat_session: usize, sort: usize, starred: usize, is_forwarded: usize,
    deleted: usize,
}

struct IosContext<'a> {
    media_map: HashMap<i64, MediaInfo>,
    pushname_map: HashMap<String, String>,
    chat_map: HashMap<i64, Chat>,
    col: IosColumnMap,
    tz_offset_secs: i32,
    fs: &'a dyn ForensicFs,
}
```

**Key implementation details.**

1. **Dynamic column resolution.** Already done in scaffold via `parse_column_positions`; promote to `IosColumnMap::from_pragma(table_info_records)`. Refuse to extract a row if a required column is missing — emit `SchemaVersionMismatch`.
2. **Cocoa epoch.** `apple_epoch_to_utc_ms(zmsg_date) = (zmsg_date + 978_307_200.0) * 1000.0`. Already in `schema.rs`. Add a `#[test]` covering the boundary (Cocoa epoch == Unix `978_307_200_000` ms).
3. **Five mandatory JOINs** (mirroring wfe's SQL but at record-recovery level, not via `sqlite3`):

   ```text
   ZWAMESSAGE.ZCHATSESSION       → ZWACHATSESSION.Z_PK
   ZWAMESSAGE.ZMEDIAITEM         → ZWAMEDIAITEM.Z_PK
   ZWAMESSAGE.ZFROMJID/ZTOJID    → ZWAPROFILEPUSHNAME.ZJID  (push-name resolution)
   ZWAMESSAGE.ZGROUPMEMBER       → ZWAGROUPMEMBER.Z_PK     (group sender resolution)
   ZWACALLEVENT.ZCHATSESSION     → ZWACHATSESSION.Z_PK     (calls)
   ```

   In our model, "JOIN" is `HashMap<i64, T>::get`, populated by walking each table's recovered records once. Build maps **before** building messages so they cover deleted-but-recovered referent rows. This is a forensic improvement over wfe's `sqlite3` JOIN — we resolve referents that no longer exist in the live table.
4. **Direction.** wfe uses `ZFROMJID IS NULL`. We have `ZISFROMME` available too — prefer that, fall back to `ZFROMJID IS NULL` when missing. Document in code: "ZISFROMME is reliable on iOS WA ≥ 22.4; pre-22.4 only ZFROMJID IS NULL is set."
5. **Calls.** `ZWACALLEVENT` table — currently unimplemented in scaffold. Fields: `ZDATE` (Cocoa), `ZDURATION`, `ZINCOMING` (0/1), `ZOUTGOING` (0/1), `ZMISSED`, `ZVIDEO`, `ZGROUPCALLEVENT`, plus participant set via `ZWACALLEVENTPARTICIPANT`.
6. **Receipts.** iOS does not have Android's `message_receipt_*` tables. The `Z_PK` of `ZWAMESSAGEINFO` rows holds receipt-like fields (`ZRECEIPTINFO` blob — protobuf). v1 leaves `Message.receipts` empty for iOS and documents that limitation in the report's per-chat header.
7. **iOS-specific recovery.** ChatStorage.db is `journal_mode=WAL` on iOS. Our existing `chat4n6-sqlite-forensics::wal` works unchanged. CoreData's `Z_PRIMARYKEY` table tracks max-PK per entity — recovering deleted Z_PK gaps requires comparing live max against `Z_PRIMARYKEY.Z_MAX`, which yields a count of vanished rows even when the rows themselves are unrecoverable. Emit `CoreDataPkGap` (new warning, §2.6) when the difference exceeds zero and freelist did not produce that many records.

**User stories** (`docs/user-stories/platforms/ios-whatsapp-production.json`):

```json
[
  {
    "description": "IosWhatsAppPlugin is registered in the CLI and runs on an iOS backup directory",
    "steps": [
      "Add IosWhatsAppPlugin to the plugin vector in cli/src/commands/run.rs",
      "Run `chat4n6 run --input fixtures/ios_backup_minimal --output /tmp/out`",
      "Assert /tmp/out/index.html lists the WhatsApp iOS extraction",
      "Assert at least one chat appears under chats/",
      "cargo test -p cli -- ios_whatsapp_registered passes"
    ],
    "passes": false
  },
  {
    "description": "ZWAPROFILEPUSHNAME push-names override raw JIDs in extracted Contact.display_name",
    "steps": [
      "Build ChatStorage fixture with pushname 'Alice Smith' for jid '4155550100@s.whatsapp.net'",
      "Call extract_from_chatstorage(bytes, 0)",
      "Assert at least one Contact has display_name == 'Alice Smith' and jid == '4155550100@s.whatsapp.net'",
      "Assert the corresponding chat name resolves to 'Alice Smith' when name column is null",
      "cargo test -p chat4n6-ios-whatsapp -- pushname_resolution passes"
    ],
    "passes": false
  },
  {
    "description": "ZWACALLEVENT records are extracted into ExtractionResult.calls with Cocoa-converted timestamps",
    "steps": [
      "Build ChatStorage fixture with one ZWACALLEVENT row at ZDATE=600_000_000 (Cocoa)",
      "Assert ExtractionResult.calls.len() >= 1",
      "Assert call.timestamp.utc.timestamp() == 1_578_307_200 (978_307_200 + 600_000_000)",
      "Assert call.from_me reflects ZOUTGOING=1",
      "cargo test -p chat4n6-ios-whatsapp -- call_extraction passes"
    ],
    "passes": false
  }
]
```

---

### 2.2 — Forensic Statistics & Analytics (`stats.html`)

**What.** New report page exposing investigator-grade aggregate metrics derived from `ExtractionResult`. Not pretty charts — quantified evidence about communication patterns and concealment.

**Why.** Whapa has the only existing implementation (Android-only, descriptive). It is not forensic-grade — no deletion-rate quantification, no impossible-time detection, no cross-platform overlap. Investigators currently compute these by hand from CSV exports. Surfacing them as ranked, sortable, reproducible numbers in the report is high-leverage.

**Crates affected.**

- `crates/chat4n6-report` — new module `stats.rs`, new template `templates/stats.html`
- `crates/chat4n6-plugin-api/src/types.rs` — extend `ExtractionResult` with one new field (see below). Statistics themselves are computed at render-time; the field is for cross-extraction context only.

**Data model changes.**

```rust
// In ExtractionResult — single new field, default-empty so old JSON deserializes:
#[serde(default)]
pub extraction_started_at: Option<chrono::DateTime<Utc>>,
#[serde(default)]
pub extraction_finished_at: Option<chrono::DateTime<Utc>>,
```

These bound the activity heatmap's "after acquisition" detection (any message timestamp > `extraction_finished_at` ⇒ `TimestampAnomaly`). Without them statistics still works but the impossible-time check requires a CLI flag.

**No new fields on `Message`.** All stats are derived. This is deliberate — `ExtractionResult` is the on-disk contract; computing stats from it ensures any third party using our JSON gets the same numbers.

**Key implementation details.**

| Metric | Computation | Forensic question it answers |
|---|---|---|
| Hourly activity heatmap (24×7) | bucket message timestamps in local TZ; hour × weekday matrix | When is the suspect awake / online? Alibi window? |
| Per-chat deletion rate | `deletion_rate(chat) = deleted_msgs / max(rowid_seen) × 100` (already used inside `SelectiveDeletion` warning) | Which chats were targeted for scrubbing? |
| Response-time distribution | for each adjacent inbound→outbound pair in a 1:1 chat, record Δt; plot percentiles | Bot/automation suspicion (sub-second responses) |
| Burst detection | sliding 60-second window over per-chat timestamps; flag windows with > 30 messages | Mass-forwarding / spam evidence |
| Contact intersection across plugins | hash-join JIDs (or normalised E.164 phone) across `ExtractionResult.contacts` from all platforms | Same actor on WhatsApp + Signal + Telegram = stronger identity attribution |
| Top words / top emoji per chat | tokenise text content; rank by frequency; redact stopwords | Whapa-parity, also useful for keyword-driven scope |
| Impossible timestamp count | messages where `timestamp.utc > extraction_finished_at` | Time-tampered records |
| Source-distribution per chat | bar of evidence-source counts per chat | Where is the evidence coming from? |

Computation lives in `chat4n6-report::stats::compute(result: &ExtractionResult, tz_offset_secs: i32) -> StatsBundle`. `StatsBundle` is serializable; we write `stats.json` alongside `stats.html` for downstream consumption.

Cross-platform contact intersection requires merging is already done in `cli/src/commands/run.rs::merge_results`; render-side we group `result.contacts` by normalised key:

```rust
fn normalise_jid(jid: &str) -> String {
    // strip @s.whatsapp.net, @g.us; normalise to E.164 if leading digits
    let body = jid.split('@').next().unwrap_or(jid);
    if body.chars().all(|c| c.is_ascii_digit()) {
        format!("+{}", body)
    } else {
        body.to_string()
    }
}
```

**User stories** (`docs/user-stories/report/stats-page.json`):

```json
[
  {
    "description": "stats.html is generated and shows hourly activity heatmap per chat",
    "steps": [
      "Build an ExtractionResult with messages spanning 3 days, varied hours",
      "Call ReportGenerator::render with output_dir",
      "Assert output_dir/stats.html exists",
      "Assert stats.html contains an SVG/HTML heatmap with 24 hour columns",
      "Assert stats.json exists and round-trips through serde",
      "cargo test -p chat4n6-report -- stats_heatmap passes"
    ],
    "passes": false
  },
  {
    "description": "Cross-platform contact intersection appears for JIDs present on multiple platforms",
    "steps": [
      "Merge an ExtractionResult containing the same E.164 number on WhatsApp and Signal contacts",
      "Render with ReportGenerator",
      "Assert stats.html contains a 'Cross-platform contacts' section listing that number with platforms 'WhatsApp, Signal'",
      "cargo test -p chat4n6-report -- cross_platform_intersection passes"
    ],
    "passes": false
  },
  {
    "description": "Messages with timestamps after extraction_finished_at produce TimestampAnomaly warnings in stats.html",
    "steps": [
      "Build an ExtractionResult with extraction_finished_at = T and one message at timestamp T+1 day",
      "Render via ReportGenerator",
      "Assert stats.html contains 'Impossible timestamp' or 'future-dated' wording referencing 1 message",
      "Assert ExtractionResult.forensic_warnings contains TimestampAnomaly for that row_id",
      "cargo test -p chat4n6-report -- impossible_timestamp passes"
    ],
    "passes": false
  }
]
```

---

### 2.3 — WAL Snapshot Timeline (`snapshots.html`)

**What.** Surface the per-frame WAL state we already capture (`EvidenceSource::WalFrame(u32)`) as a navigable timeline. Investigator can answer "at WAL frame N, which messages existed in the database?" — and visually diff against frame N+1.

**Why.** This is unique territory. No competitor (commercial or OSS) exposes WAL-frame-level temporal slicing of an evidence database. It directly answers the "when was this message last present" question that comes up in spoliation hearings. We have the data; we just haven't surfaced it.

**Crates affected.**

- `crates/chat4n6-sqlite-forensics` — already produces `WalFrame(u32)` provenance and `WalDelta` records. Add one new builder: `wal_snapshots::build_snapshot_index(deltas: &[WalDelta]) -> SnapshotIndex` returning a `BTreeMap<u32, FrameSummary>` ordered by frame number.
- `crates/chat4n6-plugin-api/src/types.rs` — new top-level field on `ExtractionResult`:

  ```rust
  #[serde(default)]
  pub wal_snapshots: Vec<WalSnapshot>,
  ```

  with

  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct WalSnapshot {
      pub frame_number: u32,
      pub commit_marker: bool,           // true if this frame has the commit-set bit
      pub messages_added: Vec<i64>,      // message ROWIDs introduced in this frame
      pub messages_removed: Vec<i64>,    // ROWIDs whose newest copy in this frame is a deletion tombstone
      pub messages_mutated: Vec<i64>,    // same ROWID, different content vs previous frame
      pub frame_offset: u64,             // byte offset in the WAL file
  }
  ```

- `crates/chat4n6-report` — new template `templates/snapshots.html`; new render fn.

**Key implementation details.**

1. `WalDelta` already encodes the per-row before/after across the WAL. Group by frame number to derive `WalSnapshot` entries.
2. Snapshot rendering shows three columns per frame: **added** (green), **removed** (red), **mutated** (amber). Each cell links to the per-chat page anchor for that ROWID.
3. **Visual diff between frames N and N+1**: the page contains a JavaScript-free "step through" via simple anchor links, using CSS to highlight the current frame's row set. Server-side rendering only — no JS. (Compatible with the static-report distribution model.)
4. The `commit_marker` bit comes from WAL header parsing already done in `chat4n6-sqlite-forensics::wal`. A non-committed frame carries different forensic weight — surface it visually (dashed outline).
5. Frames are *not* a wall-clock timeline — their ordering is monotonic but not time-stamped. Where messages reference `timestamp` we cross-correlate; in the page header explain the distinction.

**User stories** (`docs/user-stories/report/wal-snapshots.json`):

```json
[
  {
    "description": "snapshots.html lists each WAL frame with added/removed/mutated message ROWIDs",
    "steps": [
      "Construct ExtractionResult.wal_snapshots with 3 frames",
      "Frame 1 introduces ROWIDs 100,101; Frame 2 mutates 100; Frame 3 removes 101",
      "Render ReportGenerator",
      "Assert snapshots.html exists with three sections labelled 'Frame 1', 'Frame 2', 'Frame 3'",
      "Assert Frame 2 highlights ROWID 100 in the mutated column",
      "Assert Frame 3 highlights ROWID 101 in the removed column",
      "cargo test -p chat4n6-report -- snapshot_timeline passes"
    ],
    "passes": false
  },
  {
    "description": "WalSnapshot.commit_marker controls dashed-vs-solid frame styling in snapshots.html",
    "steps": [
      "Build snapshots where frame 2 has commit_marker=false",
      "Render ReportGenerator",
      "Assert frame 2's rendered block has CSS class 'frame-uncommitted'",
      "Assert frames 1 and 3 (commit_marker=true) have class 'frame-committed'",
      "cargo test -p chat4n6-report -- snapshot_commit_styling passes"
    ],
    "passes": false
  },
  {
    "description": "snapshots.html cross-links each ROWID to the per-chat page anchor",
    "steps": [
      "Build a chat 'alice' containing message id=100 with anchor 'msg-100'",
      "Build wal_snapshots referencing ROWID 100 in frame 1",
      "Render ReportGenerator",
      "Assert snapshots.html contains a relative link to 'chats/alice/page_001.html#msg-100'",
      "cargo test -p chat4n6-report -- snapshot_rowid_links passes"
    ],
    "passes": false
  }
]
```

---

### 2.4 — Media Export Pipeline

**What.** End-to-end pipeline that copies referenced media files from the forensic image into the report, hashes them at export, and renders thumbnails for court-exhibit-ready output.

**Why.** Today `MediaRef.file_hash` is a *field* but no pipeline produces it. Reports show file paths; investigators must extract media manually. wfe embeds images in a single PDF (nice, but lossy). We can ship a verifiable directory of original-quality media with hash chain — strictly better.

**Crates affected.**

- `crates/chat4n6-report` — new module `media_export.rs`
- `crates/chat4n6-plugin-api/src/fs.rs` — verify `ForensicFs::read` handles binary files in DAR + iOS backup adapters (it already does for SQLite; large media is the same code path)
- `cli/src/commands/run.rs` — new flag `--export-media[=<bool>]` (default `false` to preserve current behaviour), passed through to `ReportGenerator::with_export_media(true)`

**Data model changes.** None to public types. `MediaRef.file_hash` and `MediaRef.encrypted_hash` already exist; the export pipeline populates them when previously `None`.

**Directory structure.**

```
output/
├── index.html
├── media/
│   ├── by-chat/
│   │   ├── alice/
│   │   │   ├── IMG-20260415-WA0001.jpg
│   │   │   └── PTT-20260415-WA0002.opus
│   │   └── group-foo/
│   │       └── ...
│   ├── orphaned/
│   │   └── ... files referenced by no message ...
│   └── thumbnails/
│       └── <sha256-prefix>.jpg     # 200×200 JPEG, deterministic name
├── manifest.json   # SHA-256 of every file in output/, including media
└── ...
```

**Key implementation details.**

1. `ForensicFs::read(path)` returns the encrypted-on-disk bytes (e.g. WhatsApp `.crypt` media uses per-message keys). We skip per-message decryption in v1 and write the **on-disk bytes verbatim** — this preserves the encrypted artefact exactly as it was found, which is what most court protocols require. Decrypting media would require the per-message `MediaRef.media_key_b64`, doable in a v2 follow-up.
2. **Hash on export.** During copy: `let mut hasher = Sha256::new(); hasher.update(&bytes); let h = hex::encode(hasher.finalize());`. Set `media_ref.encrypted_hash = Some(h)`. The plaintext hash (`file_hash`) only becomes computable after per-message decryption — leave it `None` in v1.
3. **Thumbnails.** `image` crate, pure Rust. JPEG decode → 200×200 max-side resize → JPEG encode at q=70. Name: `thumbnails/<first 16 hex chars of sha256>.jpg`. Deterministic name lets the manifest hash chain remain stable across re-runs.
4. **DAR support.** `DarFs::read(path)` already returns inflated file bytes. Confirm with one test that copies a media file out of a DAR fixture.
5. **Orphaned media.** `crates/plugins/chat4n6-whatsapp/src/orphaned_media.rs` already detects orphans. Export them to `media/orphaned/` and link from the existing gallery / a new "Orphans" section.
6. **Gallery enhancement.** The current `gallery.html` template lists media references. Update it to embed `<img src="media/thumbnails/<hash>.jpg">` when `--export-media` was used. Without the flag the template falls back to the current "path only" rendering.
7. **Court-exhibit packet.** Add a deterministic `EXHIBIT-INDEX.csv` listing one row per exported media file: `path, sha256, source_chat, source_msg_id, source_evidence_layer`. This is the artefact lawyers actually attach to motions.

**User stories** (`docs/user-stories/report/media-export.json`):

```json
[
  {
    "description": "--export-media copies referenced media files into output/media/by-chat/<slug>/",
    "steps": [
      "Build a fixture ForensicFs containing one image file at the WhatsApp Media path",
      "Build an ExtractionResult with one Message referencing that file via MediaRef",
      "Run chat4n6 with --export-media",
      "Assert output/media/by-chat/<chat-slug>/<filename> exists with identical bytes",
      "Assert MediaRef.encrypted_hash in stored JSON matches sha256(bytes)",
      "cargo test -p chat4n6-report -- media_export_copy passes"
    ],
    "passes": false
  },
  {
    "description": "Thumbnails are generated for image media and referenced from gallery.html",
    "steps": [
      "Run chat4n6 --export-media on a fixture with one JPEG and one MP4",
      "Assert output/media/thumbnails/<hex16>.jpg exists for the JPEG",
      "Assert no thumbnail is produced for the MP4 (out of scope for v1)",
      "Assert gallery.html contains <img src=\"media/thumbnails/<hex16>.jpg\">",
      "cargo test -p chat4n6-report -- media_thumbnails passes"
    ],
    "passes": false
  },
  {
    "description": "EXHIBIT-INDEX.csv is generated with sha256 + source provenance for every exported file",
    "steps": [
      "Run chat4n6 --export-media on a fixture with two media files",
      "Assert output/EXHIBIT-INDEX.csv exists",
      "Assert it contains exactly two data rows (plus header)",
      "Assert each row has a non-empty sha256 column matching the file's actual hash",
      "Assert source_evidence_layer matches the producing Message.source variant",
      "cargo test -p chat4n6-report -- exhibit_index passes"
    ],
    "passes": false
  }
]
```

---

### 2.5 — Signal & Telegram Completion

**What.** Promote both plugins from "extractor compiles" to "produces forensically useful output". For Signal that means recipients/threads/groups/reactions and the Signal-specific anti-forensic surface. For Telegram that means dialogs/users/messages/media/calls and channel-message provenance.

**Why.** The CLI registers both today, but they emit empty `ExtractionResult`s on real images. This is brittle — investigators run chat4n6, see no Signal output, and conclude the device has no Signal. Empty output must be distinguishable from "we don't support this artefact" — best fix is to actually support it.

**Crates affected.**

- `crates/plugins/chat4n6-signal` — completion
- `crates/plugins/chat4n6-telegram` — completion
- `crates/chat4n6-plugin-api/src/types.rs` — three new variants (see below) and one optional new `Message` field

**Data model changes.**

```rust
// types.rs — additions
pub enum ForensicWarning {
    // ... existing 6 variants ...
    /// Signal: a `disappearing_messages_timer` value > 0 was set in this chat,
    /// AND the count of `MessageContent::Deleted` matches the timer cadence —
    /// suggests intentional vanishing-message use.
    DisappearingTimerActive { chat_id: i64, timer_seconds: u32, vanished_count: u32 },
    /// Signal: a sealed-sender envelope was received for which we cannot resolve
    /// the originating identity from the recipient table.
    SealedSenderUnresolved { thread_id: i64, count: u32 },
    /// Telegram: a forwarded-from reference points to a channel/user we have no
    /// record of in the users/channels tables — message was forwarded from a
    /// source the device never observed directly.
    UnresolvedForwardSource { message_id: i64, forward_from_id: i64 },
}

// Message — one new optional field, default-empty:
#[serde(default)]
pub forwarded_from: Option<ForwardOrigin>,

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForwardOrigin {
    pub origin_kind: ForwardOriginKind,    // User | Channel | Unknown
    pub origin_id: String,                 // jid / channel_id / username
    pub origin_name: Option<String>,
    pub original_timestamp: Option<ForensicTimestamp>,
}
```

**Signal — minimum viable output.**

Tables to read from `signal.db`:

| Table | Purpose | chat4n6 mapping |
|---|---|---|
| `recipient` | identity table (UUID, ACI, PNI, phone, profile name) | `Contact` |
| `thread` | one row per chat (1:1 or group); links to `recipient.id` | `Chat` |
| `message` (legacy: `sms` + `mms`) | message body, type bits, expiration timer, sender id | `Message` |
| `groups_v2` (or `groups`) | group membership | populates `Chat.is_group`, group participant resolution |
| `reaction` | per-message reactions | `Message.reactions` |
| `mention` | @-mentions in group messages | annotate text |
| `payment_table` | MobileCoin payments (rare) | optional v2 |

Signal-specific forensic logic:

1. **Disappearing message timer.** Each `thread` row has `expires_in_seconds`. When > 0, count messages whose `expires_started > 0` and whose body has been overwritten with `null`/empty — these are timer-vanished. Emit `DisappearingTimerActive`.
2. **Sealed sender.** `message.envelope_type & 0x10 == 0x10` indicates sealed sender. If `recipient_id` cannot be resolved against `recipient`, emit `SealedSenderUnresolved`.
3. **`message.message_type` bit field** decodes to delivered/read/failed/key-exchange/etc. — already a 16+ value space in upstream Signal source. Map to `Message.receipts` where bits indicate delivery/read.

**Telegram — minimum viable output.**

Tables to read from `cache4.db` (modern Android Telegram):

| Table | Purpose | chat4n6 mapping |
|---|---|---|
| `users` | user_id → name/username/phone | `Contact` |
| `chats` (or `dialogs`) | chat list | `Chat` |
| `messages_v2` | per-dialog messages (current schema) | `Message` |
| `media_v3` | attachments | `MediaRef` |
| `channel_users` | channel admins/members | participant resolution |
| `tgcalls` | call history | `CallRecord` |

Telegram-specific forensic logic:

1. **Forwarded-from origin.** Each forwarded message stores a small protobuf in `messages_v2.data` containing `fwd_from.from_id`, `fwd_from.from_name`, `fwd_from.date`, `fwd_from.channel_post`. Decode and populate `Message.forwarded_from`. If `from_id` is not in `users`/`chats`, emit `UnresolvedForwardSource`.
2. **Channel-message provenance.** Channel posts have `out_peer.channel_id` and `peer.access_hash`. Concatenate as `tg-channel://<channel_id>` and use as `Message.sender_jid` to give a stable identifier even when the channel is not known.

**Common implementation note.** Both plugins must use our `chat4n6-sqlite-forensics::recover_all` API, *not* `rusqlite` direct queries. This is what gives them WAL/freelist/FTS recovery for free. The current Signal scaffold already does this — extend the same pattern to message-body decoding.

**User stories** (`docs/user-stories/platforms/signal-production.json` and `telegram-production.json` — three each, examples below):

```json
[
  {
    "description": "Signal disappearing-message timer produces DisappearingTimerActive warning",
    "steps": [
      "Build signal.db fixture: thread row with expires_in_seconds=86400; 3 messages with expires_started>0 and empty body",
      "Run SignalPlugin extract",
      "Assert ExtractionResult.forensic_warnings contains DisappearingTimerActive { chat_id, timer_seconds: 86400, vanished_count: 3 }",
      "cargo test -p chat4n6-signal -- disappearing_timer passes"
    ],
    "passes": false
  },
  {
    "description": "Signal sealed-sender unresolved envelopes are counted and warned",
    "steps": [
      "Build signal.db with one message envelope_type & 0x10 == 0x10 and recipient_id not in recipient table",
      "Run SignalPlugin extract",
      "Assert ExtractionResult.forensic_warnings contains SealedSenderUnresolved { thread_id, count: 1 }",
      "cargo test -p chat4n6-signal -- sealed_sender_unresolved passes"
    ],
    "passes": false
  },
  {
    "description": "Telegram forwarded message populates Message.forwarded_from with origin metadata",
    "steps": [
      "Build cache4.db with one message containing fwd_from.from_id=12345, from_name='Channel X', date=1700000000",
      "Run TelegramPlugin extract",
      "Assert the message's forwarded_from is Some with origin_id=='12345' and original_timestamp.utc.timestamp()==1700000000",
      "cargo test -p chat4n6-telegram -- forwarded_from passes"
    ],
    "passes": false
  }
]
```

---

### 2.6 — New `ForensicWarning` variants

**What.** Extend `ForensicWarning` from 6 variants to 14, covering anti-forensic patterns that are currently silently undetected.

**Why.** Each new warning is the answer to a specific question an investigator types into Slack at 2am. Today our 6 variants cover the *categorical* forensic surface but the long tail of platform-specific tampering patterns is invisible.

**Crates affected.**

- `crates/chat4n6-plugin-api/src/types.rs` — variants below
- `crates/plugins/chat4n6-whatsapp/src/anti_forensics.rs` — Android-specific detectors
- `crates/plugins/chat4n6-ios-whatsapp` — iOS-specific detectors
- `crates/plugins/chat4n6-signal`, `chat4n6-telegram` — sealed-sender + forward-source (already in §2.5)
- `crates/chat4n6-sqlite-forensics` — generic detectors (timestamps, ROWID reuse)

**The 8 new variants.**

```rust
// 7. iOS / CoreData specific
CoreDataPkGap { entity_name: String, expected_max: i64, observed_max: i64, recovered_count: i64 },
//    Z_PRIMARYKEY.Z_MAX exceeds (live max + recovered count) — rows vanished without freelist trace.

// 8. Cross-platform: time tampering
ImpossibleTimestamp { message_row_id: i64, ts_utc: chrono::DateTime<Utc>, reason: ImpossibleReason },
//    where ImpossibleReason ∈ { FuturePastAcquisition, BeforeAppInstall, BeforeUnixEpoch }

// 9. Cross-platform: identity collision
DuplicateStanzaId { stanza_id: String, occurrences: u32 },
//    Same XMPP-style stanza id appears on multiple ROWIDs — possible re-import or device cloning.

// 10. Android-specific: ROWID reuse
RowIdReuseDetected { table: String, rowid: i64, conflicting_timestamps: Vec<chrono::DateTime<Utc>> },
//    A ROWID is observed at two different timestamps in WAL history — DELETE then INSERT in same slot.

// 11. Android-specific: thumbnail orphan ratio
ThumbnailOrphanHigh { orphan_thumbnails: u32, total_messages: u32, ratio_pct: u8 },
//    message_thumbnails has many entries with no matching messages.media_url — media deleted, evidence remains.

// 12. Backup-level: per-file HMAC mismatch (granularity beyond existing whole-file HmacMismatch)
PerFileHmacMismatch { file_name: String },

// 13. Signal: disappearing-timer tampering — see §2.5

// 14. Telegram: unresolved-forward — see §2.5
```

**Key implementation details for the generic detectors.**

- **`ImpossibleTimestamp`.** Three sub-checks:
  - `FuturePastAcquisition`: `msg.timestamp.utc > extraction_finished_at` (requires §2.2 field).
  - `BeforeAppInstall`: requires app-install timestamp from device. v1 leaves this undetected (no source); document as v2 work.
  - `BeforeUnixEpoch`: `msg.timestamp.utc < UNIX_EPOCH`.
- **`DuplicateStanzaId`.** WhatsApp `messages.key_id` (Android) and `ZSTANZAID` (iOS). Build `HashMap<String, Vec<i64>>` over all extracted messages; emit one warning per stanza_id with > 1 occurrence.
- **`RowIdReuseDetected`.** Walk `WalDelta` records grouped by `(table, rowid)`. If two non-deletion observations have non-equal `timestamp` content, emit. Already partially detected by our delta logic — needs to be raised as a warning, not just data.

**User stories** (`docs/user-stories/sqlite-engine/new-warnings.json`):

```json
[
  {
    "description": "DuplicateStanzaId is emitted when WhatsApp messages.key_id repeats across ROWIDs",
    "steps": [
      "Build msgstore.db fixture with two messages sharing key_id 'ABC123' but different _id",
      "Run WhatsAppPlugin extract",
      "Assert ExtractionResult.forensic_warnings contains DuplicateStanzaId { stanza_id: 'ABC123', occurrences: 2 }",
      "cargo test -p chat4n6-whatsapp -- duplicate_stanza_id passes"
    ],
    "passes": false
  },
  {
    "description": "RowIdReuseDetected is emitted when a WAL replay shows the same ROWID at two different timestamp values",
    "steps": [
      "Build msgstore.db + WAL fixture: WAL frame 1 inserts rowid=42 ts=1000; frame 2 deletes; frame 3 inserts rowid=42 ts=2000",
      "Run extraction with WAL recovery enabled",
      "Assert ExtractionResult.forensic_warnings contains RowIdReuseDetected { table: 'messages', rowid: 42, .. } with both timestamps in conflicting_timestamps",
      "cargo test -p chat4n6-sqlite-forensics -- rowid_reuse passes"
    ],
    "passes": false
  },
  {
    "description": "ThumbnailOrphanHigh is emitted when message_thumbnails orphan ratio exceeds 30%",
    "steps": [
      "Build msgstore.db with 10 messages and 5 message_thumbnails entries pointing to non-existent message_row_id",
      "Run WhatsAppPlugin extract",
      "Assert ExtractionResult.forensic_warnings contains ThumbnailOrphanHigh { orphan_thumbnails: 5, total_messages: 10, ratio_pct: 50 }",
      "cargo test -p chat4n6-whatsapp -- thumbnail_orphan_high passes"
    ],
    "passes": false
  }
]
```

---

## 3. Priority Ordering

| Rank | Spec | Forensic value | Effort | Differentiation | Dependency |
|---|---|---|---|---|---|
| 1 | §2.1 iOS WhatsApp production | High — closes only iOS gap that matters | M (scaffold ⇒ orchestrate) | High — wfe is read-only; we add 9-layer recovery on iOS | Standalone |
| 2 | §2.6 New `ForensicWarning` variants | High — every variant is a real investigative question | S (mostly detector logic on existing data) | High — no competitor has comparable warning vocabulary | Standalone (some detectors require §2.2 field for impossible-time) |
| 3 | §2.4 Media export pipeline | High — court-exhibit-ready output is table-stakes | M | Medium — wfe inlines into PDF; our verifiable directory is better but less novel | Standalone |
| 4 | §2.2 Statistics & analytics | Medium-high — investigator productivity multiplier | M | High — Whapa has descriptive stats; our forensic-grade metrics (deletion rate, impossible time, cross-platform overlap) are unique | Independent of others; emits new field that §2.6 consumes |
| 5 | §2.3 WAL snapshot timeline | Medium — niche but uniquely ours | S–M (data exists) | Highest — nothing comparable exists in any tool | Independent |
| 6 | §2.5 Signal + Telegram completion | Medium — silent failure is currently misleading | L (two plugins, full surface) | Medium — Cellebrite already does both; our edge is recovery + warnings | Standalone |

**Ordering rationale.**

- **Rank 1 (iOS)** is first because it is the highest-value gap *and* the lightest lift (the parsing scaffold is largely written; orchestration + JOIN maps + CLI registration is ~3 days). Shipping it makes "we cover both Android and iOS WhatsApp with forensic recovery" provable in a single demo.
- **Rank 2 (warnings)** is second because each warning is small, independent, and adds tangible forensic value per commit. They can be developed in parallel by separate subagents and merged in any order.
- **Rank 3 (media export)** is third because it unblocks the court-exhibit use case that legal teams ask for first.
- **Rank 4 (stats)** depends on no other work but the *quality* of stats is a function of warning coverage (§2.6), so doing §2.6 first means stats launches with all warnings already counted.
- **Rank 5 (snapshots)** is independently doable but lower urgency: it is differentiation, not table-stakes.
- **Rank 6 (Signal/Telegram)** is biggest scope. It is intentionally last because (a) the existing scaffolds make the silent-failure damage tolerable in the short term, and (b) the iOS work proves the pattern that Signal/Telegram completion will follow.

**Skipped from this design (deferred or out of scope):**

- Multi-language report headers (wfe parity feature — defer; English-first market priority).
- Differential acquisition reporting (`chat4n6 diff`) — already in v1 roadmap §2.C.3, no new design needed.
- Interactive hex viewer — deferred (largest single effort, separate decomposition).
- BLOB signature detection (§2.A.2 of v1 roadmap) — already specified, no overlap.
- Timestamp auto-detection (§2.A.1 of v1 roadmap) — already specified, no overlap; §2.6 `ImpossibleTimestamp` consumes its output.

---

## 4. Architecture Observations

These are cross-cutting issues exposed by designing the above. Addressing them up front prevents repeated DRY violations.

**O1. `ExtractionResult` is the single source of truth — keep it serialisable.** Every new field must have `#[serde(default)]` so old JSON deserialises cleanly (the existing tests for `MediaRef` enforce this pattern; replicate). The added fields in §2.2 (`extraction_*_at`) and §2.3 (`wal_snapshots`) follow this.

**O2. Render-time computation vs storage.** Stats (§2.2), snapshots-rendering (§2.3), and warnings-derivation should all live in render-time helpers on top of `ExtractionResult` — *not* baked into the plugin output. This keeps plugins focused on extraction and lets a third party consuming our JSON compute the same numbers.

  Exception: warnings the plugin alone can detect (e.g. `DuplicateStanzaId` over WhatsApp's `key_id`) should be detected in the plugin and surfaced via `forensic_warnings`. Render-time warning derivation is for cross-extraction stuff (e.g. impossible timestamps relative to acquisition window).

**O3. Plugin registry is an ordered `Vec`, not a config.** `cli/src/commands/run.rs` enumerates plugins inline. Iterating "all plugins" today means modifying that file. Promote to a `fn registered_plugins() -> Vec<Box<dyn ForensicPlugin>>` in a small new `chat4n6-plugins` aggregator crate, which downstream binary embedders can re-export. Cost: 30 lines. Benefit: §2.5 + iOS registration become single-line additions.

**O4. `ForensicFs::read` returns `Vec<u8>` — fine for SQLite, sub-optimal for media export.** A 200 MB MP4 forces a full allocation. v1 of media export accepts this; v2 should add `read_streaming(path: &str) -> Box<dyn Read>` to the trait, default-implemented as `Cursor::new(self.read(path))` so existing impls stay sound.

**O5. Report-template DRY — `base.html` already factors header/footer.** New pages (`stats.html`, `snapshots.html`) must extend `base.html`, not duplicate its scaffolding. The existing `chat_page.html`, `timeline.html`, `index.html` set the pattern; follow it.

**O6. Test fixtures — `make_chatstorage_db()`, `make_telegram_db()` patterns are good; standardise.** Each plugin crate already has a `make_*_db()` builder in tests. Hoist a tiny `chat4n6-test-fixtures` dev-dep crate exposing primitive SQLite-builder helpers (table create, row insert) so the per-plugin builders are thin.

**O7. The `Message` type is at risk of becoming a god-struct.** It already has 14 fields. Adding `forwarded_from` (§2.5) brings it to 15. After that, any new platform-specific metadata should live in a `Message.platform_metadata: serde_json::Value` bag, not a typed field. Document this as a soft cap: "if your new field is platform-specific, use the bag; if it's cross-platform, use a typed field."

**O8. CLI flags vs always-on.** `--export-media` (§2.4) is opt-in to avoid bloating reports. Stats and snapshots are *always* generated — they cost nothing if there is nothing to render and add no bytes when empty. iOS plugin registration is always-on (no flag).

**O9. `cli/src/commands/run.rs::merge_results` does not merge `forensic_warnings` or `group_participant_events`.** Read the current code: `dst.chats.extend; dst.contacts.extend; dst.calls.extend; dst.wal_deltas.extend;` — that's it. Bug. Adding §2.6 warnings will make this bug visible because per-plugin warnings will get dropped on the floor when a second plugin runs. Fix in the same PR as §2.1 iOS (which is the first time more than one plugin produces warnings).

**O10. ROWID-reuse detection (§2.6 #10) requires `WalDelta` to carry per-frame timestamp content, which it currently does not store as a structured field — only the whole-row blob.** This is a small data-model change in `chat4n6-sqlite-forensics::wal::WalDelta`. Either parse the timestamp out at delta-emit time, or in the warning detector. Detector-side is cleaner (keeps `WalDelta` schema-agnostic).

---

## 5. Implementation Sequencing

A concrete ordering compatible with TDD (RED commit, then GREEN commit, per `~/.claude/CLAUDE.md`):

```
Sprint 1 (1–2 weeks)
  - O3 plugin registry refactor      (1 day)
  - O9 merge_results fix             (½ day)
  - §2.1 iOS WhatsApp completion     (5 days)
  - §2.6 new warnings: 7, 8, 9, 12   (3 days, parallelisable)

Sprint 2 (1–2 weeks)
  - §2.4 media export pipeline       (4 days)
  - §2.6 new warnings: 10, 11        (2 days)
  - O7 Message.platform_metadata bag (1 day)

Sprint 3 (1–2 weeks)
  - §2.2 statistics page             (4 days)
  - O5/O6 template + fixture cleanup (1 day)

Sprint 4 (1–2 weeks)
  - §2.3 WAL snapshots               (3 days)
  - §2.6 finalisation, missing tests (2 days)

Sprint 5–6 (3–4 weeks)
  - §2.5 Signal completion           (5 days)
  - §2.5 Telegram completion         (5 days)
  - §2.6 warnings 13, 14             (with §2.5)
```

Gate each sprint behind: (a) `cargo test --workspace` green, (b) Nemetz corpus benchmark non-regression (already in CI per recent commits), (c) updated user-stories JSON files with `passes: true` flipped on shipped items.

---

## 6. Quick-Reference: New Public Types

For the convenience of subagents implementing this design, here is the consolidated diff to `crates/chat4n6-plugin-api/src/types.rs`:

```rust
// On ExtractionResult — three new fields (additive, serde-default):
#[serde(default)] pub extraction_started_at: Option<DateTime<Utc>>,
#[serde(default)] pub extraction_finished_at: Option<DateTime<Utc>>,
#[serde(default)] pub wal_snapshots: Vec<WalSnapshot>,

// New struct:
pub struct WalSnapshot {
    pub frame_number: u32,
    pub commit_marker: bool,
    pub messages_added: Vec<i64>,
    pub messages_removed: Vec<i64>,
    pub messages_mutated: Vec<i64>,
    pub frame_offset: u64,
}

// On Message — one new optional field:
#[serde(default)] pub forwarded_from: Option<ForwardOrigin>,

// New struct + enum:
pub struct ForwardOrigin {
    pub origin_kind: ForwardOriginKind,
    pub origin_id: String,
    pub origin_name: Option<String>,
    pub original_timestamp: Option<ForensicTimestamp>,
}
pub enum ForwardOriginKind { User, Channel, Unknown }

// On ForensicWarning — eight new variants (existing 6 retained):
DisappearingTimerActive { chat_id: i64, timer_seconds: u32, vanished_count: u32 },
SealedSenderUnresolved { thread_id: i64, count: u32 },
UnresolvedForwardSource { message_id: i64, forward_from_id: i64 },
CoreDataPkGap { entity_name: String, expected_max: i64, observed_max: i64, recovered_count: i64 },
ImpossibleTimestamp { message_row_id: i64, ts_utc: DateTime<Utc>, reason: ImpossibleReason },
DuplicateStanzaId { stanza_id: String, occurrences: u32 },
RowIdReuseDetected { table: String, rowid: i64, conflicting_timestamps: Vec<DateTime<Utc>> },
ThumbnailOrphanHigh { orphan_thumbnails: u32, total_messages: u32, ratio_pct: u8 },
PerFileHmacMismatch { file_name: String },

pub enum ImpossibleReason { FuturePastAcquisition, BeforeAppInstall, BeforeUnixEpoch }
```

All additions are backward-compatible at the JSON layer because they are either new variants (forward-compatible enum extension is a serde non-issue with `#[serde(...)]` default tagging) or new fields with `#[serde(default)]`.

---

## 7. What This Design Does Not Cover

For accountability against the original task's "5 well-specified beats 20 vague" guidance, here is what was deliberately *not* included:

- **Multi-language report headers** — wfe parity feature, low ROI.
- **Differential acquisition reporting** — already in v1 roadmap, no new design needed.
- **Interactive hex viewer** — too large for this design; needs its own decomposition.
- **Per-message media decryption (`file_hash`)** — v2 work; v1 ships `encrypted_hash` only.
- **Streaming `ForensicFs::read`** — noted in O4 as v2.
- **`Message.platform_metadata` bag (O7)** — flagged as architectural guidance; specific use cases not enumerated.
- **Signal payment table, Telegram secret chats, WhatsApp Communities** — long-tail platform features; revisit per investigator demand.

End of design.
