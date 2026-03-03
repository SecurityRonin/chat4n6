# chat4n6

> Fast, deep WhatsApp forensics from Android images — recovers what commercial tools miss.

`chat4n6` is an open-source command-line tool for digital forensic examiners. It extracts
WhatsApp artifacts from Android forensic images (DAR archives from Passware Kit Mobile),
including messages that were deleted, resided only in the SQLite write-ahead log, or were
carved from unallocated space.

---

## Why chat4n6?

Most forensic tools read what SQLite openly offers. `chat4n6` digs deeper:

| Recovery source | Most tools | chat4n6 |
|---|---|---|
| Live messages | Yes | Yes |
| WAL (uncommitted frames) | Partial | Yes — with delta report |
| WAL (historic, checkpointed) | Rarely | Yes |
| Freelist pages (stacked records) | Rarely | Yes |
| FTS index (deleted-after-search) | Almost never | Yes |
| Unallocated space carving | Sometimes | Yes — with confidence scoring |
| Carved SQLite DBs from unallocated | No | Yes |
| Rollback journals (zeroed headers) | No | Yes |
| Schema version history (ALTER TABLE) | No | Yes |

Every recovered record is tagged with its evidence source (`[LIVE]`, `[WAL-PENDING]`,
`[FREELIST]`, `[FTS-ONLY]`, `[CARVED-UNALLOC]`, etc.) and carved records include a
confidence percentage derived from live-record signature learning — information that
matters when presenting evidence.

Reports are paginated HTML with inline thumbnails — no JavaScript, no external
dependencies, court-ready out of the box.

---

## Quick Start

```bash
# Install (requires Rust 1.75+)
cargo install chat4n6

# Run full analysis
chat4n6 run --input case001.dar --output ./case001-report

# With timezone and decryption key
chat4n6 run \
  --input case001.dar \
  --output ./case001-report \
  --timezone "Asia/Manila" \
  --key-file ./whatsapp.key

# Open the report
open ./case001-report/index.html
```

That's it. `chat4n6 run` handles everything: DAR parsing, database decryption,
6-layer SQLite recovery, and HTML report generation.

---

## What You Get

```
case001-report/
├── index.html              ← Case dashboard with evidence summary
├── chats/                  ← One folder per conversation, paginated
├── calls/                  ← Full call log (audio + video, group calls)
├── media_gallery/          ← Extracted images, videos, voice notes
├── deleted/
│   ├── wal_delta.html      ← What changed between WAL and main DB
│   ├── fts_recovered.html  ← Messages recovered from search index
│   └── carved_unalloc.html ← Carved records with confidence scores
├── carved_dbs/             ← Databases reconstructed from unallocated space
├── media/                  ← Extracted media files
└── carve-results.json      ← Machine-readable output for scripting
```

---

## Input Requirements

`chat4n6` accepts DAR archives (v8 and v9) produced by **Passware Kit Mobile**.
The DAR format preserves the Android filesystem including unallocated space,
which is essential for deep recovery.

If you already have a decrypted directory of WhatsApp database files, pass the
directory path directly:

```bash
chat4n6 run --input /path/to/extracted/com.whatsapp/databases/ --output ./report
```

---

## Supported Artifacts

**Messages:** text, images, video, audio, voice notes, stickers (animated and static),
documents, contact cards, location shares, system messages, deleted messages (type 15)

**Reactions:** emoji reactions with reactor identity and timestamp

**Quoted messages:** preserves the text of messages that were deleted after being quoted

**Calls:** direction, type (audio/video), duration, group calls, timestamps

**Contacts:** display names, JIDs, phone numbers from `wa.db`

**Linked devices:** companion device records from `companion_devices.db`

---

## Advanced Usage

<details>
<summary>Subcommands (run stages separately)</summary>

```bash
# Stage 1: Parse DAR and locate databases
chat4n6 extract --input case001.dar --output ./work

# Stage 2: Run forensic recovery
chat4n6 carve --input ./work --output ./work

# Stage 3: Generate report (fast — no re-carving)
chat4n6 report --from ./work/carve-results.json --output ./report --timezone "UTC+8"
```

Separating stages lets you adjust report parameters (timezone, page size, confidence
threshold) without re-running the slow unallocated space carving.

</details>

<details>
<summary>Tuning recovery</summary>

```bash
# Skip unallocated carving for speed (still runs layers 1-5)
chat4n6 run --input case001.dar --output ./report --no-unalloc

# Only include carved records above 70% confidence
chat4n6 run --input case001.dar --output ./report --confidence 0.7

# Adjust records per HTML page (default: 500)
chat4n6 run --input case001.dar --output ./report --page-size 200
```

</details>

<details>
<summary>Encrypted databases</summary>

WhatsApp encrypts its backup databases (`.crypt14`, `.crypt15`). The decryption key
is stored on the device at `/data/data/com.whatsapp/files/key`.

If Passware Kit Mobile extracted the key, pass it directly:
```bash
chat4n6 run --input case001.dar --output ./report --key-file ./key
```

If the key file is inside the DAR archive, `chat4n6` will locate it automatically.

</details>

<details>
<summary>Understanding evidence tags</summary>

Every message and artifact in the report carries a source tag:

| Tag | Meaning |
|---|---|
| `[LIVE]` | Present in the active database |
| `[WAL-PENDING]` | In the WAL file, not yet written to main DB |
| `[WAL-HISTORIC]` | Was in the WAL but superseded — indicates modification or deletion |
| `[FREELIST]` | Recovered from SQLite freelist (deleted but space not reused) |
| `[FTS-ONLY]` | Present in WhatsApp's search index but deleted from message table |
| `[CARVED-UNALLOC]` | Carved from unallocated space — includes confidence % |
| `[CARVED-DB]` | From a database reconstructed from unallocated space |

Confidence percentages on carved records are derived from statistical analysis of
live records — a 94% confidence record matches the serial type pattern seen in 94%
of live records in that table.

</details>

---

## Limitations

- **MVP:** Android only. iOS support is planned.
- **MVP:** WhatsApp only. Signal and Telegram support is planned.
- **Encrypted backups** require the original key file. `chat4n6` does not brute-force keys.
- Recovery of deleted data depends on acquisition timing — records overwritten before
  acquisition cannot be recovered by any tool.

---

## Building from Source

```bash
git clone https://github.com/SecurityRonin/chat4n6.git
cd chat4n6
cargo build --release
./target/release/chat4n6 --help
```

Requires Rust 1.75 or later. No system dependencies (pure Rust, no SQLite C library).

---

## Contributing

Issues and pull requests welcome. See `docs/plans/` for the implementation roadmap.

---

## License

MIT — see [LICENSE](LICENSE).
