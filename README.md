# chat4n6

> Fast, deep WhatsApp forensics from Android images — recovers what commercial tools miss.

When a suspect deletes a WhatsApp message, the data rarely disappears. It lingers in SQLite freelists, write-ahead logs, rollback journals, the in-app search index, intra-page gaps, and unallocated disk space — often intact and recoverable, if you know where to look.

`chat4n6` is a free, open-source forensic tool that systematically recovers this evidence from Android filesystem images. It goes **eight layers deep** into each WhatsApp database, tags every recovered record with its evidence source and confidence score, and produces court-ready HTML reports — all from a single command.

**No SQLite C library. No Python. No runtime dependencies. One binary.**

---

## Who This Is For

### Incident Response Teams

You're in the first 72 hours of an insider threat investigation. A device image landed on your desk. You need chat artifacts — fast — to understand scope and identify other compromised parties before evidence disappears.

```bash
chat4n6 run --input ./acquired-image/ --output ./triage-report --no-unalloc
```

Layers 1-7 complete in seconds. Open `triage-report/index.html` and you have live messages, deleted messages recovered from WAL/freelist/journal/FTS, all tagged with evidence source. Layer 8 (unallocated carving) is optional and adds thoroughness at the cost of time.

### Digital Forensics Practitioners

You need defensible, reproducible evidence recovery that goes deeper than commercial tools. `chat4n6` provides:

- **Eight recovery layers** with full provenance — every record tagged `[LIVE]`, `[WAL-PENDING]`, `[FREELIST]`, `[FTS-ONLY]`, `[CARVED-UNALLOC 94%]`, etc.
- **Confidence scoring** on carved records — derived from schema signature frequency analysis against live records
- **SHA-256 deduplication** across all layers — no double-counting, no inflated statistics
- **Verification commands** — for each carved finding, the report includes `sqlite3` and `xxd` shell commands to independently verify the raw hex at the reported offset
- **WAL delta analysis** — row-level comparison (Added / Deleted / Modified) between WAL and main database state

### Law Firms & Liquidators

You don't need to be a forensic examiner. You need to understand what's there — fast — so you can make informed decisions about resourcing, legal strategy, and whether to engage a specialist.

`chat4n6` gives you a triage-grade view of the evidence landscape:

- **How many messages?** Live count vs. deleted count, broken down by chat
- **What was deleted?** Recovered messages shown alongside live ones, clearly tagged
- **How much more could there be?** Carved records with confidence scores tell you whether deeper analysis is likely to yield additional evidence
- **Scale and severity** — the HTML report is self-contained, readable in any browser, and can be shared with counsel immediately

**Important:** Carved and recovered records carry inherent uncertainty. False positives and false negatives are possible. The triage report helps you gauge whether the case warrants full forensic analysis — it is not a substitute for expert examination when evidence will be presented in proceedings.

---

## Recovery Depth

Most forensic tools read what SQLite openly offers. `chat4n6` implements eight recovery layers, informed by peer-reviewed techniques (bring2lite, FQLite, Sanderson et al.):

| Layer | Source | What it finds | Commercial tools |
|-------|--------|---------------|-----------------|
| 1 | Live B-tree | Active messages, calls, contacts | All tools |
| 2 | WAL replay | Uncommitted transactions, pending writes | Some tools |
| 3 | WAL delta | Row-level Added/Deleted/Modified analysis | Rarely |
| 4 | Freelist | Deleted rows on reusable pages | Rarely |
| 5 | FTS index | Messages deleted after being searched | Almost never |
| 6 | Intra-page gaps | Records in unallocated space within pages | Almost never |
| 7 | Rollback journal | Pre-modification page snapshots | Almost never |
| 8 | Unallocated carving | Schema-aware heuristic carving with confidence scoring | Sometimes (no scoring) |

Every record carries an evidence source tag. Carved records include a confidence percentage: a 94% record matches the serial type pattern of 94% of live records in that table.

---

## Quick Start

```bash
# Install (requires Rust 1.75+)
cargo install chat4n6

# Run full analysis on an extracted Android filesystem
chat4n6 run --input /path/to/android/root --output ./report

# With timezone and case metadata
chat4n6 run \
  --input /path/to/android/root \
  --output ./case-2026-001 \
  --case-name "Case 2026-001" \
  --timezone "Asia/Manila"

# Fast triage — skip unallocated carving (layers 1-7 only)
chat4n6 run --input ./image/ --output ./triage --no-unalloc

# DAR archive from Passware Kit Mobile
chat4n6 run --input ./userdata.1.dar --output ./report

# iOS backup (iTunes-style with Manifest.db)
chat4n6 run --input ./ios-backup-dir/ --output ./report

# Encrypted WhatsApp databases
chat4n6 run --input ./image/ --output ./report --key-file ./key
```

---

## Input Formats

`chat4n6` auto-detects the input format:

| Format | Source | How to acquire |
|--------|--------|----------------|
| **Plaintext directory** | Extracted Android filesystem tree | Any extraction tool preserving directory structure |
| **DAR archive** (`.dar`) | Passware Kit Mobile, other acquisition tools | Direct from acquisition software |
| **iOS backup** | iTunes-style backup with `Manifest.db` | `libimobiledevice`, iTunes, Finder backup |

WhatsApp databases are expected at:
```
<root>/data/data/com.whatsapp/databases/
```

If WhatsApp databases are encrypted (`.crypt14`, `.crypt15`), provide the key file from `/data/data/com.whatsapp/files/key` on the device.

---

## Output

```
report/
├── index.html              ← Case dashboard: chat list, counts, evidence summary
├── chat_<id>_<page>.html   ← Paginated conversations (500 messages/page)
├── calls.html              ← Full call log (audio + video)
├── deleted.html            ← All non-LIVE records across every chat
├── gallery.html            ← Media references and thumbnails
├── carve-results.json      ← Machine-readable output for scripting / ingestion
└── manifest.json           ← Report metadata and generation parameters
```

Reports are static HTML — no JavaScript dependencies, no external resources. They can be opened offline, archived, printed, or attached to legal filings.

---

## Evidence Tags

Every message and call record carries a provenance tag:

| Tag | Layer | Meaning |
|-----|-------|---------|
| `[LIVE]` | 1 | Present in the active B-tree |
| `[WAL-PENDING]` | 2 | In WAL, not yet checkpointed to main database |
| `[WAL-DELETED]` | 3 | Present in main database but removed by WAL transaction |
| `[WAL-HISTORIC]` | 3 | In WAL but superseded by a later frame |
| `[FREELIST]` | 4 | On a freelist page — deleted but space not yet reused |
| `[FTS-ONLY]` | 5 | In WhatsApp's search index but absent from message table |
| `[CARVED-INTRA-PAGE 87%]` | 6 | Found in intra-page gap with 87% confidence |
| `[JOURNAL]` | 7 | Recovered from rollback journal pre-modification snapshot |
| `[CARVED-UNALLOC 94%]` | 8 | Carved from unallocated space with 94% confidence |
| `[CARVED-DB]` | 8 | From a database reconstructed from unallocated space |

---

## Limitations

- **Android focus.** iOS backup support is functional but less mature than Android.
- **WhatsApp only.** Signal and Telegram plugins are scaffolded but not yet implemented.
- **Encrypted databases** require the original key file. `chat4n6` does not perform key recovery.
- **Recovery depends on timing.** Records overwritten before acquisition cannot be recovered by any tool.
- **Carved records are probabilistic.** Confidence scores reflect schema pattern match quality, not semantic correctness. False positives are possible, particularly below 80% confidence. Triage findings should be validated by a qualified examiner before being presented as evidence.

---

## Building from Source

```bash
git clone https://github.com/SecurityRonin/chat4n6.git
cd chat4n6
cargo build --release
./target/release/chat4n6 --help
```

No system dependencies. Pure Rust — no SQLite C library, no Python, no JVM.

Requires Rust 1.75 or later ([rustup.rs](https://rustup.rs)).

**Pre-built binaries** for Windows are available from [GitHub Actions artifacts](https://github.com/SecurityRonin/chat4n6/actions) (latest `build-windows` run).

---

## Test Coverage

573 tests across the workspace. The SQLite forensics engine (`chat4n6-sqlite-forensics`) has 98.77% line coverage and 99.51% function coverage across 22 source modules. Remaining uncovered lines are provably unreachable defensive guards.

```bash
cargo test                    # Run all tests
cargo llvm-cov test           # Run with coverage report (requires cargo-llvm-cov)
```

---

## Contributing

Issues and pull requests welcome. See `docs/` for design specs and implementation plans.

---

## License

MIT — see [LICENSE](LICENSE).
