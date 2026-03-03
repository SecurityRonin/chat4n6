# chat4n6

> Deleted WhatsApp messages aren't always gone. chat4n6 finds them.

When a suspect deletes a WhatsApp message, the data rarely disappears immediately.
It lingers in SQLite freelists, write-ahead logs, the in-app search index, and
unallocated disk space — often intact and recoverable, if you know where to look.

`chat4n6` is a free, open-source command-line tool that systematically recovers
this evidence from Android filesystem images. It goes six layers deep into each
WhatsApp database, surfaces every recoverable artifact, tags each record with its
evidence source, and produces a paginated HTML report ready for review or court
presentation.

---

## Installation

**Linux / macOS** — requires Rust 1.75 or later ([rustup.rs](https://rustup.rs)):

```bash
cargo install chat4n6
```

**Windows** — download the pre-built binary from the
[GitHub Actions artifacts](https://github.com/SecurityRonin/chat4n6/actions)
(latest `build-windows` run → `chat4n6-windows-x86_64`).

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
| Schema version history (ALTER TABLE) | No | Yes |

Every recovered record is tagged with its evidence source (`[LIVE]`, `[WAL-PENDING]`,
`[FREELIST]`, `[FTS-ONLY]`, `[CARVED-UNALLOC]`, etc.) and carved records include a
confidence percentage derived from live-record signature learning.

Reports are paginated HTML — no JavaScript, no external dependencies, court-ready
out of the box.

---

## Quick Start

```bash
# Run full analysis on a plaintext Android filesystem tree
chat4n6 run --input /path/to/android/root --output ./case001-report

# With timezone (accepts offset or IANA name)
chat4n6 run \
  --input /path/to/android/root \
  --output ./case001-report \
  --case-name "Case 2025-001" \
  --timezone "Asia/Manila"

# Skip unallocated space carving (faster, still runs layers 1–5)
chat4n6 run --input /path/to/android/root --output ./report --no-unalloc
```

---

## What You Get

```
case001-report/
├── index.html              ← Case dashboard: chat list, counts, evidence summary
├── chat_<id>_<page>.html   ← Paginated conversation views (500 messages/page)
├── calls.html              ← Full call log (audio + video)
├── deleted.html            ← All non-LIVE records across every chat
└── carve-results.json      ← Machine-readable output for scripting
```

---

## Evidence Tags

| Tag | Meaning |
|---|---|
| `[LIVE]` | Present in the active database |
| `[WAL-PENDING]` | In the WAL file, not yet written to main DB |
| `[WAL-HISTORIC]` | Was in the WAL but superseded — indicates modification or deletion |
| `[FREELIST]` | Recovered from SQLite freelist (deleted but space not reused) |
| `[FTS-ONLY]` | In WhatsApp's search index but deleted from message table |
| `[CARVED-UNALLOC]` | Carved from unallocated space — includes confidence % |
| `[CARVED-DB]` | From a database reconstructed from unallocated space |

---

## Limitations

- **MVP:** Android only. iOS support is planned.
- **MVP:** WhatsApp only. Signal and Telegram support is planned.
- **Encrypted backups** require the original key file. `chat4n6` does not brute-force keys.

---

## License

MIT — see [LICENSE](https://github.com/SecurityRonin/chat4n6/blob/main/LICENSE).
