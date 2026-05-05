# chat4n6 Agent Guidelines

## Project

Rust workspace for forensic extraction of mobile messaging apps (WhatsApp, Signal, Telegram, iOS).
Target audience: incident responders, digital forensics examiners, legal review.

## Architecture

```
crates/
  chat4n6-plugin-api/        — shared types (Message, Chat, ExtractionResult, …)
  chat4n6-sqlite-forensics/  — ForensicEngine (btree walker, WAL, freelist recovery)
  chat4n6-report/            — HTML thread-view, CASE/UCO JSON-LD, PDF signing
  plugins/
    chat4n6-whatsapp/        — Android WhatsApp (msgstore.db)
    chat4n6-ios-whatsapp/    — iOS WhatsApp (ChatStorage.sqlite / CoreData)
    chat4n6-signal/          — Signal Android
    chat4n6-telegram/        — Telegram (cache.db / TDLib format)
  chat4n6-cli/               — CLI entry point
fuzz/                        — cargo-fuzz targets
docs/user-stories/           — Ralph story JSON files
```

## Mandatory TDD

Every feature requires two separate git commits:
1. **RED**: failing tests only (`cargo test` confirms failure). Message: `test(red): <description> (N tests fail)`
2. **GREEN**: implementation that makes tests pass. Message: `feat(green): <description>` or `fix(green): <description>`

Never mix tests and implementation in one commit.

## Commit Signing

All commits: `git -c commit.gpgsign=false commit -m "..."`

## ForensicEngine API

```rust
ForensicEngine::new(db_bytes: &[u8], Some(tz_offset_secs)) -> Result<Self>
engine.recover_layer1() -> Result<Vec<RecoveredRecord>>

RecoveredRecord { table: String, row_id: Option<i64>, values: Vec<SqlValue>, source: EvidenceSource, offset: u64 }
SqlValue::{Null, Int(i64), Real(f64), Text(String), Blob(Vec<u8>)}
EvidenceSource::{Live, WalHistoric, Freelist, CarvedUnalloc, Overflow}
```

`values[0]` is always `Null` (INTEGER PRIMARY KEY alias). Real columns start at `values[1]`.

## Test Patterns

- Tests use `rusqlite` + `tempfile` to build in-memory SQLite DBs from fixtures
- Fixture SQL lives in `tests/fixtures/*.sql`
- `extract_from_msgstore(&db_bytes, 0, SchemaVersion::Modern)` is the main entry point
- `proptest!` for property-based tests (add to existing proptest module, not new one)

## Coding Rules

- No `unwrap()` in production code — use `?` and `anyhow::Context`
- No `clippy::allow` suppression without comment explaining why
- No feature flags — just implement it
- Prefer extending existing functions over adding new pub functions
- Column indices in comments: `values[N] = column_name`
- SQLite header bytes: page_size at offset 16 (big-endian u16), free_page_count at offset 36 (big-endian u32)
- WhatsApp timestamp: milliseconds since Unix epoch
- iOS timestamp: seconds since 2001-01-01 (Apple epoch); convert: `(secs + 978307200.0) * 1000.0`

## Story Lifecycle

When a story is implemented and verified: set `"passes": true` in the JSON file and commit the change.
