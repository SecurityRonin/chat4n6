# chat4n6-sqlite-forensics

Zero-copy SQLite forensics library for the
[chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

Recovers deleted records from SQLite databases without requiring the SQLite C
library — everything is implemented in pure Rust against raw bytes.

## Recovery layers

| Layer | Source | What it finds |
|---|---|---|
| 1 | Live B-tree pages | Current records |
| 2 | WAL pending frames | Uncommitted changes |
| 3 | WAL historic frames | Previously checkpointed frames (modifications/deletions) |
| 4 | Freelist pages | Deleted records whose pages haven't been reused |
| 5 | FTS shadow tables | Messages deleted after being indexed for search |
| 6 | Unallocated space carving | Records from pages that were overwritten |

Carved records include a confidence score derived from statistical analysis of
live-record serial type patterns — useful when presenting carved evidence.

## Crates in this workspace

| Crate | Description |
|---|---|
| `chat4n6-plugin-api` | Shared types and plugin trait |
| `chat4n6-core` | DAR archive parser and filesystem abstraction |
| `chat4n6-sqlite-forensics` | This crate |
| `chat4n6-whatsapp` | WhatsApp extraction plugin |
| `chat4n6-report` | HTML report generator |
| `chat4n6` | CLI — `cargo install chat4n6` |

## License

MIT
