# chat4n6-core

DAR archive parser and filesystem abstraction layer for the
[chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

Provides:

- **`DarFs`** — mmap-based parser for DAR v8/v9 archives produced by Passware Kit Mobile,
  exposing the Android filesystem (including unallocated space) through the `ForensicFs` trait
- **`PlaintextDirFs`** — wraps a plaintext directory tree with path-traversal protection,
  for cases where the filesystem has already been extracted

Both implementations satisfy the `ForensicFs` trait from `chat4n6-plugin-api`, so
forensic plugins work identically against either source.

## Crates in this workspace

| Crate | Description |
|---|---|
| `chat4n6-plugin-api` | Shared types and plugin trait |
| `chat4n6-core` | This crate |
| `chat4n6-sqlite-forensics` | Zero-copy SQLite forensics: B-tree, WAL, FTS, freelist |
| `chat4n6-whatsapp` | WhatsApp extraction plugin |
| `chat4n6-report` | HTML report generator |
| `chat4n6` | CLI — `cargo install chat4n6` |

## License

MIT
