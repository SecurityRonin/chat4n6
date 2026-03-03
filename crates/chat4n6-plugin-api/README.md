# chat4n6-plugin-api

Shared types and traits for the [chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

This crate defines the plugin contract — the `ForensicPlugin` trait and all shared
data types (`Chat`, `Message`, `CallRecord`, `ExtractionResult`, `EvidenceSource`,
etc.) — used by both the forensic plugins and the report generator.

## Crates in this workspace

| Crate | Description |
|---|---|
| `chat4n6-plugin-api` | This crate — shared types and plugin trait |
| `chat4n6-core` | DAR archive parser and filesystem abstraction |
| `chat4n6-sqlite-forensics` | Zero-copy SQLite forensics: B-tree, WAL, FTS, freelist |
| `chat4n6-whatsapp` | WhatsApp extraction plugin |
| `chat4n6-report` | HTML report generator |
| `chat4n6` | CLI — `cargo install chat4n6` |

## License

MIT
