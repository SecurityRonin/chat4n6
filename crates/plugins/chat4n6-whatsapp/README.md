# chat4n6-whatsapp

WhatsApp forensic extraction plugin for the
[chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

Implements the `ForensicPlugin` trait to extract WhatsApp artifacts from an
Android filesystem image, using `chat4n6-sqlite-forensics` for deep database
recovery.

## What it recovers

**Messages** — text, media references, contact cards, location shares, system
messages, and deleted messages — from six recovery layers:

| Layer | Source |
|---|---|
| Live | Active `msgstore.db` records |
| WAL pending | Uncommitted WAL frames |
| WAL historic | Previously checkpointed frames |
| Freelist | Freed pages not yet reused |
| FTS shadow | Search index (deleted-after-search) |
| Carved unalloc | Raw carving with confidence scoring |

**Calls** — direction, type (audio/video), duration, group calls, timestamps.

**Encryption** — supports crypt14 and crypt15 backup databases when a key file
is provided.

**Schema versions** — handles both legacy and modern WhatsApp database schemas.

## Crates in this workspace

| Crate | Description |
|---|---|
| `chat4n6-plugin-api` | Shared types and plugin trait |
| `chat4n6-core` | DAR archive parser and filesystem abstraction |
| `chat4n6-sqlite-forensics` | Zero-copy SQLite forensics: B-tree, WAL, FTS, freelist |
| `chat4n6-whatsapp` | This crate |
| `chat4n6-report` | HTML report generator |
| `chat4n6` | CLI — `cargo install chat4n6` |

## License

MIT
