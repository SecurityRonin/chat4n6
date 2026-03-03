# chat4n6-report

HTML report generator for the
[chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

Takes an `ExtractionResult` (from any `ForensicPlugin`) and renders a
self-contained, paginated HTML report — no JavaScript, no external dependencies,
court-ready out of the box.

Templates are embedded in the binary at compile time via `rust-embed`, so there
are no runtime file path dependencies.

## Output

```
report/
├── index.html              ← Case dashboard: chat list, counts, evidence summary
├── chat_<id>_<page>.html   ← Paginated conversation views (500 messages/page)
├── calls.html              ← Full call log
├── deleted.html            ← All non-LIVE records across every chat
└── carve-results.json      ← Machine-readable output
```

## Crates in this workspace

| Crate | Description |
|---|---|
| `chat4n6-plugin-api` | Shared types and plugin trait |
| `chat4n6-core` | DAR archive parser and filesystem abstraction |
| `chat4n6-sqlite-forensics` | Zero-copy SQLite forensics: B-tree, WAL, FTS, freelist |
| `chat4n6-whatsapp` | WhatsApp extraction plugin |
| `chat4n6-report` | This crate |
| `chat4n6` | CLI — `cargo install chat4n6` |

## License

MIT
