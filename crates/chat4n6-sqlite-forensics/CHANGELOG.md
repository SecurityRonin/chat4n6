# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-sqlite-forensics-v0.1.1...chat4n6-sqlite-forensics-v0.1.3) - 2026-09-03

### Added

- complete ralph loop — all user stories passing (1024 tests)
- integrate freeblock, WAL classification, ROWID gaps into recover_all()
- verify.rs — verification report with hex offsets and shell commands
- rowid_gap.rs — ROWID gap detection for deletion evidence
- wal_enhanced.rs — WAL frame classification and WAL-only table detection
- freeblock.rs — varint brute-force deleted record recovery (bring2lite Algorithm 3)
- page_map.rs — page-to-table ownership mapping (bring2lite Algorithm 2)
- add pragma.rs (PragmaInfo, viability_report) and context.rs (RecoveryContext)
- recover_all() orchestrator with RecoveryStats and deduplication
- rollback journal parsing with multi-section support (Layer 8)
- overflow page chain following for large record reassembly (Layer 4)
- freelist page content recovery with B-tree parse + schema carving (Layer 3)
- WAL replay with page overlay and differential analysis (Layer 2 enhanced)
- add intra-page gap scanning for deleted record recovery (Layer 7)
- add SHA-256 record deduplication (Sanderson-style)
- add SchemaSignature with Boyer-Moore search and plausibility checks (FQLite-style)

### Other

- DRY, debuggability, maintainability across all crates
- recover_all() uses RecoveryContext with pragma-aware layer skipping
- add RecoveryContext-aware wrappers for all recovery layers
