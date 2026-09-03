# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-whatsapp-v0.1.1...chat4n6-whatsapp-v0.1.3) - 2026-09-03

### Added

- *(whatsapp-android)* GREEN — msg_type_label, edit_version delete semantics, bounds-check
- *(types)* GREEN — v2 data model: WalSnapshot, ForwardOrigin, 9 new ForensicWarning variants
- *(GREEN)* timezone autodetect from data/property/persist.sys.timezone
- complete ralph loop — all user stories passing (1024 tests)
- *(GREEN)* implement detect_header_tamper and extract_fts5_content
- dar-archive v9 catalog, Signal/Telegram scaffolds, WhatsApp enhancements, report templates

### Fixed

- *(green)* make extraction output deterministic (total chat/message order)
- *(green)* resolve msgstore columns by name, not hardcoded ordinals
- add tbl helper to signal and android-whatsapp extractors, fix confidence field

### Other

- *(whatsapp)* move type helpers to schema.rs, add named column constants
- *(whatsapp)* add tbl helper and replace all by_table.get patterns
- DRY, debuggability, maintainability across all crates
