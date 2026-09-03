# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-report-v0.1.1...chat4n6-report-v0.1.3) - 2026-09-03

### Added

- *(green)* self-contained viewer embeds media as base64 data URIs
- *(report)* GREEN — §2.4 media export pipeline + --export-media CLI flag
- *(report)* GREEN — §2.2 stats/analytics page (stats.html + stats.json)
- *(report)* GREEN — §2.3 WAL snapshot timeline (snapshots.html)
- *(types)* GREEN — v2 data model: WalSnapshot, ForwardOrigin, 9 new ForensicWarning variants
- *(GREEN)* forwarded message badges in chat pages
- *(GREEN)* phone number obfuscation via with_obfuscate(true)
- *(GREEN)* timeline.html cross-chat chronological view
- *(GREEN)* forensic warnings banner in index.html
- *(GREEN)* root_href nav prefix and WAL delta rows in deleted.html
- *(GREEN)* nested chat layout — chats/chat_{id}_{name}/page_{NNN}.html
- *(GREEN)* report subcommand, --page-size, --plugin flag
- complete ralph loop — all user stories passing (1024 tests)
- merge ralph-1 (C7/C8) + ralph-2 (Telegram) + GhostRecovered match arms
- CASE/UCO JSON-LD + thread-view HTML — 23 new tests pass
- new evidence types — ViewOnce, EditHistoryEntry, MessageReceipt, GroupParticipantEvent, ForensicWarning; Message.starred/forwarded/edit_history/receipts, Chat.archived, ExtractionResult.forensic_warnings/group_participant_events (911 tests pass)
- dar-archive v9 catalog, Signal/Telegram scaffolds, WhatsApp enhancements, report templates
- add WalDeleted, Journal, IndexRecovery, CarvedIntraPage, CarvedOverflow evidence source variants

### Fixed

- update chat4n6-report test fixtures for expanded MediaRef and CallRecord fields

### Other

- DRY, debuggability, maintainability across all crates
