# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-v0.1.1...chat4n6-v0.1.3) - 2026-09-03

### Added

- *(report)* GREEN — §2.4 media export pipeline + --export-media CLI flag
- *(ios-whatsapp)* GREEN — §2.1 pushname resolution, ZWACALLEVENT, CoreDataPkGap
- *(whatsapp)* §2.6 DuplicateStanzaId + ThumbnailOrphanHigh + RowIdReuseDetected detectors
- *(GREEN)* nested chat layout — chats/chat_{id}_{name}/page_{NNN}.html
- *(GREEN)* report subcommand, --page-size, --plugin flag
- dar-archive v9 catalog, Signal/Telegram scaffolds, WhatsApp enhancements, report templates
- *(cli)* auto-detect dar/ios-backup/plaintext input, dissolve chat4n6-core

### Fixed

- *(O9)* merge_results drops forensic_warnings and group_participant_events
- IosBackupFs flat list, file_id guard, dir read guard, deprecation fix
- *(cli)* actionable error when --input is a DAR file or plain file

### Other

- DRY, debuggability, maintainability across all crates
- *(O3)* registered_plugins() factory — single-line platform additions
- remove --plugin flag (YAGNI)
