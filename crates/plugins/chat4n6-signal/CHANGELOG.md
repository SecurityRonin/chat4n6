# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-signal-v0.1.2...chat4n6-signal-v0.1.3) - 2026-09-03

### Added

- *(signal)* GREEN — fix direction heuristic, reaction layout, attachment table, timestamp priority
- *(signal)* GREEN — DisappearingTimerActive + SealedSenderUnresolved detectors
- *(types)* GREEN — v2 data model: WalSnapshot, ForwardOrigin, 9 new ForensicWarning variants
- Signal Android — sms/thread/recipient/reaction/call extraction, 19 tests pass
- dar-archive v9 catalog, Signal/Telegram scaffolds, WhatsApp enhancements, report templates

### Fixed

- add tbl helper to signal and android-whatsapp extractors, fix confidence field

### Other

- *(signal)* GREEN — replace tbl call sites, add helpers::cols constants
- DRY, debuggability, maintainability across all crates
