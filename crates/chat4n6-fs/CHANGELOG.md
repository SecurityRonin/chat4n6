# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/SecurityRonin/chat4n6/compare/chat4n6-fs-v0.1.2...chat4n6-fs-v0.1.3) - 2026-09-03

### Added

- *(chat4n6-fs)* add IosBackupFs ForensicFs adapter
- *(chat4n6-fs)* add DarFs ForensicFs adapter
- *(chat4n6-fs)* bootstrap crate, migrate PlaintextDirFs

### Fixed

- IosBackupFs flat list, file_id guard, dir read guard, deprecation fix
- *(chat4n6-fs)* normalize trailing slash in DarFs::list, add prefix logic test
