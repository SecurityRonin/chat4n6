use crate::header::DbHeader;

/// Whether SECURE_DELETE is enabled.
#[derive(Debug, Clone, PartialEq)]
pub enum SecureDeleteMode {
    Off,
    On,
    Fast,
}

impl Default for SecureDeleteMode {
    fn default() -> Self {
        SecureDeleteMode::Off
    }
}

/// Auto-vacuum mode.
#[derive(Debug, Clone, PartialEq)]
pub enum AutoVacuumMode {
    None,
    Full,
    Incremental,
}

impl Default for AutoVacuumMode {
    fn default() -> Self {
        AutoVacuumMode::None
    }
}

/// Journal mode relevant to forensics.
#[derive(Debug, Clone, PartialEq)]
pub enum JournalMode {
    Wal,
    NonWal,
}

impl Default for JournalMode {
    fn default() -> Self {
        JournalMode::NonWal
    }
}

/// Text encoding used by the database.
#[derive(Debug, Clone, PartialEq)]
pub enum TextEncoding {
    Utf8,
    Utf16le,
    Utf16be,
}

impl Default for TextEncoding {
    fn default() -> Self {
        TextEncoding::Utf8
    }
}

/// Parsed pragma-equivalent values from the SQLite header.
#[derive(Debug, Clone)]
pub struct PragmaInfo {
    pub secure_delete: SecureDeleteMode,
    pub auto_vacuum: AutoVacuumMode,
    pub journal_mode: JournalMode,
    pub text_encoding: TextEncoding,
    pub schema_format: u32,
    pub user_version: u32,
}

impl Default for PragmaInfo {
    fn default() -> Self {
        PragmaInfo {
            secure_delete: SecureDeleteMode::default(),
            auto_vacuum: AutoVacuumMode::default(),
            journal_mode: JournalMode::default(),
            text_encoding: TextEncoding::default(),
            schema_format: 0,
            user_version: 0,
        }
    }
}

/// A single entry in a viability report.
#[derive(Debug, Clone)]
pub struct ViabilityEntry {
    pub layer: String,
    pub viable: bool,
    pub explanation: String,
}

/// Parse pragma-equivalent information from a raw SQLite database byte slice.
///
/// Reads values from fixed header offsets (SQLite file format spec §1.3):
/// - Offset 18-19: write/read version (both == 2 → WAL mode)
/// - Offset 44:    schema format number
/// - Offset 52:    auto-vacuum enabled flag
/// - Offset 56:    text encoding (1=UTF-8, 2=UTF-16le, 3=UTF-16be)
/// - Offset 60:    user version
/// - Offset 64:    incremental vacuum flag
///
/// `secure_delete` is always `Off` because it is a run-time-only setting
/// that is not stored in the file header.
pub fn parse_pragma_info(_header: &DbHeader, db: &[u8]) -> PragmaInfo {
    if db.len() < 100 {
        return PragmaInfo::default();
    }

    let text_encoding = match u32::from_be_bytes([db[56], db[57], db[58], db[59]]) {
        2 => TextEncoding::Utf16le,
        3 => TextEncoding::Utf16be,
        _ => TextEncoding::Utf8,
    };

    let user_version = u32::from_be_bytes([db[60], db[61], db[62], db[63]]);

    let schema_format = u32::from_be_bytes([db[44], db[45], db[46], db[47]]);

    let av_enabled = u32::from_be_bytes([db[52], db[53], db[54], db[55]]);
    let av_incr = u32::from_be_bytes([db[64], db[65], db[66], db[67]]);
    let auto_vacuum = if av_enabled == 0 {
        AutoVacuumMode::None
    } else if av_incr == 0 {
        AutoVacuumMode::Full
    } else {
        AutoVacuumMode::Incremental
    };

    // WAL mode: write version (offset 18) and read version (offset 19) both == 2
    let journal_mode = if db[18] == 2 && db[19] == 2 {
        JournalMode::Wal
    } else {
        JournalMode::NonWal
    };

    PragmaInfo {
        secure_delete: SecureDeleteMode::Off,
        auto_vacuum,
        journal_mode,
        text_encoding,
        schema_format,
        user_version,
    }
}

/// Generate a viability report for each recovery layer given pragma settings.
pub fn viability_report(info: &PragmaInfo) -> Vec<ViabilityEntry> {
    vec![
        ViabilityEntry {
            layer: "Live B-tree".to_string(),
            viable: true,
            explanation: "Always viable: reads committed data from the live B-tree.".to_string(),
        },
        ViabilityEntry {
            layer: "WAL replay".to_string(),
            viable: info.journal_mode == JournalMode::Wal,
            explanation: if info.journal_mode == JournalMode::Wal {
                "WAL mode active: uncommitted frames may be recoverable.".to_string()
            } else {
                "WAL mode not active: no WAL file to replay.".to_string()
            },
        },
        ViabilityEntry {
            layer: "Freelist content".to_string(),
            viable: info.auto_vacuum != AutoVacuumMode::Full,
            explanation: if info.auto_vacuum == AutoVacuumMode::Full {
                "Auto-vacuum (Full) reclaims freelist pages immediately; content likely zeroed."
                    .to_string()
            } else {
                "Freelist pages retained; deleted content may be present.".to_string()
            },
        },
        ViabilityEntry {
            layer: "Freeblock recovery".to_string(),
            viable: info.secure_delete == SecureDeleteMode::Off,
            explanation: if info.secure_delete != SecureDeleteMode::Off {
                "Secure-delete zeros freeblocks; recovery not viable.".to_string()
            } else {
                "Freeblocks not zeroed; deleted cell data may be recoverable.".to_string()
            },
        },
        ViabilityEntry {
            layer: "Intra-page gap scanning".to_string(),
            viable: info.secure_delete == SecureDeleteMode::Off,
            explanation: if info.secure_delete != SecureDeleteMode::Off {
                "Secure-delete zeros gap regions; scanning not viable.".to_string()
            } else {
                "Gap regions not zeroed; residual data may be present.".to_string()
            },
        },
        ViabilityEntry {
            layer: "FTS shadow tables".to_string(),
            viable: true,
            explanation: "FTS shadow tables are independent of pragma settings.".to_string(),
        },
        ViabilityEntry {
            layer: "Journal".to_string(),
            viable: info.journal_mode == JournalMode::NonWal,
            explanation: if info.journal_mode == JournalMode::NonWal {
                "Non-WAL mode: a rollback journal may exist with prior page images.".to_string()
            } else {
                "WAL mode active: no rollback journal is written.".to_string()
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DbHeader;

    fn make_test_header_bytes(overrides: &[(usize, &[u8])]) -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // page_size = 4096
        buf[18] = 1; // write version
        buf[19] = 1; // read version
        buf[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        for (offset, bytes) in overrides {
            buf[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        buf
    }

    fn header_from_bytes(buf: &[u8]) -> DbHeader {
        DbHeader::parse(buf).expect("valid header bytes")
    }

    #[test]
    fn test_default_pragma_parsing() {
        let buf = make_test_header_bytes(&[]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.secure_delete, SecureDeleteMode::Off);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::None);
        assert_eq!(info.journal_mode, JournalMode::NonWal);
        assert_eq!(info.text_encoding, TextEncoding::Utf8);
        assert_eq!(info.user_version, 0);
    }

    #[test]
    fn test_wal_mode_detection() {
        let buf = make_test_header_bytes(&[
            (18, &[2u8]),
            (19, &[2u8]),
        ]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.journal_mode, JournalMode::Wal);
    }

    #[test]
    fn test_auto_vacuum_full() {
        // offset 52 non-zero (enabled), offset 64 = 0 (Full)
        let buf = make_test_header_bytes(&[
            (52, &1u32.to_be_bytes()),
            (64, &0u32.to_be_bytes()),
        ]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::Full);
    }

    #[test]
    fn test_auto_vacuum_incremental() {
        // offset 52 non-zero (enabled), offset 64 non-zero (Incremental)
        let buf = make_test_header_bytes(&[
            (52, &1u32.to_be_bytes()),
            (64, &1u32.to_be_bytes()),
        ]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::Incremental);
    }

    #[test]
    fn test_utf16le_detection() {
        let buf = make_test_header_bytes(&[(56, &2u32.to_be_bytes())]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.text_encoding, TextEncoding::Utf16le);
    }

    #[test]
    fn test_utf16be_detection() {
        let buf = make_test_header_bytes(&[(56, &3u32.to_be_bytes())]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.text_encoding, TextEncoding::Utf16be);
    }

    #[test]
    fn test_user_version_parsing() {
        let buf = make_test_header_bytes(&[(60, &42u32.to_be_bytes())]);
        let hdr = header_from_bytes(&buf);
        let info = parse_pragma_info(&hdr, &buf);
        assert_eq!(info.user_version, 42);
    }

    #[test]
    fn test_too_short_returns_default() {
        // Provide a valid-looking header but too short to fully parse
        let buf = vec![0u8; 50];
        let info = parse_pragma_info(
            // We need a DbHeader; borrow a real one from a valid buf for the fn signature
            &DbHeader::parse(&make_test_header_bytes(&[])).unwrap(),
            &buf,
        );
        assert_eq!(info.secure_delete, SecureDeleteMode::Off);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::None);
        assert_eq!(info.journal_mode, JournalMode::NonWal);
        assert_eq!(info.text_encoding, TextEncoding::Utf8);
        assert_eq!(info.user_version, 0);
    }

    // --- viability report tests ---

    #[test]
    fn test_viability_default() {
        let info = PragmaInfo::default();
        let report = viability_report(&info);
        let map: std::collections::HashMap<_, _> =
            report.iter().map(|e| (e.layer.as_str(), e.viable)).collect();
        assert!(map["Live B-tree"]);
        assert!(!map["WAL replay"]);
        assert!(map["Freelist content"]);
        assert!(map["Freeblock recovery"]);
        assert!(map["Intra-page gap scanning"]);
        assert!(map["FTS shadow tables"]);
        assert!(map["Journal"]);
    }

    #[test]
    fn test_viability_auto_vacuum_full() {
        let info = PragmaInfo {
            auto_vacuum: AutoVacuumMode::Full,
            ..Default::default()
        };
        let report = viability_report(&info);
        let map: std::collections::HashMap<_, _> =
            report.iter().map(|e| (e.layer.as_str(), e.viable)).collect();
        assert!(!map["Freelist content"]);
        assert!(map["Freeblock recovery"]);
    }

    #[test]
    fn test_viability_secure_delete_on() {
        let info = PragmaInfo {
            secure_delete: SecureDeleteMode::On,
            ..Default::default()
        };
        let report = viability_report(&info);
        let map: std::collections::HashMap<_, _> =
            report.iter().map(|e| (e.layer.as_str(), e.viable)).collect();
        assert!(!map["Freeblock recovery"]);
        assert!(!map["Intra-page gap scanning"]);
        assert!(map["Live B-tree"]);
    }

    #[test]
    fn test_viability_wal_mode() {
        let info = PragmaInfo {
            journal_mode: JournalMode::Wal,
            ..Default::default()
        };
        let report = viability_report(&info);
        let map: std::collections::HashMap<_, _> =
            report.iter().map(|e| (e.layer.as_str(), e.viable)).collect();
        assert!(map["WAL replay"]);
        assert!(!map["Journal"]);
    }

    #[test]
    fn test_real_db_parse() {
        use rusqlite::Connection;
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 7; CREATE TABLE t (x INTEGER);",
            )
            .unwrap();
        }
        let db_bytes = std::fs::read(&path).unwrap();
        let hdr = DbHeader::parse(&db_bytes).expect("valid db header");
        let info = parse_pragma_info(&hdr, &db_bytes);
        assert_eq!(info.user_version, 7);
        assert_eq!(info.text_encoding, TextEncoding::Utf8);
        assert_eq!(info.journal_mode, JournalMode::NonWal);
        assert_eq!(info.auto_vacuum, AutoVacuumMode::None);
        assert_eq!(info.secure_delete, SecureDeleteMode::Off);
    }
}
