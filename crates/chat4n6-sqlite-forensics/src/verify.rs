use crate::context::RecoveryContext;
use crate::db::{RecoveryResult, RecoveryStats};
use crate::pragma::{viability_report, ViabilityEntry};
use crate::record::RecoveredRecord;
use crate::rowid_gap::RowidGap;
use chat4n6_plugin_api::EvidenceSource;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct VerifiableFinding {
    pub record: RecoveredRecord,
    pub page_number: u32,
    pub byte_offset: usize,
    pub hex_context: String,
    pub recovery_technique: String,
    pub verification_command: String,
    pub cross_validation: Option<String>,
}

#[derive(Debug)]
pub struct VerificationReport {
    pub evidence_hash: String,
    pub wal_hash: Option<String>,
    pub journal_hash: Option<String>,
    pub tool_version: String,
    pub viability: Vec<ViabilityEntry>,
    pub findings: Vec<VerifiableFinding>,
    pub rowid_gaps: Vec<RowidGap>,
    pub stats: RecoveryStats,
    pub benchmark_score: Option<f64>,
}

pub fn build_verification_report(
    ctx: &RecoveryContext,
    result: &RecoveryResult,
) -> VerificationReport {
    // 1. SHA-256 hash of ctx.db
    let evidence_hash = {
        let mut hasher = Sha256::new();
        hasher.update(ctx.db);
        format!("{:x}", hasher.finalize())
    };

    // 2. Build findings for each record
    let findings: Vec<VerifiableFinding> = result
        .records
        .iter()
        .map(|record| {
            let page_number = if record.offset > 0 {
                (record.offset as u32 / ctx.page_size) + 1
            } else {
                0
            };

            let byte_offset = record.offset as usize;

            // Extract 32 bytes of hex context around the finding
            let hex_start = byte_offset.saturating_sub(16);
            let hex_end = (byte_offset + 16).min(ctx.db.len());
            let hex_context = if hex_start < ctx.db.len() {
                ctx.db[hex_start..hex_end]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            };

            let recovery_technique = match record.source {
                EvidenceSource::Live => "B-tree traversal (live record)".to_string(),
                EvidenceSource::WalPending => "WAL replay (pending transaction)".to_string(),
                EvidenceSource::WalDeleted => "WAL analysis (deleted in WAL)".to_string(),
                EvidenceSource::Freelist => "Freelist/freeblock recovery".to_string(),
                EvidenceSource::CarvedUnalloc { .. }
                | EvidenceSource::CarvedIntraPage { .. }
                | EvidenceSource::CarvedOverflow
                | EvidenceSource::CarvedDb => "Heuristic carving".to_string(),
                EvidenceSource::Journal => "Rollback journal parsing".to_string(),
                _ => format!("{:?}", record.source),
            };

            let verification_command = match record.source {
                EvidenceSource::Live => {
                    if let Some(rid) = record.row_id {
                        format!(
                            "sqlite3 evidence.db \"SELECT * FROM {} WHERE rowid={}\"",
                            record.table, rid
                        )
                    } else {
                        format!("xxd -s {} -l 64 evidence.db", byte_offset)
                    }
                }
                _ => format!("xxd -s {} -l 64 evidence.db", byte_offset),
            };

            VerifiableFinding {
                record: record.clone(),
                page_number,
                byte_offset,
                hex_context,
                recovery_technique,
                verification_command,
                cross_validation: None,
            }
        })
        .collect();

    // 3. Viability assessment
    let viability = viability_report(&ctx.pragma_info);

    VerificationReport {
        evidence_hash,
        wal_hash: None,
        journal_hash: None,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        viability,
        findings,
        rowid_gaps: Vec::new(),
        stats: RecoveryStats::default(),
        benchmark_score: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DbHeader;
    use crate::pragma::{parse_pragma_info, PragmaInfo};
    use crate::record::SqlValue;
    use std::collections::HashMap;

    fn make_minimal_db() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // page_size bytes[16..17] = 0x1000 → 4096
        buf[17] = 0x00;
        buf[18] = 1;
        buf[19] = 1;
        buf[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        buf
    }

    /// Returns (db_bytes, header) so the caller can build a RecoveryContext
    /// with explicit lifetimes.
    fn make_db_and_header() -> (Vec<u8>, DbHeader) {
        let db = make_minimal_db();
        let header = DbHeader::parse(&db).expect("valid header");
        (db, header)
    }

    fn make_result(records: Vec<RecoveredRecord>) -> RecoveryResult {
        RecoveryResult {
            records,
            stats: RecoveryStats::default(),
        }
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;
        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info: pragma_info.clone(),
        };

        let result = make_result(vec![]);
        let report1 = build_verification_report(&ctx, &result);

        // Rebuild ctx (same data)
        let ctx2 = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };
        let report2 = build_verification_report(&ctx2, &result);

        assert_eq!(report1.evidence_hash, report2.evidence_hash);
        assert_eq!(report1.evidence_hash.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_live_record_verification_command() {
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;
        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "messages".to_string(),
            row_id: Some(42),
            values: vec![SqlValue::Int(1)],
            source: EvidenceSource::Live,
            offset: 128,
            confidence: 1.0,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert!(
            finding.verification_command.contains("sqlite3"),
            "Live record should use sqlite3 command: {}",
            finding.verification_command
        );
        assert!(
            finding.verification_command.contains("rowid=42"),
            "Command should reference rowid=42: {}",
            finding.verification_command
        );
    }

    #[test]
    fn test_carved_record_verification_command() {
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;
        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "messages".to_string(),
            row_id: None,
            values: vec![SqlValue::Text("hello".to_string())],
            source: EvidenceSource::CarvedUnalloc { confidence_pct: 80 },
            offset: 512,
            confidence: 0.8,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert!(
            finding.verification_command.starts_with("xxd"),
            "Carved record should use xxd command: {}",
            finding.verification_command
        );
        assert!(
            finding.verification_command.contains("512"),
            "xxd command should contain the byte offset: {}",
            finding.verification_command
        );
        assert_eq!(finding.recovery_technique, "Heuristic carving");
    }

    #[test]
    fn test_empty_result() {
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;
        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let result = make_result(vec![]);
        let report = build_verification_report(&ctx, &result);

        assert!(!report.evidence_hash.is_empty(), "Hash must always be present");
        assert_eq!(report.findings.len(), 0);
        assert!(report.rowid_gaps.is_empty());
        assert!(report.benchmark_score.is_none());
    }

    #[test]
    fn test_hex_context_generated() {
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;
        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // offset 100 is well within our 4096-byte db
        let record = RecoveredRecord {
            table: "events".to_string(),
            row_id: Some(1),
            values: vec![SqlValue::Null],
            source: EvidenceSource::Freelist,
            offset: 100,
            confidence: 0.9,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert!(
            !finding.hex_context.is_empty(),
            "hex_context should be non-empty for a valid offset"
        );
        // hex context is space-separated bytes, so length > 0
        assert!(finding.hex_context.contains(' ') || finding.hex_context.len() == 2);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_at_offset_zero_page_number() {
        // Covers line 52: page_number = 0 when record.offset == 0.
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: Some(1),
            values: vec![SqlValue::Int(1)],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert_eq!(report.findings[0].page_number, 0);
    }

    #[test]
    fn test_hex_context_beyond_db() {
        // Covers line 67: String::new() when hex_start >= db.len().
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::Freelist,
            offset: 999999, // well beyond db.len()
            confidence: 0.5,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert!(report.findings[0].hex_context.is_empty());
    }

    #[test]
    fn test_wal_pending_recovery_technique() {
        // Covers line 72: WalPending technique string.
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::WalPending,
            offset: 100,
            confidence: 0.9,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert_eq!(report.findings[0].recovery_technique, "WAL replay (pending transaction)");
    }

    #[test]
    fn test_wal_deleted_recovery_technique() {
        // Covers line 73: WalDeleted technique string.
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::WalDeleted,
            offset: 100,
            confidence: 0.8,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert_eq!(report.findings[0].recovery_technique, "WAL analysis (deleted in WAL)");
    }

    #[test]
    fn test_journal_recovery_technique() {
        // Covers line 79: Journal technique string.
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::Journal,
            offset: 100,
            confidence: 0.7,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert_eq!(report.findings[0].recovery_technique, "Rollback journal parsing");
    }

    #[test]
    fn test_catchall_recovery_technique() {
        // Covers line 80: catch-all format!("{:?}", record.source).
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![],
            source: EvidenceSource::FtsOnly,
            offset: 100,
            confidence: 0.6,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert!(report.findings[0].recovery_technique.contains("FtsOnly"));
    }

    #[test]
    fn test_live_record_no_rowid_uses_xxd() {
        // Covers line 91: Live record with row_id=None uses xxd command.
        let (db, header) = make_db_and_header();
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let record = RecoveredRecord {
            table: "t".to_string(),
            row_id: None,
            values: vec![SqlValue::Int(1)],
            source: EvidenceSource::Live,
            offset: 256,
            confidence: 1.0,
        };
        let result = make_result(vec![record]);
        let report = build_verification_report(&ctx, &result);
        assert!(report.findings[0].verification_command.starts_with("xxd"));
        assert!(report.findings[0].verification_command.contains("256"));
    }
}
