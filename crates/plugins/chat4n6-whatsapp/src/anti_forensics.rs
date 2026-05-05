/// Anti-forensics analysis for WhatsApp SQLite databases.
///
/// Detects evidence of external tampering, selective deletion,
/// VACUUM operations, and timestamp anomalies.

use chat4n6_plugin_api::ExtractionResult;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ForensicWarning {
    /// Free-page count is non-zero, indicating a prior VACUUM or deletion.
    VacuumDetected { free_pages: u32 },
    /// Rowid sequence has gaps consistent with selective row deletion.
    SelectiveDeletion { table: String, gap_count: usize },
    /// Timestamps on otherwise sequential rows are non-monotonic.
    TimestampAnomaly { table: String, anomaly_count: usize },
    /// write_counter ≠ read_counter while not in WAL mode — external edit.
    SchemaVersionMismatch { found: u32, expected: u32 },
    /// Declared page_size × page_count ≠ actual file length.
    SuspiciousSequenceGap {
        table: String,
        gap_start: i64,
        gap_end: i64,
    },
}

#[derive(Debug, Clone)]
pub struct AntiForensicsReport {
    pub warnings: Vec<ForensicWarning>,
}

// ── Existing detectors ────────────────────────────────────────────────────────

/// Detect VACUUM by checking free_page_count (bytes 36–39).
pub fn detect_vacuum(db_bytes: &[u8]) -> Vec<ForensicWarning> {
    if db_bytes.len() < 40 {
        return vec![];
    }
    // Verify magic
    if &db_bytes[..16] != b"SQLite format 3\0" {
        return vec![];
    }
    let free_pages = u32::from_be_bytes([
        db_bytes[36],
        db_bytes[37],
        db_bytes[38],
        db_bytes[39],
    ]);
    if free_pages > 0 {
        vec![ForensicWarning::VacuumDetected { free_pages }]
    } else {
        vec![]
    }
}

/// Detect selective deletion from rowid gaps in a recovered record set.
pub fn detect_selective_deletion(
    result: &ExtractionResult,
) -> Vec<ForensicWarning> {
    // Stub: real implementation would inspect row_offset gaps across chats/messages.
    let _ = result;
    vec![]
}

/// Detect timestamp anomalies in message timelines.
pub fn detect_timestamp_anomalies(
    result: &ExtractionResult,
) -> Vec<ForensicWarning> {
    let _ = result;
    vec![]
}

// ── Story 1: header tamper detection ─────────────────────────────────────────

/// Analyse the SQLite file header for signs of external tampering.
///
/// Checks performed:
/// 1. write_counter ≠ read_counter (and not WAL mode) → SchemaVersionMismatch
/// 2. page_size × page_count ≠ actual file length     → SuspiciousSequenceGap
pub fn detect_header_tamper(db_bytes: &[u8]) -> Vec<ForensicWarning> {
    todo!("implement detect_header_tamper")
}

// ── Top-level analyser ────────────────────────────────────────────────────────

/// Run all anti-forensics checks and return a consolidated report.
///
/// `db_bytes` is the raw SQLite file content, used for header-level checks.
pub fn analyse(result: &ExtractionResult, db_bytes: &[u8]) -> AntiForensicsReport {
    todo!("implement analyse")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod header_tamper_tests {
    use super::*;

    #[test]
    fn header_tamper_write_read_counter_mismatch_emits_warning() {
        // Build 100 bytes: valid magic + page_size=4096 + write_counter=5, read_counter=3
        let mut header = [0u8; 100];
        header[..16].copy_from_slice(b"SQLite format 3\0");
        header[16..18].copy_from_slice(&4096u16.to_be_bytes());
        header[18] = 1; // non-WAL write version
        header[28..32].copy_from_slice(&1u32.to_be_bytes()); // page_count=1
        header[92..96].copy_from_slice(&5u32.to_be_bytes()); // write_counter=5
        header[96..100].copy_from_slice(&3u32.to_be_bytes()); // read_counter=3
        let warnings = detect_header_tamper(&header);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::SchemaVersionMismatch { .. })),
            "write/read counter mismatch must emit SchemaVersionMismatch"
        );
    }

    #[test]
    fn header_tamper_page_size_mismatch_emits_warning() {
        // 100-byte buffer: valid magic, page_size=4096, page_count=2 (expected 8192 bytes)
        // but actual buffer is only 100 bytes → size mismatch
        let mut header = [0u8; 100];
        header[..16].copy_from_slice(b"SQLite format 3\0");
        header[16..18].copy_from_slice(&4096u16.to_be_bytes());
        header[28..32].copy_from_slice(&2u32.to_be_bytes()); // page_count=2 → expected 8192
        // write=read so no counter mismatch
        header[92..96].copy_from_slice(&1u32.to_be_bytes());
        header[96..100].copy_from_slice(&1u32.to_be_bytes());
        let warnings = detect_header_tamper(&header);
        assert!(
            warnings.iter().any(|w| matches!(w, ForensicWarning::SuspiciousSequenceGap { .. })),
            "page size * count != file size must emit SuspiciousSequenceGap"
        );
    }
}
