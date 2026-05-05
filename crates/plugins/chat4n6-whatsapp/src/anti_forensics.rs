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
    // Need at least 100 bytes for a valid SQLite header.
    if db_bytes.len() < 100 {
        return vec![];
    }

    // Check magic — if wrong, this is not a SQLite file; return empty.
    if &db_bytes[..16] != b"SQLite format 3\0" {
        return vec![];
    }

    let mut warnings = Vec::new();

    // ── Check 1: write_counter vs read_counter ───────────────────────────
    // Byte 18: file format write version (1 = journal, 2 = WAL)
    let write_version = db_bytes[18];
    let write_counter = u32::from_be_bytes([
        db_bytes[92],
        db_bytes[93],
        db_bytes[94],
        db_bytes[95],
    ]);
    let read_counter = u32::from_be_bytes([
        db_bytes[96],
        db_bytes[97],
        db_bytes[98],
        db_bytes[99],
    ]);
    // Mismatch is suspicious only when NOT in WAL mode (write_version == 2).
    if write_counter != read_counter && write_version != 2 {
        warnings.push(ForensicWarning::SchemaVersionMismatch {
            found: write_counter,
            expected: read_counter,
        });
    }

    // ── Check 2: page_size × page_count vs actual file size ─────────────
    // bytes 16–17: page_size (big-endian u16; value 1 means 65536)
    let raw_page_size = u16::from_be_bytes([db_bytes[16], db_bytes[17]]);
    let page_size: u64 = if raw_page_size == 1 {
        65536
    } else {
        raw_page_size as u64
    };
    // bytes 28–31: page_count (big-endian u32)
    let page_count = u32::from_be_bytes([
        db_bytes[28],
        db_bytes[29],
        db_bytes[30],
        db_bytes[31],
    ]) as u64;

    let expected_size = page_size * page_count;
    let actual_size = db_bytes.len() as u64;

    // Only emit when actual >= 100 (i.e., the file has a full header).
    if actual_size >= 100 && actual_size != expected_size {
        warnings.push(ForensicWarning::SuspiciousSequenceGap {
            table: "sqlite_header".to_string(),
            gap_start: expected_size as i64,
            gap_end: actual_size as i64,
        });
    }

    warnings
}

// ── Top-level analyser ────────────────────────────────────────────────────────

/// Run all anti-forensics checks and return a consolidated report.
///
/// `db_bytes` is the raw SQLite file content, used for header-level checks.
pub fn analyse(result: &ExtractionResult, db_bytes: &[u8]) -> AntiForensicsReport {
    let mut warnings = Vec::new();
    warnings.extend(detect_vacuum(db_bytes));
    warnings.extend(detect_selective_deletion(result));
    warnings.extend(detect_timestamp_anomalies(result));
    warnings.extend(detect_header_tamper(db_bytes));
    AntiForensicsReport { warnings }
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
