use anyhow::Result;
use chat4n6_plugin_api::ExtractionResult;

/// Extract all forensic artifacts from a Signal `signal.sqlite` byte slice.
///
/// Callers are responsible for providing **plaintext** SQLite bytes. Signal encrypts
/// its database with SQLCipher; decryption is a separate pre-processing step.
///
/// `tz_offset_secs` — seconds east of UTC used for local timestamp display.
pub fn extract_from_signal_db(_db_bytes: &[u8], _tz_offset_secs: i32) -> Result<ExtractionResult> {
    // Stub — implementation pending (GREEN commit).
    Ok(ExtractionResult::default())
}
