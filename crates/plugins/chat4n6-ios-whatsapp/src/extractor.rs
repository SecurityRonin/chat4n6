use anyhow::Result;
use chat4n6_plugin_api::ExtractionResult;

/// Extract all forensic artifacts from a ChatStorage.sqlite byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
pub fn extract_from_chatstorage(_db_bytes: &[u8], _tz_offset_secs: i32) -> Result<ExtractionResult> {
    // TODO: implement
    anyhow::bail!("not yet implemented")
}
