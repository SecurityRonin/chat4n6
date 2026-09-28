pub mod extractor;
pub mod schema;

use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};

/// iMessage stores its database as `chat.db` on macOS (`~/Library/Messages/chat.db`)
/// and as `sms.db` under the `HomeDomain` in an iOS backup. `detect` matches either.
pub const DB_PATH_MAC: &str = "chat.db";
pub const DB_PATH_MAC_ALT: &str = "Library/Messages/chat.db";
pub const DB_PATH_IOS: &str = "HomeDomain/Library/SMS/sms.db";

const CANDIDATES: [&str; 3] = [DB_PATH_MAC, DB_PATH_MAC_ALT, DB_PATH_IOS];

pub struct ImessagePlugin;

impl ForensicPlugin for ImessagePlugin {
    fn name(&self) -> &str {
        "iMessage"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        CANDIDATES.iter().any(|p| fs.exists(p))
    }

    fn extract(
        &self,
        fs: &dyn ForensicFs,
        local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        let path = CANDIDATES
            .iter()
            .copied()
            .find(|p| fs.exists(p))
            .unwrap_or(DB_PATH_MAC);
        let db_bytes = fs.read(path)?;
        extractor::extract_from_chatdb(&db_bytes, local_offset_seconds.unwrap_or(0))
    }
}
