pub mod extractor;
pub mod schema;

use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};
use anyhow::Result;

pub const DB_PATH: &str = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite";
pub const DB_ALT_PATH: &str = "AppDomain-net.whatsapp.WhatsApp/Library/ChatStorage.sqlite";

pub struct IosWhatsAppPlugin;

impl ForensicPlugin for IosWhatsAppPlugin {
    fn name(&self) -> &str {
        "WhatsApp iOS"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        fs.exists(DB_PATH) || fs.exists(DB_ALT_PATH)
    }

    fn extract(&self, fs: &dyn ForensicFs, local_offset_seconds: Option<i32>) -> Result<ExtractionResult> {
        let path = if fs.exists(DB_PATH) { DB_PATH } else { DB_ALT_PATH };
        let db_bytes = fs.read(path)?;
        let tz = local_offset_seconds.unwrap_or(0);
        extractor::extract_from_chatstorage(&db_bytes, tz)
    }
}
