// chat4n6-whatsapp

pub mod decrypt;
pub mod extractor;
pub mod schema;
pub mod timezone;

use crate::extractor::extract_from_msgstore;
use crate::schema::detect_schema_version;
use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};

pub struct WhatsAppPlugin;

impl ForensicPlugin for WhatsAppPlugin {
    fn name(&self) -> &str {
        "WhatsApp Android"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        let db_path = "data/data/com.whatsapp/databases/msgstore.db";
        fs.exists(db_path)
    }

    fn extract(
        &self,
        fs: &dyn ForensicFs,
        local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        let db_path = "data/data/com.whatsapp/databases/msgstore.db";
        let db_bytes = fs.read(db_path)?;
        let tz = local_offset_seconds.unwrap_or(0);
        // SQLite user_version is stored in header bytes 60-63 as big-endian u32
        // https://www.sqlite.org/fileformat.html
        let user_version = if db_bytes.len() >= 64 {
            u32::from_be_bytes([db_bytes[60], db_bytes[61], db_bytes[62], db_bytes[63]])
        } else {
            0
        };
        // Table-name detection path (requires tables slice) is intentionally
        // skipped here; user_version-based detection is sufficient for all
        // known WhatsApp builds. The schema value is currently informational
        // only (_schema_version is unused in extract_from_msgstore).
        let schema = detect_schema_version(user_version, &[]);
        extract_from_msgstore(&db_bytes, tz, schema)
    }
}
