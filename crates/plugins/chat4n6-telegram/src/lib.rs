pub mod extractor;

use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};

const DB_PATHS: &[&str] = &[
    "data/data/org.telegram.messenger/files/cache4.db",
    "data/data/org.telegram.messenger/files/cache.db",
];

pub struct TelegramPlugin;

impl ForensicPlugin for TelegramPlugin {
    fn name(&self) -> &str {
        "Telegram Android"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        DB_PATHS.iter().any(|p| fs.exists(p))
    }

    fn extract(
        &self,
        fs: &dyn ForensicFs,
        local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        let tz = local_offset_seconds.unwrap_or(0);
        for path in DB_PATHS {
            if fs.exists(path) {
                let bytes = fs.read(path)?;
                return extractor::extract_from_telegram_db(&bytes, tz);
            }
        }
        log::warn!("Telegram cache.db not found; returning empty result");
        Ok(ExtractionResult::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{FsEntry, UnallocatedRegion};
    use std::collections::HashMap;

    struct MockFs {
        files: HashMap<String, Vec<u8>>,
    }

    impl MockFs {
        fn new() -> Self {
            Self {
                files: HashMap::new(),
            }
        }
        fn with_file(mut self, path: &str) -> Self {
            self.files.insert(path.to_string(), vec![0u8; 100]);
            self
        }
    }

    impl ForensicFs for MockFs {
        fn list(&self, _: &str) -> anyhow::Result<Vec<FsEntry>> {
            Ok(vec![])
        }
        fn read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not found"))
        }
        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }
        fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
            vec![]
        }
    }

    #[test]
    fn test_detect_cache4() {
        let fs =
            MockFs::new().with_file("data/data/org.telegram.messenger/files/cache4.db");
        assert!(TelegramPlugin.detect(&fs));
    }

    #[test]
    fn test_detect_cache() {
        let fs =
            MockFs::new().with_file("data/data/org.telegram.messenger/files/cache.db");
        assert!(TelegramPlugin.detect(&fs));
    }

    #[test]
    fn test_detect_absent() {
        assert!(!TelegramPlugin.detect(&MockFs::new()));
    }

    /// The mock file contains 100 zero bytes — not a valid SQLite DB.
    /// extract() propagates the error from ForensicEngine rather than silently
    /// returning empty, so callers can detect corrupted/missing databases.
    #[test]
    fn test_extract_invalid_db_returns_err() {
        let fs =
            MockFs::new().with_file("data/data/org.telegram.messenger/files/cache4.db");
        let r = TelegramPlugin.extract(&fs, None);
        assert!(r.is_err(), "invalid SQLite bytes should return Err");
    }

    #[test]
    fn test_name() {
        assert_eq!(TelegramPlugin.name(), "Telegram Android");
    }
}
