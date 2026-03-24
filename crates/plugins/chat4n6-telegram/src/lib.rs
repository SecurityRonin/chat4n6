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
        _fs: &dyn ForensicFs,
        _local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        log::warn!("Telegram extraction is not yet implemented; returning empty result");
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

    #[test]
    fn test_extract_returns_empty() {
        let fs =
            MockFs::new().with_file("data/data/org.telegram.messenger/files/cache4.db");
        let r = TelegramPlugin.extract(&fs, None).unwrap();
        assert!(r.chats.is_empty());
        assert!(r.calls.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(TelegramPlugin.name(), "Telegram Android");
    }
}
