use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};

const DB_PATHS: &[&str] = &[
    "data/data/org.thoughtcrime.securesms/databases/signal.sqlite",
    "data/data/org.thoughtcrime.securesms/databases/signal.db",
];

pub struct SignalPlugin;

impl ForensicPlugin for SignalPlugin {
    fn name(&self) -> &str {
        "Signal Android"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        DB_PATHS.iter().any(|p| fs.exists(p))
    }

    fn extract(
        &self,
        _fs: &dyn ForensicFs,
        _local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        log::warn!("Signal extraction is not yet implemented; returning empty result");
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
    fn test_detect_modern_path() {
        let fs = MockFs::new()
            .with_file("data/data/org.thoughtcrime.securesms/databases/signal.sqlite");
        assert!(SignalPlugin.detect(&fs));
    }

    #[test]
    fn test_detect_legacy_path() {
        let fs =
            MockFs::new().with_file("data/data/org.thoughtcrime.securesms/databases/signal.db");
        assert!(SignalPlugin.detect(&fs));
    }

    #[test]
    fn test_detect_absent() {
        assert!(!SignalPlugin.detect(&MockFs::new()));
    }

    #[test]
    fn test_extract_returns_empty() {
        let fs = MockFs::new()
            .with_file("data/data/org.thoughtcrime.securesms/databases/signal.sqlite");
        let r = SignalPlugin.extract(&fs, None).unwrap();
        assert!(r.chats.is_empty());
        assert!(r.calls.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(SignalPlugin.name(), "Signal Android");
    }
}
