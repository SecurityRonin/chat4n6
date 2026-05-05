// chat4n6-whatsapp

pub mod contact_report;
pub mod decrypt;
pub mod extractor;
pub mod orphaned_media;
pub mod platform;
pub mod system_event;
pub mod schema;
pub mod timezone;
pub mod album;
pub mod poll;
pub mod group_metadata;
pub mod location;
pub mod mention;
pub mod pin;
pub mod status;
pub mod link;

use crate::extractor::{extract_contacts, extract_from_msgstore, build_contact_names};
use crate::schema::detect_schema_version;
use anyhow::{Context, Result};
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, ForensicPlugin};

const DB_PATH: &str = "data/data/com.whatsapp/databases/msgstore.db";
const DB_CRYPT14: &str = "data/data/com.whatsapp/databases/msgstore.db.crypt14";
const DB_CRYPT15: &str = "data/data/com.whatsapp/databases/msgstore.db.crypt15";
const KEY_PATH: &str = "data/data/com.whatsapp/files/key";
const WA_DB_PATH: &str = "data/data/com.whatsapp/databases/wa.db";

pub struct WhatsAppPlugin {
    key: Option<Vec<u8>>,
}

impl WhatsAppPlugin {
    pub fn new() -> Self {
        Self { key: None }
    }

    pub fn with_key(key: Vec<u8>) -> Self {
        Self { key: Some(key) }
    }

    /// Resolve the decryption key: explicit key takes priority, then auto-detect
    /// from the standard Android key file path on the filesystem.
    fn resolve_key(&self, fs: &dyn ForensicFs) -> Option<Vec<u8>> {
        if let Some(ref k) = self.key {
            return Some(k.clone());
        }
        if fs.exists(KEY_PATH) {
            fs.read(KEY_PATH).ok()
        } else {
            None
        }
    }
}

impl Default for WhatsAppPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicPlugin for WhatsAppPlugin {
    fn name(&self) -> &str {
        "WhatsApp Android"
    }

    fn detect(&self, fs: &dyn ForensicFs) -> bool {
        fs.exists(DB_PATH) || fs.exists(DB_CRYPT14) || fs.exists(DB_CRYPT15)
    }

    fn extract(
        &self,
        fs: &dyn ForensicFs,
        local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult> {
        // ── Obtain plaintext database bytes ──────────────────────────────
        let db_bytes = if fs.exists(DB_PATH) {
            let bytes = fs.read(DB_PATH)?;
            if decrypt::is_sqlite(&bytes) {
                bytes
            } else {
                // File exists but isn't SQLite — might be encrypted despite name
                self.try_decrypt(&bytes)?
            }
        } else {
            // Try encrypted paths
            let (crypt_path, version) = if fs.exists(DB_CRYPT15) {
                (DB_CRYPT15, decrypt::CryptVersion::Crypt15)
            } else if fs.exists(DB_CRYPT14) {
                (DB_CRYPT14, decrypt::CryptVersion::Crypt14)
            } else {
                anyhow::bail!("no WhatsApp database found (checked plaintext and encrypted paths)");
            };
            let encrypted = fs.read(crypt_path)?;
            let key = self.resolve_key(fs).ok_or_else(|| {
                anyhow::anyhow!(
                    "encrypted database found at {crypt_path} but no key available \
                     (use --key-file or place key at {KEY_PATH})"
                )
            })?;
            decrypt::decrypt_db(&encrypted, &key, version)
                .with_context(|| format!("decrypting {crypt_path}"))?
        };

        let tz = local_offset_seconds.unwrap_or(0);

        // Detect schema version
        let user_version = if db_bytes.len() >= 64 {
            u32::from_be_bytes([db_bytes[60], db_bytes[61], db_bytes[62], db_bytes[63]])
        } else {
            0
        };
        let schema = detect_schema_version(user_version, &[]);

        let mut result = extract_from_msgstore(&db_bytes, tz, schema)?;

        // ── wa.db contact enrichment ─────────────────────────────────────
        if fs.exists(WA_DB_PATH) {
            if let Ok(wa_bytes) = fs.read(WA_DB_PATH) {
                if let Ok(contacts) = extract_contacts(&wa_bytes) {
                    let name_map = build_contact_names(&contacts);
                    // Apply display names to 1-to-1 chats that lack a subject
                    for chat in &mut result.chats {
                        if chat.name.is_none() {
                            chat.name = name_map.get(&chat.jid).cloned();
                        }
                    }
                    result.contacts = contacts;
                }
            }
        }

        Ok(result)
    }
}

impl WhatsAppPlugin {
    fn try_decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("database is not SQLite and no decryption key provided"))?;
        // Try crypt15 first, then crypt14
        if let Ok(plain) = decrypt::decrypt_db(bytes, key, decrypt::CryptVersion::Crypt15) {
            return Ok(plain);
        }
        decrypt::decrypt_db(bytes, key, decrypt::CryptVersion::Crypt14)
            .context("decryption failed for both crypt15 and crypt14")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
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
        fn add(mut self, path: &str, data: Vec<u8>) -> Self {
            self.files.insert(path.to_string(), data);
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
                .ok_or_else(|| anyhow::anyhow!("not found: {path}"))
        }
        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }
        fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
            vec![]
        }
    }

    #[test]
    fn test_detect_plaintext() {
        let fs = MockFs::new().add(DB_PATH, b"SQLite format 3\x00".to_vec());
        assert!(WhatsAppPlugin::new().detect(&fs));
    }

    #[test]
    fn test_detect_crypt15() {
        let fs = MockFs::new().add(DB_CRYPT15, vec![0; 200]);
        assert!(WhatsAppPlugin::new().detect(&fs));
    }

    #[test]
    fn test_detect_crypt14() {
        let fs = MockFs::new().add(DB_CRYPT14, vec![0; 200]);
        assert!(WhatsAppPlugin::new().detect(&fs));
    }

    #[test]
    fn test_detect_nothing() {
        let fs = MockFs::new();
        assert!(!WhatsAppPlugin::new().detect(&fs));
    }

    #[test]
    fn test_plugin_name() {
        assert_eq!(WhatsAppPlugin::new().name(), "WhatsApp Android");
    }

    #[test]
    fn test_default_impl() {
        let p = WhatsAppPlugin::default();
        assert!(p.key.is_none());
    }

    #[test]
    fn test_with_key() {
        let p = WhatsAppPlugin::with_key(vec![0x42; 32]);
        assert!(p.key.is_some());
        assert_eq!(p.key.unwrap().len(), 32);
    }

    #[test]
    fn test_extract_no_db_errors() {
        let fs = MockFs::new();
        let p = WhatsAppPlugin::new();
        // detect() returns false but if extract() is called anyway, it should error
        assert!(p.extract(&fs, None).is_err());
    }

    #[test]
    fn test_extract_encrypted_no_key_errors() {
        let fs = MockFs::new().add(DB_CRYPT15, vec![0; 200]);
        let p = WhatsAppPlugin::new();
        let err = p.extract(&fs, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no key"),
            "error should mention missing key, got: {msg}"
        );
    }

    #[test]
    fn test_resolve_key_explicit_priority() {
        let explicit_key = vec![0xAA; 32];
        let auto_key = vec![0xBB; 158];
        let fs = MockFs::new().add(KEY_PATH, auto_key);
        let p = WhatsAppPlugin::with_key(explicit_key.clone());
        let resolved = p.resolve_key(&fs).unwrap();
        assert_eq!(resolved, explicit_key, "explicit key should take priority");
    }

    #[test]
    fn test_resolve_key_auto_detect() {
        let auto_key = vec![0xCC; 158];
        let fs = MockFs::new().add(KEY_PATH, auto_key.clone());
        let p = WhatsAppPlugin::new();
        let resolved = p.resolve_key(&fs).unwrap();
        assert_eq!(resolved, auto_key);
    }

    #[test]
    fn test_resolve_key_none() {
        let fs = MockFs::new();
        let p = WhatsAppPlugin::new();
        assert!(p.resolve_key(&fs).is_none());
    }
}
