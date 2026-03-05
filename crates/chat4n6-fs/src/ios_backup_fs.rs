use anyhow::Result;
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use ios_backup::IosBackup;
use std::path::Path;

pub struct IosBackupFs(IosBackup);

impl IosBackupFs {
    pub fn open(backup_dir: &Path) -> Result<Self> {
        Ok(Self(IosBackup::open(backup_dir)?))
    }
}

impl ForensicFs for IosBackupFs {
    /// Virtual path: `<domain>/<relative_path>`
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else {
            format!("{}/", path.trim_start_matches('/').trim_end_matches('/'))
        };
        let entries = self
            .0
            .entries()
            .iter()
            .map(|e| format!("{}/{}", e.domain, e.relative_path))
            .filter(|vp| {
                if prefix.is_empty() {
                    true // list("") returns all entries
                } else {
                    vp.starts_with(&prefix)
                }
            })
            .map(|vp| FsEntry { path: vp, size: 0, is_dir: false })
            .collect();
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let (domain, relative_path) = key.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("invalid IosBackupFs path (expected domain/path): {path}")
        })?;
        let entry = self
            .0
            .get(domain, relative_path)
            .ok_or_else(|| anyhow::anyhow!("file not found in iOS backup: {path}"))?;
        self.0.read(entry)
    }

    fn exists(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        key.split_once('/')
            .map(|(domain, rel)| self.0.get(domain, rel).is_some())
            .unwrap_or(false)
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_backup(tmp: &TempDir) -> std::path::PathBuf {
        let dir = tmp.path().to_path_buf();
        let conn = Connection::open(dir.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (
                fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT,
                flags INTEGER, file BLOB
            );
            INSERT INTO Files VALUES (
                'aabbccdd1122334455667788990011223344556677',
                'AppDomain-net.whatsapp.WhatsApp',
                'Documents/ChatStorage.sqlite',
                1, NULL
            );",
        )
        .unwrap();
        let sub = dir.join("aa");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("aabbccdd1122334455667788990011223344556677"),
            b"sqlite3-magic",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_exists_by_virtual_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = IosBackupFs::open(&make_backup(&tmp)).unwrap();
        assert!(fs.exists(
            "AppDomain-net.whatsapp.WhatsApp/Documents/ChatStorage.sqlite"
        ));
        assert!(!fs.exists("AppDomain-net.whatsapp.WhatsApp/no-such-file"));
    }

    #[test]
    fn test_read_by_virtual_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = IosBackupFs::open(&make_backup(&tmp)).unwrap();
        let data = fs
            .read("AppDomain-net.whatsapp.WhatsApp/Documents/ChatStorage.sqlite")
            .unwrap();
        assert_eq!(data, b"sqlite3-magic");
    }

    #[test]
    fn test_list_returns_matching_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let fs = IosBackupFs::open(&make_backup(&tmp)).unwrap();
        // list("") should return all entries
        let all = fs.list("").unwrap();
        assert_eq!(all.len(), 1, "list(\"\") should return all 1 entry");
        // list("AppDomain-net.whatsapp.WhatsApp") should return entries with that domain prefix
        let domain_entries = fs.list("AppDomain-net.whatsapp.WhatsApp").unwrap();
        assert_eq!(domain_entries.len(), 1, "domain prefix should match 1 entry");
        // list("AppDomain-nonexistent") should return no entries
        let none = fs.list("AppDomain-nonexistent").unwrap();
        assert_eq!(none.len(), 0);
    }
}
