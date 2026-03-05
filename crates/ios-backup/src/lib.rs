use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BackupEntry {
    pub domain: String,
    pub relative_path: String,
    pub file_id: String, // 40-char SHA-1 hex string
    pub flags: u32,
}

pub struct IosBackup {
    backup_dir: PathBuf,
    entries: Vec<BackupEntry>,
}

impl IosBackup {
    /// Open a backup directory. Reads `Manifest.db` once and builds an in-memory index.
    pub fn open(backup_dir: &Path) -> Result<Self> {
        let manifest = backup_dir.join("Manifest.db");
        anyhow::ensure!(
            manifest.exists(),
            "Manifest.db not found in {}",
            backup_dir.display()
        );
        let conn = Connection::open(&manifest)
            .with_context(|| format!("cannot open {}", manifest.display()))?;
        let mut stmt = conn
            .prepare(
                "SELECT fileID, domain, relativePath, flags \
                 FROM Files WHERE relativePath != '' AND relativePath IS NOT NULL",
            )
            .context("prepare Files query")?;
        let entries: Vec<BackupEntry> = stmt
            .query_map([], |row| {
                Ok(BackupEntry {
                    file_id: row.get(0)?,
                    domain: row.get(1)?,
                    relative_path: row.get(2)?,
                    flags: row.get::<_, u32>(3)?,
                })
            })
            .context("query Files")?
            .collect::<Result<_, _>>()
            .context("collect entries")?;
        Ok(Self {
            backup_dir: backup_dir.to_path_buf(),
            entries,
        })
    }

    pub fn entries(&self) -> &[BackupEntry] {
        &self.entries
    }

    /// Find an entry by domain + relative_path.
    pub fn get(&self, domain: &str, relative_path: &str) -> Option<&BackupEntry> {
        self.entries
            .iter()
            .find(|e| e.domain == domain && e.relative_path == relative_path)
    }

    /// Read the backing file for an entry.
    /// Backing file path: `<backup_dir>/<file_id[0..2]>/<file_id>`
    pub fn read(&self, entry: &BackupEntry) -> Result<Vec<u8>> {
        anyhow::ensure!(
            entry.file_id.len() >= 2,
            "file_id too short (expected 40-char SHA-1 hex): {:?}",
            entry.file_id
        );
        let sub = &entry.file_id[..2];
        let path = self.backup_dir.join(sub).join(&entry.file_id);
        std::fs::read(&path)
            .with_context(|| format!("cannot read backup file {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_backup(tmp: &TempDir) -> PathBuf {
        let dir = tmp.path().to_path_buf();
        let conn = Connection::open(dir.join("Manifest.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (
                fileID TEXT PRIMARY KEY,
                domain TEXT,
                relativePath TEXT,
                flags INTEGER,
                file BLOB
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
            b"fake-sqlite-content",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_open_reads_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        assert_eq!(backup.entries().len(), 1);
    }

    #[test]
    fn test_get_finds_by_domain_and_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        let entry = backup.get(
            "AppDomain-net.whatsapp.WhatsApp",
            "Documents/ChatStorage.sqlite",
        );
        assert!(entry.is_some());
        assert_eq!(
            entry.unwrap().file_id,
            "aabbccdd1122334455667788990011223344556677"
        );
    }

    #[test]
    fn test_get_returns_none_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        assert!(backup.get("AppDomain-net.whatsapp.WhatsApp", "no-such-file").is_none());
    }

    #[test]
    fn test_read_returns_file_content() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = make_backup(&tmp);
        let backup = IosBackup::open(&dir).unwrap();
        let entry = backup
            .get("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite")
            .unwrap();
        let content = backup.read(entry).unwrap();
        assert_eq!(content, b"fake-sqlite-content");
    }
}
