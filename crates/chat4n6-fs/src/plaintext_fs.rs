use anyhow::{Context, Result};
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use std::path::{Component, Path, PathBuf};

pub struct PlaintextDirFs {
    root: PathBuf,
}

impl PlaintextDirFs {
    pub fn new(root: &Path) -> Result<Self> {
        anyhow::ensure!(root.is_dir(), "not a directory: {}", root.display());
        let root = root
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", root.display()))?;
        Ok(Self { root })
    }
}

/// Validate and join `path` against `root`, rejecting traversal attempts.
///
/// Rejects absolute paths (PathBuf::join would silently replace root) and
/// any path that after lexical normalization escapes the root directory.
fn checked_join(root: &Path, path: &str) -> Result<PathBuf> {
    anyhow::ensure!(!Path::new(path).is_absolute(), "absolute path rejected: {path}");
    // Lexically normalize the joined path to resolve `..` components.
    let joined = root.join(path);
    let normalized = joined.components().fold(PathBuf::new(), |mut acc, c| {
        match c {
            Component::ParentDir => {
                acc.pop();
            }
            other => acc.push(other),
        }
        acc
    });
    anyhow::ensure!(normalized.starts_with(root), "path traversal rejected: {path}");
    Ok(normalized)
}

impl ForensicFs for PlaintextDirFs {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let full = checked_join(&self.root, path)?;
        let mut entries = Vec::new();
        for entry in
            std::fs::read_dir(&full).with_context(|| format!("reading dir {}", full.display()))?
        {
            let entry = entry?;
            let meta = entry.metadata()?;
            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .with_context(|| format!("entry {:?} outside root {:?}", entry.path(), self.root))?
                .to_string_lossy()
                .into_owned();
            entries.push(FsEntry {
                path: rel,
                size: meta.len(),
                is_dir: meta.is_dir(),
            });
        }
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let full = checked_join(&self.root, path)?;
        std::fs::read(&full).with_context(|| format!("reading {}", full.display()))
    }

    fn exists(&self, path: &str) -> bool {
        checked_join(&self.root, path)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_temp_tree() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("data/data/com.whatsapp/databases")).unwrap();
        fs::write(
            dir.path()
                .join("data/data/com.whatsapp/databases/msgstore.db"),
            b"SQLite format 3\x00",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_list_finds_db() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        let entries = fs.list("data/data/com.whatsapp/databases").unwrap();
        assert!(entries.iter().any(|e| e.path.ends_with("msgstore.db")));
    }

    #[test]
    fn test_read_returns_bytes() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        let bytes = fs
            .read("data/data/com.whatsapp/databases/msgstore.db")
            .unwrap();
        assert_eq!(&bytes[..7], b"SQLite ");
    }

    #[test]
    fn test_unallocated_empty_for_plain_dir() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        assert!(fs.unallocated_regions().is_empty());
    }

    #[test]
    fn test_path_traversal_rejected() {
        let dir = make_temp_tree();
        let fs = PlaintextDirFs::new(dir.path()).unwrap();
        // Relative traversal
        assert!(fs.read("../../etc/passwd").is_err());
        assert!(fs.list("../..").is_err());
        // Absolute path injection (PathBuf::join would silently replace root)
        assert!(fs.read("/etc/passwd").is_err());
        // exists() returns false rather than panicking or leaking
        assert!(!fs.exists("../../etc/passwd"));
        assert!(!fs.exists("/etc/passwd"));
    }
}
