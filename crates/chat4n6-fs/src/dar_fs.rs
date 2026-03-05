use anyhow::Result;
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use dar_archive::DarArchive;
use std::path::Path;

pub struct DarFs(DarArchive);

impl DarFs {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self(DarArchive::open(path)?))
    }

    pub fn open_slices(basename: &Path) -> Result<Self> {
        Ok(Self(DarArchive::open_slices(basename)?))
    }
}

impl ForensicFs for DarFs {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else {
            format!("{}/", path.trim_start_matches('/'))
        };
        let entries = self
            .0
            .entries()
            .iter()
            .filter(|e| {
                let p = e.path.to_string_lossy();
                p.starts_with(&prefix) && {
                    let remainder = &p[prefix.len()..];
                    !remainder.is_empty() && !remainder.contains('/')
                }
            })
            .map(|e| FsEntry {
                path: e.path.to_string_lossy().into_owned(),
                size: e.size,
                is_dir: e.is_dir,
            })
            .collect();
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let entry = self
            .0
            .entries()
            .iter()
            .find(|e| e.path.to_str() == Some(key))
            .ok_or_else(|| anyhow::anyhow!("file not found in DAR: {path}"))?;
        Ok(self.0.read(entry)?.into_owned())
    }

    fn exists(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        self.0.entries().iter().any(|e| e.path.to_str() == Some(key))
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAR_PATH: &str = "/path/to/userdata.1.dar"; // update for local testing

    #[test]
    fn test_darfs_with_real_file() {
        if !std::path::Path::new(DAR_PATH).exists() {
            eprintln!("Skipping DarFs test: no real .dar fixture at {DAR_PATH}");
            return;
        }
        let fs = DarFs::open(std::path::Path::new(DAR_PATH)).expect("DarFs::open");
        assert!(!fs.list("").unwrap().is_empty(), "root listing should be non-empty");
        assert!(
            fs.exists("data/data/com.whatsapp/databases/msgstore.db"),
            "msgstore.db should exist in archive"
        );
        let bytes = fs.read("data/data/com.whatsapp/databases/msgstore.db").unwrap();
        assert_eq!(&bytes[..7], b"SQLite ", "msgstore.db should start with SQLite header");
    }
}
