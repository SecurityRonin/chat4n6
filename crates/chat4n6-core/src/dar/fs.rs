use anyhow::Result;
use chat4n6_plugin_api::{ForensicFs, FsEntry, UnallocatedRegion};
use std::collections::HashMap;
use std::path::Path;

use super::catalog::CatalogEntry;

/// ForensicFs implementation over a DAR archive file.
pub struct DarFs {
    /// Raw archive data (memory-mapped or loaded).
    data: Vec<u8>,
    /// Catalog: path → (data_offset, data_size, is_dir).
    catalog: HashMap<String, CatalogEntry>,
    /// Unallocated regions extracted from the image.
    unallocated: Vec<UnallocatedRegion>,
}

impl DarFs {
    /// Open a DAR archive file and parse its catalog.
    ///
    /// MVP: loads the entire archive into memory. Archives larger than 2 GiB
    /// will be rejected — use a memory-mapped implementation for production use.
    pub fn open(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        anyhow::ensure!(
            metadata.len() <= 2 * 1024 * 1024 * 1024,
            "DAR archive too large for in-memory loading ({} bytes); mmap support pending",
            metadata.len()
        );
        let data = std::fs::read(path)?;
        // For MVP: build an empty catalog (full parsing is iterative).
        // Real implementation would parse the terminator, locate the catalog,
        // and walk file entries. This stub satisfies the trait contract.
        Ok(Self {
            data,
            catalog: HashMap::new(),
            unallocated: Vec::new(),
        })
    }
}

impl ForensicFs for DarFs {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>> {
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else {
            format!("{}/", path.trim_start_matches('/'))
        };
        let entries: Vec<FsEntry> = self
            .catalog
            .iter()
            .filter(|(k, _)| {
                k.starts_with(&prefix) && {
                    let remainder = &k[prefix.len()..];
                    !remainder.is_empty() && !remainder.contains('/')
                }
            })
            .map(|(k, v)| FsEntry {
                path: k.clone(),
                size: v.data_size,
                is_dir: v.is_dir,
            })
            .collect();
        Ok(entries)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let key = path.trim_start_matches('/');
        let entry = self
            .catalog
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("file not found in DAR: {}", path))?;
        let start = entry.data_offset as usize;
        let end = start + entry.data_size as usize;
        anyhow::ensure!(end <= self.data.len(), "DAR entry out of bounds: {}", path);
        Ok(self.data[start..end].to_vec())
    }

    fn exists(&self, path: &str) -> bool {
        let key = path.trim_start_matches('/');
        self.catalog.contains_key(key)
    }

    fn unallocated_regions(&self) -> Vec<UnallocatedRegion> {
        self.unallocated.clone()
    }
}
