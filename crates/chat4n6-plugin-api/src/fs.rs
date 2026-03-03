use crate::types::ExtractionResult;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnallocatedRegion {
    pub offset: u64,
    pub data: Vec<u8>,
}

pub trait ForensicFs: Send + Sync {
    fn list(&self, path: &str) -> Result<Vec<FsEntry>>;
    fn read(&self, path: &str) -> Result<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
    fn unallocated_regions(&self) -> &[UnallocatedRegion];
}

pub trait ForensicPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, fs: &dyn ForensicFs) -> bool;
    fn extract(
        &self,
        fs: &dyn ForensicFs,
        local_offset_seconds: Option<i32>,
    ) -> Result<ExtractionResult>;
}
