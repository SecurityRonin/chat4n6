use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Chain-of-custody manifest written alongside every report.
///
/// Records SHA-256 hashes of all input artifacts and generated output files
/// so that report integrity can be verified after the fact.
#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicManifest {
    pub tool_name: String,
    pub tool_version: String,
    pub case_name: String,
    pub generated_at_utc: String,
    /// filename → SHA-256 hex digest of each input artifact.
    pub input_hashes: BTreeMap<String, String>,
    /// filename → SHA-256 hex digest of each generated output file.
    pub output_hashes: BTreeMap<String, String>,
}

impl ForensicManifest {
    pub fn new(case_name: &str, generated_at: &str) -> Self {
        Self {
            tool_name: "chat4n6".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_name: case_name.to_string(),
            generated_at_utc: generated_at.to_string(),
            input_hashes: BTreeMap::new(),
            output_hashes: BTreeMap::new(),
        }
    }

    pub fn add_input_hash(&mut self, filename: &str, data: &[u8]) {
        self.input_hashes
            .insert(filename.to_string(), sha256_hex(data));
    }

    pub fn add_output_hash(&mut self, filename: &str, data: &[u8]) {
        self.output_hashes
            .insert(filename.to_string(), sha256_hex(data));
    }
}

/// Compute the SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
