//! §2.4 Media export pipeline.
//!
//! Copies referenced media from the forensic image into
//! `output/media/by-chat/<slug>/`, hashes each file (SHA-256),
//! and generates `EXHIBIT-INDEX.csv`.
//!
//! Note: thumbnail generation deferred — requires image crate.

use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs};
use std::path::Path;

/// One row in the exhibit index CSV.
pub struct ExhibitRow {
    pub path: String,
    pub sha256: String,
    pub source_chat: String,
    pub source_msg_id: i64,
    pub evidence_layer: String,
}

/// Export all media files referenced in `result` from `fs` into
/// `output_dir/media/by-chat/<slug>/`.
///
/// For each exported file:
/// - Copies bytes to destination.
/// - Computes SHA-256 and sets `media_ref.encrypted_hash`.
/// - Records an `ExhibitRow`.
///
/// Writes `EXHIBIT-INDEX.csv` at the end.
pub fn export_media(
    _result: &mut ExtractionResult,
    _fs: &dyn ForensicFs,
    _output_dir: &Path,
) -> Result<Vec<ExhibitRow>> {
    // Stub — GREEN implementation not yet written.
    Ok(vec![])
}
