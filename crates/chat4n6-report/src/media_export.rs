//! §2.4 Media export pipeline.
//!
//! Copies referenced media from the forensic image into
//! `output/media/by-chat/<slug>/`, hashes each file (SHA-256),
//! and generates `EXHIBIT-INDEX.csv`.
//!
//! Note: thumbnail generation deferred — requires image crate.

use anyhow::Result;
use chat4n6_plugin_api::{ExtractionResult, ForensicFs, MessageContent};
use sha2::{Digest, Sha256};
use std::path::Path;

/// One row in the exhibit index CSV.
pub struct ExhibitRow {
    pub path: String,
    pub sha256: String,
    pub source_chat: String,
    pub source_msg_id: i64,
    pub evidence_layer: String,
}

/// Convert a JID/display name to a filesystem-safe slug: `chat_{id}_{slug}`.
fn chat_slug(id: i64, display: &str) -> String {
    let slug: String = display
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(40)
        .collect();
    format!("chat_{}_{}", id, slug)
}

/// Compute SHA-256 hex digest of bytes.
fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Export all media files referenced in `result` from `fs` into
/// `output_dir/media/by-chat/<slug>/`.
///
/// For each exported file:
/// - Reads bytes from `fs` using `media_ref.file_path`.
/// - Copies bytes to `output_dir/media/by-chat/<slug>/<filename>`.
/// - Computes SHA-256 and sets `media_ref.encrypted_hash`.
/// - Records an `ExhibitRow`.
///
/// Writes `EXHIBIT-INDEX.csv` at the end. Returns all exhibit rows.
pub fn export_media(
    result: &mut ExtractionResult,
    fs: &dyn ForensicFs,
    output_dir: &Path,
) -> Result<Vec<ExhibitRow>> {
    let mut rows: Vec<ExhibitRow> = Vec::new();

    for chat in result.chats.iter_mut() {
        let slug = chat_slug(chat.id, chat.name.as_deref().unwrap_or(&chat.jid));
        let dest_dir = output_dir.join("media").join("by-chat").join(&slug);

        for msg in chat.messages.iter_mut() {
            if let MessageContent::Media(ref mut media_ref) = msg.content {
                // Attempt to read the file; skip on error.
                let bytes = match fs.read(&media_ref.file_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                // Compute SHA-256.
                let hash = sha256_hex(&bytes);

                // Set encrypted_hash on the media ref.
                media_ref.encrypted_hash = Some(hash.clone());

                // Determine filename (last path component).
                let filename = media_ref.file_path
                    .rsplit('/')
                    .next()
                    .unwrap_or("unknown")
                    .to_string();

                // Create destination directory and write file.
                std::fs::create_dir_all(&dest_dir)?;
                let dest_path = dest_dir.join(&filename);
                std::fs::write(&dest_path, &bytes)?;

                let rel_path = format!("media/by-chat/{}/{}", slug, filename);
                rows.push(ExhibitRow {
                    path: rel_path,
                    sha256: hash,
                    source_chat: chat.jid.clone(),
                    source_msg_id: msg.id,
                    evidence_layer: msg.source.to_string(),
                });
            }
        }
    }

    // Write EXHIBIT-INDEX.csv
    let csv_path = output_dir.join("EXHIBIT-INDEX.csv");
    let mut csv = String::from("path,sha256,source_chat,source_msg_id,evidence_layer\n");
    for row in &rows {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            row.path, row.sha256, row.source_chat, row.source_msg_id, row.evidence_layer
        ));
    }
    std::fs::write(&csv_path, csv)?;

    Ok(rows)
}
