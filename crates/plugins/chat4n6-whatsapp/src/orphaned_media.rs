use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrphanedMedia {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub extension: String,
    pub file_hash: Option<String>,          // SHA-256 hex, computed lazily
    pub linked_media_path: Option<String>,  // set after rescue pass
}

/// Recognized media file extensions (lowercase).
const RECOGNIZED_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "mp4", "mov", "avi", "opus", "ogg", "mp3", "aac",
    "pdf", "doc", "docx", "webp",
];

fn is_recognized_extension(ext: &str) -> bool {
    let lower = ext.to_lowercase();
    RECOGNIZED_EXTENSIONS.contains(&lower.as_str())
}

/// Walk `media_dir` and find files with recognized extensions that are NOT
/// in the `known_paths` set. Return them as OrphanedMedia records (file_hash=None initially).
pub fn scan_orphaned_media(
    media_dir: &Path,
    known_paths: &HashSet<String>,
) -> Vec<OrphanedMedia> {
    let mut orphans = Vec::new();
    let read_dir = match std::fs::read_dir(media_dir) {
        Ok(rd) => rd,
        Err(_) => return orphans,
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if !is_recognized_extension(&ext) {
            continue;
        }
        let path_str = path.to_string_lossy().to_string();
        if known_paths.contains(&path_str) {
            continue;
        }
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        orphans.push(OrphanedMedia {
            file_path: path,
            file_size,
            extension: ext,
            file_hash: None,
            linked_media_path: None,
        });
    }
    orphans
}

/// For each orphan, compute SHA-256 of its bytes and store in file_hash.
pub fn hash_orphans(orphans: &mut Vec<OrphanedMedia>) {
    use sha2::{Digest, Sha256};
    for orphan in orphans.iter_mut() {
        if let Ok(bytes) = std::fs::read(&orphan.file_path) {
            orphan.file_hash = Some(hex::encode(Sha256::digest(&bytes)));
        }
    }
}

/// Rescue pass: match orphans to missing_media entries by file size first,
/// then by SHA-256 hash. Returns the number of matches made.
///
/// `missing_media`: list of (expected_file_path, file_size, file_hash_base64) for
/// media rows whose file no longer exists at their recorded path.
pub fn rescue_orphans(
    orphans: &mut Vec<OrphanedMedia>,
    missing_media: &[(String, u64, Option<String>)],
) -> usize {
    use base64::Engine;
    let mut matched = 0;

    for orphan in orphans.iter_mut() {
        if orphan.linked_media_path.is_some() {
            continue; // already rescued
        }
        for (expected_path, expected_size, expected_hash_b64) in missing_media {
            // Size must match first
            if orphan.file_size != *expected_size {
                continue;
            }
            // If hash provided, must also match
            if let Some(expected_b64) = expected_hash_b64 {
                // Decode base64 hash to bytes, then to hex for comparison
                let expected_hex = base64::engine::general_purpose::STANDARD
                    .decode(expected_b64)
                    .ok()
                    .map(hex::encode);
                if let Some(exp_hex) = expected_hex {
                    if orphan.file_hash.as_deref() != Some(exp_hex.as_str()) {
                        continue; // hash mismatch — reject size collision
                    }
                }
            }
            orphan.linked_media_path = Some(expected_path.clone());
            matched += 1;
            break;
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    // ── scan_orphaned_media tests ─────────────────────────────────────────────

    #[test]
    fn test_scan_finds_files_not_in_known_set() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "orphan.jpg", b"fakejpeg");
        write_file(dir.path(), "also_orphan.mp4", b"fakemp4");

        let known: HashSet<String> = HashSet::new();
        let orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 2, "should find both orphans");
    }

    #[test]
    fn test_scan_excludes_known_files() {
        let dir = tempdir().unwrap();
        let path = write_file(dir.path(), "known.jpg", b"fakejpeg");
        write_file(dir.path(), "orphan.png", b"fakepng");

        let mut known = HashSet::new();
        known.insert(path.to_string_lossy().to_string());
        let orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 1, "should find only the orphan, not the known file");
        assert!(orphans[0].file_path.file_name().unwrap() == "orphan.png");
    }

    #[test]
    fn test_scan_ignores_unrecognized_extensions() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "script.py", b"print('hi')");
        write_file(dir.path(), "image.jpg", b"fakejpeg");

        let known: HashSet<String> = HashSet::new();
        let orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 1, "should only find .jpg, not .py");
        assert_eq!(orphans[0].extension.to_lowercase(), "jpg");
    }

    #[test]
    fn test_scan_records_correct_file_size() {
        let dir = tempdir().unwrap();
        let content = b"hello world";
        write_file(dir.path(), "test.jpg", content);

        let known: HashSet<String> = HashSet::new();
        let orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].file_size, content.len() as u64);
    }

    #[test]
    fn test_scan_file_hash_initially_none() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "test.png", b"fakepng");

        let known: HashSet<String> = HashSet::new();
        let orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 1);
        assert!(orphans[0].file_hash.is_none(), "file_hash should be None before hashing");
    }

    // ── hash_orphans tests ────────────────────────────────────────────────────

    #[test]
    fn test_hash_orphans_computes_correct_sha256() {
        let dir = tempdir().unwrap();
        let content = b"test content for hashing";
        write_file(dir.path(), "test.jpg", content);

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        assert_eq!(orphans.len(), 1);

        hash_orphans(&mut orphans);

        let hash = orphans[0].file_hash.as_ref().expect("hash should be set");
        // Compute expected SHA-256 manually
        use sha2::{Digest, Sha256};
        let expected = hex::encode(Sha256::digest(content));
        assert_eq!(*hash, expected, "SHA-256 hash should match expected value");
    }

    #[test]
    fn test_hash_orphans_sets_all_hashes() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "a.jpg", b"aaa");
        write_file(dir.path(), "b.mp4", b"bbb");

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        hash_orphans(&mut orphans);

        for o in &orphans {
            assert!(o.file_hash.is_some(), "all orphans should have hashes after hash_orphans");
        }
    }

    // ── rescue_orphans tests ──────────────────────────────────────────────────

    #[test]
    fn test_rescue_matches_by_size_and_hash() {
        let dir = tempdir().unwrap();
        let content = b"media content to rescue";
        write_file(dir.path(), "orphan.jpg", content);

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        hash_orphans(&mut orphans);

        use sha2::{Digest, Sha256};
        let hash_hex = hex::encode(Sha256::digest(content));
        // Convert hex to base64 for the missing_media format
        use base64::Engine;
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(
            &hex::decode(&hash_hex).unwrap()
        );

        let missing = vec![
            ("expected/path/media.jpg".to_string(), content.len() as u64, Some(hash_b64)),
        ];

        let matched = rescue_orphans(&mut orphans, &missing);
        assert_eq!(matched, 1, "should match 1 orphan");
        assert!(orphans[0].linked_media_path.is_some(), "linked_media_path should be set after rescue");
    }

    #[test]
    fn test_rescue_does_not_match_when_hash_differs() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "orphan.jpg", b"actual content");

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        hash_orphans(&mut orphans);

        use base64::Engine;
        let wrong_hash_b64 = base64::engine::general_purpose::STANDARD.encode(b"wrong hash bytes");

        let missing = vec![
            ("expected/path/media.jpg".to_string(), b"actual content".len() as u64, Some(wrong_hash_b64)),
        ];

        let matched = rescue_orphans(&mut orphans, &missing);
        assert_eq!(matched, 0, "should not match when hash differs even if size matches");
    }

    #[test]
    fn test_rescue_does_not_match_when_size_differs() {
        let dir = tempdir().unwrap();
        write_file(dir.path(), "orphan.jpg", b"content");

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        hash_orphans(&mut orphans);

        let missing = vec![
            ("expected/path/media.jpg".to_string(), 99999u64, None),
        ];

        let matched = rescue_orphans(&mut orphans, &missing);
        assert_eq!(matched, 0, "should not match when size differs");
    }

    #[test]
    fn test_rescue_returns_count_of_matches() {
        let dir = tempdir().unwrap();
        let content1 = b"file one content";
        let content2 = b"file two content";
        write_file(dir.path(), "a.jpg", content1);
        write_file(dir.path(), "b.mp4", content2);

        let known: HashSet<String> = HashSet::new();
        let mut orphans = scan_orphaned_media(dir.path(), &known);
        hash_orphans(&mut orphans);

        use sha2::{Digest, Sha256};
        use base64::Engine;
        let h1 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(content1).as_slice());
        let h2 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(content2).as_slice());

        let missing = vec![
            ("path/a.jpg".to_string(), content1.len() as u64, Some(h1)),
            ("path/b.mp4".to_string(), content2.len() as u64, Some(h2)),
        ];

        let matched = rescue_orphans(&mut orphans, &missing);
        assert_eq!(matched, 2, "should match both orphans");
    }
}
