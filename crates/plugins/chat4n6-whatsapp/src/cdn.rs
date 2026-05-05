use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CdnError {
    #[error("media key too short: expected 32+ bytes, got {0}")]
    KeyTooShort(usize),
    #[error("encrypted blob too short: expected {0}+ bytes, got {1}")]
    BlobTooShort(usize, usize),
    #[error("HMAC verification failed")]
    HmacMismatch,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnAcquisitionRecord {
    pub url_hash: String,              // SHA-256 hex of the URL (NOT the URL itself)
    pub media_key_hash: String,        // SHA-256 hex of the raw media key bytes
    pub timestamp_utc: String,         // ISO 8601 UTC timestamp of download attempt
    pub file_hash_result: Option<String>, // SHA-256 hex of plaintext bytes (None if download failed)
    pub file_size_bytes: Option<u64>,
    pub examiner: Option<String>,      // examiner identifier for chain of custody
    pub success: bool,
}

/// AES-256-CBC decrypt a WhatsApp media blob.
///
/// NOTE: This is a SIMPLIFIED implementation that does not perform full HKDF expansion.
/// Real WhatsApp uses HKDF to expand the 32-byte media_key to 112 bytes with a media-type
/// specific info string (e.g., "WhatsApp Image Keys\x00"). This MVP implementation directly
/// slices the key bytes:
/// - bytes 0..16: IV
/// - bytes 16..48: AES-256-CBC key
/// - HMAC verification is TODO — currently skipped
///
/// `media_key_bytes`: the raw 32-byte media key decoded from base64
/// `encrypted_bytes`: the full downloaded CDN blob
pub fn decrypt_whatsapp_media(
    media_key_bytes: &[u8],
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>, CdnError> {
    // STUB — not yet implemented
    let _ = (media_key_bytes, encrypted_bytes);
    Err(CdnError::KeyTooShort(0))
}

/// Generate a CDN acquisition log record for writing to cdn_acquisition.jsonl.
/// Does NOT perform the actual download — just creates the log entry.
pub fn build_acquisition_record(
    cdn_url: &str,
    media_key_bytes: &[u8],
    plaintext: Option<&[u8]>,
    examiner: Option<&str>,
) -> CdnAcquisitionRecord {
    // STUB — not yet implemented
    let _ = (cdn_url, media_key_bytes, plaintext, examiner);
    CdnAcquisitionRecord {
        url_hash: String::new(),
        media_key_hash: String::new(),
        timestamp_utc: String::new(),
        file_hash_result: None,
        file_size_bytes: None,
        examiner: None,
        success: false,
    }
}

/// Append a CdnAcquisitionRecord to a JSONL log file.
/// Creates the file if it doesn't exist.
pub fn append_to_log(
    log_path: &std::path::Path,
    record: &CdnAcquisitionRecord,
) -> Result<(), CdnError> {
    // STUB — not yet implemented
    let _ = (log_path, record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    // ── build_acquisition_record tests ───────────────────────────────────────

    #[test]
    fn test_build_acquisition_record_hashes_url_not_url() {
        let url = "https://mmg.whatsapp.net/v/t62.7114-24/supersecretfile";
        let key = vec![0xABu8; 32];
        let record = build_acquisition_record(url, &key, None, None);
        // url_hash should be a SHA-256 hex string, NOT the original URL
        assert_ne!(record.url_hash, url, "url_hash must not be the URL itself");
        assert!(!record.url_hash.is_empty(), "url_hash must not be empty");
        // Verify it's the expected SHA-256 hex
        let expected = hex::encode(Sha256::digest(url.as_bytes()));
        assert_eq!(record.url_hash, expected, "url_hash should be SHA-256 of the URL");
    }

    #[test]
    fn test_build_acquisition_record_hashes_media_key() {
        let url = "https://example.com/file";
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let record = build_acquisition_record(url, key, None, None);
        let expected = hex::encode(Sha256::digest(key));
        assert_eq!(record.media_key_hash, expected, "media_key_hash should be SHA-256 of key bytes");
        // Also verify it doesn't leak the actual key
        let key_hex = hex::encode(key);
        assert_ne!(record.media_key_hash, key_hex, "media_key_hash should be SHA-256, not hex of key");
    }

    #[test]
    fn test_build_acquisition_record_success_false_when_no_plaintext() {
        let key = vec![0u8; 32];
        let record = build_acquisition_record("https://example.com", &key, None, None);
        assert!(!record.success, "success should be false when plaintext is None");
        assert!(record.file_hash_result.is_none(), "file_hash_result should be None when no plaintext");
        assert!(record.file_size_bytes.is_none());
    }

    #[test]
    fn test_build_acquisition_record_success_true_when_plaintext_present() {
        let key = vec![0u8; 32];
        let plaintext = b"decrypted media content";
        let record = build_acquisition_record("https://example.com", &key, Some(plaintext), None);
        assert!(record.success, "success should be true when plaintext is provided");
        assert!(record.file_hash_result.is_some(), "file_hash_result should be set");
        assert_eq!(record.file_size_bytes, Some(plaintext.len() as u64));
    }

    #[test]
    fn test_build_acquisition_record_file_hash_is_sha256_of_plaintext() {
        let key = vec![0u8; 32];
        let plaintext = b"some test content";
        let record = build_acquisition_record("https://example.com", &key, Some(plaintext), None);
        let expected = hex::encode(Sha256::digest(plaintext));
        assert_eq!(record.file_hash_result.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn test_build_acquisition_record_examiner_preserved() {
        let key = vec![0u8; 32];
        let record = build_acquisition_record("https://example.com", &key, None, Some("examiner_alice"));
        assert_eq!(record.examiner.as_deref(), Some("examiner_alice"));
    }

    #[test]
    fn test_build_acquisition_record_timestamp_not_empty() {
        let key = vec![0u8; 32];
        let record = build_acquisition_record("https://example.com", &key, None, None);
        assert!(!record.timestamp_utc.is_empty(), "timestamp_utc must be set");
    }

    // ── append_to_log tests ───────────────────────────────────────────────────

    #[test]
    fn test_append_to_log_creates_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("cdn_acquisition.jsonl");
        assert!(!log_path.exists(), "log file should not exist before append");

        let key = vec![0u8; 32];
        let record = build_acquisition_record("https://example.com", &key, None, None);
        append_to_log(&log_path, &record).expect("append should succeed");

        assert!(log_path.exists(), "log file should be created after append");
    }

    #[test]
    fn test_append_to_log_appends_not_overwrites() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("cdn_acquisition.jsonl");

        let key = vec![0u8; 32];
        let r1 = build_acquisition_record("https://example.com/file1", &key, None, Some("e1"));
        let r2 = build_acquisition_record("https://example.com/file2", &key, None, Some("e2"));

        append_to_log(&log_path, &r1).unwrap();
        append_to_log(&log_path, &r2).unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "should have exactly 2 lines after 2 appends");
    }

    #[test]
    fn test_append_to_log_valid_json_per_line() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("cdn_acquisition.jsonl");

        let key = vec![0u8; 32];
        let r1 = build_acquisition_record("https://example.com/a", &key, Some(b"content"), Some("ex"));
        let r2 = build_acquisition_record("https://example.com/b", &key, None, None);

        append_to_log(&log_path, &r1).unwrap();
        append_to_log(&log_path, &r2).unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        for line in content.lines().filter(|l| !l.is_empty()) {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .expect("each line must be valid JSON");
            assert!(parsed.is_object(), "each line must be a JSON object");
        }
    }

    // ── decrypt_whatsapp_media tests ──────────────────────────────────────────

    #[test]
    fn test_decrypt_key_too_short_returns_error() {
        let short_key = vec![0u8; 10]; // too short — need 32+
        let blob = vec![0u8; 64];
        let result = decrypt_whatsapp_media(&short_key, &blob);
        assert!(matches!(result, Err(CdnError::KeyTooShort(_))),
            "should return KeyTooShort error for short key");
    }

    #[test]
    fn test_decrypt_blob_too_short_returns_error() {
        let key = vec![0u8; 32];
        let short_blob = vec![0u8; 5]; // too short — need at least 17 bytes (IV + 1 block)
        let result = decrypt_whatsapp_media(&key, &short_blob);
        assert!(matches!(result, Err(CdnError::BlobTooShort(_, _))),
            "should return BlobTooShort error for short blob");
    }

    #[test]
    fn test_decrypt_aes_cbc_basic() {
        // Construct a known AES-256-CBC encrypted payload using the aes+cbc crates
        // to test round-trip decryption.
        use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        // media_key: first 16 bytes = IV, bytes 16..48 = AES key (in simplified MVP mode)
        let iv_bytes = [0x01u8; 16];
        let aes_key_bytes = [0x02u8; 32];
        let mut media_key = Vec::new();
        media_key.extend_from_slice(&iv_bytes);   // bytes 0..16 = IV
        media_key.extend_from_slice(&aes_key_bytes); // bytes 16..48 = AES key

        let plaintext = b"Hello, WhatsApp media!";
        // Encrypt with AES-256-CBC using PKCS7 padding
        let mut buf = [0u8; 32]; // 32 bytes — enough for 22 bytes + padding
        let ciphertext = Aes256CbcEnc::new(&aes_key_bytes.into(), &iv_bytes.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap();

        let result = decrypt_whatsapp_media(&media_key, ciphertext);
        assert!(result.is_ok(), "decrypt should succeed for valid AES-256-CBC payload: {:?}", result);
        assert_eq!(result.unwrap(), plaintext, "decrypted bytes should match original plaintext");
    }

    // ── audit: no URL or key in serialized record ─────────────────────────────

    #[test]
    fn test_acquisition_record_no_url_in_serialized_json() {
        let url = "https://mmg.whatsapp.net/v/t62.7114-24/supersecret";
        let key = b"SECRETKEYNOTFORLOGS12345678901";
        let record = build_acquisition_record(url, key, None, None);
        let json = serde_json::to_string(&record).unwrap();

        assert!(!json.contains(url), "serialized JSON must NOT contain the original URL");
        // Also verify the raw key bytes don't appear (hex encoded)
        let key_hex = hex::encode(key);
        assert!(!json.contains(&key_hex), "serialized JSON must NOT contain the raw key hex");
    }

    #[test]
    fn test_acquisition_record_examiner_preserved_in_json() {
        let key = vec![0u8; 32];
        let record = build_acquisition_record("https://example.com", &key, None, Some("forensic_lab_01"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("forensic_lab_01"), "examiner should appear in JSON");
    }
}
