use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};

/// WhatsApp encrypted database format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptVersion {
    Crypt14,
    Crypt15,
}

/// Detect the crypt version from a filename by its extension.
///
/// Returns `Some(CryptVersion::Crypt14)` for `.crypt14` files,
/// `Some(CryptVersion::Crypt15)` for `.crypt15` files, and `None` otherwise.
pub fn detect_version(filename: &str) -> Option<CryptVersion> {
    if filename.ends_with(".crypt14") {
        Some(CryptVersion::Crypt14)
    } else if filename.ends_with(".crypt15") {
        Some(CryptVersion::Crypt15)
    } else {
        None
    }
}

/// Decrypt a WhatsApp crypt14/crypt15 database.
///
/// # Arguments
///
/// * `ciphertext` - The full encrypted database file contents (including the 67-byte header).
/// * `key` - Either a raw 32-byte AES key, or the full `key` file (≥158 bytes); the
///   32-byte AES key is extracted from bytes [126..158] of the key file.
/// * `version` - The crypt format version (currently treated identically for Crypt14/Crypt15).
///
/// # File layout
///
/// ```text
/// [0..67]    67-byte header (ignored during decryption)
/// [67..83]   16-byte AES-GCM IV / nonce
/// [83..N-16] AES-256-GCM ciphertext body
/// [N-16..N]  16-byte GCM authentication tag
/// ```
///
/// # Returns
///
/// The decrypted plaintext on success.
pub fn decrypt_db(ciphertext: &[u8], key: &[u8], _version: CryptVersion) -> Result<Vec<u8>> {
    // --- Key extraction ---
    let aes_key: &[u8] = match key.len() {
        32 => key,
        n if n >= 158 => &key[126..158],
        n => bail!(
            "key must be exactly 32 bytes or a key file of ≥158 bytes, got {} bytes",
            n
        ),
    };

    // --- Ciphertext length validation ---
    // Minimum: 67 (header) + 16 (IV) + 0 (body) + 16 (tag) = 99 bytes, but spec says > 83
    if ciphertext.len() <= 83 {
        bail!(
            "ciphertext too short: must be >83 bytes, got {} bytes",
            ciphertext.len()
        );
    }

    // --- Extract IV (nonce) ---
    // The file stores 16 bytes at [67..83]; AES-GCM uses a 12-byte (96-bit) nonce.
    // WhatsApp uses the first 12 bytes of the 16-byte field as the GCM nonce.
    let iv = &ciphertext[67..79]; // 12 bytes (AES-GCM standard nonce length)

    // --- Extract body and GCM tag ---
    let total = ciphertext.len();
    if total < 83 + 16 {
        bail!(
            "ciphertext too short to contain both body and GCM tag ({} bytes)",
            total
        );
    }
    let body = &ciphertext[83..total - 16];
    let tag = &ciphertext[total - 16..];

    // Reconstruct ciphertext+tag for aes-gcm (it expects them concatenated)
    let mut ct_with_tag = Vec::with_capacity(body.len() + tag.len());
    ct_with_tag.extend_from_slice(body);
    ct_with_tag.extend_from_slice(tag);

    // --- AES-256-GCM decryption ---
    let key_arr = Key::<Aes256Gcm>::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key_arr);
    let nonce = Nonce::from_slice(iv); // 12-byte nonce

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &ct_with_tag, aad: b"" })
        .map_err(|e| anyhow!("AES-256-GCM decryption failed: {}", e))
        .context("failed to decrypt WhatsApp database")?;

    Ok(plaintext)
}

/// Returns `true` if `data` begins with the SQLite3 magic header.
pub fn is_sqlite(data: &[u8]) -> bool {
    data.starts_with(b"SQLite format 3\x00")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };

    // ---- detect_version tests ----

    #[test]
    fn test_detect_version_crypt14() {
        assert_eq!(
            detect_version("msgstore.db.crypt14"),
            Some(CryptVersion::Crypt14)
        );
    }

    #[test]
    fn test_detect_version_crypt15() {
        assert_eq!(
            detect_version("msgstore.db.crypt15"),
            Some(CryptVersion::Crypt15)
        );
    }

    #[test]
    fn test_detect_version_unknown() {
        assert_eq!(detect_version("msgstore.db"), None);
    }

    // ---- decrypt_db error tests ----

    #[test]
    fn test_decrypt_db_wrong_key_length() {
        let key = vec![0u8; 10];
        let ciphertext = vec![0u8; 200];
        let result = decrypt_db(&ciphertext, &key, CryptVersion::Crypt14);
        assert!(result.is_err(), "expected error for 10-byte key");
    }

    #[test]
    fn test_decrypt_db_ciphertext_too_short() {
        let key = vec![0u8; 32];
        let ciphertext = vec![0u8; 10];
        let result = decrypt_db(&ciphertext, &key, CryptVersion::Crypt14);
        assert!(result.is_err(), "expected error for 10-byte ciphertext");
    }

    // ---- is_sqlite tests ----

    #[test]
    fn test_is_sqlite_positive() {
        let magic = b"SQLite format 3\x00some data here";
        assert!(is_sqlite(magic));
    }

    #[test]
    fn test_is_sqlite_negative() {
        let data = b"\x00\x01\x02\x03not a sqlite file";
        assert!(!is_sqlite(data));
    }

    // ---- roundtrip test ----

    /// Build a fake crypt14-format buffer, encrypt known plaintext, then decrypt and verify.
    ///
    /// File layout:
    ///   [0..67]   67-byte header (zeros)
    ///   [67..79]  12-byte AES-GCM nonce  (first 12 bytes of the 16-byte IV field)
    ///   [79..83]  4-byte padding          (remaining bytes of the 16-byte IV field, unused)
    ///   [83..N-16] ciphertext body
    ///   [N-16..N]  16-byte GCM tag
    #[test]
    fn test_decrypt_roundtrip() {
        let plaintext = b"Hello, WhatsApp forensics!";

        // 32-byte AES key (all 0x42 for test)
        let raw_key = [0x42u8; 32];

        // 12-byte AES-GCM nonce (standard GCM nonce size)
        let nonce_bytes = [0x11u8; 12];

        // Encrypt with aes-gcm directly
        let key_arr = Key::<Aes256Gcm>::from_slice(&raw_key);
        let cipher = Aes256Gcm::new(key_arr);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encryption failed");
        // `encrypted` = ciphertext body + GCM tag (last 16 bytes)

        let body = &encrypted[..encrypted.len() - 16];
        let tag = &encrypted[encrypted.len() - 16..];

        // Build the fake crypt14 file:
        // [0..67]   = 67-byte header
        // [67..79]  = 12-byte nonce
        // [79..83]  = 4-byte padding (zeroes; not used by decryptor)
        // [83..N-16]= ciphertext body
        // [N-16..N] = 16-byte GCM tag
        let mut file = Vec::new();
        file.extend_from_slice(&[0u8; 67]); // header
        file.extend_from_slice(&nonce_bytes); // 12-byte nonce at [67..79]
        file.extend_from_slice(&[0u8; 4]);    // 4-byte padding at [79..83]
        file.extend_from_slice(body);         // ciphertext body
        file.extend_from_slice(tag);          // GCM tag

        // Decrypt using our function with the 32-byte key directly
        let decrypted =
            decrypt_db(&file, &raw_key, CryptVersion::Crypt14).expect("decryption failed");

        assert_eq!(decrypted, plaintext);
    }
}
