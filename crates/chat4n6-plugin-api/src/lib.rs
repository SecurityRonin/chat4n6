// chat4n6-plugin-api

pub mod fs;
pub mod types;

pub use fs::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_source_display() {
        assert_eq!(format!("{}", EvidenceSource::Live), "LIVE");
        assert_eq!(format!("{}", EvidenceSource::WalPending), "WAL-PENDING");
        assert_eq!(format!("{}", EvidenceSource::WalHistoric), "WAL-HISTORIC");
        assert_eq!(format!("{}", EvidenceSource::Freelist), "FREELIST");
        assert_eq!(format!("{}", EvidenceSource::FtsOnly), "FTS-ONLY");
        assert_eq!(
            format!("{}", EvidenceSource::CarvedUnalloc { confidence_pct: 94 }),
            "CARVED-UNALLOC 94%"
        );
        assert_eq!(format!("{}", EvidenceSource::CarvedDb), "CARVED-DB");
    }

    #[test]
    fn test_new_evidence_source_display() {
        assert_eq!(EvidenceSource::WalDeleted.to_string(), "WAL-DELETED");
        assert_eq!(EvidenceSource::Journal.to_string(), "JOURNAL");
        assert_eq!(EvidenceSource::IndexRecovery.to_string(), "INDEX-RECOVERY");
        assert_eq!(EvidenceSource::CarvedOverflow.to_string(), "CARVED-OVERFLOW");
        assert_eq!(
            EvidenceSource::CarvedIntraPage { confidence_pct: 75 }.to_string(),
            "CARVED-INTRA-PAGE 75%"
        );
    }

    #[test]
    fn test_timestamp_utc_str() {
        let ts = ForensicTimestamp::from_millis(1710513127000, 0);
        assert_eq!(ts.utc_str(), "2024-03-15 14:32:07 UTC");
    }

    #[test]
    fn test_timestamp_local_str_positive_offset() {
        let ts = ForensicTimestamp::from_millis(1710513127000, 8 * 3600);
        assert_eq!(
            ts.local_str(),
            "2024-03-15 14:32:07 UTC  |  2024-03-15 22:32:07 +08:00"
        );
    }

    #[test]
    fn test_timestamp_local_str_negative_offset() {
        let ts = ForensicTimestamp::from_millis(1710513127000, -5 * 3600);
        assert_eq!(
            ts.local_str(),
            "2024-03-15 14:32:07 UTC  |  2024-03-15 09:32:07 -05:00"
        );
    }

    #[test]
    fn test_timestamp_local_str_utc() {
        let ts = ForensicTimestamp::from_millis(1710513127000, 0);
        assert_eq!(
            ts.local_str(),
            "2024-03-15 14:32:07 UTC  |  2024-03-15 14:32:07 +00:00"
        );
    }

    #[test]
    fn test_timestamp_local_str_subhour_offset() {
        // India Standard Time = UTC+05:30
        let ts = ForensicTimestamp::from_millis(1710513127000, 5 * 3600 + 30 * 60);
        assert_eq!(
            ts.local_str(),
            "2024-03-15 14:32:07 UTC  |  2024-03-15 20:02:07 +05:30"
        );
    }

    #[test]
    fn test_extraction_result_default_empty() {
        let r = ExtractionResult::default();
        assert!(r.chats.is_empty());
        assert!(r.calls.is_empty());
        assert!(r.wal_deltas.is_empty());
        assert!(r.timezone_offset_seconds.is_none());
    }

    #[test]
    fn test_call_result_display() {
        assert_eq!(format!("{}", CallResult::Connected), "Connected");
        assert_eq!(format!("{}", CallResult::Missed), "Missed");
        assert_eq!(format!("{}", CallResult::Rejected), "Rejected");
        assert_eq!(format!("{}", CallResult::Unavailable), "Unavailable");
        assert_eq!(format!("{}", CallResult::Cancelled), "Cancelled");
        assert_eq!(format!("{}", CallResult::Unknown), "Unknown");
    }

    #[test]
    fn test_call_result_from_int() {
        assert_eq!(CallResult::from(0i64), CallResult::Unknown);
        assert_eq!(CallResult::from(1i64), CallResult::Connected);
        assert_eq!(CallResult::from(2i64), CallResult::Rejected);
        assert_eq!(CallResult::from(3i64), CallResult::Unavailable);
        assert_eq!(CallResult::from(4i64), CallResult::Missed);
        assert_eq!(CallResult::from(5i64), CallResult::Cancelled);
        assert_eq!(CallResult::from(99i64), CallResult::Unknown);
    }

    #[test]
    fn test_call_result_default() {
        assert_eq!(CallResult::default(), CallResult::Unknown);
    }

    // ── F5: MediaRef new fields tests ─────────────────────────────────────────

    #[test]
    fn test_media_ref_new_fields_default_none() {
        // Construct MediaRef with only the original fields — new fields should default to None
        let m = MediaRef {
            file_path: "path/to/file.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            file_size: 1024,
            extracted_name: None,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        };
        assert!(m.file_hash.is_none());
        assert!(m.encrypted_hash.is_none());
        assert!(m.cdn_url.is_none());
        assert!(m.media_key_b64.is_none());
    }

    #[test]
    fn test_media_ref_serialize_roundtrip_with_hashes() {
        let m = MediaRef {
            file_path: "path/to/file.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            file_size: 2048,
            extracted_name: Some("photo.jpg".to_string()),
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: Some("abc123def456".to_string()),
            encrypted_hash: Some("enc789xyz000".to_string()),
            cdn_url: Some("https://mmg.whatsapp.net/v/abc".to_string()),
            media_key_b64: Some("dGVzdGtleQ==".to_string()),
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let back: MediaRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, back);
        assert_eq!(back.file_hash.as_deref(), Some("abc123def456"));
        assert_eq!(back.encrypted_hash.as_deref(), Some("enc789xyz000"));
        assert_eq!(back.cdn_url.as_deref(), Some("https://mmg.whatsapp.net/v/abc"));
        assert_eq!(back.media_key_b64.as_deref(), Some("dGVzdGtleQ=="));
    }

    #[test]
    fn test_media_ref_deserialize_old_json_without_new_fields() {
        // Old JSON without new fields — should deserialize without error, new fields default to None
        let old_json = r#"{
            "file_path": "path/to/file.mp4",
            "mime_type": "video/mp4",
            "file_size": 4096,
            "extracted_name": null,
            "thumbnail_b64": null,
            "duration_secs": 30
        }"#;
        let m: MediaRef = serde_json::from_str(old_json).expect("must deserialize old JSON without error");
        assert!(m.file_hash.is_none(), "file_hash should default to None");
        assert!(m.encrypted_hash.is_none(), "encrypted_hash should default to None");
        assert!(m.cdn_url.is_none(), "cdn_url should default to None");
        assert!(m.media_key_b64.is_none(), "media_key_b64 should default to None");
        assert_eq!(m.mime_type, "video/mp4");
        assert_eq!(m.file_size, 4096);
        assert_eq!(m.duration_secs, Some(30));
    }

    #[test]
    fn test_encrypted_hash_differs_from_file_hash() {
        // Document semantic difference: encrypted_hash is SHA-256 of the CDN-encrypted bytes;
        // file_hash is SHA-256 of the plaintext decrypted bytes.
        // Same file re-shared by two users may have same encrypted_hash but different file_hash
        // after independent re-encryption (or same file_hash if WhatsApp deduplicates CDN upload).
        // This test simply asserts that the two fields are distinct and independently settable.
        let m = MediaRef {
            file_path: "file.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            file_size: 100,
            extracted_name: None,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: Some("plaintext_sha256_hex".to_string()),
            encrypted_hash: Some("encrypted_blob_sha256_hex".to_string()),
            cdn_url: None,
            media_key_b64: None,
        };
        assert_ne!(
            m.file_hash.as_deref(),
            m.encrypted_hash.as_deref(),
            "file_hash (plaintext) and encrypted_hash (CDN blob) are semantically distinct"
        );
    }
}
