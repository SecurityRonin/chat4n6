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
}
