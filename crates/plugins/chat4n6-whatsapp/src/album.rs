use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlbumRecord {
    pub album_message_id: i64,
    pub expected_count: u32,
    pub actual_count: u32,
    pub missing_count: u32,
    pub note: Option<String>,
}

/// Given expected and actual image counts, produce an AlbumRecord.
/// If missing_count > 0, sets note to
/// "WhatsApp expected N images; M found; K missing — possible evidence gap"
pub fn analyze_album(album_message_id: i64, expected_count: u32, actual_count: u32) -> AlbumRecord {
    todo!("implement analyze_album")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_album_no_gap() {
        let r = analyze_album(1, 5, 5);
        assert_eq!(r.missing_count, 0);
        assert!(r.note.is_none());
    }

    #[test]
    fn test_partial_album_one_missing_note_set() {
        let r = analyze_album(2, 5, 4);
        assert_eq!(r.missing_count, 1);
        assert!(r.note.is_some());
        let note = r.note.unwrap();
        assert!(note.contains("5"), "note should mention expected count");
        assert!(note.contains("4"), "note should mention actual count");
        assert!(note.contains("1"), "note should mention missing count");
    }

    #[test]
    fn test_zero_expected_no_gap() {
        let r = analyze_album(3, 0, 0);
        assert_eq!(r.missing_count, 0);
        assert!(r.note.is_none());
    }

    #[test]
    fn test_actual_greater_than_expected_zero_missing() {
        let r = analyze_album(4, 3, 5);
        assert_eq!(r.missing_count, 0);
        assert!(r.note.is_none());
    }

    #[test]
    fn test_note_format_exact() {
        let r = analyze_album(5, 10, 7);
        let note = r.note.expect("note must be set when missing > 0");
        assert!(
            note.contains("WhatsApp expected"),
            "note format: got {note}"
        );
        assert!(note.contains("possible evidence gap"), "note format: got {note}");
    }

    #[test]
    fn test_zero_actual_of_five_expected() {
        let r = analyze_album(6, 5, 0);
        assert_eq!(r.missing_count, 5);
        assert!(r.note.is_some());
    }

    #[test]
    fn test_album_message_id_preserved() {
        let r = analyze_album(99, 3, 3);
        assert_eq!(r.album_message_id, 99);
    }

    #[test]
    fn test_counts_preserved() {
        let r = analyze_album(7, 8, 6);
        assert_eq!(r.expected_count, 8);
        assert_eq!(r.actual_count, 6);
        assert_eq!(r.missing_count, 2);
    }
}
