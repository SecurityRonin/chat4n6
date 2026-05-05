use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusStats {
    pub view_count: u32,
    pub reaction_count: u32,
    pub reactions: Vec<StatusReaction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReaction {
    pub reactor_jid: String,
    pub emoji: String,
    pub timestamp_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusRecord {
    pub message_id: i64,
    pub poster_jid: String,
    pub status_type: StatusType,
    pub timestamp_ms: i64,
    pub stats: Option<StatusStats>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StatusType {
    Image,       // type 1
    Text,        // type 2
    Video,       // type 3
    Gif,         // type 43
    Audio,       // type 44
    Unknown(i32),
}

/// Parse a status type integer.
pub fn classify_status_type(msg_type: i32) -> StatusType {
    todo!("implement classify_status_type")
}

/// Merge status stats from status.db into a StatusRecord.
/// If stats is None (status.db unavailable), record.stats remains None.
pub fn enrich_with_stats(record: &mut StatusRecord, stats: Option<StatusStats>) {
    todo!("implement enrich_with_stats")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(msg_type: i32) -> StatusRecord {
        StatusRecord {
            message_id: 1,
            poster_jid: "alice@s.whatsapp.net".to_string(),
            status_type: classify_status_type(msg_type),
            timestamp_ms: 1000,
            stats: None,
        }
    }

    #[test]
    fn test_type_1_image() {
        assert_eq!(classify_status_type(1), StatusType::Image);
    }

    #[test]
    fn test_type_2_text() {
        assert_eq!(classify_status_type(2), StatusType::Text);
    }

    #[test]
    fn test_type_3_video() {
        assert_eq!(classify_status_type(3), StatusType::Video);
    }

    #[test]
    fn test_type_43_gif() {
        assert_eq!(classify_status_type(43), StatusType::Gif);
    }

    #[test]
    fn test_type_44_audio() {
        assert_eq!(classify_status_type(44), StatusType::Audio);
    }

    #[test]
    fn test_unknown_type() {
        assert_eq!(classify_status_type(99), StatusType::Unknown(99));
    }

    #[test]
    fn test_enrich_with_stats() {
        let mut r = make_record(1);
        let stats = StatusStats {
            view_count: 42,
            reaction_count: 3,
            reactions: vec![StatusReaction {
                reactor_jid: "bob@s.whatsapp.net".to_string(),
                emoji: "❤️".to_string(),
                timestamp_ms: Some(2000),
            }],
        };
        enrich_with_stats(&mut r, Some(stats));
        let s = r.stats.expect("stats should be set");
        assert_eq!(s.view_count, 42);
        assert_eq!(s.reaction_count, 3);
        assert_eq!(s.reactions.len(), 1);
    }

    #[test]
    fn test_enrich_with_none_is_noop() {
        let mut r = make_record(2);
        enrich_with_stats(&mut r, None);
        assert!(r.stats.is_none());
    }

    #[test]
    fn test_view_count_preserved() {
        let mut r = make_record(3);
        enrich_with_stats(&mut r, Some(StatusStats { view_count: 100, reaction_count: 0, reactions: vec![] }));
        assert_eq!(r.stats.unwrap().view_count, 100);
    }

    #[test]
    fn test_reactions_list_preserved() {
        let mut r = make_record(1);
        let reactions = vec![
            StatusReaction { reactor_jid: "a@s.whatsapp.net".to_string(), emoji: "👍".to_string(), timestamp_ms: None },
            StatusReaction { reactor_jid: "b@s.whatsapp.net".to_string(), emoji: "🔥".to_string(), timestamp_ms: Some(5000) },
        ];
        enrich_with_stats(&mut r, Some(StatusStats { view_count: 0, reaction_count: 2, reactions }));
        assert_eq!(r.stats.unwrap().reactions.len(), 2);
    }
}
