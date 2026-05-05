/// Per-contact HTML forensic dossier.
///
/// Builds activity statistics for a single contact and renders
/// a self-contained, no-external-deps HTML report.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Activity heatmap: hour (0-23) → message count
pub type HourlyHeatmap = [u32; 24];

/// Activity heatmap: weekday (0=Mon, 6=Sun) → message count
pub type WeeklyHeatmap = [u32; 7];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactActivityStats {
    pub jid: String,
    pub display_name: Option<String>,
    pub total_sent: u32,
    pub total_received: u32,
    pub total_media_sent: u32,
    pub total_calls: u32,
    pub hourly_heatmap: HourlyHeatmap,
    pub weekly_heatmap: WeeklyHeatmap,
    pub first_message_ms: Option<i64>,
    pub last_message_ms: Option<i64>,
    pub groups_in_common: Vec<GroupMembership>,
    pub top_link_domains: Vec<(String, u32)>,
    pub reactions_given: Vec<(String, u32)>,
    pub reactions_received: Vec<(String, u32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub group_jid: String,
    pub group_name: Option<String>,
    pub role: GroupRole,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GroupRole {
    Member,
    Admin,
    SuperAdmin,
}

// ---------------------------------------------------------------------------
// HTML escaping stub
// ---------------------------------------------------------------------------

pub(crate) fn html_escape(_s: &str) -> String {
    unimplemented!("RED: html_escape not yet implemented")
}

// ---------------------------------------------------------------------------
// Stubs — RED phase: these panic so tests fail
// ---------------------------------------------------------------------------

pub fn build_contact_stats(
    _contact_jid: &str,
    _display_name: Option<&str>,
    _messages: &[&chat4n6_plugin_api::Message],
    _tz_offset_secs: i32,
) -> ContactActivityStats {
    unimplemented!("RED: build_contact_stats not yet implemented")
}

pub fn render_html(_stats: &ContactActivityStats) -> String {
    unimplemented!("RED: render_html not yet implemented")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{
        EvidenceSource, ForensicTimestamp, MediaRef, Message, MessageContent, Reaction,
    };

    fn make_ts(ms: i64) -> ForensicTimestamp {
        ForensicTimestamp::from_millis(ms, 0)
    }

    fn make_text_msg(
        id: i64,
        sender_jid: Option<&str>,
        from_me: bool,
        ts_ms: i64,
        text: &str,
    ) -> Message {
        Message {
            id,
            chat_id: 1,
            sender_jid: sender_jid.map(str::to_string),
            from_me,
            timestamp: make_ts(ts_ms),
            content: MessageContent::Text(text.to_string()),
            reactions: vec![],
            quoted_message: None,
            source: EvidenceSource::Live,
            row_offset: 0,
        }
    }

    fn make_media_msg(
        id: i64,
        sender_jid: Option<&str>,
        from_me: bool,
        ts_ms: i64,
    ) -> Message {
        Message {
            id,
            chat_id: 1,
            sender_jid: sender_jid.map(str::to_string),
            from_me,
            timestamp: make_ts(ts_ms),
            content: MessageContent::Media(MediaRef {
                file_path: "photo.jpg".to_string(),
                mime_type: "image/jpeg".to_string(),
                file_size: 1024,
                extracted_name: None,
                thumbnail_b64: None,
                duration_secs: None,
                file_hash: None,
                encrypted_hash: None,
                cdn_url: None,
                media_key_b64: None,
            }),
            reactions: vec![],
            quoted_message: None,
            source: EvidenceSource::Live,
            row_offset: 0,
        }
    }

    const CONTACT_JID: &str = "15551234567@s.whatsapp.net";

    // ---- build_contact_stats ----

    #[test]
    fn test_stats_counts_sent_messages() {
        let m1 = make_text_msg(1, Some(CONTACT_JID), false, 0, "hello");
        let m2 = make_text_msg(2, Some(CONTACT_JID), false, 1000, "world");
        let msgs: Vec<&Message> = vec![&m1, &m2];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert_eq!(stats.total_sent, 2);
    }

    #[test]
    fn test_stats_counts_received_messages() {
        let m1 = make_text_msg(1, None, true, 0, "hi");
        let m2 = make_text_msg(2, None, true, 1000, "there");
        let msgs: Vec<&Message> = vec![&m1, &m2];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert_eq!(stats.total_received, 2);
    }

    #[test]
    fn test_stats_hourly_heatmap_populated() {
        // 2024-01-15 14:07:00 UTC
        let ts_ms: i64 = 1_705_323_820_000;
        let m = make_text_msg(1, Some(CONTACT_JID), false, ts_ms, "test");
        let msgs: Vec<&Message> = vec![&m];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert!(stats.hourly_heatmap[14] > 0);
    }

    #[test]
    fn test_stats_weekly_heatmap_populated() {
        // 2024-01-15 is a Monday → weekday index 0
        let ts_ms: i64 = 1_705_323_820_000;
        let m = make_text_msg(1, Some(CONTACT_JID), false, ts_ms, "test");
        let msgs: Vec<&Message> = vec![&m];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert!(stats.weekly_heatmap[0] > 0);
    }

    #[test]
    fn test_stats_first_last_message_timestamps() {
        let m1 = make_text_msg(1, Some(CONTACT_JID), false, 1000, "first");
        let m2 = make_text_msg(2, Some(CONTACT_JID), false, 5000, "middle");
        let m3 = make_text_msg(3, Some(CONTACT_JID), false, 3000, "between");
        let msgs: Vec<&Message> = vec![&m1, &m2, &m3];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert_eq!(stats.first_message_ms, Some(1000));
        assert_eq!(stats.last_message_ms, Some(5000));
    }

    #[test]
    fn test_stats_empty_messages_returns_defaults() {
        let msgs: Vec<&Message> = vec![];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert_eq!(stats.total_sent, 0);
        assert_eq!(stats.total_received, 0);
        assert_eq!(stats.total_media_sent, 0);
        assert_eq!(stats.first_message_ms, None);
        assert_eq!(stats.last_message_ms, None);
        assert_eq!(stats.hourly_heatmap, [0u32; 24]);
        assert_eq!(stats.weekly_heatmap, [0u32; 7]);
    }

    #[test]
    fn test_stats_top_link_domains_sorted() {
        let m1 = make_text_msg(1, Some(CONTACT_JID), false, 1000, "check https://example.com/foo");
        let m2 = make_text_msg(2, Some(CONTACT_JID), false, 2000, "also https://example.com/bar and https://other.com/baz");
        let msgs: Vec<&Message> = vec![&m1, &m2];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert!(!stats.top_link_domains.is_empty());
        assert_eq!(stats.top_link_domains[0].0, "example.com");
        assert_eq!(stats.top_link_domains[0].1, 2);
    }

    #[test]
    fn test_stats_reactions_given_counted() {
        let mut m1 = make_text_msg(1, Some(CONTACT_JID), false, 1000, "hi");
        m1.reactions.push(Reaction {
            emoji: "👍".to_string(),
            reactor_jid: CONTACT_JID.to_string(),
            timestamp: make_ts(1100),
            source: EvidenceSource::Live,
        });
        m1.reactions.push(Reaction {
            emoji: "👍".to_string(),
            reactor_jid: CONTACT_JID.to_string(),
            timestamp: make_ts(1200),
            source: EvidenceSource::Live,
        });
        let msgs: Vec<&Message> = vec![&m1];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert!(!stats.reactions_given.is_empty());
        assert_eq!(stats.reactions_given[0].0, "👍");
        assert_eq!(stats.reactions_given[0].1, 2);
    }

    // ---- render_html ----

    #[test]
    fn test_render_html_contains_jid() {
        let stats = ContactActivityStats {
            jid: CONTACT_JID.to_string(),
            ..Default::default()
        };
        let html = render_html(&stats);
        assert!(html.contains(CONTACT_JID));
    }

    #[test]
    fn test_render_html_contains_display_name() {
        let stats = ContactActivityStats {
            jid: CONTACT_JID.to_string(),
            display_name: Some("Alice Smith".to_string()),
            ..Default::default()
        };
        let html = render_html(&stats);
        assert!(html.contains("Alice Smith"));
    }

    #[test]
    fn test_render_html_is_valid_structure() {
        let stats = ContactActivityStats::default();
        let html = render_html(&stats);
        let trimmed = html.trim();
        assert!(trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<html"));
        assert!(trimmed.ends_with("</html>"));
    }

    #[test]
    fn test_render_html_contains_heatmap_table() {
        let stats = ContactActivityStats::default();
        let html = render_html(&stats);
        assert!(html.contains("<table"));
    }

    #[test]
    fn test_render_html_no_external_resources() {
        let stats = ContactActivityStats {
            jid: "test@s.whatsapp.net".to_string(),
            ..Default::default()
        };
        let html = render_html(&stats);
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn test_render_html_stats_zero_still_renders() {
        let stats = ContactActivityStats::default();
        let html = render_html(&stats);
        assert!(!html.is_empty());
    }

    #[test]
    fn test_render_html_escapes_display_name() {
        let stats = ContactActivityStats {
            jid: "x@s.whatsapp.net".to_string(),
            display_name: Some("<script>alert(1)</script>".to_string()),
            ..Default::default()
        };
        let html = render_html(&stats);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    // ---- additional ----

    #[test]
    fn test_stats_media_sent_counted() {
        let m1 = make_media_msg(1, Some(CONTACT_JID), false, 1000);
        let m2 = make_media_msg(2, Some(CONTACT_JID), false, 2000);
        let m3 = make_media_msg(3, None, true, 3000);
        let msgs: Vec<&Message> = vec![&m1, &m2, &m3];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert_eq!(stats.total_media_sent, 2);
    }

    #[test]
    fn test_stats_display_name_stored() {
        let msgs: Vec<&Message> = vec![];
        let stats = build_contact_stats(CONTACT_JID, Some("Bob"), &msgs, 0);
        assert_eq!(stats.display_name, Some("Bob".to_string()));
    }

    #[test]
    fn test_html_escape_helper() {
        assert_eq!(
            html_escape("<b>\"test\" & 'it'</b>"),
            "&lt;b&gt;&quot;test&quot; &amp; &#39;it&#39;&lt;/b&gt;"
        );
    }
}
