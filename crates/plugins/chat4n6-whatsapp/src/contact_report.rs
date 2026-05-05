/// Per-contact HTML forensic dossier.
///
/// Builds activity statistics for a single contact and renders
/// a self-contained, no-external-deps HTML report.

use std::collections::HashMap;
use chrono::{DateTime, Datelike, FixedOffset, Timelike};
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
// HTML escaping
// ---------------------------------------------------------------------------

pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Domain extraction helper
// ---------------------------------------------------------------------------

fn extract_domains(text: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for part in text.split("://").skip(1) {
        let host = part.split('/').next().unwrap_or("").split('?').next().unwrap_or("");
        let host = host.split('#').next().unwrap_or("").trim();
        if !host.is_empty() {
            domains.push(host.to_lowercase());
        }
    }
    domains
}

// ---------------------------------------------------------------------------
// Core statistics builder
// ---------------------------------------------------------------------------

pub fn build_contact_stats(
    contact_jid: &str,
    display_name: Option<&str>,
    messages: &[&chat4n6_plugin_api::Message],
    tz_offset_secs: i32,
) -> ContactActivityStats {
    use chat4n6_plugin_api::MessageContent;

    let offset = FixedOffset::east_opt(tz_offset_secs).unwrap_or(FixedOffset::east_opt(0).unwrap());
    let mut stats = ContactActivityStats {
        jid: contact_jid.to_string(),
        display_name: display_name.map(|s| s.to_string()),
        ..Default::default()
    };

    let mut domain_counts: HashMap<String, u32> = HashMap::new();
    let mut reactions_given: HashMap<String, u32> = HashMap::new();
    let mut reactions_received: HashMap<String, u32> = HashMap::new();
    let mut first_ms: Option<i64> = None;
    let mut last_ms: Option<i64> = None;

    for msg in messages {
        let ts_ms = msg.timestamp.utc.timestamp_millis();
        first_ms = Some(first_ms.map_or(ts_ms, |m: i64| m.min(ts_ms)));
        last_ms = Some(last_ms.map_or(ts_ms, |m: i64| m.max(ts_ms)));

        // Determine heatmap bucket via local time
        let local: DateTime<FixedOffset> = msg.timestamp.utc.with_timezone(&offset);
        let hour = local.hour() as usize;
        let weekday = local.weekday().num_days_from_monday() as usize; // Mon=0, Sun=6

        if msg.from_me {
            stats.total_received += 1;
        } else {
            stats.total_sent += 1;
        }

        stats.hourly_heatmap[hour] += 1;
        stats.weekly_heatmap[weekday] += 1;

        // Media count (sent by contact = not from_me)
        if !msg.from_me {
            if let MessageContent::Media(_) = &msg.content {
                stats.total_media_sent += 1;
            }
        }

        // Domain extraction from text messages
        if let MessageContent::Text(text) = &msg.content {
            for domain in extract_domains(text) {
                *domain_counts.entry(domain).or_insert(0) += 1;
            }
        }

        // Reactions given by contact, received by contact
        for reaction in &msg.reactions {
            if reaction.reactor_jid == contact_jid {
                *reactions_given.entry(reaction.emoji.clone()).or_insert(0) += 1;
            } else {
                *reactions_received.entry(reaction.emoji.clone()).or_insert(0) += 1;
            }
        }
    }

    stats.first_message_ms = first_ms;
    stats.last_message_ms = last_ms;

    // Sort domains by count desc
    let mut domains_vec: Vec<(String, u32)> = domain_counts.into_iter().collect();
    domains_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    stats.top_link_domains = domains_vec;

    // Sort reactions by count desc
    let mut rg: Vec<(String, u32)> = reactions_given.into_iter().collect();
    rg.sort_by(|a, b| b.1.cmp(&a.1));
    stats.reactions_given = rg;

    let mut rr: Vec<(String, u32)> = reactions_received.into_iter().collect();
    rr.sort_by(|a, b| b.1.cmp(&a.1));
    stats.reactions_received = rr;

    stats
}

// ---------------------------------------------------------------------------
// HTML renderer
// ---------------------------------------------------------------------------

pub fn render_html(stats: &ContactActivityStats) -> String {
    let name = stats
        .display_name
        .as_deref()
        .map(html_escape)
        .unwrap_or_else(|| html_escape(&stats.jid));
    let jid_escaped = html_escape(&stats.jid);

    let hourly_rows = stats
        .hourly_heatmap
        .iter()
        .enumerate()
        .map(|(h, &count)| {
            let intensity = if count == 0 {
                "#eee".to_string()
            } else {
                format!("hsl(200,70%,{}%)", 80_u32.saturating_sub(count * 5).max(20))
            };
            format!(
                "<td style=\"background:{intensity};padding:4px\" title=\"{h}:00 — {count} msgs\">{h}</td>",
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let weekly_rows = stats
        .weekly_heatmap
        .iter()
        .enumerate()
        .map(|(d, &count)| {
            let intensity = if count == 0 {
                "#eee".to_string()
            } else {
                format!("hsl(120,60%,{}%)", 80_u32.saturating_sub(count * 5).max(20))
            };
            format!(
                "<td style=\"background:{intensity};padding:4px\" title=\"{day} — {count} msgs\">{day}</td>",
                day = days[d],
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let domains_html = if stats.top_link_domains.is_empty() {
        "<p>No links found.</p>".to_string()
    } else {
        let rows = stats
            .top_link_domains
            .iter()
            .map(|(d, c)| format!("<tr><td>{}</td><td>{c}</td></tr>", html_escape(d)))
            .collect::<Vec<_>>()
            .join("");
        format!("<table border=\"1\"><tr><th>Domain</th><th>Count</th></tr>{rows}</table>")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Contact Dossier — {name}</title>
<style>body{{font-family:monospace;margin:2em}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px}}</style>
</head>
<body>
<h1>Contact Dossier</h1>
<p><strong>JID:</strong> {jid_escaped}</p>
<p><strong>Display Name:</strong> {name}</p>
<p><strong>Sent:</strong> {sent} &nbsp; <strong>Received:</strong> {received} &nbsp; <strong>Media Sent:</strong> {media}</p>
<h2>Hourly Activity</h2>
<table><tr>{hourly_rows}</tr></table>
<h2>Weekly Activity</h2>
<table><tr>{weekly_rows}</tr></table>
<h2>Top Link Domains</h2>
{domains_html}
</body>
</html>"#,
        name = name,
        jid_escaped = jid_escaped,
        sent = stats.total_sent,
        received = stats.total_received,
        media = stats.total_media_sent,
        hourly_rows = hourly_rows,
        weekly_rows = weekly_rows,
        domains_html = domains_html,
    )
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
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
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
            starred: false,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
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
        // 2024-01-15 13:03:40 UTC (Unix ms = 1_705_323_820_000)
        let ts_ms: i64 = 1_705_323_820_000;
        let m = make_text_msg(1, Some(CONTACT_JID), false, ts_ms, "test");
        let msgs: Vec<&Message> = vec![&m];
        let stats = build_contact_stats(CONTACT_JID, None, &msgs, 0);
        assert!(stats.hourly_heatmap[13] > 0);
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
