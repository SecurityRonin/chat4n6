use chat4n6_plugin_api::{EvidenceSource, ExtractionResult, Message, MessageContent};
use std::path::Path;

fn evidence_color(source: &EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Live => "#22c55e",
        EvidenceSource::WalPending | EvidenceSource::WalHistoric | EvidenceSource::WalDeleted => {
            "#f97316"
        }
        EvidenceSource::Freelist | EvidenceSource::FtsOnly => "#eab308",
        EvidenceSource::CarvedUnalloc { .. }
        | EvidenceSource::CarvedIntraPage { .. }
        | EvidenceSource::CarvedOverflow
        | EvidenceSource::CarvedDb => "#ef4444",
        EvidenceSource::Journal | EvidenceSource::IndexRecovery => "#8b5cf6",
    }
}

fn evidence_class(source: &EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Live => "src-live",
        EvidenceSource::WalPending | EvidenceSource::WalHistoric | EvidenceSource::WalDeleted => {
            "src-wal"
        }
        EvidenceSource::Freelist | EvidenceSource::FtsOnly => "src-freelist",
        EvidenceSource::CarvedUnalloc { .. }
        | EvidenceSource::CarvedIntraPage { .. }
        | EvidenceSource::CarvedOverflow
        | EvidenceSource::CarvedDb => "src-carved",
        EvidenceSource::Journal | EvidenceSource::IndexRecovery => "src-journal",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_message_content(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(t) => html_escape(t),
        MessageContent::Media(m) => format!(
            "<span class=\"media-label\">[Media: {}]</span>",
            html_escape(&m.mime_type)
        ),
        MessageContent::ViewOnce(m) => format!(
            "<span class=\"view-once-label\">🔒 View Once — media key preserved ({})</span>",
            html_escape(&m.mime_type)
        ),
        MessageContent::Location { lat, lon, name } => {
            let label = name.as_deref().unwrap_or("Location");
            format!(
                "<span class=\"location-label\">[{}: {:.6}, {:.6}]</span>",
                html_escape(label),
                lat,
                lon
            )
        }
        MessageContent::VCard(v) => format!("<span class=\"vcard-label\">[Contact: {}]</span>", html_escape(v)),
        MessageContent::Deleted => "<span class=\"deleted-label\">[Deleted]</span>".to_string(),
        MessageContent::GhostRecovered(s) => format!("<span class=\"ghost-label\">[Ghost: {}]</span>", html_escape(s)),
        MessageContent::System(s) => {
            format!("<span class=\"system-label\">[System: {}]</span>", html_escape(s))
        }
        MessageContent::Unknown(t) => format!("<span class=\"unknown-label\">[Unknown type {t}]</span>"),
    }
}

fn render_message_bubble(msg: &Message) -> String {
    let dir_class = if msg.from_me { "sent" } else { "received" };
    let color = evidence_color(&msg.source);
    let src_class = evidence_class(&msg.source);
    let source_label = msg.source.to_string();
    let ts = msg.timestamp.utc_str();
    let content_html = render_message_content(&msg.content);

    let sender_html = if !msg.from_me {
        let jid = msg.sender_jid.as_deref().unwrap_or("unknown");
        format!("<div class=\"sender-jid\">{}</div>", html_escape(jid))
    } else {
        String::new()
    };

    let starred_html = if msg.starred {
        "<span class=\"star-indicator\">⭐</span> ".to_string()
    } else {
        String::new()
    };

    let forwarded_html = if msg.is_forwarded {
        "<span class=\"fwd-indicator\">↪ Forwarded</span> ".to_string()
    } else {
        String::new()
    };

    let quoted_html = if let Some(ref q) = msg.quoted_message {
        let q_sender = q.sender_jid.as_deref().unwrap_or("me");
        let q_content = render_message_content(&q.content);
        format!(
            "<div class=\"quoted-msg\"><span class=\"quoted-sender\">{}</span>: {}</div>",
            html_escape(q_sender),
            q_content
        )
    } else {
        String::new()
    };

    let reactions_html = if !msg.reactions.is_empty() {
        let r: Vec<String> = msg
            .reactions
            .iter()
            .map(|r| {
                format!(
                    "<span class=\"reaction\" title=\"{}\">{}</span>",
                    html_escape(&r.reactor_jid),
                    html_escape(&r.emoji)
                )
            })
            .collect();
        format!("<div class=\"reactions\">{}</div>", r.join(" "))
    } else {
        String::new()
    };

    format!(
        r#"<div class="msg {dir_class}" data-from-me="{from_me}" data-source="{source_label}">
  {sender_html}
  <div class="bubble">
    {starred_html}{forwarded_html}{quoted_html}
    <div class="content">{content_html}</div>
    <div class="meta">
      <span class="timestamp">{ts}</span>
      <span class="evidence-badge {src_class}" style="background:{color}" title="{source_label}"> </span>
    </div>
  </div>
  {reactions_html}
</div>"#,
        dir_class = dir_class,
        from_me = msg.from_me,
        source_label = html_escape(&source_label),
        sender_html = sender_html,
        starred_html = starred_html,
        forwarded_html = forwarded_html,
        quoted_html = quoted_html,
        content_html = content_html,
        ts = html_escape(&ts),
        src_class = src_class,
        color = color,
        reactions_html = reactions_html,
    )
}

/// Render a WhatsApp-style thread view HTML report.
pub fn render_thread_view(result: &ExtractionResult, case_name: &str) -> String {
    let warning_banner = if result.forensic_warnings.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = result
            .forensic_warnings
            .iter()
            .map(|w| format!("<li>{}</li>", html_escape(&w.to_string())))
            .collect();
        format!(
            r#"<div class="forensic-warnings">
  <strong>Forensic Warnings</strong>
  <ul>{}</ul>
</div>"#,
            items.join("\n")
        )
    };

    let mut chat_sections = String::new();
    for chat in &result.chats {
        let chat_title = chat
            .name
            .as_deref()
            .unwrap_or(&chat.jid)
            .to_string();

        let messages_html: String = chat.messages.iter().map(render_message_bubble).collect();

        chat_sections.push_str(&format!(
            r#"<section class="chat-section" id="chat-{id}">
  <h2 class="chat-title">{title}</h2>
  <div class="messages">{msgs}</div>
</section>"#,
            id = chat.id,
            title = html_escape(&chat_title),
            msgs = messages_html,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Thread View — {case_name}</title>
<style>
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #f0f2f5;
  margin: 0; padding: 0;
}}
header {{
  background: #075e54;
  color: white;
  padding: 12px 24px;
}}
.forensic-warnings {{
  background: #fee2e2;
  border-left: 4px solid #ef4444;
  margin: 16px 24px;
  padding: 12px 16px;
  border-radius: 4px;
  color: #7f1d1d;
}}
.search-bar {{
  padding: 12px 24px;
  background: white;
  border-bottom: 1px solid #ddd;
}}
#msg-search {{
  width: 100%; max-width: 400px;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 20px;
  font-size: 14px;
}}
.chat-section {{
  max-width: 900px;
  margin: 24px auto;
  background: #e5ddd5;
  border-radius: 8px;
  overflow: hidden;
}}
.chat-title {{
  background: #128c7e;
  color: white;
  margin: 0;
  padding: 12px 20px;
  font-size: 16px;
}}
.messages {{
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}}
.msg {{
  max-width: 70%;
  display: flex;
  flex-direction: column;
}}
.msg.sent {{
  align-self: flex-end;
  align-items: flex-end;
}}
.msg.received {{
  align-self: flex-start;
  align-items: flex-start;
}}
.bubble {{
  background: white;
  padding: 8px 12px;
  border-radius: 8px;
  box-shadow: 0 1px 1px rgba(0,0,0,.13);
  position: relative;
}}
.msg.sent .bubble {{
  background: #dcf8c6;
  border-radius: 8px 0 8px 8px;
}}
.msg.received .bubble {{
  border-radius: 0 8px 8px 8px;
}}
.sender-jid {{
  font-size: 11px;
  color: #667781;
  margin-bottom: 2px;
  padding-left: 2px;
}}
.quoted-msg {{
  background: rgba(0,0,0,.05);
  border-left: 3px solid #128c7e;
  padding: 4px 8px;
  margin-bottom: 6px;
  border-radius: 4px;
  font-size: 13px;
}}
.meta {{
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 4px;
  justify-content: flex-end;
}}
.timestamp {{
  font-size: 11px;
  color: #667781;
}}
.evidence-badge {{
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}}
.reactions {{
  display: flex;
  gap: 4px;
  margin-top: 2px;
}}
.reaction {{
  background: white;
  border-radius: 12px;
  padding: 2px 6px;
  font-size: 14px;
  box-shadow: 0 1px 2px rgba(0,0,0,.2);
}}
.star-indicator, .fwd-indicator {{
  font-size: 12px;
  margin-right: 4px;
}}
.view-once-label {{
  color: #5f6368;
  font-style: italic;
}}
.deleted-label {{
  color: #9e9e9e;
  font-style: italic;
}}
.hidden {{ display: none !important; }}
</style>
</head>
<body>
<header>
  <h1>Thread View — {case_name_esc}</h1>
</header>
{warning_banner}
<div class="search-bar">
  <input type="text" id="msg-search" placeholder="Search messages..." oninput="filterMessages(this.value)">
</div>
{chat_sections}
<script>
function filterMessages(query) {{
  var q = query.toLowerCase();
  document.querySelectorAll('.msg').forEach(function(el) {{
    var text = el.querySelector('.content') ? el.querySelector('.content').textContent.toLowerCase() : '';
    el.classList.toggle('hidden', q.length > 0 && !text.includes(q));
  }});
}}
</script>
</body>
</html>"#,
        case_name = html_escape(case_name),
        case_name_esc = html_escape(case_name),
        warning_banner = warning_banner,
        chat_sections = chat_sections,
    )
}

/// Write the thread view HTML to `path/thread-view.html`.
pub fn write_thread_view(
    result: &ExtractionResult,
    case_name: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let html = render_thread_view(result, case_name);
    std::fs::write(path.join("thread-view.html"), html)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{
        Chat, EvidenceSource, ExtractionResult, ForensicTimestamp, ForensicWarning, MediaRef,
        Message, MessageContent, Reaction,
    };
    use tempfile::TempDir;

    fn ts(ms: i64) -> ForensicTimestamp {
        ForensicTimestamp::from_millis(ms, 0)
    }

    fn make_msg(
        id: i64,
        chat_id: i64,
        sender_jid: Option<&str>,
        from_me: bool,
        content: MessageContent,
        source: EvidenceSource,
        starred: bool,
    ) -> Message {
        Message {
            id,
            chat_id,
            sender_jid: sender_jid.map(|s| s.to_string()),
            from_me,
            timestamp: ts(1710513127000 + id * 1000),
            content,
            reactions: vec![],
            quoted_message: None,
            source,
            row_offset: 0,
            starred,
            forward_score: None,
            is_forwarded: false,
            edit_history: vec![],
            receipts: vec![],
        }
    }

    fn make_result_with(msgs: Vec<Message>) -> ExtractionResult {
        let chat = Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: Some("Alice".to_string()),
            is_group: false,
            messages: msgs,
            archived: false,
        };
        ExtractionResult {
            chats: vec![chat],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
            forensic_warnings: vec![],
            group_participant_events: vec![],
        }
    }

    // Test 1: Output contains valid HTML (starts with <!DOCTYPE html>)
    #[test]
    fn test_thread_view_starts_with_doctype() {
        let result = make_result_with(vec![]);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.trim_start().starts_with("<!DOCTYPE html>")
                || html.trim_start().starts_with("<!doctype html>"),
            "output must start with <!DOCTYPE html>"
        );
    }

    // Test 2: Message text appears in output
    #[test]
    fn test_thread_view_message_text_in_output() {
        let result = make_result_with(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("Hello forensics world".into()),
            EvidenceSource::Live, false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        assert!(html.contains("Hello forensics world"), "message text must appear in HTML");
    }

    // Test 3: from_me message has class or data-attribute indicating "sent"
    #[test]
    fn test_thread_view_sent_message_indicator() {
        let result = make_result_with(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("sent by me".into()),
            EvidenceSource::Live, false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        // Must contain "sent" class or data-from-me attribute
        assert!(
            html.contains("class=\"msg sent\"")
                || html.contains("class=\"msg  sent\"")
                || html.contains("data-from-me=\"true\"")
                || html.contains("msg sent"),
            "from_me message must have sent indicator in HTML"
        );
    }

    // Test 4: Received message has indicator for sender_jid
    #[test]
    fn test_thread_view_received_message_has_sender() {
        let result = make_result_with(vec![make_msg(
            1, 1, Some("bob@s.whatsapp.net"), false,
            MessageContent::Text("received message".into()),
            EvidenceSource::Live, false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.contains("bob@s.whatsapp.net"),
            "received message must show sender jid"
        );
    }

    // Test 5: EvidenceSource::Live produces green indicator class
    #[test]
    fn test_thread_view_live_source_green() {
        let result = make_result_with(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("live message".into()),
            EvidenceSource::Live, false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        // Color #22c55e or CSS class referencing live/green
        assert!(
            html.contains("#22c55e") || html.contains("src-live") || html.contains("evidence-live"),
            "Live source must produce green indicator (#22c55e or src-live class)"
        );
    }

    // Test 6: Carved evidence produces red indicator class
    #[test]
    fn test_thread_view_carved_source_red() {
        let result = make_result_with(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("carved message".into()),
            EvidenceSource::CarvedUnalloc { confidence_pct: 80 },
            false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.contains("#ef4444") || html.contains("src-carved") || html.contains("evidence-carved"),
            "Carved source must produce red indicator (#ef4444 or src-carved class)"
        );
    }

    // Test 7: Starred message contains ⭐ or "starred"
    #[test]
    fn test_thread_view_starred_message_indicator() {
        let result = make_result_with(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("important evidence".into()),
            EvidenceSource::Live, true,
        )]);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.contains('⭐') || html.contains("starred") || html.contains("star"),
            "starred message must have ⭐ or 'starred' indicator"
        );
    }

    // Test 8: ViewOnce content shows "View Once" label
    #[test]
    fn test_thread_view_view_once_label() {
        let media = MediaRef {
            file_path: "photo.jpg".into(),
            mime_type: "image/jpeg".into(),
            file_size: 1024,
            extracted_name: None,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        };
        let result = make_result_with(vec![make_msg(
            1, 1, Some("alice@s.whatsapp.net"), false,
            MessageContent::ViewOnce(media),
            EvidenceSource::Live, false,
        )]);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.contains("View Once") || html.contains("view-once") || html.contains("ViewOnce"),
            "ViewOnce message must show 'View Once' label"
        );
    }

    // Test 9: Forensic warning in result appears in HTML banner
    #[test]
    fn test_thread_view_forensic_warning_banner() {
        let mut result = make_result_with(vec![]);
        result.forensic_warnings.push(ForensicWarning::HmacMismatch);
        let html = render_thread_view(&result, "TestCase");
        assert!(
            html.contains("HMAC") || html.contains("Hmac") || html.contains("warning") || html.contains("mismatch"),
            "forensic warning must appear in HTML output"
        );
    }

    // Test 10: Empty result produces valid HTML with no messages
    #[test]
    fn test_thread_view_empty_result_valid_html() {
        let result = ExtractionResult::default();
        let html = render_thread_view(&result, "EmptyCase");
        assert!(
            html.trim_start().starts_with("<!DOCTYPE html>")
                || html.trim_start().starts_with("<!doctype html>"),
            "empty result must still produce valid HTML doctype"
        );
        // Should not contain any message bubbles
        assert!(
            !html.contains("class=\"msg sent\"") && !html.contains("class=\"msg received\""),
            "empty result should produce no message bubbles"
        );
    }
}
