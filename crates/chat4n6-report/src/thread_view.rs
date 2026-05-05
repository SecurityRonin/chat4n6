use chat4n6_plugin_api::{EvidenceSource, ExtractionResult, MessageContent};
use std::path::Path;

/// Render a WhatsApp-style thread view HTML report.
pub fn render_thread_view(result: &ExtractionResult, case_name: &str) -> String {
    todo!("implement render_thread_view")
}

/// Write the thread view HTML to `path/thread-view.html`.
pub fn write_thread_view(
    result: &ExtractionResult,
    case_name: &str,
    path: &Path,
) -> anyhow::Result<()> {
    todo!("implement write_thread_view")
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
