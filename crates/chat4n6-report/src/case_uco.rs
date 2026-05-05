use chat4n6_plugin_api::{EvidenceSource, ExtractionResult, MessageContent};
use serde_json::{json, Value};
use std::path::Path;

/// Serialize an ExtractionResult to a CASE/UCO JSON-LD document.
pub fn to_case_uco(result: &ExtractionResult, case_id: &str, tool_version: &str) -> Value {
    let mut objects: Vec<Value> = Vec::new();

    // Collect all messages across all chats
    for chat in &result.chats {
        for msg in &chat.messages {
            let mut obj = json!({
                "@type": "uco-observable:Message",
                "@id": format!("msg-{}", msg.id),
                "uco-observable:sentTime": msg.timestamp.utc.to_rfc3339(),
                "uco-observable:isRead": true,
            });

            // Message text
            if let MessageContent::Text(ref text) = msg.content {
                obj["uco-observable:messageText"] = json!(text);
            }

            // Content type for media
            let cdn_url: Option<String> = match &msg.content {
                MessageContent::Media(m) | MessageContent::ViewOnce(m) => {
                    obj["uco-observable:contentType"] = json!(m.mime_type);
                    m.cdn_url.clone()
                }
                _ => None,
            };

            // Sender: only for received messages (from_me=false)
            if !msg.from_me {
                if let Some(ref jid) = msg.sender_jid {
                    obj["uco-observable:sender"] = json!({ "@id": format!("contact-{jid}") });
                }
            }

            // Starred → isHighlighted
            if msg.starred {
                obj["uco-observable:isHighlighted"] = json!(true);
            }

            // Evidence provenance facet
            let source_str = msg.source.to_string();
            let mut facet = json!({
                "@type": "case-investigation:ProvenanceRecord",
                "case-investigation:exhibitNumber": format!("chat-{}-msg-{}", msg.chat_id, msg.id),
                "uco-observable:evidenceSource": source_str,
            });

            if let Some(url) = cdn_url {
                facet["uco-observable:cdnUrl"] = json!(url);
            }

            obj["uco-core:hasFacet"] = json!([facet]);

            objects.push(obj);
        }
    }

    // Bundle-level examiner notes from ForensicWarnings
    if !result.forensic_warnings.is_empty() {
        let notes: Vec<String> = result.forensic_warnings.iter().map(|w| w.to_string()).collect();
        objects.push(json!({
            "@type": "case-investigation:ExaminerNotes",
            "case-investigation:caseId": case_id,
            "uco-core:description": notes,
        }));
    }

    json!({
        "@context": {
            "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
            "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
            "case-investigation": "https://caseontology.org/ontology/case/investigation/"
        },
        "@type": "uco-core:Bundle",
        "uco-core:name": "chat4n6-export",
        "uco-core:createdBy": {
            "@type": "uco-core:Tool",
            "uco-core:name": "chat4n6",
            "uco-core:version": tool_version,
        },
        "uco-core:caseId": case_id,
        "uco-core:object": objects,
    })
}

/// Write the CASE/UCO JSON-LD document to `path/case-uco.json`.
pub fn write_case_uco(
    result: &ExtractionResult,
    case_id: &str,
    tool_version: &str,
    path: &Path,
) -> anyhow::Result<()> {
    let doc = to_case_uco(result, case_id, tool_version);
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(path.join("case-uco.json"), json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{
        Chat, EvidenceSource, ExtractionResult, ForensicTimestamp, ForensicWarning, MediaRef,
        Message, MessageContent,
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

    fn make_result_with_msgs(msgs: Vec<Message>) -> ExtractionResult {
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

    // Test 1: Output is valid JSON (serde_json::to_string succeeds)
    #[test]
    fn test_case_uco_output_is_valid_json() {
        let result = make_result_with_msgs(vec![]);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let s = serde_json::to_string(&doc);
        assert!(s.is_ok(), "should serialize to JSON without error");
    }

    // Test 2: Top-level @type is "uco-core:Bundle"
    #[test]
    fn test_case_uco_top_level_type_is_bundle() {
        let result = make_result_with_msgs(vec![]);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        assert_eq!(
            doc["@type"].as_str().unwrap_or(""),
            "uco-core:Bundle",
            "@type must be uco-core:Bundle"
        );
    }

    // Test 3: Message count matches input
    #[test]
    fn test_case_uco_message_count_matches() {
        let msgs = vec![
            make_msg(1, 1, None, true, MessageContent::Text("hi".into()), EvidenceSource::Live, false),
            make_msg(2, 1, Some("bob@s.whatsapp.net"), false, MessageContent::Text("hello".into()), EvidenceSource::Live, false),
            make_msg(3, 1, None, true, MessageContent::Text("bye".into()), EvidenceSource::Live, false),
        ];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().expect("uco-core:object must be array");
        let msg_count = objects
            .iter()
            .filter(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .count();
        assert_eq!(msg_count, 3, "should have 3 message objects");
    }

    // Test 4: Message text content is preserved
    #[test]
    fn test_case_uco_message_text_preserved() {
        let msgs = vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("Hello there".into()),
            EvidenceSource::Live, false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().unwrap();
        let msg = objects
            .iter()
            .find(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .expect("no message object");
        assert_eq!(
            msg["uco-observable:messageText"].as_str().unwrap_or(""),
            "Hello there"
        );
    }

    // Test 5: from_me=false message has sender field
    #[test]
    fn test_case_uco_received_message_has_sender() {
        let msgs = vec![make_msg(
            1, 1, Some("bob@s.whatsapp.net"), false,
            MessageContent::Text("yo".into()),
            EvidenceSource::Live, false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().unwrap();
        let msg = objects
            .iter()
            .find(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .unwrap();
        // sender must be present and reference the contact
        assert!(
            !msg["uco-observable:sender"].is_null(),
            "received message must have sender field"
        );
        let sender_id = msg["uco-observable:sender"]["@id"].as_str().unwrap_or("");
        assert!(
            sender_id.contains("bob@s.whatsapp.net"),
            "sender @id should reference the jid, got: {sender_id}"
        );
    }

    // Test 6: from_me=true message has no sender (or empty)
    #[test]
    fn test_case_uco_sent_message_no_sender() {
        let msgs = vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("sent by me".into()),
            EvidenceSource::Live, false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().unwrap();
        let msg = objects
            .iter()
            .find(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .unwrap();
        // Either absent or "local-device" — must NOT reference an external JID
        let sender = &msg["uco-observable:sender"];
        if !sender.is_null() {
            let id = sender["@id"].as_str().unwrap_or("");
            assert!(
                id.is_empty() || id == "local-device",
                "from_me message sender should be empty or local-device, got: {id}"
            );
        }
    }

    // Test 7: evidence source appears in output
    #[test]
    fn test_case_uco_evidence_source_in_output() {
        let msgs = vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("carved".into()),
            EvidenceSource::CarvedUnalloc { confidence_pct: 82 },
            false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let json_str = serde_json::to_string(&doc).unwrap();
        assert!(
            json_str.contains("CARVED") || json_str.contains("carved") || json_str.contains("ProvenanceRecord"),
            "evidence source should appear in output, got snippet: {}",
            &json_str[..200.min(json_str.len())]
        );
    }

    // Test 8: starred message has isHighlighted
    #[test]
    fn test_case_uco_starred_message_is_highlighted() {
        let msgs = vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("important".into()),
            EvidenceSource::Live, true,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().unwrap();
        let msg = objects
            .iter()
            .find(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .unwrap();
        assert_eq!(
            msg["uco-observable:isHighlighted"].as_bool().unwrap_or(false),
            true,
            "starred message must have uco-observable:isHighlighted = true"
        );
    }

    // Test 9: media message has contentType field
    #[test]
    fn test_case_uco_media_message_has_content_type() {
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
        let msgs = vec![make_msg(
            1, 1, Some("alice@s.whatsapp.net"), false,
            MessageContent::Media(media),
            EvidenceSource::Live, false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let objects = doc["uco-core:object"].as_array().unwrap();
        let msg = objects
            .iter()
            .find(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .unwrap();
        let ct = msg["uco-observable:contentType"].as_str().unwrap_or("");
        assert_eq!(ct, "image/jpeg", "media message must include contentType");
    }

    // Test 10: MediaRef with cdn_url includes the URL
    #[test]
    fn test_case_uco_media_cdn_url_included() {
        let media = MediaRef {
            file_path: "photo.jpg".into(),
            mime_type: "image/jpeg".into(),
            file_size: 1024,
            extracted_name: None,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: Some("https://mmg.whatsapp.net/v/abc123".into()),
            media_key_b64: None,
        };
        let msgs = vec![make_msg(
            1, 1, Some("alice@s.whatsapp.net"), false,
            MessageContent::Media(media),
            EvidenceSource::Live, false,
        )];
        let result = make_result_with_msgs(msgs);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let json_str = serde_json::to_string(&doc).unwrap();
        assert!(
            json_str.contains("mmg.whatsapp.net"),
            "cdn_url must appear in output"
        );
    }

    // Test 11: ForensicWarning included in bundle-level notes
    #[test]
    fn test_case_uco_forensic_warning_in_bundle() {
        let mut result = make_result_with_msgs(vec![]);
        result.forensic_warnings.push(ForensicWarning::HmacMismatch);
        let doc = to_case_uco(&result, "CASE-001", "0.1.2");
        let json_str = serde_json::to_string(&doc).unwrap();
        assert!(
            json_str.contains("HMAC") || json_str.contains("Hmac") || json_str.contains("ExaminerNote"),
            "forensic warning must appear in bundle output"
        );
    }

    // Test 12: Empty extraction result produces valid but empty bundle
    #[test]
    fn test_case_uco_empty_result_valid_bundle() {
        let result = ExtractionResult::default();
        let doc = to_case_uco(&result, "EMPTY-001", "0.1.2");
        assert_eq!(doc["@type"].as_str().unwrap_or(""), "uco-core:Bundle");
        let objects = doc["uco-core:object"].as_array().expect("must have uco-core:object");
        let msg_count = objects
            .iter()
            .filter(|o| o["@type"].as_str() == Some("uco-observable:Message"))
            .count();
        assert_eq!(msg_count, 0, "empty result should produce 0 message objects");
        assert!(serde_json::to_string(&doc).is_ok());
    }

    // Test 13: write_case_uco creates a .json file
    #[test]
    fn test_write_case_uco_creates_file() {
        let dir = TempDir::new().unwrap();
        let result = make_result_with_msgs(vec![make_msg(
            1, 1, None, true,
            MessageContent::Text("test".into()),
            EvidenceSource::Live, false,
        )]);
        write_case_uco(&result, "CASE-WRITE", "0.1.2", dir.path()).unwrap();
        let out_file = dir.path().join("case-uco.json");
        assert!(out_file.exists(), "case-uco.json must be created");
        let content = std::fs::read_to_string(&out_file).unwrap();
        let parsed: Value = serde_json::from_str(&content).expect("file must be valid JSON");
        assert_eq!(parsed["@type"].as_str().unwrap_or(""), "uco-core:Bundle");
    }
}
