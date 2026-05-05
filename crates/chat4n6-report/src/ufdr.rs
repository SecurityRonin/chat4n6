//! UFDR (Universal Forensic Data Report) ZIP archive output.
//!
//! Generates a ZIP archive containing UFDRManifest.xml plus per-chat XML
//! files. The format is compatible with the MSAB UFDR specification.

use anyhow::Result;
use chat4n6_plugin_api::ExtractionResult;
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Write the extraction result as a UFDR ZIP archive to `dest`.
pub fn write_ufdr(result: &ExtractionResult, dest: &Path) -> Result<()> {
    let file = std::fs::File::create(dest)?;
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Build UFDRManifest.xml
    let manifest_xml = build_manifest_xml(result);
    zip.start_file("UFDRManifest.xml", opts)?;
    zip.write_all(manifest_xml.as_bytes())?;

    // Per-chat message XML files
    for chat in &result.chats {
        let filename = format!("chats/chat_{}.xml", chat.id);
        let chat_xml = build_chat_xml(chat);
        zip.start_file(&filename, opts)?;
        zip.write_all(chat_xml.as_bytes())?;
    }

    zip.finish()?;
    Ok(())
}

fn build_manifest_xml(result: &ExtractionResult) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ufdr version=\"3.0\" xmlns=\"urn:org:ufed:ufdr\">\n",
    );

    xml.push_str("  <messages>\n");
    for chat in &result.chats {
        for msg in &chat.messages {
            let ts = msg.timestamp.utc.format("%Y-%m-%dT%H:%M:%SZ");
            let sender = msg
                .sender_jid
                .as_deref()
                .unwrap_or(if msg.from_me { "me" } else { "unknown" });
            let body = match &msg.content {
                chat4n6_plugin_api::MessageContent::Text(t) => xml_escape(t),
                chat4n6_plugin_api::MessageContent::Media(_) => "[media]".to_string(),
                chat4n6_plugin_api::MessageContent::Deleted => "[deleted]".to_string(),
                _ => "[other]".to_string(),
            };
            xml.push_str(&format!(
                "    <message id=\"{id}\" chatId=\"{cid}\">\
                 <from>{sender}</from><body>{body}</body>\
                 <timestamp>{ts}</timestamp></message>\n",
                id = msg.id,
                cid = chat.id,
                sender = sender,
                body = body,
                ts = ts,
            ));
        }
    }
    xml.push_str("  </messages>\n");
    xml.push_str("</ufdr>\n");
    xml
}

fn build_chat_xml(chat: &chat4n6_plugin_api::Chat) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <chat id=\"{}\" jid=\"{}\">\n",
        chat.id,
        xml_escape(&chat.jid)
    );
    for msg in &chat.messages {
        let ts = msg.timestamp.utc.format("%Y-%m-%dT%H:%M:%SZ");
        xml.push_str(&format!(
            "  <message id=\"{}\" fromMe=\"{}\"><timestamp>{}</timestamp></message>\n",
            msg.id, msg.from_me, ts
        ));
    }
    xml.push_str("</chat>\n");
    xml
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
