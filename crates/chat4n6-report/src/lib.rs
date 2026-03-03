pub mod paginator;

use anyhow::{Context, Result};
use chat4n6_plugin_api::{Chat, EvidenceSource, ExtractionResult, MessageContent};
use chrono::Utc;
use paginator::paginate;
use serde_json::Value;
use std::path::Path;
use tera::{Context as TeraCtx, Tera};

const PAGE_SIZE: usize = 500;

pub struct ReportGenerator {
    tera: Tera,
}

impl ReportGenerator {
    /// Create a new generator. `template_dir` must point to the `templates/` directory.
    pub fn new(template_dir: &Path) -> Result<Self> {
        let pattern = template_dir
            .join("**/*.html")
            .to_string_lossy()
            .into_owned();
        let tera = Tera::new(&pattern)
            .with_context(|| format!("failed to load Tera templates from {}", template_dir.display()))?;
        Ok(Self { tera })
    }

    /// Render the full report into `output_dir`.
    pub fn render(
        &self,
        case_name: &str,
        result: &ExtractionResult,
        output_dir: &Path,
    ) -> Result<()> {
        std::fs::create_dir_all(output_dir)?;

        let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let tz_offset = result.timezone_offset_seconds.unwrap_or(0);
        let timezone_label = format_tz_label(tz_offset);

        let base_ctx = BaseCtx {
            case_name: case_name.to_string(),
            generated_at_utc: generated_at,
            timezone_label,
        };

        // --- index.html ---
        self.render_index(&base_ctx, result, output_dir)?;

        // --- chat pages ---
        for chat in &result.chats {
            self.render_chat(&base_ctx, chat, output_dir)?;
        }

        // --- calls.html ---
        self.render_calls(&base_ctx, result, output_dir)?;

        // --- deleted.html ---
        self.render_deleted(&base_ctx, result, output_dir)?;

        // --- carve-results.json ---
        let json_path = output_dir.join("carve-results.json");
        let json = serde_json::to_string_pretty(result)?;
        std::fs::write(json_path, json)?;

        Ok(())
    }

    fn render_index(&self, base: &BaseCtx, result: &ExtractionResult, out: &Path) -> Result<()> {
        let mut ctx = TeraCtx::new();
        ctx.insert("case_name", &base.case_name);
        ctx.insert("generated_at_utc", &base.generated_at_utc);
        ctx.insert("timezone_label", &base.timezone_label);

        let total_messages: usize = result.chats.iter().map(|c| c.messages.len()).sum();
        ctx.insert("total_chats", &result.chats.len());
        ctx.insert("total_messages", &total_messages);
        ctx.insert("total_calls", &result.calls.len());

        let chat_summaries: Vec<_> = result.chats.iter().map(|c| {
            serde_json::json!({
                "id": c.id,
                "jid": c.jid,
                "name": c.name,
                "is_group": c.is_group,
                "message_count": c.messages.len(),
            })
        }).collect();
        ctx.insert("chats", &chat_summaries);

        let html = self.tera.render("index.html", &ctx)
            .context("render index.html")?;
        std::fs::write(out.join("index.html"), html)?;
        Ok(())
    }

    fn render_chat(&self, base: &BaseCtx, chat: &Chat, out: &Path) -> Result<()> {
        let pages = paginate(&chat.messages, PAGE_SIZE);
        let total_pages = pages.len().max(1);

        for (page_idx, page_msgs) in pages.iter().enumerate() {
            let current_page = page_idx + 1;
            let mut ctx = TeraCtx::new();
            ctx.insert("case_name", &base.case_name);
            ctx.insert("generated_at_utc", &base.generated_at_utc);
            ctx.insert("timezone_label", &base.timezone_label);
            ctx.insert("chat_id", &chat.id);
            ctx.insert("chat_name", &chat.name.as_deref().unwrap_or(&chat.jid));
            ctx.insert("current_page", &current_page);
            ctx.insert("total_pages", &total_pages);

            let msg_rows: Vec<Value> = page_msgs.iter().map(|m| {
                let content = render_content(&m.content);
                let deleted = matches!(m.content, MessageContent::Deleted);
                let source_str = m.source.to_string();
                let source_class = source_class(&m.source);
                serde_json::json!({
                    "timestamp_utc": m.timestamp.utc_str(),
                    "from_me": m.from_me,
                    "sender": m.sender_jid,
                    "content": content,
                    "deleted": deleted,
                    "source": source_str,
                    "source_class": source_class,
                })
            }).collect();
            ctx.insert("messages", &msg_rows);

            let filename = format!("chat_{}_{}.html", chat.id, current_page);
            let html = self.tera.render("chat_page.html", &ctx)
                .context("render chat_page.html")?;
            std::fs::write(out.join(&filename), html)?;
        }
        Ok(())
    }

    fn render_calls(&self, base: &BaseCtx, result: &ExtractionResult, out: &Path) -> Result<()> {
        let mut ctx = TeraCtx::new();
        ctx.insert("case_name", &base.case_name);
        ctx.insert("generated_at_utc", &base.generated_at_utc);
        ctx.insert("timezone_label", &base.timezone_label);

        let call_rows: Vec<Value> = result.calls.iter().map(|c| {
            serde_json::json!({
                "timestamp_utc": c.timestamp.utc_str(),
                "participants": c.participants,
                "from_me": c.from_me,
                "video": c.video,
                "duration_secs": c.duration_secs,
                "source": c.source.to_string(),
                "source_class": source_class(&c.source),
            })
        }).collect();
        ctx.insert("calls", &call_rows);

        let html = self.tera.render("calls.html", &ctx).context("render calls.html")?;
        std::fs::write(out.join("calls.html"), html)?;
        Ok(())
    }

    fn render_deleted(&self, base: &BaseCtx, result: &ExtractionResult, out: &Path) -> Result<()> {
        let mut ctx = TeraCtx::new();
        ctx.insert("case_name", &base.case_name);
        ctx.insert("generated_at_utc", &base.generated_at_utc);
        ctx.insert("timezone_label", &base.timezone_label);

        let deleted: Vec<Value> = result.chats.iter()
            .flat_map(|chat| chat.messages.iter().map(move |m| (chat.id, m)))
            .filter(|(_, m)| !matches!(m.source, EvidenceSource::Live))
            .map(|(chat_id, m)| {
                serde_json::json!({
                    "chat_id": chat_id,
                    "timestamp_utc": m.timestamp.utc_str(),
                    "from_me": m.from_me,
                    "content": render_content(&m.content),
                    "source": m.source.to_string(),
                    "source_class": source_class(&m.source),
                })
            }).collect();
        ctx.insert("deleted_messages", &deleted);

        let html = self.tera.render("deleted.html", &ctx).context("render deleted.html")?;
        std::fs::write(out.join("deleted.html"), html)?;
        Ok(())
    }
}

// ── helper structs / functions ────────────────────────────────────────────────

struct BaseCtx {
    case_name: String,
    generated_at_utc: String,
    timezone_label: String,
}

fn format_tz_label(offset_secs: i32) -> String {
    let sign = if offset_secs >= 0 { '+' } else { '-' };
    let abs = offset_secs.unsigned_abs();
    let h = abs / 3600;
    let m = (abs % 3600) / 60;
    format!("UTC{}{:02}:{:02}", sign, h, m)
}

fn render_content(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(s) => s.clone(),
        MessageContent::Media(m) => format!("[Media: {}]", m.mime_type),
        MessageContent::Location { lat, lon, name } => {
            if let Some(n) = name {
                format!("[Location: {} ({}, {})]", n, lat, lon)
            } else {
                format!("[Location: {}, {}]", lat, lon)
            }
        }
        MessageContent::VCard(v) => format!("[Contact: {}]", v),
        MessageContent::Deleted => "[Deleted]".to_string(),
        MessageContent::System(s) => format!("[System: {}]", s),
        MessageContent::Unknown(t) => format!("[Unknown type {}]", t),
    }
}

fn source_class(source: &EvidenceSource) -> String {
    match source {
        EvidenceSource::Live => "live",
        EvidenceSource::WalPending => "wal-pending",
        EvidenceSource::WalHistoric => "wal-historic",
        EvidenceSource::Freelist => "freelist",
        EvidenceSource::FtsOnly => "fts-only",
        EvidenceSource::CarvedUnalloc { .. } => "carved-unalloc",
        EvidenceSource::CarvedDb => "carved-db",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::{Chat, EvidenceSource, ExtractionResult, ForensicTimestamp, Message, MessageContent};
    use tempfile::TempDir;

    fn make_test_result() -> ExtractionResult {
        let msg = Message {
            id: 1,
            chat_id: 1,
            sender_jid: None,
            from_me: true,
            timestamp: ForensicTimestamp::from_millis(1710513127000, 0),
            content: MessageContent::Text("Hello forensics".to_string()),
            reactions: vec![],
            quoted_message: None,
            source: EvidenceSource::Live,
            row_offset: 0,
        };
        let chat = Chat {
            id: 1,
            jid: "test@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![msg],
        };
        ExtractionResult {
            chats: vec![chat],
            contacts: vec![],
            calls: vec![],
            wal_deltas: vec![],
            timezone_offset_seconds: Some(0),
            schema_version: 200,
        }
    }

    fn template_dir() -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join("templates")
    }

    #[test]
    fn test_report_creates_index_html() {
        let out = TempDir::new().unwrap();
        let gen = ReportGenerator::new(&template_dir()).expect("template load");
        gen.render("TestCase", &make_test_result(), out.path()).unwrap();
        assert!(out.path().join("index.html").exists());
    }

    #[test]
    fn test_report_creates_carve_json() {
        let out = TempDir::new().unwrap();
        let gen = ReportGenerator::new(&template_dir()).expect("template load");
        gen.render("TestCase", &make_test_result(), out.path()).unwrap();
        assert!(out.path().join("carve-results.json").exists());
    }

    #[test]
    fn test_report_creates_chat_page() {
        let out = TempDir::new().unwrap();
        let gen = ReportGenerator::new(&template_dir()).expect("template load");
        gen.render("TestCase", &make_test_result(), out.path()).unwrap();
        assert!(out.path().join("chat_1_1.html").exists());
    }

    #[test]
    fn test_format_tz_label() {
        assert_eq!(format_tz_label(8 * 3600), "UTC+08:00");
        assert_eq!(format_tz_label(0), "UTC+00:00");
        assert_eq!(format_tz_label(-5 * 3600), "UTC-05:00");
    }
}
