use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    Live,
    WalPending,
    WalHistoric,
    WalDeleted,
    Freelist,
    FtsOnly,
    CarvedUnalloc { confidence_pct: u8 },
    CarvedIntraPage { confidence_pct: u8 },
    CarvedOverflow,
    CarvedDb,
    Journal,
    IndexRecovery,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "LIVE"),
            Self::WalPending => write!(f, "WAL-PENDING"),
            Self::WalHistoric => write!(f, "WAL-HISTORIC"),
            Self::WalDeleted => write!(f, "WAL-DELETED"),
            Self::Freelist => write!(f, "FREELIST"),
            Self::FtsOnly => write!(f, "FTS-ONLY"),
            Self::CarvedUnalloc { confidence_pct } => {
                write!(f, "CARVED-UNALLOC {confidence_pct}%")
            }
            Self::CarvedIntraPage { confidence_pct } => {
                write!(f, "CARVED-INTRA-PAGE {confidence_pct}%")
            }
            Self::CarvedOverflow => write!(f, "CARVED-OVERFLOW"),
            Self::CarvedDb => write!(f, "CARVED-DB"),
            Self::Journal => write!(f, "JOURNAL"),
            Self::IndexRecovery => write!(f, "INDEX-RECOVERY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForensicTimestamp {
    pub utc: DateTime<Utc>,
    pub local_offset_seconds: i32,
}

impl ForensicTimestamp {
    pub fn from_millis(ms: i64, local_offset_seconds: i32) -> Self {
        use chrono::TimeZone;
        let utc = Utc
            .timestamp_millis_opt(ms)
            .single()
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        Self {
            utc,
            local_offset_seconds,
        }
    }

    pub fn utc_str(&self) -> String {
        self.utc.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    pub fn local_str(&self) -> String {
        let offset = FixedOffset::east_opt(self.local_offset_seconds)
            .unwrap_or(FixedOffset::east_opt(0).unwrap());
        let local = self.utc.with_timezone(&offset);
        let total_secs = self.local_offset_seconds;
        let sign = if total_secs >= 0 { '+' } else { '-' };
        let abs_secs = total_secs.unsigned_abs();
        let hours = abs_secs / 3600;
        let mins = (abs_secs % 3600) / 60;
        format!(
            "{}  |  {} {}{:02}:{:02}",
            self.utc.format("%Y-%m-%d %H:%M:%S UTC"),
            local.format("%Y-%m-%d %H:%M:%S"),
            sign,
            hours,
            mins
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MediaRef {
    pub file_path: String,
    pub mime_type: String,
    pub file_size: u64,
    pub extracted_name: Option<String>,
    pub thumbnail_b64: Option<String>,
    pub duration_secs: Option<u32>,
    /// SHA-256 hex of plaintext (decrypted) bytes.
    #[serde(default)]
    pub file_hash: Option<String>,
    /// SHA-256 hex of encrypted CDN bytes.
    /// WhatsApp re-uses the encrypted blob for forwards — same encrypted_hash means same CDN object,
    /// enabling cross-chat forward-chain deduplication regardless of re-encryption.
    #[serde(default)]
    pub encrypted_hash: Option<String>,
    /// WhatsApp CDN download URL.
    #[serde(default)]
    pub cdn_url: Option<String>,
    /// AES-256-CBC decrypt key (base64-encoded 32-byte media key).
    #[serde(default)]
    pub media_key_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reaction {
    pub emoji: String,
    pub reactor_jid: String,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallResult {
    Unknown,
    Connected,
    Rejected,
    Unavailable,
    Missed,
    Cancelled,
}

impl Default for CallResult {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<i64> for CallResult {
    fn from(v: i64) -> Self {
        match v {
            1 => Self::Connected,
            2 => Self::Rejected,
            3 => Self::Unavailable,
            4 => Self::Missed,
            5 => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for CallResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Connected => write!(f, "Connected"),
            Self::Rejected => write!(f, "Rejected"),
            Self::Unavailable => write!(f, "Unavailable"),
            Self::Missed => write!(f, "Missed"),
            Self::Cancelled => write!(f, "Cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallRecord {
    pub call_id: i64,
    pub participants: Vec<String>,
    pub from_me: bool,
    pub video: bool,
    pub group_call: bool,
    pub duration_secs: u32,
    pub call_result: CallResult,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
    /// Device JID of the call creator (present in newer msgstore schemas).
    #[serde(default)]
    pub call_creator_device_jid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageContent {
    Text(String),
    Media(MediaRef),
    Location {
        lat: f64,
        lon: f64,
        name: Option<String>,
    },
    VCard(String),
    Deleted,
    System(String),
    Unknown(i32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub id: i64,
    pub chat_id: i64,
    pub sender_jid: Option<String>,
    pub from_me: bool,
    pub timestamp: ForensicTimestamp,
    pub content: MessageContent,
    pub reactions: Vec<Reaction>,
    pub quoted_message: Option<Box<Message>>,
    pub source: EvidenceSource,
    pub row_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    pub jid: String,
    pub display_name: Option<String>,
    pub phone_number: Option<String>,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub id: i64,
    pub jid: String,
    pub name: Option<String>,
    pub is_group: bool,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalDeltaStatus {
    AddedInWal,
    DeletedInWal,
    ModifiedInWal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalDelta {
    pub table: String,
    pub row_id: i64,
    pub status: WalDeltaStatus,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub chats: Vec<Chat>,
    pub contacts: Vec<Contact>,
    pub calls: Vec<CallRecord>,
    pub wal_deltas: Vec<WalDelta>,
    pub timezone_offset_seconds: Option<i32>,
    pub schema_version: u32,
}

#[cfg(test)]
mod new_types_tests {
    use super::*;

    // ── EditHistoryEntry ──────────────────────────────────────────────────
    #[test]
    fn edit_history_entry_roundtrip() {
        let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
        let entry = EditHistoryEntry {
            original_text: "original".to_string(),
            edited_at: ts.clone(),
            source: EvidenceSource::Live,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: EditHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.original_text, "original");
        assert_eq!(back.source, EvidenceSource::Live);
    }

    // ── ReceiptType / MessageReceipt ──────────────────────────────────────
    #[test]
    fn receipt_type_display() {
        assert_eq!(format!("{}", ReceiptType::Delivered), "Delivered");
        assert_eq!(format!("{}", ReceiptType::Read), "Read");
        assert_eq!(format!("{}", ReceiptType::Played), "Played");
    }

    #[test]
    fn message_receipt_roundtrip() {
        let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
        let r = MessageReceipt {
            device_jid: "4155550100.0:1@s.whatsapp.net".to_string(),
            receipt_type: ReceiptType::Read,
            timestamp: ts,
            source: EvidenceSource::WalHistoric,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MessageReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.device_jid, "4155550100.0:1@s.whatsapp.net");
    }

    // ── ParticipantAction / GroupParticipantEvent ─────────────────────────
    #[test]
    fn participant_action_display() {
        assert_eq!(format!("{}", ParticipantAction::Joined), "Joined");
        assert_eq!(format!("{}", ParticipantAction::Left), "Left");
        assert_eq!(format!("{}", ParticipantAction::Added), "Added");
        assert_eq!(format!("{}", ParticipantAction::Removed), "Removed");
        assert_eq!(format!("{}", ParticipantAction::Promoted), "Promoted");
        assert_eq!(format!("{}", ParticipantAction::Demoted), "Demoted");
    }

    #[test]
    fn group_participant_event_roundtrip() {
        let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
        let ev = GroupParticipantEvent {
            group_jid: "group123@g.us".to_string(),
            participant_jid: "alice@s.whatsapp.net".to_string(),
            action: ParticipantAction::Added,
            timestamp: ts,
            source: EvidenceSource::Live,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: GroupParticipantEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.group_jid, "group123@g.us");
        assert_eq!(format!("{}", back.action), "Added");
    }

    // ── ForensicWarning ───────────────────────────────────────────────────
    #[test]
    fn forensic_warning_vacuum_display() {
        let w = ForensicWarning::DatabaseVacuumed { freelist_page_count: 0 };
        let s = format!("{}", w);
        assert!(s.contains("VACUUM") || s.contains("vacuum") || s.contains("Vacuum"), "got: {s}");
    }

    #[test]
    fn forensic_warning_selective_deletion_display() {
        let w = ForensicWarning::SelectiveDeletion {
            suspect_jid: "bad@s.whatsapp.net".to_string(),
            deletion_rate_pct: 87,
        };
        let s = format!("{}", w);
        assert!(s.contains("87") || s.contains("selective") || s.contains("Selective"), "got: {s}");
    }

    #[test]
    fn forensic_warning_hmac_mismatch() {
        let w = ForensicWarning::HmacMismatch;
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("Hmac") || json.contains("hmac") || json.contains("HMAC"), "got: {json}");
    }

    #[test]
    fn forensic_warning_roundtrip() {
        let w = ForensicWarning::TimestampAnomaly {
            message_row_id: 42,
            description: "backwards".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: ForensicWarning = serde_json::from_str(&json).unwrap();
        if let ForensicWarning::TimestampAnomaly { message_row_id, .. } = back {
            assert_eq!(message_row_id, 42);
        } else {
            panic!("wrong variant");
        }
    }

    // ── Message new fields ────────────────────────────────────────────────
    #[test]
    fn message_starred_default_false() {
        let json = r#"{
            "id":1,"chat_id":1,"from_me":true,
            "timestamp":{"utc":"2024-03-15T14:07:00Z","local_offset_seconds":0},
            "content":{"Text":"hi"},
            "reactions":[],"source":"Live","row_offset":0
        }"#;
        let m: Message = serde_json::from_str(json).unwrap();
        assert!(!m.starred, "starred should default to false");
        assert!(!m.is_forwarded);
        assert_eq!(m.forward_score, None);
        assert!(m.edit_history.is_empty());
        assert!(m.receipts.is_empty());
    }

    #[test]
    fn message_starred_true_roundtrip() {
        let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
        let m = Message {
            id: 1,
            chat_id: 1,
            sender_jid: None,
            from_me: true,
            timestamp: ts,
            content: MessageContent::Text("hello".to_string()),
            reactions: vec![],
            quoted_message: None,
            source: EvidenceSource::Live,
            row_offset: 0,
            starred: true,
            forward_score: Some(5),
            is_forwarded: true,
            edit_history: vec![],
            receipts: vec![],
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert!(back.starred);
        assert!(back.is_forwarded);
        assert_eq!(back.forward_score, Some(5));
    }

    // ── ViewOnce MessageContent variant ──────────────────────────────────
    #[test]
    fn message_content_view_once_roundtrip() {
        let mr = MediaRef {
            file_path: "Media/WhatsApp Images/IMG-001.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            file_size: 1234,
            extracted_name: None,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        };
        let c = MessageContent::ViewOnce(mr);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("ViewOnce"), "got: {json}");
        let back: MessageContent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, MessageContent::ViewOnce(_)));
    }

    // ── Chat.archived ─────────────────────────────────────────────────────
    #[test]
    fn chat_archived_default_false() {
        let json = r#"{"id":1,"jid":"alice@s.whatsapp.net","is_group":false,"messages":[]}"#;
        let c: Chat = serde_json::from_str(json).unwrap();
        assert!(!c.archived, "archived should default to false");
    }

    #[test]
    fn chat_archived_true_roundtrip() {
        let c = Chat {
            id: 1,
            jid: "alice@s.whatsapp.net".to_string(),
            name: None,
            is_group: false,
            messages: vec![],
            archived: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Chat = serde_json::from_str(&json).unwrap();
        assert!(back.archived);
    }

    // ── ExtractionResult new fields ───────────────────────────────────────
    #[test]
    fn extraction_result_new_fields_default_empty() {
        let r = ExtractionResult::default();
        assert!(r.forensic_warnings.is_empty());
        assert!(r.group_participant_events.is_empty());
    }
}
