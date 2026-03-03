use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    Live,
    WalPending,
    WalHistoric,
    Freelist,
    FtsOnly,
    CarvedUnalloc { confidence_pct: u8 },
    CarvedDb,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "LIVE"),
            Self::WalPending => write!(f, "WAL-PENDING"),
            Self::WalHistoric => write!(f, "WAL-HISTORIC"),
            Self::Freelist => write!(f, "FREELIST"),
            Self::FtsOnly => write!(f, "FTS-ONLY"),
            Self::CarvedUnalloc { confidence_pct } => {
                write!(f, "CARVED-UNALLOC {}%", confidence_pct)
            }
            Self::CarvedDb => write!(f, "CARVED-DB"),
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
        Self { utc, local_offset_seconds }
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub reactor_jid: String,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallRecord {
    pub call_id: i64,
    pub participants: Vec<String>,
    pub from_me: bool,
    pub video: bool,
    pub group_call: bool,
    pub duration_secs: u32,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageContent {
    Text(String),
    Media(MediaRef),
    Location { lat: f64, lon: f64, name: Option<String> },
    VCard(String),
    Deleted,
    System(String),
    Unknown(i32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
