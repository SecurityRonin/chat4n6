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
    /// View-once image (msg_type 53) or video (msg_type 54).
    /// Media key and CDN URL survive long after the user "viewed" it.
    ViewOnce(MediaRef),
    Location {
        lat: f64,
        lon: f64,
        name: Option<String>,
    },
    VCard(String),
    Deleted,
    /// Forensically recovered ghost content: deleted message text recovered
    /// from message_quoted table (msg_type=15 tombstone with quoted reference).
    GhostRecovered(String),
    System(String),
    Unknown(i32),
}

// ── Edit history ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EditHistoryEntry {
    pub original_text: String,
    pub edited_at: ForensicTimestamp,
    pub source: EvidenceSource,
}

// ── Message receipts ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReceiptType {
    Delivered,
    Read,
    Played,
}

impl fmt::Display for ReceiptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivered => write!(f, "Delivered"),
            Self::Read => write!(f, "Read"),
            Self::Played => write!(f, "Played"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageReceipt {
    pub device_jid: String,
    pub receipt_type: ReceiptType,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

// ── Group participant events ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParticipantAction {
    Joined,
    Left,
    Added,
    Removed,
    Promoted,
    Demoted,
}

impl fmt::Display for ParticipantAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Joined => write!(f, "Joined"),
            Self::Left => write!(f, "Left"),
            Self::Added => write!(f, "Added"),
            Self::Removed => write!(f, "Removed"),
            Self::Promoted => write!(f, "Promoted"),
            Self::Demoted => write!(f, "Demoted"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupParticipantEvent {
    pub group_jid: String,
    pub participant_jid: String,
    pub action: ParticipantAction,
    pub timestamp: ForensicTimestamp,
    pub source: EvidenceSource,
}

// ── WAL snapshot ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalSnapshot {
    /// Sequential frame index within the WAL file.
    pub frame_number: u32,
    /// True if this frame is a commit record (salt matches, valid checksum).
    pub commit_marker: bool,
    /// ROWIDs of messages that first appear in this frame.
    pub messages_added: Vec<i64>,
    /// ROWIDs of messages whose row was deleted in this frame.
    pub messages_removed: Vec<i64>,
    /// ROWIDs of messages that were modified (content changed) in this frame.
    pub messages_mutated: Vec<i64>,
    /// Byte offset of this frame within the WAL file.
    pub frame_offset: u64,
}

// ── Forward origin ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForwardOriginKind {
    User,
    Channel,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForwardOrigin {
    pub origin_kind: ForwardOriginKind,
    /// Platform-scoped identifier (JID, channel URL, etc.).
    pub origin_id: String,
    pub origin_name: Option<String>,
    pub original_timestamp: Option<ForensicTimestamp>,
}

// ── ImpossibleReason ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpossibleReason {
    /// Timestamp predates Unix epoch (1970-01-01).
    BeforeUnixEpoch,
    /// Timestamp is in the future relative to acquisition date.
    AfterAcquisition,
    /// Timestamp predates WhatsApp's founding (2009).
    BeforeWhatsApp,
}

// ── Anti-forensics warnings ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForensicWarning {
    /// SQLite VACUUM was run — freelist erased, potentially destroying deleted record remnants.
    DatabaseVacuumed { freelist_page_count: u32 },
    /// ROWID gaps concentrate on one JID: possible targeted scrubbing.
    SelectiveDeletion { suspect_jid: String, deletion_rate_pct: u8 },
    /// Timestamp order violated: a later ROWID has an earlier timestamp.
    TimestampAnomaly { message_row_id: i64, description: String },
    /// Backup crypt14/15 HMAC does not match payload — file may have been tampered.
    HmacMismatch,
    /// PRAGMA user_version inconsistent with claimed app version.
    SchemaVersionMismatch { db_version: u32, app_version: String },
    /// SQLite change counter implies writes after acquisition date.
    HeaderTampered { change_counter: u32, expected_max: u32 },
    /// iOS CoreData primary-key gap indicates deleted records.
    CoreDataPkGap {
        entity_name: String,
        expected_max: u32,
        observed_max: u32,
        recovered_count: u32,
    },
    /// A message timestamp is logically impossible (before epoch, after acquisition, etc.).
    ImpossibleTimestamp {
        message_row_id: i64,
        ts_utc: DateTime<Utc>,
        reason: ImpossibleReason,
    },
    /// Two or more messages share the same stanza ID — possible replay or copy-paste injection.
    DuplicateStanzaId { stanza_id: String, occurrences: u32 },
    /// A ROWID was reused by rows with different timestamps — evidence of partial delete + reinsert.
    RowIdReuseDetected {
        table: String,
        rowid: i64,
        conflicting_timestamps: Vec<DateTime<Utc>>,
    },
    /// High ratio of orphaned thumbnail blobs with no corresponding message row.
    ThumbnailOrphanHigh {
        orphan_thumbnails: u32,
        total_messages: u32,
        ratio_pct: u8,
    },
    /// Per-file HMAC check failed (individual attachment / WAL segment).
    PerFileHmacMismatch { file_name: String },
    /// A chat has disappearing messages enabled — some content may be permanently lost.
    DisappearingTimerActive {
        chat_id: i64,
        timer_seconds: u32,
        vanished_count: u32,
    },
    /// Signal sealed-sender message whose sender identity could not be resolved.
    SealedSenderUnresolved { thread_id: i64, count: u32 },
    /// A forwarded message references a source message ID that is not present in any snapshot.
    UnresolvedForwardSource { message_id: i64, forward_from_id: i64 },
}

impl fmt::Display for ForensicWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseVacuumed { freelist_page_count } => {
                write!(f, "VACUUM detected (freelist pages remaining: {freelist_page_count})")
            }
            Self::SelectiveDeletion { suspect_jid, deletion_rate_pct } => {
                write!(f, "Selective deletion: {suspect_jid} ({deletion_rate_pct}% gap rate)")
            }
            Self::TimestampAnomaly { message_row_id, description } => {
                write!(f, "Timestamp anomaly at row {message_row_id}: {description}")
            }
            Self::HmacMismatch => write!(f, "HMAC mismatch — backup integrity check FAILED"),
            Self::SchemaVersionMismatch { db_version, app_version } => {
                write!(f, "Schema v{db_version} incompatible with app version {app_version}")
            }
            Self::HeaderTampered { change_counter, expected_max } => {
                write!(f, "Header tamper: change_counter={change_counter} > expected_max={expected_max}")
            }
            Self::CoreDataPkGap { entity_name, recovered_count, .. } => {
                write!(f, "CoreData PK gap in {entity_name}: {recovered_count} potential deleted rows")
            }
            Self::ImpossibleTimestamp { message_row_id, reason, .. } => {
                write!(f, "Impossible timestamp at row {message_row_id}: {reason:?}")
            }
            Self::DuplicateStanzaId { stanza_id, occurrences } => {
                write!(f, "Duplicate stanza ID '{stanza_id}' seen {occurrences}×")
            }
            Self::RowIdReuseDetected { table, rowid, .. } => {
                write!(f, "ROWID {rowid} reused in table '{table}'")
            }
            Self::ThumbnailOrphanHigh { orphan_thumbnails, ratio_pct, .. } => {
                write!(f, "High thumbnail orphan rate: {orphan_thumbnails} orphans ({ratio_pct}%)")
            }
            Self::PerFileHmacMismatch { file_name } => {
                write!(f, "Per-file HMAC mismatch: {file_name}")
            }
            Self::DisappearingTimerActive { chat_id, timer_seconds, vanished_count } => {
                write!(f, "Disappearing timer on chat {chat_id} ({timer_seconds}s): {vanished_count} messages vanished")
            }
            Self::SealedSenderUnresolved { thread_id, count } => {
                write!(f, "Sealed-sender unresolved: {count} messages in thread {thread_id}")
            }
            Self::UnresolvedForwardSource { message_id, forward_from_id } => {
                write!(f, "Forward source missing: message {message_id} references absent ID {forward_from_id}")
            }
        }
    }
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
    /// User deliberately starred this message — proof of awareness.
    #[serde(default)]
    pub starred: bool,
    /// Number of times this message has been forwarded (from message.forward_score).
    #[serde(default)]
    pub forward_score: Option<u32>,
    /// True when forward_score > 0 or message_type indicates forwarded content.
    #[serde(default)]
    pub is_forwarded: bool,
    /// Prior versions of this message's text (message_edit_history table).
    #[serde(default)]
    pub edit_history: Vec<EditHistoryEntry>,
    /// Per-device delivery/read receipts (message_receipt_* tables).
    #[serde(default)]
    pub receipts: Vec<MessageReceipt>,
    /// Resolved origin of a forwarded message (channel, user, unknown source).
    #[serde(default)]
    pub forwarded_from: Option<ForwardOrigin>,
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
    /// User deliberately archived this chat — potential concealment indicator.
    #[serde(default)]
    pub archived: bool,
}

impl Chat {
    /// Creates a minimal placeholder Chat; fill in jid/name/is_group at the call site.
    pub fn stub(id: i64) -> Self {
        Chat {
            id,
            jid: String::new(),
            name: None,
            is_group: false,
            messages: Vec::new(),
            archived: false,
        }
    }
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
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub forensic_warnings: Vec<ForensicWarning>,
    #[serde(default)]
    pub group_participant_events: Vec<GroupParticipantEvent>,
    /// Wall-clock time when extraction began (recorded by the CLI).
    #[serde(default)]
    pub extraction_started_at: Option<DateTime<Utc>>,
    /// Wall-clock time when extraction completed.
    #[serde(default)]
    pub extraction_finished_at: Option<DateTime<Utc>>,
    /// Per-WAL-frame change records for snapshot timeline view.
    #[serde(default)]
    pub wal_snapshots: Vec<WalSnapshot>,
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
            forwarded_from: None,
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

    // ── v2 data model tests (RED — new types not yet implemented) ─────────

    #[test]
    fn extraction_result_has_acquisition_timestamps() {
        let r = ExtractionResult::default();
        assert!(r.extraction_started_at.is_none(),
            "extraction_started_at must default to None");
        assert!(r.extraction_finished_at.is_none(),
            "extraction_finished_at must default to None");
        // Roundtrip with values set
        let json = r#"{"chats":[],"contacts":[],"calls":[],"wal_deltas":[],
            "extraction_started_at":"2026-05-06T10:00:00Z",
            "extraction_finished_at":"2026-05-06T10:01:00Z"}"#;
        let r2: ExtractionResult = serde_json::from_str(json).unwrap();
        assert!(r2.extraction_started_at.is_some());
        assert!(r2.extraction_finished_at.is_some());
    }

    #[test]
    fn extraction_result_has_wal_snapshots() {
        let r = ExtractionResult::default();
        assert!(r.wal_snapshots.is_empty(), "wal_snapshots must default to empty");
        // Build a snapshot and roundtrip
        let snap = WalSnapshot {
            frame_number: 3,
            commit_marker: true,
            messages_added: vec![100, 101],
            messages_removed: vec![99],
            messages_mutated: vec![],
            frame_offset: 4096,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: WalSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.frame_number, 3);
        assert_eq!(back.messages_added, vec![100, 101]);
        assert!(back.commit_marker);
    }

    #[test]
    fn message_has_forwarded_from_field() {
        let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
        let origin = ForwardOrigin {
            origin_kind: ForwardOriginKind::Channel,
            origin_id: "tg-channel://123456".to_string(),
            origin_name: Some("News Channel".to_string()),
            original_timestamp: Some(ts),
        };
        let m = Message {
            id: 1, chat_id: 1,
            sender_jid: None, from_me: false,
            timestamp: ForensicTimestamp::from_millis(1_710_513_200_000, 0),
            content: MessageContent::Text("forwarded".to_string()),
            reactions: vec![], quoted_message: None,
            source: EvidenceSource::Live, row_offset: 0,
            starred: false, forward_score: Some(3), is_forwarded: true,
            edit_history: vec![], receipts: vec![],
            forwarded_from: Some(origin),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("Channel"), "ForwardOriginKind::Channel must serialise");
        let back: Message = serde_json::from_str(&json).unwrap();
        let fo = back.forwarded_from.unwrap();
        assert_eq!(fo.origin_id, "tg-channel://123456");
        assert!(matches!(fo.origin_kind, ForwardOriginKind::Channel));
    }

    #[test]
    fn message_forwarded_from_defaults_to_none() {
        // Old JSON without forwarded_from must still deserialise
        let json = r#"{"id":1,"chat_id":1,"from_me":true,
            "timestamp":{"utc":"2024-03-15T14:07:00Z","local_offset_seconds":0},
            "content":{"Text":"hi"},"reactions":[],"source":"Live",
            "row_offset":0}"#;
        let m: Message = serde_json::from_str(json).unwrap();
        assert!(m.forwarded_from.is_none());
    }

    #[test]
    fn new_forensic_warning_variants_serialise() {
        use chrono::Utc;
        let warnings: Vec<ForensicWarning> = vec![
            ForensicWarning::CoreDataPkGap {
                entity_name: "ZWAMESSAGE".to_string(),
                expected_max: 500, observed_max: 450, recovered_count: 10,
            },
            ForensicWarning::ImpossibleTimestamp {
                message_row_id: 42,
                ts_utc: Utc::now(),
                reason: ImpossibleReason::BeforeUnixEpoch,
            },
            ForensicWarning::DuplicateStanzaId {
                stanza_id: "ABC123".to_string(), occurrences: 2,
            },
            ForensicWarning::RowIdReuseDetected {
                table: "messages".to_string(), rowid: 99,
                conflicting_timestamps: vec![Utc::now(), Utc::now()],
            },
            ForensicWarning::ThumbnailOrphanHigh {
                orphan_thumbnails: 5, total_messages: 10, ratio_pct: 50,
            },
            ForensicWarning::PerFileHmacMismatch {
                file_name: "msgstore.db".to_string(),
            },
            ForensicWarning::DisappearingTimerActive {
                chat_id: 1, timer_seconds: 86400, vanished_count: 3,
            },
            ForensicWarning::SealedSenderUnresolved {
                thread_id: 7, count: 2,
            },
            ForensicWarning::UnresolvedForwardSource {
                message_id: 55, forward_from_id: 99999,
            },
        ];
        for w in &warnings {
            let json = serde_json::to_string(w)
                .unwrap_or_else(|e| panic!("failed to serialise {w:?}: {e}"));
            let _back: ForensicWarning = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("failed to deserialise {json}: {e}"));
        }
    }
}
