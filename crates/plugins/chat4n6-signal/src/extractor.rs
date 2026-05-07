//! Signal Android `signal.sqlite` extractor.
//!
//! Signal uses SQLite encrypted with SQLCipher.  Callers must supply
//! **plaintext** bytes; decryption is a separate pre-processing step.
//!
//! # Signal `sms.type` direction heuristic
//!
//! Signal's `sms.type` is a bitmask.  Bits 0-4 encode the "message box" base type.
//! The authoritative source is `Types.java` in the Signal-Android repository.
//!
//! Correct approach: `BASE_TYPE_MASK = 0x1F`; message is outgoing if the masked
//! base type is in `OUTGOING_BASE_TYPES = {2, 11, 21, 22, 23, 24, 25, 26, 28}`.
//! Examples: type=87 → base=23 (SECURE_SENT, outgoing); type=20 → base=20 (incoming).
//!
//! `from_recipient_id` identifies the sender row but is unreliable as a direction
//! proxy because Signal sets it to the local user's `_id` for outgoing messages —
//! and we do not know the local user's `_id` without additional context.

use anyhow::{Context, Result};
pub use helpers::{is_outgoing_base_type, attachment_table_name};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EvidenceSource, ExtractionResult, ForensicTimestamp,
    ForensicWarning, MediaRef, Message, MessageContent, Reaction,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    read_schema_version,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

// ── Public API ───────────────────────────────────────────────────────────────

/// Extract all forensic artifacts from a Signal `signal.sqlite` byte slice.
///
/// `tz_offset_secs` — seconds east of UTC for local time display.
pub fn extract_from_signal_db(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open signal.sqlite")?;

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    let by_table = partition_by_table(&records);

    // Determine schema version early — used for schema-aware table/column selection.
    let schema_version: u32 = read_schema_version(db_bytes);

    // Build recipient lookup: _id → (jid_string, display_name, phone)
    let recipients = build_recipient_map(tbl(&by_table, "recipient"));

    // Build thread map: thread._id → Chat (filled with messages below)
    let mut chats = build_thread_map(tbl(&by_table, "thread"), &recipients);

    // Build attachment lookup: message_id → MediaRef.
    // Schema v168+: table is `attachment` (columns: message_id, file_name, data_size)
    // pre-v168:     table is `part`       (columns: mid, name, file_size)
    let attach_table = helpers::attachment_table_name(Some(schema_version));
    let parts = build_part_map(tbl(&by_table, attach_table), Some(schema_version));

    // Build reaction lookup: sms._id → Vec<Reaction>
    let reactions = build_reaction_map(
        tbl(&by_table, "reaction"),
        &recipients,
        tz_offset_secs,
        Some(schema_version),
    );

    // Map sms rows into chats
    for rec in tbl(&by_table, "sms") {
        if let Some(msg) = record_to_message(rec, &parts, &reactions, tz_offset_secs) {
            chats
                .entry(msg.chat_id)
                .or_insert_with(|| Chat::stub(msg.chat_id))
                .messages
                .push(msg);
        }
    }

    // Extract calls
    let calls = extract_calls(tbl(&by_table, "call"), tz_offset_secs);

    // Build contacts from recipients
    let contacts: Vec<Contact> = recipients
        .values()
        .map(|r| Contact {
            jid: r.jid.clone(),
            display_name: r.display_name.clone(),
            phone_number: r.phone.clone(),
            source: EvidenceSource::Live,
        })
        .collect();

    // Detect forensic warnings
    let mut forensic_warnings: Vec<ForensicWarning> = Vec::new();
    detect_disappearing_timers(
        tbl(&by_table, "thread"),
        tbl(&by_table, "sms"),
        &mut forensic_warnings,
    );
    detect_sealed_sender_unresolved(
        tbl(&by_table, "sms"),
        &recipients,
        &mut forensic_warnings,
    );

    let chats_vec: Vec<Chat> = chats.into_values().collect();

    Ok(ExtractionResult {
        chats: chats_vec,
        contacts,
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version,
        forensic_warnings,
        group_participant_events: Vec::new(),
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
    })
}

// ── Internal data structures ─────────────────────────────────────────────────

struct RecipientInfo {
    /// Signal JID: `{e164}@signal` or `{aci}@signal` fallback.
    jid: String,
    display_name: Option<String>,
    phone: Option<String>,
}

// ── Partition ────────────────────────────────────────────────────────────────

fn partition_by_table(records: &[RecoveredRecord]) -> HashMap<String, Vec<RecoveredRecord>> {
    let mut map: HashMap<String, Vec<RecoveredRecord>> = HashMap::new();
    for r in records {
        map.entry(r.table.clone()).or_default().push(r.clone());
    }
    map
}

/// Look up a table name in a `partition_by_table` map and return its records as a slice.
/// Returns an empty slice when the table is absent.
fn tbl<'a>(by: &'a HashMap<String, Vec<RecoveredRecord>>, name: &str) -> &'a [RecoveredRecord] {
    by.get(name).map(|v| v.as_slice()).unwrap_or_default()
}

// ── Recipient map ────────────────────────────────────────────────────────────

/// Schema: _id, e164, aci, group_id, system_display_name, profile_joined_name, type
/// values[] after the leading Null (INTEGER PRIMARY KEY): [0]=Null, [1]=e164, [2]=aci,
/// [3]=group_id, [4]=system_display_name, [5]=profile_joined_name, [6]=type
fn build_recipient_map(records: &[RecoveredRecord]) -> HashMap<i64, RecipientInfo> {
    use helpers::cols::recipient as col;
    let mut map = HashMap::new();
    for r in records {
        let id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let e164 = r.text_val(col::E164);
        let aci = r.text_val(col::ACI);
        let _group_id = r.text_val(col::GROUP_ID);
        let system_name = r.text_val(col::SYSTEM_DISPLAY_NAME);
        let joined_name = r.text_val(col::PROFILE_JOINED_NAME);

        // JID: prefer e164, fall back to aci
        let jid = if let Some(ref phone) = e164 {
            format!("{}@signal", phone.trim_start_matches('+'))
        } else if let Some(ref uuid) = aci {
            format!("{uuid}@signal")
        } else {
            format!("{id}@signal")
        };

        // display_name: prefer profile_joined_name, then system_display_name
        let display_name = joined_name.or(system_name);

        map.insert(id, RecipientInfo { jid, display_name, phone: e164 });
    }
    map
}

// ── Thread map ───────────────────────────────────────────────────────────────

/// Schema: _id, recipient_id, archived, message_count
/// values[]: [0]=Null, [1]=recipient_id, [2]=archived, [3]=message_count
fn build_thread_map(
    records: &[RecoveredRecord],
    recipients: &HashMap<i64, RecipientInfo>,
) -> HashMap<i64, Chat> {
    use helpers::cols::thread as col;
    let mut map = HashMap::new();
    for r in records {
        let thread_id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let recipient_id = match r.values.get(col::RECIPIENT_ID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let archived = match r.values.get(col::ARCHIVED) {
            Some(SqlValue::Int(n)) => *n != 0,
            _ => false,
        };

        let (jid, name) = if let Some(info) = recipients.get(&recipient_id) {
            (info.jid.clone(), info.display_name.clone())
        } else {
            (format!("{recipient_id}@signal"), None)
        };

        map.insert(
            thread_id,
            Chat {
                id: thread_id,
                jid,
                name,
                is_group: false, // group detection deferred (group_id check on recipient)
                messages: Vec::new(),
                archived,
            },
        );
    }
    map
}

// ── Part (attachment) map ────────────────────────────────────────────────────

/// Handles both pre-v168 `part` table and post-v168 `attachment` table.
/// Column positions are the same in both layouts (column names differ):
///   pre-v168 `part`:       _id, mid,        content_type, name,      file_size
///   post-v168 `attachment`: _id, message_id, content_type, file_name, data_size
/// values[]: [0]=Null, [1]=message_id, [2]=content_type, [3]=file_name, [4]=file_size
fn build_part_map(records: &[RecoveredRecord], _schema_version: Option<u32>) -> HashMap<i64, MediaRef> {
    use helpers::cols::attachment as col;
    let mut map = HashMap::new();
    for r in records {
        let mid = match r.values.get(col::MESSAGE_ID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let mime_type = r.text_val(col::CONTENT_TYPE).unwrap_or_else(|| "application/octet-stream".to_string());
        let file_name = r.text_val(col::FILE_NAME);
        let file_size = match r.values.get(col::FILE_SIZE) {
            Some(SqlValue::Int(n)) => *n as u64,
            _ => 0,
        };
        map.insert(
            mid,
            MediaRef {
                file_path: file_name.clone().unwrap_or_default(),
                mime_type,
                file_size,
                extracted_name: file_name,
                thumbnail_b64: None,
                duration_secs: None,
                file_hash: None,
                encrypted_hash: None,
                cdn_url: None,
                media_key_b64: None,
            },
        );
    }
    map
}

// ── Reaction map ─────────────────────────────────────────────────────────────

/// Reaction table layout changed at schema v168.
///
/// Pre-v168:  _id, message_id, is_mms, author_id, emoji, date_sent, date_received
///   values[]: [0]=Null, [1]=message_id, [2]=is_mms, [3]=author_id, [4]=emoji,
///             [5]=date_sent, [6]=date_received
///
/// Post-v168: _id, message_id, author_id, emoji, date_sent, date_received
///   values[]: [0]=Null, [1]=message_id, [2]=author_id, [3]=emoji,
///             [4]=date_sent, [5]=date_received
fn build_reaction_map(
    records: &[RecoveredRecord],
    recipients: &HashMap<i64, RecipientInfo>,
    tz_offset_secs: i32,
    schema_version: Option<u32>,
) -> HashMap<i64, Vec<Reaction>> {
    use helpers::cols::reaction as col;
    // Determine column offsets based on schema version.
    // pre-v168 had an extra `is_mms` column at index 2; all subsequent columns shift +1.
    // v168+:    author_id=col::AUTHOR_ID(2), emoji=col::EMOJI(3), date_sent=col::DATE_SENT(4)
    // pre-v168: author_id=3, emoji=4, date_sent=5
    let (author_col, emoji_col, date_sent_col) = if schema_version.map_or(false, |v| v >= 168) {
        (col::AUTHOR_ID, col::EMOJI, col::DATE_SENT)
    } else {
        (col::AUTHOR_ID + 1, col::EMOJI + 1, col::DATE_SENT + 1)
    };

    let mut map: HashMap<i64, Vec<Reaction>> = HashMap::new();
    for r in records {
        let message_id = match r.values.get(col::MESSAGE_ID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let author_id = match r.values.get(author_col) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let emoji = match r.text_val(emoji_col) {
            Some(e) => e,
            None => continue,
        };
        let date_sent = match r.values.get(date_sent_col) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };

        let reactor_jid = recipients
            .get(&author_id)
            .map(|i| i.jid.clone())
            .unwrap_or_else(|| format!("{author_id}@signal"));

        let reaction = Reaction {
            emoji,
            reactor_jid,
            timestamp: ForensicTimestamp::from_millis(date_sent, tz_offset_secs),
            source: r.source.clone(),
        };
        map.entry(message_id).or_default().push(reaction);
    }
    map
}

// ── SMS → Message ────────────────────────────────────────────────────────────

/// Schema: _id, thread_id, date, date_received, type, body, from_recipient_id,
///         read, remote_deleted[, expires_started[, envelope_type[, date_server]]]
/// values[]: [0]=Null, [1]=thread_id, [2]=date (sent), [3]=date_received, [4]=type,
///           [5]=body, [6]=from_recipient_id, [7]=read, [8]=remote_deleted
///           [9]=expires_started (optional), [10]=envelope_type (optional),
///           [11]=date_server (optional, added ~v168)
///
/// Timestamp priority: date_server > date_received > date (sent)
fn record_to_message(
    r: &RecoveredRecord,
    parts: &HashMap<i64, MediaRef>,
    reactions: &HashMap<i64, Vec<Reaction>>,
    tz_offset_secs: i32,
) -> Option<Message> {
    use helpers::cols::sms as col;
    let id = r.row_id?;
    let thread_id = match r.values.get(col::THREAD_ID)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    // date (sent) is mandatory — used as last-resort fallback.
    let date_sent_ms = match r.values.get(col::DATE)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    // date_received: prefer over date_sent when available and positive.
    let date_received_ms = match r.values.get(col::DATE_RECEIVED) {
        Some(SqlValue::Int(n)) if *n > 0 => Some(*n),
        _ => None,
    };
    // date_server: highest priority — absent in older schemas → None.
    let date_server_ms = match r.values.get(col::DATE_SERVER) {
        Some(SqlValue::Int(n)) if *n > 0 => Some(*n),
        _ => None,
    };
    // Priority: date_server > date_received > date_sent
    let ts_ms = date_server_ms
        .or(date_received_ms)
        .unwrap_or(date_sent_ms);

    let sms_type = match r.values.get(col::TYPE) {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };
    let body = r.text_val(col::BODY);
    let remote_deleted = match r.values.get(col::REMOTE_DELETED) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };

    // Direction: use Signal's canonical OUTGOING_BASE_TYPES set from Types.java.
    let from_me = helpers::is_outgoing_base_type(sms_type);

    // Content resolution:
    // 1. remote_deleted → Deleted
    // 2. has a matching part attachment → Media
    // 3. body text present → Text
    // 4. otherwise → Deleted (empty purged row)
    let content = if remote_deleted {
        MessageContent::Deleted
    } else if let Some(media) = parts.get(&id) {
        MessageContent::Media(media.clone())
    } else if let Some(text) = body {
        MessageContent::Text(text)
    } else {
        MessageContent::Deleted
    };

    let msg_reactions = reactions.get(&id).cloned().unwrap_or_default();

    Some(Message {
        id,
        chat_id: thread_id,
        sender_jid: None,
        from_me,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        content,
        reactions: msg_reactions,
        quoted_message: None,
        source: r.source.clone(),
        row_offset: r.offset,
        starred: false,
        forward_score: None,
        is_forwarded: false,
        edit_history: Vec::new(),
        receipts: Vec::new(),
        forwarded_from: None,
    })
}

// ── Call extraction ──────────────────────────────────────────────────────────

/// Schema: _id, call_id, message_id, peer, type, direction, event, timestamp
/// values[]: [0]=Null, [1]=call_id, [2]=message_id, [3]=peer, [4]=type,
///           [5]=direction, [6]=event, [7]=timestamp
///
/// `type`: 1=audio incoming, 2=audio outgoing, 3=video incoming, 4=video outgoing
/// `direction`: 0=incoming, 1=outgoing
/// `event`: 0=ongoing, 1=missed, 2=busy, 3=declined, 4=accepted, 5=deleted
fn extract_calls(records: &[RecoveredRecord], tz_offset_secs: i32) -> Vec<CallRecord> {
    records.iter().filter_map(|r| record_to_call(r, tz_offset_secs)).collect()
}

fn record_to_call(r: &RecoveredRecord, tz_offset_secs: i32) -> Option<CallRecord> {
    let id = r.row_id?;
    let peer = r.text_val(3).unwrap_or_default();
    let call_type = match r.values.get(4) {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };
    let direction = match r.values.get(5) {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };
    let event = match r.values.get(6) {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };
    let ts_ms = match r.values.get(7)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };

    // direction: 0=incoming, 1=outgoing
    let from_me = direction != 0;

    // video: call type 3 or 4 = video
    let video = call_type == 3 || call_type == 4;

    // event → CallResult:
    // 0=ongoing→Unknown, 1=missed→Missed, 2=busy→Unknown, 3=declined→Rejected,
    // 4=accepted→Connected, 5=deleted→Unknown
    let call_result = match event {
        1 => CallResult::Missed,
        3 => CallResult::Rejected,
        4 => CallResult::Connected,
        _ => CallResult::Unknown,
    };

    Some(CallRecord {
        call_id: id,
        participants: vec![peer],
        from_me,
        video,
        group_call: false,
        duration_secs: 0, // Signal call table doesn't store duration
        call_result,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        source: r.source.clone(),
        call_creator_device_jid: None,
    })
}

// ── ForensicWarning detectors ─────────────────────────────────────────────────

/// Detect disappearing message timers.
///
/// For each thread row with `expires_in > 0`, count sms rows in that thread
/// where body is absent/empty AND `expires_started > 0` (message has vanished).
/// Emits `ForensicWarning::DisappearingTimerActive` for every such thread.
///
/// Thread schema (values[]): [0]=Null, [1]=recipient_id, [2]=archived,
///   [3]=message_count, [4]=expires_in  (column may be absent in older schemas)
///
/// SMS schema (values[]): [0]=Null, [1]=thread_id, [2]=date, [3]=date_received,
///   [4]=type, [5]=body, [6]=from_recipient_id, [7]=read, [8]=remote_deleted,
///   [9]=expires_started  (column may be absent in older schemas)
fn detect_disappearing_timers(
    thread_records: &[RecoveredRecord],
    sms_records: &[RecoveredRecord],
    warnings: &mut Vec<ForensicWarning>,
) {
    use helpers::cols::{thread as tcol, sms as scol};
    for thread_rec in thread_records {
        let thread_id = match thread_rec.row_id {
            Some(id) => id,
            None => continue,
        };
        let expires_in = match thread_rec.values.get(tcol::EXPIRES_IN) {
            Some(SqlValue::Int(n)) if *n > 0 => *n as u32,
            _ => continue,
        };

        // Count sms rows in this thread that have vanished:
        // body absent/empty AND expires_started > 0
        let vanished_count = sms_records
            .iter()
            .filter(|sms| {
                // Check thread_id matches
                let tid = match sms.values.get(scol::THREAD_ID) {
                    Some(SqlValue::Int(n)) => *n,
                    _ => return false,
                };
                if tid != thread_id {
                    return false;
                }
                // Body absent or empty
                let body_empty = match sms.values.get(scol::BODY) {
                    None | Some(SqlValue::Null) => true,
                    Some(SqlValue::Text(s)) => s.is_empty(),
                    _ => false,
                };
                if !body_empty {
                    return false;
                }
                // expires_started > 0
                match sms.values.get(scol::EXPIRES_STARTED) {
                    Some(SqlValue::Int(n)) => *n > 0,
                    _ => false,
                }
            })
            .count() as u32;

        if vanished_count > 0 {
            warnings.push(ForensicWarning::DisappearingTimerActive {
                chat_id: thread_id,
                timer_seconds: expires_in,
                vanished_count,
            });
        }
    }
}

// ── Public helpers (also used by tests) ──────────────────────────────────────

pub mod helpers {
    /// Return the attachment table name for a given schema version.
    ///
    /// Signal renamed the attachment table in schema v168:
    /// - pre-v168:  `part`       (columns: mid, name, _data, …)
    /// - v168+:     `attachment` (columns: message_id, file_name, data_size, …)
    ///
    /// Unknown schema version falls back to `part` (conservative).
    pub fn attachment_table_name(schema_version: Option<u32>) -> &'static str {
        match schema_version {
            Some(v) if v >= 168 => "attachment",
            _ => "part",
        }
    }

    /// Determine whether a raw Signal `sms.type` value represents an outgoing message.
    ///
    /// Signal's `Types.java` defines:
    ///   `BASE_TYPE_MASK = 0x1F`
    ///   Outgoing base types: {2, 11, 21, 22, 23, 24, 25, 26, 28}
    ///
    /// A message is outgoing if `(type_val & BASE_TYPE_MASK)` is in that set.
    pub fn is_outgoing_base_type(type_val: i64) -> bool {
        const OUTGOING_BASE_TYPES: &[i64] = &[2, 11, 21, 22, 23, 24, 25, 26, 28];
        let base = type_val & 0x1F;
        OUTGOING_BASE_TYPES.contains(&base)
    }

    /// Column index constants for `RecoveredRecord::values[]`.
    ///
    /// Index 0 is always `Null` (the implicit `_id` INTEGER PRIMARY KEY rowid alias).
    /// Real column data starts at index 1.
    pub mod cols {
        /// `sms` table column indices.
        ///
        /// Schema: _id, thread_id, date, date_received, type, body,
        ///         from_recipient_id, read, remote_deleted[, expires_started
        ///         [, envelope_type[, date_server]]]
        pub mod sms {
            pub const THREAD_ID: usize = 1;
            pub const DATE: usize = 2;          // date_sent (ms)
            pub const DATE_RECEIVED: usize = 3;
            pub const TYPE: usize = 4;
            pub const BODY: usize = 5;
            pub const FROM_RECIPIENT_ID: usize = 6;
            pub const READ: usize = 7;
            pub const REMOTE_DELETED: usize = 8;
            pub const EXPIRES_STARTED: usize = 9;
            pub const ENVELOPE_TYPE: usize = 10;
            pub const DATE_SERVER: usize = 11;
        }
        /// `thread` table column indices.
        ///
        /// Schema: _id, recipient_id, archived, message_count[, expires_in]
        pub mod thread {
            pub const RECIPIENT_ID: usize = 1;
            pub const ARCHIVED: usize = 2;
            pub const MESSAGE_COUNT: usize = 3;
            pub const EXPIRES_IN: usize = 4;
        }
        /// `recipient` table column indices.
        ///
        /// Schema: _id, e164, aci, group_id, system_display_name, profile_joined_name, type
        pub mod recipient {
            pub const E164: usize = 1;
            pub const ACI: usize = 2;
            pub const GROUP_ID: usize = 3;
            pub const SYSTEM_DISPLAY_NAME: usize = 4;
            pub const PROFILE_JOINED_NAME: usize = 5;
            pub const TYPE: usize = 6;
        }
        /// `reaction` table column indices (post-v168 layout).
        ///
        /// Schema: _id, message_id, author_id, emoji, date_sent, date_received
        ///
        /// Pre-v168 had an extra `is_mms` column at index 2; author_id shifted to 3.
        /// Use `build_reaction_map`'s schema-version branch for the offset adjustment.
        pub mod reaction {
            pub const MESSAGE_ID: usize = 1;
            pub const AUTHOR_ID: usize = 2;     // post-v168; pre-v168 = 3
            pub const EMOJI: usize = 3;         // post-v168; pre-v168 = 4
            pub const DATE_SENT: usize = 4;     // post-v168; pre-v168 = 5
            pub const DATE_RECEIVED: usize = 5; // post-v168; pre-v168 = 6
        }
        /// `attachment` / `part` table column indices.
        ///
        /// Both tables share the same column positions (only names differ):
        ///   pre-v168 `part`:       _id, mid,        content_type, name,      file_size
        ///   post-v168 `attachment`: _id, message_id, content_type, file_name, data_size
        pub mod attachment {
            pub const MESSAGE_ID: usize = 1;
            pub const CONTENT_TYPE: usize = 2;
            pub const FILE_NAME: usize = 3;
            pub const FILE_SIZE: usize = 4;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_sqlite_forensics::record::{RecoveredRecord, SqlValue};
    use chat4n6_plugin_api::EvidenceSource;

    fn make_record(table: &str) -> RecoveredRecord {
        RecoveredRecord {
            table: table.to_string(),
            row_id: Some(1),
            values: vec![SqlValue::Null],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        }
    }

    #[test]
    fn tbl_empty_map_returns_empty_slice() {
        let by: HashMap<String, Vec<RecoveredRecord>> = HashMap::new();
        assert!(tbl(&by, "thread").is_empty());
    }

    #[test]
    fn tbl_populated_map_returns_correct_slice() {
        let mut by: HashMap<String, Vec<RecoveredRecord>> = HashMap::new();
        by.insert("thread".to_string(), vec![make_record("thread"), make_record("thread")]);
        by.insert("sms".to_string(), vec![make_record("sms")]);
        assert_eq!(tbl(&by, "thread").len(), 2);
        assert_eq!(tbl(&by, "sms").len(), 1);
        assert!(tbl(&by, "missing").is_empty());
    }
}

/// Detect sealed-sender messages whose sender cannot be resolved.
///
/// Iterates sms rows looking for `envelope_type & 0x10 != 0` (sealed sender bit).
/// If the `from_recipient_id` for such a row is absent from the recipient map,
/// the sender is unresolvable.  Emits one `ForensicWarning::SealedSenderUnresolved`
/// per thread_id where at least one unresolved sealed-sender message was found.
///
/// SMS schema (values[]): [0]=Null, [1]=thread_id, [2]=date, [3]=date_received,
///   [4]=type, [5]=body, [6]=from_recipient_id, [7]=read, [8]=remote_deleted,
///   [9]=expires_started, [10]=envelope_type  (may be absent in older schemas)
fn detect_sealed_sender_unresolved(
    sms_records: &[RecoveredRecord],
    recipients: &HashMap<i64, RecipientInfo>,
    warnings: &mut Vec<ForensicWarning>,
) {
    use helpers::cols::sms as col;
    let mut unresolved_per_thread: HashMap<i64, u32> = HashMap::new();

    for sms in sms_records {
        // envelope_type — silently skip if column absent (older schemas)
        let envelope_type = match sms.values.get(col::ENVELOPE_TYPE) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        // Sealed-sender bit: 0x10
        if envelope_type & 0x10 == 0 {
            continue;
        }

        let thread_id = match sms.values.get(col::THREAD_ID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let from_recipient_id = match sms.values.get(col::FROM_RECIPIENT_ID) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };

        // Unresolved = sender not in recipient map
        if !recipients.contains_key(&from_recipient_id) {
            *unresolved_per_thread.entry(thread_id).or_insert(0) += 1;
        }
    }

    for (thread_id, count) in unresolved_per_thread {
        warnings.push(ForensicWarning::SealedSenderUnresolved { thread_id, count });
    }
}

