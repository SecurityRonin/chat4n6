//! Signal Android `signal.sqlite` extractor.
//!
//! Signal uses SQLite encrypted with SQLCipher.  Callers must supply
//! **plaintext** bytes; decryption is a separate pre-processing step.
//!
//! # Signal `sms.type` direction heuristic
//!
//! Signal's `sms.type` is a bitmask carrying the "message box" in bits 0-4.
//! Documented base types: 1 = inbox (received), 2 = sent.  In practice the
//! field accumulates flags so the raw value is rarely exactly 1 or 2.
//!
//! Reliable approach: `(type & 0x20) != 0` identifies the outgoing flag that
//! Signal consistently sets for sent/outbox states (values 87, 23, 20 all have
//! bit 5 set; received value 10485 does not).
//!
//! Alternative cross-check: `from_recipient_id` is the sender's `_id`.  For
//! outgoing messages Signal sets this to the local user's own recipient row
//! (typically 1 for accounts that have sent at least one message).  We use the
//! `type` bitmask as the primary signal because it is more reliable than
//! assuming the local user's `_id`.

use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EvidenceSource, ExtractionResult, ForensicTimestamp,
    MediaRef, Message, MessageContent, Reaction,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
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
    let empty: Vec<RecoveredRecord> = Vec::new();

    // Build recipient lookup: _id → (jid_string, display_name, phone)
    let recipients = build_recipient_map(by_table.get("recipient").map(|v| v.as_slice()).unwrap_or(&empty));

    // Build thread map: thread._id → Chat (filled with messages below)
    let mut chats = build_thread_map(by_table.get("thread").map(|v| v.as_slice()).unwrap_or(&empty), &recipients);

    // Build attachment lookup: sms._id (= part.mid) → MediaRef
    let parts = build_part_map(by_table.get("part").map(|v| v.as_slice()).unwrap_or(&empty));

    // Build reaction lookup: sms._id → Vec<Reaction>
    let reactions = build_reaction_map(
        by_table.get("reaction").map(|v| v.as_slice()).unwrap_or(&empty),
        &recipients,
        tz_offset_secs,
    );

    // Map sms rows into chats
    for rec in by_table.get("sms").map(|v| v.as_slice()).unwrap_or(&empty) {
        if let Some(msg) = record_to_message(rec, &parts, &reactions, tz_offset_secs) {
            chats
                .entry(msg.chat_id)
                .or_insert_with(|| Chat {
                    id: msg.chat_id,
                    jid: String::new(),
                    name: None,
                    is_group: false,
                    messages: Vec::new(),
                    archived: false,
                })
                .messages
                .push(msg);
        }
    }

    // Extract calls
    let calls = extract_calls(
        by_table.get("call").map(|v| v.as_slice()).unwrap_or(&empty),
        tz_offset_secs,
    );

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

    let chats_vec: Vec<Chat> = chats.into_values().collect();

    Ok(ExtractionResult {
        chats: chats_vec,
        contacts,
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 185,
        forensic_warnings: Vec::new(),
        group_participant_events: Vec::new(),
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

// ── Recipient map ────────────────────────────────────────────────────────────

/// Schema: _id, e164, aci, group_id, system_display_name, profile_joined_name, type
/// values[] after the leading Null (INTEGER PRIMARY KEY): [0]=Null, [1]=e164, [2]=aci,
/// [3]=group_id, [4]=system_display_name, [5]=profile_joined_name, [6]=type
fn build_recipient_map(records: &[RecoveredRecord]) -> HashMap<i64, RecipientInfo> {
    let mut map = HashMap::new();
    for r in records {
        let id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let e164 = text_val(r, 1);
        let aci = text_val(r, 2);
        let _group_id = text_val(r, 3);
        let system_name = text_val(r, 4);
        let joined_name = text_val(r, 5);

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
    let mut map = HashMap::new();
    for r in records {
        let thread_id = match r.row_id {
            Some(id) => id,
            None => continue,
        };
        let recipient_id = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let archived = match r.values.get(2) {
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

/// Schema: _id, mid, content_type, name, file_size
/// values[]: [0]=Null, [1]=mid, [2]=content_type, [3]=name, [4]=file_size
fn build_part_map(records: &[RecoveredRecord]) -> HashMap<i64, MediaRef> {
    let mut map = HashMap::new();
    for r in records {
        let mid = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let mime_type = text_val(r, 2).unwrap_or_else(|| "application/octet-stream".to_string());
        let file_name = text_val(r, 3);
        let file_size = match r.values.get(4) {
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

/// Schema: _id, message_id, is_mms, author_id, emoji, date_sent, date_received
/// values[]: [0]=Null, [1]=message_id, [2]=is_mms, [3]=author_id, [4]=emoji,
///           [5]=date_sent, [6]=date_received
fn build_reaction_map(
    records: &[RecoveredRecord],
    recipients: &HashMap<i64, RecipientInfo>,
    tz_offset_secs: i32,
) -> HashMap<i64, Vec<Reaction>> {
    let mut map: HashMap<i64, Vec<Reaction>> = HashMap::new();
    for r in records {
        let message_id = match r.values.get(1) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let author_id = match r.values.get(3) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let emoji = match text_val(r, 4) {
            Some(e) => e,
            None => continue,
        };
        let date_sent = match r.values.get(5) {
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
///         read, remote_deleted
/// values[]: [0]=Null, [1]=thread_id, [2]=date, [3]=date_received, [4]=type,
///           [5]=body, [6]=from_recipient_id, [7]=read, [8]=remote_deleted
fn record_to_message(
    r: &RecoveredRecord,
    parts: &HashMap<i64, MediaRef>,
    reactions: &HashMap<i64, Vec<Reaction>>,
    tz_offset_secs: i32,
) -> Option<Message> {
    let id = r.row_id?;
    let thread_id = match r.values.get(1)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let ts_ms = match r.values.get(2)? {
        SqlValue::Int(n) => *n,
        _ => return None,
    };
    let sms_type = match r.values.get(4) {
        Some(SqlValue::Int(n)) => *n,
        _ => 0,
    };
    let body = text_val(r, 5);
    let remote_deleted = match r.values.get(8) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };

    // Direction heuristic using the base type (bits 0-4).
    // Signal's Types.java defines these base type constants:
    //   SECURE_SENT_TYPE     = 23 (0x17) — outgoing
    //   SECURE_RECEIVED_TYPE = 20..22    — incoming
    //   Standard SMS: sent = 2, received = 1
    // Fixture values: 87 → base 23 (sent), 10485 → base 21 (received).
    // Treat base types 2, 3, 4, 5, 6, 23 as outgoing; all others as incoming.
    let base_type = sms_type & 0x1F;
    let from_me = matches!(base_type, 2 | 3 | 4 | 5 | 6 | 23 | 24 | 25);

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
    let peer = text_val(r, 3).unwrap_or_default();
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

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract a TEXT value at `values[idx]`, returning None if absent/null/non-text.
fn text_val(r: &RecoveredRecord, idx: usize) -> Option<String> {
    match r.values.get(idx) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}
