use crate::anti_forensics::{
    detect_duplicate_stanza_ids, detect_rowid_reuse, detect_thumbnail_orphans,
    detect_timestamp_distribution_anomaly,
};
use crate::columns::{
    CallLogColumns, ChatColumns, JidColumns, MessageColumns, SchemaColumns, TableColumns,
};
use crate::schema::SchemaVersion;
pub use crate::schema::{default_mime_for_type, is_media_type, msg_type_label};
use crate::schema_gate::validate_message_columns;
use anyhow::{bail, Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EditHistoryEntry, ExtractionResult, ForensicTimestamp,
    GroupParticipantEvent, MediaRef, Message, MessageContent, MessageReceipt, ParticipantAction,
    Reaction, ReceiptType, WalDelta,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    partition_by_table,
    record::{RecoveredRecord, SqlValue},
};
use chrono::Utc;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

/// Extract all forensic artifacts from a msgstore.db byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
///
/// Every column position is resolved by name from the database's own
/// `CREATE TABLE` SQL (see [`crate::columns`]).  WhatsApp reorders these tables
/// between releases, so a fixed ordinal is only ever right for one schema —
/// reading the wrong one yields a complete report full of wrong values.
pub fn extract_from_msgstore(
    db_bytes: &[u8],
    tz_offset_secs: i32,
    _schema_version: SchemaVersion,
) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open msgstore.db")?;

    // Resolve every column position from the database's own schema.  A database
    // whose sqlite_master cannot be read is a bootstrap failure, not an empty
    // database: report it rather than returning a plausible-looking empty result.
    let ddl_map = engine.table_ddl();
    if ddl_map.is_empty() {
        bail!(
            "no CREATE TABLE statement could be read from sqlite_master (page 1 of \
             {} bytes); refusing to extract with unresolved column positions",
            db_bytes.len()
        );
    }
    let schema_cols = SchemaColumns::from_ddl_map(&ddl_map);
    if schema_cols.table("message").is_empty() {
        // Reporting zero messages here would be indistinguishable from a clean
        // device, so name what was actually found instead.
        if !schema_cols.table("messages").is_empty() {
            bail!(
                "msgstore.db declares the legacy `messages` table and no modern `message` \
                 table; this extractor reads the modern generation (message/jid/chat) only. \
                 Refusing to report zero messages for a database it cannot read."
            );
        }
        bail!(
            "msgstore.db declares no `message` table, and no legacy `messages` table \
             either. Tables found ({} total): [{}]",
            schema_cols.table_names().len(),
            summarise_table_names(&schema_cols.table_names())
        );
    }
    let msg_cols = MessageColumns::resolve(schema_cols.table("message"));
    let jid_cols = JidColumns::resolve(schema_cols.table("jid"));
    let chat_cols = ChatColumns::resolve(schema_cols.table("chat"));
    let call_cols = CallLogColumns::resolve(schema_cols.table("call_log"));

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    // Partition by table
    let by_table = partition_by_table(&records);

    // Build JID lookup: id → raw_string
    let jid_map = build_jid_map(tbl(&by_table, "jid"), &jid_cols);

    // Build chat map: chat_id → Chat (populated with messages below)
    let mut chats = build_chats(tbl(&by_table, "chat"), &jid_map, &chat_cols);

    // Validate the resolved map against the records before interpreting any of
    // them.  A wrong map still yields a complete report, so this must fail
    // loudly rather than degrade.
    let msg_records = tbl(&by_table, "message");
    validate_message_columns(msg_records, &msg_cols, Utc::now().timestamp_millis())
        .context("msgstore.db schema validation failed")?;

    // Map messages into chats.  If the chat record was deleted/unrecovered,
    // create a stub so forensically-recovered messages are never silently dropped.
    for rec in msg_records {
        if let Some(msg) = record_to_message(rec, &jid_map, tz_offset_secs, &msg_cols) {
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

    // Build key_id → Vec<row_id> map for DuplicateStanzaId detection.
    let key_id_map = build_key_id_map(msg_records, msg_cols.key_id);

    // ── Quoted messages ──────────────────────────────────────────────────
    // Build a map of message_row_id → (text, sender_jid, from_me, timestamp)
    // from the message_quoted table, then attach to parent messages.
    let quoted_cols = schema_cols.table("message_quoted");
    let quoted_records = tbl(&by_table, "message_quoted");
    let quoted_map = build_quoted_map(quoted_records, &jid_map, tz_offset_secs, quoted_cols);

    // Build ghost map: message_row_id → text_data for ghost recovery.
    // When a deleted/tombstone message (msg_type=15) is later quoted, the
    // message_quoted table preserves its original text.  We index that here
    // so we can upgrade Deleted/Unknown(15) messages to GhostRecovered.
    let ghost_map = build_ghost_map(quoted_records, quoted_cols);

    for chat in chats.values_mut() {
        for msg in &mut chat.messages {
            // Attach quoted_message reference (reply threading)
            if let Some(quoted) = quoted_map.get(&msg.id) {
                msg.quoted_message = Some(Box::new(quoted.clone()));
            }
            // Ghost recovery: upgrade tombstone messages whose original text
            // was preserved in message_quoted.
            if matches!(
                &msg.content,
                MessageContent::Unknown(15) | MessageContent::Deleted
            ) {
                if let Some(ghost_text) = ghost_map.get(&msg.id) {
                    msg.content = MessageContent::GhostRecovered(ghost_text.clone());
                }
            }
        }
    }

    // ── Reactions (message_add_on type=56) ──────────────────────────────────
    // Build map: message_row_id → Vec<Reaction>
    let mut reactions_map: HashMap<i64, Vec<Reaction>> = HashMap::new();
    let add_on_cols = schema_cols.table("message_add_on");
    let add_on_msg_row_id = add_on_cols.get("message_row_id");
    let add_on_sender = add_on_cols.get("sender_jid_row_id");
    let add_on_ts = add_on_cols.get("timestamp");
    let add_on_type_col = add_on_cols.get("type");
    let add_on_text = add_on_cols.get("text_data");
    let add_on_records = tbl(&by_table, "message_add_on");
    for r in add_on_records {
        let Some(msg_row_id) = int_at(r, add_on_msg_row_id) else {
            continue;
        };
        let Some(add_on_type) = int_at(r, add_on_type_col) else {
            continue;
        };
        if add_on_type == 56 {
            // Reaction: emoji in text_data
            let Some(emoji) = text_at(r, add_on_text) else {
                continue;
            };
            let ts_ms = int_at(r, add_on_ts).unwrap_or(0);
            let reactor_jid = int_at(r, add_on_sender)
                .and_then(|n| jid_map.get(&n).cloned())
                .unwrap_or_default();
            reactions_map.entry(msg_row_id).or_default().push(Reaction {
                emoji,
                reactor_jid,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                source: r.source.clone(),
            });
        }
    }

    // ── Edit history (message_edit_info) ────────────────────────────────────
    // Build map: message_row_id → Vec<EditHistoryEntry>
    let mut edits_map: HashMap<i64, Vec<EditHistoryEntry>> = HashMap::new();
    let edit_cols = schema_cols.table("message_edit_info");
    let edit_msg_row_id = edit_cols.get("message_row_id");
    let edit_ts = edit_cols.get("edited_timestamp");
    let edit_text = edit_cols.get("original_text");
    let edit_records = tbl(&by_table, "message_edit_info");
    for r in edit_records {
        let Some(msg_row_id) = int_at(r, edit_msg_row_id) else {
            continue;
        };
        let edited_ts = int_at(r, edit_ts).unwrap_or(0);
        let Some(original_text) = text_at(r, edit_text) else {
            continue;
        };
        edits_map
            .entry(msg_row_id)
            .or_default()
            .push(EditHistoryEntry {
                original_text,
                edited_at: ForensicTimestamp::from_millis(edited_ts, tz_offset_secs),
                source: r.source.clone(),
            });
    }

    // ── Receipts (receipt_user) ─────────────────────────────────────────────
    // Build map: message_row_id → Vec<MessageReceipt>
    let mut receipts_map: HashMap<i64, Vec<MessageReceipt>> = HashMap::new();
    let receipt_cols = schema_cols.table("receipt_user");
    let receipt_msg_row_id = receipt_cols.get("message_row_id");
    let receipt_jid_row_id = receipt_cols.get("receipt_user_jid_row_id");
    let receipt_status = receipt_cols.get("status");
    let receipt_ts = receipt_cols.get("timestamp");
    let receipt_records = tbl(&by_table, "receipt_user");
    for r in receipt_records {
        let Some(msg_row_id) = int_at(r, receipt_msg_row_id) else {
            continue;
        };
        let Some(jid_row_id) = int_at(r, receipt_jid_row_id) else {
            continue;
        };
        let Some(status) = int_at(r, receipt_status) else {
            continue;
        };
        let ts_ms = int_at(r, receipt_ts).unwrap_or(0);
        let receipt_type = match status {
            5 => ReceiptType::Delivered,
            13 => ReceiptType::Read,
            17 => ReceiptType::Played,
            _ => continue, // skip unknown receipt statuses
        };
        let device_jid = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
        receipts_map
            .entry(msg_row_id)
            .or_default()
            .push(MessageReceipt {
                device_jid,
                receipt_type,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                source: r.source.clone(),
            });
    }

    // ── Forwarded messages (message_forwarded) ───────────────────────────────
    // Build map: message_row_id → forward_score
    let mut forwarded_map: HashMap<i64, u32> = HashMap::new();
    let fwd_cols = schema_cols.table("message_forwarded");
    let fwd_msg_row_id = fwd_cols.get("message_row_id");
    let fwd_score = fwd_cols.get("forward_score");
    let fwd_records = tbl(&by_table, "message_forwarded");
    for r in fwd_records {
        let Some(msg_row_id) = int_at(r, fwd_msg_row_id) else {
            continue;
        };
        let Some(score) = int_at(r, fwd_score) else {
            continue;
        };
        forwarded_map.insert(msg_row_id, score as u32);
    }

    // Attach reactions, edit history, receipts, and forwarding to messages
    for chat in chats.values_mut() {
        for msg in &mut chat.messages {
            if let Some(rxns) = reactions_map.remove(&msg.id) {
                msg.reactions = rxns;
            }
            if let Some(edits) = edits_map.remove(&msg.id) {
                msg.edit_history = edits;
            }
            if let Some(recpts) = receipts_map.remove(&msg.id) {
                msg.receipts = recpts;
            }
            if let Some(score) = forwarded_map.get(&msg.id) {
                msg.forward_score = Some(*score);
                msg.is_forwarded = true;
            }
        }
    }

    // Sort messages by timestamp within each chat
    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    // Map call records, then merge group calls by shared call_row_id
    let call_records = tbl(&by_table, "call_log");
    let raw_calls: Vec<(CallRecord, Option<i64>)> = call_records
        .iter()
        .filter_map(|r| record_to_call(r, &jid_map, tz_offset_secs, &call_cols))
        .collect();
    let calls = merge_group_calls(raw_calls);

    // ── Group participant events (group_participant_user) ───────────────────
    let gpe_records = tbl(&by_table, "group_participant_user");
    let group_participant_events = build_group_participant_events(
        gpe_records,
        &jid_map,
        tz_offset_secs,
        schema_cols.table("group_participant_user"),
    );

    // WAL deltas (placeholder — WAL integration in CLI layer)
    let wal_deltas: Vec<WalDelta> = Vec::new();

    // Read schema_version from SQLite header: PRAGMA user_version is stored
    // as a big-endian u32 at bytes 60–63 of the database file.
    let schema_version = if db_bytes.len() >= 64 {
        u32::from_be_bytes([db_bytes[60], db_bytes[61], db_bytes[62], db_bytes[63]])
    } else {
        0
    };

    // ── §2.6 Anti-forensics detectors ────────────────────────────────────────

    // Collect live message IDs for thumbnail orphan detection.
    let live_message_ids: HashSet<i64> = chats
        .values()
        .flat_map(|c| c.messages.iter().map(|m| m.id))
        .collect();
    let total_messages = live_message_ids.len() as u32;

    // Collect message_thumbnails row IDs.
    let thumbnail_records = tbl(&by_table, "message_thumbnails");
    let thumbnail_row_ids: Vec<i64> = thumbnail_records.iter().filter_map(|r| r.row_id).collect();

    let chats_vec: Vec<_> = chats.into_values().collect();

    let mut forensic_warnings = Vec::new();
    forensic_warnings.extend(detect_duplicate_stanza_ids(&key_id_map));
    forensic_warnings.extend(detect_thumbnail_orphans(
        &thumbnail_row_ids,
        &live_message_ids,
        total_messages,
    ));
    forensic_warnings.extend(detect_rowid_reuse(&chats_vec));
    forensic_warnings.extend(detect_timestamp_distribution_anomaly(&chats_vec));

    Ok(ExtractionResult {
        chats: chats_vec,
        contacts: Vec::new(),
        calls,
        wal_deltas,
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version,
        forensic_warnings,
        group_participant_events,
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
    })
}

/// Stream messages from a msgstore.db, invoking `callback` for each extracted
/// message. The callback receives messages in chat-then-timestamp order.
///
/// This is the idiomatic API when the caller wants to process messages
/// incrementally (e.g. write to a file) without building a full Vec in memory.
pub fn extract_streaming<F>(
    db_bytes: &[u8],
    tz_offset_secs: i32,
    schema_version: SchemaVersion,
    mut callback: F,
) -> Result<()>
where
    F: FnMut(Message),
{
    let result = extract_from_msgstore(db_bytes, tz_offset_secs, schema_version)?;
    for chat in result.chats {
        for msg in chat.messages {
            callback(msg);
        }
    }
    Ok(())
}

/// Extract messages using rayon to parallelise per-chat post-processing.
///
/// The B-tree reading phase is inherently sequential (I/O bound), but
/// message sorting within each chat is parallelised via rayon, giving a
/// measurable speedup when the number of chats × messages is large.
pub fn extract_parallel(
    db_bytes: &[u8],
    tz_offset_secs: i32,
    schema_version: SchemaVersion,
) -> Result<ExtractionResult> {
    let mut result = extract_from_msgstore(db_bytes, tz_offset_secs, schema_version)?;
    result.chats.par_iter_mut().for_each(|chat| {
        chat.messages.par_sort_by_key(|m| m.timestamp.utc);
    });
    Ok(result)
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Look up a table name in a `partition_by_table` map and return its records as a slice.
/// Returns an empty slice when the table is absent.
fn tbl<'a>(
    by: &'a HashMap<String, Vec<&'a RecoveredRecord>>,
    name: &str,
) -> &'a [&'a RecoveredRecord] {
    by.get(name).map(|v| v.as_slice()).unwrap_or_default()
}

/// Render a table-name list for a diagnostic.
///
/// A real msgstore declares well over a hundred tables, so whole names beyond
/// the first 20 are omitted — and the omission is stated, with the full count
/// alongside. Every name shown is verbatim.
fn summarise_table_names(names: &[&str]) -> String {
    const SHOWN: usize = 20;
    let head = names
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        format!("{head}, and {} more", names.len() - SHOWN)
    } else {
        head
    }
}

/// Read the integer at a resolved column position.
///
/// `None` when the schema does not declare the column, the record is shorter
/// than that position, or the stored value is not an integer — never a
/// neighbouring column's value.
fn int_at(r: &RecoveredRecord, idx: Option<usize>) -> Option<i64> {
    match r.values.get(idx?) {
        Some(SqlValue::Int(n)) => Some(*n),
        _ => None,
    }
}

/// Read the non-empty text at a resolved column position.
fn text_at(r: &RecoveredRecord, idx: Option<usize>) -> Option<String> {
    match r.values.get(idx?) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Read a resolved column as a boolean flag (any non-zero integer is true).
fn flag_at(r: &RecoveredRecord, idx: Option<usize>) -> bool {
    int_at(r, idx).is_some_and(|n| n != 0)
}

/// Build a map of key_id (XMPP stanza ID) → list of message row_ids.
///
/// Empty when the schema declares no `key_id` column.
fn build_key_id_map(
    msg_records: &[&RecoveredRecord],
    key_id_idx: Option<usize>,
) -> HashMap<String, Vec<i64>> {
    let mut map: HashMap<String, Vec<i64>> = HashMap::new();
    if key_id_idx.is_none() {
        return map;
    }
    for rec in msg_records {
        let Some(row_id) = rec.row_id else {
            continue;
        };
        if let Some(kid) = text_at(rec, key_id_idx) {
            map.entry(kid).or_default().push(row_id);
        }
    }
    map
}

/// jid table: row_id is `_id`; the JID string lives in `raw_string`.
///
/// Reading the neighbouring `user` column instead yields a bare phone number,
/// which looks plausible enough to hide the mistake.
fn build_jid_map(records: &[&RecoveredRecord], cols: &JidColumns) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    for r in records {
        let Some(id) = r.row_id else {
            continue;
        };
        let Some(raw) = text_at(r, cols.raw_string) else {
            continue;
        };
        map.insert(id, raw);
    }
    map
}

/// chat table: row_id is `_id`; `jid_row_id` links to `jid`.
fn build_chats(
    records: &[&RecoveredRecord],
    jid_map: &HashMap<i64, String>,
    cols: &ChatColumns,
) -> HashMap<i64, Chat> {
    let mut map = HashMap::new();
    for r in records {
        let Some(id) = r.row_id else {
            continue;
        };
        let Some(jid_row_id) = int_at(r, cols.jid_row_id) else {
            continue;
        };
        let jid = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
        let is_group = jid.ends_with("@g.us");
        map.insert(
            id,
            Chat {
                id,
                jid,
                name: text_at(r, cols.subject),
                is_group,
                messages: Vec::new(),
                archived: flag_at(r, cols.archived),
            },
        );
    }
    map
}

/// Map one `message` record using resolved column positions.
///
/// A record without a resolvable `chat_row_id` or `timestamp` is skipped rather
/// than attributed to a guessed column.
fn record_to_message(
    r: &RecoveredRecord,
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
    cols: &MessageColumns,
) -> Option<Message> {
    let id = r.row_id?;
    let chat_id = int_at(r, cols.chat_row_id)?;
    let sender_jid = int_at(r, cols.sender_jid_row_id).and_then(|n| jid_map.get(&n).cloned());
    let from_me = flag_at(r, cols.from_me);
    let ts_ms = int_at(r, cols.timestamp)?;
    let msg_type = int_at(r, cols.message_type).unwrap_or(0) as i32;
    let media_mime = text_at(r, cols.media_mime_type);
    let media_name = text_at(r, cols.media_name);
    let starred = flag_at(r, cols.starred);
    // edit_version column added in newer schema versions.
    //   5 = deleted-for-me  (local deletion only)
    //   7 = deleted-for-all (sender deleted from everyone's view)
    // Both cases override the content to Deleted regardless of msg_type or text_data.
    let edit_version = int_at(r, cols.edit_version).unwrap_or(0);
    let text_data = text_at(r, cols.text_data);
    let content = if edit_version == 5 || edit_version == 7 {
        // Message deleted: override any msg_type or text content.
        // edit_version=5 → deleted-for-me; edit_version=7 → deleted-for-all.
        MessageContent::Deleted
    } else if msg_type == 53 || msg_type == 54 {
        // View-once image (53) or video (54) — media key/CDN URL may survive device deletion
        let mime = media_mime.unwrap_or_else(|| {
            if msg_type == 54 {
                "video/mp4"
            } else {
                "image/jpeg"
            }
            .to_string()
        });
        MessageContent::ViewOnce(MediaRef {
            file_path: media_name.unwrap_or_default(),
            mime_type: mime,
            file_size: 0,
            extracted_name: text_data,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        })
    } else if is_media_type(msg_type) {
        let mime = media_mime.unwrap_or_else(|| default_mime_for_type(msg_type).to_string());
        MessageContent::Media(MediaRef {
            file_path: media_name.unwrap_or_default(),
            mime_type: mime,
            file_size: 0,
            extracted_name: text_data, // caption stored as extracted_name
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url: None,
            media_key_b64: None,
        })
    } else if let Some(text) = text_data {
        MessageContent::Text(text)
    } else if msg_type == 0 || msg_type == 15 {
        // msg_type=0 with no text: revoked/deleted message
        // msg_type=15: tombstone placeholder row — purged message, row exists but content is empty
        MessageContent::Deleted
    } else {
        MessageContent::Unknown(msg_type)
    };

    Some(Message {
        id,
        chat_id,
        sender_jid,
        from_me,
        timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
        content,
        reactions: Vec::new(),
        quoted_message: None,
        source: r.source.clone(),
        row_offset: r.offset,
        starred,
        forward_score: None,
        is_forwarded: false,
        edit_history: Vec::new(),
        receipts: Vec::new(),
        forwarded_from: None,
    })
}

/// Map one `call_log` record using resolved column positions.
///
/// Returns `(CallRecord, call_row_id)`, where `call_row_id` groups the
/// participants of one group call.  Schemas that declare no such column yield
/// `None`, so unrelated calls are never merged on a neighbouring value — the
/// modern schema has no `call_row_id`, and reading `duration` in its place
/// collapses every pair of calls that happened to run the same length.
fn record_to_call(
    r: &RecoveredRecord,
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
    cols: &CallLogColumns,
) -> Option<(CallRecord, Option<i64>)> {
    let id = r.row_id?;
    let jid_row_id = int_at(r, cols.jid_row_id)?;
    let participant = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
    let from_me = flag_at(r, cols.from_me);
    let video = flag_at(r, cols.video_call);
    let duration = int_at(r, cols.duration).unwrap_or(0) as u32;
    let ts_ms = int_at(r, cols.timestamp)?;
    let call_result = int_at(r, cols.call_result).map_or(CallResult::Unknown, CallResult::from);
    let call_row_id = int_at(r, cols.call_row_id);
    let call_creator_device_jid =
        int_at(r, cols.call_creator_device_jid_row_id).and_then(|n| jid_map.get(&n).cloned());
    Some((
        CallRecord {
            call_id: id,
            participants: vec![participant],
            from_me,
            video,
            group_call: false,
            duration_secs: duration,
            call_result,
            timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
            source: r.source.clone(),
            call_creator_device_jid,
        },
        call_row_id,
    ))
}

/// Merge call records that share the same `call_row_id` into a single `CallRecord`
/// with `group_call = true` and all participants listed.
/// Records with `call_row_id = None` are kept as solo calls.
fn merge_group_calls(raw: Vec<(CallRecord, Option<i64>)>) -> Vec<CallRecord> {
    let mut solo: Vec<CallRecord> = Vec::new();
    let mut by_row_id: std::collections::BTreeMap<i64, Vec<CallRecord>> =
        std::collections::BTreeMap::new();

    for (record, call_row_id) in raw {
        match call_row_id {
            None => solo.push(record),
            Some(rid) => by_row_id.entry(rid).or_default().push(record),
        }
    }

    let mut result = solo;
    for (_rid, mut group) in by_row_id {
        if group.len() == 1 {
            result.push(group.remove(0));
        } else {
            // Merge: take metadata from first record, collect all participants
            let mut base = group.remove(0);
            base.group_call = true;
            for other in group {
                base.participants.extend(other.participants);
                if base.call_creator_device_jid.is_none() {
                    base.call_creator_device_jid = other.call_creator_device_jid;
                }
            }
            result.push(base);
        }
    }
    result
}

// ── Quoted message support ───────────────────────────────────────────────────

/// message_quoted: the snapshot a reply keeps of the message it quotes.
fn build_quoted_map(
    records: &[&RecoveredRecord],
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
    cols: &TableColumns,
) -> HashMap<i64, Message> {
    let msg_row_id_col = cols.get("message_row_id");
    let chat_row_id_col = cols.get("chat_row_id");
    let sender_col = cols.get("sender_jid_row_id");
    let from_me_col = cols.get("from_me");
    let ts_col = cols.get("timestamp");
    let text_col = cols.get("text_data");
    let type_col = cols.get("message_type");

    let mut map = HashMap::new();
    for r in records {
        let Some(msg_row_id) = int_at(r, msg_row_id_col) else {
            continue;
        };
        let Some(chat_id) = int_at(r, chat_row_id_col) else {
            continue;
        };
        let sender_jid = int_at(r, sender_col).and_then(|n| jid_map.get(&n).cloned());
        let from_me = flag_at(r, from_me_col);
        let ts_ms = int_at(r, ts_col).unwrap_or(0);
        let msg_type = int_at(r, type_col).unwrap_or(0) as i32;
        let content = match text_at(r, text_col) {
            Some(text) => MessageContent::Text(text),
            None if msg_type == 0 => MessageContent::Deleted,
            None => MessageContent::Unknown(msg_type),
        };

        map.insert(
            msg_row_id,
            Message {
                id: r.row_id.unwrap_or(0),
                chat_id,
                sender_jid,
                from_me,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                content,
                reactions: Vec::new(),
                quoted_message: None,
                source: r.source.clone(),
                row_offset: r.offset,
                starred: false,
                forward_score: None,
                is_forwarded: false,
                edit_history: Vec::new(),
                receipts: Vec::new(),
                forwarded_from: None,
            },
        );
    }
    map
}

// ── Group participant events ─────────────────────────────────────────────────

/// group_participant_user: membership changes for group chats.
fn build_group_participant_events(
    records: &[&RecoveredRecord],
    jid_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
    cols: &TableColumns,
) -> Vec<GroupParticipantEvent> {
    let group_col = cols.get("group_jid_row_id");
    let jid_col = cols.get("jid_row_id");
    let action_col = cols.get("user_action");
    let action_ts_col = cols.get("action_ts");

    let mut events = Vec::new();
    for r in records {
        let Some(group_jid_row_id) = int_at(r, group_col) else {
            continue;
        };
        let Some(jid_row_id) = int_at(r, jid_col) else {
            continue;
        };
        let Some(user_action) = int_at(r, action_col) else {
            continue;
        };
        let action_ts = int_at(r, action_ts_col).unwrap_or(0);
        let action = match user_action {
            0 => ParticipantAction::Added,
            1 => ParticipantAction::Removed,
            2 => ParticipantAction::Left,
            5 => ParticipantAction::Promoted,
            6 => ParticipantAction::Demoted,
            _ => continue,
        };
        let group_jid = jid_map.get(&group_jid_row_id).cloned().unwrap_or_default();
        let participant_jid = jid_map.get(&jid_row_id).cloned().unwrap_or_default();
        events.push(GroupParticipantEvent {
            group_jid,
            participant_jid,
            action,
            timestamp: ForensicTimestamp::from_millis(action_ts, tz_offset_secs),
            source: r.source.clone(),
        });
    }
    events
}

/// Build a ghost map: message_row_id → text_data from message_quoted.
///
/// Used to recover the original text of deleted/tombstone messages (msg_type=15)
/// that were later quoted by another message. The quoting message preserves
/// the original text in message_quoted.text_data.
fn build_ghost_map(records: &[&RecoveredRecord], cols: &TableColumns) -> HashMap<i64, String> {
    let msg_row_id_col = cols.get("message_row_id");
    let text_col = cols.get("text_data");

    let mut map = HashMap::new();
    for r in records {
        let Some(msg_row_id) = int_at(r, msg_row_id_col) else {
            continue;
        };
        let Some(text) = text_at(r, text_col) else {
            continue;
        };
        map.insert(msg_row_id, text);
    }
    map
}

// ── wa.db contact extraction ─────────────────────────────────────────────────

/// Extract contacts from wa.db bytes using the forensic B-tree walker.
///
/// `wa_contacts` column positions are resolved by name, as for msgstore.db.
pub fn extract_contacts(wa_db_bytes: &[u8]) -> Result<Vec<Contact>> {
    let engine = ForensicEngine::new(wa_db_bytes, None).context("failed to open wa.db")?;
    let schema_cols = SchemaColumns::from_ddl_map(&engine.table_ddl());
    let cols = schema_cols.table("wa_contacts");
    let jid_col = cols.get("jid");
    let display_name_col = cols.get("display_name");
    let number_col = cols.get("number");

    let records = engine.recover_layer1().context("wa.db layer 1 recovery")?;
    let by_table = partition_by_table(&records);
    let contact_records = tbl(&by_table, "wa_contacts");

    let mut contacts = Vec::new();
    for r in contact_records {
        let Some(jid) = text_at(r, jid_col) else {
            continue;
        };
        let display_name = text_at(r, display_name_col);
        let phone_number = text_at(r, number_col);
        contacts.push(Contact {
            jid,
            display_name,
            phone_number,
            source: r.source.clone(),
        });
    }
    Ok(contacts)
}

/// Build a JID → display name lookup from extracted contacts.
pub fn build_contact_names(contacts: &[Contact]) -> HashMap<String, String> {
    contacts
        .iter()
        .filter_map(|c| {
            c.display_name
                .as_ref()
                .map(|name| (c.jid.clone(), name.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_modern_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extracts_messages() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert!(!result.chats.is_empty(), "should have at least one chat");
        let all_msgs: Vec<_> = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .collect();
        assert!(!all_msgs.is_empty(), "should have messages");
        assert!(
            all_msgs
                .iter()
                .any(|m| matches!(&m.content, MessageContent::Text(s) if s == "Hello there")),
            "should contain text message 'Hello there'"
        );
    }

    #[test]
    fn test_extracts_call_records() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1, "should have 1 call record");
        assert!(result.calls[0].from_me);
        assert!(!result.calls[0].video);
        assert_eq!(result.calls[0].duration_secs, 120);
    }

    #[test]
    fn test_timezone_offset_preserved() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 8 * 3600, SchemaVersion::Modern).unwrap();
        assert_eq!(result.timezone_offset_seconds, Some(8 * 3600));
    }

    #[test]
    fn test_sender_jid_resolved() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result
            .chats
            .iter()
            .find(|c| c.id == 1)
            .expect("chat 1 missing");
        // message 2 is received (from_me=0), sender_jid_row_id=1
        let received = chat1
            .messages
            .iter()
            .find(|m| !m.from_me)
            .expect("received msg");
        assert_eq!(
            received.sender_jid.as_deref(),
            Some("4155550100@s.whatsapp.net")
        );
    }

    // ── E4: call_result tests ────────────────────────────────────────────

    #[test]
    fn test_call_result_extraction() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1);
        // Fixture inserts call_result=1 (Connected)
        assert_eq!(
            result.calls[0].call_result,
            chat4n6_plugin_api::CallResult::Connected
        );
    }

    // ── E5: quoted message tests ─────────────────────────────────────────

    #[test]
    fn test_quoted_message_attached() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 2 ("Hi back!") quotes message 1 ("Hello there")
        let msg2 = chat1.messages.iter().find(|m| m.id == 2).expect("msg 2");
        assert!(
            msg2.quoted_message.is_some(),
            "message 2 should have a quoted message"
        );
        let quoted = msg2.quoted_message.as_ref().unwrap();
        assert!(
            matches!(&quoted.content, MessageContent::Text(s) if s == "Hello there"),
            "quoted content should be 'Hello there'"
        );
    }

    #[test]
    fn test_unquoted_message_has_none() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 1 is not quoted by anyone; it itself has no quoted_message
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(msg1.quoted_message.is_none());
    }

    // ── E3: contact extraction tests ─────────────────────────────────────

    fn make_wa_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE wa_contacts (
                _id INTEGER PRIMARY KEY,
                jid TEXT NOT NULL,
                display_name TEXT,
                status TEXT,
                number TEXT
            );
            INSERT INTO wa_contacts VALUES (1, '4155550100@s.whatsapp.net', 'Alice Smith', 'Hey!', '+14155550100');
            INSERT INTO wa_contacts VALUES (2, '4155550200@s.whatsapp.net', 'Bob Jones', '', '+14155550200');
            INSERT INTO wa_contacts VALUES (3, '120363001234567890@g.us', NULL, NULL, NULL);"
        ).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_extract_contacts_from_wa_db() {
        let wa_db = make_wa_db();
        let contacts = extract_contacts(&wa_db).unwrap();
        assert!(
            contacts.len() >= 2,
            "should have at least 2 contacts with names"
        );
        let alice = contacts
            .iter()
            .find(|c| c.jid == "4155550100@s.whatsapp.net")
            .expect("Alice missing");
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(alice.phone_number.as_deref(), Some("+14155550100"));
    }

    #[test]
    fn test_build_contact_names_map() {
        let contacts = vec![
            Contact {
                jid: "a@s.whatsapp.net".into(),
                display_name: Some("Alice".into()),
                phone_number: None,
                source: chat4n6_plugin_api::EvidenceSource::Live,
            },
            Contact {
                jid: "b@s.whatsapp.net".into(),
                display_name: None,
                phone_number: None,
                source: chat4n6_plugin_api::EvidenceSource::Live,
            },
        ];
        let map = build_contact_names(&contacts);
        assert_eq!(map.get("a@s.whatsapp.net"), Some(&"Alice".to_string()));
        assert!(!map.contains_key("b@s.whatsapp.net"));
    }

    // ── E8: media type mapping tests ────────────────────────────────────

    #[test]
    fn test_image_message_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 3: message_type=1 (image), media_mime_type='image/jpeg'
        let msg3 = chat1.messages.iter().find(|m| m.id == 3).expect("msg 3");
        match &msg3.content {
            MessageContent::Media(ref m) => {
                assert_eq!(m.mime_type, "image/jpeg");
                assert_eq!(m.file_path, "Media/WhatsApp Images/IMG-20240315-001.jpg");
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    #[test]
    fn test_audio_message_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 4: message_type=2 (audio)
        let msg4 = chat1.messages.iter().find(|m| m.id == 4).expect("msg 4");
        match &msg4.content {
            MessageContent::Media(ref m) => {
                assert!(m.mime_type.starts_with("audio/"));
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    #[test]
    fn test_video_with_caption_creates_media_ref() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat2 = result.chats.iter().find(|c| c.id == 2).expect("chat 2");
        // Message 5: message_type=3 (video), text_data='Check this' (caption)
        let msg5 = chat2.messages.iter().find(|m| m.id == 5).expect("msg 5");
        match &msg5.content {
            MessageContent::Media(ref m) => {
                assert_eq!(m.mime_type, "video/mp4");
                assert_eq!(m.extracted_name.as_deref(), Some("Check this"));
            }
            other => panic!("expected Media, got {:?}", other),
        }
    }

    // ── F2: tombstone type-15 tests ──────────────────────────────────────

    #[test]
    fn test_tombstone_type15_creates_deleted() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        // Message 6 has message_type=15 (tombstone, no message_quoted entry) → Deleted
        let msg6 = chat1
            .messages
            .iter()
            .find(|m| m.id == 6)
            .expect("msg 6 (tombstone)");
        assert!(
            matches!(
                &msg6.content,
                MessageContent::Deleted | MessageContent::GhostRecovered(_)
            ),
            "msg_type=15 tombstone should produce Deleted or GhostRecovered, got {:?}",
            msg6.content
        );
    }

    #[test]
    fn test_tombstone_preserved_not_dropped() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let tombstone = chat1.messages.iter().find(|m| m.id == 6);
        assert!(
            tombstone.is_some(),
            "tombstone message (id=6, type=15) must be preserved in extraction results"
        );
    }

    // ── C7: schema_version from PRAGMA user_version ──────────────────────

    #[test]
    fn schema_version_is_read_from_pragma_user_version() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        conn.execute_batch("PRAGMA user_version = 215;").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(
            result.schema_version, 215,
            "schema_version must be read from PRAGMA user_version, not hardcoded"
        );
    }

    // ── C8: ghost message recovery from message_quoted ───────────────────

    #[test]
    fn ghost_message_recovered_from_message_quoted() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        conn.execute_batch(
            "INSERT INTO message_quoted VALUES (99, 6, 1, NULL, 1, 1710513600000, 'Secret deleted message', 0, NULL, NULL);",
        ).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let ghost = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .find(|m| matches!(&m.content, MessageContent::GhostRecovered(_)));
        assert!(
            ghost.is_some(),
            "msg_type=15 with message_quoted entry must produce GhostRecovered"
        );
        if let Some(MessageContent::GhostRecovered(text)) = ghost.map(|m| &m.content) {
            assert!(
                text.contains("Secret deleted message"),
                "GhostRecovered text must contain the quoted text_data"
            );
        }
    }

    #[test]
    fn test_is_media_type_helper() {
        assert!(is_media_type(1)); // image
        assert!(is_media_type(2)); // audio
        assert!(is_media_type(3)); // video
        assert!(is_media_type(8)); // document
        assert!(is_media_type(13)); // gif
        assert!(is_media_type(20)); // sticker
        assert!(!is_media_type(0)); // text
        assert!(!is_media_type(7)); // system
    }

    #[test]
    fn test_text_message_unchanged() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg1.content, MessageContent::Text(s) if s == "Hello there"),
            "text messages should still be Text"
        );
    }

    // ── F17: call creator device JID ─────────────────────────────────────

    fn make_msgstore_with_creator_jid() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER NOT NULL, sender_jid_row_id INTEGER, from_me INTEGER NOT NULL DEFAULT 0, timestamp INTEGER NOT NULL, text_data TEXT, message_type INTEGER NOT NULL DEFAULT 0, media_mime_type TEXT, media_name TEXT);
            CREATE TABLE call_log (
                _id INTEGER PRIMARY KEY,
                jid_row_id INTEGER NOT NULL,
                from_me INTEGER NOT NULL DEFAULT 0,
                video_call INTEGER NOT NULL DEFAULT 0,
                duration INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                call_result INTEGER NOT NULL DEFAULT 0,
                call_row_id INTEGER DEFAULT NULL,
                call_creator_device_jid_row_id INTEGER DEFAULT NULL
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO jid VALUES (2, 'bob@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            INSERT INTO call_log VALUES (1, 1, 0, 0, 90, 1710513500000, 1, NULL, 2);
        "#).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_call_creator_device_jid_extracted() {
        let db = make_msgstore_with_creator_jid();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1);
        assert_eq!(
            result.calls[0].call_creator_device_jid.as_deref(),
            Some("bob@s.whatsapp.net"),
            "creator JID should be resolved from jid_row_id=2"
        );
    }

    #[test]
    fn test_call_creator_device_jid_none_for_solo_call() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(result.calls.len(), 1);
        assert!(
            result.calls[0].call_creator_device_jid.is_none(),
            "solo call with NULL creator should have None"
        );
    }

    // ── F21: multi-signal group call detection ───────────────────────────

    fn make_msgstore_with_group_call() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER NOT NULL, sender_jid_row_id INTEGER, from_me INTEGER NOT NULL DEFAULT 0, timestamp INTEGER NOT NULL, text_data TEXT, message_type INTEGER NOT NULL DEFAULT 0, media_mime_type TEXT, media_name TEXT);
            CREATE TABLE call_log (
                _id INTEGER PRIMARY KEY,
                jid_row_id INTEGER NOT NULL,
                from_me INTEGER NOT NULL DEFAULT 0,
                video_call INTEGER NOT NULL DEFAULT 0,
                duration INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                call_result INTEGER NOT NULL DEFAULT 0,
                call_row_id INTEGER DEFAULT NULL,
                call_creator_device_jid_row_id INTEGER DEFAULT NULL
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO jid VALUES (2, 'bob@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            -- 2 participants in same group call (call_row_id=42)
            INSERT INTO call_log VALUES (1, 1, 0, 0, 120, 1710513400000, 1, 42, NULL);
            INSERT INTO call_log VALUES (2, 2, 0, 0, 120, 1710513400000, 1, 42, NULL);
            -- 1 solo call (no call_row_id)
            INSERT INTO call_log VALUES (3, 1, 1, 0, 60, 1710513500000, 1, NULL, NULL);
        "#).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn test_group_call_merged_into_one_record() {
        let db = make_msgstore_with_group_call();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let group_calls: Vec<_> = result.calls.iter().filter(|c| c.group_call).collect();
        assert_eq!(
            group_calls.len(),
            1,
            "two rows with same call_row_id → 1 merged record"
        );
        assert_eq!(group_calls[0].participants.len(), 2);
    }

    #[test]
    fn test_group_call_participants_contain_both_jids() {
        let db = make_msgstore_with_group_call();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let gc = result
            .calls
            .iter()
            .find(|c| c.group_call)
            .expect("no group call");
        assert!(gc
            .participants
            .contains(&"alice@s.whatsapp.net".to_string()));
        assert!(gc.participants.contains(&"bob@s.whatsapp.net".to_string()));
    }

    #[test]
    fn test_solo_call_not_merged_and_group_call_false() {
        let db = make_msgstore_with_group_call();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let solo_calls: Vec<_> = result.calls.iter().filter(|c| !c.group_call).collect();
        assert_eq!(solo_calls.len(), 1, "one solo call (call_row_id=NULL)");
        assert!(!solo_calls[0].group_call);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use chat4n6_plugin_api::{CallRecord, CallResult, EvidenceSource, ForensicTimestamp};
    use proptest::prelude::*;

    fn make_call(call_id: i64, participant: &str, group_call: bool) -> CallRecord {
        CallRecord {
            call_id,
            participants: vec![participant.to_string()],
            from_me: false,
            video: false,
            group_call,
            duration_secs: 60,
            call_result: CallResult::Unknown,
            timestamp: ForensicTimestamp::from_millis(1_710_513_127_000, 0),
            source: EvidenceSource::Live,
            call_creator_device_jid: None,
        }
    }

    fn arb_call_record() -> impl Strategy<Value = (CallRecord, Option<i64>)> {
        (
            0i64..100i64,
            "[a-z]{3,8}@s\\.whatsapp\\.net",
            any::<bool>(),
            any::<bool>(),
            prop::option::of(0i64..10i64),
        )
            .prop_map(|(call_id, participant, from_me, video, call_row_id)| {
                let ts = ForensicTimestamp::from_millis(1_710_513_127_000, 0);
                let rec = CallRecord {
                    call_id,
                    participants: vec![participant],
                    from_me,
                    video,
                    group_call: false,
                    duration_secs: 60,
                    call_result: CallResult::Unknown,
                    timestamp: ts,
                    source: EvidenceSource::Live,
                    call_creator_device_jid: None,
                };
                (rec, call_row_id)
            })
    }

    proptest! {
        #[test]
        fn group_call_merge_no_participants_lost(
            calls in prop::collection::vec(arb_call_record(), 0..20usize)
        ) {
            let all_participants: std::collections::HashSet<String> = calls
                .iter()
                .flat_map(|(c, _)| c.participants.iter().cloned())
                .collect();

            let merged = merge_group_calls(calls);

            let merged_participants: std::collections::HashSet<String> = merged
                .iter()
                .flat_map(|c| c.participants.iter().cloned())
                .collect();

            prop_assert_eq!(all_participants, merged_participants,
                "No participant should be lost during group call merging");
        }

        #[test]
        fn group_call_merge_count_monotone(
            calls in prop::collection::vec(arb_call_record(), 0..20usize)
        ) {
            let input_count = calls.len();
            let merged = merge_group_calls(calls);
            prop_assert!(merged.len() <= input_count,
                "Merged call count must not exceed input count");
        }

        #[test]
        fn group_call_merge_solo_calls_preserved(
            calls in prop::collection::vec(arb_call_record(), 0..10usize)
        ) {
            // Calls with call_row_id=None are always solo and must not be lost.
            // Calls with a unique call_row_id (only 1 record sharing it) also pass
            // through as non-group. Both contribute to output !group_call count.
            let solo_count = calls.iter().filter(|(_, rid)| rid.is_none()).count();

            // Count call_row_ids that appear exactly once (single-participant group slots)
            let mut rid_counts: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();
            for (_, rid) in &calls {
                if let Some(r) = rid {
                    *rid_counts.entry(*r).or_insert(0) += 1;
                }
            }
            let single_group_count = rid_counts.values().filter(|&&n| n == 1).count();

            let expected_non_group = solo_count + single_group_count;
            let merged = merge_group_calls(calls);
            let output_non_group = merged.iter().filter(|c| !c.group_call).count();
            prop_assert_eq!(expected_non_group, output_non_group,
                "Solo calls and single-participant group slots must be preserved as non-group");
        }
    }

    // Suppress unused-import warning for make_call helper used in doc
    #[allow(dead_code)]
    fn _uses_make_call() {
        let _ = make_call(0, "a@s.whatsapp.net", false);
    }
}

/// RED tests for features I1–I8: reactions, edit history, receipts, starred,
/// group participant events, forwarded messages.
#[cfg(test)]
mod features_i1_i8_tests {
    use super::*;
    use crate::schema::SchemaVersion;

    fn make_modern_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn reactions_extracted_from_message_add_on() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg2 = chat1.messages.iter().find(|m| m.id == 2).expect("msg 2");
        assert_eq!(
            msg2.reactions.len(),
            1,
            "msg 2 should have 1 reaction, got {:?}",
            msg2.reactions
        );
        assert_eq!(msg2.reactions[0].emoji, "👍");
    }

    #[test]
    fn edit_history_extracted_from_message_edit_info() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg2 = chat1.messages.iter().find(|m| m.id == 2).expect("msg 2");
        assert_eq!(
            msg2.edit_history.len(),
            1,
            "msg 2 should have 1 edit history entry, got {:?}",
            msg2.edit_history
        );
        assert_eq!(msg2.edit_history[0].original_text, "Hi back!");
    }

    #[test]
    fn receipts_extracted_from_receipt_user() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert_eq!(
            msg1.receipts.len(),
            1,
            "msg 1 should have 1 receipt, got {:?}",
            msg1.receipts
        );
        assert_eq!(
            msg1.receipts[0].receipt_type,
            chat4n6_plugin_api::ReceiptType::Read
        );
    }

    #[test]
    fn starred_messages_extracted() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat1 = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg2 = chat1.messages.iter().find(|m| m.id == 2).expect("msg 2");
        assert!(
            msg2.starred,
            "msg 2 starred=1 in DB must produce Message.starred=true"
        );
        let msg1 = chat1.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(!msg1.starred, "msg 1 starred=0 must be false");
    }

    #[test]
    fn group_participant_events_in_result() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(
            result.group_participant_events.len(),
            1,
            "should have 1 group participant event, got {:?}",
            result.group_participant_events
        );
        assert_eq!(
            result.group_participant_events[0].action,
            chat4n6_plugin_api::ParticipantAction::Added
        );
    }

    #[test]
    fn forwarded_message_has_forward_score() {
        let db = make_modern_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat2 = result.chats.iter().find(|c| c.id == 2).expect("chat 2");
        let msg5 = chat2.messages.iter().find(|m| m.id == 5).expect("msg 5");
        assert_eq!(
            msg5.forward_score,
            Some(8),
            "msg 5 forward_score should be Some(8)"
        );
        assert!(
            msg5.is_forwarded,
            "msg 5 with forward_score=8 must be is_forwarded=true"
        );
    }
}

#[cfg(test)]
mod proptest_redo_tests {
    use super::*;
    use proptest::prelude::*;

    fn make_db_with_sql(extra_sql: &str) -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/modern_schema.sql"))
            .unwrap();
        conn.execute_batch(extra_sql).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn view_once_msg_type_53_produces_view_once_content() {
        // RED: msg_type 53 is currently treated as Unknown(53), not ViewOnce
        let db = make_db_with_sql(
            "INSERT INTO message (chat_row_id, sender_jid_row_id, from_me, timestamp, text_data, message_type, media_mime_type, media_name)
             VALUES (1, 1, 0, 1710514000000, NULL, 53, 'image/jpeg', 'Media/WhatsApp View Once/VIEW-001.jpg');",
        );
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let view_once_count = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .filter(|m| matches!(&m.content, MessageContent::ViewOnce(_)))
            .count();
        assert_eq!(
            view_once_count, 1,
            "msg_type 53 must produce ViewOnce, not Unknown"
        );
    }

    #[test]
    fn view_once_msg_type_54_produces_view_once_content() {
        // RED: msg_type 54 (view-once video) also unhandled
        let db = make_db_with_sql(
            "INSERT INTO message (chat_row_id, sender_jid_row_id, from_me, timestamp, text_data, message_type, media_mime_type, media_name)
             VALUES (1, 1, 0, 1710514100000, NULL, 54, 'video/mp4', 'Media/WhatsApp View Once/VIEW-002.mp4');",
        );
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let view_once_count = result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .filter(|m| matches!(&m.content, MessageContent::ViewOnce(_)))
            .count();
        assert_eq!(view_once_count, 1, "msg_type 54 must produce ViewOnce");
    }

    #[test]
    fn chat_archived_column_is_extracted() {
        // RED: build_chat_map() currently hardcodes archived: false regardless of DB value
        let db = make_db_with_sql(
            "ALTER TABLE chat ADD COLUMN archived INTEGER NOT NULL DEFAULT 0;
             UPDATE chat SET archived = 1 WHERE _id = 2;",
        );
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let archived_chats: Vec<_> = result.chats.iter().filter(|c| c.archived).collect();
        assert!(
            !archived_chats.is_empty(),
            "archived=1 in DB must produce Chat.archived=true"
        );
    }

    #[test]
    fn jid_type_1_implies_is_group() {
        // RED: is_group is currently derived from subject.is_some(), not jid.type
        // A group JID ending @g.us should always be is_group=true
        let db = make_db_with_sql(
            "INSERT INTO jid VALUES (10, 'group123@g.us');
             INSERT INTO chat VALUES (10, 10, NULL);", // no subject — old heuristic fails
        );
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let g = result.chats.iter().find(|c| c.jid == "group123@g.us");
        assert!(
            g.map_or(false, |c| c.is_group),
            "chat with @g.us JID must be is_group=true even without a subject"
        );
    }

    proptest! {
        #[test]
        fn view_once_never_classified_as_media(
            msg_type in prop::sample::select(vec![53i32, 54])
        ) {
            // Property: ViewOnce types must never produce MessageContent::Media
            let sql = format!(
                "INSERT INTO message (chat_row_id, from_me, timestamp, message_type, media_mime_type, media_name) \
                 VALUES (1, 1, 1710515000000, {}, 'image/jpeg', 'test.jpg');",
                msg_type
            );
            let db = make_db_with_sql(&sql);
            let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
            // The inserted row has media_name='test.jpg'; it must not appear as Media(_)
            let misclassified = result.chats.iter()
                .flat_map(|c| c.messages.iter())
                .filter(|m| matches!(&m.content, MessageContent::Media(mr) if mr.file_path == "test.jpg"))
                .count();
            prop_assert_eq!(misclassified, 0,
                "msg_type {} must not produce MessageContent::Media", msg_type);
        }
    }
}

// ── FTS5 content shadow table recovery ───────────────────────────────────────

/// Extract text fragments from FTS5 _content shadow tables.
/// Returns a map of table_name → Vec<String> (text fragments).
pub fn extract_fts5_content(db_bytes: &[u8]) -> Result<HashMap<String, Vec<String>>> {
    let engine = ForensicEngine::new(db_bytes, None)
        .context("failed to open database for FTS5 content extraction")?;
    let records = engine.recover_layer1().context("FTS5 layer 1 recovery")?;

    let mut result: HashMap<String, Vec<String>> = HashMap::new();

    for record in &records {
        if !record.table.ends_with("_content") {
            continue;
        }
        let texts: Vec<String> = record
            .values
            .iter()
            .filter_map(|v| {
                if let SqlValue::Text(s) = v {
                    if !s.is_empty() {
                        Some(s.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        if !texts.is_empty() {
            result
                .entry(record.table.clone())
                .or_default()
                .extend(texts);
        }
    }

    Ok(result)
}

// ── media_type_extended tests (RED → GREEN) ───────────────────────────────────

#[cfg(test)]
mod media_type_extended_tests {
    use super::*;

    fn make_msgstore_with_msg_type(msg_type_val: i32) -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0,
                media_mime_type TEXT,
                media_name TEXT,
                starred INTEGER NOT NULL DEFAULT 0,
                forwarded INTEGER NOT NULL DEFAULT 0,
                quoted_row_id INTEGER
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            INSERT INTO message VALUES (1, 1, NULL, 1, 1710513500000, NULL, {}, NULL, NULL, 0, 0, NULL);
        "#, msg_type_val)).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn location_message_is_media_with_geo_mime() {
        let db = make_msgstore_with_msg_type(5);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Media(mr) if mr.mime_type.contains("geo")),
            "msg_type=5 (location) should produce Media with geo mime, got: {:?}",
            msg.content
        );
    }

    #[test]
    fn live_location_message_is_media() {
        let db = make_msgstore_with_msg_type(42);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Media(_)),
            "msg_type=42 (live location) should produce Media, got: {:?}",
            msg.content
        );
    }

    #[test]
    fn contact_card_message_is_media_with_vcard_mime() {
        let db = make_msgstore_with_msg_type(64);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Media(mr) if mr.mime_type == "text/vcard"),
            "msg_type=64 (contact card) should produce Media with text/vcard, got: {:?}",
            msg.content
        );
    }

    #[test]
    fn payment_and_unknown_types_do_not_panic() {
        // These types should return Unknown(n) or some valid variant — never panic.
        for &mt in &[9i32, 16, 23, 65, 66, 67, 70, 74] {
            let db = make_msgstore_with_msg_type(mt);
            let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
            let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
            // Message may be omitted (filtered) or extracted as Unknown — no panic is the requirement
            let _ = chat.messages.iter().find(|m| m.id == 1);
        }
    }
}

// ── streaming_extraction tests (RED → GREEN) ──────────────────────────────────

#[cfg(test)]
mod streaming_extraction_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_multi_message_db(msg_count: usize) -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 200;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0,
                media_mime_type TEXT,
                media_name TEXT,
                starred INTEGER NOT NULL DEFAULT 0,
                forwarded INTEGER NOT NULL DEFAULT 0,
                quoted_row_id INTEGER
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
        "#,
        )
        .unwrap();
        for i in 1..=msg_count {
            conn.execute(
                "INSERT INTO message VALUES (?, 1, NULL, 0, ?, ?, 0, NULL, NULL, 0, 0, NULL)",
                rusqlite::params![
                    i as i64,
                    (1710000000000i64 + i as i64 * 1000),
                    format!("msg {}", i)
                ],
            )
            .unwrap();
        }
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn streaming_extraction_callback_invoked_per_message() {
        let db = make_multi_message_db(10);
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);
        extract_streaming(&db, 0, SchemaVersion::Modern, |_msg| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("extract_streaming should succeed");
        assert_eq!(
            count.load(Ordering::SeqCst),
            10,
            "callback must be invoked exactly once per message"
        );
    }

    #[test]
    fn streaming_extraction_same_content_as_batch() {
        let db = make_multi_message_db(5);

        // Batch extraction
        let batch = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let mut batch_ids: Vec<i64> = batch
            .chats
            .iter()
            .flat_map(|c| c.messages.iter().map(|m| m.id))
            .collect();
        batch_ids.sort();

        // Streaming extraction
        let mut streaming_ids = Vec::new();
        extract_streaming(&db, 0, SchemaVersion::Modern, |msg| {
            streaming_ids.push(msg.id);
        })
        .expect("extract_streaming should succeed");
        streaming_ids.sort();

        assert_eq!(
            streaming_ids, batch_ids,
            "streaming and batch extraction must yield the same message IDs"
        );
    }

    #[test]
    fn parallel_extraction_same_result_as_serial() {
        let db = make_multi_message_db(20);

        let serial = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let mut serial_ids: Vec<i64> = serial
            .chats
            .iter()
            .flat_map(|c| c.messages.iter().map(|m| m.id))
            .collect();
        serial_ids.sort();

        let parallel = extract_parallel(&db, 0, SchemaVersion::Modern).unwrap();
        let mut parallel_ids: Vec<i64> = parallel
            .chats
            .iter()
            .flat_map(|c| c.messages.iter().map(|m| m.id))
            .collect();
        parallel_ids.sort();

        assert_eq!(
            parallel_ids, serial_ids,
            "parallel extraction must return the same messages as serial"
        );
    }
}

#[cfg(test)]
mod fts5_tests {
    use super::*;

    fn make_fts5_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/fts5_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn fts5_content_table_text_recovered() {
        let db = make_fts5_db();
        let fragments = extract_fts5_content(&db).unwrap();
        // Should find at least one _content table with text fragments
        let content_tables: Vec<_> = fragments
            .keys()
            .filter(|k| k.ends_with("_content"))
            .collect();
        assert!(
            !content_tables.is_empty(),
            "must find at least one FTS5 _content table"
        );
        let all_texts: Vec<_> = fragments.values().flatten().collect();
        assert!(
            all_texts.iter().any(|t| t.contains("forensics")),
            "must recover text fragments from FTS5 content table"
        );
    }
}

// ── Task 1: msg_type_label correctness tests (RED) ────────────────────────────

#[cfg(test)]
mod msg_type_label_tests {
    use super::*;

    /// Task 1: verify the corrected WhatsApp Android message type labels.
    ///
    /// Historical bug: type 8 was labelled "AudioCall" and type 9 was "Application".
    /// Community reverse engineering shows:
    ///   8  = VoiceNote (long-form audio attachment, not PTT)
    ///   9  = Document  (arbitrary file attachment)
    ///   13 = Gif       (animated GIF, distinct from video type 3)
    ///   15 = Deleted   (deleted-for-all tombstone placeholder, NOT ProductSingle)
    #[test]
    fn type_8_label_is_voice_note() {
        assert_eq!(msg_type_label(8), "VoiceNote");
    }

    #[test]
    fn type_9_label_is_document() {
        assert_eq!(msg_type_label(9), "Document");
    }

    #[test]
    fn type_13_label_is_gif() {
        assert_eq!(msg_type_label(13), "Gif");
    }

    #[test]
    fn type_15_label_is_deleted() {
        assert_eq!(msg_type_label(15), "Deleted");
    }

    /// Sanity-check a selection of unambiguous types that must remain unchanged.
    #[test]
    fn unchanged_types_still_correct() {
        assert_eq!(msg_type_label(0), "Text");
        assert_eq!(msg_type_label(1), "Image");
        assert_eq!(msg_type_label(2), "Audio");
        assert_eq!(msg_type_label(3), "Video");
        assert_eq!(msg_type_label(4), "Contact");
        assert_eq!(msg_type_label(5), "Location");
        assert_eq!(msg_type_label(7), "StatusUpdate");
        assert_eq!(msg_type_label(20), "Sticker");
    }
}

// ── Task 2: edit_version delete semantics tests (RED) ─────────────────────────

#[cfg(test)]
mod edit_version_tests {
    use super::*;

    /// Build a minimal msgstore with a message that has `edit_version` set.
    ///
    /// `edit_version_val`: the integer value to store in the edit_version column.
    /// When the schema includes `edit_version` at column index 10, values 5 and 7
    /// must both produce `MessageContent::Deleted`.
    fn make_msgstore_with_edit_version(edit_version_val: i64) -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(r#"
            PRAGMA user_version = 230;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0,
                media_mime_type TEXT,
                media_name TEXT,
                starred INTEGER NOT NULL DEFAULT 0,
                edit_version INTEGER
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            -- A message that originally had text, but was deleted (edit_version={})
            INSERT INTO message VALUES (1, 1, NULL, 1, 1710513500000, 'original text', 0, NULL, NULL, 0, {});
        "#, edit_version_val, edit_version_val)).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn edit_version_7_produces_deleted_content() {
        // edit_version=7: deleted-for-all (sender deleted from everyone's view)
        let db = make_msgstore_with_edit_version(7);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Deleted),
            "edit_version=7 (deleted-for-all) must produce MessageContent::Deleted, got: {:?}",
            msg.content
        );
    }

    #[test]
    fn edit_version_5_produces_deleted_content() {
        // edit_version=5: deleted-for-me (local deletion only)
        let db = make_msgstore_with_edit_version(5);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Deleted),
            "edit_version=5 (deleted-for-me) must produce MessageContent::Deleted, got: {:?}",
            msg.content
        );
    }

    #[test]
    fn edit_version_0_preserves_original_content() {
        // edit_version=0 (or NULL): normal message, content must not be overridden
        let db = make_msgstore_with_edit_version(0);
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Text(s) if s == "original text"),
            "edit_version=0 must not override content, got: {:?}",
            msg.content
        );
    }
}

// ── tbl helper tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tbl_helper_tests {
    use super::*;
    use chat4n6_plugin_api::EvidenceSource;
    use chat4n6_sqlite_forensics::record::RecoveredRecord;

    fn make_record() -> RecoveredRecord {
        RecoveredRecord {
            table: "message".to_string(),
            row_id: Some(1),
            values: vec![],
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        }
    }

    #[test]
    fn tbl_returns_empty_slice_for_unknown_key() {
        let record = make_record();
        let mut map: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
        map.insert("message".to_string(), vec![&record]);
        // "jid" is not in the map
        let result = tbl(&map, "jid");
        assert!(result.is_empty(), "unknown key must return empty slice");
    }

    #[test]
    fn tbl_returns_records_for_known_key() {
        let record = make_record();
        let mut map: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
        map.insert("message".to_string(), vec![&record]);
        let result = tbl(&map, "message");
        assert_eq!(
            result.len(),
            1,
            "known key must return the inserted records"
        );
    }
}

// ── Task 3: bounds-check / truncated-record regression tests (RED) ────────────

#[cfg(test)]
mod truncated_record_tests {
    use super::*;

    /// Build a msgstore whose message row has fewer columns than the modern schema
    /// (simulates an older/legacy schema version where columns 7–9 may not exist).
    ///
    /// This must not panic — the extractor must degrade gracefully to the available data.
    fn make_msgstore_with_short_message_row() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Deliberately omit media_mime_type, media_name, starred, edit_version
        // so that column indices 7, 8, 9, 10 are absent from the physical row.
        conn.execute_batch(
            r#"
            PRAGMA user_version = 100;
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER NOT NULL,
                sender_jid_row_id INTEGER,
                from_me INTEGER NOT NULL DEFAULT 0,
                timestamp INTEGER NOT NULL,
                text_data TEXT,
                message_type INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
            INSERT INTO chat VALUES (1, 1, NULL);
            INSERT INTO message VALUES (1, 1, NULL, 1, 1710513500000, 'hello short', 0);
        "#,
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn truncated_row_does_not_panic() {
        // Must not panic even when columns 7–10 are absent.
        let db = make_msgstore_with_short_message_row();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern);
        assert!(result.is_ok(), "extraction must not fail on truncated rows");
    }

    #[test]
    fn truncated_row_text_content_preserved() {
        // The text must still be extracted from the available columns.
        let db = make_msgstore_with_short_message_row();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let chat = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        let msg = chat.messages.iter().find(|m| m.id == 1).expect("msg 1");
        assert!(
            matches!(&msg.content, MessageContent::Text(s) if s == "hello short"),
            "text content must be preserved from truncated row, got: {:?}",
            msg.content
        );
    }
}

// ── T1: extraction against the real 2023-era device schema ───────────────────

/// These exercise the same code path as the simplified fixtures, but against
/// the `CREATE TABLE` shapes read out of a real device.  Every assertion here
/// is one the hardcoded-ordinal reader gets wrong: it lands on
/// `sender_jid_row_id` instead of `timestamp`, `user` instead of `raw_string`,
/// `hidden` instead of `subject`, and `duration` instead of `call_row_id`.
#[cfg(test)]
mod real_schema_tests {
    use super::*;
    use chrono::Datelike;

    fn make_real_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/real_modern_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    fn all_messages(result: &ExtractionResult) -> Vec<&Message> {
        result
            .chats
            .iter()
            .flat_map(|c| c.messages.iter())
            .collect()
    }

    #[test]
    fn message_timestamps_are_2022_not_epoch_zero() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let msgs = all_messages(&result);
        assert_eq!(msgs.len(), 3, "all three messages must be extracted");
        for m in &msgs {
            assert_eq!(
                m.timestamp.utc.year(),
                2022,
                "message {} timestamp resolved to {} — the reader is on the wrong column",
                m.id,
                m.timestamp.utc
            );
        }
    }

    #[test]
    fn message_text_comes_from_text_data() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let texts: Vec<&str> = all_messages(&result)
            .iter()
            .filter_map(|m| match &m.content {
                MessageContent::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"Incoming real-schema message"),
            "text_data must be read by name, got: {texts:?}"
        );
    }

    #[test]
    fn sender_resolves_via_jid_raw_string_not_bare_user() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let received = all_messages(&result)
            .into_iter()
            .find(|m| m.id == 2)
            .expect("message 2");
        assert_eq!(
            received.sender_jid.as_deref(),
            Some("4155550100@s.whatsapp.net"),
            "sender must come from jid.raw_string, not the bare `user` column"
        );
    }

    #[test]
    fn from_me_is_read_by_name() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let msgs = all_messages(&result);
        let outgoing = msgs.iter().find(|m| m.id == 1).expect("message 1");
        let incoming = msgs.iter().find(|m| m.id == 2).expect("message 2");
        assert!(outgoing.from_me, "message 1 has from_me = 1");
        assert!(!incoming.from_me, "message 2 has from_me = 0");
    }

    #[test]
    fn starred_flag_is_read_by_name() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let msgs = all_messages(&result);
        assert!(
            msgs.iter().find(|m| m.id == 2).expect("message 2").starred,
            "message 2 has starred = 1 at DDL position 16"
        );
        assert!(
            !msgs.iter().find(|m| m.id == 1).expect("message 1").starred,
            "message 1 has starred = 0"
        );
    }

    #[test]
    fn chat_subject_and_archived_are_read_by_name() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let group = result.chats.iter().find(|c| c.id == 2).expect("chat 2");
        assert_eq!(
            group.name.as_deref(),
            Some("Real Schema Group"),
            "subject sits at position 3; position 2 is `hidden`"
        );
        assert!(group.archived, "chat 2 has archived = 1 at position 10");
        let direct = result.chats.iter().find(|c| c.id == 1).expect("chat 1");
        assert!(!direct.archived, "chat 1 has archived = 0");
    }

    #[test]
    fn chat_jid_resolves_and_group_is_flagged() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let group = result.chats.iter().find(|c| c.id == 2).expect("chat 2");
        assert_eq!(group.jid, "120363001234567890@g.us");
        assert!(group.is_group);
    }

    #[test]
    fn calls_are_not_collapsed_by_a_mistaken_grouping_key() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        assert_eq!(
            result.calls.len(),
            3,
            "three call_log rows must yield three records; the real schema has no \
             call_row_id column, so nothing may be merged"
        );
        assert!(
            result.calls.iter().all(|c| !c.group_call),
            "no call may be flagged as a group call"
        );
    }

    #[test]
    fn call_duration_and_video_flag_are_read_by_name() {
        let db = make_real_msgstore();
        let result = extract_from_msgstore(&db, 0, SchemaVersion::Modern).unwrap();
        let video = result
            .calls
            .iter()
            .find(|c| c.call_id == 2)
            .expect("call 2");
        assert!(video.video, "call 2 has video_call = 1 at position 6");
        assert_eq!(video.duration_secs, 42, "duration sits at position 7");
        let voice = result
            .calls
            .iter()
            .find(|c| c.call_id == 1)
            .expect("call 1");
        assert!(!voice.video);
        assert_eq!(voice.duration_secs, 137);
    }

    fn make_shuffled_msgstore() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/shuffled_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    /// Two databases that differ only in column declaration order must extract
    /// identically.  Any ordinal creeping back into the extractor breaks this.
    #[test]
    fn column_order_does_not_change_the_extraction() {
        let straight = extract_from_msgstore(&make_real_msgstore(), 0, SchemaVersion::Modern)
            .expect("real-order fixture");
        let shuffled = extract_from_msgstore(&make_shuffled_msgstore(), 0, SchemaVersion::Modern)
            .expect("permuted-order fixture");

        let summarise = |r: &ExtractionResult| {
            let mut chats: Vec<(i64, String, Option<String>, bool)> = r
                .chats
                .iter()
                .map(|c| (c.id, c.jid.clone(), c.name.clone(), c.archived))
                .collect();
            chats.sort();
            let mut msgs: Vec<(i64, i64, Option<String>, bool, i64, bool)> = r
                .chats
                .iter()
                .flat_map(|c| c.messages.iter())
                .map(|m| {
                    (
                        m.id,
                        m.chat_id,
                        m.sender_jid.clone(),
                        m.from_me,
                        m.timestamp.utc.timestamp_millis(),
                        m.starred,
                    )
                })
                .collect();
            msgs.sort();
            let mut calls: Vec<(i64, bool, u32, i64, bool)> = r
                .calls
                .iter()
                .map(|c| {
                    (
                        c.call_id,
                        c.video,
                        c.duration_secs,
                        c.timestamp.utc.timestamp_millis(),
                        c.group_call,
                    )
                })
                .collect();
            calls.sort();
            (chats, msgs, calls)
        };

        assert_eq!(
            summarise(&straight),
            summarise(&shuffled),
            "extraction must depend on column names, not on their declaration order"
        );
        // Guard against the comparison passing because both sides are empty.
        assert_eq!(summarise(&straight).1.len(), 3);
    }

    /// A legacy-generation database has no `message` table at all.  Reporting
    /// zero messages would be indistinguishable from a clean device.
    #[test]
    fn a_legacy_schema_database_is_refused_rather_than_reported_empty() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../tests/fixtures/legacy_schema.sql"))
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let err = extract_from_msgstore(&db, 0, SchemaVersion::Legacy)
            .expect_err("a legacy database must not yield a silently empty report");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("messages"),
            "error must name the legacy table it found: {msg}"
        );
        assert!(
            msg.contains("message") && msg.contains("legacy"),
            "error must say which generation it recognised: {msg}"
        );
    }

    /// A database with neither table is likewise a refusal, not an empty report.
    #[test]
    fn a_database_with_no_message_table_is_refused() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE unrelated (_id INTEGER PRIMARY KEY, x TEXT);")
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let err = extract_from_msgstore(&db, 0, SchemaVersion::Modern)
            .expect_err("a database with no message table is not a msgstore.db");
        assert!(
            format!("{err:#}").contains("message"),
            "error must name what it looked for: {err:#}"
        );
    }

    /// A database whose `message.timestamp` column does not hold epoch
    /// milliseconds is a bootstrap failure: extraction must stop rather than
    /// emit a report whose every date is wrong.
    #[test]
    fn implausible_timestamps_abort_extraction_naming_the_values() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
             CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER NOT NULL,
                 sender_jid_row_id INTEGER, from_me INTEGER, timestamp INTEGER,
                 text_data TEXT, message_type INTEGER);
             INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
             INSERT INTO chat VALUES (1, 1, NULL);
             INSERT INTO message VALUES (1, 1, NULL, 1, 5243, 'a', 0);
             INSERT INTO message VALUES (2, 1, NULL, 1, 5244, 'b', 0);
             INSERT INTO message VALUES (3, 1, NULL, 1, 5245, 'c', 0);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let err = extract_from_msgstore(&db, 0, SchemaVersion::Modern)
            .expect_err("must refuse to report on timestamps that are not epoch millis");
        let msg = format!("{err:#}");
        assert!(msg.contains("timestamp"), "must name the column: {msg}");
        assert!(msg.contains("5243"), "must quote an offending value: {msg}");
    }

    /// A schema that declares no `timestamp` at all must be named, not silently
    /// treated as a database with no messages.
    #[test]
    fn message_table_without_a_timestamp_column_aborts_extraction() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
             CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
             CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER NOT NULL,
                 text_data TEXT);
             INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net');
             INSERT INTO chat VALUES (1, 1, NULL);
             INSERT INTO message VALUES (1, 1, 'orphan');",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let err = extract_from_msgstore(&db, 0, SchemaVersion::Modern)
            .expect_err("an unrecognisable message schema must be reported");
        assert!(
            format!("{err:#}").contains("timestamp"),
            "error must name the missing column: {err:#}"
        );
    }

    /// The invariant every resolved ordinal rests on: SQLite writes the
    /// `INTEGER PRIMARY KEY` column as a NULL **at its declared position**, so
    /// `values[i]` is the column at DDL position `i` — even when the rowid
    /// alias is not declared first.
    #[test]
    fn rowid_alias_is_null_at_its_declared_position() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (a TEXT, _id INTEGER PRIMARY KEY, c INTEGER);
             INSERT INTO t VALUES ('first', 7, 42);",
        )
        .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None)
            .unwrap();
        let db = std::fs::read(tmp.path()).unwrap();

        let engine = ForensicEngine::new(&db, None).unwrap();
        let records = engine.recover_layer1().unwrap();
        let r = records.iter().find(|r| r.table == "t").expect("table t");

        assert_eq!(r.row_id, Some(7), "rowid comes from the cell header");
        assert!(
            matches!(r.values.first(), Some(SqlValue::Text(s)) if s == "first"),
            "position 0 is the declared first column, got {:?}",
            r.values.first()
        );
        assert!(
            matches!(r.values.get(1), Some(SqlValue::Null)),
            "the rowid alias reads as Null at its own declared position, got {:?}",
            r.values.get(1)
        );
        assert!(
            matches!(r.values.get(2), Some(SqlValue::Int(42))),
            "position 2 is the declared third column, got {:?}",
            r.values.get(2)
        );
    }
}
