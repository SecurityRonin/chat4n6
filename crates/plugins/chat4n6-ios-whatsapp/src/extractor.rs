use crate::schema::{
    apple_epoch_to_utc_ms, default_mime_for_type, is_media_type, msg_type, zflags_is_forwarded,
    zmessagedate_to_utc_ms,
};
use anyhow::{Context, Result};
use chat4n6_plugin_api::{
    CallRecord, CallResult, Chat, Contact, EvidenceSource, ExtractionResult, ForensicTimestamp,
    ForensicWarning, MediaRef, Message, MessageContent,
};
use chat4n6_sqlite_forensics::{
    db::ForensicEngine,
    partition_by_table,
    record::{RecoveredRecord, SqlValue},
};
use std::collections::HashMap;

/// Extract all forensic artifacts from a ChatStorage.sqlite byte slice.
///
/// `tz_offset_secs` is seconds east of UTC for local time display.
pub fn extract_from_chatstorage(db_bytes: &[u8], tz_offset_secs: i32) -> Result<ExtractionResult> {
    let engine = ForensicEngine::new(db_bytes, Some(tz_offset_secs))
        .context("failed to open ChatStorage.sqlite")?;

    // Build dynamic column map from the actual schema DDL.
    // Falls back to the hardcoded default if the DDL is unavailable.
    let ddl_map = engine.table_ddl();
    let msg_col_map = ddl_map
        .get("ZWAMESSAGE")
        .map(|ddl| parse_column_positions(ddl))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(default_msg_column_map);

    let records = engine.recover_layer1().context("Layer 1 recovery failed")?;

    let by_table = partition_by_table(&records);

    let media_map = build_media_map(
        by_table.get("ZWAMEDIAITEM").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    // Task 3: pre-build ZWAGROUPMEMBER map: Z_PK → ZMEMBERJID
    let member_map = build_member_map(
        by_table.get("ZWAGROUPMEMBER").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    let mut chats: HashMap<i64, Chat> = HashMap::new();
    let session_records = by_table.get("ZWACHATSESSION").map(|v| v.as_slice()).unwrap_or(&[]);
    for r in session_records {
        if let Some(chat) = record_to_chat(r) {
            chats.insert(chat.id, chat);
        }
    }

    let msg_records = by_table.get("ZWAMESSAGE").map(|v| v.as_slice()).unwrap_or(&[]);

    // Collect ZSORT values per chat for gap-based selective deletion detection.
    let zsort_idx = msg_col_map.get("ZSORT").copied().unwrap_or(11);
    let chat_id_idx = msg_col_map.get("ZCHATSESSION").copied().unwrap_or(1);
    let mut zsort_by_chat: HashMap<i64, Vec<f64>> = HashMap::new();
    for r in msg_records {
        let chat_id = match r.values.get(chat_id_idx) {
            Some(SqlValue::Int(n)) => *n,
            _ => continue,
        };
        let zsort = match r.values.get(zsort_idx) {
            Some(SqlValue::Real(f)) => *f,
            Some(SqlValue::Int(n)) => *n as f64,
            _ => continue,
        };
        zsort_by_chat.entry(chat_id).or_default().push(zsort);
    }

    for r in msg_records {
        if let Some(msg) = record_to_message(r, &media_map, &member_map, tz_offset_secs, &msg_col_map) {
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

    for chat in chats.values_mut() {
        chat.messages.sort_by_key(|m| m.timestamp.utc);
    }

    // Build push-name map from ZWAPROFILEPUSHNAME.
    let pushname_map = build_pushname_map(
        by_table.get("ZWAPROFILEPUSHNAME").map(|v| v.as_slice()).unwrap_or(&[]),
    );

    // Apply push names as chat names where chat name is null.
    for chat in chats.values_mut() {
        if chat.name.is_none() {
            if let Some(pn) = pushname_map.get(&chat.jid) {
                chat.name = Some(pn.clone());
            }
        }
    }

    let contacts = extract_contacts(
        by_table.get("ZWACONTACT").map(|v| v.as_slice()).unwrap_or(&[]),
        &pushname_map,
    );

    // Collect calls from ZWACALLINFO (legacy) and ZWACALLEVENT (modern).
    let mut calls = extract_calls(
        by_table.get("ZWACALLINFO").map(|v| v.as_slice()).unwrap_or(&[]),
        tz_offset_secs,
    );
    calls.extend(extract_calls_event(
        by_table.get("ZWACALLEVENT").map(|v| v.as_slice()).unwrap_or(&[]),
        tz_offset_secs,
    ));

    let mut forensic_warnings = detect_zsort_gaps(&zsort_by_chat, &chats);

    // CoreData PK gap detection.
    let zpk_records = by_table.get("Z_PRIMARYKEY").map(|v| v.as_slice()).unwrap_or(&[]);
    // Count non-live records as "recovered" (freelist, carved, WAL-deleted, etc.)
    let recovered_count = msg_records
        .iter()
        .filter(|r| r.source != EvidenceSource::Live)
        .count();
    forensic_warnings.extend(detect_coredata_pk_gaps(
        zpk_records,
        msg_records,
        recovered_count,
    ));

    Ok(ExtractionResult {
        chats: chats.into_values().collect(),
        contacts,
        calls,
        wal_deltas: Vec::new(),
        timezone_offset_seconds: Some(tz_offset_secs),
        schema_version: 32,
        forensic_warnings,
        group_participant_events: Vec::new(),
        extraction_started_at: None,
        extraction_finished_at: None,
        wal_snapshots: vec![],
    })
}

// ── Column map ────────────────────────────────────────────────────────────────

/// Parse column positions from a CREATE TABLE DDL statement.
/// Returns column_name (uppercase) → values-array index.
/// Z_PK (INTEGER PRIMARY KEY) is included at index 0 (stored as Null by the btree walker).
fn parse_column_positions(ddl: &str) -> HashMap<String, usize> {
    let start = ddl.find('(').map(|i| i + 1).unwrap_or(0);
    let end = ddl.rfind(')').unwrap_or(ddl.len());
    let block = &ddl[start..end];

    let mut map = HashMap::new();
    let mut idx = 0usize;

    for part in block.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let upper = part.to_uppercase();
        // Skip table-level constraints — they don't consume a values slot.
        if upper.starts_with("PRIMARY")
            || upper.starts_with("UNIQUE")
            || upper.starts_with("CHECK")
            || upper.starts_with("FOREIGN")
            || upper.starts_with("CONSTRAINT")
        {
            continue;
        }
        if let Some(col_name) = part.split_whitespace().next() {
            map.insert(col_name.to_uppercase(), idx);
        }
        idx += 1;
    }

    map
}

/// Hardcoded fallback for the standard ZWAMESSAGE schema.
fn default_msg_column_map() -> HashMap<String, usize> {
    [
        ("Z_PK", 0),
        ("ZCHATSESSION", 1),
        ("ZMESSAGEDATE", 2),
        ("ZTEXT", 3),
        ("ZMESSAGETYPE", 4),
        ("ZMEDIAITEM", 5),
        ("ZISFROMME", 6),
        ("ZFROMJID", 7),
        ("ZSTARRED", 8),
        ("ZISFORWARDED", 9),
        ("ZDELETED", 10),
        ("ZSORT", 11),
        // Extended columns — present in modern WhatsApp iOS schemas
        ("ZGROUPMEMBER", 12),
        ("ZFLAGS", 13),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), *v))
    .collect()
}

// ── ZSORT gap detection ───────────────────────────────────────────────────────

/// Detect selective deletion by analysing ZSORT sequence gaps per chat.
/// Emits SelectiveDeletion when a gap is >5× the median gap and ≥10 units.
fn detect_zsort_gaps(
    zsort_by_chat: &HashMap<i64, Vec<f64>>,
    chats: &HashMap<i64, Chat>,
) -> Vec<ForensicWarning> {
    let mut warnings = Vec::new();
    for (chat_id, zsort_vals) in zsort_by_chat {
        if zsort_vals.len() < 3 {
            continue;
        }
        let mut sorted = zsort_vals.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let gaps: Vec<f64> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
        let mut sorted_gaps = gaps.clone();
        sorted_gaps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_gap = sorted_gaps[sorted_gaps.len() / 2];
        let threshold = (median_gap * 5.0).max(10.0);
        let suspicious: Vec<_> = gaps.iter().filter(|&&g| g > threshold).collect();
        if !suspicious.is_empty() {
            let suspect_jid = chats
                .get(chat_id)
                .map(|c| c.jid.clone())
                .unwrap_or_default();
            if suspect_jid.is_empty() {
                continue;
            }
            let deletion_rate_pct = ((suspicious.len() * 100) / gaps.len()).min(100) as u8;
            warnings.push(ForensicWarning::SelectiveDeletion {
                suspect_jid,
                deletion_rate_pct,
            });
        }
    }
    warnings
}

// ── helpers ──────────────────────────────────────────────────────────────────

struct MediaInfo {
    mime_type: String,
    file_size: u64,
    local_path: String,
    cdn_url: Option<String>,
}

/// ZWAGROUPMEMBER → map of Z_PK → ZMEMBERJID for group sender resolution.
fn build_member_map(records: &[&RecoveredRecord]) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    for r in records {
        let Some(pk) = r.row_id else { continue };
        let jid = match r.values.get(1) {
            Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
            _ => continue,
        };
        map.insert(pk, jid);
    }
    map
}

fn build_media_map(records: &[&RecoveredRecord]) -> HashMap<i64, MediaInfo> {
    let mut map = HashMap::new();
    for r in records {
        let Some(pk) = r.row_id else { continue };
        let mime = match r.values.get(2) {
            Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
            _ => "application/octet-stream".to_string(),
        };
        let file_size = match r.values.get(3) {
            Some(SqlValue::Int(n)) => *n as u64,
            _ => 0,
        };
        let local_path = match r.values.get(4) {
            Some(SqlValue::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let cdn_url = match r.values.get(5) {
            Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        map.insert(pk, MediaInfo { mime_type: mime, file_size, local_path, cdn_url });
    }
    map
}

/// ZWACHATSESSION → Chat (hardcoded — this table schema is stable).
fn record_to_chat(r: &RecoveredRecord) -> Option<Chat> {
    let id = r.row_id?;
    let archived = match r.values.get(1) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    let jid = match r.values.get(2) {
        Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
        _ => return None,
    };
    let name = match r.values.get(3) {
        Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let is_group = match r.values.get(5) {
        Some(SqlValue::Int(n)) => *n != 0,
        _ => false,
    };
    Some(Chat { id, jid, name, is_group, messages: Vec::new(), archived })
}

/// ZWAMESSAGE → Message using a dynamic column map.
fn record_to_message(
    r: &RecoveredRecord,
    media_map: &HashMap<i64, MediaInfo>,
    member_map: &HashMap<i64, String>,
    tz_offset_secs: i32,
    col: &HashMap<String, usize>,
) -> Option<Message> {
    let id = r.row_id?;

    let get_int = |name: &str| -> Option<i64> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Int(n) => Some(*n),
            _ => None,
        }
    };
    let get_real = |name: &str| -> Option<f64> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Real(f) => Some(*f),
            SqlValue::Int(n) => Some(*n as f64),
            _ => None,
        }
    };
    let get_text = |name: &str| -> Option<String> {
        match r.values.get(*col.get(name)?)? {
            SqlValue::Text(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    };

    let chat_id = get_int("ZCHATSESSION")?;
    // Task 4: handle millisecond timestamps (value > 4_000_000_000)
    let ts_ms = get_real("ZMESSAGEDATE").map(zmessagedate_to_utc_ms)?;
    let text = get_text("ZTEXT");
    let msg_type_val = get_int("ZMESSAGETYPE").unwrap_or(0) as i32;
    let media_item_pk = get_int("ZMEDIAITEM");
    let from_me = get_int("ZISFROMME").unwrap_or(0) != 0;
    // Task 3: resolve group sender via ZGROUPMEMBER FK → ZWAGROUPMEMBER.ZMEMBERJID
    let group_member_fk = get_int("ZGROUPMEMBER");
    let sender_jid = group_member_fk
        .and_then(|fk| member_map.get(&fk).cloned())
        .or_else(|| get_text("ZFROMJID"));
    let starred = get_int("ZSTARRED").unwrap_or(0) != 0;
    // Task 2: forwarded requires both bit 7 (0x80) and bit 8 (0x100) set in ZFLAGS
    let is_forwarded = get_int("ZFLAGS")
        .map(zflags_is_forwarded)
        .unwrap_or_else(|| get_int("ZISFORWARDED").unwrap_or(0) != 0);
    let deleted = get_int("ZDELETED").unwrap_or(0) != 0;

    let content = if deleted || msg_type_val == msg_type::DELETED {
        MessageContent::Deleted
    } else if msg_type_val == msg_type::SYSTEM_MSG {
        MessageContent::System(text.unwrap_or_default())
    } else if is_media_type(msg_type_val) {
        let media_info = media_item_pk.and_then(|pk| media_map.get(&pk));
        let mime = media_info
            .map(|m| m.mime_type.clone())
            .unwrap_or_else(|| default_mime_for_type(msg_type_val).to_string());
        let file_size = media_info.map(|m| m.file_size).unwrap_or(0);
        let file_path = media_info.map(|m| m.local_path.clone()).unwrap_or_default();
        let cdn_url = media_info.and_then(|m| m.cdn_url.clone());
        MessageContent::Media(MediaRef {
            file_path,
            mime_type: mime,
            file_size,
            extracted_name: text,
            thumbnail_b64: None,
            duration_secs: None,
            file_hash: None,
            encrypted_hash: None,
            cdn_url,
            media_key_b64: None,
        })
    } else if let Some(t) = text {
        MessageContent::Text(t)
    } else {
        MessageContent::Unknown(msg_type_val)
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
        is_forwarded,
        edit_history: Vec::new(),
        receipts: Vec::new(),
        forwarded_from: None,
    })
}

/// ZWACONTACT → Contact, with push-name override.
fn extract_contacts(records: &[&RecoveredRecord], pushname_map: &HashMap<String, String>) -> Vec<Contact> {
    records
        .iter()
        .filter_map(|r| {
            let jid = match r.values.get(1) {
                Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
                _ => return None,
            };
            let phone_number = match r.values.get(2) {
                Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
            let display_name = pushname_map.get(&jid).cloned().or_else(|| {
                match r.values.get(3) {
                    Some(SqlValue::Text(s)) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                }
            });
            Some(Contact {
                jid,
                display_name,
                phone_number,
                source: r.source.clone(),
            })
        })
        .collect()
}

/// Compare Z_PRIMARYKEY.Z_MAX for ZWAMESSAGE against live + recovered rows.
/// Emits CoreDataPkGap when rows vanished without freelist traces.
fn detect_coredata_pk_gaps(
    zpk_records: &[&RecoveredRecord],
    msg_records: &[&RecoveredRecord],
    recovered_count: usize,
) -> Vec<ForensicWarning> {
    // Z_PRIMARYKEY columns: Z_PK=0, Z_ENT=1, Z_NAME=2, Z_MAX=3
    let expected_max = zpk_records.iter().find_map(|r| {
        let name = match r.values.get(2) {
            Some(SqlValue::Text(s)) => s.as_str(),
            _ => return None,
        };
        if name != "ZWAMESSAGE" {
            return None;
        }
        match r.values.get(3) {
            Some(SqlValue::Int(n)) => Some(*n as u32),
            _ => None,
        }
    });

    let Some(expected_max) = expected_max else {
        return Vec::new();
    };

    let observed_max = msg_records
        .iter()
        .filter_map(|r| r.row_id)
        .map(|id| id as u32)
        .max()
        .unwrap_or(0);

    let rc = recovered_count as u32;
    if expected_max > observed_max + rc {
        vec![ForensicWarning::CoreDataPkGap {
            entity_name: "ZWAMESSAGE".to_string(),
            expected_max,
            observed_max,
            recovered_count: rc,
        }]
    } else {
        Vec::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── tbl helper ────────────────────────────────────────────────────────────

    #[test]
    fn tbl_returns_slice_when_key_present() {
        let r1 = RecoveredRecord {
            table: "ZWAMESSAGE".to_string(),
            row_id: Some(1),
            values: vec![],
            source: chat4n6_plugin_api::EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let r2 = RecoveredRecord {
            table: "ZWAMESSAGE".to_string(),
            row_id: Some(2),
            values: vec![],
            source: chat4n6_plugin_api::EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        };
        let mut by: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
        by.insert("ZWAMESSAGE".to_string(), vec![&r1, &r2]);
        let slice = tbl(&by, "ZWAMESSAGE");
        assert_eq!(slice.len(), 2);
    }

    #[test]
    fn tbl_returns_empty_slice_when_key_absent() {
        let by: HashMap<String, Vec<&RecoveredRecord>> = HashMap::new();
        let slice = tbl(&by, "ZWAMESSAGE");
        assert!(slice.is_empty());
    }

    /// Build a minimal ChatStorage with ZWAPROFILEPUSHNAME to test push-name resolution.
    fn make_pushname_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            PRAGMA user_version = 32;
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZARCHIVED INTEGER DEFAULT 0,
                ZCONTACTIDENTIFIER TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 0
            );
            CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                ZCHATSESSION INTEGER,
                ZMESSAGEDATE REAL NOT NULL,
                ZTEXT TEXT,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZMEDIAITEM INTEGER,
                ZISFROMME INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZSTARRED INTEGER DEFAULT 0,
                ZISFORWARDED INTEGER DEFAULT 0,
                ZDELETED INTEGER DEFAULT 0,
                ZSORT REAL
            );
            CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMIMETYPE TEXT, ZFILESIZE INTEGER DEFAULT 0, ZLOCALPATH TEXT, ZMEDIAURL TEXT);
            CREATE TABLE ZWACONTACT (Z_PK INTEGER PRIMARY KEY, ZABUSEIDENTIFIER TEXT, ZPHONENUMBER TEXT, ZFULLNAME TEXT);
            CREATE TABLE ZWACALLINFO (Z_PK INTEGER PRIMARY KEY, ZCALLDATE REAL NOT NULL, ZDURATION INTEGER DEFAULT 0, ZISVIDEOCALL INTEGER DEFAULT 0, ZPARTNERCONTACT INTEGER, ZCALLTYPE INTEGER DEFAULT 0);
            CREATE TABLE ZWAPROFILEPUSHNAME (
                Z_PK INTEGER PRIMARY KEY,
                ZJID TEXT,
                ZPUSHNAME TEXT
            );
            INSERT INTO ZWACHATSESSION VALUES (1, 0, '4155550100@s.whatsapp.net', NULL, 732205927.0, 0);
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 732205927.0, 'hello', 0, NULL, 1, NULL, 0, 0, 0, 1.0);
            INSERT INTO ZWACONTACT VALUES (1, '4155550100@s.whatsapp.net', '+14155550100', NULL);
            INSERT INTO ZWAPROFILEPUSHNAME VALUES (1, '4155550100@s.whatsapp.net', 'Alice Smith');
        ").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    /// Build a minimal ChatStorage with ZWACALLEVENT for call extraction test.
    fn make_callevent_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            PRAGMA user_version = 32;
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZARCHIVED INTEGER DEFAULT 0,
                ZCONTACTIDENTIFIER TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 0
            );
            CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                ZCHATSESSION INTEGER,
                ZMESSAGEDATE REAL NOT NULL,
                ZTEXT TEXT,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZMEDIAITEM INTEGER,
                ZISFROMME INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZSTARRED INTEGER DEFAULT 0,
                ZISFORWARDED INTEGER DEFAULT 0,
                ZDELETED INTEGER DEFAULT 0,
                ZSORT REAL
            );
            CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMIMETYPE TEXT, ZFILESIZE INTEGER DEFAULT 0, ZLOCALPATH TEXT, ZMEDIAURL TEXT);
            CREATE TABLE ZWACONTACT (Z_PK INTEGER PRIMARY KEY, ZABUSEIDENTIFIER TEXT, ZPHONENUMBER TEXT, ZFULLNAME TEXT);
            CREATE TABLE ZWACALLEVENT (
                Z_PK INTEGER PRIMARY KEY,
                ZDATE REAL NOT NULL,
                ZDURATION INTEGER DEFAULT 0,
                ZINCOMING INTEGER DEFAULT 0,
                ZOUTGOING INTEGER DEFAULT 0,
                ZMISSED INTEGER DEFAULT 0,
                ZVIDEO INTEGER DEFAULT 0,
                ZGROUPCALLEVENT INTEGER DEFAULT 0
            );
            INSERT INTO ZWACHATSESSION VALUES (1, 0, 'test@s.whatsapp.net', 'Test', 600000000.0, 0);
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 600000000.0, 'hello', 0, NULL, 1, NULL, 0, 0, 0, 1.0);
            -- ZDATE=600000000.0 → unix_ms = (600000000 + 978307200) * 1000 = 1578307200000
            INSERT INTO ZWACALLEVENT VALUES (1, 600000000.0, 120, 0, 1, 0, 0, 0);
        ").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn pushname_resolution_sets_display_name() {
        let db = make_pushname_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        // Contact from ZWACONTACT with push-name override from ZWAPROFILEPUSHNAME
        let contact = result
            .contacts
            .iter()
            .find(|c| c.jid == "4155550100@s.whatsapp.net")
            .expect("contact with JID 4155550100@s.whatsapp.net must exist");
        assert_eq!(
            contact.display_name.as_deref(),
            Some("Alice Smith"),
            "ZWAPROFILEPUSHNAME.ZPUSHNAME must override display_name"
        );
    }

    #[test]
    fn pushname_used_as_chat_name_when_null() {
        let db = make_pushname_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        // ZWACHATSESSION.ZPARTNERNAME is NULL — should fall back to pushname
        let chat = result
            .chats
            .iter()
            .find(|c| c.jid == "4155550100@s.whatsapp.net")
            .expect("chat must exist");
        assert_eq!(
            chat.name.as_deref(),
            Some("Alice Smith"),
            "chat name should be filled from ZWAPROFILEPUSHNAME when ZPARTNERNAME is NULL"
        );
    }

    /// Build a DB with ZWAGROUPMEMBER and a group message referencing it.
    fn make_group_member_db() -> Vec<u8> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("
            PRAGMA user_version = 32;
            CREATE TABLE ZWACHATSESSION (
                Z_PK INTEGER PRIMARY KEY,
                ZARCHIVED INTEGER DEFAULT 0,
                ZCONTACTIDENTIFIER TEXT,
                ZPARTNERNAME TEXT,
                ZLASTMESSAGEDATE REAL,
                ZSESSIONTYPE INTEGER DEFAULT 0
            );
            CREATE TABLE ZWAGROUPMEMBER (
                Z_PK INTEGER PRIMARY KEY,
                ZMEMBERJID TEXT,
                ZCHATSESSION INTEGER
            );
            CREATE TABLE ZWAMESSAGE (
                Z_PK INTEGER PRIMARY KEY,
                ZCHATSESSION INTEGER,
                ZMESSAGEDATE REAL NOT NULL,
                ZTEXT TEXT,
                ZMESSAGETYPE INTEGER DEFAULT 0,
                ZMEDIAITEM INTEGER,
                ZISFROMME INTEGER DEFAULT 0,
                ZFROMJID TEXT,
                ZSTARRED INTEGER DEFAULT 0,
                ZISFORWARDED INTEGER DEFAULT 0,
                ZDELETED INTEGER DEFAULT 0,
                ZSORT REAL,
                ZGROUPMEMBER INTEGER,
                ZFLAGS INTEGER DEFAULT 0
            );
            CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMESSAGE INTEGER, ZMIMETYPE TEXT, ZFILESIZE INTEGER DEFAULT 0, ZLOCALPATH TEXT, ZMEDIAURL TEXT);
            CREATE TABLE ZWACONTACT (Z_PK INTEGER PRIMARY KEY, ZABUSEIDENTIFIER TEXT, ZPHONENUMBER TEXT, ZFULLNAME TEXT);
            INSERT INTO ZWACHATSESSION VALUES (1, 0, 'group@g.us', 'TestGroup', 600000000.0, 1);
            INSERT INTO ZWAGROUPMEMBER VALUES (42, '1234567890@s.whatsapp.net', 1);
            -- ZFROMJID is NULL; sender comes from ZGROUPMEMBER FK=42
            INSERT INTO ZWAMESSAGE VALUES (1, 1, 600000000.0, 'group hello', 0, NULL, 0, NULL, 0, 0, 0, 1.0, 42, 0);
        ").unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        conn.backup(rusqlite::DatabaseName::Main, tmp.path(), None).unwrap();
        std::fs::read(tmp.path()).unwrap()
    }

    #[test]
    fn group_sender_resolved_from_zwagroupmember() {
        let db = make_group_member_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        let chat = result.chats.iter().find(|c| c.jid == "group@g.us").expect("group chat must exist");
        assert_eq!(chat.messages.len(), 1, "must have 1 message");
        assert_eq!(
            chat.messages[0].sender_jid.as_deref(),
            Some("1234567890@s.whatsapp.net"),
            "sender must be resolved from ZWAGROUPMEMBER.ZMEMBERJID via ZGROUPMEMBER FK"
        );
    }

    #[test]
    fn call_extraction_from_zwacallevent() {
        let db = make_callevent_db();
        let result = extract_from_chatstorage(&db, 0).expect("extraction should succeed");

        assert!(result.calls.len() >= 1, "must have at least 1 call from ZWACALLEVENT");

        let call = result.calls.iter().find(|c| c.call_id == 1).expect("call with id=1 must exist");
        // ZDATE=600000000.0 → unix epoch seconds = 600000000 + 978307200 = 1578307200
        assert_eq!(
            call.timestamp.utc.timestamp(),
            1578307200,
            "timestamp must match Apple epoch conversion of 600000000.0"
        );
        assert!(call.from_me, "ZOUTGOING=1 must set from_me=true");
        assert_eq!(call.duration_secs, 120, "ZDURATION=120 must be preserved");
        assert!(!call.video, "ZVIDEO=0 must set video=false");
    }
}

/// ZWAPROFILEPUSHNAME → pushname map (JID → display name).
fn build_pushname_map(records: &[&RecoveredRecord]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for r in records {
        let jid = match r.values.get(1) {
            Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
            _ => continue,
        };
        let pushname = match r.values.get(2) {
            Some(SqlValue::Text(s)) if !s.is_empty() => s.clone(),
            _ => continue,
        };
        map.insert(jid, pushname);
    }
    map
}

/// ZWACALLEVENT → CallRecord (modern iOS WA schema).
fn extract_calls_event(records: &[&RecoveredRecord], tz_offset_secs: i32) -> Vec<CallRecord> {
    records
        .iter()
        .filter_map(|r| {
            let call_id = r.row_id?;
            // ZDATE=1, ZDURATION=2, ZINCOMING=3, ZOUTGOING=4, ZMISSED=5, ZVIDEO=6, ZGROUPCALLEVENT=7
            let ts_ms = match r.values.get(1)? {
                SqlValue::Real(f) => apple_epoch_to_utc_ms(*f),
                SqlValue::Int(n) => apple_epoch_to_utc_ms(*n as f64),
                _ => return None,
            };
            let duration_secs = match r.values.get(2) {
                Some(SqlValue::Int(n)) => *n as u32,
                _ => 0,
            };
            let from_me = match r.values.get(4) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            let missed = match r.values.get(5) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            let video = match r.values.get(6) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            let group_call = match r.values.get(7) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            Some(CallRecord {
                call_id,
                participants: Vec::new(),
                from_me,
                video,
                group_call,
                duration_secs,
                call_result: if missed { CallResult::Missed } else { CallResult::Unknown },
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                source: r.source.clone(),
                call_creator_device_jid: None,
            })
        })
        .collect()
}

/// ZWACALLINFO → CallRecord
fn extract_calls(records: &[&RecoveredRecord], tz_offset_secs: i32) -> Vec<CallRecord> {
    records
        .iter()
        .filter_map(|r| {
            let call_id = r.row_id?;
            let ts_ms = match r.values.get(1)? {
                SqlValue::Real(f) => apple_epoch_to_utc_ms(*f),
                SqlValue::Int(n) => apple_epoch_to_utc_ms(*n as f64),
                _ => return None,
            };
            let duration_secs = match r.values.get(2) {
                Some(SqlValue::Int(n)) => *n as u32,
                _ => 0,
            };
            let video = match r.values.get(3) {
                Some(SqlValue::Int(n)) => *n != 0,
                _ => false,
            };
            Some(CallRecord {
                call_id,
                participants: Vec::new(),
                from_me: false,
                video,
                group_call: false,
                duration_secs,
                call_result: CallResult::Unknown,
                timestamp: ForensicTimestamp::from_millis(ts_ms, tz_offset_secs),
                source: EvidenceSource::Live,
                call_creator_device_jid: None,
            })
        })
        .collect()
}
