//! Tier-1 validation of the WhatsApp extractor against a real msgstore.db.
//!
//! Ground truth comes from `sqlite3` reading the same file — an independent
//! implementation, not a fixture we authored. Fixtures can only prove the code
//! agrees with itself; this proves it agrees with SQLite about a database
//! neither of them was written for.
//!
//! # Running
//!
//! Both inputs are supplied by the operator and never recorded here:
//!
//! ```text
//! CHAT4N6_REAL_MSGSTORE=/path/to/msgstore.db \
//! CHAT4N6_REAL_INPUT_DIR=/path/to/extraction-root \
//!   cargo test -p chat4n6-whatsapp --test real_msgstore_validation -- --nocapture
//! ```
//!
//! Absent the variables every test skips cleanly, so CI stays green without the
//! evidence. `sqlite3` must be on PATH for the oracle comparisons; without it
//! the reconciling tests skip and only the self-contained ones run.
//!
//! # Case hygiene
//!
//! Nothing here prints or asserts on message content, phone numbers, JIDs,
//! subjects or paths. Failures report counts, shapes and years only. Keep it
//! that way: this file is committed, the evidence is not.

use chat4n6_plugin_api::ExtractionResult;
use chat4n6_whatsapp::extractor::extract_from_msgstore;
use chat4n6_whatsapp::schema::SchemaVersion;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const MSGSTORE_ENV: &str = "CHAT4N6_REAL_MSGSTORE";
const INPUT_DIR_ENV: &str = "CHAT4N6_REAL_INPUT_DIR";

/// The evidence path, or `None` with a skip note.
fn msgstore_path() -> Option<PathBuf> {
    match std::env::var(MSGSTORE_ENV) {
        Ok(p) if !p.is_empty() => {
            let path = PathBuf::from(p);
            if path.is_file() {
                Some(path)
            } else {
                // A variable pointing at nothing is operator error, not absence
                // of evidence — say so rather than skipping quietly.
                panic!("{MSGSTORE_ENV} is set but is not a readable file");
            }
        }
        _ => {
            eprintln!("SKIP: {MSGSTORE_ENV} not set — Tier-1 validation not run");
            None
        }
    }
}

/// Run one scalar query through the `sqlite3` oracle, read-only and immutable.
fn oracle(db: &Path, sql: &str) -> Option<String> {
    let uri = format!("file:{}?mode=ro&immutable=1", db.display());
    let out = Command::new("sqlite3").arg(uri).arg(sql).output().ok()?;
    if !out.status.success() {
        eprintln!(
            "SKIP: sqlite3 oracle failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn oracle_count(db: &Path, table: &str) -> Option<u64> {
    oracle(db, &format!("SELECT COUNT(*) FROM {table};"))?
        .parse()
        .ok()
}

/// Extract, or skip. Returns the result and the evidence path.
fn extract() -> Option<(ExtractionResult, PathBuf)> {
    let path = msgstore_path()?;
    let bytes = std::fs::read(&path).expect("reading the evidence file");
    let result = extract_from_msgstore(&bytes, 0, SchemaVersion::Modern)
        .expect("extraction must succeed on a real msgstore.db");
    Some((result, path))
}

fn message_count(r: &ExtractionResult) -> usize {
    r.chats.iter().map(|c| c.messages.len()).sum()
}

// ── Reconciliation against the sqlite3 oracle ────────────────────────────────

#[test]
fn message_count_matches_the_sqlite3_oracle() {
    let Some((result, path)) = extract() else {
        return;
    };
    let Some(expected) = oracle_count(&path, "message") else {
        return;
    };
    let actual = message_count(&result) as u64;

    if actual != expected {
        // Turn a bare mismatch into a diagnosis: extras are either duplicate
        // row_ids or records attributed to a layer other than the live btree.
        let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
        let mut ids: Vec<i64> = Vec::new();
        for m in result.chats.iter().flat_map(|c| c.messages.iter()) {
            *by_source.entry(format!("{:?}", m.source)).or_insert(0) += 1;
            ids.push(m.id);
        }
        let unique = {
            let mut v = ids.clone();
            v.sort_unstable();
            v.dedup();
            v.len()
        };
        panic!(
            "extracted {actual} messages, sqlite3 reports {expected} in `message` \
             (delta {}). Distinct row_ids: {unique} of {}. By source: {by_source:?}",
            actual as i64 - expected as i64,
            ids.len()
        );
    }
}

#[test]
fn chat_count_matches_the_sqlite3_oracle() {
    let Some((result, path)) = extract() else {
        return;
    };
    let Some(expected) = oracle_count(&path, "chat") else {
        return;
    };
    // Chats carrying messages whose own row was not recovered appear as stubs,
    // so our count may exceed the table's; it must never fall short.
    let stubs = result.chats.iter().filter(|c| c.jid.is_empty()).count();
    assert!(
        result.chats.len() as u64 >= expected,
        "extracted {} chats, sqlite3 reports {expected} in `chat` ({stubs} stubs)",
        result.chats.len()
    );
    assert_eq!(
        result.chats.len() as u64 - stubs as u64,
        expected,
        "non-stub chats must reconcile exactly with the `chat` table"
    );
}

#[test]
fn call_count_matches_the_sqlite3_oracle() {
    let Some((result, path)) = extract() else {
        return;
    };
    let Some(expected) = oracle_count(&path, "call_log") else {
        return;
    };
    // Group calls merge several rows into one record; without a call_row_id
    // column nothing merges, so the counts are equal.
    let participants: usize = result.calls.iter().map(|c| c.participants.len()).sum();
    assert_eq!(
        participants as u64,
        expected,
        "one participant per call_log row: got {participants} across {} records",
        result.calls.len()
    );
}

#[test]
fn year_histogram_matches_the_sqlite3_oracle() {
    let Some((result, path)) = extract() else {
        return;
    };
    let Some(raw) = oracle(
        &path,
        "SELECT strftime('%Y', timestamp/1000, 'unixepoch'), COUNT(*) \
         FROM message GROUP BY 1 ORDER BY 1;",
    ) else {
        return;
    };

    let mut expected: BTreeMap<String, u64> = BTreeMap::new();
    for line in raw.lines() {
        let (year, count) = line.split_once('|').unwrap_or(("", ""));
        if let Ok(n) = count.parse::<u64>() {
            // A row whose year does not render (NULL or out of range) keys on
            // the empty string; it must be carried, not dropped.
            expected.insert(year.to_string(), n);
        }
    }
    if expected.is_empty() {
        eprintln!("SKIP: oracle returned no year histogram");
        return;
    }

    let mut actual: BTreeMap<String, u64> = BTreeMap::new();
    for m in result.chats.iter().flat_map(|c| c.messages.iter()) {
        *actual
            .entry(m.timestamp.utc.format("%Y").to_string())
            .or_insert(0) += 1;
    }

    // Compare only years both sides can express: SQLite renders an
    // unrepresentable timestamp as an empty year, which has no counterpart in a
    // parsed DateTime. Report it rather than letting it vanish.
    let unrenderable = expected.get("").copied().unwrap_or(0);
    if unrenderable > 0 {
        eprintln!(
            "NOTE: sqlite3 renders no year for {unrenderable} row(s); \
             extractor placed them in: {:?}",
            actual
                .iter()
                .filter(|(y, _)| !expected.contains_key(*y))
                .collect::<Vec<_>>()
        );
    }
    let comparable: BTreeMap<&String, &u64> =
        expected.iter().filter(|(y, _)| !y.is_empty()).collect();
    for (year, count) in comparable {
        assert_eq!(
            actual.get(year).copied().unwrap_or(0),
            *count,
            "year {year}: extractor and sqlite3 disagree (full histogram: {actual:?})"
        );
    }
}

// ── Self-contained assertions (no oracle needed) ─────────────────────────────

#[test]
fn no_message_is_dated_1970() {
    let Some((result, _)) = extract() else {
        return;
    };
    let epoch_year: Vec<i64> = result
        .chats
        .iter()
        .flat_map(|c| c.messages.iter())
        .filter(|m| m.timestamp.utc.format("%Y").to_string() == "1970")
        .map(|m| m.id)
        .take(5)
        .collect();
    assert!(
        epoch_year.is_empty(),
        "messages dated 1970 indicate a misread timestamp column; first row_ids: {epoch_year:?}"
    );
}

#[test]
fn senders_resolve_to_jids_not_bare_numbers() {
    let Some((result, _)) = extract() else {
        return;
    };
    let (mut resolved, mut bare) = (0usize, 0usize);
    for m in result.chats.iter().flat_map(|c| c.messages.iter()) {
        match m.sender_jid.as_deref() {
            Some(s) if s.contains('@') => resolved += 1,
            Some(_) => bare += 1,
            None => {}
        }
    }
    assert!(resolved > 0, "no sender resolved to a JID at all");
    assert_eq!(
        bare, 0,
        "{bare} senders carry no '@' — that is jid.user, not jid.raw_string \
         ({resolved} resolved correctly)"
    );
}

#[test]
fn hourly_distribution_is_not_concentrated_in_one_bucket() {
    let Some((result, _)) = extract() else {
        return;
    };
    let mut hours = [0u64; 24];
    let mut total = 0u64;
    for m in result.chats.iter().flat_map(|c| c.messages.iter()) {
        let h = m
            .timestamp
            .utc
            .format("%H")
            .to_string()
            .parse::<usize>()
            .unwrap_or(0);
        if let Some(slot) = hours.get_mut(h) {
            *slot += 1;
        }
        total += 1;
    }
    // A spread is a property of volume: a handful of messages can legitimately
    // sit in one hour, so below this the check would report noise as a finding.
    const MIN_FOR_SPREAD: u64 = 1000;
    if total < MIN_FOR_SPREAD {
        eprintln!("SKIP: {total} messages is too few to judge hourly spread");
        return;
    }
    let occupied = hours.iter().filter(|&&n| n > 0).count();
    let busiest = hours.iter().max().copied().unwrap_or(0);
    assert!(
        occupied >= 12,
        "only {occupied} of 24 hourly buckets occupied — human messaging spreads \
         across the day; a single bucket means every timestamp collapsed to one instant"
    );
    assert!(
        busiest * 100 / total < 50,
        "busiest hour holds {}% of {total} messages",
        busiest * 100 / total
    );
}

#[test]
fn no_implausible_timestamp_distribution_warning_is_raised() {
    let Some((result, _)) = extract() else {
        return;
    };
    let anomalies: Vec<String> = result
        .forensic_warnings
        .iter()
        .filter(|w| {
            matches!(
                w,
                chat4n6_plugin_api::ForensicWarning::TimestampDistributionAnomaly { .. }
            )
        })
        .map(std::string::ToString::to_string)
        .collect();
    assert!(
        anomalies.is_empty(),
        "the detector reports the extraction's own dates as implausible: {anomalies:?}"
    );
}

// ── Pipeline-level run over the extraction tree ──────────────────────────────

#[test]
fn plugin_detects_and_extracts_from_the_extraction_tree() {
    let Ok(root) = std::env::var(INPUT_DIR_ENV) else {
        eprintln!("SKIP: {INPUT_DIR_ENV} not set — pipeline-level run not performed");
        return;
    };
    if root.is_empty() {
        eprintln!("SKIP: {INPUT_DIR_ENV} is empty");
        return;
    }
    let fs =
        chat4n6_fs::PlaintextDirFs::new(Path::new(&root)).expect("opening the extraction tree");
    let plugin = chat4n6_whatsapp::WhatsAppPlugin::new();
    assert!(
        chat4n6_plugin_api::ForensicPlugin::detect(&plugin, &fs),
        "the WhatsApp plugin must detect its database under {INPUT_DIR_ENV}"
    );
    let result = chat4n6_plugin_api::ForensicPlugin::extract(&plugin, &fs, Some(0))
        .expect("pipeline extraction must succeed");
    assert!(
        message_count(&result) > 0,
        "pipeline extraction produced no messages"
    );
}
