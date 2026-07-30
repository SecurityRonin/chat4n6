//! Bootstrap validation for the resolved `message` column map.
//!
//! Resolving a column by name is only as good as the DDL it was read from.  If
//! the map is wrong the extractor still produces a structurally complete
//! report — one that is indistinguishable from a correct one until somebody
//! notices every message is dated 1970.  That is the worst failure class a
//! forensic tool has, so the map is checked against the data before any of it
//! is interpreted, and a failed check is an error rather than a report.

use crate::columns::MessageColumns;
use anyhow::{bail, Result};
use chat4n6_sqlite_forensics::record::{RecoveredRecord, SqlValue};

/// 2009-01-01T00:00:00Z in epoch milliseconds.
///
/// WhatsApp shipped in 2009, so no genuine message timestamp precedes it.
pub const EARLIEST_PLAUSIBLE_MS: i64 = 1_230_768_000_000;

/// Grace added to the acquisition time before a timestamp counts as future-dated.
pub const FUTURE_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// Rows examined.  Enough to be decisive, small enough to stay free on a
/// quarter-million-row database.
const SAMPLE_SIZE: usize = 512;

/// Share of sampled timestamps that must be plausible.
///
/// Deliberately not 1.0: a genuine database can carry a handful of corrupt or
/// out-of-range rows, and rejecting real evidence over one bad row would be a
/// worse failure than the one this gate exists to catch.  A misresolved column
/// is wrong for essentially every row, so it fails this bar easily.
const MIN_PLAUSIBLE_RATIO: f64 = 0.90;

/// Offending values quoted in the error.
const OFFENDERS_SHOWN: usize = 3;

/// Check that the resolved `message` map actually describes the records.
///
/// `now_ms` is the acquisition time in epoch milliseconds; it is passed in
/// rather than read from the clock so the bounds are testable.
pub fn validate_message_columns(
    records: &[&RecoveredRecord],
    cols: &MessageColumns,
    now_ms: i64,
) -> Result<()> {
    let Some(ts_idx) = cols.timestamp else {
        bail!(
            "msgstore `message` table declares no `timestamp` column; the schema is \
             unrecognised and its records will not be interpreted"
        );
    };
    if cols.chat_row_id.is_none() {
        bail!(
            "msgstore `message` table declares no `chat_row_id` column; messages \
             cannot be attributed to a chat and will not be interpreted"
        );
    }
    if records.is_empty() {
        return Ok(());
    }

    let latest_ms = now_ms.saturating_add(FUTURE_GRACE_MS);
    let mut sampled = 0usize;
    let mut plausible = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut short_rows = 0usize;

    for r in records.iter().take(SAMPLE_SIZE) {
        let value = r.values.get(ts_idx);
        if value.is_none() {
            short_rows += 1;
        }
        sampled += 1;
        if matches!(value, Some(SqlValue::Int(ms)) if *ms >= EARLIEST_PLAUSIBLE_MS && *ms <= latest_ms)
        {
            plausible += 1;
        } else if offenders.len() < OFFENDERS_SHOWN {
            let row = r
                .row_id
                .map_or_else(|| "?".to_string(), |id| id.to_string());
            offenders.push(format!("_id={row} -> {}", render_value(value)));
        }
    }

    #[allow(clippy::cast_precision_loss)] // sample is at most SAMPLE_SIZE rows
    let ratio = plausible as f64 / sampled as f64;
    if ratio >= MIN_PLAUSIBLE_RATIO {
        return Ok(());
    }

    let detail = if short_rows == sampled {
        format!("no sampled record is long enough to carry column {ts_idx}")
    } else {
        format!(
            "{plausible} of {sampled} sampled rows carry a plausible epoch-millisecond \
             value (need {:.0}%)",
            MIN_PLAUSIBLE_RATIO * 100.0
        )
    };

    bail!(
        "msgstore `message`.`timestamp` resolved to column {ts_idx}, but {detail}. \
         Offending values: [{}]. Expected epoch milliseconds between \
         {EARLIEST_PLAUSIBLE_MS} (2009-01-01) and {latest_ms} (acquisition + 1 day). \
         Refusing to report on a column map the data contradicts.",
        offenders.join("; ")
    )
}

/// Render a stored value for a diagnostic, verbatim where it is bounded.
pub fn render_value(value: Option<&SqlValue>) -> String {
    match value {
        None => "<absent: record is shorter than this column>".to_string(),
        Some(SqlValue::Null) => "NULL".to_string(),
        Some(SqlValue::Int(n)) => n.to_string(),
        Some(SqlValue::Real(f)) => f.to_string(),
        Some(SqlValue::Text(s)) => format!("TEXT {s:?}"),
        Some(SqlValue::Blob(b)) => {
            const SHOWN: usize = 16;
            let head: String = b.iter().take(SHOWN).map(|x| format!("{x:02x}")).collect();
            if b.len() > SHOWN {
                format!("BLOB {} bytes, first {SHOWN}: {head}", b.len())
            } else {
                format!("BLOB {} bytes: {head}", b.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4n6_plugin_api::EvidenceSource;

    /// 2024-03-15T14:32:07Z.
    const GOOD_MS: i64 = 1_710_513_127_000;
    /// A little after the newest fixture timestamp, standing in for acquisition.
    const NOW_MS: i64 = 1_760_000_000_000;

    fn cols_at(timestamp: Option<usize>, chat_row_id: Option<usize>) -> MessageColumns {
        MessageColumns {
            chat_row_id,
            timestamp,
            ..MessageColumns::default()
        }
    }

    fn record(row_id: i64, values: Vec<SqlValue>) -> RecoveredRecord {
        RecoveredRecord {
            table: "message".to_string(),
            row_id: Some(row_id),
            values,
            source: EvidenceSource::Live,
            offset: 0,
            confidence: 1.0,
        }
    }

    /// `n` records whose column 1 holds `ts`.
    fn records_with(ts: impl Fn(usize) -> SqlValue, n: usize) -> Vec<RecoveredRecord> {
        (0..n)
            .map(|i| record(i as i64 + 1, vec![SqlValue::Null, ts(i)]))
            .collect()
    }

    fn refs(v: &[RecoveredRecord]) -> Vec<&RecoveredRecord> {
        v.iter().collect()
    }

    #[test]
    fn plausible_timestamps_pass() {
        let recs = records_with(|i| SqlValue::Int(GOOD_MS + i as i64 * 1000), 20);
        assert!(validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS).is_ok());
    }

    #[test]
    fn no_message_rows_is_not_an_error() {
        assert!(
            validate_message_columns(&[], &cols_at(Some(1), Some(0)), NOW_MS).is_ok(),
            "an empty message table is a real state, not a bootstrap failure"
        );
    }

    #[test]
    fn missing_timestamp_column_is_rejected() {
        let recs = records_with(|_| SqlValue::Int(GOOD_MS), 5);
        let err = validate_message_columns(&refs(&recs), &cols_at(None, Some(0)), NOW_MS)
            .expect_err("a message table with no resolvable timestamp must not be extracted");
        let msg = err.to_string();
        assert!(
            msg.contains("timestamp"),
            "error must name the column: {msg}"
        );
        assert!(msg.contains("message"), "error must name the table: {msg}");
    }

    #[test]
    fn missing_chat_row_id_column_is_rejected() {
        let recs = records_with(|_| SqlValue::Int(GOOD_MS), 5);
        let err = validate_message_columns(&refs(&recs), &cols_at(Some(1), None), NOW_MS)
            .expect_err("messages cannot be attributed without chat_row_id");
        assert!(
            err.to_string().contains("chat_row_id"),
            "error must name the column: {err}"
        );
    }

    #[test]
    fn epoch_zero_timestamps_are_rejected_and_the_values_shown() {
        // The real failure: sender_jid_row_id read as a timestamp — small ints.
        let recs = records_with(|i| SqlValue::Int(5243 + i as i64), 50);
        let err = validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS)
            .expect_err("small integers are not epoch milliseconds");
        let msg = err.to_string();
        assert!(msg.contains("timestamp"), "must name the column: {msg}");
        assert!(msg.contains('1'), "must name the resolved ordinal: {msg}");
        assert!(msg.contains("5243"), "must quote an offending value: {msg}");
    }

    #[test]
    fn a_few_implausible_rows_do_not_trip_the_gate() {
        // A real database carries the odd corrupt row; rejecting good evidence
        // over one of them would be the worse failure.
        let mut recs = records_with(|i| SqlValue::Int(GOOD_MS + i as i64 * 1000), 199);
        recs.push(record(200, vec![SqlValue::Null, SqlValue::Int(0)]));
        assert!(
            validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS).is_ok(),
            "1 bad row in 200 is an outlier, not a misresolved column"
        );
    }

    #[test]
    fn future_dated_timestamps_are_rejected() {
        let beyond = NOW_MS + FUTURE_GRACE_MS + 1;
        let recs = records_with(|i| SqlValue::Int(beyond + i as i64), 20);
        let err = validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS)
            .expect_err("timestamps past the acquisition time cannot be genuine");
        assert!(err.to_string().contains(&beyond.to_string()));
    }

    #[test]
    fn one_day_of_clock_skew_is_tolerated() {
        let recs = records_with(|_| SqlValue::Int(NOW_MS + FUTURE_GRACE_MS - 1), 20);
        assert!(
            validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS).is_ok(),
            "a day of grace absorbs device/host clock skew"
        );
    }

    #[test]
    fn non_integer_timestamps_are_rejected_and_shown() {
        let recs = records_with(|_| SqlValue::Text("AAAA1111".to_string()), 20);
        let err = validate_message_columns(&refs(&recs), &cols_at(Some(1), Some(0)), NOW_MS)
            .expect_err("a text column is not a timestamp column");
        assert!(
            err.to_string().contains("AAAA1111"),
            "the offending value must be shown verbatim: {err}"
        );
    }

    #[test]
    fn records_too_short_for_the_resolved_ordinal_are_rejected() {
        let recs = records_with(|_| SqlValue::Int(GOOD_MS), 20);
        // Resolve timestamp past the end of every record.
        let err = validate_message_columns(&refs(&recs), &cols_at(Some(9), Some(0)), NOW_MS)
            .expect_err("no row carries the resolved column");
        assert!(
            err.to_string().contains('9'),
            "error must name the resolved ordinal: {err}"
        );
    }

    // ── render_value ─────────────────────────────────────────────────────────

    #[test]
    fn render_value_shows_each_kind() {
        assert_eq!(render_value(Some(&SqlValue::Int(-5))), "-5");
        assert_eq!(render_value(Some(&SqlValue::Null)), "NULL");
        assert_eq!(
            render_value(Some(&SqlValue::Text("hi".into()))),
            "TEXT \"hi\""
        );
        assert_eq!(
            render_value(Some(&SqlValue::Blob(vec![0xde, 0xad]))),
            "BLOB 2 bytes: dead"
        );
        assert!(render_value(None).contains("absent"));
    }

    #[test]
    fn render_value_labels_a_truncated_blob() {
        let rendered = render_value(Some(&SqlValue::Blob(vec![0xab; 40])));
        assert!(
            rendered.contains("40 bytes"),
            "the full length must be stated: {rendered}"
        );
        assert!(
            rendered.contains("first 16"),
            "the elision must be labelled: {rendered}"
        );
    }
}
