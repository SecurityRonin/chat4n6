# Validation — WhatsApp Android (msgstore.db)

## Summary

The WhatsApp extractor resolves every msgstore.db column position by name from
the database's own `CREATE TABLE` SQL, and refuses to report on a database whose
data contradicts the resolved map. This document records how that is checked,
by what, and how far each check can be trusted.

Three things carry the correctness claim:

1. **Real-device DDL under test.** A fixture built from the `CREATE TABLE`
   shapes of a real 2023-era handset, where the columns a positional reader
   would land on are the wrong ones.
2. **Position-independence as a property.** A second fixture with identical
   names and data but permuted column order. Both must extract identically.
3. **Reconciliation with `sqlite3`.** An independent implementation reading the
   same evidence file, comparing counts and the timestamp year histogram.

Item 3 is Tier 1 and requires the evidence, which lives only in the operator's
case workspace. **It has not been executed in this repository.** Items 1 and 2
run in CI on every commit.

## Evidence tiers

Tiering is by *who confirms the result*, not by whether the input is synthetic.

| Check | Tier | Confirmed by |
|---|---|---|
| Counts and year histogram vs. `sqlite3` on the case database | 1 | Independent implementation, real-world artifact |
| Extraction over real-device DDL (`real_modern_schema.sql`) | 2 | Real SQLite engine writes the file; expected values follow from the documented construction |
| Column order permutation (`shuffled_schema.sql`) | 2 | Differential: two constructions must agree, neither one's answer authored by hand |
| DDL parser unit tests (`columns.rs`) | 3 | Rules authored here; correctness is defined by the SQLite grammar they implement |
| Schema-gate behaviour (`schema_gate.rs`) | 3 | Detection rules — the fixture specifies behaviour rather than vouching for a value |

Tier 3 is legitimate where it sits: those cases define detection rules and
robustness properties, not values an external oracle could adjudicate. The
value-producing paths — timestamps, senders, subjects, call durations — are
covered at Tier 2 by construction and at Tier 1 by `sqlite3`.

## Method

### Tier-1 reconciliation

Ground truth is `sqlite3` reading the evidence read-only and immutable:

```
sqlite3 "file:$CHAT4N6_REAL_MSGSTORE?mode=ro&immutable=1"
```

The test derives every expected value from that oracle at run time rather than
from transcribed constants, so it reconciles against whatever database it is
pointed at. It asserts:

- extracted message count equals `SELECT COUNT(*) FROM message`
- non-stub chat count equals `SELECT COUNT(*) FROM chat`
- call participants equal `SELECT COUNT(*) FROM call_log`
- the per-year message histogram matches
  `strftime('%Y', timestamp/1000, 'unixepoch')` bucket for bucket
- no message is dated 1970
- every resolved sender is a JID, not a bare subscriber number
- messages spread across at least 12 hourly buckets, with no single hour
  holding half of them
- the extraction raises no `TimestampDistributionAnomaly` against itself

A count mismatch fails with a breakdown by evidence source and a distinct-rowid
tally, so an over-count is diagnosed rather than merely reported.

### Running it

Both paths come from the operator's case workspace and are never recorded in
this repository:

```
CHAT4N6_REAL_MSGSTORE=/path/to/msgstore.db \
CHAT4N6_REAL_INPUT_DIR=/path/to/extraction-root \
  cargo test -p chat4n6-whatsapp --test real_msgstore_validation -- --nocapture
```

Without the variables every test skips and prints why; without `sqlite3` on
PATH the reconciling tests skip and the self-contained ones still run. A
variable that is set but points at no readable file fails loudly rather than
skipping, so a typo cannot masquerade as "no evidence available".

The test file asserts on counts, shapes and years only. No message content,
JID, subject, phone number or path is printed or embedded.

### Expected values

Recorded from the oracle on 2026-07-29 against this case's database. Aggregate
counts only.

| Query | Value |
|---|---|
| `SELECT COUNT(*) FROM message` | 245,227 |
| `SELECT COUNT(*) FROM chat` | 2,309 |
| `SELECT COUNT(*) FROM call_log` | 166 |
| `PRAGMA freelist_count` | 0 |
| Messages dated 1970 | 0 |

One `message` row renders an empty year under `strftime`, meaning its timestamp
is NULL or outside the representable range. The year-histogram test reports
that row and where the extractor placed it rather than dropping it silently.

## What is checked in CI

`cargo test -p chat4n6-whatsapp` covers, without any evidence present:

- DDL parsing: nested parentheses, commas inside string defaults, quoted and
  bracketed identifiers, table-level constraints occupying no column position,
  malformed input yielding an empty map rather than a panic
- resolution of the confirmed real-device positions for `message`, `jid`,
  `chat` and `call_log`
- extraction over real-device DDL: 2022 timestamps, senders via
  `jid.raw_string`, subject via `chat.subject`, `archived`, per-call duration
  and video flag, and three call rows staying three records
- identical extraction from the column-permuted fixture
- the record-layout invariant the resolver rests on: SQLite writes an
  `INTEGER PRIMARY KEY` as a NULL at its *declared* position, so `values[i]` is
  the column at DDL position `i` even when `_id` is declared mid-table
- the schema gate rejecting an unresolvable or contradicted column map, and
  accepting an empty message table and a handful of outlier rows
- refusal of a legacy-generation database instead of an empty report

## Known gaps

These are real and unaddressed; none is masked by a passing test.

- **Media metadata on the modern schema.** The 2023-era `message` table has no
  `media_mime_type` or `media_name`; that metadata moved to `message_media`,
  which the extractor does not read. Media fields resolve to `None` on a modern
  database and media messages carry no path or MIME type. The
  media-in-message path is still exercised by `modern_schema.sql`, which
  represents an older modern-generation schema.
- **Auxiliary table column names are unverified.** `message_quoted`,
  `message_add_on`, `message_edit_info`, `receipt_user`, `message_forwarded`
  and `group_participant_user` resolve by the names in `modern_schema.sql`,
  which were not read off a device. Where a real schema spells a column
  differently the field resolves to `None`, so reactions, edits and receipts
  may be absent rather than wrong. Auditing those names against the case
  database is outstanding.
- **Only the live btree layer is interpreted.** WAL deltas, freelist, journal,
  intra-page carve and unallocated carve are not mapped into messages by this
  plugin. Unallocated carving additionally needs a raw-image input: the
  plaintext-directory filesystem reports no unallocated regions by design.
- **`detect_timestamp_anomalies` cannot fire from this plugin.** Messages are
  sorted by timestamp before the detectors run, so the pairwise out-of-order
  check has nothing to find. `detect_selective_deletion` is likewise not wired
  into extraction. The distribution-level detector is wired and does fire.
- **Other plugins are unaudited.** `chat4n6-ios-whatsapp`, `chat4n6-signal` and
  `chat4n6-telegram` still read records by hardcoded ordinals and have not been
  checked against real DDL.

## Fixtures

| File | What it is | Provenance |
|---|---|---|
| `real_modern_schema.sql` | Real 2023-era device DDL, synthetic rows | Confirmed positions read off the case device; intervening columns from published WhatsApp schema documentation, position-preserving and never read |
| `shuffled_schema.sql` | The same names, data and values with every column order permuted | Synthetic permutation; no device ships these orders |
| `legacy_schema.sql` | Pre-2018 `messages` + `chat_list` generation | Published legacy schema documentation, not read off the case device |
| `modern_schema.sql` | Simplified shapes, retained for the media-in-message path and for the aux tables | Authored here; explicitly not a device schema |

`real_modern_schema.sql` and `shuffled_schema.sql` exist because a fixture
written to the layout the reader assumes cannot falsify that assumption. Those
two can.
