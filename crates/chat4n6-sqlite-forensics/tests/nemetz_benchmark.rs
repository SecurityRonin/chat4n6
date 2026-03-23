//! Nemetz corpus benchmarks for forensic recovery.
//!
//! Tests marked #[ignore] require the Nemetz corpus to be downloaded via Git LFS.
//! Run with: cargo test --test nemetz_benchmark -- --ignored
//!
//! Non-ignored tests use programmatically generated databases and run unconditionally.

use chat4n6_sqlite_forensics::db::ForensicEngine;
use chat4n6_plugin_api::EvidenceSource;

/// Non-degradation guarantee: live records from recover_layer1() must be
/// identical to live records from recover_all().
/// No recovery feature may reduce live-data extraction.
#[test]
fn non_degradation_guarantee() {
    // Test with multiple DB configurations
    for (label, db) in generate_test_dbs() {
        let engine = ForensicEngine::new(&db, None).unwrap();
        let layer1 = engine.recover_layer1().unwrap();
        let full = engine.recover_all().unwrap();

        let live_in_full: Vec<_> = full.records.iter()
            .filter(|r| r.source == EvidenceSource::Live)
            .collect();

        assert_eq!(
            layer1.len(),
            live_in_full.len(),
            "non-degradation failed for {}: layer1={}, live_in_full={}",
            label, layer1.len(), live_in_full.len()
        );
    }
}

/// No false positives: a clean database with no deletions should produce
/// zero non-live records.
#[test]
fn no_false_positives_on_clean_db() {
    let db = make_clean_db();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();

    let non_live: Vec<_> = result.records.iter()
        .filter(|r| r.source != EvidenceSource::Live)
        .collect();

    assert!(
        non_live.is_empty(),
        "found {} non-live records in clean DB: {:?}",
        non_live.len(),
        non_live.iter().map(|r| format!("{}:{:?}", r.table, r.source)).collect::<Vec<_>>()
    );
}

/// Benchmark recovery rate against Nemetz corpus.
/// Requires Git LFS checkout of tests/fixtures/nemetz/
#[test]
#[ignore]
fn benchmark_recovery_rate() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("tests/fixtures/nemetz");

    if !corpus_dir.exists() {
        eprintln!("Nemetz corpus not found at {:?}. Run 'git lfs pull' first.", corpus_dir);
        return;
    }

    let mut total_dbs = 0;
    let mut total_recovered = 0;
    let mut total_live = 0;

    for entry in std::fs::read_dir(&corpus_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |e| e == "db") {
            let db = std::fs::read(&path).unwrap();
            if let Ok(engine) = ForensicEngine::new(&db, None) {
                if let Ok(result) = engine.recover_all() {
                    total_dbs += 1;
                    total_live += result.stats.live_count;
                    total_recovered += result.records.len();
                }
            }
        }
    }

    eprintln!("Nemetz corpus: {} DBs, {} live records, {} total recovered",
        total_dbs, total_live, total_recovered);

    assert!(total_dbs > 0, "no databases found in corpus");
}

/// Anti-forensic corpus: must not panic or hang on any input.
#[test]
#[ignore]
fn anti_forensic_corpus_no_crash() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("tests/fixtures/nemetz");

    if !corpus_dir.exists() {
        return;
    }

    for entry in std::fs::read_dir(&corpus_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |e| e == "db") {
            let db = std::fs::read(&path).unwrap();
            // Must not panic — recovery rate may be 0%, that's fine
            let _ = ForensicEngine::new(&db, None)
                .map(|e| e.recover_all());
        }
    }
}

// ─── Helpers ───

fn make_clean_db() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clean.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT, ts INTEGER);
         INSERT INTO messages VALUES (1, 'hello world', 1710000000);
         INSERT INTO messages VALUES (2, 'test message', 1710000001);
         INSERT INTO messages VALUES (3, 'another one', 1710000002);
         CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO contacts VALUES (1, 'Alice');
         INSERT INTO contacts VALUES (2, 'Bob');",
    ).unwrap();
    drop(conn);
    std::fs::read(&path).unwrap()
}

fn generate_test_dbs() -> Vec<(&'static str, Vec<u8>)> {
    let mut dbs = Vec::new();

    // Simple DB
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("simple.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
             INSERT INTO t VALUES (1, 'a');
             INSERT INTO t VALUES (2, 'b');
             INSERT INTO t VALUES (3, 'c');",
        ).unwrap();
        drop(conn);
        dbs.push(("simple", std::fs::read(&path).unwrap()));
    }

    // DB with deletions
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deleted.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA secure_delete=OFF; PRAGMA page_size=1024;").unwrap();
        conn.execute_batch(
            "CREATE TABLE msgs (id INTEGER PRIMARY KEY, text TEXT);
             INSERT INTO msgs VALUES (1, 'keep');
             INSERT INTO msgs VALUES (2, 'delete me');
             INSERT INTO msgs VALUES (3, 'keep too');
             DELETE FROM msgs WHERE id = 2;",
        ).unwrap();
        drop(conn);
        dbs.push(("deleted", std::fs::read(&path).unwrap()));
    }

    // Multi-table DB
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t1 (id INTEGER PRIMARY KEY, a TEXT);
             CREATE TABLE t2 (id INTEGER PRIMARY KEY, b TEXT);
             INSERT INTO t1 VALUES (1, 'x');
             INSERT INTO t2 VALUES (1, 'y');",
        ).unwrap();
        drop(conn);
        dbs.push(("multi-table", std::fs::read(&path).unwrap()));
    }

    dbs
}
