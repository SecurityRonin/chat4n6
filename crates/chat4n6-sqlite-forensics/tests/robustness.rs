//! Tier 4: Robustness integration tests.
use chat4n6_sqlite_forensics::db::ForensicEngine;

/// Create a real on-disk SQLite database with the given page_size pragma, one
/// table and one row, then return the raw bytes.
fn make_db_with_page_size_pragma(page_size: u32) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(&format!("PRAGMA page_size={page_size};")).unwrap();
    conn.execute_batch(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO items VALUES (1, 'test');",
    )
    .unwrap();
    drop(conn);
    std::fs::read(&path).unwrap()
}

#[test]
fn test_page_size_512() {
    let db = make_db_with_page_size_pragma(512);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0, "should recover live records with page_size=512");
}

#[test]
fn test_page_size_8192() {
    let db = make_db_with_page_size_pragma(8192);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0, "should recover live records with page_size=8192");
}

#[test]
fn test_page_size_32768() {
    let db = make_db_with_page_size_pragma(32768);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0, "should recover live records with page_size=32768");
}

#[test]
fn test_page_size_65536() {
    // SQLite encodes page_size=65536 as 1 in the header; the engine must handle this.
    let db = make_db_with_page_size_pragma(65536);
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(result.stats.live_count > 0, "should recover live records with page_size=65536");
}

#[test]
fn test_db_only_sqlite_master() {
    // Create a table then immediately drop it — sqlite_master row is gone,
    // no user-table B-trees exist → live_count must be 0.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE tmp (id INTEGER PRIMARY KEY);
         DROP TABLE tmp;",
    )
    .unwrap();
    drop(conn);
    let db = std::fs::read(&path).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert_eq!(result.stats.live_count, 0, "no user tables → live_count must be 0");
}

#[test]
fn test_truncated_db_at_page_boundary() {
    // Truncate to exactly one page. The engine must not panic — it may succeed
    // or return an error, but must not crash.
    let db = make_db_with_page_size_pragma(4096);
    let truncated = db[..4096.min(db.len())].to_vec();
    // If parsing succeeds, recover_all must also not panic.
    if let Ok(engine) = ForensicEngine::new(&truncated, None) {
        let _ = engine.recover_all();
    }
    // No panic == pass.
}

#[test]
fn test_garbage_db_rejected() {
    let garbage = vec![0xFFu8; 4096];
    assert!(
        ForensicEngine::new(&garbage, None).is_err(),
        "all-0xFF bytes must be rejected as not a SQLite database"
    );
}

#[test]
fn test_too_small_db_rejected() {
    let tiny = [0u8; 50];
    assert!(
        ForensicEngine::new(&tiny, None).is_err(),
        "50-byte buffer must be rejected — too small for a valid SQLite header"
    );
}

#[test]
fn test_auto_vacuum_full_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("av.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA auto_vacuum=FULL;").unwrap();
    conn.execute_batch(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);
         INSERT INTO items VALUES (1, 'auto_vacuum_test');",
    )
    .unwrap();
    drop(conn);
    let db = std::fs::read(&path).unwrap();
    let engine = ForensicEngine::new(&db, None).unwrap();
    let result = engine.recover_all().unwrap();
    assert!(
        result.stats.live_count > 0,
        "auto_vacuum=FULL database should still yield live records"
    );
}

#[test]
fn test_non_degradation() {
    // Live records from recover_layer1 must be identical in count to the
    // live_count reported by recover_all (layer1 only returns live records).
    let db = make_db_with_page_size_pragma(4096);
    let engine = ForensicEngine::new(&db, None).unwrap();

    let layer1 = engine.recover_layer1().unwrap();
    let all = engine.recover_all().unwrap();

    assert_eq!(
        all.stats.live_count,
        layer1.len(),
        "recover_all live_count must equal recover_layer1 record count"
    );
}
