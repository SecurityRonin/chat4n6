use assert_cmd::Command;
use tempfile::TempDir;

fn setup_whatsapp_fixture() -> TempDir {
    let root = TempDir::new().unwrap();
    let db_dir = root.path().join("data/data/com.whatsapp/databases");
    std::fs::create_dir_all(&db_dir).unwrap();
    let conn = rusqlite::Connection::open(db_dir.join("msgstore.db")).unwrap();
    conn.execute_batch(
        "
        PRAGMA user_version = 200;
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL, subject TEXT);
        CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER NOT NULL,
            sender_jid_row_id INTEGER, from_me INTEGER NOT NULL DEFAULT 0,
            timestamp INTEGER NOT NULL, text_data TEXT, message_type INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE call_log (_id INTEGER PRIMARY KEY, jid_row_id INTEGER NOT NULL,
            from_me INTEGER NOT NULL DEFAULT 0, video_call INTEGER NOT NULL DEFAULT 0,
            duration INTEGER NOT NULL DEFAULT 0, timestamp INTEGER NOT NULL);
        INSERT INTO jid VALUES (1, 'test@s.whatsapp.net');
        INSERT INTO chat VALUES (1, 1, NULL);
        INSERT INTO message VALUES (1, 1, NULL, 1, 1710513127000, 'Hello', 0);
    ",
    )
    .unwrap();
    root
}

#[test]
fn test_run_produces_report() {
    let fixture = setup_whatsapp_fixture();
    let output = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("chat4n6").unwrap();
    cmd.args([
            "run",
            "--input",
            fixture.path().to_str().unwrap(),
            "--output",
            output.path().to_str().unwrap(),
            "--case-name",
            "TestCase",
            "--no-unalloc",
        ])
        .assert()
        .success();
    assert!(
        output.path().join("index.html").exists(),
        "index.html missing"
    );
    assert!(
        output.path().join("carve-results.json").exists(),
        "carve-results.json missing"
    );
}
