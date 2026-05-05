use assert_cmd::cmd::Command;
use tempfile::TempDir;

fn setup_whatsapp_fixture() -> TempDir {
    setup_whatsapp_fixture_with_messages(1)
}

fn setup_whatsapp_fixture_with_messages(n: usize) -> TempDir {
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
    ",
    )
    .unwrap();
    for i in 0..n {
        let ts = 1710513127000i64 + i as i64 * 1000;
        conn.execute(
            "INSERT INTO message (_id, chat_row_id, from_me, timestamp, text_data, message_type) VALUES (?1, 1, 1, ?2, 'msg', 0)",
            rusqlite::params![i as i64 + 1, ts],
        )
        .unwrap();
    }
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

#[test]
fn report_subcommand_regenerates_html_from_carve_results() {
    // Step 1: produce carve-results.json via run
    let fixture = setup_whatsapp_fixture();
    let first_out = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", first_out.path().to_str().unwrap(),
            "--case-name", "Case1",
            "--no-unalloc",
        ])
        .assert()
        .success();

    let carve_results = first_out.path().join("carve-results.json");
    assert!(carve_results.exists(), "carve-results.json not produced by run");

    // Step 2: regenerate report from carve-results.json without re-extracting
    let second_out = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "report",
            "--from", carve_results.to_str().unwrap(),
            "--output", second_out.path().to_str().unwrap(),
            "--case-name", "Case1",
        ])
        .assert()
        .success();

    assert!(
        second_out.path().join("index.html").exists(),
        "report subcommand did not produce index.html"
    );
}

#[test]
fn page_size_flag_splits_chat_into_multiple_pages() {
    // 5 messages, page-size 2 → must produce page_001, page_002, page_003
    let fixture = setup_whatsapp_fixture_with_messages(5);
    let output = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", output.path().to_str().unwrap(),
            "--case-name", "PagingTest",
            "--no-unalloc",
            "--page-size", "2",
        ])
        .assert()
        .success();

    // Find any chat subdirectory
    let chats_dir = output.path().join("chats");
    let chat_dir = std::fs::read_dir(&chats_dir)
        .expect("chats/ missing")
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .expect("no chat subdirectory found");

    let page3 = chat_dir.path().join("page_003.html");
    assert!(page3.exists(), "page_003.html missing — page-size flag not honoured");
}

#[test]
fn plugin_flag_limits_extraction_to_named_plugin() {
    let fixture = setup_whatsapp_fixture();
    let output = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", output.path().to_str().unwrap(),
            "--case-name", "PluginTest",
            "--no-unalloc",
            "--plugin", "whatsapp",
        ])
        .assert()
        .success();

    assert!(
        output.path().join("index.html").exists(),
        "index.html missing with --plugin whatsapp"
    );

    // carve-results.json must not contain signal or telegram chats
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(output.path().join("carve-results.json")).unwrap(),
    )
    .unwrap();
    let chats = json["chats"].as_array().unwrap();
    for chat in chats {
        let platform = chat["platform"].as_str().unwrap_or("");
        assert_ne!(platform, "signal", "signal chat found despite --plugin whatsapp");
        assert_ne!(platform, "telegram", "telegram chat found despite --plugin whatsapp");
    }
}
