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

    // Chat id=1, page 3 → chats/chat_1_*/page_003.html
    let chat_subdir = std::fs::read_dir(output.path().join("chats"))
        .expect("chats/ missing")
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .expect("no chat subdir in chats/");
    let page3 = chat_subdir.path().join("page_003.html");
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

#[test]
fn nested_chat_layout_uses_chats_subdirectory() {
    let fixture = setup_whatsapp_fixture();
    let output = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", output.path().to_str().unwrap(),
            "--case-name", "LayoutTest",
            "--no-unalloc",
        ])
        .assert()
        .success();

    // Must have chats/ directory
    let chats_dir = output.path().join("chats");
    assert!(chats_dir.exists(), "chats/ directory missing");

    // Must have a chat subdirectory inside chats/
    let chat_subdir = std::fs::read_dir(&chats_dir)
        .expect("chats/ unreadable")
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .expect("no chat subdirectory inside chats/");

    // page_001.html must exist inside the chat subdir
    assert!(
        chat_subdir.path().join("page_001.html").exists(),
        "page_001.html not found in chat subdir {:?}", chat_subdir.path()
    );

    // No flat chat_{id}_{page}.html files in root
    let root_has_flat = std::fs::read_dir(output.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.starts_with("chat_") && s.ends_with(".html")
        });
    assert!(!root_has_flat, "flat chat_{{id}}_{{page}}.html files found in report root");
}

#[test]
fn index_links_to_chats_subdirectory() {
    let fixture = setup_whatsapp_fixture();
    let output = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", output.path().to_str().unwrap(),
            "--case-name", "LinkTest",
            "--no-unalloc",
        ])
        .assert()
        .success();

    let index = std::fs::read_to_string(output.path().join("index.html")).unwrap();
    assert!(
        index.contains("chats/"),
        "index.html does not link into chats/ subdirectory"
    );
}

#[test]
fn chat_page_has_breadcrumb_to_index() {
    let fixture = setup_whatsapp_fixture();
    let output = TempDir::new().unwrap();
    Command::cargo_bin("chat4n6")
        .unwrap()
        .args([
            "run",
            "--input", fixture.path().to_str().unwrap(),
            "--output", output.path().to_str().unwrap(),
            "--case-name", "BreadcrumbTest",
            "--no-unalloc",
        ])
        .assert()
        .success();

    // Find page_001.html in any chat subdir (lives at chats/chat_1_*/page_001.html)
    let chat_subdir = std::fs::read_dir(output.path().join("chats"))
        .expect("chats/ missing")
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .expect("no chat subdir");
    let page = std::fs::read_to_string(chat_subdir.path().join("page_001.html")).unwrap();

    // The nav link must use ../../index.html (two levels up from chats/chat_*/page.html)
    assert!(
        page.contains("../../index.html"),
        "chat page_001.html nav link must use ../../index.html (nested two levels deep)"
    );
}
