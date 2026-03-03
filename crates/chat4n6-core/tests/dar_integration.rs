use chat4n6_core::dar::fs::DarFs;
use chat4n6_plugin_api::ForensicFs;
use std::path::Path;

#[test]
#[ignore = "requires test DAR fixture at tests/fixtures/sample.dar"]
fn test_dar_lists_whatsapp_databases() {
    let fs = DarFs::open(Path::new("tests/fixtures/sample.dar")).unwrap();
    let entries = fs.list("data/data/com.whatsapp/databases").unwrap();
    assert!(entries.iter().any(|e| e.path.contains("msgstore.db")));
}
