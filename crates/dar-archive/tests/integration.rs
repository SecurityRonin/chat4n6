//! Integration tests that require a real .dar fixture.
//! Tests skip gracefully (return without panic) if the fixture is absent.
//!
//! To run locally:
//!   Update the path constants below, then:
//!   cargo test -p dar-archive --test integration -- --nocapture

use dar_archive::DarArchive;
use std::path::Path;

// Update these paths before running integration tests locally.
const SINGLE_SLICE_PATH: &str = "/path/to/userdata.1.dar";
const MULTI_SLICE_BASENAME: &str = "/path/to/userdata";

fn fixture_present() -> bool {
    Path::new(SINGLE_SLICE_PATH).exists()
}

#[test]
fn test_open_single_slice_has_entries() {
    if !fixture_present() {
        eprintln!("Skipping: real .dar fixture not present at {SINGLE_SLICE_PATH}");
        return;
    }
    let archive = DarArchive::open(Path::new(SINGLE_SLICE_PATH))
        .expect("DarArchive::open");
    let count = archive.entries().len();
    println!("entries: {count}");
    assert!(count > 0, "expected entries in catalog");
}

#[test]
fn test_open_single_slice_contains_whatsapp() {
    if !fixture_present() { return; }
    let archive = DarArchive::open(Path::new(SINGLE_SLICE_PATH)).unwrap();
    let found = archive.entries().iter().any(|e| {
        e.path.to_str().map_or(false, |p| p.contains("com.whatsapp"))
    });
    assert!(found, "expected a com.whatsapp entry in the catalog");
}

#[test]
fn test_open_slices_finds_first_slice() {
    if !fixture_present() { return; }
    let archive = DarArchive::open_slices(Path::new(MULTI_SLICE_BASENAME))
        .expect("DarArchive::open_slices");
    assert!(!archive.entries().is_empty());
}
