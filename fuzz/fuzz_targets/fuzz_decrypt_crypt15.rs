#![no_main]
use libfuzzer_sys::fuzz_target;
use chat4n6_sqlite_forensics::db::ForensicEngine;

fuzz_target!(|data: &[u8]| {
    // Any input that's not a valid crypt15 file must produce Err, never panic.
    // chat4n6-whatsapp decrypt functions are pub(crate); test via ForensicEngine
    // which exercises the same SQLite-level parsing path used after decryption.
    let _ = ForensicEngine::new(data, None);
});
