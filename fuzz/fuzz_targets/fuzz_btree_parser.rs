#![no_main]
use libfuzzer_sys::fuzz_target;
use chat4n6_sqlite_forensics::db::ForensicEngine;

fuzz_target!(|data: &[u8]| {
    // Must never panic on arbitrary input, only return errors
    let _ = ForensicEngine::new(data, None);
});
