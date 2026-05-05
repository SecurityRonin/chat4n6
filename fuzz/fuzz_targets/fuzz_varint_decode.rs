#![no_main]
use libfuzzer_sys::fuzz_target;
use chat4n6_sqlite_forensics::varint;

fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        let _ = varint::read_varint(data, 0);
        let _ = varint::read_varint_reverse(data, data.len());
    }
});
