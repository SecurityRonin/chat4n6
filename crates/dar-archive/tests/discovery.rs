//! Format-discovery test. Run locally against a real .dar file to analyze catalog structure:
//!   cargo test -p dar-archive --test discovery -- --nocapture --ignored
//!
//! Update DAR_PATH before running.

use dar_archive::scanner::find_zzzzz;
use memmap2::Mmap;
use std::fs::File;

const DAR_PATH: &str = "/path/to/userdata.1.dar"; // ← update before running

#[test]
#[ignore = "requires real .dar fixture; run manually for format discovery"]
fn dump_catalog_bytes() {
    if !std::path::Path::new(DAR_PATH).exists() {
        eprintln!("Skipping: DAR_PATH={DAR_PATH:?} does not exist. Update the constant before running.");
        return;
    }
    let file = File::open(DAR_PATH).expect("open dar file");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap");
    let data: &[u8] = &mmap;

    let pos = find_zzzzz(data).expect("no zzzzz found in file");
    println!("zzzzz at offset {pos} (0x{pos:08x}), file size = {}", data.len());

    let after = &data[pos + 5..];
    println!("\nFirst 512 bytes after zzzzz (catalog start):");
    for (i, chunk) in after[..512.min(after.len())].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        println!("  {:04x}: {:48}  |{}|", i * 16, hex.join(" "), ascii);
    }

    if let Some(pos2) = find_zzzzz(&after[5..]) {
        let catalog_size = pos2 + 5;
        println!("\nSecond zzzzz at +{} from catalog start", pos2 + 5);
        println!("Catalog section size: {catalog_size} bytes");
    } else {
        println!("\nNo second zzzzz found — catalog may extend to EOF");
    }

    // Print context around printable ASCII runs (likely filenames)
    println!("\n--- Named entries near start of catalog ---");
    let search_len = 4096.min(after.len());
    let mut i = 0;
    let mut shown = 0;
    while i < search_len && shown < 20 {
        if after[i].is_ascii_alphanumeric() || after[i] == b'/' || after[i] == b'.' {
            let start = i.saturating_sub(4);
            let end = (i + 32).min(after.len());
            let hex: Vec<String> = after[start..end].iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = after[start..end]
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect();
            println!("  offset {:04x}: {:48}  |{}|", start, hex.join(" "), ascii);
            i += 32;
            shown += 1;
        } else {
            i += 1;
        }
    }
}
