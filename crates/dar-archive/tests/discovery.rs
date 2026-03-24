//! Format-discovery test. Run locally against a real .dar file to analyze catalog structure:
//!   cargo test -p dar-archive --test discovery -- --nocapture --ignored
//!
//! Update DAR_PATH before running.

use memmap2::Mmap;
use std::fs::File;

const DAR_PATH: &str = "/Users/4n6h4x0r/Documents/Cases/DCCC677_2025/02_Acquired/Redmi/unprotected/userdata.1.dar";

fn dump_hex(label: &str, data: &[u8], max_bytes: usize) {
    let show = max_bytes.min(data.len());
    println!("\n{label} (showing {show} of {} bytes):", data.len());
    for (i, chunk) in data[..show].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b >= 0x20 && b < 0x7F { b as char } else { '.' })
            .collect();
        println!("  {:04x}: {:48}  |{}|", i * 16, hex.join(" "), ascii);
    }
}

// ── Infinint decoder (confirmed from real_infinint.cpp, TG=4) ─────────────
//   BB = 0x80 → 1 group → 5 bytes; BB = 0x40 → 2 groups → 9 bytes
fn decode_infinint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() { return None; }
    let bb = data[pos];
    if bb == 0x00 { return Some((0, 1)); }
    let num_groups = (bb.leading_zeros() as usize) + 1;
    let data_bytes = num_groups * 4;
    let total = 1 + data_bytes;
    if pos + total > data.len() { return None; }
    if data_bytes > 8 { return Some((u64::MAX, total)); }
    let mut v = 0u64;
    for i in 0..data_bytes { v = (v << 8) | (data[pos + 1 + i] as u64); }
    Some((v, total))
}

// ── Null-terminated string reader ─────────────────────────────────────────
fn read_cstr(data: &[u8], pos: usize) -> Option<(String, usize)> {
    let end = data[pos..].iter().position(|&b| b == 0)?;
    let name = String::from_utf8_lossy(&data[pos..pos + end]).into_owned();
    Some((name, pos + end + 1))
}

// ── Datetime skipper ─────────────────────────────────────────────────────
fn skip_datetime(data: &[u8], mut pos: usize) -> Option<usize> {
    if pos >= data.len() { return None; }
    let precision = data[pos] as char;
    pos += 1;
    let (_, c) = decode_infinint(data, pos)?;
    pos += c;
    if precision == 'n' || precision == 'u' {
        let (_, c) = decode_infinint(data, pos)?;
        pos += c;
    }
    Some(pos)
}

// ── Inode header skipper ─────────────────────────────────────────────────
fn skip_inode(data: &[u8], mut pos: usize) -> Option<(u16, usize)> {
    if pos >= data.len() { return None; }
    let flag = data[pos];
    let ea_flag = flag & 0x07;
    pos += 1;
    // UID, GID
    let (_, c) = decode_infinint(data, pos)?; pos += c;
    let (_, c) = decode_infinint(data, pos)?; pos += c;
    // perm (2 bytes BE)
    if pos + 2 > data.len() { return None; }
    let perm = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    // atime, mtime, ctime
    pos = skip_datetime(data, pos)?;
    pos = skip_datetime(data, pos)?;
    pos = skip_datetime(data, pos)?;
    // EA conditional fields
    if ea_flag == 0x01 {
        let (_, c) = decode_infinint(data, pos)?; pos += c; // ea_size
        let (_, c) = decode_infinint(data, pos)?; pos += c; // ea_offset
        let (crc_len, c) = decode_infinint(data, pos)?;     // ea_crc
        pos += c + crc_len as usize;
    }
    Some((perm, pos))
}

// ── Catalog tree walker ───────────────────────────────────────────────────

struct WalkStats {
    dirs: usize,
    files: usize,
    other: usize,
    max_depth: usize,
    errors: usize,
}

fn walk_catalog(
    data: &[u8],
    pos: &mut usize,
    path: &str,
    depth: usize,
    budget: &mut usize,
    stats: &mut WalkStats,
    verbose: bool,
) {
    let indent = "  ".repeat(depth);
    if depth > stats.max_depth { stats.max_depth = depth; }

    loop {
        if *pos >= data.len() || *budget == 0 { return; }

        // zzzzz terminator
        if *pos + 5 <= data.len() && &data[*pos..*pos + 5] == b"zzzzz" {
            if verbose { println!("{indent}[zzzzz catalog terminator at +{pos}]"); }
            *pos += 5;
            return;
        }

        let sig = data[*pos];
        let type_char = ((sig & 0x1F) | 0x60) as char;
        let status = sig >> 5;

        match type_char {
            'z' => {
                *pos += 1;
                return;
            }
            'd' | 'f' | 'l' | 'c' | 'b' | 'p' | 's' | 'h' | 'e' | 'x' | 'm' => {
                *pos += 1;
                let Some((name, new_pos)) = read_cstr(data, *pos) else {
                    stats.errors += 1;
                    return;
                };
                *pos = new_pos;
                let full_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };

                match type_char {
                    'd' => {
                        stats.dirs += 1;
                        let Some((perm, new_pos)) = skip_inode(data, *pos) else {
                            if verbose { println!("{indent}d [{full_path}] ERROR: truncated inode"); }
                            stats.errors += 1;
                            return;
                        };
                        *pos = new_pos;
                        if verbose || *budget <= 20 {
                            println!("{indent}d [{full_path}]  perm={perm:04o}  status={status}");
                        }
                        *budget -= 1;
                        walk_catalog(data, pos, &full_path, depth + 1, budget, stats, verbose);
                    }
                    'f' => {
                        stats.files += 1;
                        let Some((perm, new_pos)) = skip_inode(data, *pos) else {
                            if verbose { println!("{indent}f [{full_path}] ERROR: truncated inode"); }
                            stats.errors += 1;
                            return;
                        };
                        *pos = new_pos;
                        let Some((size, c)) = decode_infinint(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos += c;
                        let saved = status == 3 || status == 1;
                        let data_offset;
                        if saved {
                            let Some((offset, c)) = decode_infinint(data, *pos) else {
                                stats.errors += 1; return;
                            };
                            *pos += c;
                            data_offset = offset;
                            let Some((_, c)) = decode_infinint(data, *pos) else {
                                stats.errors += 1; return;
                            }; // storage_size
                            *pos += c;
                            if *pos + 2 > data.len() { stats.errors += 1; return; }
                            let algo = data[*pos + 1] as char;
                            *pos += 2; // flags + algo
                            let Some((crc_len, c)) = decode_infinint(data, *pos) else {
                                stats.errors += 1; return;
                            };
                            *pos += c + crc_len as usize;
                            if verbose || *budget <= 20 {
                                println!("{indent}f [{full_path}]  \
                                    size={size}  offset={data_offset}  perm={perm:04o}  algo={algo}");
                            }
                        } else {
                            data_offset = 0;
                            if *pos >= data.len() { stats.errors += 1; return; }
                            *pos += 1; // flags byte
                            if verbose || *budget <= 20 {
                                println!("{indent}f [{full_path}]  \
                                    size={size}  (not saved)  perm={perm:04o}");
                            }
                        }
                        let _ = data_offset;
                        *budget -= 1;
                    }
                    'l' => {
                        stats.other += 1;
                        let Some((_, new_pos)) = skip_inode(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos = new_pos;
                        let Some((target, new_pos)) = read_cstr(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos = new_pos;
                        if verbose { println!("{indent}l [{full_path}] -> {target}"); }
                    }
                    'c' | 'b' => {
                        stats.other += 1;
                        let Some((_, new_pos)) = skip_inode(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos = new_pos;
                        let Some((_, c)) = decode_infinint(data, *pos) else { stats.errors += 1; return; };
                        *pos += c;
                        let Some((_, c)) = decode_infinint(data, *pos) else { stats.errors += 1; return; };
                        *pos += c;
                    }
                    'p' | 's' => {
                        stats.other += 1;
                        let Some((_, new_pos)) = skip_inode(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos = new_pos;
                        if status != 3 { *pos += 1; }
                    }
                    'h' | 'e' => {
                        stats.other += 1;
                        let Some((_, c)) = decode_infinint(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos += c;
                    }
                    'x' => {
                        stats.other += 1;
                        let Some((_, new_pos)) = skip_inode(data, *pos) else {
                            stats.errors += 1; return;
                        };
                        *pos = new_pos;
                    }
                    'm' => {
                        stats.other += 1;
                        if *pos >= data.len() { stats.errors += 1; return; }
                        *pos += 1;
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                println!(
                    "{indent}[UNKNOWN sig=0x{sig:02x} type='{type_char}' status={status} at +{pos}]"
                );
                stats.errors += 1;
                *budget = 0;
                return;
            }
        }
    }
}

// ── Main discovery test ───────────────────────────────────────────────────

#[test]
#[ignore = "requires real .dar fixture; run manually for format discovery"]
fn dump_catalog_bytes() {
    if !std::path::Path::new(DAR_PATH).exists() {
        eprintln!("Skipping: DAR_PATH={DAR_PATH:?} does not exist.");
        return;
    }
    let file = File::open(DAR_PATH).expect("open dar file");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap");
    let data: &[u8] = &mmap;
    let file_size = data.len();
    println!("File size: {file_size} bytes ({:.2} GB)", file_size as f64 / 1e9);

    // ── Slice header ─────────────────────────────────────────────────────
    println!("\n=== Slice header (first 64 bytes) ===");
    dump_hex("Slice header", data, 64);

    // ── Catalog boundary discovery ────────────────────────────────────────
    let catalog_start = dar_archive::scanner::find_catalog_start(data)
        .expect("failed to find catalog start");
    let zzzzz_pos = dar_archive::scanner::find_last_zzzzz(data)
        .expect("failed to find catalog end (zzzzz)");

    println!("\n=== Catalog boundaries ===");
    println!("Catalog start : offset {catalog_start} (0x{catalog_start:08x})");
    println!("Last zzzzz    : offset {zzzzz_pos} (0x{zzzzz_pos:08x})");
    println!("Catalog size  : {} bytes ({:.2} MB)",
        zzzzz_pos - catalog_start,
        (zzzzz_pos - catalog_start) as f64 / 1_048_576.0);
    println!("Bytes after zzzzz (footer): {}", file_size - zzzzz_pos - 5);

    dump_hex("First 256 bytes of catalog", &data[catalog_start..], 256);
    dump_hex("64 bytes before zzzzz", &data[zzzzz_pos.saturating_sub(64)..zzzzz_pos], 64);
    dump_hex("64 bytes after zzzzz (footer)", &data[zzzzz_pos + 5..], 64);

    // ── Full catalog walk (verbose for first 50, then stats-only) ─────────
    println!("\n=== Catalog tree walk ===");
    let catalog_data = &data[catalog_start..zzzzz_pos + 5];

    // First pass: verbose walk of first 50 entries
    let mut pos = 0;
    let mut budget = 50usize;
    let mut stats = WalkStats { dirs: 0, files: 0, other: 0, max_depth: 0, errors: 0 };

    // Skip root entry header manually for verbose walk
    let sig = catalog_data[pos];
    let type_char = ((sig & 0x1F) | 0x60) as char;
    println!("Root sig=0x{sig:02x} type='{type_char}'");
    pos += 1;
    let Some((root_name, new_pos)) = read_cstr(catalog_data, pos) else {
        println!("ERROR: truncated root name"); return;
    };
    pos = new_pos;
    println!("Root name: {root_name:?}");
    let Some((root_perm, new_pos)) = skip_inode(catalog_data, pos) else {
        println!("ERROR: truncated root inode"); return;
    };
    pos = new_pos;
    println!("Root perm: {root_perm:04o}  inode_end_offset: {pos}");

    println!("\n--- First {budget} entries (verbose) ---");
    walk_catalog(catalog_data, &mut pos, "", 0, &mut budget, &mut stats, true);
    println!("\n--- Verbose walk done (budget=0 or catalog end) ---");

    // Second pass: full walk for counts.
    // Run on a dedicated thread with a 256 MB stack to survive deeply nested
    // Android directory trees (the default ~8 MB stack overflows).
    println!("\n=== Full catalog statistics ===");
    {
        pos = 0;
        pos += 1; // sig
        if let Some((_, new_pos)) = read_cstr(catalog_data, pos) { pos = new_pos; }
        if let Some((_, new_pos)) = skip_inode(catalog_data, pos) { pos = new_pos; }

        // Clone data into owned Vec so the thread can own it.
        let owned: Vec<u8> = catalog_data.to_vec();
        let result = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                let mut p = pos;
                let mut budget = usize::MAX;
                let mut s = WalkStats { dirs: 0, files: 0, other: 0, max_depth: 0, errors: 0 };
                walk_catalog(&owned, &mut p, "", 0, &mut budget, &mut s, false);
                (p, s, owned.len())
            })
            .expect("spawn full-walk thread")
            .join()
            .expect("full-walk thread panicked");

        let (final_pos, full_stats, catalog_len) = result;
        println!("Directories : {}", full_stats.dirs);
        println!("Files       : {}", full_stats.files);
        println!("Other       : {}", full_stats.other);
        println!("Max depth   : {}", full_stats.max_depth);
        println!("Parse errors: {}", full_stats.errors);
        println!("Final pos   : {final_pos} of {catalog_len} catalog bytes");
    }
}
