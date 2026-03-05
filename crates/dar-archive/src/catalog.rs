use std::path::PathBuf;
use anyhow::{bail, Result};
use crate::infinint::decode_infinint;
use crate::archive::DarEntry;

// Type byte constants — initial values; adjust after running the discovery test
// if a real DAR file uses different type byte values.
const TYPE_FILE: u8 = 0x02;
const TYPE_DIR: u8  = 0x04;
const TYPE_END: u8  = 0x00;

/// Parse all catalog entries from `data` (the bytes immediately after the first zzzzz).
/// `slice_index` is stored in every returned DarEntry.
pub fn parse_catalog(data: &[u8], slice_index: usize) -> Result<Vec<DarEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // End-of-catalog: second zzzzz or explicit terminator
        if pos + 5 <= data.len() && &data[pos..pos + 5] == b"zzzzz" {
            break;
        }
        let type_byte = data[pos];
        if type_byte == TYPE_END {
            break;
        }
        match parse_one_entry(&data[pos..], slice_index) {
            Ok((entry, consumed)) => {
                pos += consumed;
                if let Some(e) = entry {
                    entries.push(e);
                }
            }
            Err(e) => {
                // Graceful degradation: stop at parse error rather than propagating
                eprintln!("catalog parse stopped at offset 0x{pos:x}: {e}");
                break;
            }
        }
    }

    Ok(entries)
}

/// Parse one catalog entry starting at `data[0]`.
/// Returns (Some(DarEntry), bytes_consumed) for file/dir entries,
/// or (None, bytes_consumed) for unknown types (skipped).
fn parse_one_entry(data: &[u8], slice_index: usize) -> Result<(Option<DarEntry>, usize)> {
    if data.is_empty() {
        bail!("empty entry data at parse_one_entry");
    }
    let type_byte = data[0];
    let mut pos = 1;

    // Entry name: infinint(name_len) + name_bytes
    let (name_len, consumed) = decode_infinint(&data[pos..])
        .map_err(|e| anyhow::anyhow!("name_len infinint: {e}"))?;
    pos += consumed;
    let name_end = pos + name_len as usize;
    anyhow::ensure!(
        name_end <= data.len(),
        "truncated entry name (need {name_end}, have {})",
        data.len()
    );
    let name = std::str::from_utf8(&data[pos..name_end])
        .map_err(|_| anyhow::anyhow!("non-UTF8 entry name"))?
        .to_owned();
    pos = name_end;

    match type_byte & 0x7F {
        t if t == TYPE_DIR => {
            Ok((Some(DarEntry {
                path: PathBuf::from(&name),
                size: 0,
                is_dir: true,
                permissions: 0o755,
                slice_index,
                data_offset: 0,
            }), pos))
        }
        t if t == TYPE_FILE => {
            let (size, c) = decode_infinint(&data[pos..])
                .map_err(|e| anyhow::anyhow!("file size for '{name}': {e}"))?;
            pos += c;
            let (data_offset, c) = decode_infinint(&data[pos..])
                .map_err(|e| anyhow::anyhow!("data_offset for '{name}': {e}"))?;
            pos += c;
            Ok((Some(DarEntry {
                path: PathBuf::from(&name),
                size,
                is_dir: false,
                permissions: 0o644,
                slice_index,
                data_offset,
            }), pos))
        }
        _ => {
            // Unknown type — skip (name was already consumed above)
            Ok((None, pos))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a u64 as a DAR infinint.
    ///
    /// decode_infinint rules:
    /// - First byte non-zero → single-byte encoding: value = first byte (works for 1..=255)
    /// - N leading zero bytes → read next N bytes as big-endian value
    ///
    /// So: value 0..=255 non-zero → single byte [v]
    ///     value 0 → [0x00, 0x00]
    ///     value 256..=65535 → [0x00, 0x00, hi, lo]
    ///     value 65536..=16777215 → [0x00, 0x00, 0x00, b2, b1, b0]
    fn enc(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0x00, 0x00];
        }
        if value <= 255 {
            return vec![value as u8];
        }
        // Compute the big-endian bytes needed for value
        let mut value_bytes: Vec<u8> = Vec::new();
        let mut v = value;
        while v > 0 {
            value_bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        value_bytes.reverse(); // big-endian
        let n = value_bytes.len();
        let mut buf = vec![0u8; n]; // N zero prefix bytes
        buf.extend_from_slice(&value_bytes); // N value bytes
        buf
    }

    fn synthetic_catalog() -> Vec<u8> {
        let mut buf = Vec::new();
        // Directory entry: type=0x04, name="testdir" (7 bytes)
        buf.push(TYPE_DIR);
        buf.extend(enc(7));
        buf.extend_from_slice(b"testdir");
        // File entry: type=0x02, name="hello.txt" (9 bytes), size=13, offset=512
        buf.push(TYPE_FILE);
        buf.extend(enc(9));
        buf.extend_from_slice(b"hello.txt");
        buf.extend(enc(13));
        buf.extend(enc(512));
        // End of catalog
        buf.push(TYPE_END);
        buf
    }

    #[test]
    fn test_parse_synthetic_counts() {
        let entries = parse_catalog(&synthetic_catalog(), 0).unwrap();
        assert_eq!(entries.len(), 2, "expected 1 dir + 1 file");
    }

    #[test]
    fn test_parse_synthetic_dir() {
        let entries = parse_catalog(&synthetic_catalog(), 0).unwrap();
        let dir = entries.iter().find(|e| e.is_dir).expect("dir entry");
        assert_eq!(dir.path.to_str().unwrap(), "testdir");
        assert_eq!(dir.size, 0);
    }

    #[test]
    fn test_parse_synthetic_file() {
        let entries = parse_catalog(&synthetic_catalog(), 0).unwrap();
        let file = entries.iter().find(|e| !e.is_dir).expect("file entry");
        assert_eq!(file.path.to_str().unwrap(), "hello.txt");
        assert_eq!(file.size, 13);
        assert_eq!(file.data_offset, 512);
    }

    #[test]
    fn test_parse_stops_at_second_zzzzz() {
        let mut data = synthetic_catalog();
        data.extend_from_slice(b"zzzzz");
        data.push(TYPE_FILE); // garbage after zzzzz — must be ignored
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
