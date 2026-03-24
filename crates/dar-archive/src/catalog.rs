use anyhow::{bail, Context, Result};
use crate::infinint::decode_infinint;
use crate::archive::DarEntry;

// ── Signature byte decoding (from libdar cat_signature.cpp) ─────────────────
//
//   sig_byte = (status << 5) | (type_char & 0x1F)
//
//   Decode:
//     type_char = (sig_byte & 0x1F) | 0x60   (recovers ASCII char 'a'..'~')
//     status    = sig_byte >> 5
//
// ── EA / FSA flag byte layout (from libdar cat_inode.cpp) ───────────────────
//
//   bits 0-2:  EA status
//     0x01 = EA_FULL    (EAs fully saved in archive)
//     0x02 = EA_PART    (EAs partially saved)
//     0x03 = EA_NONE    (no EAs — most common in Passware archives)
//     0x04 = EA_FAKE
//     0x05 = EA_REMO    (EAs removed)
//   bits 3-4:  FSA status
//     0x00 = FSA_NONE
//     0x08 = FSA_PART
//     0x10 = FSA_FULL

const INODE_FLAG_EA_FULL: u8 = 0x01;
const INODE_FLAG_EA_MASK: u8 = 0x07;
const INODE_FLAG_FSA_MASK: u8 = 0x18;
const INODE_FLAG_FSA_FULL: u8 = 0x10;
const INODE_FLAG_FSA_PART: u8 = 0x08;

// Saved-status values (sig_byte >> 5):
const STATUS_DELTA: u8 = 1;
const STATUS_SAVED: u8 = 3;

/// Parse a libdar v8/v9 catalog.
///
/// `data` must start at the root directory entry (`d` sig byte) and end at or
/// after the final `zzzzz` terminator.  `slice_index` is stored in every
/// returned `DarEntry` so the caller can locate the right memory-mapped slice.
///
/// Uses iterative traversal with an explicit directory stack to avoid stack
/// overflow on deeply nested Android directory trees.
pub fn parse_catalog(data: &[u8], slice_index: usize) -> Result<Vec<DarEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    if data.is_empty() {
        bail!("empty catalog data");
    }

    // ── Root directory entry ──────────────────────────────────────────────
    // The catalog always opens with a pseudo-root `d` entry (typically named
    // "root").  We skip it and begin iterating over its children.
    let sig = data[pos];
    let type_char = ((sig & 0x1F) | 0x60) as char;
    if type_char != 'd' {
        bail!(
            "catalog must begin with a root directory entry, \
             got sig=0x{sig:02x} (type='{type_char}')"
        );
    }
    pos += 1;
    let (_, new_pos) = read_cstr(data, pos).context("reading root dir name")?;
    pos = new_pos;
    let (_, new_pos) = parse_inode_header(data, pos).context("skipping root inode header")?;
    pos = new_pos;

    // ── Iterative tree walk ───────────────────────────────────────────────
    // `dir_stack` holds the parent path for each open directory level.
    // Pushing: when a directory entry is encountered.
    // Popping: when EOD (0x7A) closes that directory.
    use std::path::PathBuf;
    let mut dir_stack: Vec<PathBuf> = vec![PathBuf::new()]; // root level

    while let Some(parent) = dir_stack.last().cloned() {
        if pos >= data.len() {
            bail!("unexpected end of catalog data at offset {pos} (no EOD)");
        }

        // zzzzz = catalog terminator; five consecutive EOD bytes.
        if pos + 5 <= data.len() && &data[pos..pos + 5] == b"zzzzz" {
            break;
        }

        let sig = data[pos];
        let type_char = ((sig & 0x1F) | 0x60) as char;
        let status = sig >> 5;

        match type_char {
            // ── End of directory ─────────────────────────────────────────
            'z' => {
                pos += 1;
                dir_stack.pop();
            }

            // ── Directory ────────────────────────────────────────────────
            'd' => {
                pos += 1;
                let (name, new_pos) = read_cstr(data, pos)
                    .with_context(|| format!("reading dir name at offset {pos}"))?;
                pos = new_pos;
                let path = parent.join(&name);
                let (inode, new_pos) = parse_inode_header(data, pos)
                    .with_context(|| format!("parsing inode for dir {path:?}"))?;
                pos = new_pos;

                entries.push(DarEntry {
                    path: path.clone(),
                    size: 0,
                    is_dir: true,
                    permissions: inode.perm as u32,
                    slice_index,
                    data_offset: 0,
                });

                // Push this directory so its children use it as parent.
                dir_stack.push(path);
            }

            // ── Regular file ─────────────────────────────────────────────
            'f' => {
                pos += 1;
                let (name, new_pos) = read_cstr(data, pos)
                    .with_context(|| format!("reading file name at offset {pos}"))?;
                pos = new_pos;
                let path = parent.join(&name);
                let (inode, new_pos) = parse_inode_header(data, pos)
                    .with_context(|| format!("parsing inode for file {path:?}"))?;
                pos = new_pos;

                // File-specific fields (from cat_file::inherited_dump):
                //   size         infinint  — always present
                //   if saved || delta:
                //     offset       infinint
                //     storage_size infinint
                //     flags        1 byte
                //     algo         1 byte (compression char)
                //     CRC          size_infinint + raw bytes
                //   else (not saved):
                //     flags        1 byte

                let (size, c) = decode_infinint(&data[pos..])
                    .with_context(|| format!("reading size for {path:?}"))?;
                pos += c;

                let saved = status == STATUS_SAVED || status == STATUS_DELTA;
                let data_offset;

                if saved {
                    let (offset, c) = decode_infinint(&data[pos..])
                        .with_context(|| format!("reading offset for {path:?}"))?;
                    pos += c;
                    data_offset = offset;

                    let (_, c) = decode_infinint(&data[pos..])
                        .with_context(|| format!("reading storage_size for {path:?}"))?;
                    pos += c;

                    if pos + 2 > data.len() {
                        bail!("truncated file entry {path:?}: missing flags/algo bytes");
                    }
                    pos += 2; // flags byte + compression algo byte

                    let (crc_len, c) = decode_infinint(&data[pos..])
                        .with_context(|| format!("reading CRC length for {path:?}"))?;
                    pos += c;
                    if pos + crc_len as usize > data.len() {
                        bail!("truncated file entry {path:?}: CRC data extends past end");
                    }
                    pos += crc_len as usize;
                } else {
                    if pos >= data.len() {
                        bail!("truncated file entry {path:?}: missing flags byte");
                    }
                    pos += 1; // flags byte
                    data_offset = 0;
                }

                entries.push(DarEntry {
                    path,
                    size,
                    is_dir: false,
                    permissions: inode.perm as u32,
                    slice_index,
                    data_offset,
                });
            }

            // ── Symbolic link ─────────────────────────────────────────────
            'l' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, new_pos) = parse_inode_header(data, pos)?; pos = new_pos;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos; // link target
            }

            // ── Character / block device ──────────────────────────────────
            'c' | 'b' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, new_pos) = parse_inode_header(data, pos)?; pos = new_pos;
                let (_, c) = decode_infinint(&data[pos..])?; pos += c; // major
                let (_, c) = decode_infinint(&data[pos..])?; pos += c; // minor
            }

            // ── Pipe / socket ─────────────────────────────────────────────
            'p' | 's' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, new_pos) = parse_inode_header(data, pos)?; pos = new_pos;
                if status != STATUS_SAVED { pos += 1; } // flags byte
            }

            // ── Hard link label ───────────────────────────────────────────
            'h' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, c) = decode_infinint(&data[pos..])?; pos += c; // etiquette
            }

            // ── File label (hard link target) ─────────────────────────────
            'e' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, c) = decode_infinint(&data[pos..])?; pos += c; // etiquette
            }

            // ── Door / ignored entry ──────────────────────────────────────
            'x' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                let (_, new_pos) = parse_inode_header(data, pos)?; pos = new_pos;
            }

            // ── Mirage (deleted-entry marker) ─────────────────────────────
            'm' => {
                pos += 1;
                let (_, new_pos) = read_cstr(data, pos)?; pos = new_pos;
                pos += 1; // original sig byte of deleted entry
            }

            _ => {
                bail!(
                    "unknown catalog entry type 0x{sig:02x} \
                     (decoded type='{type_char}', status={status}) at offset {pos}"
                );
            }
        }
    }

    Ok(entries)
}

// ── Inode header parsing ──────────────────────────────────────────────────

struct InodeFields {
    perm: u16,
}

/// Parse the inode header at `data[pos..]`, returning parsed fields and the
/// new position immediately after the header.
///
/// Inode header layout (archive format ≥ 08, ≥ 09 with datetime unit bytes):
///
///   flag        1 byte   EA+FSA status flags
///   uid         infinint UID (variable-length, typically 5 bytes)
///   gid         infinint GID
///   perm        2 bytes  POSIX mode bits, big-endian u16
///   atime       datetime unit_char(1) + seconds_infinint [+ sub_infinint if 'n'/'u']
///   mtime       datetime (same)
///   ctime       datetime (same; always present for archive ≥ 08)
///   [ea_size    infinint  only if ea_flag == EA_FULL]
///   [ea_offset  infinint  only if ea_flag == EA_FULL]
///   [ea_crc     size_infinint + raw bytes  only if ea_flag == EA_FULL]
///   [fsa fields if fsa_flag != FSA_NONE — currently unsupported]
fn parse_inode_header(data: &[u8], mut pos: usize) -> Result<(InodeFields, usize)> {
    if pos >= data.len() {
        bail!("truncated inode: missing flag byte at offset {pos}");
    }
    let flag_byte = data[pos];
    let ea_flag = flag_byte & INODE_FLAG_EA_MASK;
    let fsa_flag = flag_byte & INODE_FLAG_FSA_MASK;
    pos += 1;

    // UID (infinint)
    let (_, c) = decode_infinint(&data[pos..]).context("inode uid")?;
    pos += c;

    // GID (infinint)
    let (_, c) = decode_infinint(&data[pos..]).context("inode gid")?;
    pos += c;

    // perm (2-byte big-endian u16)
    if pos + 2 > data.len() {
        bail!("truncated inode: missing perm bytes at offset {pos}");
    }
    let perm = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Timestamps: atime, mtime, ctime (ctime always present for archive ≥ 08)
    pos = skip_datetime(data, pos).context("inode atime")?;
    pos = skip_datetime(data, pos).context("inode mtime")?;
    pos = skip_datetime(data, pos).context("inode ctime")?;

    // EA conditional fields (only when ea_saved == EA_FULL == 0x01)
    if ea_flag == INODE_FLAG_EA_FULL {
        // ea_size (infinint)
        let (_, c) = decode_infinint(&data[pos..]).context("ea_size")?;
        pos += c;
        // ea_offset (infinint)  — only in full (non-small) catalog
        let (_, c) = decode_infinint(&data[pos..]).context("ea_offset")?;
        pos += c;
        // ea_crc: size_infinint + raw bytes
        let (crc_len, c) = decode_infinint(&data[pos..]).context("ea_crc length")?;
        pos += c;
        pos += crc_len as usize;
    }

    // FSA fields: only supported for FSA_NONE; bail on anything else to avoid
    // silently misaligning the catalog stream.
    if fsa_flag == INODE_FLAG_FSA_FULL || fsa_flag == INODE_FLAG_FSA_PART {
        bail!(
            "FSA data (flag_byte=0x{flag_byte:02x}) is not yet supported; \
             cannot reliably parse this catalog entry"
        );
    }

    Ok((InodeFields { perm }, pos))
}

// ── Datetime field ────────────────────────────────────────────────────────

/// Skip one libdar datetime field at `data[pos..]`.
///
/// Format (archive ≥ version 9):
///   precision_char  1 byte  's'=second, 'n'=nanosecond, 'u'=microsecond
///   seconds         infinint
///   [sub_seconds    infinint  only if precision is 'n' or 'u']
fn skip_datetime(data: &[u8], mut pos: usize) -> Result<usize> {
    if pos >= data.len() {
        bail!("truncated datetime: missing precision byte at offset {pos}");
    }
    let precision = data[pos] as char;
    pos += 1;

    let (_, c) = decode_infinint(&data[pos..]).context("datetime seconds")?;
    pos += c;

    if precision == 'n' || precision == 'u' {
        let (_, c) = decode_infinint(&data[pos..]).context("datetime sub-seconds")?;
        pos += c;
    }

    Ok(pos)
}

// ── String reading ────────────────────────────────────────────────────────

/// Read a null-terminated UTF-8 string starting at `data[pos]`.
/// Returns `(name, position_after_null)`.
fn read_cstr(data: &[u8], pos: usize) -> Result<(String, usize)> {
    let end = data[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated string at offset {pos}"))?;
    let name = String::from_utf8_lossy(&data[pos..pos + end]).into_owned();
    Ok((name, pos + end + 1))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Build a minimal 5-byte infinint for the given u32 value.
    fn inf(v: u32) -> Vec<u8> {
        let mut b = vec![0x80u8];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    /// Build a minimal inode header with seconds-precision timestamps.
    /// ea_flag = EA_NONE (0x03), uid = 0, gid = 0, perm = 0o755.
    fn minimal_inode(perm: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x03); // ea_flag = EA_NONE
        buf.extend(inf(0)); // uid = 0
        buf.extend(inf(0)); // gid = 0
        buf.extend_from_slice(&perm.to_be_bytes()); // perm
        // atime: 's' + 0
        buf.push(b's');
        buf.extend(inf(0));
        // mtime: 's' + 0
        buf.push(b's');
        buf.extend(inf(0));
        // ctime: 's' + 0
        buf.push(b's');
        buf.extend(inf(0));
        buf
    }

    fn build_catalog(entries: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Root directory entry
        buf.push(0x64); // sig 'd', saved (status=3)
        buf.extend_from_slice(b"root\x00"); // name
        buf.extend(minimal_inode(0o755));
        // Children
        buf.extend_from_slice(entries);
        // zzzzz terminator
        buf.extend_from_slice(b"zzzzz");
        buf
    }

    #[test]
    fn test_empty_catalog() {
        let data = build_catalog(&[]);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_single_directory() {
        let mut children = Vec::new();
        // Directory entry: 'd' sig + "subdir\0" + inode + EOD
        children.push(0x64); // sig 'd', saved
        children.extend_from_slice(b"subdir\x00");
        children.extend(minimal_inode(0o755));
        children.push(0x7A); // EOD closes "subdir"

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("subdir"));
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].permissions, 0o755);
    }

    #[test]
    fn test_single_saved_file() {
        let mut children = Vec::new();
        // File entry: 'f' sig + "hello.txt\0" + inode + size + offset + storage_size
        //             + flags(1) + algo(1) + crc_size + crc_bytes
        children.push(0x66); // sig 'f', saved (status=3)
        children.extend_from_slice(b"hello.txt\x00");
        children.extend(minimal_inode(0o644));
        children.extend(inf(13)); // size = 13
        children.extend(inf(512)); // offset = 512
        children.extend(inf(13)); // storage_size = 13
        children.push(0x00); // flags = 0
        children.push(b'n'); // algo = 'n' (no compression)
        // CRC: 4-byte CRC32
        children.extend(inf(4)); // crc_len = 4
        children.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // crc data

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 1);
        let file = &entries[0];
        assert_eq!(file.path, PathBuf::from("hello.txt"));
        assert!(!file.is_dir);
        assert_eq!(file.size, 13);
        assert_eq!(file.data_offset, 512);
        assert_eq!(file.permissions, 0o644);
    }

    #[test]
    fn test_nested_directory_with_file() {
        let mut children = Vec::new();
        // Directory "docs" containing file "readme.txt"
        children.push(0x64); // 'd' saved
        children.extend_from_slice(b"docs\x00");
        children.extend(minimal_inode(0o755));
        // -- docs children --
        children.push(0x66); // 'f' saved
        children.extend_from_slice(b"readme.txt\x00");
        children.extend(minimal_inode(0o644));
        children.extend(inf(100)); // size
        children.extend(inf(1024)); // offset
        children.extend(inf(100)); // storage_size
        children.push(0x00); // flags
        children.push(b'n'); // algo
        children.extend(inf(4)); // crc_len
        children.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // crc
        children.push(0x7A); // EOD closes docs
        // Top-level file "top.txt"
        children.push(0x66);
        children.extend_from_slice(b"top.txt\x00");
        children.extend(minimal_inode(0o644));
        children.extend(inf(5));
        children.extend(inf(2048));
        children.extend(inf(5));
        children.push(0x00);
        children.push(b'n');
        children.extend(inf(4));
        children.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 3, "docs dir + readme.txt + top.txt");

        let docs = entries.iter().find(|e| e.is_dir).unwrap();
        assert_eq!(docs.path, PathBuf::from("docs"));

        let readme = entries.iter().find(|e| e.path == PathBuf::from("docs/readme.txt")).unwrap();
        assert_eq!(readme.size, 100);
        assert_eq!(readme.data_offset, 1024);

        let top = entries.iter().find(|e| e.path == PathBuf::from("top.txt")).unwrap();
        assert_eq!(top.size, 5);
        assert_eq!(top.data_offset, 2048);
    }

    #[test]
    fn test_not_saved_file() {
        let mut children = Vec::new();
        // File with status=2 (not saved / isolated catalog): sig = (2 << 5) | ('f' & 0x1F)
        //   'f' = 0x66, 0x1F & 0x66 = 0x06, 2 << 5 = 0x40 → sig = 0x46
        children.push(0x46); // 'f', not saved
        children.extend_from_slice(b"ghost.bin\x00");
        children.extend(minimal_inode(0o600));
        children.extend(inf(42)); // size (always present)
        children.push(0x00); // flags byte (present when not saved)

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 1);
        let f = &entries[0];
        assert_eq!(f.size, 42);
        assert_eq!(f.data_offset, 0); // no offset for unsaved entries
    }

    #[test]
    fn test_symlink_skipped() {
        let mut children = Vec::new();
        // Symlink 'l' + name + inode + target string
        children.push(0x6C); // 'l', saved
        children.extend_from_slice(b"mylink\x00");
        children.extend(minimal_inode(0o777));
        children.extend_from_slice(b"/etc/passwd\x00"); // link target
        // File after symlink
        children.push(0x66);
        children.extend_from_slice(b"after.txt\x00");
        children.extend(minimal_inode(0o644));
        children.extend(inf(1));
        children.extend(inf(17));
        children.extend(inf(1));
        children.push(0x00);
        children.push(b'n');
        children.extend(inf(4));
        children.extend_from_slice(&[0x00; 4]);

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        // Symlink is skipped (not added to entries); only file is returned.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("after.txt"));
    }

    #[test]
    fn test_eod_terminates_dir() {
        // Empty directory (EOD immediately after inode header) should produce
        // the dir entry with 0 children.
        let mut children = Vec::new();
        children.push(0x64);
        children.extend_from_slice(b"empty\x00");
        children.extend(minimal_inode(0o755));
        children.push(0x7A); // EOD

        let data = build_catalog(&children);
        let entries = parse_catalog(&data, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_dir);
    }
}
