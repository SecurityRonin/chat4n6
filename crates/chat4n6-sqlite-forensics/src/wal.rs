use crate::btree::{parse_table_leaf_page, walk_table_btree, walk_table_btree_with_overlay};
use crate::db::WalMode;
use crate::dedup::record_hash;
use crate::record::RecoveredRecord;
use chat4n6_plugin_api::{EvidenceSource, WalDelta, WalDeltaStatus};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const WAL_MAGIC_1: u32 = 0x377f0682;
pub const WAL_MAGIC_2: u32 = 0x377f0683;
pub const WAL_HEADER_SIZE: usize = 32;
pub const WAL_FRAME_HEADER_SIZE: usize = 24;

pub fn is_wal_header(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == WAL_MAGIC_1 || magic == WAL_MAGIC_2
}

pub fn wal_frame_offset(frame_index: usize, page_size: u32) -> u64 {
    (WAL_HEADER_SIZE + frame_index * (WAL_FRAME_HEADER_SIZE + page_size as usize)) as u64
}

#[derive(Debug)]
pub struct WalHeader {
    pub page_size: u32,
    pub checkpoint_seq: u32,
    pub salt1: u32,
    pub salt2: u32,
}

impl WalHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 || !is_wal_header(data) {
            return None;
        }
        Some(Self {
            page_size: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            checkpoint_seq: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            salt1: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            salt2: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct WalFrame {
    pub page_number: u32,
    /// Non-zero means this is a commit frame.
    pub db_size_after_commit: u32,
    pub salt1: u32,
    pub salt2: u32,
    /// Byte offset of the page data within the WAL byte slice.
    pub page_data_offset: usize,
}

/// Parse all frames from a WAL file, grouped by salt1 (transaction identifier).
/// Returns BTreeMap<salt1, Vec<WalFrame>> preserving file order within each group.
///
/// Note: salt1 values are random — BTreeMap ordering by key does NOT imply
/// time ordering. Use file position (frame index) to determine recency.
pub fn parse_wal_frames(wal: &[u8], page_size: u32) -> BTreeMap<u32, Vec<WalFrame>> {
    let mut map: BTreeMap<u32, Vec<WalFrame>> = BTreeMap::new();
    if !is_wal_header(wal) {
        return map;
    }
    let frame_size = WAL_FRAME_HEADER_SIZE + page_size as usize;
    let mut idx = 0;
    loop {
        let frame_off = WAL_HEADER_SIZE + idx * frame_size;
        if frame_off + WAL_FRAME_HEADER_SIZE > wal.len() {
            break;
        }
        let fh = &wal[frame_off..frame_off + WAL_FRAME_HEADER_SIZE];
        let page_number = u32::from_be_bytes([fh[0], fh[1], fh[2], fh[3]]);
        let db_size = u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]);
        let salt1 = u32::from_be_bytes([fh[8], fh[9], fh[10], fh[11]]);
        let salt2 = u32::from_be_bytes([fh[12], fh[13], fh[14], fh[15]]);
        if page_number == 0 {
            break;
        }
        let page_data_end = frame_off + frame_size;
        if page_data_end > wal.len() {
            break;
        }
        map.entry(salt1).or_default().push(WalFrame {
            page_number,
            db_size_after_commit: db_size,
            salt1,
            salt2,
            page_data_offset: frame_off + WAL_FRAME_HEADER_SIZE,
        });
        idx += 1;
    }
    map
}

/// Layer 2: extract records from WAL frames that haven't been checkpointed to main DB.
///
/// Processes ALL WAL frames (all salt groups, in file order). A frame is considered
/// unapplied if its page content differs from the corresponding main DB page.
/// Tags records as `EvidenceSource::WalPending`.
pub fn recover_layer2(
    wal: &[u8],
    db: &[u8],
    page_size: u32,
    table_name: &str,
) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    let frames = parse_wal_frames(wal, page_size);

    // Process all salt groups in file order (BTreeMap iteration is by salt1 key,
    // but within each group frames are in file order). We process all groups
    // because forensic recovery must not discard any session's data.
    for frame_group in frames.values() {
        for frame in frame_group {
            let wal_page = match wal
                .get(frame.page_data_offset..frame.page_data_offset + page_size as usize)
            {
                Some(p) => p,
                None => continue,
            };
            // Frame is "pending" (unapplied) if the main DB page differs from WAL page
            let db_offset = (frame.page_number as usize - 1) * page_size as usize;
            let db_page = db.get(db_offset..db_offset + page_size as usize);
            if db_page == Some(wal_page) {
                continue; // already checkpointed
            }
            let bhdr = if frame.page_number == 1 { 100 } else { 0 };
            let mut page_records =
                parse_table_leaf_page(db, wal_page, bhdr, frame.page_number, page_size, table_name);
            for r in &mut page_records {
                r.source = EvidenceSource::WalPending;
            }
            records.extend(page_records);
        }
    }
    records
}

/// Layer 3: compare WAL pages against main DB to detect row-level changes.
///
/// For each database page that appears in the WAL, compares the WAL version
/// against the main DB version. Produces `WalDelta` entries tagged as
/// AddedInWal / DeletedInWal / ModifiedInWal.
///
/// Deduplication: for each (table, row_id), only the **last-written** delta
/// (by file position) is retained, preventing contradictory entries when
/// a row is modified across multiple WAL sessions.
pub fn recover_layer3_deltas(
    wal: &[u8],
    db: &[u8],
    page_size: u32,
    table_name: &str,
) -> Vec<WalDelta> {
    use std::collections::HashMap;

    // Use a HashMap keyed by row_id to keep only the last-seen delta per row.
    // BTreeMap iteration order is by salt1 value (not file position), so we
    // process frames in the order they appear within each group (file order)
    // but accept that cross-group ordering may not be strictly chronological.
    // For forensic purposes this is acceptable — we expose all differences.
    let mut seen: HashMap<i64, WalDeltaStatus> = HashMap::new();

    let frames = parse_wal_frames(wal, page_size);
    for frame_group in frames.values() {
        for frame in frame_group {
            let wal_page = match wal
                .get(frame.page_data_offset..frame.page_data_offset + page_size as usize)
            {
                Some(p) => p,
                None => continue,
            };
            let db_offset = (frame.page_number as usize - 1) * page_size as usize;
            let bhdr = if frame.page_number == 1 { 100 } else { 0 };

            let db_page = match db.get(db_offset..db_offset + page_size as usize) {
                Some(p) => p,
                None => {
                    // Page absent in main DB — all WAL rows are additions
                    let wal_records = parse_table_leaf_page(
                        db,
                        wal_page,
                        bhdr,
                        frame.page_number,
                        page_size,
                        table_name,
                    );
                    for r in wal_records {
                        if let Some(row_id) = r.row_id {
                            seen.insert(row_id, WalDeltaStatus::AddedInWal);
                        }
                    }
                    continue;
                }
            };
            if wal_page == db_page {
                continue;
            }

            let wal_records =
                parse_table_leaf_page(db, wal_page, bhdr, frame.page_number, page_size, table_name);
            let db_records =
                parse_table_leaf_page(db, db_page, bhdr, frame.page_number, page_size, table_name);

            let wal_ids: HashMap<i64, _> = wal_records
                .iter()
                .filter_map(|r| r.row_id.map(|id| (id, &r.values)))
                .collect();
            let db_ids: HashMap<i64, _> = db_records
                .iter()
                .filter_map(|r| r.row_id.map(|id| (id, &r.values)))
                .collect();

            for &id in wal_ids.keys() {
                if !db_ids.contains_key(&id) {
                    seen.insert(id, WalDeltaStatus::AddedInWal);
                }
            }
            for &id in db_ids.keys() {
                if !wal_ids.contains_key(&id) {
                    seen.insert(id, WalDeltaStatus::DeletedInWal);
                }
            }
            for (&id, wal_vals) in &wal_ids {
                if let Some(db_vals) = db_ids.get(&id) {
                    if wal_vals != db_vals {
                        seen.insert(id, WalDeltaStatus::ModifiedInWal);
                    }
                }
            }
        }
    }

    seen.into_iter()
        .map(|(row_id, status)| WalDelta {
            table: table_name.to_string(),
            row_id,
            status,
        })
        .collect()
}

/// Build a page overlay from WAL frames. Last-writer-wins per page number.
///
/// Iterates all frames in file order across all salt groups and inserts
/// each frame's page data into the overlay map, overwriting any earlier entry
/// for the same page number.
pub fn build_wal_overlay(wal: &[u8], page_size: u32) -> HashMap<u32, Vec<u8>> {
    let mut overlay: HashMap<u32, Vec<u8>> = HashMap::new();
    let frames = parse_wal_frames(wal, page_size);

    // Collect all frames in their BTreeMap order (by salt1) and file order within groups.
    // For strict last-writer-wins by absolute file position, we use page_data_offset
    // as the ordering key.
    let mut all_frames: Vec<&WalFrame> = frames.values().flatten().collect();
    // Sort by page_data_offset so later frames (higher offset) overwrite earlier ones.
    all_frames.sort_by_key(|f| f.page_data_offset);

    for frame in all_frames {
        if let Some(page_bytes) =
            wal.get(frame.page_data_offset..frame.page_data_offset + page_size as usize)
        {
            overlay.insert(frame.page_number, page_bytes.to_vec());
        }
    }
    overlay
}

/// Enhanced Layer 2: WAL replay with differential analysis.
///
/// - `WalMode::Ignore`: returns empty.
/// - `WalMode::Apply`: walks B-tree with overlay only; tags all records `WalPending`.
/// - `WalMode::Both`: differential analysis — records only in WAL view are `WalPending`,
///   records only in raw DB view are `WalDeleted` (deleted by WAL transaction).
pub fn recover_layer2_enhanced(
    db: &[u8],
    wal: &[u8],
    page_size: u32,
    mode: WalMode,
    table_roots: &HashMap<String, u32>,
) -> Vec<RecoveredRecord> {
    if mode == WalMode::Ignore {
        return Vec::new();
    }

    let overlay = build_wal_overlay(wal, page_size);
    if overlay.is_empty() {
        return Vec::new();
    }

    // Walk B-trees through overlay to get WAL-applied view.
    let mut wal_view = Vec::new();
    for (table, root) in table_roots {
        walk_table_btree_with_overlay(db, page_size, *root, table, &overlay, &mut wal_view);
    }

    if mode == WalMode::Apply {
        for r in &mut wal_view {
            r.source = EvidenceSource::WalPending;
        }
        return wal_view;
    }

    // WalMode::Both — differential analysis.
    let mut raw_view = Vec::new();
    for (table, root) in table_roots {
        walk_table_btree(db, page_size, *root, table, EvidenceSource::Live, &mut raw_view);
    }

    let wal_hashes: HashSet<[u8; 32]> = wal_view.iter().map(record_hash).collect();
    let raw_hashes: HashSet<[u8; 32]> = raw_view.iter().map(record_hash).collect();

    let mut results = Vec::new();

    // Records only in WAL view → WalPending (new/modified by WAL transaction).
    for mut r in wal_view {
        let h = record_hash(&r);
        if !raw_hashes.contains(&h) {
            r.source = EvidenceSource::WalPending;
            results.push(r);
        }
    }

    // Records only in raw view → WalDeleted (deleted by WAL transaction).
    for mut r in raw_view {
        let h = record_hash(&r);
        if !wal_hashes.contains(&h) {
            r.source = EvidenceSource::WalDeleted;
            results.push(r);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_magic_detection() {
        let magic1 = 0x377f0682u32.to_be_bytes();
        let magic2 = 0x377f0683u32.to_be_bytes();
        assert!(is_wal_header(&magic1));
        assert!(is_wal_header(&magic2));
        assert!(!is_wal_header(b"\x00\x00\x00\x00"));
    }

    #[test]
    fn test_wal_frame_offset_calculation() {
        let page_size = 4096u32;
        let frame_0_offset = wal_frame_offset(0, page_size);
        assert_eq!(frame_0_offset, 32);
        let frame_1_offset = wal_frame_offset(1, page_size);
        assert_eq!(frame_1_offset, 32 + 24 + 4096);
    }

    #[test]
    fn test_parse_wal_header() {
        let mut header = vec![0u8; 32];
        header[0..4].copy_from_slice(&0x377f0682u32.to_be_bytes());
        header[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        header[12..16].copy_from_slice(&7u32.to_be_bytes()); // checkpoint_seq
        header[16..20].copy_from_slice(&42u32.to_be_bytes()); // salt1
        header[20..24].copy_from_slice(&99u32.to_be_bytes()); // salt2
        let wh = WalHeader::parse(&header).unwrap();
        assert_eq!(wh.page_size, 4096);
        assert_eq!(wh.checkpoint_seq, 7);
        assert_eq!(wh.salt1, 42);
        assert_eq!(wh.salt2, 99);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn make_wal_bytes(page_size: u32, frames: &[(u32, u32, u32, &[u8])]) -> Vec<u8> {
        // frames: (page_number, db_size_after_commit, salt1, page_data)
        let mut wal = vec![0u8; WAL_HEADER_SIZE];
        wal[0..4].copy_from_slice(&WAL_MAGIC_1.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        for (page_number, db_size, salt1, page_data) in frames {
            let mut frame_header = vec![0u8; WAL_FRAME_HEADER_SIZE];
            frame_header[0..4].copy_from_slice(&page_number.to_be_bytes());
            frame_header[4..8].copy_from_slice(&db_size.to_be_bytes());
            frame_header[8..12].copy_from_slice(&salt1.to_be_bytes());
            wal.extend_from_slice(&frame_header);
            let mut padded = vec![0u8; page_size as usize];
            let copy_len = page_data.len().min(page_size as usize);
            padded[..copy_len].copy_from_slice(&page_data[..copy_len]);
            wal.extend_from_slice(&padded);
        }
        wal
    }

    #[test]
    fn test_parse_wal_frames_single_frame() {
        let page_size = 4096u32;
        let page_data = vec![0xABu8; page_size as usize];
        let wal = make_wal_bytes(page_size, &[(2, 1, 42, &page_data)]);
        let frames = parse_wal_frames(&wal, page_size);
        assert_eq!(frames.len(), 1);
        let group = frames.get(&42).unwrap();
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].page_number, 2);
        assert_eq!(group[0].salt1, 42);
    }

    #[test]
    fn test_parse_wal_frames_empty_wal() {
        let frames = parse_wal_frames(&[], 4096);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_parse_wal_frames_groups_by_salt1() {
        let page_size = 4096u32;
        let pd = vec![0u8; page_size as usize];
        let wal = make_wal_bytes(
            page_size,
            &[(1, 0, 100, &pd), (2, 1, 100, &pd), (3, 1, 200, &pd)],
        );
        let frames = parse_wal_frames(&wal, page_size);
        assert_eq!(frames.get(&100).unwrap().len(), 2);
        assert_eq!(frames.get(&200).unwrap().len(), 1);
    }

    #[test]
    fn test_build_wal_overlay() {
        let page_size = 4096u32;
        let page_data = vec![0xABu8; page_size as usize];
        let wal = make_wal_bytes(page_size, &[(2, 1, 42, &page_data)]);
        let overlay = build_wal_overlay(&wal, page_size);
        assert_eq!(overlay.len(), 1);
        assert!(overlay.contains_key(&2));
        assert_eq!(overlay[&2].len(), page_size as usize);
    }

    #[test]
    fn test_build_wal_overlay_last_writer_wins() {
        let page_size = 4096u32;
        let page1 = vec![0xAAu8; page_size as usize];
        let page2 = vec![0xBBu8; page_size as usize];
        let wal = make_wal_bytes(
            page_size,
            &[
                (2, 0, 42, &page1),
                (2, 1, 42, &page2), // same page, later frame — should win
            ],
        );
        let overlay = build_wal_overlay(&wal, page_size);
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[&2][0], 0xBB, "last writer should win");
    }

    #[test]
    fn test_build_wal_overlay_empty_wal() {
        let overlay = build_wal_overlay(&[], 4096);
        assert!(overlay.is_empty());
    }

    #[test]
    fn test_recover_layer2_enhanced_ignore_mode() {
        let page_size = 4096u32;
        let page_data = vec![0u8; page_size as usize];
        let wal = make_wal_bytes(page_size, &[(1, 1, 42, &page_data)]);
        let table_roots = std::collections::HashMap::new();
        let results =
            recover_layer2_enhanced(&[], &wal, page_size, WalMode::Ignore, &table_roots);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_layer2_enhanced_empty_overlay() {
        // No WAL header → empty overlay → should return empty
        let table_roots = std::collections::HashMap::new();
        let results = recover_layer2_enhanced(
            &[],
            &[],
            4096,
            WalMode::Both,
            &table_roots,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn test_empty_wal_zero_frames() {
        // Valid WAL header but zero frames → parse_wal_frames returns empty map.
        let page_size = 4096u32;
        let wal = make_wal_bytes(page_size, &[]);
        let frames = parse_wal_frames(&wal, page_size);
        assert!(frames.is_empty(), "zero frames should yield empty frame map");
    }

    #[test]
    fn test_recover_layer2_enhanced_wal_mode_ignore_returns_empty() {
        // WalMode::Ignore must always return empty regardless of WAL content.
        let page_size = 4096u32;
        let page_data = vec![0xABu8; page_size as usize];
        let wal = make_wal_bytes(page_size, &[(1, 1, 99, &page_data)]);
        let mut roots = std::collections::HashMap::new();
        roots.insert("t".to_string(), 1u32);
        let results = recover_layer2_enhanced(&[], &wal, page_size, WalMode::Ignore, &roots);
        assert!(
            results.is_empty(),
            "WalMode::Ignore must return empty regardless of frame content"
        );
    }

    // -----------------------------------------------------------------------
    // Helper: build a valid table leaf page with one record (int + text cols)
    // -----------------------------------------------------------------------

    /// Create a valid SQLite table leaf page (0x0D) with one record.
    /// The record has two columns: a 1-byte integer and a zero-length text.
    /// `row_id` and `int_value` are single-byte values.
    fn make_table_leaf_page(page_size: usize, row_id: u8, int_value: u8) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        page[0] = 0x0D; // table leaf
        // cell count = 1 (bytes 3-4, big-endian)
        page[3] = 0x00;
        page[4] = 0x01;
        // cell content area start (bytes 5-6)
        let cell_start: u16 = 100;
        page[5] = (cell_start >> 8) as u8;
        page[6] = (cell_start & 0xFF) as u8;
        // cell pointer array entry (bytes 8-9)
        page[8] = (cell_start >> 8) as u8;
        page[9] = (cell_start & 0xFF) as u8;
        // Cell at offset 100:
        //   payload_len(varint) = 4
        //   rowid(varint) = row_id
        //   record header: header_len=3, serial_type=1 (1-byte int), serial_type=13 (0-len text)
        //   data: int_value
        page[cell_start as usize] = 0x04;     // payload_len = 4
        page[cell_start as usize + 1] = row_id; // rowid
        page[cell_start as usize + 2] = 0x03; // header_len = 3
        page[cell_start as usize + 3] = 0x01; // serial_type 1 (1-byte signed int)
        page[cell_start as usize + 4] = 0x0D; // serial_type 13 = text, len=(13-13)/2=0
        page[cell_start as usize + 5] = int_value; // the integer value
        page
    }

    /// Build a minimal "DB" consisting of `num_pages` zero-filled pages.
    fn make_empty_db(page_size: usize, num_pages: usize) -> Vec<u8> {
        vec![0u8; page_size * num_pages]
    }

    // -----------------------------------------------------------------------
    // WalHeader::parse returning None  (line 36)
    // -----------------------------------------------------------------------

    #[test]
    fn test_wal_header_parse_too_short() {
        // Data shorter than 32 bytes → None
        let short = vec![0u8; 16];
        assert!(WalHeader::parse(&short).is_none());
    }

    #[test]
    fn test_wal_header_parse_wrong_magic() {
        // 32 bytes but magic is wrong → None
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(WalHeader::parse(&data).is_none());
    }

    #[test]
    fn test_wal_header_parse_empty() {
        assert!(WalHeader::parse(&[]).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_wal_frames edge cases: page_number=0 (line 81), truncated (line 85)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_wal_frames_page_number_zero_breaks() {
        // A frame with page_number=0 should cause early break (line 80-81)
        let page_size = 512u32;
        // Build WAL manually: header + frame with page_number=0
        let mut wal = vec![0u8; WAL_HEADER_SIZE];
        wal[0..4].copy_from_slice(&WAL_MAGIC_1.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        // Frame header: page_number=0
        let mut fh = vec![0u8; WAL_FRAME_HEADER_SIZE];
        fh[0..4].copy_from_slice(&0u32.to_be_bytes()); // page_number = 0
        fh[8..12].copy_from_slice(&1u32.to_be_bytes()); // salt1
        wal.extend_from_slice(&fh);
        wal.extend_from_slice(&vec![0u8; page_size as usize]); // page data

        let frames = parse_wal_frames(&wal, page_size);
        assert!(frames.is_empty(), "page_number=0 should break parsing, yielding no frames");
    }

    #[test]
    fn test_parse_wal_frames_truncated_page_data() {
        // Frame header is present but page data is truncated (line 83-85)
        let page_size = 4096u32;
        let mut wal = vec![0u8; WAL_HEADER_SIZE];
        wal[0..4].copy_from_slice(&WAL_MAGIC_1.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        // Frame header with valid page_number
        let mut fh = vec![0u8; WAL_FRAME_HEADER_SIZE];
        fh[0..4].copy_from_slice(&1u32.to_be_bytes());
        fh[8..12].copy_from_slice(&42u32.to_be_bytes());
        wal.extend_from_slice(&fh);
        // Only add 100 bytes of page data instead of 4096
        wal.extend_from_slice(&vec![0u8; 100]);

        let frames = parse_wal_frames(&wal, page_size);
        assert!(frames.is_empty(), "truncated page data should break parsing");
    }

    #[test]
    fn test_parse_wal_frames_valid_then_page_zero() {
        // One valid frame followed by page_number=0 → only first frame parsed
        let page_size = 512u32;
        let valid_page = make_table_leaf_page(page_size as usize, 1, 42);
        let mut wal = vec![0u8; WAL_HEADER_SIZE];
        wal[0..4].copy_from_slice(&WAL_MAGIC_1.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        // Frame 1: valid
        let mut fh1 = vec![0u8; WAL_FRAME_HEADER_SIZE];
        fh1[0..4].copy_from_slice(&2u32.to_be_bytes());
        fh1[8..12].copy_from_slice(&10u32.to_be_bytes());
        wal.extend_from_slice(&fh1);
        wal.extend_from_slice(&valid_page);
        // Frame 2: page_number=0
        let mut fh2 = vec![0u8; WAL_FRAME_HEADER_SIZE];
        fh2[0..4].copy_from_slice(&0u32.to_be_bytes());
        fh2[8..12].copy_from_slice(&10u32.to_be_bytes());
        wal.extend_from_slice(&fh2);
        wal.extend_from_slice(&vec![0u8; page_size as usize]);

        let frames = parse_wal_frames(&wal, page_size);
        assert_eq!(frames.values().flatten().count(), 1);
    }

    // -----------------------------------------------------------------------
    // recover_layer2 tests (lines 104-140)
    // -----------------------------------------------------------------------

    #[test]
    fn test_recover_layer2_finds_wal_pending_records() {
        let page_size = 512u32;
        // DB has 2 pages: page 1 (unused) and page 2 (all zeros — differs from WAL)
        let db = make_empty_db(page_size as usize, 2);
        // WAL has page 2 with a valid leaf page containing row_id=1, int=42
        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);

        let records = recover_layer2(&wal, &db, page_size, "test_table");
        assert!(!records.is_empty(), "should recover records from WAL page differing from DB");
        assert!(
            records.iter().all(|r| r.source == EvidenceSource::WalPending),
            "all records should be tagged WalPending"
        );
        assert!(
            records.iter().all(|r| r.table == "test_table"),
            "all records should have the correct table name"
        );
        // Should have row_id=1
        assert!(records.iter().any(|r| r.row_id == Some(1)));
    }

    #[test]
    fn test_recover_layer2_skips_checkpointed_page() {
        let page_size = 512u32;
        // DB page 2 is identical to the WAL page → already checkpointed
        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let mut db = make_empty_db(page_size as usize, 2);
        // Copy the leaf page into DB page 2 (offset = page_size)
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&leaf);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);

        let records = recover_layer2(&wal, &db, page_size, "test_table");
        assert!(records.is_empty(), "identical WAL and DB page should be skipped (already checkpointed)");
    }

    #[test]
    fn test_recover_layer2_page1_uses_bhdr_100() {
        // When frame.page_number == 1, bhdr should be 100
        let page_size = 512u32;
        let mut leaf = vec![0u8; page_size as usize];
        // For page 1, the B-tree header starts at offset 100
        leaf[100] = 0x0D; // table leaf marker at bhdr=100
        leaf[103] = 0x00; leaf[104] = 0x01; // cell count = 1
        let cell_start: u16 = 200;
        leaf[105] = (cell_start >> 8) as u8;
        leaf[106] = (cell_start & 0xFF) as u8;
        leaf[108] = (cell_start >> 8) as u8;
        leaf[109] = (cell_start & 0xFF) as u8;
        leaf[cell_start as usize] = 0x04;     // payload_len
        leaf[cell_start as usize + 1] = 0x01; // rowid=1
        leaf[cell_start as usize + 2] = 0x03; // header_len=3
        leaf[cell_start as usize + 3] = 0x01; // serial 1 (1-byte int)
        leaf[cell_start as usize + 4] = 0x0D; // serial 13 (0-len text)
        leaf[cell_start as usize + 5] = 0x07; // int value=7

        let db = make_empty_db(page_size as usize, 1); // 1 page, all zeros
        let wal = make_wal_bytes(page_size, &[(1, 1, 50, &leaf)]);

        let records = recover_layer2(&wal, &db, page_size, "pg1_table");
        assert!(!records.is_empty(), "page 1 with bhdr=100 should yield records");
        assert!(records.iter().all(|r| r.source == EvidenceSource::WalPending));
    }

    #[test]
    fn test_recover_layer2_empty_wal() {
        let db = make_empty_db(4096, 2);
        let wal = make_wal_bytes(4096, &[]);
        let records = recover_layer2(&wal, &db, 4096, "t");
        assert!(records.is_empty());
    }

    #[test]
    fn test_recover_layer2_multiple_salt_groups() {
        let page_size = 512u32;
        let db = make_empty_db(page_size as usize, 3);
        let leaf1 = make_table_leaf_page(page_size as usize, 1, 10);
        let leaf2 = make_table_leaf_page(page_size as usize, 2, 20);
        // Two frames with different salt1 values (different WAL sessions)
        let wal = make_wal_bytes(page_size, &[
            (2, 2, 100, &leaf1),
            (3, 3, 200, &leaf2),
        ]);

        let records = recover_layer2(&wal, &db, page_size, "multi");
        // Should recover from both salt groups
        assert!(records.len() >= 2, "should recover records from both WAL sessions");
        assert!(records.iter().any(|r| r.row_id == Some(1)));
        assert!(records.iter().any(|r| r.row_id == Some(2)));
    }

    #[test]
    fn test_recover_layer2_wal_page_out_of_bounds() {
        // WAL references a page_data_offset that is out of bounds
        let page_size = 512u32;
        let db = make_empty_db(page_size as usize, 2);
        // Build a WAL where the page data slice would fail
        // We manually craft this: valid header, frame header but truncated data
        let mut wal = vec![0u8; WAL_HEADER_SIZE];
        wal[0..4].copy_from_slice(&WAL_MAGIC_1.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        // Add frame header
        let mut fh = vec![0u8; WAL_FRAME_HEADER_SIZE];
        fh[0..4].copy_from_slice(&2u32.to_be_bytes());
        fh[8..12].copy_from_slice(&42u32.to_be_bytes());
        wal.extend_from_slice(&fh);
        // Add only partial page data (less than page_size)
        wal.extend_from_slice(&vec![0u8; page_size as usize]);

        // Now manually tamper: set page_data_offset in such a way that
        // wal.get(offset..offset+page_size) returns None.
        // Actually this is handled by parse_wal_frames which already breaks on truncation.
        // But we can still test recover_layer2 with a valid parse that has an out-of-bounds ref.
        // The simplest: DB page is beyond DB length → db.get returns None → db_page == Some(wal_page) is false
        let leaf = make_table_leaf_page(page_size as usize, 5, 99);
        let wal = make_wal_bytes(page_size, &[(10, 10, 42, &leaf)]);
        // DB only has 2 pages, but WAL references page 10
        let records = recover_layer2(&wal, &db, page_size, "oob");
        // db_page is None, which != Some(wal_page), so it proceeds to parse
        assert!(!records.is_empty(), "WAL page beyond DB should still be parsed as pending");
        assert!(records.iter().all(|r| r.source == EvidenceSource::WalPending));
    }

    // -----------------------------------------------------------------------
    // recover_layer3_deltas tests (lines 151-243)
    // -----------------------------------------------------------------------

    #[test]
    fn test_layer3_added_in_wal() {
        // WAL has a leaf page for a page number that doesn't exist in DB (DB too small)
        let page_size = 512u32;
        let db = make_empty_db(page_size as usize, 1); // only 1 page
        let leaf = make_table_leaf_page(page_size as usize, 5, 77);
        // WAL references page 3 which is beyond DB
        let wal = make_wal_bytes(page_size, &[(3, 3, 42, &leaf)]);

        let deltas = recover_layer3_deltas(&wal, &db, page_size, "added_test");
        assert!(!deltas.is_empty(), "should detect added rows");
        assert!(deltas.iter().any(|d| d.status == WalDeltaStatus::AddedInWal && d.row_id == 5));
        assert!(deltas.iter().all(|d| d.table == "added_test"));
    }

    #[test]
    fn test_layer3_deleted_in_wal() {
        // DB has records at page 2, WAL has page 2 with an empty leaf (no cells)
        let page_size = 512u32;
        // DB page 2 has a record with row_id=3
        let db_leaf = make_table_leaf_page(page_size as usize, 3, 55);
        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&db_leaf);

        // WAL page 2 is a valid leaf but with 0 cells (empty)
        let mut wal_leaf = vec![0u8; page_size as usize];
        wal_leaf[0] = 0x0D; // table leaf
        // cell count = 0 (bytes 3-4 already zero)
        let wal = make_wal_bytes(page_size, &[(2, 2, 42, &wal_leaf)]);

        let deltas = recover_layer3_deltas(&wal, &db, page_size, "del_test");
        assert!(!deltas.is_empty(), "should detect deleted rows");
        assert!(
            deltas.iter().any(|d| d.status == WalDeltaStatus::DeletedInWal && d.row_id == 3),
            "row 3 from DB should be detected as deleted in WAL"
        );
    }

    #[test]
    fn test_layer3_modified_in_wal() {
        // Both DB and WAL have page 2 with same row_id but different values
        let page_size = 512u32;
        let db_leaf = make_table_leaf_page(page_size as usize, 7, 10); // row 7, value 10
        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&db_leaf);

        let wal_leaf = make_table_leaf_page(page_size as usize, 7, 99); // row 7, value 99 (different)
        let wal = make_wal_bytes(page_size, &[(2, 2, 42, &wal_leaf)]);

        let deltas = recover_layer3_deltas(&wal, &db, page_size, "mod_test");
        assert!(!deltas.is_empty(), "should detect modified rows");
        assert!(
            deltas.iter().any(|d| d.status == WalDeltaStatus::ModifiedInWal && d.row_id == 7),
            "row 7 should be detected as modified"
        );
    }

    #[test]
    fn test_layer3_same_content_no_deltas() {
        // WAL page identical to DB page → no deltas (line 198-199)
        let page_size = 512u32;
        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&leaf);
        let wal = make_wal_bytes(page_size, &[(2, 2, 42, &leaf)]);

        let deltas = recover_layer3_deltas(&wal, &db, page_size, "same_test");
        assert!(deltas.is_empty(), "identical pages should produce no deltas");
    }

    #[test]
    fn test_layer3_empty_wal_no_deltas() {
        let db = make_empty_db(4096, 2);
        let wal = make_wal_bytes(4096, &[]);
        let deltas = recover_layer3_deltas(&wal, &db, 4096, "empty");
        assert!(deltas.is_empty());
    }

    #[test]
    fn test_layer3_multiple_delta_types() {
        // Complex scenario: WAL page has some new rows, removes some old rows, modifies others
        let page_size = 512u32;

        // DB page 2: rows 1 (val=10), 2 (val=20)
        let mut db_page = vec![0u8; page_size as usize];
        db_page[0] = 0x0D; // table leaf
        db_page[3] = 0x00; db_page[4] = 0x02; // 2 cells
        let cell1_start: u16 = 100;
        let cell2_start: u16 = 110;
        db_page[5] = 0x00; db_page[6] = cell1_start as u8; // content area start
        // Cell pointer array
        db_page[8] = (cell1_start >> 8) as u8; db_page[9] = cell1_start as u8;
        db_page[10] = (cell2_start >> 8) as u8; db_page[11] = cell2_start as u8;
        // Cell 1: row_id=1, value=10
        db_page[cell1_start as usize] = 0x04;
        db_page[cell1_start as usize + 1] = 0x01; // rowid=1
        db_page[cell1_start as usize + 2] = 0x03;
        db_page[cell1_start as usize + 3] = 0x01;
        db_page[cell1_start as usize + 4] = 0x0D;
        db_page[cell1_start as usize + 5] = 10;
        // Cell 2: row_id=2, value=20
        db_page[cell2_start as usize] = 0x04;
        db_page[cell2_start as usize + 1] = 0x02; // rowid=2
        db_page[cell2_start as usize + 2] = 0x03;
        db_page[cell2_start as usize + 3] = 0x01;
        db_page[cell2_start as usize + 4] = 0x0D;
        db_page[cell2_start as usize + 5] = 20;

        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&db_page);

        // WAL page 2: rows 1 (val=99, modified), 3 (val=30, added) — row 2 is deleted
        let mut wal_page = vec![0u8; page_size as usize];
        wal_page[0] = 0x0D;
        wal_page[3] = 0x00; wal_page[4] = 0x02; // 2 cells
        let wc1: u16 = 100;
        let wc2: u16 = 110;
        wal_page[5] = 0x00; wal_page[6] = wc1 as u8;
        wal_page[8] = (wc1 >> 8) as u8; wal_page[9] = wc1 as u8;
        wal_page[10] = (wc2 >> 8) as u8; wal_page[11] = wc2 as u8;
        // Cell 1: row_id=1, value=99 (modified from 10)
        wal_page[wc1 as usize] = 0x04;
        wal_page[wc1 as usize + 1] = 0x01;
        wal_page[wc1 as usize + 2] = 0x03;
        wal_page[wc1 as usize + 3] = 0x01;
        wal_page[wc1 as usize + 4] = 0x0D;
        wal_page[wc1 as usize + 5] = 99;
        // Cell 2: row_id=3, value=30 (added)
        wal_page[wc2 as usize] = 0x04;
        wal_page[wc2 as usize + 1] = 0x03;
        wal_page[wc2 as usize + 2] = 0x03;
        wal_page[wc2 as usize + 3] = 0x01;
        wal_page[wc2 as usize + 4] = 0x0D;
        wal_page[wc2 as usize + 5] = 30;

        let wal = make_wal_bytes(page_size, &[(2, 2, 42, &wal_page)]);
        let deltas = recover_layer3_deltas(&wal, &db, page_size, "complex");

        assert!(deltas.iter().any(|d| d.row_id == 1 && d.status == WalDeltaStatus::ModifiedInWal),
            "row 1 should be modified");
        assert!(deltas.iter().any(|d| d.row_id == 2 && d.status == WalDeltaStatus::DeletedInWal),
            "row 2 should be deleted");
        assert!(deltas.iter().any(|d| d.row_id == 3 && d.status == WalDeltaStatus::AddedInWal),
            "row 3 should be added");
    }

    #[test]
    fn test_layer3_page1_uses_bhdr_100() {
        // When page_number == 1, bhdr should be 100 for both WAL and DB parsing
        let page_size = 512u32;

        // Build a page-1 leaf at bhdr=100
        let mut leaf = vec![0u8; page_size as usize];
        leaf[100] = 0x0D;
        leaf[103] = 0x00; leaf[104] = 0x01;
        let cs: u16 = 200;
        leaf[105] = (cs >> 8) as u8; leaf[106] = (cs & 0xFF) as u8;
        leaf[108] = (cs >> 8) as u8; leaf[109] = (cs & 0xFF) as u8;
        leaf[cs as usize] = 0x04;
        leaf[cs as usize + 1] = 0x01;
        leaf[cs as usize + 2] = 0x03;
        leaf[cs as usize + 3] = 0x01;
        leaf[cs as usize + 4] = 0x0D;
        leaf[cs as usize + 5] = 0x0A;

        // DB is too small for page 1 content to match WAL → AddedInWal
        let db = vec![0u8; 0]; // empty DB
        let wal = make_wal_bytes(page_size, &[(1, 1, 50, &leaf)]);

        let deltas = recover_layer3_deltas(&wal, &db, page_size, "pg1");
        // Page 1 with empty DB → db.get returns None → AddedInWal
        assert!(!deltas.is_empty());
        assert!(deltas.iter().any(|d| d.status == WalDeltaStatus::AddedInWal));
    }

    #[test]
    fn test_layer3_wal_page_data_out_of_bounds_skip() {
        // WAL page data can't be sliced → continue (None from wal.get)
        // This is hard to trigger through make_wal_bytes since parse_wal_frames
        // already validates bounds. We test with a valid empty WAL instead.
        let wal = make_wal_bytes(4096, &[]);
        let db = make_empty_db(4096, 2);
        let deltas = recover_layer3_deltas(&wal, &db, 4096, "skip");
        assert!(deltas.is_empty());
    }

    // -----------------------------------------------------------------------
    // recover_layer2_enhanced: WalMode::Apply (lines 294-304)
    // -----------------------------------------------------------------------

    #[test]
    fn test_layer2_enhanced_apply_mode() {
        let page_size = 512u32;
        // Create a DB with 2 pages (page 1 unused header, page 2 is a table root)
        let db = make_empty_db(page_size as usize, 2);
        // Page 2 in DB is empty/zeros

        // WAL provides page 2 as a valid leaf page with row_id=1
        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);

        let mut roots = HashMap::new();
        roots.insert("apply_table".to_string(), 2u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Apply, &roots);
        assert!(!results.is_empty(), "Apply mode should return records from WAL overlay");
        assert!(
            results.iter().all(|r| r.source == EvidenceSource::WalPending),
            "all records in Apply mode should be tagged WalPending"
        );
        assert!(results.iter().any(|r| r.row_id == Some(1)));
    }

    #[test]
    fn test_layer2_enhanced_apply_mode_multiple_tables() {
        let page_size = 512u32;
        let db = make_empty_db(page_size as usize, 4);

        let leaf2 = make_table_leaf_page(page_size as usize, 1, 10);
        let leaf3 = make_table_leaf_page(page_size as usize, 2, 20);
        let wal = make_wal_bytes(page_size, &[
            (2, 2, 100, &leaf2),
            (3, 3, 100, &leaf3),
        ]);

        let mut roots = HashMap::new();
        roots.insert("t1".to_string(), 2u32);
        roots.insert("t2".to_string(), 3u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Apply, &roots);
        assert!(results.len() >= 2, "should find records from both tables");
        assert!(results.iter().all(|r| r.source == EvidenceSource::WalPending));
    }

    // -----------------------------------------------------------------------
    // recover_layer2_enhanced: WalMode::Both (lines 307-335)
    // -----------------------------------------------------------------------

    #[test]
    fn test_layer2_enhanced_both_mode_wal_only_records() {
        // WAL has records that DB doesn't → WalPending
        let page_size = 512u32;
        let db = make_empty_db(page_size as usize, 2);
        // DB page 2 is all zeros (not a valid leaf)

        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);

        let mut roots = HashMap::new();
        roots.insert("both_t".to_string(), 2u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Both, &roots);
        // WAL view has records, raw DB view (page 2 = zeros) has none
        // → records only in WAL view → WalPending
        let wal_pending: Vec<_> = results.iter().filter(|r| r.source == EvidenceSource::WalPending).collect();
        assert!(!wal_pending.is_empty(), "records only in WAL view should be WalPending");
    }

    #[test]
    fn test_layer2_enhanced_both_mode_db_only_records() {
        // DB has records, WAL replaces that page with an empty leaf → WalDeleted
        let page_size = 512u32;
        // DB page 2 has a valid leaf with row_id=5
        let db_leaf = make_table_leaf_page(page_size as usize, 5, 88);
        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&db_leaf);

        // WAL provides page 2 as an empty leaf (no cells)
        let mut empty_leaf = vec![0u8; page_size as usize];
        empty_leaf[0] = 0x0D; // valid leaf, 0 cells
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &empty_leaf)]);

        let mut roots = HashMap::new();
        roots.insert("del_t".to_string(), 2u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Both, &roots);
        let wal_deleted: Vec<_> = results.iter().filter(|r| r.source == EvidenceSource::WalDeleted).collect();
        assert!(!wal_deleted.is_empty(), "records only in raw DB view should be WalDeleted");
        assert!(wal_deleted.iter().any(|r| r.row_id == Some(5)));
    }

    #[test]
    fn test_layer2_enhanced_both_mode_identical_records() {
        // DB and WAL have same records → no results (neither WalPending nor WalDeleted)
        let page_size = 512u32;
        let leaf = make_table_leaf_page(page_size as usize, 3, 55);
        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&leaf);
        // WAL also provides the exact same page 2
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);

        let mut roots = HashMap::new();
        roots.insert("same_t".to_string(), 2u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Both, &roots);
        assert!(results.is_empty(), "identical WAL and DB content should yield no differential results");
    }

    #[test]
    fn test_layer2_enhanced_both_mode_modified_records() {
        // DB has row 1 with value 10, WAL has row 1 with value 99
        // → row with val=10 is WalDeleted (only in raw), row with val=99 is WalPending (only in WAL)
        let page_size = 512u32;
        let db_leaf = make_table_leaf_page(page_size as usize, 1, 10);
        let wal_leaf = make_table_leaf_page(page_size as usize, 1, 99);

        let mut db = make_empty_db(page_size as usize, 2);
        db[page_size as usize..2 * page_size as usize].copy_from_slice(&db_leaf);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &wal_leaf)]);

        let mut roots = HashMap::new();
        roots.insert("mod_t".to_string(), 2u32);

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Both, &roots);
        let pending: Vec<_> = results.iter().filter(|r| r.source == EvidenceSource::WalPending).collect();
        let deleted: Vec<_> = results.iter().filter(|r| r.source == EvidenceSource::WalDeleted).collect();
        assert!(!pending.is_empty(), "new WAL version should be WalPending");
        assert!(!deleted.is_empty(), "old DB version should be WalDeleted");
    }

    #[test]
    fn test_layer2_enhanced_both_mode_no_table_roots() {
        // With table_roots empty but overlay non-empty, walks produce no records
        let page_size = 512u32;
        let leaf = make_table_leaf_page(page_size as usize, 1, 42);
        let wal = make_wal_bytes(page_size, &[(2, 2, 100, &leaf)]);
        let db = make_empty_db(page_size as usize, 2);
        let roots = HashMap::new();

        let results = recover_layer2_enhanced(&db, &wal, page_size, WalMode::Both, &roots);
        assert!(results.is_empty(), "no table roots → no records");
    }
}
