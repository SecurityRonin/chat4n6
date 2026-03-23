//! WAL frame classification and WAL-only table detection.
//!
//! Provides two forensic capabilities:
//! 1. Classify each WAL frame as Committed, Uncommitted, or Superseded.
//! 2. Detect tables that appear in the WAL's sqlite_master but not in the
//!    main database (i.e., created inside an uncommitted or in-flight transaction).

use crate::btree::parse_table_leaf_page;
use crate::context::RecoveryContext;
use crate::record::SqlValue;
use crate::wal::{is_wal_header, WAL_FRAME_HEADER_SIZE, WAL_HEADER_SIZE};
use std::collections::HashMap;

// ── Frame classification ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum WalFrameStatus {
    /// Frame belongs to a committed transaction.
    Committed { transaction_id: u32 },
    /// Frame was written but no commit frame follows — the transaction is incomplete.
    Uncommitted,
    /// An earlier version of this page that was overwritten by a later frame.
    Superseded { superseded_by_frame: u32 },
}

#[derive(Debug, Clone)]
pub struct ClassifiedFrame {
    pub frame_index: u32,
    pub page_number: u32,
    pub status: WalFrameStatus,
    /// Byte offset in the WAL slice where the page data starts.
    pub page_data_offset: usize,
}

/// Classify every WAL frame as Committed, Uncommitted, or Superseded.
///
/// Algorithm:
/// 1. Parse frames sequentially from the WAL.
/// 2. A frame with `db_size_after_commit > 0` is a *commit frame*; all frames
///    since the previous commit (inclusive) form one committed transaction.
/// 3. Frames after the last commit frame are Uncommitted.
/// 4. Where the same page number appears in multiple frames, all earlier
///    occurrences are marked Superseded by the latest one.
pub fn classify_wal_frames(wal: &[u8], page_size: u32) -> Vec<ClassifiedFrame> {
    if wal.len() < WAL_HEADER_SIZE || !is_wal_header(wal) {
        return Vec::new();
    }

    let frame_size = WAL_FRAME_HEADER_SIZE + page_size as usize;
    let mut raw: Vec<(u32, u32, bool, usize)> = Vec::new(); // (frame_idx, page_num, is_commit, page_data_off)

    let mut idx = 0usize;
    loop {
        let frame_off = WAL_HEADER_SIZE + idx * frame_size;
        if frame_off + WAL_FRAME_HEADER_SIZE > wal.len() {
            break;
        }
        let fh = &wal[frame_off..frame_off + WAL_FRAME_HEADER_SIZE];
        let page_number = u32::from_be_bytes([fh[0], fh[1], fh[2], fh[3]]);
        let db_size = u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]);

        if page_number == 0 {
            break;
        }

        let page_data_end = frame_off + frame_size;
        if page_data_end > wal.len() {
            break;
        }

        let page_data_offset = frame_off + WAL_FRAME_HEADER_SIZE;
        raw.push((idx as u32, page_number, db_size > 0, page_data_offset));
        idx += 1;
    }

    if raw.is_empty() {
        return Vec::new();
    }

    // Pass 1: assign transaction IDs.
    // Frames between commits (exclusive prev commit, inclusive this commit) share a txn_id.
    // Frames after the last commit are Uncommitted.
    let mut transaction_id: u32 = 0;
    let total = raw.len();

    // Find the last commit frame index to know which frames are uncommitted.
    let last_commit_pos: Option<usize> = raw
        .iter()
        .enumerate()
        .filter(|(_, (_, _, is_commit, _))| *is_commit)
        .map(|(i, _)| i)
        .last();

    // txn_id_for[i] = Some(txn_id) if committed, None if uncommitted
    let mut txn_id_for: Vec<Option<u32>> = vec![None; total];
    {
        let mut current_txn = 1u32;
        for i in 0..total {
            let (_, _, is_commit, _) = raw[i];
            let committed_up_to = last_commit_pos.map_or(false, |lcp| i <= lcp);
            if committed_up_to {
                txn_id_for[i] = Some(current_txn);
                if is_commit {
                    transaction_id = current_txn;
                    current_txn += 1;
                }
            }
            // else remains None (Uncommitted)
        }
    }
    let _ = transaction_id; // used above

    // Pass 2: detect superseded frames.
    // For each page number, track the *latest* frame position that references it.
    // All earlier frames for the same page become Superseded.
    let mut latest_frame_for_page: HashMap<u32, u32> = HashMap::new();
    for (frame_idx, page_number, _, _) in raw.iter().rev() {
        latest_frame_for_page
            .entry(*page_number)
            .or_insert(*frame_idx);
    }

    // Build result
    let mut frames: Vec<ClassifiedFrame> = Vec::with_capacity(total);
    for (i, (frame_idx, page_number, _, page_data_offset)) in raw.iter().enumerate() {
        let latest = *latest_frame_for_page.get(page_number).unwrap();
        let status = if *frame_idx < latest {
            WalFrameStatus::Superseded {
                superseded_by_frame: latest,
            }
        } else {
            match txn_id_for[i] {
                Some(tid) => WalFrameStatus::Committed {
                    transaction_id: tid,
                },
                None => WalFrameStatus::Uncommitted,
            }
        };

        frames.push(ClassifiedFrame {
            frame_index: *frame_idx,
            page_number: *page_number,
            status,
            page_data_offset: *page_data_offset,
        });
    }

    frames
}

// ── WAL-only table detection ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WalOnlyTable {
    pub name: String,
    pub create_sql: String,
    pub root_page: u32,
    pub frame_status: WalFrameStatus,
}

/// Detect tables that exist in the WAL's sqlite_master (page 1) but are absent
/// from the main database's known table roots.
///
/// Steps:
/// 1. Classify all WAL frames.
/// 2. For every frame containing page 1 (sqlite_master), parse it as a B-tree
///    leaf using the same parser as the rest of the codebase.
/// 3. Extract table rows: sqlite_master columns are
///    (type, name, tbl_name, rootpage, sql) — indices 0..4.
/// 4. Any table whose name is absent from `ctx.table_roots` is WAL-only.
pub fn detect_wal_only_tables(ctx: &RecoveryContext<'_>, wal: &[u8]) -> Vec<WalOnlyTable> {
    if wal.len() < WAL_HEADER_SIZE || !is_wal_header(wal) {
        return Vec::new();
    }

    let page_size = ctx.page_size;
    let frames = classify_wal_frames(wal, page_size);

    if frames.is_empty() {
        return Vec::new();
    }

    let mut result: Vec<WalOnlyTable> = Vec::new();

    for frame in &frames {
        if frame.page_number != 1 {
            continue;
        }

        let page_data_end = frame.page_data_offset + page_size as usize;
        if page_data_end > wal.len() {
            continue;
        }

        let page_data = &wal[frame.page_data_offset..page_data_end];

        // Page 1 in SQLite has the file header in the first 100 bytes;
        // the B-tree header starts at offset 100.
        // parse_table_leaf_page expects:
        //   db (for overflow resolution — empty here is fine for schema pages),
        //   page_data, bhdr, page_number, page_size, table name.
        let bhdr = 100usize;
        let records =
            parse_table_leaf_page(&[], page_data, bhdr, 1, page_size, "sqlite_master");

        for record in &records {
            // sqlite_master row: (type, name, tbl_name, rootpage, sql)
            // indices:             0      1     2         3         4
            let obj_type = match record.values.get(0) {
                Some(SqlValue::Text(s)) => s.as_str(),
                _ => continue,
            };
            if obj_type != "table" {
                continue;
            }

            let name = match record.values.get(1) {
                Some(SqlValue::Text(s)) => s.clone(),
                _ => continue,
            };

            let root_page = match record.values.get(3) {
                Some(SqlValue::Int(n)) => *n as u32,
                _ => 0,
            };

            let create_sql = match record.values.get(4) {
                Some(SqlValue::Text(s)) => s.clone(),
                _ => String::new(),
            };

            // Only report tables not present in the main DB.
            if ctx.table_roots.contains_key(&name) {
                continue;
            }

            // Avoid duplicates — keep only the entry from the latest frame for this page.
            if result.iter().any(|t| t.name == name) {
                continue;
            }

            result.push(WalOnlyTable {
                name,
                create_sql,
                root_page,
                frame_status: frame.status.clone(),
            });
        }
    }

    result
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wal_header(page_size: u32, salt1: u32, salt2: u32) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[0..4].copy_from_slice(&0x377F0682u32.to_be_bytes());
        h[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        h[8..12].copy_from_slice(&page_size.to_be_bytes());
        h[16..20].copy_from_slice(&salt1.to_be_bytes());
        h[20..24].copy_from_slice(&salt2.to_be_bytes());
        h
    }

    fn make_frame_header(page_num: u32, db_size: u32, salt1: u32, salt2: u32) -> Vec<u8> {
        let mut h = vec![0u8; 24];
        h[0..4].copy_from_slice(&page_num.to_be_bytes());
        h[4..8].copy_from_slice(&db_size.to_be_bytes());
        h[8..12].copy_from_slice(&salt1.to_be_bytes());
        h[12..16].copy_from_slice(&salt2.to_be_bytes());
        h
    }

    #[test]
    fn test_empty_wal() {
        let frames = classify_wal_frames(&[], 4096);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_wal_header_only() {
        let wal = make_wal_header(4096, 1, 2);
        let frames = classify_wal_frames(&wal, 4096);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_single_committed_frame() {
        let mut wal = make_wal_header(512, 1, 2);
        // Add one frame: page 2, db_size=2 (commit frame)
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 512]); // page data
        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 1);
        assert!(
            matches!(frames[0].status, WalFrameStatus::Committed { .. }),
            "expected Committed, got {:?}",
            frames[0].status
        );
    }

    #[test]
    fn test_uncommitted_frames() {
        let mut wal = make_wal_header(512, 1, 2);
        // Frame 0: page 2, db_size=0 (not a commit frame) → Uncommitted
        wal.extend(make_frame_header(2, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].status, WalFrameStatus::Uncommitted);
    }

    #[test]
    fn test_superseded_frames() {
        let mut wal = make_wal_header(512, 1, 2);
        // Frame 0: page 2, db_size=0
        wal.extend(make_frame_header(2, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        // Frame 1: page 2 again, db_size=2 (commit)
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 512]);
        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 2);
        // Frame 0 should be superseded by frame 1
        assert!(
            matches!(
                frames[0].status,
                WalFrameStatus::Superseded {
                    superseded_by_frame: 1
                }
            ),
            "expected Superseded{{1}}, got {:?}",
            frames[0].status
        );
        assert!(
            matches!(frames[1].status, WalFrameStatus::Committed { .. }),
            "expected Committed, got {:?}",
            frames[1].status
        );
    }

    #[test]
    fn test_multiple_transactions() {
        // Two committed transactions: txn1 = frames 0-1, txn2 = frames 2-3
        let mut wal = make_wal_header(512, 1, 2);
        // txn 1
        wal.extend(make_frame_header(2, 0, 1, 2)); // non-commit
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(3, 3, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);
        // txn 2
        wal.extend(make_frame_header(4, 0, 1, 2)); // non-commit
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(5, 5, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 4);

        // Frames 0-1 are txn 1
        let tid0 = match frames[0].status {
            WalFrameStatus::Committed { transaction_id } => transaction_id,
            ref s => panic!("frame 0 expected Committed, got {:?}", s),
        };
        let tid1 = match frames[1].status {
            WalFrameStatus::Committed { transaction_id } => transaction_id,
            ref s => panic!("frame 1 expected Committed, got {:?}", s),
        };
        assert_eq!(tid0, tid1, "frames 0 and 1 should share a transaction_id");

        // Frames 2-3 are txn 2
        let tid2 = match frames[2].status {
            WalFrameStatus::Committed { transaction_id } => transaction_id,
            ref s => panic!("frame 2 expected Committed, got {:?}", s),
        };
        let tid3 = match frames[3].status {
            WalFrameStatus::Committed { transaction_id } => transaction_id,
            ref s => panic!("frame 3 expected Committed, got {:?}", s),
        };
        assert_eq!(tid2, tid3, "frames 2 and 3 should share a transaction_id");
        assert_ne!(tid0, tid2, "txn 1 and txn 2 should have different IDs");
    }

    #[test]
    fn test_page_data_offset() {
        // Verify page_data_offset points past the frame header inside the WAL bytes.
        let page_size: u32 = 512;
        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0xABu8; 512]);
        let frames = classify_wal_frames(&wal, page_size);
        assert_eq!(frames.len(), 1);
        // offset = WAL_HEADER_SIZE(32) + WAL_FRAME_HEADER_SIZE(24) = 56
        assert_eq!(frames[0].page_data_offset, 56);
        assert_eq!(wal[frames[0].page_data_offset], 0xAB);
    }

    #[test]
    fn test_detect_wal_only_tables_no_wal() {
        use crate::context::RecoveryContext;
        use crate::header::DbHeader;
        use crate::pragma::parse_pragma_info;
        use std::collections::HashMap;

        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let header = DbHeader::parse(&db).expect("valid header");
        let pragma_info = parse_pragma_info(&header, &db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Empty WAL → no tables
        let tables = detect_wal_only_tables(&ctx, &[]);
        assert!(tables.is_empty());
    }
}
