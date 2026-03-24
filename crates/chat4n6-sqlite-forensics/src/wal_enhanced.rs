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

    // ── New coverage tests ──────────────────────────────────────────────────

    /// Helper: build a minimal RecoveryContext from a real SQLite DB.
    fn make_ctx_from_db(db: &[u8]) -> (crate::header::DbHeader, crate::pragma::PragmaInfo) {
        use crate::header::DbHeader;
        use crate::pragma::parse_pragma_info;
        let header = DbHeader::parse(db).expect("valid db header");
        let pragma_info = parse_pragma_info(&header, db);
        (header, pragma_info)
    }

    /// Encode a value as a SQLite varint (1-9 bytes).
    fn encode_varint(val: u64) -> Vec<u8> {
        if val <= 0x7f {
            return vec![val as u8];
        }
        let mut bytes = Vec::new();
        let mut v = val;
        let mut tmp = Vec::new();
        for i in 0..9 {
            if i == 8 {
                tmp.push((v & 0xFF) as u8);
                break;
            }
            tmp.push((v & 0x7F) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        tmp.reverse();
        for (i, b) in tmp.iter().enumerate() {
            if i < tmp.len() - 1 {
                bytes.push(b | 0x80);
            } else {
                bytes.push(*b);
            }
        }
        bytes
    }

    /// Build a sqlite_master cell payload for a "table" row.
    /// Columns: (type="table", name, tbl_name=name, rootpage, sql)
    fn make_sqlite_master_cell(row_id: u64, name: &str, rootpage: u32, sql: &str) -> Vec<u8> {
        let type_str = b"table";
        let name_bytes = name.as_bytes();
        let sql_bytes = sql.as_bytes();

        // Serial types: text of len N = 2*N + 13, int (1-byte) = 1
        let st_type = 2 * type_str.len() as u64 + 13;
        let st_name = 2 * name_bytes.len() as u64 + 13;
        let st_tbl_name = 2 * name_bytes.len() as u64 + 13;
        let st_rootpage: u64 = 1; // 1-byte int
        let st_sql = 2 * sql_bytes.len() as u64 + 13;

        // Record header: [header_len varint][serial types...]
        let mut serial_type_bytes = Vec::new();
        serial_type_bytes.extend(encode_varint(st_type));
        serial_type_bytes.extend(encode_varint(st_name));
        serial_type_bytes.extend(encode_varint(st_tbl_name));
        serial_type_bytes.extend(encode_varint(st_rootpage));
        serial_type_bytes.extend(encode_varint(st_sql));

        // header_len includes the header_len varint itself
        let header_len = 1 + serial_type_bytes.len(); // 1 byte for header_len varint (if < 128)
        let mut record = Vec::new();
        record.extend(encode_varint(header_len as u64));
        record.extend(&serial_type_bytes);

        // Data: type, name, tbl_name, rootpage (1 byte), sql
        record.extend(type_str);
        record.extend(name_bytes);
        record.extend(name_bytes); // tbl_name = name
        record.push(rootpage as u8); // 1-byte int
        record.extend(sql_bytes);

        // Cell format: [payload_len varint][row_id varint][record]
        let mut cell = Vec::new();
        cell.extend(encode_varint(record.len() as u64));
        cell.extend(encode_varint(row_id));
        cell.extend(&record);

        cell
    }

    /// Build a synthetic page 1 (4096 bytes) with a valid B-tree leaf containing
    /// sqlite_master rows. The first 100 bytes are the SQLite file header area
    /// (in WAL frames this is the DB header copy), and the B-tree header starts
    /// at offset 100.
    fn make_page1_with_tables(
        page_size: u32,
        tables: &[(&str, u32, &str)], // (name, rootpage, create_sql)
    ) -> Vec<u8> {
        let mut page = vec![0u8; page_size as usize];

        // Build all cells and place them at the end of the page
        let mut cells: Vec<Vec<u8>> = Vec::new();
        for (i, (name, rootpage, sql)) in tables.iter().enumerate() {
            cells.push(make_sqlite_master_cell((i + 1) as u64, name, *rootpage, sql));
        }

        // Place cells from the end of the page backwards
        let mut cell_offsets: Vec<u16> = Vec::new();
        let mut write_pos = page_size as usize;
        for cell in &cells {
            write_pos -= cell.len();
            page[write_pos..write_pos + cell.len()].copy_from_slice(cell);
            cell_offsets.push(write_pos as u16);
        }

        // B-tree header at offset 100 (for page 1)
        let bhdr = 100usize;
        page[bhdr] = 0x0D; // table leaf page
        // freeblock offset = 0 (no freeblocks)
        page[bhdr + 1] = 0;
        page[bhdr + 2] = 0;
        // cell count
        let cell_count = cells.len() as u16;
        page[bhdr + 3] = (cell_count >> 8) as u8;
        page[bhdr + 4] = (cell_count & 0xFF) as u8;
        // cell content area offset
        page[bhdr + 5] = (write_pos >> 8) as u8;
        page[bhdr + 6] = (write_pos & 0xFF) as u8;
        // fragmented free bytes
        page[bhdr + 7] = 0;

        // Cell pointer array at bhdr + 8
        let ptr_start = bhdr + 8;
        for (i, off) in cell_offsets.iter().enumerate() {
            let pos = ptr_start + i * 2;
            page[pos] = (*off >> 8) as u8;
            page[pos + 1] = (*off & 0xFF) as u8;
        }

        page
    }

    #[test]
    fn test_classify_frames_zero_page_number_break() {
        // A frame with page_number == 0 should cause the parser to stop (line 63).
        let mut wal = make_wal_header(512, 1, 2);
        // Frame with page_number=0 → should break
        wal.extend(make_frame_header(0, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        let frames = classify_wal_frames(&wal, 512);
        assert!(frames.is_empty(), "zero page_number should stop parsing");
    }

    #[test]
    fn test_classify_frames_truncated_frame_data() {
        // Frame header present but page data is truncated (line 67-68).
        let mut wal = make_wal_header(512, 1, 2);
        // Valid frame header but only 100 bytes of page data instead of 512
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 100]); // < page_size
        let frames = classify_wal_frames(&wal, 512);
        assert!(frames.is_empty(), "truncated frame data should be skipped");
    }

    #[test]
    fn test_classify_frames_mixed_committed_and_uncommitted() {
        // Transaction 1 committed, then some uncommitted frames follow.
        let mut wal = make_wal_header(512, 1, 2);
        // Committed txn: frame 0 (page 2, commit)
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 512]);
        // Uncommitted frame: frame 1 (page 3, no commit)
        wal.extend(make_frame_header(3, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        // Uncommitted frame: frame 2 (page 4, no commit)
        wal.extend(make_frame_header(4, 0, 1, 2));
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 3);

        // Frame 0: committed
        assert!(
            matches!(frames[0].status, WalFrameStatus::Committed { transaction_id: 1 }),
            "frame 0 should be committed txn 1, got {:?}",
            frames[0].status
        );
        // Frames 1,2: uncommitted
        assert_eq!(frames[1].status, WalFrameStatus::Uncommitted);
        assert_eq!(frames[2].status, WalFrameStatus::Uncommitted);
    }

    #[test]
    fn test_classify_frames_superseded_across_transactions() {
        // Page 2 written in txn 1, then overwritten in txn 2 → first becomes superseded.
        let mut wal = make_wal_header(512, 1, 2);
        // txn 1: page 2 commit
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 512]);
        // txn 2: page 2 again + commit
        wal.extend(make_frame_header(2, 2, 1, 2));
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 2);
        // Frame 0 superseded by frame 1
        assert!(
            matches!(
                frames[0].status,
                WalFrameStatus::Superseded { superseded_by_frame: 1 }
            ),
            "expected Superseded by 1, got {:?}",
            frames[0].status
        );
        // Frame 1 committed
        assert!(matches!(
            frames[1].status,
            WalFrameStatus::Committed { transaction_id: 2 }
        ));
    }

    #[test]
    fn test_classify_frames_superseded_uncommitted() {
        // Two uncommitted frames for the same page → first superseded.
        let mut wal = make_wal_header(512, 1, 2);
        // No commit frames at all
        wal.extend(make_frame_header(5, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(5, 0, 1, 2));
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 2);
        assert!(matches!(
            frames[0].status,
            WalFrameStatus::Superseded { superseded_by_frame: 1 }
        ));
        assert_eq!(frames[1].status, WalFrameStatus::Uncommitted);
    }

    #[test]
    fn test_classify_frames_many_pages_no_supersede() {
        // Multiple distinct pages, all committed — none superseded.
        let mut wal = make_wal_header(512, 1, 2);
        wal.extend(make_frame_header(2, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(3, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(4, 4, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 3);
        // All committed, none superseded
        for f in &frames {
            assert!(
                matches!(f.status, WalFrameStatus::Committed { .. }),
                "expected Committed, got {:?}",
                f.status
            );
        }
    }

    #[test]
    fn test_detect_wal_only_tables_invalid_wal_header() {
        // WAL bytes present but not a valid WAL header → early return (line 172-173).
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Invalid WAL (not starting with magic)
        let bad_wal = vec![0u8; 100];
        let tables = detect_wal_only_tables(&ctx, &bad_wal);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_detect_wal_only_tables_wal_header_only_no_frames() {
        // Valid WAL header but no frames → frames empty → early return (line 179-180).
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let wal = make_wal_header(4096, 1, 2);
        let tables = detect_wal_only_tables(&ctx, &wal);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_detect_wal_only_tables_non_page1_frames() {
        // WAL contains frames but none for page 1 → no sqlite_master pages to scan.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x10;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Frame for page 5 (not page 1)
        let mut wal = make_wal_header(4096, 1, 2);
        wal.extend(make_frame_header(5, 5, 1, 2));
        wal.extend(vec![0u8; 4096]);

        let tables = detect_wal_only_tables(&ctx, &wal);
        assert!(tables.is_empty());
    }

    #[test]
    fn test_detect_wal_only_tables_page1_frame_with_empty_page() {
        // WAL has a page 1 frame, but the page data doesn't contain valid
        // B-tree records → parse_table_leaf_page returns empty.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Create WAL with page 1 frame containing zeros (invalid B-tree data)
        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(vec![0u8; page_size as usize]);

        let tables = detect_wal_only_tables(&ctx, &wal);
        assert!(tables.is_empty(), "empty page data should yield no tables");
    }

    #[test]
    fn test_detect_wal_only_tables_with_synthetic_page1() {
        // Build a synthetic WAL with a page-1 frame containing valid
        // sqlite_master rows. This exercises lines 206-247 fully.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);

        // table_roots has "known_tbl" but not "wal_tbl"
        let mut table_roots = HashMap::new();
        table_roots.insert("known_tbl".to_string(), 3);

        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots,
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Build page 1 with two table rows:
        // 1. "wal_tbl" (rootpage=5) — NOT in table_roots → WAL-only
        // 2. "known_tbl" (rootpage=3) — IS in table_roots → filtered out
        let page1 = make_page1_with_tables(page_size, &[
            ("wal_tbl", 5, "CREATE TABLE wal_tbl (id INTEGER)"),
            ("known_tbl", 3, "CREATE TABLE known_tbl (x TEXT)"),
        ]);

        // Build WAL: header + page-1 commit frame
        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2)); // page 1, commit
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        let names: Vec<&str> = wal_only.iter().map(|t| t.name.as_str()).collect();

        // "wal_tbl" should be detected as WAL-only
        assert!(
            names.contains(&"wal_tbl"),
            "expected wal_tbl in WAL-only tables, got: {:?}",
            names
        );
        // "known_tbl" should be filtered out (line 233-234)
        assert!(
            !names.contains(&"known_tbl"),
            "known_tbl should be filtered out, got: {:?}",
            names
        );

        // Verify fields on the WAL-only table
        let wt = wal_only.iter().find(|t| t.name == "wal_tbl").unwrap();
        assert_eq!(wt.root_page, 5);
        assert!(wt.create_sql.contains("wal_tbl"));
    }

    #[test]
    fn test_detect_wal_only_tables_duplicate_name_dedup() {
        // Two page-1 frames in WAL, both containing "dup_tbl".
        // The duplicate-name guard (line 238-239) should prevent duplicates.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let page1 = make_page1_with_tables(page_size, &[
            ("dup_tbl", 2, "CREATE TABLE dup_tbl (a INT)"),
        ]);

        // Two page-1 frames, both committed
        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2)); // frame 0: page 1 commit
        wal.extend(&page1);
        wal.extend(make_frame_header(1, 1, 1, 2)); // frame 1: page 1 commit (supersedes frame 0)
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        let dup_count = wal_only.iter().filter(|t| t.name == "dup_tbl").count();
        assert_eq!(dup_count, 1, "dup_tbl should appear exactly once, got {}", dup_count);
    }

    #[test]
    fn test_detect_wal_only_tables_page_data_truncated() {
        // Frame claims page 1 but page_data_end exceeds WAL length (line 191-192).
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Create WAL with page 1 frame but truncate the page data
        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(vec![0u8; 100]); // Only 100 bytes instead of 4096

        let tables = detect_wal_only_tables(&ctx, &wal);
        assert!(tables.is_empty(), "truncated page data should be skipped");
    }

    #[test]
    fn test_detect_wal_only_tables_non_table_obj_type() {
        // Exercise the obj_type != "table" continue branch (line 213-214)
        // by including an "index" row in the synthetic page 1.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Build a page 1 with an "index" row instead of "table".
        // We need a custom cell since make_sqlite_master_cell always uses "table".
        // Build a cell manually with type="index".
        let page1 = make_page1_with_index_row(page_size, "my_index", 4, "CREATE INDEX my_index ON t(x)");

        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        // Index rows should be skipped → no WAL-only tables
        assert!(
            wal_only.is_empty(),
            "index rows should not produce WAL-only tables, got: {:?}",
            wal_only.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    /// Build a sqlite_master cell with a custom type (e.g. "index" instead of "table").
    fn make_sqlite_master_cell_custom_type(
        row_id: u64,
        obj_type: &str,
        name: &str,
        rootpage: u32,
        sql: &str,
    ) -> Vec<u8> {
        let type_bytes = obj_type.as_bytes();
        let name_bytes = name.as_bytes();
        let sql_bytes = sql.as_bytes();

        let st_type = 2 * type_bytes.len() as u64 + 13;
        let st_name = 2 * name_bytes.len() as u64 + 13;
        let st_tbl_name = 2 * name_bytes.len() as u64 + 13;
        let st_rootpage: u64 = 1;
        let st_sql = 2 * sql_bytes.len() as u64 + 13;

        let mut serial_type_bytes = Vec::new();
        serial_type_bytes.extend(encode_varint(st_type));
        serial_type_bytes.extend(encode_varint(st_name));
        serial_type_bytes.extend(encode_varint(st_tbl_name));
        serial_type_bytes.extend(encode_varint(st_rootpage));
        serial_type_bytes.extend(encode_varint(st_sql));

        let header_len = 1 + serial_type_bytes.len();
        let mut record = Vec::new();
        record.extend(encode_varint(header_len as u64));
        record.extend(&serial_type_bytes);
        record.extend(type_bytes);
        record.extend(name_bytes);
        record.extend(name_bytes);
        record.push(rootpage as u8);
        record.extend(sql_bytes);

        let mut cell = Vec::new();
        cell.extend(encode_varint(record.len() as u64));
        cell.extend(encode_varint(row_id));
        cell.extend(&record);
        cell
    }

    /// Build a page 1 with an "index" type row.
    fn make_page1_with_index_row(page_size: u32, name: &str, rootpage: u32, sql: &str) -> Vec<u8> {
        let mut page = vec![0u8; page_size as usize];
        let cell = make_sqlite_master_cell_custom_type(1, "index", name, rootpage, sql);

        let write_pos = page_size as usize - cell.len();
        page[write_pos..write_pos + cell.len()].copy_from_slice(&cell);

        let bhdr = 100usize;
        page[bhdr] = 0x0D;
        page[bhdr + 1] = 0;
        page[bhdr + 2] = 0;
        page[bhdr + 3] = 0;
        page[bhdr + 4] = 1; // 1 cell
        page[bhdr + 5] = (write_pos >> 8) as u8;
        page[bhdr + 6] = (write_pos & 0xFF) as u8;
        page[bhdr + 7] = 0;

        let ptr_start = bhdr + 8;
        page[ptr_start] = (write_pos >> 8) as u8;
        page[ptr_start + 1] = (write_pos & 0xFF) as u8;

        page
    }

    #[test]
    fn test_classify_frames_three_txns_with_supersede() {
        // Three committed transactions where page 2 appears in all three.
        // Only the last frame for page 2 is non-superseded.
        let mut wal = make_wal_header(512, 1, 2);
        // txn 1: page 2
        wal.extend(make_frame_header(2, 2, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);
        // txn 2: page 2 again
        wal.extend(make_frame_header(2, 2, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);
        // txn 3: page 2 again
        wal.extend(make_frame_header(2, 2, 1, 2)); // commit
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 3);

        // Frames 0 and 1 superseded by frame 2
        assert!(matches!(
            frames[0].status,
            WalFrameStatus::Superseded { superseded_by_frame: 2 }
        ));
        assert!(matches!(
            frames[1].status,
            WalFrameStatus::Superseded { superseded_by_frame: 2 }
        ));
        // Frame 2 committed
        assert!(matches!(
            frames[2].status,
            WalFrameStatus::Committed { transaction_id: 3 }
        ));
    }

    #[test]
    fn test_classify_frames_all_uncommitted() {
        // No commit frames at all → all frames are Uncommitted.
        let mut wal = make_wal_header(512, 1, 2);
        wal.extend(make_frame_header(2, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(3, 0, 1, 2));
        wal.extend(vec![0u8; 512]);
        wal.extend(make_frame_header(4, 0, 1, 2));
        wal.extend(vec![0u8; 512]);

        let frames = classify_wal_frames(&wal, 512);
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert!(
                matches!(f.status, WalFrameStatus::Uncommitted)
                    || matches!(f.status, WalFrameStatus::Superseded { .. }),
                "expected Uncommitted or Superseded, got {:?}",
                f.status
            );
        }
        // All are distinct pages so all should be Uncommitted
        assert_eq!(frames[0].status, WalFrameStatus::Uncommitted);
        assert_eq!(frames[1].status, WalFrameStatus::Uncommitted);
        assert_eq!(frames[2].status, WalFrameStatus::Uncommitted);
    }

    #[test]
    fn test_wal_only_table_has_create_sql_and_root_page() {
        // Verify WalOnlyTable fields using synthetic WAL.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let page1 = make_page1_with_tables(page_size, &[
            ("field_test", 7, "CREATE TABLE field_test (a INTEGER PRIMARY KEY, b TEXT NOT NULL)"),
        ]);

        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);

        let ft = wal_only.iter().find(|t| t.name == "field_test");
        assert!(ft.is_some(), "field_test should be in WAL-only tables, got: {:?}",
            wal_only.iter().map(|t| &t.name).collect::<Vec<_>>());
        let ft = ft.unwrap();
        assert!(
            ft.create_sql.contains("field_test"),
            "create_sql should contain table name, got: {}",
            ft.create_sql
        );
        assert_eq!(ft.root_page, 7);
        assert!(matches!(ft.frame_status, WalFrameStatus::Committed { .. }));
    }

    #[test]
    fn test_detect_wal_only_tables_rootpage_zero() {
        // Test that rootpage defaults to 0 when not a valid Int (line 224)
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Build a valid page1 with a table that has rootpage=0
        // (like a virtual table placeholder)
        let page1 = make_page1_with_tables(page_size, &[
            ("virt_tbl", 0, "CREATE VIRTUAL TABLE virt_tbl USING fts5(body)"),
        ]);

        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        // Virtual table with rootpage=0 should still appear
        let vt = wal_only.iter().find(|t| t.name == "virt_tbl");
        assert!(vt.is_some(), "virt_tbl should be in WAL-only tables");
        assert_eq!(vt.unwrap().root_page, 0);
    }

    #[test]
    fn test_detect_wal_only_non_text_values() {
        // Exercise the _ => continue branches for non-Text values in
        // detect_wal_only_tables (lines 211, 219, 224, 229).
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);
        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        // Build page 1 with cells that have unusual serial types:
        // Cell 1: values[0] = Int (not Text) → line 211
        // Cell 2: values[0] = "table", values[1] = Null (not Text) → line 219
        // Cell 3: values[0] = "table", values[1] = "x", values[3] = Null → line 224
        // Cell 4: values[0] = "table", values[1] = "y", values[3] = Int, values[4] = Null → line 229
        let cells = build_unusual_cells_for_detect();
        let page1 = make_page1_with_cells(page_size, &cells);

        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        // Cell 4 has name="y", rootpage=Int(5), sql=Null→String::new(),
        // and "y" is not in table_roots, so it should appear as WAL-only.
        let names: Vec<&str> = wal_only.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"y"), "expected 'y' in WAL-only tables, got: {:?}", names);
        // Verify the sql field is empty for this entry
        let y_entry = wal_only.iter().find(|t| t.name == "y").unwrap();
        assert_eq!(y_entry.create_sql, "");
    }

    /// Build a Vec of cell byte arrays with unusual serial types for
    /// testing detect_wal_only_tables defensive branches.
    fn build_unusual_cells_for_detect() -> Vec<Vec<u8>> {
        vec![
            // Cell 1: values[0] = Int (serial type 1) instead of Text → line 211
            make_cell_raw(1, &[1, 23, 23, 1, 23], &[&[42], b"hello", b"hello", &[2], b"hello"]),
            // Cell 2: values[0] = "table", values[1] = Null → line 219
            make_cell_raw(2, &[2*5+13, 0, 0, 1, 2*5+13], &[b"table", &[], &[], &[2], b"hello"]),
            // Cell 3: values[0] = "table", values[1] = "x", values[3] = Null → line 224
            make_cell_raw(3, &[2*5+13, 2*1+13, 2*1+13, 0, 2*5+13], &[b"table", b"x", b"x", &[], b"hello"]),
            // Cell 4: values[0] = "table", values[1] = "y", values[3] = Int(5), values[4] = Null → line 229
            make_cell_raw(4, &[2*5+13, 2*1+13, 2*1+13, 1, 0], &[b"table", b"y", b"y", &[5], &[]]),
        ]
    }

    /// Generic cell builder with arbitrary serial types and data.
    fn make_cell_raw(row_id: u64, serial_types: &[u64], column_data: &[&[u8]]) -> Vec<u8> {
        let mut serial_bytes = Vec::new();
        for &st in serial_types {
            serial_bytes.extend(encode_varint(st));
        }
        let header_len = 1 + serial_bytes.len();
        let mut record = Vec::new();
        record.extend(encode_varint(header_len as u64));
        record.extend(&serial_bytes);
        for data in column_data {
            record.extend(*data);
        }
        let mut cell = Vec::new();
        cell.extend(encode_varint(record.len() as u64));
        cell.extend(encode_varint(row_id));
        cell.extend(&record);
        cell
    }

    /// Build a page 1 with arbitrary cells.
    fn make_page1_with_cells(page_size: u32, cells: &[Vec<u8>]) -> Vec<u8> {
        let mut page = vec![0u8; page_size as usize];
        let bhdr = 100usize;
        page[bhdr] = 0x0D; // table leaf
        let mut cell_offsets: Vec<u16> = Vec::new();
        let mut write_pos = page_size as usize;
        for cell in cells {
            write_pos -= cell.len();
            page[write_pos..write_pos + cell.len()].copy_from_slice(cell);
            cell_offsets.push(write_pos as u16);
        }
        let cc = cells.len() as u16;
        page[bhdr + 3] = (cc >> 8) as u8;
        page[bhdr + 4] = (cc & 0xFF) as u8;
        page[bhdr + 5] = (write_pos >> 8) as u8;
        page[bhdr + 6] = (write_pos & 0xFF) as u8;
        page[bhdr + 7] = 0;
        let ptr_start = bhdr + 8;
        for (i, off) in cell_offsets.iter().enumerate() {
            let pos = ptr_start + i * 2;
            page[pos] = (*off >> 8) as u8;
            page[pos + 1] = (*off & 0xFF) as u8;
        }
        page
    }

    #[test]
    fn test_detect_wal_only_tables_multiple_tables_in_page1() {
        // Multiple tables in a single page-1 frame.
        use crate::context::RecoveryContext;
        use std::collections::HashMap;

        let page_size: u32 = 4096;
        let mut db = vec![0u8; page_size as usize];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = 0x00;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let (header, pragma_info) = make_ctx_from_db(&db);

        let mut table_roots = HashMap::new();
        table_roots.insert("existing".to_string(), 2);

        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots,
            schema_signatures: Vec::new(),
            pragma_info,
        };

        let page1 = make_page1_with_tables(page_size, &[
            ("tbl_a", 3, "CREATE TABLE tbl_a (x INT)"),
            ("existing", 2, "CREATE TABLE existing (y INT)"),
            ("tbl_b", 4, "CREATE TABLE tbl_b (z TEXT)"),
        ]);

        let mut wal = make_wal_header(page_size, 1, 2);
        wal.extend(make_frame_header(1, 1, 1, 2));
        wal.extend(&page1);

        let wal_only = detect_wal_only_tables(&ctx, &wal);
        let names: Vec<&str> = wal_only.iter().map(|t| t.name.as_str()).collect();

        assert!(names.contains(&"tbl_a"), "tbl_a should be WAL-only");
        assert!(names.contains(&"tbl_b"), "tbl_b should be WAL-only");
        assert!(!names.contains(&"existing"), "existing should be filtered");
        assert_eq!(wal_only.len(), 2);
    }
}
