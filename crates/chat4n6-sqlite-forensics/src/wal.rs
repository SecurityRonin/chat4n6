use std::collections::BTreeMap;
use crate::btree::parse_table_leaf_page;
use crate::record::RecoveredRecord;
use chat4n6_plugin_api::{EvidenceSource, WalDelta, WalDeltaStatus};

pub const WAL_MAGIC_1: u32 = 0x377f0682;
pub const WAL_MAGIC_2: u32 = 0x377f0683;
pub const WAL_HEADER_SIZE: usize = 32;
pub const WAL_FRAME_HEADER_SIZE: usize = 24;

pub fn is_wal_header(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
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
        if data.len() < 32 || !is_wal_header(data) { return None; }
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
/// Returns BTreeMap<salt1, Vec<WalFrame>> in frame order.
pub fn parse_wal_frames(wal: &[u8], page_size: u32) -> BTreeMap<u32, Vec<WalFrame>> {
    let mut map: BTreeMap<u32, Vec<WalFrame>> = BTreeMap::new();
    if !is_wal_header(wal) { return map; }
    let frame_size = WAL_FRAME_HEADER_SIZE + page_size as usize;
    let mut idx = 0;
    loop {
        let frame_off = WAL_HEADER_SIZE + idx * frame_size;
        if frame_off + WAL_FRAME_HEADER_SIZE > wal.len() { break; }
        let fh = &wal[frame_off..frame_off + WAL_FRAME_HEADER_SIZE];
        let page_number = u32::from_be_bytes([fh[0], fh[1], fh[2], fh[3]]);
        let db_size = u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]);
        let salt1 = u32::from_be_bytes([fh[8], fh[9], fh[10], fh[11]]);
        let salt2 = u32::from_be_bytes([fh[12], fh[13], fh[14], fh[15]]);
        if page_number == 0 { break; }
        let page_data_end = frame_off + frame_size;
        if page_data_end > wal.len() { break; }
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

/// Layer 2: extract records from WAL frames that haven't been checkpointed.
/// A frame is "unapplied" if the main DB page at that page number differs from
/// the WAL frame's page data. Tag: WalPending.
pub fn recover_layer2(
    wal: &[u8],
    db: &[u8],
    page_size: u32,
    table_name: &str,
) -> Vec<RecoveredRecord> {
    let mut records = Vec::new();
    let frames = parse_wal_frames(wal, page_size);
    // Use the most-recent salt1 group (largest key = most recent WAL session)
    let Some((_, frame_group)) = frames.iter().next_back() else { return records };

    for frame in frame_group {
        let wal_page = match wal.get(frame.page_data_offset..frame.page_data_offset + page_size as usize) {
            Some(p) => p,
            None => continue,
        };
        // Check if this page matches the main DB page
        let db_offset = (frame.page_number as usize - 1) * page_size as usize;
        let db_page = db.get(db_offset..db_offset + page_size as usize);
        if db_page == Some(wal_page) {
            continue; // already checkpointed — not pending
        }
        // Parse records from the WAL page version
        let bhdr = if frame.page_number == 1 { 100 } else { 0 };
        let mut page_records = parse_table_leaf_page(wal_page, bhdr, frame.page_number, page_size, table_name);
        for r in &mut page_records {
            r.source = EvidenceSource::WalPending;
        }
        records.extend(page_records);
    }
    records
}

/// Layer 3: compare WAL pages against main DB to detect added/modified/deleted rows.
/// Returns WalDelta entries for each changed row_id.
pub fn recover_layer3_deltas(
    wal: &[u8],
    db: &[u8],
    page_size: u32,
    table_name: &str,
) -> Vec<WalDelta> {
    use std::collections::HashMap;
    let mut deltas = Vec::new();
    let frames = parse_wal_frames(wal, page_size);

    for (_, frame_group) in &frames {
        for frame in frame_group {
            let wal_page = match wal.get(frame.page_data_offset..frame.page_data_offset + page_size as usize) {
                Some(p) => p,
                None => continue,
            };
            let db_offset = (frame.page_number as usize - 1) * page_size as usize;
            let db_page = match db.get(db_offset..db_offset + page_size as usize) {
                Some(p) => p,
                None => {
                    // Page doesn't exist in main DB — all WAL records are additions
                    let bhdr = if frame.page_number == 1 { 100 } else { 0 };
                    let wal_records = parse_table_leaf_page(wal_page, bhdr, frame.page_number, page_size, table_name);
                    for r in wal_records {
                        if let Some(row_id) = r.row_id {
                            deltas.push(WalDelta {
                                table: table_name.to_string(),
                                row_id,
                                status: WalDeltaStatus::AddedInWal,
                            });
                        }
                    }
                    continue;
                }
            };
            if wal_page == db_page { continue; }

            // Build row_id sets for WAL and DB versions of this page
            let bhdr = if frame.page_number == 1 { 100 } else { 0 };
            let wal_records = parse_table_leaf_page(wal_page, bhdr, frame.page_number, page_size, table_name);
            let db_records = parse_table_leaf_page(db_page, bhdr, frame.page_number, page_size, table_name);

            let wal_ids: HashMap<i64, _> = wal_records.iter()
                .filter_map(|r| r.row_id.map(|id| (id, &r.values)))
                .collect();
            let db_ids: HashMap<i64, _> = db_records.iter()
                .filter_map(|r| r.row_id.map(|id| (id, &r.values)))
                .collect();

            // In WAL but not in DB → added in WAL
            for &id in wal_ids.keys() {
                if !db_ids.contains_key(&id) {
                    deltas.push(WalDelta {
                        table: table_name.to_string(),
                        row_id: id,
                        status: WalDeltaStatus::AddedInWal,
                    });
                }
            }
            // In DB but not in WAL → deleted in WAL
            for &id in db_ids.keys() {
                if !wal_ids.contains_key(&id) {
                    deltas.push(WalDelta {
                        table: table_name.to_string(),
                        row_id: id,
                        status: WalDeltaStatus::DeletedInWal,
                    });
                }
            }
            // In both but different values → modified in WAL
            for (&id, wal_vals) in &wal_ids {
                if let Some(db_vals) = db_ids.get(&id) {
                    if wal_vals != db_vals {
                        deltas.push(WalDelta {
                            table: table_name.to_string(),
                            row_id: id,
                            status: WalDeltaStatus::ModifiedInWal,
                        });
                    }
                }
            }
        }
    }
    deltas
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
        header[16..20].copy_from_slice(&42u32.to_be_bytes());
        let wh = WalHeader::parse(&header).unwrap();
        assert_eq!(wh.page_size, 4096);
        assert_eq!(wh.salt1, 42);
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
        let wal = make_wal_bytes(page_size, &[
            (1, 0, 100, &pd),
            (2, 1, 100, &pd),
            (3, 1, 200, &pd),
        ]);
        let frames = parse_wal_frames(&wal, page_size);
        assert_eq!(frames.get(&100).unwrap().len(), 2);
        assert_eq!(frames.get(&200).unwrap().len(), 1);
    }
}
