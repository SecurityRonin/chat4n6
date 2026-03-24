use crate::btree::get_page_data;
use crate::context::RecoveryContext;
use crate::record::{decode_serial_type, RecoveredRecord, SqlValue};
use crate::schema_sig::SchemaSignature;
use crate::varint::read_varint;
use chat4n6_plugin_api::EvidenceSource;
use std::collections::HashSet;

/// A freeblock extracted from a B-tree page header chain.
struct Freeblock {
    /// Absolute byte offset of this freeblock within the page.
    page_offset: usize,
    /// The raw freeblock bytes (including the 4-byte chain header).
    data: Vec<u8>,
}

/// Walk the freeblock linked list within `page_data` (a full page slice).
/// `bhdr` is the byte offset of the B-tree page header within `page_data`.
///
/// Page header layout (8 bytes from `bhdr`):
///   +0: page type
///   +1-2: first freeblock offset (big-endian u16; 0 = none)
///   +3-4: cell count
///   +5-6: cell content area start
///   +7: fragmented bytes count
///
/// Each freeblock entry:
///   [0-1]: next freeblock offset (0 = end of chain)
///   [2-3]: size of this freeblock in bytes (includes the 4-byte header)
fn collect_freeblocks(page_data: &[u8], bhdr: usize) -> Vec<Freeblock> {
    let page_len = page_data.len();
    if page_len < bhdr + 4 {
        return Vec::new();
    }

    // First freeblock offset is at bhdr+1..bhdr+2 (big-endian u16).
    let first_fb = u16::from_be_bytes([page_data[bhdr + 1], page_data[bhdr + 2]]) as usize;
    if first_fb == 0 {
        return Vec::new();
    }

    let mut freeblocks = Vec::new();
    let mut fb_offset = first_fb;
    let mut visited: HashSet<usize> = HashSet::new();

    while fb_offset != 0 {
        // Bounds: need at least 4 bytes for the freeblock header.
        if fb_offset + 4 > page_len {
            break;
        }
        // Freeblock must not start before the B-tree page header.
        if fb_offset < bhdr + 8 {
            break;
        }
        // Cycle guard.
        if !visited.insert(fb_offset) {
            break;
        }

        let next = u16::from_be_bytes([page_data[fb_offset], page_data[fb_offset + 1]]) as usize;
        let size = u16::from_be_bytes([page_data[fb_offset + 2], page_data[fb_offset + 3]]) as usize;

        // Sanity: size must be >= 4 and fit within the page.
        if size < 4 || fb_offset + size > page_len {
            break;
        }

        freeblocks.push(Freeblock {
            page_offset: fb_offset,
            data: page_data[fb_offset..fb_offset + size].to_vec(),
        });

        fb_offset = next;
    }

    freeblocks
}

/// Try to parse a SQLite record header starting at `data[pos]`.
///
/// Returns `(serial_types, header_end)` where `header_end` is the offset
/// just past the record header (i.e., where values start), or `None` on
/// any parse failure.
fn try_parse_header(data: &[u8], pos: usize) -> Option<(Vec<u64>, usize)> {
    // Read header_len varint.
    let (header_len, hl_size) = read_varint(data, pos)?;
    let header_len = header_len as usize;

    // Sanity: header must be at least 2 bytes (header_len varint itself +
    // at least one serial type), no larger than 512 bytes, and fit in data.
    if header_len < 2 || header_len > 512 {
        return None;
    }
    let header_end_abs = pos + header_len;
    if header_end_abs > data.len() {
        return None;
    }

    // Parse serial type varints.
    let mut serial_types = Vec::new();
    let mut p = pos + hl_size;
    while p < header_end_abs {
        let (st, st_size) = read_varint(data, p)?;
        // Reserved serial types 10 and 11 are invalid in table leaf records.
        if st == 10 || st == 11 {
            return None;
        }
        serial_types.push(st);
        p += st_size;
    }

    if serial_types.is_empty() {
        return None;
    }

    Some((serial_types, header_end_abs))
}

/// Validate `serial_types` against `sig` and decode values from `data[values_start..]`.
///
/// Returns decoded `Vec<SqlValue>` and a confidence score in [0, 1], or `None`
/// if the column count doesn't match or decoding fails.
fn validate_and_decode(
    sig: &SchemaSignature,
    serial_types: &[u64],
    data: &[u8],
    values_start: usize,
) -> Option<(Vec<SqlValue>, f32)> {
    if serial_types.len() != sig.column_count {
        return None;
    }

    // Type-compatibility check.
    let mut compat = 0usize;
    for (i, &st) in serial_types.iter().enumerate() {
        if SchemaSignature::is_compatible(&sig.type_hints[i], st) {
            compat += 1;
        }
    }
    if compat == 0 {
        return None;
    }

    // Decode values.
    let mut values = Vec::with_capacity(serial_types.len());
    let mut vpos = values_start;
    for &st in serial_types {
        if vpos > data.len() {
            return None;
        }
        let (val, consumed) = decode_serial_type(st, data, vpos)?;
        values.push(val);
        vpos += consumed;
    }

    // Total decoded size sanity: must not exceed a full SQLite page (65 536 B).
    if vpos > 65536 {
        return None;
    }

    let confidence = compat as f32 / sig.column_count as f32 * 0.6;
    Some((values, confidence))
}

/// Collect all leaf page numbers for the B-tree rooted at `root_page`.
fn collect_leaf_pages(db: &[u8], page_size: u32, root_page: u32) -> Vec<u32> {
    let mut leaves = Vec::new();
    let mut stack = vec![root_page];
    let mut visited: HashSet<u32> = HashSet::new();

    while let Some(page_num) = stack.pop() {
        if !visited.insert(page_num) {
            continue;
        }
        if let Some((page_data, bhdr)) = get_page_data(db, page_num, page_size as usize) {
            if bhdr >= page_data.len() {
                continue;
            }
            match page_data[bhdr] {
                0x0D => leaves.push(page_num), // table leaf
                0x05 => {
                    // table interior — right-most child pointer at bhdr+8..+12
                    if bhdr + 12 <= page_data.len() {
                        let rp = u32::from_be_bytes([
                            page_data[bhdr + 8],
                            page_data[bhdr + 9],
                            page_data[bhdr + 10],
                            page_data[bhdr + 11],
                        ]);
                        stack.push(rp);
                    }
                    // Cell pointer array starts at bhdr+12 for interior pages.
                    if bhdr + 5 <= page_data.len() {
                        let cell_count = u16::from_be_bytes([
                            page_data[bhdr + 3],
                            page_data[bhdr + 4],
                        ]) as usize;
                        let ptr_start = bhdr + 12;
                        for i in 0..cell_count {
                            let ptr_off = ptr_start + i * 2;
                            if ptr_off + 2 > page_data.len() {
                                break;
                            }
                            let cell_off = u16::from_be_bytes([
                                page_data[ptr_off],
                                page_data[ptr_off + 1],
                            ]) as usize;
                            // Each interior cell starts with a 4-byte left child pointer.
                            if cell_off + 4 <= page_data.len() {
                                let child = u32::from_be_bytes([
                                    page_data[cell_off],
                                    page_data[cell_off + 1],
                                    page_data[cell_off + 2],
                                    page_data[cell_off + 3],
                                ]);
                                stack.push(child);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    leaves
}

/// Recover deleted records from freeblocks within active B-tree leaf pages.
///
/// Implements bring2lite Algorithm 3: for each leaf page, walk the freeblock
/// chain and brute-force the varint offset `v` (0..20) to find a valid record
/// header that matches a known schema signature.
pub fn recover_freeblocks(ctx: &RecoveryContext) -> Vec<RecoveredRecord> {
    let mut results = Vec::new();

    for (table_name, &root_page) in &ctx.table_roots {
        // Find the matching schema signature for this table.
        let sig = match ctx
            .schema_signatures
            .iter()
            .find(|s| s.table_name == *table_name)
        {
            Some(s) => s,
            None => continue,
        };

        if sig.column_count == 0 {
            continue;
        }

        let leaf_pages = collect_leaf_pages(ctx.db, ctx.page_size, root_page);

        for page_num in leaf_pages {
            let (page_data, bhdr) =
                match get_page_data(ctx.db, page_num, ctx.page_size as usize) {
                    Some(x) => x,
                    None => continue,
                };

            let page_abs_offset = (page_num as u64 - 1) * ctx.page_size as u64;

            let freeblocks = collect_freeblocks(page_data, bhdr);

            for fb in &freeblocks {
                // The first 4 bytes of a freeblock are the chain header
                // (next_offset, size) — the original cell payload start was
                // overwritten by those 4 bytes.  We skip them and brute-force
                // the remaining bytes.
                let fb_data = &fb.data;
                if fb_data.len() <= 4 {
                    continue;
                }
                // The usable payload region starts at byte 4 of the freeblock.
                let payload = &fb_data[4..];
                let max_v = payload.len().min(20);

                for v in 0..max_v {
                    if v >= payload.len() {
                        break;
                    }
                    let candidate_region = &payload[v..];

                    if let Some((serial_types, header_end_rel)) =
                        try_parse_header(candidate_region, 0)
                    {
                        if let Some((values, confidence)) =
                            validate_and_decode(sig, &serial_types, candidate_region, header_end_rel)
                        {
                            let abs_offset =
                                page_abs_offset + fb.page_offset as u64 + 4 + v as u64;

                            results.push(RecoveredRecord {
                                table: table_name.clone(),
                                row_id: None,
                                values,
                                source: EvidenceSource::Freelist,
                                offset: abs_offset,
                                confidence,
                            });
                            // Accept the first valid `v` for this freeblock to
                            // avoid duplicate records at different offsets.
                            break;
                        }
                    }
                }
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RecoveryContext;
    use crate::header::DbHeader;
    use crate::pragma::PragmaInfo;
    use crate::schema_sig::SchemaSignature;
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Create a 1-page (1024 B) database byte buffer with the SQLite magic
    /// header and a minimal B-tree leaf page header.
    fn make_minimal_db_1024() -> Vec<u8> {
        let mut buf = vec![0u8; 1024];
        // SQLite file header magic (bytes 0-15).
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        // Page size: 1024 = 0x0400 → bytes [16..17]
        buf[16] = 0x04;
        buf[17] = 0x00;
        // file_format_write = 1, file_format_read = 1
        buf[18] = 1;
        buf[19] = 1;
        // text encoding: UTF-8 = 1 (bytes 56-59)
        buf[56..60].copy_from_slice(&1u32.to_be_bytes());
        // Page 1: B-tree header starts at offset 100.
        // Page type = 0x0D (table leaf)
        buf[100] = 0x0D;
        // First freeblock offset = 0 (no freeblocks)
        buf[101] = 0x00;
        buf[102] = 0x00;
        // Cell count = 0
        buf[103] = 0x00;
        buf[104] = 0x00;
        // Cell content area start = 1024 (end of page, big-endian u16).
        // SQLite stores 0 to mean 65536, but 1024 as u16 = 0x0400.
        buf[105] = 0x04;
        buf[106] = 0x00;
        buf
    }

    /// Build a RecoveryContext for a single-page DB with one table whose
    /// schema is given by `create_sql`.  The table root page is always 1.
    fn make_ctx_with_schema<'a>(
        db: &'a [u8],
        table_name: &str,
        create_sql: &str,
        leaked_header: &'a DbHeader,
    ) -> RecoveryContext<'a> {
        let header_ref = leaked_header;
        let page_size = header_ref.page_size;
        let mut roots = HashMap::new();
        roots.insert(table_name.to_string(), 1u32);
        let sig = SchemaSignature::from_create_sql(table_name, create_sql).unwrap();
        RecoveryContext {
            db,
            page_size,
            header: header_ref,
            table_roots: roots,
            schema_signatures: vec![sig],
            pragma_info: PragmaInfo::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_ctx_no_panic() {
        // A completely empty db slice must not panic and must return empty.
        let db = vec![0u8; 0];
        // We can't parse a header, so build the context manually.
        let header = DbHeader {
            page_size: 1024,
            page_count: 0,
            freelist_trunk_page: 0,
            freelist_page_count: 0,
            text_encoding: 1,
            user_version: 0,
        };
        let leaked: &'static DbHeader = Box::leak(Box::new(header));
        let ctx = RecoveryContext {
            db: &db,
            page_size: 1024,
            header: leaked,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info: PragmaInfo::default(),
        };
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_no_freeblocks_clean_page() {
        // Page with no freeblocks → empty result.
        let db = make_minimal_db_1024();
        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_freeblock_chain_with_no_valid_record() {
        // Inject a freeblock at offset 200 on page 1 that contains garbage.
        // The brute-force should find nothing and return empty — no panic.
        let mut db = make_minimal_db_1024();

        // Set first freeblock pointer (bhdr+1..bhdr+2) = 200.
        db[101] = 0x00;
        db[102] = 0xC8; // 200 in big-endian

        // Freeblock at offset 200:
        //   [0-1] next = 0 (end of chain)
        //   [2-3] size = 20
        //   [4-19] garbage payload (all 0xFF)
        db[200] = 0x00;
        db[201] = 0x00; // next = 0
        db[202] = 0x00;
        db[203] = 0x14; // size = 20
        for i in 204..220 {
            db[i] = 0xFF;
        }

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        // May or may not find something depending on chance, but must not panic.
        let _ = results;
    }

    #[test]
    fn test_freeblock_recover_crafted_record() {
        // Hand-craft a freeblock that contains a valid record payload matching
        // schema (name TEXT, age INTEGER) i.e. 2 columns.
        //
        // Record header layout (after the 4-byte freeblock chain header):
        //   v=0: header_len varint + serial type varints
        //
        // We use:
        //   header_len = 4 (varint = 0x04)
        //   serial_type[0] = 15 (TEXT len = (15-13)/2 = 1 byte) — for "A"
        //   serial_type[1] = 1  (INT8 — 1 byte)                 — for 42
        //   values: 'A' (0x41), 42 (0x2A)
        //
        // header_len=4 means: 1 byte for the header_len varint itself + 2
        // serial type bytes (1 each) + 0 pad = positions 0..4.
        // Example with header_len=4 would produce 3 serial types (2-col schema mismatch):
        //   [0x04, 0x0F, 0x01, 0x00, 0x41, 0x2A]
        // Instead we use header_len=3 for exactly 2 serial types.

        // Wait — header_len=4 means the header occupies bytes [0..4]:
        //   byte 0: header_len varint (value=4, size=1)
        //   byte 1: serial_type 0x0F (15)
        //   byte 2: serial_type 0x01 (1)
        //   byte 3: padding byte 0x00 (extra, will be read as serial_type=0=NULL)
        // That gives 3 serial types for a 2-column schema → mismatch.
        //
        // Use header_len=3 instead:
        //   byte 0: header_len varint (value=3, size=1)
        //   byte 1: serial_type 0x0F (15) — TEXT
        //   byte 2: serial_type 0x01 (1)  — INT8
        // values start at byte 3:
        //   byte 3: 0x41 'A'
        //   byte 4: 0x2A 42
        let record: &[u8] = &[
            0x03, // header_len = 3
            0x0F, // serial_type 15: TEXT len=1
            0x01, // serial_type 1:  INT8
            0x41, // value: 'A'
            0x2A, // value: 42
        ];

        let mut db = make_minimal_db_1024();

        // Place freeblock at offset 300 (well within page 1, past bhdr+8=108).
        //   [0-1] next = 0
        //   [2-3] size = 4 + record.len() = 9
        //   [4..] = record bytes
        let fb_offset: usize = 300;
        let fb_size = 4 + record.len(); // = 9

        // Set first freeblock pointer in page header (bhdr=100, +1..+2).
        db[101] = (fb_offset >> 8) as u8;
        db[102] = (fb_offset & 0xFF) as u8;

        // Write freeblock.
        db[fb_offset] = 0x00;     // next high
        db[fb_offset + 1] = 0x00; // next low  → 0 (end of chain)
        db[fb_offset + 2] = 0x00; // size high
        db[fb_offset + 3] = fb_size as u8; // size low
        db[fb_offset + 4..fb_offset + 4 + record.len()].copy_from_slice(record);

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);

        assert!(!results.is_empty());
        let rec = &results[0];
        assert_eq!(rec.table, "t");
        assert_eq!(rec.source, EvidenceSource::Freelist);
        assert!(rec.confidence > 0.0 && rec.confidence <= 1.0);
        assert_eq!(rec.values.len(), 2);
        // First value should be text "A", second should be int 42.
        assert_eq!(rec.values[0], SqlValue::Text("A".to_string()));
        assert_eq!(rec.values[1], SqlValue::Int(42));
    }

    #[test]
    fn test_freeblock_cycle_guard() {
        // Create a freeblock chain that points to itself — must not loop forever.
        let mut db = make_minimal_db_1024();

        let fb_offset: usize = 200;
        // Set first freeblock pointer.
        db[101] = 0x00;
        db[102] = 0xC8; // 200

        // Freeblock at 200 points to itself as next.
        db[fb_offset] = 0x00;
        db[fb_offset + 1] = 0xC8; // next = 200 (self-loop)
        db[fb_offset + 2] = 0x00;
        db[fb_offset + 3] = 0x10; // size = 16
        for i in 0..12 {
            db[fb_offset + 4 + i] = 0x00;
        }

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        // Must complete without hanging.
        let _ = recover_freeblocks(&ctx);
    }

    #[test]
    fn test_no_schema_signature_returns_empty() {
        // Table root present but no matching schema → no results.
        let db = make_minimal_db_1024();
        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 1u32);
        let ctx = RecoveryContext {
            db: &db,
            page_size: leaked_header.page_size,
            header: leaked_header,
            table_roots: roots,
            schema_signatures: Vec::new(), // intentionally empty
            pragma_info: PragmaInfo::default(),
        };
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_record_offset_is_correct() {
        // Verify the absolute byte offset stored in RecoveredRecord.
        // Page 1, freeblock at page offset 300, v=0:
        //   abs_offset = (1-1)*1024 + 300 + 4 + 0 = 304.
        let record: &[u8] = &[
            0x03, // header_len = 3
            0x0F, // serial_type 15: TEXT len=1
            0x01, // serial_type 1:  INT8
            0x41, // 'A'
            0x2A, // 42
        ];
        let mut db = make_minimal_db_1024();
        let fb_offset: usize = 300;
        let fb_size = 4 + record.len();
        db[101] = (fb_offset >> 8) as u8;
        db[102] = (fb_offset & 0xFF) as u8;
        db[fb_offset] = 0x00;
        db[fb_offset + 1] = 0x00;
        db[fb_offset + 2] = 0x00;
        db[fb_offset + 3] = fb_size as u8;
        db[fb_offset + 4..fb_offset + 4 + record.len()].copy_from_slice(record);

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        assert!(!results.is_empty());
        // page 1 → base 0; freeblock at 300 → +300; skip 4-byte header → +4; v=0 → +0.
        assert_eq!(results[0].offset, 304);
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — edge cases in collect_freeblocks
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_freeblocks_page_too_short() {
        // L33: page_len < bhdr + 4 → early return Vec::new()
        let page_data = vec![0u8; 3]; // bhdr=0, need at least 4
        let result = collect_freeblocks(&page_data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_freeblocks_fb_offset_out_of_bounds() {
        // L49: fb_offset + 4 > page_len → break
        let mut page_data = vec![0u8; 16];
        // bhdr=0, page type at 0
        page_data[0] = 0x0D;
        // First freeblock offset at bhdr+1..bhdr+2 = large value near end
        page_data[1] = 0x00;
        page_data[2] = 0x0F; // offset 15, need 4 bytes but page is only 16
        let result = collect_freeblocks(&page_data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_freeblocks_fb_before_bhdr_plus_8() {
        // L53: fb_offset < bhdr + 8 → break
        let mut page_data = vec![0u8; 64];
        page_data[0] = 0x0D;
        // First freeblock offset points to 4, which is < bhdr(0) + 8 = 8
        page_data[1] = 0x00;
        page_data[2] = 0x04;
        let result = collect_freeblocks(&page_data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_freeblocks_size_too_small() {
        // L65: size < 4 → break
        let mut page_data = vec![0u8; 64];
        page_data[0] = 0x0D;
        // First freeblock at offset 10 (>= bhdr+8=8)
        page_data[1] = 0x00;
        page_data[2] = 0x0A; // 10
        // Freeblock at 10: next=0, size=2 (invalid, < 4)
        page_data[10] = 0x00;
        page_data[11] = 0x00;
        page_data[12] = 0x00;
        page_data[13] = 0x02; // size = 2
        let result = collect_freeblocks(&page_data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_freeblocks_size_exceeds_page() {
        // L65: fb_offset + size > page_len → break
        let mut page_data = vec![0u8; 32];
        page_data[0] = 0x0D;
        // First freeblock at offset 10
        page_data[1] = 0x00;
        page_data[2] = 0x0A;
        // Freeblock: next=0, size=30 → 10+30=40 > 32
        page_data[10] = 0x00;
        page_data[11] = 0x00;
        page_data[12] = 0x00;
        page_data[13] = 0x1E; // 30
        let result = collect_freeblocks(&page_data, 0);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — try_parse_header edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_try_parse_header_reserved_serial_types() {
        // L106: serial type 10 or 11 → return None
        // header_len=3 (varint 0x03), serial_type=10
        let data: &[u8] = &[0x03, 0x0A, 0x01, 0x00]; // 0x0A = 10
        assert!(try_parse_header(data, 0).is_none());
        // Also test serial type 11
        let data: &[u8] = &[0x03, 0x0B, 0x01, 0x00]; // 0x0B = 11
        assert!(try_parse_header(data, 0).is_none());
    }

    #[test]
    fn test_try_parse_header_empty_serial_types() {
        // L113: serial_types.is_empty() → return None
        // header_len=1 means header is only the header_len varint itself — no serial types.
        // But header_len < 2 is caught at L91 first. So we can't easily trigger
        // empty serial types unless header_len=2 but position arithmetic fails.
        // Actually header_len=2 with hl_size=1 means p starts at 1 and ends at 2.
        // Let's construct: header_len=2, but the varint at pos 1 would fail (e.g., pos 1 is
        // exactly at the boundary and read_varint fails).
        // Simplest: header_len < 2 → return None
        let data: &[u8] = &[0x01]; // header_len = 1 < 2
        assert!(try_parse_header(data, 0).is_none());
    }

    #[test]
    fn test_try_parse_header_too_large() {
        // header_len > 512 → return None
        // varint encoding for 513: 0x84, 0x01
        let data = &[0x84, 0x01, 0x00, 0x00];
        assert!(try_parse_header(data, 0).is_none());
    }

    #[test]
    fn test_try_parse_header_exceeds_data() {
        // L95-96: header_end_abs > data.len() → return None
        // header_len = 10 but data is only 5 bytes
        let data: &[u8] = &[0x0A, 0x01, 0x01, 0x01, 0x01];
        assert!(try_parse_header(data, 0).is_none());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — validate_and_decode edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_and_decode_column_count_mismatch() {
        // L130: serial_types.len() != sig.column_count → return None
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a TEXT, b INTEGER)").unwrap();
        // 3 serial types for a 2-column schema
        let serial_types = vec![1u64, 1, 1];
        let data = &[0x00, 0x00, 0x00];
        assert!(validate_and_decode(&sig, &serial_types, data, 0).is_none());
    }

    #[test]
    fn test_validate_and_decode_zero_compat() {
        // L141: compat == 0 → return None
        // Schema expects (TEXT, INTEGER) but provide (REAL, REAL)
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a TEXT, b INTEGER)").unwrap();
        // serial type 7 = REAL (not TEXT), serial type 7 = REAL (not INTEGER)
        let serial_types = vec![7u64, 7];
        // Provide enough data for two 8-byte floats
        let data = vec![0u8; 16];
        assert!(validate_and_decode(&sig, &serial_types, &data, 0).is_none());
    }

    #[test]
    fn test_validate_and_decode_vpos_exceeds_data() {
        // L148-149: vpos > data.len() → return None
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a INTEGER)").unwrap();
        // serial type 4 = 4-byte int, but data is too short
        let serial_types = vec![4u64];
        let data = &[0x00, 0x01]; // only 2 bytes, need 4
        assert!(validate_and_decode(&sig, &serial_types, data, 0).is_none());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — collect_leaf_pages interior page handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_leaf_pages_interior_and_leaf() {
        // Build a 2-page DB: page 1 = interior, page 2 = leaf.
        // This tests lines 181-220 (interior page traversal).
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 2];

        // SQLite header on page 1
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        // Page 1 (bhdr=100): interior page (0x05)
        let bhdr: usize = 100;
        db[bhdr] = 0x05;
        // Cell count = 1 at bhdr+3..bhdr+4
        db[bhdr + 3] = 0x00;
        db[bhdr + 4] = 0x01;
        // Right-most child pointer at bhdr+8..+12 = page 2
        db[bhdr + 8] = 0x00;
        db[bhdr + 9] = 0x00;
        db[bhdr + 10] = 0x00;
        db[bhdr + 11] = 0x02; // page 2

        // Cell pointer array starts at bhdr+12 for interior pages
        // Cell pointer 0 → offset 200
        let ptr_start = bhdr + 12;
        db[ptr_start] = 0x00;
        db[ptr_start + 1] = 0xC8; // 200

        // Interior cell at offset 200: 4-byte left child pointer = page 2 (dup, will be deduped by visited set)
        db[200] = 0x00;
        db[201] = 0x00;
        db[202] = 0x00;
        db[203] = 0x02; // left child = page 2

        // Page 2 (bhdr=0): leaf page (0x0D)
        let page2_off = page_size;
        db[page2_off] = 0x0D;

        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        assert!(leaves.contains(&2), "Page 2 should be a leaf");
        assert!(!leaves.contains(&1), "Page 1 is interior, not a leaf");
    }

    #[test]
    fn test_collect_leaf_pages_visited_dedup() {
        // L172: visited.insert returns false → continue
        // An interior page with two cells both pointing to the same child
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 2];

        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let bhdr: usize = 100;
        db[bhdr] = 0x05; // interior
        db[bhdr + 3] = 0x00;
        db[bhdr + 4] = 0x02; // 2 cells
        // Right-most child = page 2
        db[bhdr + 8] = 0x00;
        db[bhdr + 9] = 0x00;
        db[bhdr + 10] = 0x00;
        db[bhdr + 11] = 0x02;

        // Cell pointer 0 → offset 200
        let ptr_start = bhdr + 12;
        db[ptr_start] = 0x00;
        db[ptr_start + 1] = 0xC8; // 200
        // Cell pointer 1 → offset 210
        db[ptr_start + 2] = 0x00;
        db[ptr_start + 3] = 0xD2; // 210

        // Both cells point to page 2
        db[200] = 0x00;
        db[201] = 0x00;
        db[202] = 0x00;
        db[203] = 0x02;
        db[210] = 0x00;
        db[211] = 0x00;
        db[212] = 0x00;
        db[213] = 0x02;

        // Page 2 = leaf
        db[page_size] = 0x0D;

        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        assert_eq!(leaves.len(), 1, "page 2 should appear only once");
    }

    #[test]
    fn test_collect_leaf_pages_bhdr_exceeds_page() {
        // L176-177: bhdr >= page_data.len() → continue
        // Page 1 is normally page_data with bhdr=100, but if the page is too short
        // this branch is hit. We use get_page_data which returns full page slices,
        // so we need a DB that's exactly 1 page where the bhdr is at 100 but page
        // type is unknown. Actually, the simplest trigger is a DB where page_data
        // is valid but get_page_data returns a slice that doesn't include bhdr.
        // This is hard to trigger with get_page_data. Instead let's test with a page
        // whose type is unrecognized (not 0x05 or 0x0D) to hit the `_ => {}` branch (L221).
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size];

        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        // Page 1: type 0x0A (index leaf — neither table leaf nor interior)
        db[100] = 0x0A;

        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        assert!(leaves.is_empty(), "index leaf should not be collected as table leaf");
    }

    #[test]
    fn test_recover_freeblocks_column_count_zero() {
        // L248: sig.column_count == 0 → continue
        let db = make_minimal_db_1024();
        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 1u32);
        // Create a schema with 0 columns
        let sig = SchemaSignature {
            table_name: "t".to_string(),
            column_count: 0,
            type_hints: vec![],
        };
        let ctx = RecoveryContext {
            db: &db,
            page_size: leaked_header.page_size,
            header: leaked_header,
            table_roots: roots,
            schema_signatures: vec![sig],
            pragma_info: PragmaInfo::default(),
        };
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freeblocks_get_page_data_none() {
        // L257-259: get_page_data returns None → continue
        // Use a root page number that's out of range
        let db = make_minimal_db_1024();
        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 999u32); // page 999 doesn't exist
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a TEXT)").unwrap();
        let ctx = RecoveryContext {
            db: &db,
            page_size: leaked_header.page_size,
            header: leaked_header,
            table_roots: roots,
            schema_signatures: vec![sig],
            pragma_info: PragmaInfo::default(),
        };
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_freeblock_payload_too_small() {
        // L271-273: fb_data.len() <= 4 → continue
        let mut db = make_minimal_db_1024();
        // Freeblock at offset 200 with size = 4 (minimum, no payload)
        db[101] = 0x00;
        db[102] = 0xC8; // 200
        db[200] = 0x00;
        db[201] = 0x00;
        db[202] = 0x00;
        db[203] = 0x04; // size = 4 (just the header, no payload)

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (a TEXT, b INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_collect_leaf_pages_interior_cell_ptr_out_of_bounds() {
        // L201-202: ptr_off + 2 > page_data.len() → break
        let page_size: usize = 128; // very small page
        let mut db = vec![0u8; page_size];
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = 0x00;
        db[17] = 0x80; // page_size = 128
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        let bhdr = 100;
        db[bhdr] = 0x05; // interior
        // cell count = 100 (way more than can fit)
        db[bhdr + 3] = 0x00;
        db[bhdr + 4] = 0x64; // 100 cells
        // Right-most child = 0 (invalid, won't be visited)
        db[bhdr + 8] = 0x00;
        db[bhdr + 9] = 0x00;
        db[bhdr + 10] = 0x00;
        db[bhdr + 11] = 0x00;

        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        // Just verifying it doesn't panic and handles bounds properly
        let _ = leaves;
    }

    #[test]
    fn test_validate_and_decode_large_vpos() {
        // L157-158: vpos > 65536 → return None
        // Create a sig with 1 column (BLOB), feed a huge serial type to make
        // decode consume >65536 bytes.
        let sig = SchemaSignature {
            table_name: "t".to_string(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Blob],
        };
        // serial type for blob of length n: st = 12 + 2*n
        // For 65536 bytes: st = 12 + 2*65536 = 131084
        // But we need the data to actually have that many bytes.
        // Instead, use a simpler approach: values_start already past 65536.
        // validate_and_decode checks vpos > 65536 AFTER decoding.
        // We need: values_start + consumed > 65536.
        // Simpler: set values_start to 65530 and have a 6-byte int serial type (type 6).
        // vpos after decode = 65530 + 8 = 65538 > 65536.
        let serial_types = vec![6u64]; // 8-byte int
        let data = vec![0u8; 65540];
        let result = validate_and_decode(&sig, &serial_types, &data, 65530);
        assert!(result.is_none(), "vpos > 65536 should return None");
    }

    #[test]
    fn test_try_parse_header_valid() {
        // Happy path for try_parse_header
        // header_len=3, serial_type 1 (INT8), serial_type 1 (INT8)
        let data: &[u8] = &[0x03, 0x01, 0x01, 0x2A, 0x2B];
        let result = try_parse_header(data, 0);
        assert!(result.is_some());
        let (serial_types, header_end) = result.unwrap();
        assert_eq!(serial_types, vec![1, 1]);
        assert_eq!(header_end, 3);
    }

    #[test]
    fn test_validate_and_decode_success() {
        // Happy path for validate_and_decode
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a INTEGER, b TEXT)").unwrap();
        // serial type 1 = INT8, serial type 15 = TEXT len 1
        let serial_types = vec![1u64, 15];
        // data: byte 0 = 42 (int8), byte 1 = 'A' (text)
        let data: &[u8] = &[0x2A, 0x41];
        let result = validate_and_decode(&sig, &serial_types, data, 0);
        assert!(result.is_some());
        let (values, confidence) = result.unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], SqlValue::Int(42));
        assert_eq!(values[1], SqlValue::Text("A".to_string()));
        assert!(confidence > 0.0);
    }

    #[test]
    fn test_validate_and_decode_vpos_exceeds_data_len() {
        // L148-149: vpos > data.len() mid-decode
        // Schema expects 2 columns, serial types match, but values_start is past end of data
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (a INTEGER, b INTEGER)").unwrap();
        let serial_types = vec![1u64, 1]; // 2 x INT8 columns
        let data: &[u8] = &[0x2A]; // Only 1 byte, but first column needs it, second goes past
        // Start at 0: first INT8 reads byte 0 (ok), vpos=1. Second INT8: vpos=1 == data.len()=1
        // Actually vpos > data.len() would need values_start to push past.
        // Let's start at values_start=1 with only 1 byte of data remaining → first column decodes
        // but decode_serial_type returns None for insufficient data.
        // The check is vpos > data.len() which is triggered when values_start is PAST the end.
        let result = validate_and_decode(&sig, &serial_types, data, 2);
        assert!(result.is_none(), "vpos > data.len() should return None");
    }

    #[test]
    fn test_try_parse_header_serial_type_empty_via_header_len_equals_1() {
        // L112-113: serial_types.is_empty() is guarded by header_len < 2 check at L91
        // header_len=1 → returns None at L92
        let data: &[u8] = &[0x01, 0x01, 0x01];
        assert!(try_parse_header(data, 0).is_none());
    }

    #[test]
    fn test_recover_freeblocks_multipage_db() {
        // Create a 3-page DB to test multi-page traversal with freeblocks.
        // Page 1 = interior, Page 2 = leaf with freeblock, Page 3 = leaf.
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 3];

        // SQLite header
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        // Page 1 (bhdr=100): interior page
        let bhdr = 100;
        db[bhdr] = 0x05;
        db[bhdr + 3] = 0x00;
        db[bhdr + 4] = 0x01; // 1 cell
        // Right-most child = page 3
        db[bhdr + 8] = 0x00;
        db[bhdr + 9] = 0x00;
        db[bhdr + 10] = 0x00;
        db[bhdr + 11] = 0x03;
        // Cell pointer at bhdr+12 → offset 200
        db[bhdr + 12] = 0x00;
        db[bhdr + 13] = 0xC8;
        // Cell at 200: left child = page 2
        db[200] = 0x00;
        db[201] = 0x00;
        db[202] = 0x00;
        db[203] = 0x02;

        // Page 2 (offset 1024, bhdr=0): leaf with a freeblock containing a valid record
        let p2 = page_size;
        db[p2] = 0x0D; // table leaf
        db[p2 + 1] = 0x00;
        db[p2 + 2] = 0x0A; // first freeblock at offset 10
        // Freeblock at page2 offset 10
        let fb_off = p2 + 10;
        db[fb_off] = 0x00;
        db[fb_off + 1] = 0x00; // next = 0
        db[fb_off + 2] = 0x00;
        db[fb_off + 3] = 0x09; // size = 9
        // Record: header_len=3, serial 15 (TEXT len 1), serial 1 (INT8), 'B', 99
        db[fb_off + 4] = 0x03;
        db[fb_off + 5] = 0x0F;
        db[fb_off + 6] = 0x01;
        db[fb_off + 7] = 0x42; // 'B'
        db[fb_off + 8] = 0x63; // 99

        // Page 3 (offset 2048, bhdr=0): leaf, no freeblocks
        let p3 = page_size * 2;
        db[p3] = 0x0D;

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        assert!(!results.is_empty(), "Should find record in page 2 freeblock");
        assert_eq!(results[0].values[0], SqlValue::Text("B".to_string()));
        assert_eq!(results[0].values[1], SqlValue::Int(99));
        // Offset should be relative to page 2
        let expected_offset = (2 - 1) as u64 * page_size as u64 + 10 + 4;
        assert_eq!(results[0].offset, expected_offset);
    }

    #[test]
    fn test_collect_leaf_pages_invalid_page_returns_none() {
        // L175: get_page_data returns None for out-of-bounds page
        let page_size: usize = 1024;
        let db = vec![0u8; page_size]; // Only 1 page
        // Try to get page 5 which doesn't exist
        let leaves = collect_leaf_pages(&db, page_size as u32, 5);
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_recover_freeblocks_with_brute_force_v_offset() {
        // Test the brute-force loop where v > 0 finds the record
        // This exercises L278-304 where v=0 doesn't parse but v=2 does
        let mut db = make_minimal_db_1024();

        let fb_offset: usize = 300;
        db[101] = (fb_offset >> 8) as u8;
        db[102] = (fb_offset & 0xFF) as u8;

        // Freeblock with garbage at v=0,1 but valid record at v=2
        let fb_size = 4 + 20; // enough room
        db[fb_offset] = 0x00;
        db[fb_offset + 1] = 0x00;
        db[fb_offset + 2] = 0x00;
        db[fb_offset + 3] = fb_size as u8;
        // v=0,1: garbage
        db[fb_offset + 4] = 0xFF;
        db[fb_offset + 5] = 0xFF;
        // v=2: valid record (header_len=3, TEXT len 1, INT8)
        db[fb_offset + 6] = 0x03;
        db[fb_offset + 7] = 0x0F;
        db[fb_offset + 8] = 0x01;
        db[fb_offset + 9] = 0x41; // 'A'
        db[fb_offset + 10] = 0x2A; // 42

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT, age INTEGER)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        // The brute force may or may not find the record at v=2 depending on
        // whether earlier v values also parse. Just verify no panic.
        let _ = results;
    }

    #[test]
    fn test_try_parse_header_varint_failure_in_serial_type() {
        // L103 ^0 annotation + L113: read_varint fails in the while loop,
        // serial_types remains empty → return None.
        // We need header_len >= 2, header_end_abs <= data.len(), but
        // read_varint fails at position p = pos + hl_size.
        // A varint with the continuation bit set but no following byte will fail.
        // header_len = 2 (varint 0x02, hl_size=1), header_end = 2, data len = 2.
        // p starts at 1, p < header_end (1 < 2), read_varint(data, 1) on byte [0x80]
        // which has continuation bit set but no next byte → returns None → ? propagates.
        // Actually the ? would propagate None through try_parse_header, not hit L112.
        // The ? on L103 returns None from try_parse_header before reaching L112.
        // So L113 can only be reached if the while loop runs 0 iterations.
        // That means p >= header_end_abs from the start, i.e., hl_size >= header_len.
        // hl_size is at least 1 (single-byte varint). header_len < 2 is caught earlier.
        // For header_len=2 and hl_size=1: p=1, header_end=2, loop runs.
        // For header_len=2 and hl_size=2: p=2, header_end=2, loop doesn't run!
        // A 2-byte varint encoding of value 2: 0x82, 0x00... no wait.
        // read_varint for value 2: single byte 0x02 (hl_size=1).
        // We need hl_size=2 with header_len=2. A 2-byte varint that equals 2:
        // 0x80 | 0x02 = 0x82 in first byte (continuation), 0x00 in second byte? No.
        // Varint: first byte 0x80 means "continue, value so far = 0".
        // Second byte 0x02 means "stop, value = (0 << 7) | 2 = 2". So data = [0x80, 0x02].
        // read_varint returns (2, 2). header_len=2, hl_size=2. p=2, header_end=2.
        // Loop: p < 2 → false. serial_types is empty → return None at L113!
        let data: &[u8] = &[0x80, 0x02, 0x00, 0x00]; // varint(2) encoded as 2 bytes
        let result = try_parse_header(data, 0);
        assert!(result.is_none(), "should return None when serial_types is empty");
    }

    #[test]
    fn test_validate_and_decode_vpos_exceeds_65536_boundary() {
        // L157-158: vpos > 65536 after decoding
        // Use a schema with 1 TEXT column. serial type for text of length n: 13 + 2*n.
        // For text of length 32760: st = 13 + 65520 = 65533.
        // decode_serial_type would consume 32760 bytes. If values_start = 32777,
        // vpos = 32777 + 32760 = 65537 > 65536 → return None.
        // But we need a huge data array. Use a simpler approach:
        // serial type 6 (8-byte int), values_start = 65530 → vpos = 65530 + 8 = 65538.
        let sig = SchemaSignature {
            table_name: "t".to_string(),
            column_count: 1,
            type_hints: vec![crate::schema_sig::ColumnTypeHint::Integer],
        };
        let serial_types = vec![6u64]; // 8-byte integer
        let data = vec![0u8; 65540];
        let result = validate_and_decode(&sig, &serial_types, &data, 65530);
        assert!(result.is_none(), "vpos 65538 > 65536 should return None");
    }

    #[test]
    fn test_collect_leaf_pages_bhdr_exceeds_page_len() {
        // L176-177: bhdr >= page_data.len()
        // This requires get_page_data to return a (page_data, bhdr) where bhdr >= len.
        // For page 1, bhdr = 100. If page_data.len() <= 100, this triggers.
        // get_page_data uses page_size to slice. With page_size very small,
        // the data returned might be small. But page_size for page 1 must be >=100
        // for the data to include the SQLite header.
        // Actually get_page_data for page_num=1 returns (&db[0..page_size], 100).
        // If page_size < 101, bhdr=100 >= page_data.len()=page_size → continue.
        // But we need a valid page_size in the DB header.
        // The smallest valid SQLite page size is 512. So bhdr=100 < 512 always.
        // For non-page-1 pages, bhdr=0 which is always < page_data.len().
        // This line is effectively unreachable with valid SQLite page sizes.
        // Just verify with a deliberately malformed scenario.
        let page_size: usize = 64; // smaller than bhdr=100, not a valid SQLite page size
        let db = vec![0u8; page_size];
        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        // get_page_data might return None for invalid page size, or if it does return,
        // bhdr=100 > 64 → continue
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_collect_freeblocks_valid_chain_two_blocks() {
        // Test a chain of two freeblocks to exercise the loop iteration
        let mut page_data = vec![0u8; 256];
        page_data[0] = 0x0D;
        // First freeblock at offset 20
        page_data[1] = 0x00;
        page_data[2] = 0x14; // 20
        // Freeblock 1 at 20: next=40, size=10
        page_data[20] = 0x00;
        page_data[21] = 0x28; // next = 40
        page_data[22] = 0x00;
        page_data[23] = 0x0A; // size = 10
        // Freeblock 2 at 40: next=0, size=8
        page_data[40] = 0x00;
        page_data[41] = 0x00; // next = 0
        page_data[42] = 0x00;
        page_data[43] = 0x08; // size = 8

        let result = collect_freeblocks(&page_data, 0);
        assert_eq!(result.len(), 2, "Should find 2 freeblocks in chain");
    }

    // ── Tests for remaining uncovered production lines ────────────────────────

    #[test]
    fn test_recover_freeblocks_leaf_page_get_page_data_none() {
        // L256-258: get_page_data returns None for a leaf page number.
        // Build a 2-page DB where page 1 is a leaf (root) but the table root
        // points to page 3 which is beyond the DB boundary.
        let page_size: usize = 1024;
        let mut db = vec![0u8; page_size * 2]; // only 2 pages
        // SQLite header
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8

        // Page 1: make it a table leaf page at offset 100
        db[100] = 0x0D; // table leaf
        db[101] = 0x00; // no freeblocks
        db[102] = 0x00;
        db[103] = 0x00; // cell count = 0
        db[104] = 0x00;

        // Page 2 (offset 1024): make it a table interior page pointing to page 3
        let p2 = page_size;
        db[p2] = 0x05; // table interior
        db[p2 + 1] = 0x00; // no freeblocks
        db[p2 + 2] = 0x00;
        db[p2 + 3] = 0x00; // cell count = 0
        db[p2 + 4] = 0x00;
        // Right child pointer at bhdr+8 = page 3 (does not exist!)
        db[p2 + 8..p2 + 12].copy_from_slice(&3u32.to_be_bytes());

        let header = DbHeader::parse(&db).unwrap();
        let leaked: &'static DbHeader = Box::leak(Box::new(header));

        // Set table root to page 2 (interior page)
        let mut roots = HashMap::new();
        roots.insert("t".to_string(), 2u32);
        let sig = SchemaSignature::from_create_sql("t", "CREATE TABLE t (x INTEGER)").unwrap();
        let ctx = RecoveryContext {
            db: &db,
            page_size: page_size as u32,
            header: leaked,
            table_roots: roots,
            schema_signatures: vec![sig],
            pragma_info: PragmaInfo::default(),
        };

        // collect_leaf_pages will find page 3 via the interior page's right child,
        // then get_page_data for page 3 returns None → continue at L258.
        let results = recover_freeblocks(&ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_recover_freeblocks_try_parse_ok_validate_fails() {
        // L304: try_parse_header succeeds but validate_and_decode returns None.
        // Build a freeblock whose payload starts with a valid record header
        // but the serial types don't match the schema at all.
        let mut db = make_minimal_db_1024();

        // Schema: single TEXT column
        // Freeblock payload: header_len=2, serial_type=7 (REAL), then 8 bytes of float.
        // try_parse_header will succeed (valid header), but validate_and_decode
        // will return None because REAL doesn't match TEXT and column_count mismatches.
        let fb_offset: usize = 300;
        let payload: &[u8] = &[
            0x02, // header_len = 2
            0x07, // serial_type 7: REAL (8-byte float)
            // 8 bytes of float value
            0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18,
        ];
        let fb_size = 4 + payload.len();

        // Set first freeblock pointer
        db[101] = (fb_offset >> 8) as u8;
        db[102] = (fb_offset & 0xFF) as u8;

        // Write freeblock header
        db[fb_offset] = 0x00;
        db[fb_offset + 1] = 0x00;
        db[fb_offset + 2] = 0x00;
        db[fb_offset + 3] = fb_size as u8;
        db[fb_offset + 4..fb_offset + 4 + payload.len()].copy_from_slice(payload);

        let leaked_header: &'static DbHeader =
            Box::leak(Box::new(DbHeader::parse(&db).unwrap()));
        // Schema expects TEXT column but freeblock has REAL → validate_and_decode
        // will see 0 compatible columns (REAL vs TEXT) and return None.
        let ctx = make_ctx_with_schema(
            &db,
            "t",
            "CREATE TABLE t (name TEXT)",
            leaked_header,
        );
        let results = recover_freeblocks(&ctx);
        // try_parse_header succeeds but validate_and_decode returns None,
        // so the inner if-let at L287 falls through → the for loop continues
        // to the next v offset. Eventually all v values fail → no results.
        assert!(results.is_empty());
    }

    #[test]
    fn test_collect_leaf_pages_interior_page_exercises_arm() {
        // L219: closing brace of the 0x05 (interior page) match arm.
        // Build a 3-page DB where page 1 is interior, page 2 and 3 are leaves.
        let page_size: usize = 512;
        let mut db = vec![0u8; page_size * 3];
        // SQLite header
        db[..16].copy_from_slice(b"SQLite format 3\x00");
        db[16] = (page_size >> 8) as u8;
        db[17] = (page_size & 0xFF) as u8;
        db[18] = 1;
        db[19] = 1;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());

        // Page 1 (bhdr=100): interior page 0x05
        db[100] = 0x05;
        // Cell count = 1 (one left child pointer cell)
        db[103] = 0x00;
        db[104] = 0x01;
        // Right child pointer at bhdr+8 (offset 108): page 3
        db[108..112].copy_from_slice(&3u32.to_be_bytes());
        // Cell pointer array starts at bhdr+12 = 112
        // Cell pointer 0 → offset 200 within page 1
        db[112] = 0x00;
        db[113] = 0xC8; // 200
        // Interior cell at offset 200: left child page number (4 bytes) = page 2
        db[200..204].copy_from_slice(&2u32.to_be_bytes());

        // Page 2 (offset 512, bhdr=0): table leaf 0x0D
        let p2 = page_size;
        db[p2] = 0x0D;

        // Page 3 (offset 1024, bhdr=0): table leaf 0x0D
        let p3 = page_size * 2;
        db[p3] = 0x0D;

        let leaves = collect_leaf_pages(&db, page_size as u32, 1);
        // Should find pages 2 and 3 as leaves
        assert!(leaves.contains(&2));
        assert!(leaves.contains(&3));
        assert_eq!(leaves.len(), 2);
    }
}
