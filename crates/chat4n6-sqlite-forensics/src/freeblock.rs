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

        assert!(
            !results.is_empty(),
            "expected at least one recovered record from crafted freeblock"
        );
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
}
