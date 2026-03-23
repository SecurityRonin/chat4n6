use crate::header::DbHeader;
use crate::pragma::PragmaInfo;
use crate::schema_sig::SchemaSignature;
use std::collections::HashMap;

/// Shared immutable state for all recovery layers.
pub struct RecoveryContext<'a> {
    pub db: &'a [u8],
    pub page_size: u32,
    pub header: &'a DbHeader,
    pub table_roots: HashMap<String, u32>,
    pub schema_signatures: Vec<SchemaSignature>,
    pub pragma_info: PragmaInfo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DbHeader;
    use crate::pragma::{parse_pragma_info, PragmaInfo};

    fn make_minimal_db() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // page_size bytes[16..17] = 0x1000 → 4096
        buf[17] = 0x00;
        buf[18] = 1;
        buf[19] = 1;
        buf[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        buf
    }

    #[test]
    fn test_recovery_context_construction() {
        let db = make_minimal_db();
        let header = DbHeader::parse(&db).expect("valid header");
        let pragma_info = parse_pragma_info(&header, &db);
        let page_size = header.page_size;

        let ctx = RecoveryContext {
            db: &db,
            page_size,
            header: &header,
            table_roots: HashMap::new(),
            schema_signatures: Vec::new(),
            pragma_info,
        };

        assert_eq!(ctx.page_size, 4096);
        assert!(ctx.table_roots.is_empty());
        assert!(ctx.schema_signatures.is_empty());
        assert_eq!(ctx.pragma_info.user_version, 0);
    }

    #[test]
    fn test_recovery_context_with_table_roots() {
        let db = make_minimal_db();
        let header = DbHeader::parse(&db).expect("valid header");
        let pragma_info = PragmaInfo::default();

        let mut roots = HashMap::new();
        roots.insert("messages".to_string(), 2u32);
        roots.insert("contacts".to_string(), 3u32);

        let ctx = RecoveryContext {
            db: &db,
            page_size: header.page_size,
            header: &header,
            table_roots: roots,
            schema_signatures: Vec::new(),
            pragma_info,
        };

        assert_eq!(ctx.table_roots.get("messages"), Some(&2u32));
        assert_eq!(ctx.table_roots.get("contacts"), Some(&3u32));
    }
}
