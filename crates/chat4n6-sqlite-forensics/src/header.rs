pub const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

pub fn is_sqlite_header(data: &[u8]) -> bool {
    data.len() >= 16 && &data[..16] == SQLITE_MAGIC
}

#[derive(Debug)]
pub struct DbHeader {
    pub page_size: u32,
    pub page_count: u32,
    pub freelist_trunk_page: u32,
    pub freelist_page_count: u32,
    pub user_version: u32,
    pub text_encoding: u32,
}

impl DbHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !is_sqlite_header(data) || data.len() < 100 {
            return None;
        }
        let page_size = {
            let raw = u16::from_be_bytes([data[16], data[17]]) as u32;
            if raw == 1 {
                65536
            } else {
                raw
            }
        };
        Some(Self {
            page_size,
            page_count: u32::from_be_bytes([data[28], data[29], data[30], data[31]]),
            freelist_trunk_page: u32::from_be_bytes([data[32], data[33], data[34], data[35]]),
            freelist_page_count: u32::from_be_bytes([data[36], data[37], data[38], data[39]]),
            text_encoding: u32::from_be_bytes([data[56], data[57], data[58], data[59]]),
            user_version: u32::from_be_bytes([data[60], data[61], data[62], data[63]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_header_magic() {
        assert!(is_sqlite_header(b"SQLite format 3\x00some more bytes"));
        assert!(!is_sqlite_header(b"not sqlite"));
    }

    #[test]
    fn test_db_header_parse_valid() {
        // Minimal 100-byte buffer: magic + zeros for the rest
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        // page_size = 4096 at bytes 16-17
        buf[16] = 0x10;
        buf[17] = 0x00;
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.page_size, 4096);
    }

    #[test]
    fn test_db_header_parse_invalid() {
        assert!(DbHeader::parse(b"not sqlite").is_none());
        assert!(DbHeader::parse(b"SQLite format 3\x00").is_none()); // too short (< 100 bytes)
    }

    #[test]
    fn test_page_size_65536() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x00;
        buf[17] = 0x01; // raw value 1 → 65536
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.page_size, 65536);
    }

    #[test]
    fn test_page_size_512() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x02;
        buf[17] = 0x00; // 512
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.page_size, 512);
    }

    #[test]
    fn test_header_truncated_99_bytes() {
        let mut buf = vec![0u8; 99];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        assert!(DbHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_header_exactly_100_bytes() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10; // 4096
        assert!(DbHeader::parse(&buf).is_some());
    }

    #[test]
    fn test_is_sqlite_header_empty() {
        assert!(!is_sqlite_header(&[]));
    }

    #[test]
    fn test_is_sqlite_header_15_bytes() {
        assert!(!is_sqlite_header(b"SQLite format 3"));
    }

    #[test]
    fn test_is_sqlite_header_near_miss() {
        assert!(!is_sqlite_header(b"SQLite format 3\x01"));
    }

    #[test]
    fn test_header_freelist_fields() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10;
        buf[32..36].copy_from_slice(&5u32.to_be_bytes());
        buf[36..40].copy_from_slice(&3u32.to_be_bytes());
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.freelist_trunk_page, 5);
        assert_eq!(hdr.freelist_page_count, 3);
    }

    #[test]
    fn test_header_text_encoding() {
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16] = 0x10;
        buf[56..60].copy_from_slice(&2u32.to_be_bytes());
        let hdr = DbHeader::parse(&buf).unwrap();
        assert_eq!(hdr.text_encoding, 2);
    }
}
