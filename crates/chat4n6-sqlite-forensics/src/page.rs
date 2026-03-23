#[derive(Debug, Clone, PartialEq)]
pub enum PageType {
    TableLeaf,         // 0x0D
    TableInterior,     // 0x05
    IndexLeaf,         // 0x0A
    IndexInterior,     // 0x02
    OverflowOrDropped, // 0x00
}

impl PageType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x0d => Some(Self::TableLeaf),
            0x05 => Some(Self::TableInterior),
            0x0a => Some(Self::IndexLeaf),
            0x02 => Some(Self::IndexInterior),
            0x00 => Some(Self::OverflowOrDropped),
            _ => None,
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::TableLeaf | Self::IndexLeaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_type_detection() {
        assert_eq!(PageType::from_byte(0x0d), Some(PageType::TableLeaf));
        assert_eq!(PageType::from_byte(0x0a), Some(PageType::IndexLeaf));
        assert_eq!(PageType::from_byte(0x05), Some(PageType::TableInterior));
        assert_eq!(PageType::from_byte(0x00), Some(PageType::OverflowOrDropped));
        assert_eq!(PageType::from_byte(0x99), None);
    }

    #[test]
    fn test_page_type_index_interior() {
        assert_eq!(PageType::from_byte(0x02), Some(PageType::IndexInterior));
    }

    #[test]
    fn test_page_type_invalid_bytes() {
        assert_eq!(PageType::from_byte(0x01), None);
        assert_eq!(PageType::from_byte(0x03), None);
        assert_eq!(PageType::from_byte(0xFF), None);
        assert_eq!(PageType::from_byte(0x0B), None);
        assert_eq!(PageType::from_byte(0x0E), None);
    }

    #[test]
    fn test_is_leaf_table_leaf() {
        assert!(PageType::TableLeaf.is_leaf());
    }

    #[test]
    fn test_is_leaf_index_leaf() {
        assert!(PageType::IndexLeaf.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_table_interior() {
        assert!(!PageType::TableInterior.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_index_interior() {
        assert!(!PageType::IndexInterior.is_leaf());
    }

    #[test]
    fn test_is_not_leaf_overflow_or_dropped() {
        assert!(!PageType::OverflowOrDropped.is_leaf());
    }
}
