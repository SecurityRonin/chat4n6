pub struct Freeblock {
    pub offset: usize,
    pub size: usize,
    pub data: Vec<u8>,
}

/// Walk the freeblock linked list within a single page.
///
/// The B-tree page header for a leaf page (8 bytes) has:
///   +0: page type
///   +1-2: first freeblock offset (0 = none)
///   +3-4: cell count
///   +5-6: cell content area start
///   +7: fragmented bytes count
///
/// Each freeblock starts with: [next: u16][size: u16][data: size-4 bytes]
/// The chain ends when next == 0.
pub fn parse_freeblock_chain(page: &[u8], _page_size: usize) -> Vec<Freeblock> {
    let mut freeblocks = Vec::new();
    if page.len() < 4 {
        return freeblocks;
    }

    // First freeblock offset is at bytes 1-2 of the page header
    let first_fb = if page.len() >= 3 {
        u16::from_be_bytes([page[1], page[2]]) as usize
    } else {
        return freeblocks;
    };

    let mut fb_offset = first_fb;
    let mut visited = std::collections::HashSet::new();

    while fb_offset != 0 && fb_offset + 4 <= page.len() {
        if !visited.insert(fb_offset) {
            break; // cycle guard
        }
        let next = u16::from_be_bytes([page[fb_offset], page[fb_offset + 1]]) as usize;
        let size = u16::from_be_bytes([page[fb_offset + 2], page[fb_offset + 3]]) as usize;

        // Sanity check: size must be at least 4 (header), and must fit in page
        if size < 4 || fb_offset + size > page.len() {
            break;
        }

        let data = page[fb_offset + 4..fb_offset + size].to_vec();
        freeblocks.push(Freeblock {
            offset: fb_offset,
            size,
            data,
        });

        fb_offset = next;
    }

    freeblocks
}

/// Walk the freelist trunk→leaf chain.
///
/// SQLite freelist format:
///   Trunk page layout (from byte 0 of page):
///     +0-3: next trunk page number (0 = last trunk)
///     +4-7: number of leaf page numbers on this trunk
///     +8..: leaf page numbers (4 bytes each)
///
/// Returns all freed page numbers (trunk and leaf pages included).
pub fn walk_freelist_chain(db: &[u8], trunk_page: u32, page_size: u32) -> Vec<u32> {
    let mut pages = Vec::new();
    if trunk_page == 0 || db.is_empty() {
        return pages;
    }

    let mut current = trunk_page;
    let mut visited = std::collections::HashSet::new();

    while current != 0 {
        if !visited.insert(current) {
            break; // cycle guard
        }
        let page_start = (current as usize - 1) * page_size as usize;
        let page_end = page_start + page_size as usize;
        let Some(page) = db.get(page_start..page_end) else {
            break;
        };

        if page.len() < 8 {
            break;
        }

        let next_trunk = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let leaf_count = u32::from_be_bytes([page[4], page[5], page[6], page[7]]) as usize;

        pages.push(current); // trunk page itself is a freed page

        // Read leaf page numbers
        for i in 0..leaf_count {
            let leaf_off = 8 + i * 4;
            if leaf_off + 4 > page.len() {
                break;
            }
            let leaf_page = u32::from_be_bytes([
                page[leaf_off],
                page[leaf_off + 1],
                page[leaf_off + 2],
                page[leaf_off + 3],
            ]);
            if leaf_page != 0 {
                pages.push(leaf_page);
            }
        }

        current = next_trunk;
    }

    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freelist_chain_empty() {
        let chains = walk_freelist_chain(&[], 0, 4096);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_freeblock_chain_parse() {
        let mut page = vec![0u8; 4096];
        page[0] = 0x0d; // table leaf page type
        // first freeblock at offset 200
        page[1] = 0x00;
        page[2] = 0xc8;
        // freeblock at 200: next=0, size=20
        page[200] = 0x00;
        page[201] = 0x00; // next = 0
        page[202] = 0x00;
        page[203] = 0x14; // size = 20
        for i in 204..220 {
            page[i] = (i % 256) as u8;
        }

        let freeblocks = parse_freeblock_chain(&page, 4096);
        assert_eq!(freeblocks.len(), 1);
        assert_eq!(freeblocks[0].offset, 200);
        assert_eq!(freeblocks[0].size, 20);
    }
}
