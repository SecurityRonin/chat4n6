/// Split a slice into pages of at most `page_size` items.
pub fn paginate<T: Clone>(items: &[T], page_size: usize) -> Vec<Vec<T>> {
    if items.is_empty() || page_size == 0 {
        return Vec::new();
    }
    items.chunks(page_size).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginate_750_into_2_pages() {
        let items: Vec<i32> = (0..750).collect();
        let pages = paginate(&items, 500);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].len(), 500);
        assert_eq!(pages[1].len(), 250);
    }

    #[test]
    fn test_paginate_exact_fit() {
        let items: Vec<i32> = (0..500).collect();
        let pages = paginate(&items, 500);
        assert_eq!(pages.len(), 1);
    }

    #[test]
    fn test_paginate_empty() {
        let items: Vec<i32> = Vec::<i32>::new();
        let pages = paginate(&items, 500);
        assert!(pages.is_empty());
    }

    #[test]
    fn test_paginate_fewer_than_page_size() {
        let items: Vec<i32> = (0..3).collect();
        let pages = paginate(&items, 500);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].len(), 3);
    }
}
