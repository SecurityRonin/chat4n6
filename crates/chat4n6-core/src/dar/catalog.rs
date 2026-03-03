use std::collections::HashMap;

/// A file entry in the DAR catalog.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub path: String,
    pub data_offset: u64,
    pub data_size: u64,
    pub is_dir: bool,
}

/// In-memory catalog: path → entry.
pub type Catalog = HashMap<String, CatalogEntry>;
