use std::borrow::Cow;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use memmap2::Mmap;

#[derive(Debug, Clone)]
pub struct DarEntry {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub permissions: u32,
    pub slice_index: usize,
    pub data_offset: u64,
}

// DarArchive intentionally omits Debug and Clone — memmap2::Mmap does not implement those traits.
pub struct DarArchive {
    mmaps: Vec<Mmap>,
    entries: Vec<DarEntry>,
}

impl DarArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        // SAFETY: file is read-only and not modified while mapped.
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("cannot mmap {}", path.display()))?;
        let mut archive = Self { mmaps: vec![mmap], entries: Vec::new() };
        archive.load_catalog(0)?;
        Ok(archive)
    }

    /// Open a multi-slice archive given the basename (no slice number, no extension).
    ///
    /// Example: `open_slices(Path::new("/path/to/userdata"))` opens
    /// `userdata.1.dar`, `userdata.2.dar`, … until no next slice is found.
    ///
    /// The catalog lives only in the last (terminal) slice; earlier slices
    /// contain only file data.
    pub fn open_slices(basename: &Path) -> Result<Self> {
        let parent = basename.parent().unwrap_or(Path::new("."));
        let stem = basename
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid basename: {}", basename.display()))?;

        let mut mmaps = Vec::new();
        let mut slice_num = 1usize;
        loop {
            let slice_path = parent.join(format!("{stem}.{slice_num}.dar"));
            if !slice_path.exists() {
                break;
            }
            let file = std::fs::File::open(&slice_path)
                .with_context(|| format!("cannot open {}", slice_path.display()))?;
            // SAFETY: read-only mapping; file not modified while mapped.
            let mmap = unsafe { Mmap::map(&file) }
                .with_context(|| format!("cannot mmap {}", slice_path.display()))?;
            mmaps.push(mmap);
            slice_num += 1;
        }
        anyhow::ensure!(
            !mmaps.is_empty(),
            "no slices found for basename: {}",
            basename.display()
        );

        let last = mmaps.len() - 1;
        let mut archive = Self { mmaps, entries: Vec::new() };
        // Catalog is in the last (terminal) slice only.
        archive.load_catalog(last)?;
        Ok(archive)
    }

    pub fn entries(&self) -> &[DarEntry] {
        &self.entries
    }

    pub fn read<'a>(&'a self, entry: &DarEntry) -> Result<Cow<'a, [u8]>> {
        anyhow::ensure!(
            !entry.is_dir,
            "cannot read directory entry: {}",
            entry.path.display()
        );
        let mmap = &self.mmaps[entry.slice_index];
        let start = entry.data_offset as usize;
        let end = start + entry.size as usize;
        anyhow::ensure!(end <= mmap.len(), "entry data out of bounds: {}", entry.path.display());
        Ok(Cow::Borrowed(&mmap[start..end]))
    }

    fn load_catalog(&mut self, slice_index: usize) -> Result<()> {
        let data: &[u8] = &self.mmaps[slice_index];

        // Locate catalog boundaries within this slice.
        let catalog_start = crate::scanner::find_catalog_start(data)
            .ok_or_else(|| anyhow::anyhow!(
                "cannot find catalog start in slice {slice_index} \
                 (no escape marker or 'droot\\0' pattern in last 200 MB)"
            ))?;

        let zzzzz_pos = crate::scanner::find_last_zzzzz(data)
            .ok_or_else(|| anyhow::anyhow!(
                "cannot find catalog end (zzzzz) in slice {slice_index} \
                 (not found in last 100 MB)"
            ))?;

        anyhow::ensure!(
            catalog_start < zzzzz_pos,
            "catalog start ({catalog_start}) is not before catalog end ({zzzzz_pos}) \
             in slice {slice_index}"
        );

        // Include the zzzzz itself so the parser can recognise the terminator.
        let catalog_data = &data[catalog_start..zzzzz_pos + 5];
        let mut new_entries =
            crate::catalog::parse_catalog(catalog_data, slice_index)
                .with_context(|| format!("parsing catalog in slice {slice_index}"))?;
        self.entries.append(&mut new_entries);
        Ok(())
    }
}
