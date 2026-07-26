# dar-archive

Pure-Rust reader for **DAR** (Disk ARchive) archives, part of the
[chat4n6](https://github.com/SecurityRonin/chat4n6) forensic toolkit.

Reads DAR catalogs and extracts file contents with no external `libdar`
dependency — the archive is memory-mapped and file bytes are returned
zero-copy (`Cow::Borrowed`) straight from the mapping.

## Features

- Single-file (`.dar`) and multi-slice (`name.1.dar`, `name.2.dar`, …) archives.
- Catalog parsing into `DarEntry` records (path, size, directory flag, Unix
  permissions, slice index, data offset).
- Bounds-checked reads — an entry whose data would fall outside its slice is
  rejected rather than read out of range.

## Usage

```rust
use dar_archive::DarArchive;
use std::path::Path;

// Single-file archive.
let archive = DarArchive::open(Path::new("evidence.1.dar"))?;

// Or a multi-slice set, given the basename (no slice number, no extension):
// let archive = DarArchive::open_slices(Path::new("evidence"))?;

for entry in archive.entries() {
    if entry.is_dir {
        continue;
    }
    let bytes = archive.read(entry)?;
    println!("{} ({} bytes)", entry.path.display(), bytes.len());
}
# Ok::<(), anyhow::Error>(())
```

For a multi-slice set the catalog lives only in the last (terminal) slice;
earlier slices hold file data.

## License

MIT
