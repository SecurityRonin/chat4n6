# DAR Format Specification Notes

Extracted from:
- https://darbinding.sourceforge.net/specs/dar5.html (DAR5 spec)
- https://darbinding.sourceforge.net/specs/darK06.html (Kaylix K06 draft)

---

## 1. Catalog Entry Type Bytes (Signature Byte)

The **first byte** of every catalog entry encodes both the **entry type** (low 7 bits, ASCII character) and the **saved status** (MSB, bit 7).

### Full Table of All 11 Entry Types

| Entry Type              | Char | Saved (MSB=0) | Unsaved (MSB=1) |
|-------------------------|------|---------------|-----------------|
| regular file            | `f`  | `0x66`        | `0xE6`          |
| symbolic link           | `l`  | `0x6C`        | `0xEC`          |
| character device        | `c`  | `0x63`        | `0xE3`          |
| block device            | `b`  | `0x62`        | `0xE2`          |
| pipe                    | `p`  | `0x70`        | `0xF0`          |
| socket                  | `s`  | `0x73`        | `0xF3`          |
| directory               | `d`  | `0x64`        | `0xE4`          |
| ignored directory       | `d`  | `0x64`        | `0xE4`          | ← same signature as directory
| hard link label         | `h`  | `0x68`        | `0xE8`          |
| regular file label      | `e`  | `0x65`        | `0xE5`          |
| ignored (door/unknown)  | `x`  | `0x78`        | `0xF8`          |
| end-of-directory (EOD)  | `z`  | `0x7A`        | N/A             |

> **Note:** The spec says 11 valid entry types including 7 POSIX types and 4 catalog-specific types.
> The 4 catalog-specific types are: EOD (`z`), hard link label (`h`), regular file label (`e`), deleted file marker.
> Deleted file marker uses the NOMME header — its signature byte comes from the *original* type of the deleted entry.

---

## 2. Signature Byte Encoding (from libdar cat_signature.cpp)

```
Encoding formula (confirmed from libdar source):
  field = (saved_status << 5) | (type_char & 0x1F)

Decoding:
  type_char = (field & 0x1F) | 0x60
  status    = field >> 5
```

### saved_status values (from libdar)
| Value | Name | Meaning |
|-------|------|---------|
| 1 | `s_delta` | delta patch (rarely seen) |
| 2 | `s_not_saved` | isolated catalog, no data |
| 3 | `s_saved` | full data saved in archive |
| 4 | `s_inode_only` | inode only (EA/FSA saved, no data) |
| 7 | `s_fake` | fake entry (mirage) |

The earlier "bit 7" model was **incorrect**. The correct formula is `status = byte >> 5`.

---

## 3. String / Name Storage

- **Encoding:** UTF-8
- **Termination:** **Null-terminated** (`\0` byte at end)
- **Name content:** Basename only — no path component. Full path is reconstructed by traversing the directory tree structure.

From the spec: *"All characters are stored in UTF-8. Strings are null-terminated arrays."*
From the `nomme` format: *"name_string: Null terminated string containing the name of the object (path not included)."*

**Exception:** EA values are NOT null-terminated. EA keys ARE null-terminated.

---

## 4. Infinint Encoding

The infinint is a variable-length big-endian integer.

```
Layout diagram from spec:
+....+....+....+----+....+....+....+....+
| 00 | 00 | 00 | BB | XX | XX | XX | XX |
+....+....+....+----+....+....+....+....+
  (1) preamble   (2) payload
```

### Preamble (length indicator)

- **N zero bytes** (one per group of 8 blocks in the payload)
- **1 bitfield byte (BB):** indicates how many 4-byte integers are in the final partial group (0–7 extra integers beyond the N×8 groups)

```
Bitfield byte layout:
+-------------------------------+
| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
+---+---+---+---+---+---+---+---+
| 1 | - | - | - | - | - | - | - |  → 1 extra 4-byte int
| - | 1 | - | - | - | - | - | - |  → 2 extra 4-byte ints
| - | - | 1 | - | - | - | - | - |  → 3 extra 4-byte ints
  ...
| - | - | - | - | - | - | - | 1 |  → 0 extra 4-byte ints (just the N×8 groups)
+-------------------------------+
```

### Payload
- `N` bytes (or more precisely: N×8×4 + extra×4 bytes)
- Stored in **network byte order (MSB / big-endian)**

### Simplified practical decoding (as implemented in existing code)

The existing `decode_infinint` in this codebase uses a simpler model:
- **First byte non-zero** → single-byte value: `value = first_byte`, consumed = 1 byte
- **N leading zero bytes** → read next N bytes as big-endian unsigned integer, consumed = 2×N bytes

This simplified model works for small values (common case: names, offsets, sizes < 64KB).

---

## 5. Entry Type Hierarchy

```
entree
├── EOD                     (z / 0x7A)
└── nomme                   (has name_string)
    ├── hard link label     (h / 0x68)
    ├── deleted file marker (type byte = original type | 0x80? — uses nomme + orig sig)
    └── inode               (has UID/GID/perm/atime/mtime)
        ├── symbolic link   (l / 0x6C)
        ├── device
        │   ├── character   (c / 0x63)
        │   └── block       (b / 0x62)
        ├── directory       (d / 0x64)
        ├── ignored dir     (d / 0x64)
        ├── file            (f / 0x66)
        │   └── file label  (e / 0x65)
        ├── socket          (s / 0x73)
        └── pipe            (p / 0x70)
```

---

## 6. File Entry (inode_file / `f`) Structure

```
+---------------------+---------------+-------------------+-------+
| INODE header dump   | size / offset | storage_size / crc|       |
+---------------------+-------\-------+-----------\-------+-------+
```

Fields (in order):
1. **signature** — `0x66` (saved) or `0xE6` (unsaved), from INODE header
2. **EA flag** — 1 byte: `ea_none=0x00`, `ea_partial=0x01`, `ea_full=0x02`
3. **UID** — 16-bit word (big-endian), POSIX user ID
4. **GID** — 16-bit word (big-endian), POSIX group ID
5. **permissions** — 16-bit word (big-endian), lower 16 bits of `st_mode` (chmod bits)
6. **atime** — infinint, time of last access
7. **mtime** — infinint, time of last modification
8. *(conditional)* **ea_offset** — infinint, offset to EA data (only if `ea_full`)
9. *(conditional)* **ea_crc** — 16-bit word, CRC of EA data (only if `ea_full`)
10. *(conditional)* **ea_ctime** — infinint, time of last EA modification (if `ea_partial` or `ea_full`)
11. **size** — infinint, original file size
12. *(conditional)* **offset** — infinint, offset to file data in archive (absent if unsaved/isolated)
13. *(conditional)* **storage_size** — infinint, compressed size in archive; `0` means same as original size (absent if unsaved/isolated)
14. **crc** — 16-bit word, CRC of original file data

The NOMME header wraps the INODE header:
- **nomme** = `sig` (1 byte) + `name_string` (null-terminated UTF-8)

So full on-disk file entry = `sig` + `name_string\0` + `ea_flag` + `UID` + `GID` + `perm` + `atime` + `mtime` + [ea fields] + `size` + [`offset`] + [`storage_size`] + `crc`

---

## 7. Directory Entry (`d` / `0x64`) Structure

```
+---------------------+---catalog entries---+-----+
| INODE header dump   | (child entries)     | EOD |
+---------------------+---------------------+-----+
```

Fields:
1. **signature** — `0x64` (saved) or `0xE4` (unsaved)
2. **EA flag** — 1 byte (same as file entry)
3. **UID** — 16-bit word
4. **GID** — 16-bit word
5. **permissions** — 16-bit word
6. **atime** — infinint
7. **mtime** — infinint
8. *(conditional)* ea_offset, ea_crc, ea_ctime

- Followed immediately by child entries (recursively)
- Terminated by an **EOD entry** (`0x7A`)
- An empty directory has one EOD immediately after the directory entry

The nomme header precedes everything: `sig` + `name_string\0`

**Root directory:** The first catalog entry is always a special root directory; its presence must be verified and it must not be treated as a real directory.

---

## 8. UID / GID / Permissions Storage

From spec verbatim:
- **UID:** *"16-bit word containing POSIX user identification number."*
- **GID:** *"16-bit word containing POSIX group identification number."*
- **permissions:** *"16-bit word containing POSIX mode and permissions."* (see `man 2 chmod`)

All three are stored in **big-endian (MSB) order** as 16-bit unsigned integers.

From the stat structure commentary:
```
mode_t st_mode;  /* Lower 16 bits (permissions) stored in Inode header.
                  * File type bits stored implicitly as entry type. */
uid_t  st_uid;   /* Stored in Inode header. */
gid_t  st_gid;   /* Stored in Inode header. */
```

Note: On most POSIX systems UID/GID are 16-bit; the spec stores them that way (unlike sizes which use infinint).

---

## 9. Catalog Terminator / Slice Structure

### Slice Header (beginning of every .dar file)

```
+-------+----------+------+-----------+................+
| magic | internal | last | extension | extension      |
| num.  | name     | flag | flag      | data           |
+-------+----------+------+-----------+................+
```

| Field         | Size    | Value / Notes                              |
|---------------|---------|--------------------------------------------|
| magic number  | 4 bytes | `SAUV_MAGIC_NUMBER = 123` → `0x0000007B`  |
| internal name | 10 bytes| Unique archive identifier (timestamp+pid)  |
| last flag     | 1 byte  | `FLAG_NON_TERMINAL = 'N'` → `0x4E`        |
|               |         | `FLAG_TERMINAL = 'T'` → `0x54`            |
| extension flag| 1 byte  | Indicates if extension data follows        |

### Catalog Terminator

The catalog **ends** (and the archive ends) at:
- A **second `zzzzz` sequence** (5 × `0x7A` / EOD bytes), or equivalently a sequence of EOD entries closing out all open directories back to root
- The `FLAG_TERMINAL` (`0x54` / `'T'`) in the slice header indicates this is the final slice

### Catalog Location

```
+--------+---------------------+-----------+------+
| slice  | file data + EA      | catalogue | term |
| header |                     |           |      |
+--------+---------------------+-----------+------+
                               ^
                        catalog offset (stored in slice header extension)
```

The first `zzzzz` (5 × `0x7A`) separates file data from the catalog section.

---

## 10. Extended Attribute Data

Stored **after** the file data in the data section. Format:

```
+---------+--[ EA entries ]--+
| count   | key\0 | val_size | val |
| (infint)|       | (infint) |     |
+---------+------------------+-----+
```

- **key:** null-terminated string
- **value_size:** infinint
- **value:** raw bytes, NOT null-terminated
- Prepended by an infinint indicating the number of EA entries

EA flag in inode header:
- `ea_none = 0x00` — no EAs stored
- `ea_partial = 0x01` — partial (ctime only, catalog isolated)
- `ea_full = 0x02` — full EA data in archive

---

## 11. Hard Link Label Format

```
+--------------+-----------+
| NOMME header | etiquette |
+--------------+-----------+
```

- **signature:** `h` / `0x68`
- **etiquette:** infinint, unique label number (NOT filesystem inode number)
- Later occurrences of the same hard-linked file reference this label number

---

## 12. Deleted File Marker Format

```
+--------------+----------+
| NOMME header | orig sig |
+--------------+----------+
```

- Uses NOMME header (has name_string)
- **orig sig:** 1 byte, the original signature of the deleted entry

---

## 13. K06 (Kaylix Draft) Changes vs DAR5

K06 is a draft extension spec. Key additions:
- **System extensions:** `arc_extension_system` for OS-specific metadata
  - `SYS_WINDOWS = "Windows"` — Windows file attributes (NTFS streams, reparse points, sparse files)
  - `SYS_MAC = "Mac OSX"` — macOS-specific metadata
- **Windows-specific:** `win32_file_attribute_data`, `backup_data`, `reparse_point`, `sparse_file`, etc.
- **New EA flags:** `ea_close` — indicates EA data is closed/complete
- **`no_cont_index`** — file attribute indicating not content-indexed
- The core catalog entry type bytes and structures appear **unchanged** from DAR5 in K06

---

## Summary: Critical Constants for Parser Implementation

```rust
// Entry type signatures (type_char = sig_byte & 0x7F)
const SIG_FILE:         u8 = b'f'; // 0x66 saved, 0xE6 unsaved
const SIG_DIR:          u8 = b'd'; // 0x64 saved, 0xE4 unsaved
const SIG_SYMLINK:      u8 = b'l'; // 0x6C saved, 0xEC unsaved
const SIG_CHAR_DEV:     u8 = b'c'; // 0x63 saved, 0xE3 unsaved
const SIG_BLOCK_DEV:    u8 = b'b'; // 0x62 saved, 0xE2 unsaved
const SIG_PIPE:         u8 = b'p'; // 0x70 saved, 0xF0 unsaved
const SIG_SOCKET:       u8 = b's'; // 0x73 saved, 0xF3 unsaved
const SIG_HARD_LINK:    u8 = b'h'; // 0x68 saved, 0xE8 unsaved
const SIG_FILE_LABEL:   u8 = b'e'; // 0x65 saved, 0xE5 unsaved
const SIG_DOOR:         u8 = b'x'; // 0x78 saved, 0xF8 unsaved
const SIG_EOD:          u8 = b'z'; // 0x7A — end of directory

const SAVED_MASK:       u8 = 0x80; // bit 7: 0=saved, 1=unsaved
const TYPE_MASK:        u8 = 0x7F; // bits 0-6: ASCII char

// EA flags
const EA_NONE:    u8 = 0x00;
const EA_PARTIAL: u8 = 0x01;
const EA_FULL:    u8 = 0x02;

// Archive magic
const SAUV_MAGIC_NUMBER: u32 = 123; // 0x0000007B
const FLAG_NON_TERMINAL: u8 = b'N'; // 0x4E
const FLAG_TERMINAL:     u8 = b'T'; // 0x54

// Fixed-width fields
// UID, GID, permissions: u16 big-endian
// CRC: u16 big-endian
// atime, mtime, size, offset, storage_size: infinint
```
