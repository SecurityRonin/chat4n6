# SQLite Undelete / Data Recovery Tools: Comprehensive Research Report

> Research compiled: 2026-03-23
> Scope: All known open-source, commercial, and academic work on SQLite deleted record recovery.

---

## Table of Contents

1. [SQLite Deletion Model: Why Recovery Is Possible](#1-sqlite-deletion-model-why-recovery-is-possible)
2. [Key Structural Recovery Sources](#2-key-structural-recovery-sources)
3. [Open Source Tools](#3-open-source-tools)
4. [Proprietary / Commercial Tools](#4-proprietary--commercial-tools)
5. [Academic Papers and Research](#5-academic-papers-and-research)
6. [Standardized Test Corpora](#6-standardized-test-corpora)
7. [Community Wisdom: Forums and Blogs](#7-community-wisdom-forums-and-blogs)
8. [Algorithm Taxonomy](#8-algorithm-taxonomy)
9. [Anti-Forensics and Edge Cases](#9-anti-forensics-and-edge-cases)
10. [Tool Comparison Summary](#10-tool-comparison-summary)

---

## 1. SQLite Deletion Model: Why Recovery Is Possible

SQLite exhibits three structural characteristics that make deleted data recoverable:

1. **Logical deletion, not physical erasure.** When a row is deleted, SQLite marks the space as available but does not zero it. The B-tree page is updated (cell pointer removed, space added to the freeblock list), but the bytes remain until overwritten by new writes.

2. **Explicit free-space management via metadata structures.** Free pages are tracked in the *freelist* (a linked list starting from a pointer in the database header). Free space within pages is tracked via *freeblocks* (a linked list embedded in the page). Both preserve deleted content until reuse.

3. **Write-Ahead Log (WAL) maintains transaction history.** From SQLite 3.7.0 (2010), WAL mode stores new/modified pages in a separate `.db-wal` file. Pages accumulate there until a checkpoint writes them back. The WAL may hold older versions of pages, uncommitted data, and deleted records for an extended period (checkpoint threshold defaults to 1,000 pages — often days or weeks of activity on mobile devices).

**The pre-WAL mechanism (Rollback Journal)** worked the opposite way: the *original* page content was backed up to a `-journal` file before being modified. If the process crashed, the journal would remain on disk and still be present for forensic recovery.

### Pragmas That Affect Recoverability

| Pragma | Default | Forensic impact |
|--------|---------|-----------------|
| `secure_delete = OFF` | OFF | Deleted space not zeroed — recoverable |
| `secure_delete = ON` | — | Deleted space overwritten with zeros — not recoverable in-place |
| `secure_delete = FAST` | — | Intermediate; only zeros leaf content |
| `auto_vacuum = NONE` | NONE | Freed pages stay in file — recoverable |
| `auto_vacuum = FULL` | — | Freed pages removed; file shrinks |
| `VACUUM` | Manual | Rebuilds entire DB; purges all traces |
| `journal_mode = WAL` | DELETE | WAL mode — rich forensic source |
| `journal_mode = DELETE` | — | Rollback journal; removed on commit |

> Note: `secure_delete` does **not** protect FTS3/FTS5 shadow tables even when ON, per the SQLite documentation.

Sources: [SQLite VACUUM docs](https://sqlite.org/lang_vacuum.html), [SQLite Pragma docs](https://sqlite.org/pragma.html)

---

## 2. Key Structural Recovery Sources

### 2.1 Table B-Tree Leaf Pages (TBLPs)
- Page type byte `0x0d` (integer 13) identifies a table B-tree leaf page.
- Contains: live cell pointer array, live records, **freeblocks** (linked list of reused space), and **unallocated space** (gap between cell pointer array end and first cell).
- Deleted content accumulates in freeblocks and unallocated space until the page is defragmented or reused.

### 2.2 Freeblocks (within a page)
- A linked list of free space segments within a page.
- Each freeblock: 2 bytes (next freeblock offset, 0x0000 = last) + 2 bytes (size) + content bytes.
- When a row is deleted, its space is added to the freeblock list.
- Content remains intact until overwritten.

### 2.3 Freelist Pages
- Database-level list of entirely free pages (trunk pages + leaf pages).
- Freelist trunk page: 4-byte pointer to next trunk, 4-byte leaf count, then leaf page numbers.
- Freelist leaf pages: entire pages of data that were freed (e.g., from table drops, mass deletes).
- Often fully intact since SQLite does not zero them — just adds to the list.

### 2.4 WAL File
- Format: 32-byte file header + frames. Each frame: 24-byte frame header (page number, commit size, salt-1, salt-2, checksum) + page data.
- **Salt values** identify WAL sessions. Multiple salt groups in one WAL file = multiple transaction sessions.
- After a checkpoint, old frames remain physically in the WAL file until overwritten ("WAL slack").
- Forensically: a WAL may contain dozens of prior versions of the same page. The most recent frame for a page (matching salt, highest frame number) is the "current" version; older frames are forensic gold.
- Opening a DB in SQLite automatically checkpoints the WAL — **do not open the DB directly** in a forensic context.

### 2.5 Rollback Journal
- Created before any write transaction, contains original page images before modification.
- Removed on successful commit; remains on disk after crash.
- Forensic value: original content of pages that were subsequently modified or deleted.

### 2.6 Unallocated Space Within Pages
- The gap between the last cell pointer entry and the first cell.
- Can contain remnants of previously stored records.
- Not tracked by any metadata — requires heuristic or schema-aware carving.

### 2.7 Overflow Pages
- Records larger than a page use overflow pages, chained in a singly-linked list.
- First 4 bytes of each overflow page = next page number (0 = last in chain).
- Auto-vacuum databases add **Pointer Map pages** that track the parent page of each overflow chain.
- Forensically: overflow chain pages can become freelist pages, retaining large deleted records (BLOBs, long texts).
- **Critical:** simple carving tools miss overflow chains; only schema-aware tools that follow the chain reconstruct the full record.

### 2.8 Index B-Tree Leaf Pages
- Contain a copy of indexed column values alongside a row ID.
- Even when the table record is unrecoverable, the index leaf page may retain the indexed values.
- Often overlooked by tools focused only on table pages. FQLite paper (Pawlaszczyk & Hummert 2021) explicitly calls this out as underexplored.

---

## 3. Open Source Tools

### 3.1 FQLite
- **URL:** https://github.com/pawlaszczyk/fqlite
- **Language:** Java (GUI + CLI)
- **Author:** Dirk Pawlaszczyk, Hochschule Mittweida (University of Applied Sciences Mittweida, Germany)
- **License:** Mozilla Public License 2.0 / GNU GPL 3+
- **Algorithm:**
  - Schema-aware: reads `sqlite_master` to obtain column types (serial types) for each table.
  - Scans all B-tree leaf pages for live records, then scans freeblocks and unallocated space for deleted record candidates.
  - Uses serial type pattern matching against the schema to validate candidate records and filter false positives.
  - Processes freelist pages using the same B-tree leaf page algorithm (with minor adjustments for freelist structure).
  - Also parses Rollback Journal and WAL files (WAL support added in later versions).
  - Supports index B-tree recovery (unique among open-source tools).
- **Uniqueness:** Schema-aware validation is FQLite's primary differentiator — it significantly reduces false positives compared to blind carving tools. It also supports a graphical UI, LLM-assisted SQL query formulation, and image/BLOB preview.
- **Confidence scoring:** Implicit — records are validated against schema types; invalid type patterns are rejected rather than scored.
- **Evaluation:** Highest recovery rate among open-source tools in the 2025 ScienceDirect survey benchmark (278 deleted records from the SQLite Forensic Corpus).
- **Paper:** "Making the Invisible Visible – Techniques for Recovering Deleted SQLite Data Records", *International Journal of Cyber Forensics and Advanced Threat Investigations*, 1(1-3), pp. 27-41, 2021. https://conceptechint.net/index.php/CFATI/article/view/17
- **User Guide:** https://www.staff.hs-mittweida.de/~pawlaszc/fqlite/downloads/FQLite_UserGuide.pdf

### 3.2 undark / sqlite-undark
- **URLs:**
  - Primary (inflex): https://github.com/inflex/undark (original by Paul Daniels)
  - Mirror (alitrack): https://github.com/alitrack/undark
  - Fork (mlt): https://github.com/mlt/undark
  - Official site: https://pldaniels.com/undark/
- **Language:** C
- **Algorithm:**
  - Reads the entire SQLite database binary, page by page.
  - Does NOT differentiate between live and deleted records — outputs everything it finds.
  - Uses `--fine-search` mode to shift one byte at a time rather than record-by-record for corrupt databases.
  - Supports cell count limits (`--cellcount-min/max`) and row size limits (`--rowsize-min/max`) to filter output.
  - Has `freelist_space_only` and `removed_only` internal flags.
  - Outputs CSV format.
- **Uniqueness:** The original SQLite undelete tool; extremely simple; works on corrupt databases by ignoring B-tree structure. Named as inspiration for SQBrite.
- **Limitations:** No schema awareness; high false positive rate; no deduplication; cannot recover data after VACUUM; no WAL/journal support; outputs both live and deleted without distinction.

### 3.3 bring2lite
- **Paper:** https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-bring2lite_a_structural_concept_and_tool_for_forensic_data_analysis_and_recovery_of_deleted_sqlite_records.pdf
- **Presentation:** https://dfrws.org/presentation/a-structural-concept-and-tool-for-forensic-data-analysis-and-recovery-of-deleted-sqlite-records/
- **ScienceDirect:** https://www.sciencedirect.com/science/article/pii/S1742287619301677 (DOI: 10.1016/j.diin.2019.04.017)
- **Language:** Python
- **Authors:** Christian Meng & Prof. Dr. Harald Baier, Darmstadt University of Applied Sciences / CRISP
- **Algorithm:**
  - Reads SQLite header (page size, freelist info, etc.).
  - Processes `sqlite_master` to map schemas to pages.
  - Loops over all pages, categorizing each by type.
  - Extracts deleted content from: table B-tree leaf unallocated area, freeblocks within leaf pages, and freelist pages.
  - Generates a cryptographic hash of findings for forensic integrity.
  - Stores output in a folder structure organized by database and table.
  - Examines deletion behavior under different pragma settings (`secure_delete`, `auto_vacuum`, `journal_mode`).
- **Uniqueness:** First tool to systematically analyze how SQLite pragma settings affect forensic recoverability. Best open-source recovery rate at time of DFRWS 2019 publication (52.9% on 27 test databases, superior to all 8 comparison tools).
- **Limitations:** No WAL or rollback journal support (at time of publication); Python dependency.

### 3.4 SQLite Deleted Records Parser (sqlparse / mdegrazia)
- **URL:** https://github.com/mdegrazia/SQLite-Deleted-Records-Parser
- **Language:** Python (also Windows CLI and GUI executables)
- **Author:** Mari DeGrazia (@maridegrazia)
- **Blog:** http://az4n6.blogspot.com/2013/11/python-parser-to-recover-deleted-sqlite.html
- **Algorithm:**
  - Identifies Table B-Tree Leaf Pages by the `0x0d` flag byte.
  - Reads the B-tree header to determine unallocated region bounds.
  - Extracts raw bytes from the unallocated region (between cell pointer array end and first cell).
  - Traverses the freeblock linked list (2 bytes next pointer + 2 bytes size + data).
  - Outputs to TSV or text file with offsets.
  - `-p` flag prints "re-purposed B-Leaf pages" (freelist pages that formerly held table data).
- **Uniqueness:** First widely-adopted Python tool for SQLite forensics. Cited in SANS585 Advanced Smartphone Forensics course and two mobile forensics textbooks (*Practical Mobile Forensics* by Bommisetty et al., *Learning iOS Forensics* by Epifani & Stirparo). Accessible entry point for many practitioners.
- **Versions:** v1.1 (2013-11-05), v1.2 (2015-06-20, added non-B-tree page printing), v1.3 (2015-06-21).
- **Limitations:** No schema awareness; raw binary output requires manual interpretation; no WAL/journal support; no deduplication.

### 3.5 SQBrite
- **URL:** https://github.com/mattboyer/sqbrite
- **PyPI:** https://pypi.org/project/sqbrite/
- **Language:** Python 3
- **Author:** Matt Boyer
- **Algorithm:**
  - Implements the SQLite on-disk format to recover deleted table rows.
  - Scans B-tree table leaf pages for freeblocks containing deleted record data.
  - Also scans freelist pages that formerly held table leaf data.
  - **YAML-based heuristics:** Since there is no metadata tracking where deleted records start within freeblocks, SQBrite uses byte-wise regular expressions specific to known database schemas. These are stored in a user-editable `~/.local/share/sqbrite/sqbrite.yaml` file, with offsets from match to first header byte.
  - Can export recovered records to CSV or re-inject ("undelete") them into a copy of the DB.
- **Uniqueness:** YAML-extensible schema heuristics system; community-contributed signatures; `undelete` subcommand to re-inject records into a live database copy; explicitly inspired by undark but entirely separate implementation.
- **Limitations:** Cannot recover records if `secure_delete` was enabled; overflow page recovery not supported; re-injection may fail on constraint violations.

### 3.6 forensics-sqlite (dutchcoders)
- **URL:** https://github.com/dutchcoders/forensics-sqlite
- **Language:** Python
- **Purpose:** WAL frame dumper — dumps all frames from a `.db-wal` file.
- **Key file:** `forensics_sqlite/WAL.py` — parses WAL frame headers (page number, salt, checksum) and extracts page data.
- **Uniqueness:** Focused exclusively on WAL forensics; useful for batch-processing WAL files without triggering automatic checkpointing.

### 3.7 recoversqlite (aramosf)
- **URL:** https://github.com/aramosf/recoversqlite
- **Language:** Python
- **Purpose:** General SQLite deleted record recovery; references CCL-Forensics Epilog as an inspiration.

### 3.8 Sanderson Forensics SQLite Forensic Toolkit
- **URL:** https://sqliteforensictoolkit.com/
- **Status:** Commercial (Windows, dongle-protected for LEO; some versions sold through Teel Technologies)
- **Components:**
  1. **Forensic Browser for SQLite** — GUI for viewing all page bytes decoded, recovering deleted and partial records, WAL/journal analysis, BLOB image preview, SQL query builder, HTML/XLSX/CSV/PDF reporting.
  2. **SQLite Forensic Explorer** — Low-level byte viewer showing every structure in a DB/WAL/journal file decoded; freelist explorer; invaluable for understanding any SQLite file.
  3. **SQLite Recovery** — Carves disk images, volumes, or files for deleted SQLite databases; useful for locating databases that no longer appear in the filesystem.
- **Recovery algorithm (Forensic Browser):**
  - Reads `sqlite_master` for schema.
  - Scans all pages for live records, freeblock content, and unallocated space.
  - WAL processing: parses all salt groups, handles WAL slack (old frames from prior sessions), allows selecting "last commit frame" to replay the database to any historical state.
  - Deduplication: creates an MD5 hash of each recovered row's column content; does NOT insert a recovered record if a live record with the same hash exists.
  - Partial record recovery: when a row header is overwritten, attempts to reconstruct missing data.
  - Recovered records labeled as "live," "recovered," or "partial."
- **Book:** Paul Sanderson, *SQLite Forensics* (2018), independently published, ISBN 978-1980293071, 315 pages.
- **Blog:** https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/

### 3.9 CCL-Forensics Epilog
- **Status:** Formerly commercial (CCL-Forensics, UK); current availability unclear.
- **Website reference:** http://www.ccl-forensics.com/Software/epilog-from-ccl-forensics.html
- **Algorithm:** Three independent recovery algorithms (specific details not publicly disclosed); signature-based tailoring for specific databases (Android SMS/call logs, Chrome history, etc.); WAL journal parsing (added in v1.1); database rebuilder to re-inject recovered records into a live DB copy.
- **Uniqueness:** First tool with WAL support (Epilog v1.1); database rebuilder; signature library allowing community contributions; real-world recovery of ~5,000 entries from web cache (vs. 400 live visible).
- **Blog review:** http://jay-fva.blogspot.com/2011/05/sqlite-forensic-tools-epilog.html

### 3.10 bulk_extractor
- **URL:** https://github.com/simsong/bulk_extractor
- **Language:** C++ (scanner plugin architecture)
- **SQLite support:** bulk_extractor can be directed at SQLite files for forensic scanning. Its plugin system allows writing custom C++ scanners (`.so`/`.dll`) that are loaded at runtime. SQLite can be used as the *output* format for feature files.
- **Approach:** Page-parallel scanning across 16 MiB chunks; processes compressed data automatically; ignores filesystem structure. SQLite-specific recovery is done via scanners but no dedicated SQLite deleted-record scanner ships by default — practitioners typically point it at raw disk images to find SQLite file signatures.
- **Uniqueness:** High-speed parallel scanning; useful for finding SQLite databases in unallocated disk space.

### 3.11 Autopsy SQLite Modules
- **Platform URL:** https://github.com/sleuthkit/autopsy
- **Two community plugins:**
  1. **SQLite Deleted Records Module** — accepts one or more SQLite DB paths, exports to temp directory, parses deleted records, creates custom Autopsy artifacts per table (`SQLite Database <FileName> Table <Table Name>`). Does not handle BLOB columns.
  2. **SQLite Importer Module** — imports live records from any SQLite DB into Autopsy artifacts. Useful for unsupported applications.
- **Additional:** Autopsy has efficient queries to locate `.db-wal` files alongside database files. The `org.sleuthkit.autopsy.coreutils.AppSQLiteDB` class provides helper methods for opening and querying SQLite databases in ingest modules.
- **Limitation:** Plugins are community-written; the deleted records module is "not very fast on large tables" per its own documentation.

---

## 4. Proprietary / Commercial Tools

### 4.1 Belkasoft X (formerly Belkasoft Evidence Center)
- **URL:** https://belkasoft.com/x
- **SQLite analysis article:** https://belkasoft.com/sqlite-analysis
- **Forensic Focus mirror:** https://www.forensicfocus.com/articles/forensic-analysis-of-sqlite-databases-free-lists-write-ahead-log-unallocated-space-and-carving/
- **Recovery sources:** Freelist pages, WAL, Rollback Journal, unallocated space within pages, RAM dumps.
- **Algorithm highlights:**
  - Developed own low-level SQLite parser (no third-party components) enabling access to corrupt databases.
  - Freelist: automatically finds all freelist pages and parses deleted records from them.
  - WAL: extracts uncommitted records from `.db-wal` files; handles cases where WAL contains >50% of forensic data (observed in Windows 10 Timeline databases).
  - Unallocated space carving: tabs in UI showing carved data from unallocated space, formatted by columns for review.
  - Deduplication: merges records from all sources (WAL, journal, freelist, live) into unified artifact views (e.g., a WAL-recovered chat appears in the Chats node alongside live chats).
  - Can process databases from RAM/memory dumps/hibernation/pagefile.
- **Uniqueness:** Handles databases that are up to 95% freelist (competitor tools fail to open these). Unified artifact view across all recovery sources. RAM processing.

### 4.2 Oxygen Forensic Detective / Oxygen Forensic SQLite Viewer
- **URL:** https://www.oxygen-forensic.com/
- **WAL deletion recovery article:** https://www.oxygen-forensic.com/en/events/news/432-oxygen-forensic-sqlite-viewer-v-2-3-introduces-deleted-data-recovery-from-wal-files
- **Recovery sources:** Freelist, WAL, Rollback Journal, unallocated space.
- **Algorithm highlights (v14.0+):**
  - Read-only, zero-footprint operation with automatic hash calculation.
  - Redesigned deleted data recovery engine in v14.0 (fewer duplicate records, 50% faster parsing, correct handling of databases >2 GB).
  - Specific improvements in v14.0: 10x more valid Facebook records, 2x+ more from LinkedIn/Viber.
  - Visual SQL query builder; supports Base64 auto-decode for string columns.
- **Uniqueness:** Standalone SQLite Viewer available separately; enterprise-scale performance improvements in v14.0; significant improvement in de-duplication accuracy.

### 4.3 Cellebrite Physical Analyzer
- **URL:** https://cellebrite.com/en/products/physical-analyzer/
- **Database Viewer article:** https://cellebrite.com/en/the-new-database-viewer-in-ufed-physical-analyzer/
- **Recovery sources:** Deleted records via SQLite Databases Viewer; WAL and Rollback Journal data (confirmed by DHS/NIST test report).
- **Algorithm highlights:**
  - New Database Viewer (v7.25+): performance improvements, advanced column-type detection (timestamps, Base64).
  - SQLite Wizard for custom application decoding.
  - Python scripting support for custom parsers.
  - App Genie: heuristic-based detection of unsupported application databases.
- **DHS/NIST validation:** AXIOM Examine v5.5.1 (Magnet) and Cellebrite both tested for WAL, Rollback Journal, and sequence WAL journal data recovery. All supported test cases passed.
- **Reference:** https://www.dhs.gov/sites/default/files/2022-03/22_0316_st_TestResults_SQLiteDataRecoveryTool_Axiomv55126621.pdf (Magnet AXIOM DHS test; similar tests exist for Cellebrite)

### 4.4 Magnet AXIOM
- **URL:** https://www.magnetforensics.com/products/magnet-axiom/
- **DHS/NIST test results:** https://www.dhs.gov/sites/default/files/2022-03/22_0316_st_TestResults_SQLiteDataRecoveryTool_Axiomv55126621.pdf
- **Recovery sources:** WAL, Rollback Journal, sequence WAL journal data, live records, dynamic unsupported app databases.
- **Algorithm highlights:**
  - **Dynamic App Finder:** searches for SQLite databases from unsupported applications, extracts data matching known patterns (geolocation, URLs, email addresses, etc.).
  - BLOB viewer (images, music, video) and plist viewer for BLOB cells.
  - NIST-validated for WAL, Rollback Journal, and sequence WAL journal.
- **Uniqueness:** Dynamic App Finder for unsupported apps; unified multi-source case file (mobile, computer, cloud, vehicle); artifact-first approach for building timelines.

### 4.5 X-Ways Forensics
- **URL:** https://www.x-ways.net/
- **SQLite support:** X-Ways can view SQLite database content and is used by advanced practitioners for granular manual analysis. It does not appear to have dedicated SQLite deleted-record recovery comparable to Belkasoft or Oxygen; practitioners typically export databases and use dedicated SQLite tools.
- **Community reputation:** Preferred by advanced examiners for manual control; limited automated SQLite recovery compared to specialized tools.

### 4.6 Forensic Toolkit (FTK) — AccessData / Exterro
- **URL:** https://www.exterro.com/digital-forensics-software/forensic-toolkit
- **SQLite support:** FTK can view SQLite databases but is not known for dedicated WAL/freelist recovery features comparable to Belkasoft or Cellebrite. Strong points are large dataset processing speed and keyword indexing.
- **Community reputation:** Often discontinued in favor of AXIOM for SQLite-heavy mobile work.

### 4.7 Sanderson Forensics SQLite Forensic Toolkit (commercial component)
- See Section 3.8. Dongle-protected commercial version adds reporting and is sold through Teel Technologies: https://www.teeltech.com/analysis/forensic-toolkit-for-sqlite/

---

## 5. Academic Papers and Research

### 5.1 Primary Survey (2025)
**"A comprehensive analysis and evaluation of SQLite deleted Record recovery techniques: A survey"**
- *ScienceDirect / Digital Investigation* (2025)
- https://www.sciencedirect.com/science/article/abs/pii/S2666281725001714
- Categorizes recovery techniques into three types: **Carving-based**, **Metadata-based**, **WAL-based**.
- Evaluates four open-source tools (Undark, SQLite Deleted Record Parser, Bring2Lite, FQLite) on the SQLite Forensic Corpus (278 deleted records).
- Identifies failure causes and false positive cases.
- Goals: expand corpus to include WAL scenarios; provide practical guidelines.

### 5.2 bring2lite (DFRWS 2019)
**"bring2lite: A Structural Concept and Tool for Forensic Data Analysis and Recovery of Deleted SQLite Records"**
- Meng, C. & Baier, H.
- *Digital Investigation*, 29, S31–S41, 2019
- https://www.sciencedirect.com/science/article/pii/S1742287619301677
- DOI: 10.1016/j.diin.2019.04.017
- https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-bring2lite_a_structural_concept_and_tool_for_forensic_data_analysis_and_recovery_of_deleted_sqlite_records.pdf
- First paper to systematically study SQLite pragma settings' impact on forensic recoverability.
- Introduces bring2lite Python tool; achieves 52.9% restoration rate, superior to all 8 comparison tools at time of publication.

### 5.3 FQLite Paper (2021)
**"Making the Invisible Visible – Techniques for Recovering Deleted SQLite Data Records"**
- Pawlaszczyk, D. & Hummert, C.
- *International Journal of Cyber Forensics and Advanced Threat Investigations*, 1(1-3), pp. 27-41, 2021
- https://conceptechint.net/index.php/CFATI/article/view/17
- PDF: https://pdfs.semanticscholar.org/40f1/5dd302e539a83ba6b96864e76b092690dbc4.pdf
- Introduces FQLite; proposes schema-aware serial type pattern matching.
- Highlights B-tree *index* leaf pages as an underexplored recovery source.
- Notes that WAL support was planned as future work.

### 5.4 FQLite User Guide (2024)
- Pawlaszczyk, D.
- https://www.researchgate.net/publication/395714042_SQLite_Forensics_with_FQLite_-_The_Official_User_Guide
- Direct PDF: https://www.staff.hs-mittweida.de/~pawlaszc/fqlite/downloads/FQLite_UserGuide.pdf
- Creative Commons Attribution 4.0.

### 5.5 SQLite Forensic Corpus (2018)
**"A standardized corpus for SQLite database forensics"**
- Nemetz, S., Schmitt, S. & Freiling, F.
- *Digital Forensics Research Workshop Europe*, 2018
- https://www.sciencedirect.com/science/article/pii/S1742287618300471
- Corpus: https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/
- 77 databases in 5 categories covering edge cases and format pitfalls.
- None of the 6 evaluated tools handled all corner cases correctly.

### 5.6 Anti-Forensics to SQLite Corpora (2018)
**"Introducing Anti-Forensics to SQLite Corpora and Tool Testing"**
- Schmitt, S.
- *IMF 2018 (11th International Conference on IT Security Incident Management & IT Forensics)*
- https://ieeexplore.ieee.org/document/8514835/
- PDF: https://imf-conference.org/imf2018/downloads/09_Sven-Schmitt_Introducing-Anti-Forensics.pdf
- Extends the SQLite Forensic Corpus with deliberately malformed databases (anti-forensic artifacts) to challenge tool robustness.

### 5.7 DFIR Review: Missing SQLite Records Analysis (2022)
- Punja, S.G. & Whiffin, I.
- https://dfir.pubpub.org/pub/33vkc2ul/release/1
- Also: https://www.sans.org/reading-room/whitepapers/forensics/missing-sqlite-records-analysis-40195
- Demonstrates how WAL checkpoint commits delete records without any user action.
- Documents the forensic challenge of a "net loss" of records across WAL commits.
- Important for iOS forensics: iOS 12+ physically wipes SQLite records almost immediately after deletion (unlike iOS 8-11).
- Introduces `mirf` tool concept for tracking missing records across WAL commits.

### 5.8 Belkasoft Technical Article
**"Forensic Analysis of SQLite Databases: Free Lists, Write Ahead Log, Unallocated Space and Carving"**
- Makeev, D., Timofeev, N., Afonin, O. & Gubanov, Y.
- https://belkasoft.com/sqlite-analysis
- https://www.forensicfocus.com/articles/forensic-analysis-of-sqlite-databases-free-lists-write-ahead-log-unallocated-space-and-carving/
- Comprehensive practitioner's guide to all four forensic sources; foundational reference.

### 5.9 Richard Drinkwater — "Forensics from the Sausage Factory"
- Blog: http://forensicsfromthesausagefactory.blogspot.com/
- "Carving SQLite databases from unallocated clusters" (2011): http://forensicsfromthesausagefactory.blogspot.com/2011/04/carving-sqlite-databases-from.html
- "SQLite overflow pages and other loose ends" (2011): http://forensicsfromthesausagefactory.blogspot.com/2011/07/sqlite-overflow-pages-and-other-loose.html
- First public exploration of Pointer Map pages for overflow chain forensics; discussions of carving challenges from unallocated disk space (no footer, no stored length).

### 5.10 Paul Sanderson — Book and Blog
- *SQLite Forensics* (2018), Paul Sanderson, independently published, ISBN 978-1980293071.
- Good general introduction but does not focus on deleted record carving (per the 2025 survey).
- Blog: https://sqliteforensictoolkit.com/recovering-deleted-records-from-an-sqlite-database/
- WAL blog post: https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/

---

## 6. Standardized Test Corpora

### 6.1 SQLite Forensic Corpus (digitalcorpora.org)
- https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/
- 77 databases in 5 categories; 278 deleted records for recovery benchmarking.
- Tests edge cases: unusual page sizes, auto_vacuum, WAL mode, pointer maps, anti-forensic malformations.
- Public domain; used by all major academic papers as benchmark.
- Created by Nemetz, Schmitt & Freiling; extended by Schmitt with anti-forensic databases.
- Training resource: https://blog.dfir.training/practice/sqlite-forensic-corpus

---

## 7. Community Wisdom: Forums and Blogs

### 7.1 Forensic Focus Forums: Key Threads
- "Recovery of SQLite deleted records": https://www.forensicfocus.com/forums/general/recovery-of-sqlite-deleted-records/
- "SQLite viewer": https://www.forensicfocus.com/forums/general/sqlite-viewer/
- "iOS SQLite database deleted data": https://www.forensicfocus.com/forums/general/ios-sqlite-database-deleted-data/
- "Deleted SQLite data": https://www.forensicfocus.com/forums/general/deleted-sqlite-data/

**Community consensus from these threads:**
1. No single tool recovers everything — use multiple tools and cross-validate.
2. Sanderson's Forensic Browser, Belkasoft, and Oxygen are the most frequently recommended for professional work.
3. Open-source options (undark, sqlparse, FQLite) are useful for quick triage and validation.
4. Different tools return different results from the same database — always verify evidence at the hex level.
5. Carving SQLite data is described as "a bit of a black art" due to sparse record storage.

### 7.2 A Standardized Corpus Webinar (Forensic Focus)
- https://www.forensicfocus.com/webinars/a-standardized-corpus-for-sqlite-database-forensics/
- Key finding: **none of the tools tested could correctly handle all corner cases** in the corpus.

### 7.3 iOS 12+ Recovery Limitation
From the DFIR Review paper and community discussions: starting with iOS 12, Apple implemented near-immediate physical wiping of deleted SQLite records. Text messages and iMessages cannot be recovered from the SQLite freelist in iOS 12 and later. WAL-based recovery remains possible for uncommitted records.

### 7.4 Windows 10 Timeline / ActivityCache.db
Community observation (Belkasoft documentation): some databases have up to 95% of their pages in freelist. The Windows 10 Timeline database (ActivityCache.db) is an extreme example where most forensic data resides in freelist pages — many tools fail to open or parse such databases.

### 7.5 Overflow Pages: Critical Gap
Blog post by Richard Drinkwater and elusivedata.io article confirm: most tools do not follow overflow page chains. A large BLOB or long text string deleted from SQLite may have its content spread across multiple overflow pages that become freelist pages; only tools that explicitly follow the `next_overflow_page` pointer chain can recover these records completely.
- https://elusivedata.io/overflow-pages/

---

## 8. Algorithm Taxonomy

### 8.1 Three Recovery Approach Categories (from 2025 ScienceDirect survey)

#### Category 1: Metadata-Based Recovery
Uses SQLite's own structural metadata to locate deleted content.
- **Sources:** Freelist (page-level), freeblocks within pages (byte-level), unallocated space within pages.
- **How it works:** Parses freelist trunk/leaf page pointers, traverses freeblock linked list within each page.
- **Tools:** All tools use this to some degree. bring2lite, sqlparse, FQLite, Sanderson Browser, Belkasoft, Oxygen.
- **Strengths:** High reliability when metadata intact; no false positive problem for page-level recovery.
- **Weaknesses:** Freeblock content is unstructured; requires schema knowledge to interpret.

#### Category 2: Carving-Based Recovery
Uses pattern matching to find record signatures within page content.
- **Blind carving:** Looks for valid varint sequences, record header patterns, or cell content signatures without schema knowledge. High false positive rate.
- **Schema-aware carving:** Uses the table schema (serial types) to validate candidate records. Dramatically reduces false positives. Used by FQLite, SQBrite (YAML heuristics), Sanderson Browser, Belkasoft.
- **Fine-grained carving (`--fine-search` in undark):** Shifts one byte at a time across the entire file — maximum coverage, maximum false positives.
- **Tools:** undark, sqlparse (partial), SQBrite, FQLite, Belkasoft, Sanderson Browser.

#### Category 3: WAL-Based Recovery
Parses WAL or rollback journal files for older page versions containing deleted content.
- **How it works:** Iterates WAL frames in order, groups by salt value (session), identifies the most recent frame per page number within each session, extracts records from all session groups.
- **Forensic subtlety:** WAL files can contain multiple salt groups (multiple sessions); after a checkpoint, old frames with obsolete salts remain in the WAL file ("WAL slack") — these contain prior database states.
- **Deduplication challenge:** Same record may appear in the live DB, WAL, and freelist — tools must deduplicate (hash-based or structural).
- **Tools:** Sanderson Forensic Browser, Belkasoft X, Oxygen Forensic Detective, Cellebrite Physical Analyzer, Magnet AXIOM (all confirmed to handle WAL). forensics-sqlite (dutchcoders) as standalone WAL dumper. FQLite added WAL support in later versions.

### 8.2 Deduplication Strategies

| Strategy | Description | Used by |
|----------|-------------|---------|
| **MD5 column hash** | Hash all column values; skip recovered record if live record with same hash exists | Sanderson Forensic Browser |
| **Merged artifact view** | All sources merged into unified artifact list; deduplication implicit in artifact normalization | Belkasoft X, Oxygen |
| **No deduplication** | All records from all sources output; analyst must deduplicate manually | undark, sqlparse |
| **Structural comparison** | Compare WAL frame page data byte-for-byte against current DB page; skip if identical | Forensic browser-level WAL merge |

### 8.3 Confidence Scoring

Most tools do not expose explicit confidence scores. Known exceptions and approaches:
- **FQLite:** Implicit confidence via schema validation — records that do not match expected serial type patterns are rejected entirely rather than scored. No numeric score output.
- **Sanderson Forensic Browser:** Distinguishes "recovered" (header intact, all columns present) vs. "partial" (header overwritten, reconstruction attempted) — a qualitative two-level confidence distinction.
- **chat4n6 (this project):** Explicit numeric `confidence: f32` field on `CarvedCandidate` struct, derived from live-record signature learning (schema signature comparison).
- **Belkasoft/Oxygen/Cellebrite:** No publicly documented confidence scoring — tools present records as found without confidence metadata.

---

## 9. Anti-Forensics and Edge Cases

### 9.1 Secure Delete
- `PRAGMA secure_delete = ON`: zeros deleted content in-place. Makes in-page recovery impossible. However, journal/WAL files written before the delete may still contain the original content.
- FTS shadow tables are NOT protected by secure_delete (SQLite docs confirmed).
- SQBrite explicitly documents this as an unsupported scenario.

### 9.2 VACUUM
- Rebuilds entire database; eliminates all freelist pages, freeblocks, and WAL.
- After VACUUM: no recovery possible from the file itself. Only journal/WAL written before the VACUUM might help, and these are typically removed before or during VACUUM.

### 9.3 Auto-Vacuum
- `PRAGMA auto_vacuum = FULL`: reclaims freed pages automatically, shrinking the file. Reduces but does not eliminate recovery (intra-page freeblocks and unallocated space remain).
- `PRAGMA auto_vacuum = INCREMENTAL`: similar but triggered manually.
- **Pointer Map pages** are added by auto-vacuum to track page ownership — a forensic artifact in themselves.

### 9.4 Overflow Pages
- Large records (BLOBs, long strings) are fragmented across overflow pages.
- Overflow chains are singly-linked (next pointer only, no back pointer).
- When overflow pages become freelist pages, reconstructing the chain requires following next-pointers and knowing the original chain start.
- **Auto-vacuum Pointer Map approach:** Type `0x03` in the pointer map = first page of overflow chain; use this to locate chain starts in auto-vacuum databases (Richard Drinkwater's technique).
- Most tools do not reconstruct overflow chains from freelist — this is a known gap across all evaluated open-source tools and most commercial tools.

### 9.5 Encrypted Databases (SQLCipher, SEE)
- SQLCipher and SQLite Encryption Extension (SEE) encrypt page content.
- Without the key, structural metadata (page headers) may still be visible to determine page type and count, but record content is inaccessible.
- Some commercial tools (Cellebrite, Oxygen) support known application keys for popular apps (e.g., WhatsApp on specific platforms).
- No open-source tool addresses encrypted SQLite recovery in the reviewed literature.

### 9.6 Corrupted Databases
- undark's `--fine-search` mode addresses corruption by searching byte-by-byte.
- Sanderson SQLite Forensic Explorer can display tables and rows from corrupt databases.
- FQLite designed to parse binary content directly, tolerating some corruption.

### 9.7 iOS 12+ Immediate Physical Wipe
- Starting iOS 12, Apple wipes deleted SQLite records (especially iMessages/SMS in `sms.db`) almost immediately after deletion.
- Freelist recovery not possible for these records on iOS 12+.
- WAL-based recovery still possible for records deleted during an uncommitted transaction.
- Source: DFIR Review paper (Punja & Whiffin, 2022).

### 9.8 WAL Anti-Forensics: Checkpoint Manipulation
- A clean checkpoint removes all pages from the WAL and resets it — equivalent to destroying the WAL forensic evidence.
- Some apps trigger checkpoints frequently; others (browsers, messaging apps) may not checkpoint for days.
- The presence of a `.db-shm` (shared memory index for WAL) file indicates WAL mode is active.

### 9.9 Deliberately Malformed Databases (Anti-Forensics)
- Schmitt (2018) demonstrated that deliberately crafted non-standard SQLite files can crash or mislead forensic tools.
- Extended the SQLite Forensic Corpus with such databases for testing tool robustness.

---

## 10. Tool Comparison Summary

| Tool | Type | Language | Sources Scanned | Schema-Aware | WAL/Journal | Deduplication | Confidence | Notes |
|------|------|----------|-----------------|--------------|-------------|---------------|------------|-------|
| **FQLite** | OSS | Java | Freelist, freeblocks, unalloc, WAL, journal, index B-trees | Yes | Yes | Implicit (type validation) | Reject/accept | Best OSS recovery rate; GUI; AI SQL assist |
| **undark** | OSS | C | All pages (blind scan) | No | No | None | None | Original tool; high FP; works on corrupt DBs |
| **bring2lite** | OSS | Python | Freelist, freeblocks, unalloc | Partial | No (at publication) | Hash | None | 52.9% rate; pragma analysis; DFRWS 2019 |
| **sqlparse (mdegrazia)** | OSS | Python | Freeblocks, unalloc | No | No | None | None | Raw binary output; SANS-referenced |
| **SQBrite** | OSS | Python | Freeblocks, freelist pages | YAML heuristics | No | None | None | YAML-extensible; `undelete` re-injection |
| **forensics-sqlite** | OSS | Python | WAL frames only | No | WAL only | None | None | WAL dumper utility |
| **Sanderson Toolkit** | Commercial | Windows | All sources + disk carving | Yes | Yes (WAL slack) | MD5 hash | Recovered/Partial | Low-level page viewer; WAL historical replay |
| **Belkasoft X** | Commercial | Windows | All sources + RAM | Yes | Yes | Merged artifact view | None public | Handles 95% freelist DBs; RAM processing |
| **Oxygen Forensic** | Commercial | Windows | All sources | Yes | Yes | Merged/deduped | None public | Standalone SQLite Viewer; v14.0 redesign |
| **Cellebrite PA** | Commercial | Windows | All sources | Yes | Yes (NIST-validated) | Merged | None public | App Genie; Python scripting; SQLite Wizard |
| **Magnet AXIOM** | Commercial | Windows | All sources | Yes | Yes (NIST-validated) | Merged | None public | Dynamic App Finder; multi-source case file |

---

## Key References (Full List)

1. FQLite GitHub: https://github.com/pawlaszczyk/fqlite
2. FQLite Homepage: https://www.staff.hs-mittweida.de/~pawlaszc/fqlite/
3. FQLite User Guide PDF: https://www.staff.hs-mittweida.de/~pawlaszc/fqlite/downloads/FQLite_UserGuide.pdf
4. "Making the Invisible Visible" paper: https://conceptechint.net/index.php/CFATI/article/view/17
5. 2025 Comprehensive Survey: https://www.sciencedirect.com/science/article/abs/pii/S2666281725001714
6. undark (inflex): https://github.com/inflex/undark
7. undark (alitrack): https://github.com/alitrack/undark
8. undark official site: https://pldaniels.com/undark/
9. bring2lite DFRWS paper PDF: https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-bring2lite_a_structural_concept_and_tool_for_forensic_data_analysis_and_recovery_of_deleted_sqlite_records.pdf
10. bring2lite ScienceDirect: https://www.sciencedirect.com/science/article/pii/S1742287619301677
11. sqlparse GitHub: https://github.com/mdegrazia/SQLite-Deleted-Records-Parser
12. sqlparse blog: http://az4n6.blogspot.com/2013/11/python-parser-to-recover-deleted-sqlite.html
13. SQBrite GitHub: https://github.com/mattboyer/sqbrite
14. forensics-sqlite GitHub: https://github.com/dutchcoders/forensics-sqlite
15. recoversqlite GitHub: https://github.com/aramosf/recoversqlite
16. Sanderson Forensics: https://sqliteforensictoolkit.com/
17. Sanderson recovering deleted records: https://sqliteforensictoolkit.com/recovering-deleted-records-from-an-sqlite-database/
18. Sanderson WAL guide: https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/
19. Belkasoft SQLite analysis: https://belkasoft.com/sqlite-analysis
20. Belkasoft SQLite forensics: https://belkasoft.com/sqlite
21. Oxygen Forensic SQLite Viewer: https://www.forensicfocus.com/news/how-to-recover-deleted-data-with-oxygen-forensic-sqlite-viewer/
22. Oxygen WAL announcement: https://www.oxygen-forensic.com/en/events/news/432-oxygen-forensic-sqlite-viewer-v-2-3-introduces-deleted-data-recovery-from-wal-files
23. Cellebrite Database Viewer: https://cellebrite.com/en/the-new-database-viewer-in-ufed-physical-analyzer/
24. Magnet AXIOM DHS test: https://www.dhs.gov/sites/default/files/2022-03/22_0316_st_TestResults_SQLiteDataRecoveryTool_Axiomv55126621.pdf
25. SQLite Forensic Corpus: https://digitalcorpora.org/corpora/sql/sqlite-forensic-corpus/
26. Corpus ScienceDirect: https://www.sciencedirect.com/science/article/pii/S1742287618300471
27. Anti-forensics IMF paper: https://ieeexplore.ieee.org/document/8514835/
28. DFIR Review missing records: https://dfir.pubpub.org/pub/33vkc2ul/release/1
29. SANS whitepaper missing records: https://www.sans.org/reading-room/whitepapers/forensics/missing-sqlite-records-analysis-40195
30. Drinkwater carving unallocated: http://forensicsfromthesausagefactory.blogspot.com/2011/04/carving-sqlite-databases-from.html
31. Drinkwater overflow pages: http://forensicsfromthesausagefactory.blogspot.com/2011/07/sqlite-overflow-pages-and-other-loose.html
32. Overflow pages forensics (elusivedata): https://elusivedata.io/overflow-pages/
33. Epilog CCL-Forensics review: http://jay-fva.blogspot.com/2011/05/sqlite-forensic-tools-epilog.html
34. Forensic Focus SQLite article: https://www.forensicfocus.com/articles/forensic-analysis-of-sqlite-databases-free-lists-write-ahead-log-unallocated-space-and-carving/
35. SQLite VACUUM docs: https://sqlite.org/lang_vacuum.html
36. SQLite pragma docs: https://sqlite.org/pragma.html
37. bulk_extractor GitHub: https://github.com/simsong/bulk_extractor
38. Autopsy GitHub: https://github.com/sleuthkit/autopsy
