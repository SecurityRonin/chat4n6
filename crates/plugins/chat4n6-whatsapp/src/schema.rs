#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SchemaVersion {
    Legacy,
    Modern,
}

/// Detect the WhatsApp msgstore.db schema version.
/// - Modern: user_version >= 100 OR has both "message" and "jid" tables
/// - Legacy: otherwise ("messages" + "wa_contacts" era)
pub fn detect_schema_version(user_version: u32, tables: &[&str]) -> SchemaVersion {
    let has_modern = tables.contains(&"message") && tables.contains(&"jid");
    if has_modern || user_version >= 100 {
        SchemaVersion::Modern
    } else {
        SchemaVersion::Legacy
    }
}

/// Returns a human-readable label for a WhatsApp Android `message_type` integer.
///
/// Values sourced from community reverse-engineering of the WhatsApp APK and the
/// Signal-Android analogue.  The corrected entries are:
///   8  = VoiceNote  (long-form audio attachment; NOT "AudioCall" — that was wrong)
///   9  = Document   (arbitrary file attachment; NOT "Application")
///   13 = Gif        (animated GIF, distinct from video type 3)
///   15 = Deleted    (deleted-for-all tombstone placeholder; NOT "ProductSingle")
pub fn msg_type_label(n: i32) -> &'static str {
    match n {
        0 => "Text",
        1 => "Image",
        2 => "Audio",
        3 => "Video",
        4 => "Contact",
        5 => "Location",
        6 => "MediaOmitted",
        7 => "StatusUpdate",
        8 => "VoiceNote",
        9 => "Document",
        10 => "MissedVoiceCall",
        11 => "MissedVideoCall",
        12 => "MediaCiphertextUnknown",
        13 => "Gif",
        14 => "Deleted",
        15 => "Deleted",
        16 => "LiveLocation",
        20 => "Sticker",
        _ => "Unknown",
    }
}

/// WhatsApp message types that represent media content.
pub fn is_media_type(msg_type: i32) -> bool {
    matches!(msg_type, 1 | 2 | 3 | 5 | 8 | 13 | 20 | 42 | 64)
}

/// Fallback MIME type when the DB doesn't store one.
pub fn default_mime_for_type(msg_type: i32) -> &'static str {
    match msg_type {
        1 => "image/jpeg",
        2 => "audio/ogg",
        3 => "video/mp4",
        5 | 42 => "application/vnd.geo+json", // location, live location
        8 => "application/octet-stream",
        13 => "image/gif",
        20 => "image/webp",
        64 => "text/vcard",
        _ => "application/octet-stream",
    }
}

// Column positions for msgstore.db tables are resolved BY NAME at runtime from
// each table's `CREATE TABLE` DDL (see `ddl_column_indices` / `cols_of` in
// extractor.rs), not hardcoded here. The real modern schema orders columns very
// differently from the legacy one (e.g. message.timestamp is values[11], not [4];
// jid.raw_string is values[5], not [1]), so fixed ordinals silently misread every
// real database. Name resolution keeps the same map correct across schema versions
// and degrades to `None` (omit) for columns a given schema lacks.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_legacy_detection() {
        assert_eq!(
            detect_schema_version(0, &["messages", "wa_contacts"]),
            SchemaVersion::Legacy
        );
    }

    #[test]
    fn test_schema_modern_by_user_version() {
        assert_eq!(
            detect_schema_version(200, &["messages"]),
            SchemaVersion::Modern
        );
    }

    #[test]
    fn test_schema_modern_by_tables() {
        assert_eq!(
            detect_schema_version(0, &["message", "message_media", "jid"]),
            SchemaVersion::Modern
        );
    }

    #[test]
    fn test_schema_modern_both_conditions() {
        assert_eq!(
            detect_schema_version(200, &["message", "jid"]),
            SchemaVersion::Modern
        );
    }
}
