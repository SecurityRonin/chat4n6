#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SchemaVersion {
    Legacy,
    Modern,
}

/// Detect the WhatsApp msgstore.db schema version from the tables present.
/// - Modern: has both "message" and "jid" tables
/// - Legacy: otherwise ("messages" + "wa_contacts" era)
///
/// `user_version` carries no schema-generation signal: a real 2023-era device
/// reports 1, so a `>= 100` test classified legacy databases as modern and
/// modern ones as legacy depending on nothing but the app's own counter.
pub fn detect_schema_version(_user_version: u32, tables: &[&str]) -> SchemaVersion {
    if tables.contains(&"message") && tables.contains(&"jid") {
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

    /// A real 2023-era device reports `user_version = 1`, so the version number
    /// carries no schema-generation signal.  Table presence is the reliable one.
    #[test]
    fn real_device_user_version_1_with_modern_tables_is_modern() {
        assert_eq!(
            detect_schema_version(1, &["message", "jid", "chat", "call_log"]),
            SchemaVersion::Modern
        );
    }

    /// `user_version` alone must not promote a legacy-table database to Modern:
    /// the number is app-defined and unrelated to the schema generation.
    #[test]
    fn high_user_version_alone_does_not_imply_modern() {
        assert_eq!(
            detect_schema_version(200, &["messages", "wa_contacts"]),
            SchemaVersion::Legacy,
            "classification must follow the tables that are actually present"
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
