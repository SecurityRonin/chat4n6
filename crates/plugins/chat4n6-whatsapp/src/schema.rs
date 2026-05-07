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
        0  => "Text",
        1  => "Image",
        2  => "Audio",
        3  => "Video",
        4  => "Contact",
        5  => "Location",
        6  => "MediaOmitted",
        7  => "StatusUpdate",
        8  => "VoiceNote",
        9  => "Document",
        10 => "MissedVoiceCall",
        11 => "MissedVideoCall",
        12 => "MediaCiphertextUnknown",
        13 => "Gif",
        14 => "Deleted",
        15 => "Deleted",
        16 => "LiveLocation",
        20 => "Sticker",
        _  => "Unknown",
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

/// Named column index constants for msgstore.db tables.
///
/// The btree walker stores INTEGER PRIMARY KEY as SqlValue::Null at values[0].
/// Real column data starts at values[1] (matching the DDL column order after _id).
pub mod cols {
    /// message table (modern schema, post-2021)
    pub mod message {
        pub const CHAT_ROW_ID: usize = 1;
        pub const SENDER_JID_ROW_ID: usize = 2;
        pub const FROM_ME: usize = 3;
        pub const TIMESTAMP: usize = 4;
        pub const TEXT_DATA: usize = 5;
        pub const MESSAGE_TYPE: usize = 6;
        pub const MEDIA_MIME_TYPE: usize = 7;
        pub const MEDIA_NAME: usize = 8;
        pub const STARRED: usize = 9;
        pub const EDIT_VERSION: usize = 10;
    }

    /// jid table
    pub mod jid {
        pub const RAW_STRING: usize = 1;
    }

    /// chat table
    pub mod chat {
        pub const JID_ROW_ID: usize = 1;
        pub const SUBJECT: usize = 2;
        pub const ARCHIVED: usize = 3;
    }

    /// call_log table
    pub mod call_log {
        pub const JID_ROW_ID: usize = 1;
        pub const FROM_ME: usize = 2;
        pub const VIDEO_CALL: usize = 3;
        pub const DURATION: usize = 4;
        pub const TIMESTAMP: usize = 5;
        pub const CALL_RESULT: usize = 6;
        pub const CALL_ROW_ID: usize = 7;
        pub const CALL_CREATOR_DEVICE_JID_ROW_ID: usize = 8;
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
