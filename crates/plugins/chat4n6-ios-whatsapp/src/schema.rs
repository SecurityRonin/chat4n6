/// Apple CoreData epoch offset: seconds between 2001-01-01T00:00:00Z and Unix epoch.
pub const APPLE_EPOCH_OFFSET: f64 = 978_307_200.0;

/// Convert Apple CoreData timestamp (seconds since 2001-01-01) to Unix milliseconds.
#[inline]
pub fn apple_epoch_to_utc_ms(secs: f64) -> i64 {
    ((secs + APPLE_EPOCH_OFFSET) * 1000.0) as i64
}

/// WhatsApp iOS message types (ZMESSAGETYPE).
pub mod msg_type {
    pub const TEXT: i32 = 0;
    pub const IMAGE: i32 = 1;
    pub const VIDEO: i32 = 2;
    pub const AUDIO: i32 = 3;
    pub const CONTACT: i32 = 4;
    pub const LOCATION: i32 = 5;
    pub const SYSTEM_MSG: i32 = 6;
    pub const VOIP_EVENT: i32 = 7;
    pub const DELETED: i32 = 8;
    pub const DOCUMENT: i32 = 9;
    pub const CALL_EVENT: i32 = 10;
    pub const GIF: i32 = 11;
    pub const WAITING: i32 = 12;
    pub const ENCRYPTION_NOTIFICATION: i32 = 13;
    pub const DELETED_BY_SENDER: i32 = 14;
    pub const STICKER: i32 = 15;
    pub const LIVE_LOCATION: i32 = 16;
    pub const PRODUCT_MESSAGE: i32 = 20;
    pub const VIEW_ONCE_IMAGE: i32 = 38;
    pub const VIEW_ONCE_VIDEO: i32 = 39;
    pub const POLL: i32 = 46;
    pub const VIEW_ONCE_AUDIO: i32 = 53;
    pub const PTV: i32 = 54;
    pub const VOICE_NOTE: i32 = 59;
    pub const MESSAGE_ASSOCIATION: i32 = 66;

    // Legacy aliases kept for callers that used the old names
    pub const VCARD: i32 = CONTACT;
    pub const SYSTEM: i32 = STICKER; // old SYSTEM=15 mapped to Sticker slot; see message_type_label
}

/// Human-readable label for a ZMESSAGETYPE value.
pub fn message_type_label(_t: i32) -> &'static str {
    todo!("Task 1: implement message_type_label")
}

/// Returns true if the message type carries media content.
pub fn is_media_type(t: i32) -> bool {
    matches!(t, msg_type::IMAGE | msg_type::AUDIO | msg_type::VIDEO)
}

/// Default MIME type for a given message type.
pub fn default_mime_for_type(t: i32) -> &'static str {
    match t {
        msg_type::IMAGE => "image/jpeg",
        msg_type::AUDIO => "audio/mpeg",
        msg_type::VIDEO => "video/mp4",
        _ => "application/octet-stream",
    }
}

/// Detect millisecond CoreData timestamps and normalise to seconds.
/// Values > 4_000_000_000 are treated as milliseconds.
#[inline]
pub fn normalise_coredata_secs(raw: f64) -> f64 {
    todo!("Task 4: implement normalise_coredata_secs")
}

/// Convert a raw ZMESSAGEDATE value (may be seconds or milliseconds) to Unix ms.
#[inline]
pub fn zmessagedate_to_utc_ms(raw: f64) -> i64 {
    apple_epoch_to_utc_ms(normalise_coredata_secs(raw))
}

/// Detect forwarded flag from ZFLAGS bitmask.
/// Both bit 7 (0x80) AND bit 8 (0x100) must be set.
#[inline]
pub fn zflags_is_forwarded(flags: i64) -> bool {
    todo!("Task 2: implement zflags_is_forwarded")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Task 1: message_type_label ────────────────────────────────────────────

    #[test]
    fn message_type_label_view_once_image() {
        assert_eq!(message_type_label(38), "ViewOnceImage");
    }

    #[test]
    fn message_type_label_view_once_video() {
        assert_eq!(message_type_label(39), "ViewOnceVideo");
    }

    #[test]
    fn message_type_label_poll() {
        assert_eq!(message_type_label(46), "Poll");
    }

    #[test]
    fn message_type_label_view_once_audio() {
        assert_eq!(message_type_label(53), "ViewOnceAudio");
    }

    #[test]
    fn message_type_label_ptv() {
        assert_eq!(message_type_label(54), "PTV");
    }

    #[test]
    fn message_type_label_voice_note() {
        assert_eq!(message_type_label(59), "VoiceNote");
    }

    #[test]
    fn message_type_label_known_types() {
        assert_eq!(message_type_label(0), "Text");
        assert_eq!(message_type_label(1), "Image");
        assert_eq!(message_type_label(2), "Video");
        assert_eq!(message_type_label(3), "Audio");
        assert_eq!(message_type_label(6), "SystemMessage");
        assert_eq!(message_type_label(8), "Deleted");
        assert_eq!(message_type_label(15), "Sticker");
        assert_eq!(message_type_label(999), "Unknown");
    }

    // ── Task 2: zflags_is_forwarded ──────────────────────────────────────────

    #[test]
    fn zflags_forwarded_both_bits() {
        // 0x180 = bits 7+8 set → forwarded
        assert!(zflags_is_forwarded(0x180), "0x180 must be forwarded");
    }

    #[test]
    fn zflags_not_forwarded_only_bit7() {
        // 0x80 = only bit 7 → NOT forwarded
        assert!(!zflags_is_forwarded(0x80), "0x80 alone must NOT be forwarded");
    }

    #[test]
    fn zflags_not_forwarded_only_bit8() {
        // 0x100 = only bit 8 → NOT forwarded
        assert!(!zflags_is_forwarded(0x100), "0x100 alone must NOT be forwarded");
    }

    #[test]
    fn zflags_forwarded_superset() {
        // 0x1FF has both bits set among others → forwarded
        assert!(zflags_is_forwarded(0x1FF), "0x1FF must be forwarded");
    }

    // ── Task 4: zmessagedate_to_utc_ms ───────────────────────────────────────

    #[test]
    fn zmessagedate_seconds_value() {
        // 600000000.0 seconds (< 4e9) → add epoch offset
        let expected = ((600_000_000.0f64 + 978_307_200.0) * 1000.0) as i64;
        assert_eq!(zmessagedate_to_utc_ms(600_000_000.0), expected);
    }

    #[test]
    fn zmessagedate_milliseconds_value() {
        // 600000000000.0 ms (> 4e9) → divide by 1000 first, then add epoch
        let secs = 600_000_000_000.0f64 / 1000.0;
        let expected = ((secs + 978_307_200.0) * 1000.0) as i64;
        assert_eq!(zmessagedate_to_utc_ms(600_000_000_000.0), expected);
    }
}
