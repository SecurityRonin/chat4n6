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
    pub const AUDIO: i32 = 2;
    pub const VIDEO: i32 = 3;
    pub const LOCATION: i32 = 5;
    pub const VCARD: i32 = 6;
    pub const DELETED: i32 = 8;
    pub const SYSTEM: i32 = 15;
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
