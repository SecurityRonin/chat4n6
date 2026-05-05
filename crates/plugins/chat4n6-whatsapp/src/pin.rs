use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PinExpiry {
    Hours24,
    Days7,
    Days30,
    Custom(u64),
    NoExpiry,
}

impl PinExpiry {
    pub fn from_secs(secs: u64) -> Self {
        todo!("implement from_secs")
    }

    /// Returns None for NoExpiry.
    pub fn as_secs(&self) -> Option<u64> {
        todo!("implement as_secs")
    }

    pub fn human_readable(&self) -> &'static str {
        todo!("implement human_readable")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PinRecord {
    pub message_id: i64,
    pub pinned_by_jid: Option<String>,
    pub conversation_id: i64,
    pub timestamp_ms: i64,
    pub expiry: PinExpiry,
    pub is_active: bool,
}

pub fn parse_pin(
    message_id: i64,
    pinned_by_jid: Option<&str>,
    conversation_id: i64,
    timestamp_ms: i64,
    expiry_duration_secs: u64,
    pin_state: i32, // 1=active, 0=unpinned
) -> PinRecord {
    todo!("implement parse_pin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_24h_expiry() {
        let e = PinExpiry::from_secs(86400);
        assert_eq!(e, PinExpiry::Hours24);
    }

    #[test]
    fn test_7d_expiry() {
        let e = PinExpiry::from_secs(604800);
        assert_eq!(e, PinExpiry::Days7);
    }

    #[test]
    fn test_30d_expiry() {
        let e = PinExpiry::from_secs(2592000);
        assert_eq!(e, PinExpiry::Days30);
    }

    #[test]
    fn test_custom_expiry() {
        let e = PinExpiry::from_secs(999);
        assert_eq!(e, PinExpiry::Custom(999));
    }

    #[test]
    fn test_no_expiry_zero() {
        let e = PinExpiry::from_secs(0);
        assert_eq!(e, PinExpiry::NoExpiry);
    }

    #[test]
    fn test_active_state() {
        let r = parse_pin(1, Some("alice@s.whatsapp.net"), 10, 1000, 86400, 1);
        assert!(r.is_active);
    }

    #[test]
    fn test_unpinned_state() {
        let r = parse_pin(2, None, 10, 2000, 86400, 0);
        assert!(!r.is_active);
    }

    #[test]
    fn test_human_readable_24h() {
        assert_eq!(PinExpiry::Hours24.human_readable(), "24 hours");
    }

    #[test]
    fn test_human_readable_7d() {
        assert_eq!(PinExpiry::Days7.human_readable(), "7 days");
    }

    #[test]
    fn test_human_readable_30d() {
        assert_eq!(PinExpiry::Days30.human_readable(), "30 days");
    }

    #[test]
    fn test_as_secs_no_expiry_returns_none() {
        assert_eq!(PinExpiry::NoExpiry.as_secs(), None);
    }

    #[test]
    fn test_as_secs_hours24() {
        assert_eq!(PinExpiry::Hours24.as_secs(), Some(86400));
    }

    #[test]
    fn test_pinned_by_jid_preserved() {
        let r = parse_pin(5, Some("bob@s.whatsapp.net"), 20, 5000, 604800, 1);
        assert_eq!(r.pinned_by_jid, Some("bob@s.whatsapp.net".to_string()));
        assert_eq!(r.expiry, PinExpiry::Days7);
    }
}
