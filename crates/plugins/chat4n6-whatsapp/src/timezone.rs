// Re-export from the shared plugin-api; keep tests here for regression coverage.
pub use chat4n6_plugin_api::resolve_timezone_offset;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tz_offset_named_manila() {
        let offset = resolve_timezone_offset("Asia/Manila").unwrap();
        assert_eq!(offset, 8 * 3600);
    }

    #[test]
    fn test_parse_tz_offset_numeric_positive() {
        let offset = resolve_timezone_offset("+08:00").unwrap();
        assert_eq!(offset, 8 * 3600);
    }

    #[test]
    fn test_parse_tz_offset_numeric_negative() {
        let offset = resolve_timezone_offset("-05:30").unwrap();
        assert_eq!(offset, -(5 * 3600 + 30 * 60));
    }

    #[test]
    fn test_utc_fallback() {
        let offset = resolve_timezone_offset("UTC").unwrap();
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_invalid_tz_returns_none() {
        assert!(resolve_timezone_offset("NotAZone").is_none());
    }

    #[test]
    fn test_invalid_numeric_returns_none() {
        assert!(resolve_timezone_offset("08:00").is_none()); // missing sign
    }

    #[test]
    fn test_invalid_plus14_30_returns_none() {
        assert!(resolve_timezone_offset("+14:30").is_none());
    }
}
