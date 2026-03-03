use chrono::TimeZone;
use chrono::Utc;
use chrono_tz::Tz;

/// Resolve a timezone name or UTC offset string to seconds east of UTC.
///
/// Accepts:
/// - Named IANA zones: "Asia/Manila", "UTC", "America/New_York"
/// - Numeric offset strings: "+08:00", "-05:30", "+00:00"
///
/// Returns None for unrecognised input.
pub fn resolve_timezone_offset(tz: &str) -> Option<i32> {
    // Try named IANA zone first
    if let Ok(tz_enum) = tz.parse::<Tz>() {
        let now = Utc::now();
        let offset = tz_enum.offset_from_utc_datetime(&now.naive_utc());
        use chrono::Offset;
        return Some(offset.fix().local_minus_utc());
    }
    // Try +HH:MM or -HH:MM
    parse_numeric_offset(tz)
}

fn parse_numeric_offset(s: &str) -> Option<i32> {
    let (sign, rest) = if let Some(r) = s.strip_prefix('+') {
        (1i32, r)
    } else if let Some(r) = s.strip_prefix('-') {
        (-1i32, r)
    } else {
        return None;
    };
    let mut parts = rest.splitn(2, ':');
    let h: i32 = parts.next()?.parse().ok()?;
    let m: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    // UTC+14:00 is the maximum (Kiribati); +14:xx with any minutes doesn't exist.
    if h > 14 || (h == 14 && m != 0) || m >= 60 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

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
