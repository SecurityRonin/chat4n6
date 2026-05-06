use chrono::TimeZone;
use chrono::Utc;
use chrono_tz::Tz;

/// Resolve a timezone name or UTC offset string to seconds east of UTC.
///
/// Accepts IANA zone names ("Asia/Manila") and numeric offsets ("+08:00", "-05:30").
/// Returns `None` for unrecognised input.
pub fn resolve_timezone_offset(tz: &str) -> Option<i32> {
    if let Ok(tz_enum) = tz.parse::<Tz>() {
        let now = Utc::now();
        let offset = tz_enum.offset_from_utc_datetime(&now.naive_utc());
        use chrono::Offset;
        return Some(offset.fix().local_minus_utc());
    }
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
    if h > 14 || (h == 14 && m != 0) || m >= 60 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}
