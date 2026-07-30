use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocationPoint {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_meters: Option<f32>,
    pub speed_mps: Option<f32>,
    pub bearing_degrees: Option<f32>,
    pub timestamp_ms: i64,
    pub source: LocationPointSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LocationPointSource {
    MainDb,
    WalRecovered,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveLocationTrajectory {
    pub sharer_jid: String,
    pub session_start_ms: i64,
    pub session_end_ms: Option<i64>,
    pub share_duration_secs: Option<u64>,
    pub points: Vec<LocationPoint>,
    pub wal_points_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticLocation {
    pub message_id: i64,
    pub latitude: f64,
    pub longitude: f64,
    pub place_name: Option<String>,
    pub place_address: Option<String>,
    pub thumbnail_b64: Option<String>,
    pub live: bool,
}

/// Build a live location trajectory from a set of raw location points.
/// Filters out (0.0, 0.0) coordinates as invalid.
/// Sorts points by timestamp.
pub fn build_trajectory(
    sharer_jid: &str,
    session_start_ms: i64,
    session_end_ms: Option<i64>,
    share_duration_secs: Option<u64>,
    raw_points: Vec<LocationPoint>,
) -> LiveLocationTrajectory {
    let mut filtered: Vec<LocationPoint> = raw_points
        .into_iter()
        .filter(|p| !(p.latitude == 0.0 && p.longitude == 0.0))
        .collect();

    filtered.sort_by_key(|p| p.timestamp_ms);

    let wal_points_count = filtered
        .iter()
        .filter(|p| p.source == LocationPointSource::WalRecovered)
        .count();

    LiveLocationTrajectory {
        sharer_jid: sharer_jid.to_string(),
        session_start_ms,
        session_end_ms,
        share_duration_secs,
        points: filtered,
        wal_points_count,
    }
}

/// Generate an OpenStreetMap preview URL for a coordinate pair.
pub fn osm_url(lat: f64, lon: f64) -> String {
    format!(
        "https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15",
        lat = lat,
        lon = lon
    )
}

/// Returns true if the coordinate is a valid GPS fix (not 0,0 and within range).
pub fn is_valid_coordinate(lat: f64, lon: f64) -> bool {
    if lat == 0.0 && lon == 0.0 {
        return false;
    }
    lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(lat: f64, lon: f64, ts: i64, source: LocationPointSource) -> LocationPoint {
        LocationPoint {
            latitude: lat,
            longitude: lon,
            accuracy_meters: None,
            speed_mps: None,
            bearing_degrees: None,
            timestamp_ms: ts,
            source,
        }
    }

    #[test]
    fn test_trajectory_sorted_by_timestamp() {
        let pts = vec![
            make_point(1.0, 2.0, 300, LocationPointSource::MainDb),
            make_point(3.0, 4.0, 100, LocationPointSource::MainDb),
            make_point(5.0, 6.0, 200, LocationPointSource::MainDb),
        ];
        let t = build_trajectory("jid@s.whatsapp.net", 0, None, None, pts);
        assert_eq!(t.points[0].timestamp_ms, 100);
        assert_eq!(t.points[1].timestamp_ms, 200);
        assert_eq!(t.points[2].timestamp_ms, 300);
    }

    #[test]
    fn test_zero_zero_filtered() {
        let pts = vec![
            make_point(0.0, 0.0, 100, LocationPointSource::MainDb),
            make_point(1.0, 2.0, 200, LocationPointSource::MainDb),
        ];
        let t = build_trajectory("jid@s.whatsapp.net", 0, None, None, pts);
        assert_eq!(t.points.len(), 1);
        assert_eq!(t.points[0].latitude, 1.0);
    }

    #[test]
    fn test_wal_point_count_tracked() {
        let pts = vec![
            make_point(1.0, 2.0, 100, LocationPointSource::WalRecovered),
            make_point(3.0, 4.0, 200, LocationPointSource::MainDb),
            make_point(5.0, 6.0, 300, LocationPointSource::WalRecovered),
        ];
        let t = build_trajectory("jid@s.whatsapp.net", 0, None, None, pts);
        assert_eq!(t.wal_points_count, 2);
    }

    #[test]
    fn test_osm_url_format() {
        let url = osm_url(51.5074, -0.1278);
        assert!(url.starts_with("https://www.openstreetmap.org"), "url: {url}");
        assert!(url.contains("51.5074"), "url: {url}");
        assert!(url.contains("-0.1278") || url.contains("0.1278"), "url: {url}");
    }

    #[test]
    fn test_valid_coordinate_normal() {
        assert!(is_valid_coordinate(37.7749, -122.4194));
    }

    #[test]
    fn test_invalid_coordinate_zero_zero() {
        assert!(!is_valid_coordinate(0.0, 0.0));
    }

    #[test]
    fn test_invalid_coordinate_out_of_range() {
        assert!(!is_valid_coordinate(91.0, 0.0));
        assert!(!is_valid_coordinate(0.0, 181.0));
    }

    #[test]
    fn test_single_point_trajectory() {
        let pts = vec![make_point(10.0, 20.0, 500, LocationPointSource::MainDb)];
        let t = build_trajectory("a@s.whatsapp.net", 100, None, None, pts);
        assert_eq!(t.points.len(), 1);
    }

    #[test]
    fn test_empty_trajectory() {
        let t = build_trajectory("a@s.whatsapp.net", 0, None, None, vec![]);
        assert_eq!(t.points.len(), 0);
        assert_eq!(t.wal_points_count, 0);
    }

    #[test]
    fn test_session_end_preserved() {
        let t = build_trajectory("a@s.whatsapp.net", 1000, Some(9000), None, vec![]);
        assert_eq!(t.session_end_ms, Some(9000));
    }

    #[test]
    fn test_duration_preserved() {
        let t = build_trajectory("a@s.whatsapp.net", 0, None, Some(3600), vec![]);
        assert_eq!(t.share_duration_secs, Some(3600));
    }

    #[test]
    fn test_sharer_jid_preserved() {
        let t = build_trajectory("bob@s.whatsapp.net", 0, None, None, vec![]);
        assert_eq!(t.sharer_jid, "bob@s.whatsapp.net");
    }
}
