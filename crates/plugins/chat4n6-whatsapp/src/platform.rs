use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SenderPlatform {
    Android,
    IPhone,
    Companion,      // Web/Desktop linked device
    AndroidLinked,  // secondary Android device
    IPhoneLinked,   // secondary iPhone device
    BusinessApi,    // WhatsApp Business Cloud API bot
    OldAndroid,     // numeric key_id ≤10 chars
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformClassification {
    pub platform: SenderPlatform,
    pub confidence: f32,
}

/// Classify the sending platform from a WhatsApp `key_id` hex string.
///
/// Classification rules validated against real devices by WAInsight.
/// TODO: implement full classification logic.
pub fn classify_key_id(
    _key_id: &str,
    _from_me: bool,
    _device_number: Option<u32>,
) -> PlatformClassification {
    // STUB — always returns Unknown; tests will fail until implemented
    PlatformClassification {
        platform: SenderPlatform::Unknown,
        confidence: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(key_id: &str, from_me: bool, device_number: Option<u32>) -> (SenderPlatform, f32) {
        let c = classify_key_id(key_id, from_me, device_number);
        (c.platform, c.confidence)
    }

    // ── len=8 tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_len8_from_me_true_android_085() {
        let (p, c) = classify("ABCD1234", true, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.85).abs() < 0.001, "confidence should be 0.85, got {c}");
    }

    #[test]
    fn test_len8_from_me_false_android_075() {
        let (p, c) = classify("ABCD1234", false, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.75).abs() < 0.001, "confidence should be 0.75, got {c}");
    }

    // ── len=16 tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_len16_prefix_ac_android_097() {
        let (p, c) = classify("AC1234567890ABCD", false, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.97).abs() < 0.001);
    }

    #[test]
    fn test_len16_prefix_ac_lowercase_android_097() {
        let (p, c) = classify("ac1234567890abcd", false, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.97).abs() < 0.001, "case-insensitive prefix match should give 0.97");
    }

    #[test]
    fn test_len16_no_ac_prefix_android_085() {
        let (p, c) = classify("BB1234567890ABCD", false, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.85).abs() < 0.001);
    }

    // ── len=18 BusinessApi exclusive ─────────────────────────────────────────

    #[test]
    fn test_len18_business_api_exclusive() {
        let (p, c) = classify("AABBCCDDEEFF001122", false, None);
        assert_eq!(p, SenderPlatform::BusinessApi);
        assert!((c - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_len18_business_api_from_me_true() {
        let (p, _) = classify("AABBCCDDEEFF001122", true, None);
        assert_eq!(p, SenderPlatform::BusinessApi);
    }

    // ── len=20 iPhone/Companion ───────────────────────────────────────────────

    #[test]
    fn test_len20_prefix_3a_iphone_095() {
        let (p, c) = classify("3A1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::IPhone);
        assert!((c - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_len20_prefix_5e_iphone_095() {
        let (p, c) = classify("5E1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::IPhone);
        assert!((c - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_len20_prefix_2a_iphone_095() {
        let (p, c) = classify("2A1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::IPhone);
        assert!((c - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_len20_prefix_3f_companion_080() {
        let (p, c) = classify("3F1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.80).abs() < 0.001);
    }

    #[test]
    fn test_len20_prefix_3b_companion_080() {
        let (p, c) = classify("3B1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.80).abs() < 0.001);
    }

    #[test]
    fn test_len20_unknown_prefix_iphone_070() {
        let (p, c) = classify("FF1234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::IPhone);
        assert!((c - 0.70).abs() < 0.001);
    }

    // ── len=22 Companion ─────────────────────────────────────────────────────

    #[test]
    fn test_len22_prefix_3eb0_companion_095() {
        let (p, c) = classify("3EB01234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_len22_prefix_3e_not_3eb0_companion_092() {
        let (p, c) = classify("3E991234567890ABCDEF12", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.92).abs() < 0.001);
    }

    #[test]
    fn test_len22_other_prefix_companion_070() {
        let (p, c) = classify("AA1234567890ABCDEF1234", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.70).abs() < 0.001);
    }

    // ── len=32 Android/AndroidLinked ─────────────────────────────────────────

    #[test]
    fn test_len32_device_number_gt0_android_linked() {
        let (p, c) = classify("AABBCCDDEEFF00112233445566778899", false, Some(2));
        assert_eq!(p, SenderPlatform::AndroidLinked);
        assert!((c - 0.90).abs() < 0.001);
    }

    #[test]
    fn test_len32_device_number_0_prefix_ac_android_097() {
        let (p, c) = classify("AC0BCCDDEEFF00112233445566778899", false, Some(0));
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.97).abs() < 0.001);
    }

    #[test]
    fn test_len32_device_number_none_no_ac_android_090() {
        let (p, c) = classify("BB0BCCDDEEFF00112233445566778899", false, None);
        assert_eq!(p, SenderPlatform::Android);
        assert!((c - 0.90).abs() < 0.001);
    }

    // ── len=40 Companion ─────────────────────────────────────────────────────

    #[test]
    fn test_len40_companion_075() {
        let (p, c) = classify("AABBCCDDEEFF00112233445566778899AABBCCDD", false, None);
        assert_eq!(p, SenderPlatform::Companion);
        assert!((c - 0.75).abs() < 0.001);
    }

    // ── OldAndroid ───────────────────────────────────────────────────────────

    #[test]
    fn test_old_android_numeric_short() {
        let (p, c) = classify("1234567890", false, None);
        assert_eq!(p, SenderPlatform::OldAndroid);
        assert!((c - 0.70).abs() < 0.001);
    }

    #[test]
    fn test_short_with_hex_letters_not_old_android() {
        // len=8 → Android (not OldAndroid)
        let (p, _) = classify("1234ABCD", false, None);
        assert_eq!(p, SenderPlatform::Android);
    }

    // ── empty / unknown ──────────────────────────────────────────────────────

    #[test]
    fn test_empty_key_id_unknown() {
        let (p, c) = classify("", false, None);
        assert_eq!(p, SenderPlatform::Unknown);
        assert!((c - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_unknown_length_returns_unknown() {
        // len=11, non-digit chars, no matching rule
        let (p, c) = classify("AABBCCDDEE1", false, None);
        assert_eq!(p, SenderPlatform::Unknown);
        assert!((c - 0.0).abs() < 0.001);
    }

    // ── serialization round-trip ─────────────────────────────────────────────

    #[test]
    fn test_platform_classification_serializes() {
        let pc = PlatformClassification {
            platform: SenderPlatform::IPhone,
            confidence: 0.95,
        };
        let json = serde_json::to_string(&pc).expect("serialize");
        let back: PlatformClassification = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pc, back);
    }
}
