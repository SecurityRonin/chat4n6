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
/// Classification rules validated against real devices by WAInsight:
/// - len=8:  from_me=true → Android 0.85; false → Android 0.75
/// - len=16: prefix "AC" → Android 0.97; else Android 0.85
/// - len=18: → BusinessApi 0.95 (exclusive 18-char space)
/// - len=20: prefix "3A"/"5E"/"4A"/"2A" → IPhone 0.95;
///           prefix "3F"/"3E"/"3B" → Companion 0.80; else IPhone 0.70
/// - len=22: prefix "3EB0" → Companion 0.95; prefix "3E" → Companion 0.92;
///           else Companion 0.70
/// - len=32: device_number>0 → AndroidLinked 0.90; prefix "AC" → Android 0.97;
///           else Android 0.90
/// - len=40: → Companion 0.75
/// - len≤10 AND all digits: → OldAndroid 0.70
/// - empty OR anything else: → Unknown 0.0
pub fn classify_key_id(
    key_id: &str,
    from_me: bool,
    device_number: Option<u32>,
) -> PlatformClassification {
    if key_id.is_empty() {
        return PlatformClassification {
            platform: SenderPlatform::Unknown,
            confidence: 0.0,
        };
    }

    let upper = key_id.to_uppercase();
    let len = key_id.len();

    match len {
        8 => {
            let confidence = if from_me { 0.85 } else { 0.75 };
            PlatformClassification {
                platform: SenderPlatform::Android,
                confidence,
            }
        }
        16 => {
            let confidence = if upper.starts_with("AC") { 0.97 } else { 0.85 };
            PlatformClassification {
                platform: SenderPlatform::Android,
                confidence,
            }
        }
        18 => PlatformClassification {
            platform: SenderPlatform::BusinessApi,
            confidence: 0.95,
        },
        20 => {
            if upper.starts_with("3A")
                || upper.starts_with("5E")
                || upper.starts_with("4A")
                || upper.starts_with("2A")
            {
                PlatformClassification {
                    platform: SenderPlatform::IPhone,
                    confidence: 0.95,
                }
            } else if upper.starts_with("3F")
                || upper.starts_with("3E")
                || upper.starts_with("3B")
            {
                PlatformClassification {
                    platform: SenderPlatform::Companion,
                    confidence: 0.80,
                }
            } else {
                PlatformClassification {
                    platform: SenderPlatform::IPhone,
                    confidence: 0.70,
                }
            }
        }
        22 => {
            if upper.starts_with("3EB0") {
                PlatformClassification {
                    platform: SenderPlatform::Companion,
                    confidence: 0.95,
                }
            } else if upper.starts_with("3E") {
                PlatformClassification {
                    platform: SenderPlatform::Companion,
                    confidence: 0.92,
                }
            } else {
                PlatformClassification {
                    platform: SenderPlatform::Companion,
                    confidence: 0.70,
                }
            }
        }
        32 => {
            if device_number.map_or(false, |d| d > 0) {
                PlatformClassification {
                    platform: SenderPlatform::AndroidLinked,
                    confidence: 0.90,
                }
            } else if upper.starts_with("AC") {
                PlatformClassification {
                    platform: SenderPlatform::Android,
                    confidence: 0.97,
                }
            } else {
                PlatformClassification {
                    platform: SenderPlatform::Android,
                    confidence: 0.90,
                }
            }
        }
        40 => PlatformClassification {
            platform: SenderPlatform::Companion,
            confidence: 0.75,
        },
        _ => {
            // OldAndroid: len≤10 AND all hex chars are digits (0-9)
            if len <= 10 && key_id.chars().all(|c| c.is_ascii_digit()) {
                PlatformClassification {
                    platform: SenderPlatform::OldAndroid,
                    confidence: 0.70,
                }
            } else {
                PlatformClassification {
                    platform: SenderPlatform::Unknown,
                    confidence: 0.0,
                }
            }
        }
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
