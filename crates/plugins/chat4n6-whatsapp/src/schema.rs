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
