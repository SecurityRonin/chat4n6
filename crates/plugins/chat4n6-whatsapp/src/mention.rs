use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MentionType {
    Person,         // type 0 — specific @person
    GroupBroadcast, // type 1 — @group
    Everyone,       // type 2 — @all/@everyone
    MetaAiBot,      // special: mentioned JID is a known Meta AI bot number
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mention {
    pub mentioned_jid: String,
    pub mention_type: MentionType,
    pub display_name: Option<String>,
}

/// Parse mention type integer to MentionType.
/// Meta AI bot JIDs take priority over raw type.
pub fn classify_mention_type(raw_type: Option<i32>, jid: &str) -> MentionType {
    todo!("implement classify_mention_type")
}

/// Known Meta AI bot JID prefixes/numbers.
/// NOTE: These are example/placeholder values derived from APK JADX analysis.
/// Real production numbers may differ.
/// Returns true if the JID matches a known Meta AI bot identifier.
pub fn is_meta_ai_bot(jid: &str) -> bool {
    todo!("implement is_meta_ai_bot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_0_is_person() {
        let t = classify_mention_type(Some(0), "alice@s.whatsapp.net");
        assert_eq!(t, MentionType::Person);
    }

    #[test]
    fn test_type_1_is_group_broadcast() {
        let t = classify_mention_type(Some(1), "group@g.us");
        assert_eq!(t, MentionType::GroupBroadcast);
    }

    #[test]
    fn test_type_2_is_everyone() {
        let t = classify_mention_type(Some(2), "group@g.us");
        assert_eq!(t, MentionType::Everyone);
    }

    #[test]
    fn test_none_type_defaults_to_person() {
        let t = classify_mention_type(None, "alice@s.whatsapp.net");
        assert_eq!(t, MentionType::Person);
    }

    #[test]
    fn test_meta_ai_jid_returns_meta_ai_bot() {
        let t = classify_mention_type(Some(0), "13135550002@s.whatsapp.net");
        assert_eq!(t, MentionType::MetaAiBot);
    }

    #[test]
    fn test_unknown_positive_int_defaults_to_person() {
        let t = classify_mention_type(Some(99), "unknown@s.whatsapp.net");
        assert_eq!(t, MentionType::Person);
    }

    #[test]
    fn test_is_meta_ai_bot_known_number() {
        assert!(is_meta_ai_bot("13135550002@s.whatsapp.net"));
        assert!(is_meta_ai_bot("18005551234@s.whatsapp.net"));
    }

    #[test]
    fn test_is_meta_ai_bot_regular_jid() {
        assert!(!is_meta_ai_bot("alice@s.whatsapp.net"));
        assert!(!is_meta_ai_bot("1234567890@s.whatsapp.net"));
    }

    #[test]
    fn test_jid_preserved_in_struct() {
        let m = Mention {
            mentioned_jid: "bob@s.whatsapp.net".to_string(),
            mention_type: MentionType::Person,
            display_name: Some("Bob".to_string()),
        };
        assert_eq!(m.mentioned_jid, "bob@s.whatsapp.net");
        assert_eq!(m.display_name, Some("Bob".to_string()));
    }
}
