use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PollOption {
    pub option_id: i64,
    pub option_text: String,
    pub vote_count: u32,
    pub voter_jids: Vec<String>,
    pub voter_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PollRecord {
    pub message_id: i64,
    pub question: String,
    pub allow_multiple_answers: bool,
    pub total_voters: u32,
    pub options: Vec<PollOption>,
}

/// Build a PollRecord from raw data.
/// voter_name_map: JID → display name (empty map = JIDs shown as-is)
pub fn build_poll(
    message_id: i64,
    question: &str,
    allow_multiple: bool,
    options: Vec<(&str, Vec<String>)>,
    voter_name_map: &HashMap<String, String>,
) -> PollRecord {
    todo!("implement build_poll")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_single_option_poll() {
        let opts = vec![("Yes", jids(&["a@s.whatsapp.net"]))];
        let r = build_poll(1, "Do you agree?", false, opts, &HashMap::new());
        assert_eq!(r.options.len(), 1);
        assert_eq!(r.options[0].option_text, "Yes");
        assert_eq!(r.options[0].vote_count, 1);
    }

    #[test]
    fn test_multi_answer_poll() {
        let opts = vec![
            ("A", jids(&["x@s.whatsapp.net", "y@s.whatsapp.net"])),
            ("B", jids(&["x@s.whatsapp.net"])),
        ];
        let r = build_poll(2, "Pick topics", true, opts, &HashMap::new());
        assert!(r.allow_multiple_answers);
        assert_eq!(r.options[0].vote_count, 2);
        assert_eq!(r.options[1].vote_count, 1);
    }

    #[test]
    fn test_voter_name_resolution() {
        let mut map = HashMap::new();
        map.insert("alice@s.whatsapp.net".to_string(), "Alice".to_string());
        let opts = vec![("Yes", jids(&["alice@s.whatsapp.net"]))];
        let r = build_poll(3, "Q?", false, opts, &map);
        assert_eq!(r.options[0].voter_names, vec!["Alice"]);
    }

    #[test]
    fn test_unknown_jid_stays_as_jid() {
        let opts = vec![("No", jids(&["unknown@s.whatsapp.net"]))];
        let r = build_poll(4, "Q?", false, opts, &HashMap::new());
        assert_eq!(r.options[0].voter_names, vec!["unknown@s.whatsapp.net"]);
    }

    #[test]
    fn test_total_voters_correct() {
        let opts = vec![
            ("A", jids(&["a@s.whatsapp.net", "b@s.whatsapp.net"])),
            ("B", jids(&["c@s.whatsapp.net"])),
        ];
        let r = build_poll(5, "Q?", false, opts, &HashMap::new());
        // total_voters = unique voter count
        assert_eq!(r.total_voters, 3);
    }

    #[test]
    fn test_empty_poll() {
        let r = build_poll(6, "Empty?", false, vec![], &HashMap::new());
        assert_eq!(r.options.len(), 0);
        assert_eq!(r.total_voters, 0);
    }

    #[test]
    fn test_duplicate_vote_dedup() {
        // Same JID voting for the same option twice should count once
        let opts = vec![("Yes", jids(&["a@s.whatsapp.net", "a@s.whatsapp.net"]))];
        let r = build_poll(7, "Q?", false, opts, &HashMap::new());
        assert_eq!(r.options[0].vote_count, 1);
        assert_eq!(r.options[0].voter_jids.len(), 1);
    }

    #[test]
    fn test_question_and_message_id_preserved() {
        let r = build_poll(42, "My question", false, vec![], &HashMap::new());
        assert_eq!(r.message_id, 42);
        assert_eq!(r.question, "My question");
    }

    #[test]
    fn test_option_ids_assigned() {
        let opts = vec![("A", vec![]), ("B", vec![])];
        let r = build_poll(8, "Q?", false, opts, &HashMap::new());
        // option_ids should be distinct
        assert_ne!(r.options[0].option_id, r.options[1].option_id);
    }
}
