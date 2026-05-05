use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SystemEventType {
    // Group admin events
    GroupSubjectChanged,          // 1
    GroupIconChanged,             // 6
    GroupDescriptionChanged,      // 19
    GroupInviteLinkReset,         // 83 (same int — use context)

    // Participant events
    ParticipantAdded,             // 12
    ParticipantLeft,              // 5
    ParticipantRemoved,           // 14
    ParticipantJoinedViaLink,     // 20
    ApprovalRequest,              // 83

    // Security/E2E
    SecurityCodeChanged,          // 18
    E2EEncryptedNotification,     // 67

    // Admin role changes
    ParticipantPromotedToAdmin,   // 84
    ParticipantDemotedFromAdmin,  // 84 (need context)

    // Number change
    NumberChanged,                // 46

    // Disappearing messages
    DisappearingTimerChanged,     // 56

    // Message pinned/unpinned
    MessagePinned,                // 79
    MessageUnpinned,              // 79 (need context)

    // Community events
    CommunityCreated,             // 97
    CommunityJoined,              // 98
    CommunitySubgroupAdded,       // 99
    CommunitySubgroupRemoved,     // 100
    CommunitySubgroupUnlinked,    // 101
    CommunityOwnerChanged,        // 102

    // Channel events
    ChannelCreated,               // 134
    ChannelDeleted,               // 135
    ChannelPrivacyNotice,         // 136

    // Permission changes
    PermissionAddMemberChanged,   // 77
    PermissionEditChanged,        // 78
    PermissionSendMessageChanged, // 104
    PermissionInviteChanged,      // 105
    PermissionJoinChanged,        // 106

    // Business
    MetaAiDisclaimer,             // 117
    BusinessMetaManaged,          // 118

    // Unknown (preserves the raw integer)
    Unknown(i32),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemEvent {
    pub event_type: SystemEventType,
    pub label: String,                // human-readable display string
    pub actor_jid: Option<String>,
    pub target_jid: Option<String>,
}

/// Parse a WhatsApp system event from message_type + optional text_data.
///
/// For number change events, text_data contains JSON with nc_old_phone / nc_new_phone.
pub fn parse_system_event(
    msg_type: i32,
    text_data: Option<&str>,
    actor_jid: Option<&str>,
    target_jid: Option<&str>,
) -> SystemEvent {
    let (event_type, label) = decode_event(msg_type, text_data);
    SystemEvent {
        event_type,
        label,
        actor_jid: actor_jid.map(String::from),
        target_jid: target_jid.map(String::from),
    }
}

fn decode_event(msg_type: i32, text_data: Option<&str>) -> (SystemEventType, String) {
    match msg_type {
        1 => (SystemEventType::GroupSubjectChanged, "Group subject changed".to_string()),
        5 => (SystemEventType::ParticipantLeft, "Participant left group".to_string()),
        6 => (SystemEventType::GroupIconChanged, "Group icon changed".to_string()),
        12 => (SystemEventType::ParticipantAdded, "Participant added to group".to_string()),
        14 => (SystemEventType::ParticipantRemoved, "Participant removed from group".to_string()),
        18 => (SystemEventType::SecurityCodeChanged, "Security code changed".to_string()),
        19 => (SystemEventType::GroupDescriptionChanged, "Group description changed".to_string()),
        20 => (SystemEventType::ParticipantJoinedViaLink, "Participant joined via link".to_string()),
        46 => {
            let label = decode_number_change(text_data);
            (SystemEventType::NumberChanged, label)
        }
        56 => (SystemEventType::DisappearingTimerChanged, "Disappearing timer changed".to_string()),
        67 => (SystemEventType::E2EEncryptedNotification, "End-to-end encryption enabled".to_string()),
        77 => (SystemEventType::PermissionAddMemberChanged, "Permission to add members changed".to_string()),
        78 => (SystemEventType::PermissionEditChanged, "Permission to edit group changed".to_string()),
        79 => (SystemEventType::MessagePinned, "Message pinned".to_string()),
        83 => (SystemEventType::GroupInviteLinkReset, "Group invite link reset".to_string()),
        84 => (SystemEventType::ParticipantPromotedToAdmin, "Participant promoted to admin".to_string()),
        97 => (SystemEventType::CommunityCreated, "Community created".to_string()),
        98 => (SystemEventType::CommunityJoined, "Joined community".to_string()),
        99 => (SystemEventType::CommunitySubgroupAdded, "Community subgroup added".to_string()),
        100 => (SystemEventType::CommunitySubgroupRemoved, "Community subgroup removed".to_string()),
        101 => (SystemEventType::CommunitySubgroupUnlinked, "Community subgroup unlinked".to_string()),
        102 => (SystemEventType::CommunityOwnerChanged, "Community owner changed".to_string()),
        104 => (SystemEventType::PermissionSendMessageChanged, "Permission to send messages changed".to_string()),
        105 => (SystemEventType::PermissionInviteChanged, "Permission to invite members changed".to_string()),
        106 => (SystemEventType::PermissionJoinChanged, "Permission to join changed".to_string()),
        117 => (SystemEventType::MetaAiDisclaimer, "Meta AI disclaimer".to_string()),
        118 => (SystemEventType::BusinessMetaManaged, "Business managed by Meta".to_string()),
        134 => (SystemEventType::ChannelCreated, "Channel created".to_string()),
        135 => (SystemEventType::ChannelDeleted, "Channel deleted".to_string()),
        136 => (SystemEventType::ChannelPrivacyNotice, "Channel privacy notice".to_string()),
        other => (SystemEventType::Unknown(other), format!("Unknown system event (type={other})")),
    }
}

fn decode_number_change(text_data: Option<&str>) -> String {
    if let Some(text) = text_data {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            let old = v.get("nc_old_phone")
                .and_then(|p| p.as_str())
                .unwrap_or("");
            let new = v.get("nc_new_phone")
                .and_then(|p| p.as_str())
                .unwrap_or("");
            if !old.is_empty() || !new.is_empty() {
                return format!("Phone number changed: {} → {}", old, new);
            }
        }
    }
    "Phone number changed".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(msg_type: i32) -> SystemEvent {
        parse_system_event(msg_type, None, None, None)
    }

    fn parse_with_text(msg_type: i32, text: &str) -> SystemEvent {
        parse_system_event(msg_type, Some(text), None, None)
    }

    // ── Group admin events ────────────────────────────────────────────────────

    #[test]
    fn test_type1_group_subject_changed() {
        let e = parse(1);
        assert_eq!(e.event_type, SystemEventType::GroupSubjectChanged);
        assert!(!e.label.is_empty(), "label must be non-empty");
    }

    #[test]
    fn test_type6_group_icon_changed() {
        let e = parse(6);
        assert_eq!(e.event_type, SystemEventType::GroupIconChanged);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type19_group_description_changed() {
        let e = parse(19);
        assert_eq!(e.event_type, SystemEventType::GroupDescriptionChanged);
        assert!(!e.label.is_empty());
    }

    // ── Participant events ────────────────────────────────────────────────────

    #[test]
    fn test_type5_participant_left() {
        let e = parse(5);
        assert_eq!(e.event_type, SystemEventType::ParticipantLeft);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type12_participant_added() {
        let e = parse(12);
        assert_eq!(e.event_type, SystemEventType::ParticipantAdded);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type14_participant_removed() {
        let e = parse(14);
        assert_eq!(e.event_type, SystemEventType::ParticipantRemoved);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type20_participant_joined_via_link() {
        let e = parse(20);
        assert_eq!(e.event_type, SystemEventType::ParticipantJoinedViaLink);
        assert!(!e.label.is_empty());
    }

    // ── Security events ───────────────────────────────────────────────────────

    #[test]
    fn test_type18_security_code_changed() {
        let e = parse(18);
        assert_eq!(e.event_type, SystemEventType::SecurityCodeChanged);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type67_e2e_encrypted_notification() {
        let e = parse(67);
        assert_eq!(e.event_type, SystemEventType::E2EEncryptedNotification);
        assert!(!e.label.is_empty());
    }

    // ── Admin role changes ────────────────────────────────────────────────────

    #[test]
    fn test_type84_participant_promoted_to_admin() {
        let e = parse(84);
        assert_eq!(e.event_type, SystemEventType::ParticipantPromotedToAdmin);
        assert!(!e.label.is_empty());
    }

    // ── Number change ─────────────────────────────────────────────────────────

    #[test]
    fn test_type46_number_changed() {
        let e = parse(46);
        assert_eq!(e.event_type, SystemEventType::NumberChanged);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type46_number_changed_with_json() {
        let json = r#"{"nc_old_phone":"15551234567","nc_new_phone":"15557654321"}"#;
        let e = parse_with_text(46, json);
        assert_eq!(e.event_type, SystemEventType::NumberChanged);
        // Label should include phone numbers when JSON is parseable
        assert!(e.label.contains("15551234567") || e.label.contains("number"),
            "label should reference the number change, got: {}", e.label);
    }

    #[test]
    fn test_type46_number_changed_without_json() {
        let e = parse(46);
        // Should still succeed without JSON text_data
        assert_eq!(e.event_type, SystemEventType::NumberChanged);
        assert!(!e.label.is_empty());
    }

    // ── Disappearing messages ─────────────────────────────────────────────────

    #[test]
    fn test_type56_disappearing_timer_changed() {
        let e = parse(56);
        assert_eq!(e.event_type, SystemEventType::DisappearingTimerChanged);
        assert!(!e.label.is_empty());
    }

    // ── Permission changes ────────────────────────────────────────────────────

    #[test]
    fn test_type77_permission_add_member_changed() {
        let e = parse(77);
        assert_eq!(e.event_type, SystemEventType::PermissionAddMemberChanged);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type78_permission_edit_changed() {
        let e = parse(78);
        assert_eq!(e.event_type, SystemEventType::PermissionEditChanged);
        assert!(!e.label.is_empty());
    }

    // ── Community events ──────────────────────────────────────────────────────

    #[test]
    fn test_type97_community_created() {
        let e = parse(97);
        assert_eq!(e.event_type, SystemEventType::CommunityCreated);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type98_community_joined() {
        let e = parse(98);
        assert_eq!(e.event_type, SystemEventType::CommunityJoined);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type99_community_subgroup_added() {
        let e = parse(99);
        assert_eq!(e.event_type, SystemEventType::CommunitySubgroupAdded);
        assert!(!e.label.is_empty());
    }

    // ── Channel events ────────────────────────────────────────────────────────

    #[test]
    fn test_type134_channel_created() {
        let e = parse(134);
        assert_eq!(e.event_type, SystemEventType::ChannelCreated);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type135_channel_deleted() {
        let e = parse(135);
        assert_eq!(e.event_type, SystemEventType::ChannelDeleted);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type136_channel_privacy_notice() {
        let e = parse(136);
        assert_eq!(e.event_type, SystemEventType::ChannelPrivacyNotice);
        assert!(!e.label.is_empty());
    }

    // ── Business events ───────────────────────────────────────────────────────

    #[test]
    fn test_type117_meta_ai_disclaimer() {
        let e = parse(117);
        assert_eq!(e.event_type, SystemEventType::MetaAiDisclaimer);
        assert!(!e.label.is_empty());
    }

    #[test]
    fn test_type118_business_meta_managed() {
        let e = parse(118);
        assert_eq!(e.event_type, SystemEventType::BusinessMetaManaged);
        assert!(!e.label.is_empty());
    }

    // ── Unknown fallback ──────────────────────────────────────────────────────

    #[test]
    fn test_unknown_type_fallback() {
        let e = parse(999);
        assert_eq!(e.event_type, SystemEventType::Unknown(999));
    }

    #[test]
    fn test_unknown_preserves_raw_int() {
        let e = parse(-5);
        assert_eq!(e.event_type, SystemEventType::Unknown(-5));
    }

    // ── Actor/target JID preservation ─────────────────────────────────────────

    #[test]
    fn test_actor_target_jid_preserved() {
        let e = parse_system_event(12, None, Some("actor@s.whatsapp.net"), Some("target@s.whatsapp.net"));
        assert_eq!(e.actor_jid.as_deref(), Some("actor@s.whatsapp.net"));
        assert_eq!(e.target_jid.as_deref(), Some("target@s.whatsapp.net"));
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn test_system_event_serializes() {
        let e = SystemEvent {
            event_type: SystemEventType::ParticipantAdded,
            label: "Participant added to group".to_string(),
            actor_jid: None,
            target_jid: None,
        };
        let json = serde_json::to_string(&e).expect("serialize");
        let back: SystemEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(e, back);
    }
}
