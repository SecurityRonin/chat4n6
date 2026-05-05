use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GroupChangeKind {
    SubjectChanged { old: Option<String>, new: String },
    IconChanged { old_jpeg_b64: Option<String>, new_jpeg_b64: Option<String> },
    DescriptionChanged { old: Option<String>, new: String },
    AdminOnlyEditChanged { admins_only: bool },
    AdminOnlySendChanged { admins_only: bool },
    DisappearingTimerChanged { old_secs: Option<u64>, new_secs: Option<u64> },
    InviteLinkReset,
    ApprovalModeChanged { requires_approval: bool },
    MembershipApprovalChanged { requires_approval: bool },
    Unknown(i32),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupChangeRecord {
    pub message_id: i64,
    pub actor_jid: Option<String>,
    pub change: GroupChangeKind,
    pub timestamp_ms: i64,
}

/// Build a GroupChangeRecord from raw fields.
/// action_type mapping:
///   1=subject, 6=icon, 19=description, 27=description alt,
///   29=admin_only_edit_on, 30=admin_only_edit_off,
///   31=admin_only_send_on, 32=admin_only_send_off,
///   56=disappearing, 83=invite_reset, 84=approval_on, 85=approval_off
pub fn parse_group_change(
    message_id: i64,
    actor_jid: Option<&str>,
    action_type: i32,
    old_value: Option<&str>,
    new_value: Option<&str>,
    timestamp_ms: i64,
) -> GroupChangeRecord {
    let change = match action_type {
        1 => GroupChangeKind::SubjectChanged {
            old: old_value.map(|s| s.to_string()),
            new: new_value.unwrap_or("").to_string(),
        },
        6 => GroupChangeKind::IconChanged {
            old_jpeg_b64: old_value.map(|s| s.to_string()),
            new_jpeg_b64: new_value.map(|s| s.to_string()),
        },
        19 | 27 => GroupChangeKind::DescriptionChanged {
            old: old_value.map(|s| s.to_string()),
            new: new_value.unwrap_or("").to_string(),
        },
        29 => GroupChangeKind::AdminOnlyEditChanged { admins_only: true },
        30 => GroupChangeKind::AdminOnlyEditChanged { admins_only: false },
        31 => GroupChangeKind::AdminOnlySendChanged { admins_only: true },
        32 => GroupChangeKind::AdminOnlySendChanged { admins_only: false },
        56 => GroupChangeKind::DisappearingTimerChanged {
            old_secs: old_value.and_then(|s| s.parse::<u64>().ok()),
            new_secs: new_value.and_then(|s| s.parse::<u64>().ok()),
        },
        83 => GroupChangeKind::InviteLinkReset,
        84 => GroupChangeKind::ApprovalModeChanged { requires_approval: true },
        85 => GroupChangeKind::ApprovalModeChanged { requires_approval: false },
        other => GroupChangeKind::Unknown(other),
    };

    GroupChangeRecord {
        message_id,
        actor_jid: actor_jid.map(|s| s.to_string()),
        change,
        timestamp_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(action: i32, old: Option<&str>, new: Option<&str>) -> GroupChangeKind {
        parse_group_change(1, Some("actor@s.whatsapp.net"), action, old, new, 1000).change
    }

    #[test]
    fn test_subject_changed() {
        let c = parse(1, Some("Old Name"), Some("New Name"));
        assert!(matches!(c, GroupChangeKind::SubjectChanged { .. }));
        if let GroupChangeKind::SubjectChanged { old, new } = c {
            assert_eq!(old, Some("Old Name".to_string()));
            assert_eq!(new, "New Name");
        }
    }

    #[test]
    fn test_subject_none_old() {
        let c = parse(1, None, Some("First Name"));
        if let GroupChangeKind::SubjectChanged { old, new } = c {
            assert!(old.is_none());
            assert_eq!(new, "First Name");
        } else {
            panic!("expected SubjectChanged");
        }
    }

    #[test]
    fn test_icon_changed_jpeg_b64_preserved() {
        let fake_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ";
        let c = parse(6, Some(fake_b64), Some(fake_b64));
        if let GroupChangeKind::IconChanged { old_jpeg_b64, new_jpeg_b64 } = c {
            assert_eq!(old_jpeg_b64, Some(fake_b64.to_string()));
            assert_eq!(new_jpeg_b64, Some(fake_b64.to_string()));
        } else {
            panic!("expected IconChanged");
        }
    }

    #[test]
    fn test_description_changed() {
        let c = parse(19, Some("Old desc"), Some("New desc"));
        assert!(matches!(c, GroupChangeKind::DescriptionChanged { .. }));
    }

    #[test]
    fn test_admin_only_edit_on() {
        let c = parse(29, None, None);
        assert_eq!(c, GroupChangeKind::AdminOnlyEditChanged { admins_only: true });
    }

    #[test]
    fn test_admin_only_edit_off() {
        let c = parse(30, None, None);
        assert_eq!(c, GroupChangeKind::AdminOnlyEditChanged { admins_only: false });
    }

    #[test]
    fn test_admin_only_send_on() {
        let c = parse(31, None, None);
        assert_eq!(c, GroupChangeKind::AdminOnlySendChanged { admins_only: true });
    }

    #[test]
    fn test_admin_only_send_off() {
        let c = parse(32, None, None);
        assert_eq!(c, GroupChangeKind::AdminOnlySendChanged { admins_only: false });
    }

    #[test]
    fn test_disappearing_timer() {
        let c = parse(56, Some("86400"), Some("604800"));
        if let GroupChangeKind::DisappearingTimerChanged { old_secs, new_secs } = c {
            assert_eq!(old_secs, Some(86400));
            assert_eq!(new_secs, Some(604800));
        } else {
            panic!("expected DisappearingTimerChanged");
        }
    }

    #[test]
    fn test_invite_link_reset() {
        let c = parse(83, None, None);
        assert_eq!(c, GroupChangeKind::InviteLinkReset);
    }

    #[test]
    fn test_approval_on() {
        let c = parse(84, None, None);
        assert_eq!(c, GroupChangeKind::ApprovalModeChanged { requires_approval: true });
    }

    #[test]
    fn test_unknown_type() {
        let c = parse(999, None, None);
        assert_eq!(c, GroupChangeKind::Unknown(999));
    }

    #[test]
    fn test_timestamp_and_actor_preserved() {
        let r = parse_group_change(42, Some("bob@s.whatsapp.net"), 83, None, None, 9999999);
        assert_eq!(r.message_id, 42);
        assert_eq!(r.actor_jid, Some("bob@s.whatsapp.net".to_string()));
        assert_eq!(r.timestamp_ms, 9999999);
    }
}
