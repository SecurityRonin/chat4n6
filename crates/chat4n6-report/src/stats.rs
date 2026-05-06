//! §2.2 Stats/Analytics computations for the report.

use chat4n6_plugin_api::ExtractionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossPlatformContact {
    pub normalized_id: String,
    pub platforms: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsBundle {
    pub hourly_counts: [u32; 24],
    pub per_chat_deletion_rate: Vec<(String, f32)>,
    pub cross_platform_contacts: Vec<CrossPlatformContact>,
    pub impossible_timestamp_count: u32,
    pub source_distribution: Vec<(String, u32)>,
    pub total_messages: u32,
    pub total_chats: u32,
    pub total_calls: u32,
}

/// Compute forensic analytics from an extraction result.
pub fn compute(_result: &ExtractionResult) -> StatsBundle {
    // Stub — will be replaced by GREEN implementation.
    StatsBundle {
        hourly_counts: [0u32; 24],
        per_chat_deletion_rate: vec![],
        cross_platform_contacts: vec![],
        impossible_timestamp_count: 0,
        source_distribution: vec![],
        total_messages: 0,
        total_chats: 0,
        total_calls: 0,
    }
}
