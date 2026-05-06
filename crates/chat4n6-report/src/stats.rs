//! §2.2 Stats/Analytics computations for the report.

use chat4n6_plugin_api::{ExtractionResult, MessageContent};
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossPlatformContact {
    pub normalized_id: String,
    pub platforms: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsBundle {
    /// Message count bucketed by UTC hour of day (0–23).
    pub hourly_counts: [u32; 24],
    /// (chat jid, deletion_rate_pct) — percentage of messages that are Deleted.
    pub per_chat_deletion_rate: Vec<(String, f32)>,
    /// Contacts appearing on 2+ platforms (v1: empty — platform field not yet available).
    pub cross_platform_contacts: Vec<CrossPlatformContact>,
    /// Number of messages whose timestamp exceeds extraction_finished_at.
    pub impossible_timestamp_count: u32,
    /// (source display name, message count).
    pub source_distribution: Vec<(String, u32)>,
    pub total_messages: u32,
    pub total_chats: u32,
    pub total_calls: u32,
}

/// Compute forensic analytics from an extraction result.
pub fn compute(result: &ExtractionResult) -> StatsBundle {
    let mut hourly_counts = [0u32; 24];
    let mut impossible_timestamp_count = 0u32;
    let mut source_map: HashMap<String, u32> = HashMap::new();
    let mut total_messages = 0u32;
    let mut per_chat_deletion_rate = Vec::new();

    for chat in &result.chats {
        let total = chat.messages.len() as u32;
        let mut deleted = 0u32;

        for msg in &chat.messages {
            total_messages += 1;

            // Hourly heatmap: bucket by UTC hour.
            let hour = msg.timestamp.utc.hour() as usize;
            if hour < 24 {
                hourly_counts[hour] += 1;
            }

            // Impossible timestamp: message timestamp after extraction_finished_at.
            if let Some(finished) = result.extraction_finished_at {
                if msg.timestamp.utc > finished {
                    impossible_timestamp_count += 1;
                }
            }

            // Source distribution.
            let source_name = msg.source.to_string();
            *source_map.entry(source_name).or_insert(0) += 1;

            // Deleted count per chat.
            if matches!(msg.content, MessageContent::Deleted) {
                deleted += 1;
            }
        }

        // Deletion rate per chat.
        if total > 0 {
            let rate = deleted as f32 / total as f32 * 100.0;
            per_chat_deletion_rate.push((chat.jid.clone(), rate));
        }
    }

    let mut source_distribution: Vec<(String, u32)> = source_map.into_iter().collect();
    source_distribution.sort_by(|a, b| b.1.cmp(&a.1)); // sort descending by count

    StatsBundle {
        hourly_counts,
        per_chat_deletion_rate,
        // cross-platform detection deferred: Contact type has no platform field in v1
        cross_platform_contacts: vec![],
        impossible_timestamp_count,
        source_distribution,
        total_messages,
        total_chats: result.chats.len() as u32,
        total_calls: result.calls.len() as u32,
    }
}
